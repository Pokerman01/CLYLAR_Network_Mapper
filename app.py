from dotenv import load_dotenv
load_dotenv()  # โหลด .env อัตโนมัติ (GOOGLE_API_KEY, GEMINI_MODEL)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session, g
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import defer
from models import db, User, ScanJob, ScheduledScan, SavedTarget, HistoryQuery, AppSetting, GeminiCall, Notification, ChatAnswer, LoginThrottle
from scanner import (port_reason, port_reason_label, PORT_REASON_TH, run_network_scan, run_vuln_scan, get_system_default_gateway, get_public_ip,
                     get_scan_capabilities, get_local_adapters, mac_note, guess_device_type, DEVICE_TYPES,
                     clamp_scan_knobs, clamp_skip_ping, clamp_all_ports, clamp_no_dns, clamp_probes, clamp_gentle, clamp_udp, clamp_udp_top, udp_max_addresses, udp_host_timeout_minutes, port_proto, port_key, port_text, udp_unavailable, udp_unavailable_th, udp_limit_error, UDP_MAX_ADDRESSES, options_conflict, options_conflict_th, gentle_limit_error, GENTLE_MAX_ADDRESSES, ports_limit_error, ALL_PORTS_MAX_ADDRESSES, ARP_ONLY_MAX, describe_scan_settings, discovery_service_text, virtual_machine_platform, is_local_ip,
                     effective_severity, severity_adjusted, severity_note, cvss_number, os_match_accuracy,
                     target_size, is_valid_target, PN_MAX_ADDRESSES, PROGRESS_EVERY)
from cwe_data import cwe_info
import voice_commands
import i18n
import local_llm
import voice_lab
import report_builder
import device_builder
import scan_diff
import scan_runner
from report_pdf import html_to_pdf, ReportPdfError
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from markupsafe import Markup
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
import ipaddress
import json
import math
import pathlib
import re
import atexit
import threading
import secrets
import time

TZ = ZoneInfo("Asia/Bangkok")

def now_th():
    return datetime.now(TZ).replace(tzinfo=None)


import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)

app = Flask(__name__, instance_path=INSTANCE_DIR)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(INSTANCE_DIR, 'scanner.db').replace(os.sep, '/')}"
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_TIME_LIMIT'] = None  # valid for the session lifetime so idle tabs don't fail unexpectedly

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


def mac_note_html(ip, mac='', vendor='', dash=True):
    """Badge explaining a missing/unresolvable MAC; '—' (dash=True) or nothing when there is nothing to explain."""
    note = mac_note(ip, mac, vendor, lang=ui_lang_now())
    if note:
        return Markup('<span class="badge mac-note-badge" title="{}">{}</span>').format(note['tip'], note['label'])
    return Markup('<span class="text-muted">—</span>') if dash else Markup('')


app.jinja_env.globals['mac_note_html'] = mac_note_html
app.jinja_env.globals['cwe_info'] = lambda cve: cwe_info(cve, lang=ui_lang_now())   # official CWE id / name / link for a stored CVE record
app.jinja_env.globals['t'] = lambda key, **values: i18n.t(key, ui_lang_now(), **values)      # interface text in the chosen language (i18n.py, locales/*.json)
app.jinja_env.globals['voice_help_examples'] = voice_commands.HELP_EXAMPLES      # the chat's help panel (base.html)
# the severity to show for a stored CVE record: NVD's label, with a CVSS v2-only 9.0+ shown as CRITICAL (see scanner.effective_severity)
app.jinja_env.globals['effective_severity'] = effective_severity
app.jinja_env.globals['port_reason_label'] = port_reason_label     # Thai words for nmap's reason of a port state (None when not recorded)
app.jinja_env.globals['PORT_REASON_TH'] = PORT_REASON_TH
app.jinja_env.globals['severity_adjusted'] = severity_adjusted
app.jinja_env.globals['severity_note'] = lambda score: severity_note(score, lang=ui_lang_now())
# The dashboard's "good" green: the donut's "No Findings" slice and the Task Status "Complete" bar. One value for both, also
# handed to dashboard.html, where inkOf() swaps it for a deeper shade whenever it is used as a text colour.
GOOD_GREEN = '#1cb454'

# The six device tiers of the dashboard's donut, one per device by its worst CVE (the Network Topology page colours its dots by risk with them too).
# Critical / High are the bright red and orange the owner prefers. A deep red + light orange pair (#991b1b / #fb923c) was tried
# because these two look alike; the owner chose these back.
DEVICE_TIER_COLOR = {
    'critical': '#dc3545',
    'high': '#fd7e14',
    'medium': '#ffc107',
    'low': '#9bc53d',
    'clean': GOOD_GREEN,
    'unscanned': '#6c757d',
}
app.jinja_env.globals['GOOD_GREEN'] = GOOD_GREEN
# first adapter lookup shells out to PowerShell (~2s): do it once in the background at startup
threading.Thread(target=get_local_adapters, daemon=True).start()

# --- Custom Jinja filter ---
SCAN_TYPE_LABELS = {
    'fast_scan': 'Fast Scan',
    'discovery': 'Discovery',
    'intense': 'Intense Scan',
    'custom': 'Custom Scan',
    'xml_upload': 'XML Upload',
    'vuln_scan': 'Vulnerability Scan (CVE)',
}
# The same names in Thai (2026-11-11, the owner: "in Thai mode every word is Thai"; the technical words are transliterated). Only what is SHOWN
# changes: the stored scan_type values and the CSV export keep the English names. The PDF report is always Thai.
SCAN_TYPE_LABELS_TH = {
    'fast_scan': 'สแกนแบบเร็ว',
    'discovery': 'ค้นหาอุปกรณ์',
    'intense': 'สแกนแบบละเอียด',
    'custom': 'สแกนแบบกำหนดเอง',
    'xml_upload': 'นำเข้าไฟล์ XML',
    'vuln_scan': 'สแกนช่องโหว่ (CVE)',
}


def scan_labels(lang=None):
    """The scan-type names for the interface language of this request (or for `lang` when given)."""
    return SCAN_TYPE_LABELS if (lang or ui_lang_now()) == 'en' else SCAN_TYPE_LABELS_TH


@app.template_filter('scan_label')
def scan_label_filter(value):
    return scan_labels().get(value, value)


def sev_label(value, lang=None):
    """Localized CVE severity label ('วิกฤต'/'สูง'/'ปานกลาง'/'ต่ำ' in TH, 'Critical'/'High'/'Medium'/'Low' in EN)."""
    k = str(value or '').strip().lower()
    if k not in ('critical', 'high', 'medium', 'low'):
        k = 'unknown'
    return i18n.t('vulns.sev.' + k, lang if lang in i18n.LANGS else ui_lang_now())


@app.template_filter('sev_label')
def sev_label_filter(value):
    return sev_label(value)


def job_label(n, lang=None):
    """Localized scan job label ('งาน #12' in TH, 'Job #12' in EN)."""
    return i18n.t('common.job_num', lang if lang in i18n.LANGS else ui_lang_now(), n=n)


@app.template_filter('job_label')
def job_label_filter(value):
    return job_label(value)

@app.template_filter('css_str')
def css_str_filter(value):
    """Text made safe to sit between double quotes in a CSS string (the report's running header / footer): no control characters, \\ and \" escaped."""
    s = ''.join(ch for ch in str(value or '') if ch >= ' ' and ch != '\x7f')
    return s.replace('\\', '\\\\').replace('"', '\\"')

@app.template_filter('from_json')
def from_json_filter(value):
    if not value:
        return []
    try:
        import json as _json
        return _json.loads(value)
    except Exception:
        return []


@app.template_filter('host_count')
def host_count_filter(job):
    """Number of real hosts discovered by a ScanJob (never counts error objects on failed scans)."""
    return len(_parse_job_hosts(job))

# --- APScheduler ---
scheduler = BackgroundScheduler(timezone="Asia/Bangkok")
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return None if user is not None and user.is_suspended else user      # a suspended account is signed out at its next request


# ─────────────────────────────────────────
#  Permission decorators
# ─────────────────────────────────────────

def superadmin_required(f):
    """เฉพาะ superadmin เท่านั้น"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """admin หรือ superadmin (สแกนได้ / จัดการ schedule ได้)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_any_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


def user_management_required(f):
    """admin, superadmin สร้าง user ได้"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_any_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────
#  Helper: กรอง ScanJob ตาม role
# ─────────────────────────────────────────

def visible_scans_query():
    """
    superadmin → เห็นเฉพาะ scan ของตัวเอง
    admin      → เห็น scan ของตัวเอง
    user       → เห็น scan ของ admin ที่สร้างตัวเอง
    """
    if current_user.role == 'superadmin':
        return ScanJob.query.filter_by(owner_id=current_user.id)
    elif current_user.role in ('admin', 'superadmin'):
        return ScanJob.query.filter_by(owner_id=current_user.id)
    else:
        # user → เห็น scan ของ admin ที่สร้างตัวเอง
        admin_id = current_user.created_by
        if admin_id:
            return ScanJob.query.filter_by(owner_id=admin_id)
        return ScanJob.query.filter(ScanJob.id == None)  # ไม่เห็นอะไรเลย


def visible_schedules_query():
    """schedule filter เช่นเดียวกับ scan"""
    if current_user.is_any_admin:
        return ScheduledScan.query.filter_by(owner_id=current_user.id)
    else:
        admin_id = current_user.created_by
        if admin_id:
            return ScheduledScan.query.filter_by(owner_id=admin_id)
        return ScheduledScan.query.filter(ScheduledScan.id == None)


# ─────────────────────────────────────────
#  Layout context (sidebar/topbar — every template)
# ─────────────────────────────────────────

EN_MONTHS = [None, 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
THAI_MONTHS = ['', 'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน', 'พฤษภาคม', 'มิถุนายน',
               'กรกฎาคม', 'สิงหาคม', 'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม']


# ─────────────────────────────────────────
#  Theme (light / dark) and interface language (th / en): one choice per user
# ─────────────────────────────────────────
# Kept per user on the server (`AppSetting` ui_theme.<user id> / ui_lang.<user id>) so it holds in every browser, and ALSO in a cookie
# (clylar_theme / clylar_lang) so the login page, which has no user yet, shows the same choice. Light and Thai are the defaults. The server writes
# both into the page (<html data-theme lang>), so there is no flash of the wrong theme. Changing them is a JSON POST (there is no CSRF token, so
# a form post is a 400), open to a visitor who is not signed in (the login page has the buttons too): it then sets the cookie only.
UI_THEMES = ('light', 'dark')
UI_COOKIE_SECONDS = 365 * 24 * 3600


def _ui_pref(kind, allowed, default):
    """kind is 'theme' or 'lang': the signed-in user's saved choice, else the cookie, else the default."""
    if current_user.is_authenticated:
        try:
            value = get_setting('ui_%s.%d' % (kind, current_user.id))
            if value in allowed:
                return value
        except Exception:
            pass
    value = request.cookies.get('clylar_' + kind)
    return value if value in allowed else default


def ui_lang_now():
    """The interface language of this request ('th' or 'en'), worked out once per request."""
    try:
        if not hasattr(g, 'ui_lang'):
            g.ui_lang = _ui_pref('lang', i18n.LANGS, i18n.DEFAULT_LANG)
        return g.ui_lang
    except RuntimeError:                       # no request (a script or a test): the default
        return i18n.DEFAULT_LANG


def tr(key, **values):
    """A text for the server's own messages (flash notices, API errors) in the current language: the same keys as t() in a template."""
    return i18n.t(key, ui_lang_now(), **values)


def fmt_dt(value, fmt='%Y-%m-%d %H:%M'):
    """A date or time in the calendar of the interface language: the Buddhist year (+543) in Thai, the ordinary year in English. Only what is shown
    changes, never what is stored. A text (already formatted) comes back as it is: use ui_year() for that."""
    if not value:
        return ''
    if isinstance(value, str):
        return ui_year(value)
    if ui_lang_now() != 'en':
        fmt = fmt.replace('%Y', '%04d' % (value.year + 543))
    return value.strftime(fmt)


def ui_year(text):
    """'2026-11-10 13:20' -> '2569-11-10 13:20' in Thai (the same for a date alone); English and anything else unchanged."""
    if ui_lang_now() == 'en' or not isinstance(text, str):
        return text
    m = re.match(r'^(\d{4})(-\d{2}-\d{2})', text)
    return '%d%s%s' % (int(m.group(1)) + 543, m.group(2), text[m.end():]) if m else text


app.jinja_env.filters['fdt'] = fmt_dt
app.jinja_env.filters['ui_year'] = ui_year


@app.route('/favicon.ico')
def favicon():
    """The browser asks for it on every page; the Clylar app icon is the answer (it used to be a 404 and a console error)."""
    return app.send_static_file('images/clylar-app-icon.png')


def _ui_save(kind, value):
    if current_user.is_authenticated:
        set_setting('ui_%s.%d' % (kind, current_user.id), value)
    response = jsonify({kind: value})
    response.set_cookie('clylar_' + kind, value, max_age=UI_COOKIE_SECONDS, samesite='Lax', path='/')
    return response


@app.route('/api/ui/theme', methods=['POST'])
def api_ui_theme():
    """{theme: 'light' | 'dark'}"""
    theme = (request.get_json(silent=True) or {}).get('theme')
    if theme not in UI_THEMES:
        return jsonify({'error': 'theme must be light or dark'}), 400
    return _ui_save('theme', theme)


@app.route('/api/ui/lang', methods=['POST'])
def api_ui_lang():
    """{lang: 'th' | 'en'}"""
    lang = (request.get_json(silent=True) or {}).get('lang')
    if lang not in i18n.LANGS:
        return jsonify({'error': 'lang must be th or en'}), 400
    return _ui_save('lang', lang)


def localized_scan_warnings():
    """Capability warnings from get_scan_capabilities(), rendered in the active UI language."""
    warnings = get_scan_capabilities().get('warnings') or []
    out = []
    for w in warnings:
        code = w.get('code') if isinstance(w, dict) else None
        if code in ('no_nmap', 'not_admin', 'no_npcap'):
            out.append({'text': tr(f'cap.{code}.text'), 'tip': tr(f'cap.{code}.tip')})
        elif isinstance(w, dict):
            out.append(w)
    return out


@app.context_processor
def inject_layout_context():
    now = now_th()
    notif_count = 0
    notif_unread = 0
    if current_user.is_authenticated:
        try:
            notif_count = visible_scans_query().filter(ScanJob.status.in_(ACTIVE_STATUSES)).count()      # waiting or running
            notif_unread = Notification.query.filter_by(user_id=current_user.id, read_at=None).count()     # the bell's badge
        except Exception:
            notif_count = 0
    chat_button_hidden = False       # the floating chat button is only drawn for admins; each of them may hide it (Settings page)
    voice_autorun = False            # "scan at once": this admin chose to skip the confirmation card for a safe target (see voice_autorun_allowed)
    chat_ai_on = True                # the chat's status line: "AI ปิดอยู่" when the Settings switch has the AI off
    chat_ai_engine = 'gemini'        # which engine answers (Settings): the chat says whether a question leaves this computer
    chat_hint_seen = True            # the one-time "you can hide this button in Settings" hint beside the speed dial: shown only while this is False (admins who have not seen it)
    if current_user.is_authenticated and current_user.is_any_admin:
        try:
            chat_button_hidden = get_setting(chat_button_key(current_user.id), '0') == '1'
            chat_hint_seen = get_setting(chat_hint_key(current_user.id), '0') == '1'
            chat_ai_on = ai_enabled()
            chat_ai_engine = ai_engine()
            voice_autorun = voice_autorun_on(current_user.id)
        except Exception:
            chat_button_hidden = False
    return {
        'now_year': now.year,
        'thai_date_today': f"{now.day} {THAI_MONTHS[now.month]} {now.year + 543}",
        # the date in the top bar in the chosen language: Thai with the Buddhist year, English with the Gregorian one
        'date_today': (f"{now.day} {EN_MONTHS[now.month]} {now.year}" if ui_lang_now() == 'en' else f"{now.day} {THAI_MONTHS[now.month]} {now.year + 543}"),
        'notification_count': notif_count,
        'notification_unread': notif_unread,
        'scan_warnings': localized_scan_warnings(),
        # the id of the scan a form just ran before redirecting here (set by the routes below), shown once as the "scan finished" notice; it does not
        # depend on the browser's storage or on the page having seen the scan run
        'scan_just_finished': session.pop('scan_just_finished', None),
        'chat_button_hidden': chat_button_hidden,
        'chat_hint_seen': chat_hint_seen,
        'chat_ai_on': chat_ai_on,
        'chat_ai_engine': chat_ai_engine,
        'voice_autorun': voice_autorun,
        'ui_theme': _ui_pref('theme', UI_THEMES, 'light'),       # <html data-theme=...> and the theme button
        'ui_lang': ui_lang_now(),                                # <html lang=...> and the language button
    }


# ─────────────────────────────────────────
#  Helpers: Schedule calculation
# ─────────────────────────────────────────

def calc_next_run(schedule):
    now = now_th()
    base = now.replace(hour=schedule.cron_hour, minute=schedule.cron_minute, second=0, microsecond=0)

    if schedule.repeat == 'daily':
        if base <= now:
            base += timedelta(days=1)
        return base
    elif schedule.repeat == 'weekly':
        dow = schedule.day_of_week or 0
        days_ahead = (dow - now.weekday()) % 7
        candidate = base + timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(weeks=1)
        return candidate
    elif schedule.repeat == 'monthly':
        # Day 29 to 31: a month that is shorter runs on its LAST day (see monthly_run_day). The next run is the first such day, this month or a
        # later one, that is still in the future; every month is worked out from its own length (a month is never built by replace(month=...),
        # which fails when the next month is shorter).
        dom = schedule.day_of_month or 1
        year, month = now.year, now.month
        for _ in range(14):
            candidate = base.replace(year=year, month=month, day=monthly_run_day(year, month, dom))
            if candidate > now:
                return candidate
            year, month = (year + 1, 1) if month == 12 else (year, month + 1)
        return candidate
    return base


def monthly_run_day(year, month, day_of_month):
    """The day of that month a monthly schedule runs on: the chosen day, or the last day when the month is shorter (31 in April is the 30th,
    29 to 31 in a common February is the 28th)."""
    import calendar
    return min(max(int(day_of_month or 1), 1), calendar.monthrange(year, month)[1])


def job_skip_ping(scan_type, custom_args, form_value):
    """What to store in ScanJob.skip_ping for a new job: the checkbox for the three port scans, -Pn typed in the arguments for a Custom
    scan, None for Discovery / XML (see scanner.clamp_skip_ping)."""
    if scan_type == 'custom':
        return '-Pn' in (custom_args or '').split()
    return clamp_skip_ping(form_value, scan_type)


def job_all_ports(scan_type, form_value):
    """What to store in ScanJob.all_ports for a new job: the checkbox for the three port scans, None for the types that cannot use it
    (see scanner.clamp_all_ports)."""
    return clamp_all_ports(form_value, scan_type)


def job_no_dns(scan_type, form_value):
    """What to store in ScanJob.no_dns for a new job (see scanner.clamp_no_dns): the checkbox for Discovery and the three port scans, None otherwise."""
    return clamp_no_dns(form_value, scan_type)


def job_probes(scan_type, form_value):
    """What to store in ScanJob.host_probes (see scanner.clamp_probes)."""
    return clamp_probes(form_value, scan_type)


def job_gentle(scan_type, form_value):
    """What to store in ScanJob.gentle (see scanner.clamp_gentle)."""
    return clamp_gentle(form_value, scan_type)


def job_udp(scan_type, form_value):
    """What to store in ScanJob.udp (see scanner.clamp_udp)."""
    return clamp_udp(form_value, scan_type)


def job_udp_top(scan_type, udp, form_value):
    """What to store in ScanJob.udp_top (see scanner.clamp_udp_top): 100 or 1000, else None = the 12 common UDP ports."""
    return clamp_udp_top(form_value, scan_type, udp)


def scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp=False, udp_top=None, timing=None):
    """Localized refusal message for a form route when options conflict or target size exceeds a safe cap, else None."""
    lang = ui_lang_now()
    conflict_fn = options_conflict if lang == 'en' else options_conflict_th
    conflict = conflict_fn(bool(skip_ping), bool(all_ports), bool(host_probes), bool(gentle))
    if conflict:
        return conflict
    refusal = all_ports_refusal(target, all_ports)
    if refusal:
        return refusal
    if gentle and gentle_limit_error(target):
        return i18n.t('refusal.gentle_limit', lang, max=format(GENTLE_MAX_ADDRESSES, ','), n=format(target_size(target), ','))
    if udp:
        unavail = udp_unavailable() if lang == 'en' else udp_unavailable_th()
        if unavail:
            return unavail
        if udp_limit_error(target, True, udp_top):
            cap = udp_max_addresses(udp_top)
            return i18n.t('refusal.udp_limit_top1000' if udp_top == 1000 else 'refusal.udp_limit', lang, max=cap, net=32 - (cap.bit_length() - 1), n=format(target_size(target), ','))
        if udp_top == 1000 and gentle:
            return i18n.t('refusal.udp_top_gentle', lang)
        if udp_top and not gentle and timing is not None and timing <= 1:
            return i18n.t('refusal.udp_top_timing', lang)
    return None


def all_ports_refusal(target, all_ports):
    """Localized refusal message when scanning all ports exceeds ALL_PORTS_MAX_ADDRESSES, else None."""
    if all_ports and ports_limit_error(target):
        return i18n.t('refusal.all_ports_limit', ui_lang_now(), max=ALL_PORTS_MAX_ADDRESSES, n=format(target_size(target), ','))
    return None


def scan_with_info(target, scan_type, custom_args=None, timing=None, version_intensity=None, multicast=False, skip_ping=False, all_ports=False, no_dns=False, host_probes=False, gentle=False, udp=False, udp_top=None):
    """Runs the scanner and returns (result text, the run's scan_info as JSON text or None). One place, so every way of starting a scan
    records the same things about the run."""
    info = {}
    if scan_type == 'vuln_scan':
        results = run_vuln_scan(target, timing=timing, version_intensity=version_intensity, skip_ping=bool(skip_ping), info=info, all_ports=bool(all_ports), no_dns=bool(no_dns),
                               host_probes=bool(host_probes), gentle=bool(gentle), udp=bool(udp), udp_top=udp_top)
    else:
        results = run_network_scan(target, scan_type, custom_args=custom_args, timing=timing, version_intensity=version_intensity,
                                   multicast=multicast, skip_ping=bool(skip_ping), info=info, all_ports=bool(all_ports), no_dns=bool(no_dns),
                               host_probes=bool(host_probes), gentle=bool(gentle), udp=bool(udp), udp_top=udp_top)
    # Snapshot this machine's outbound public IP for live scans (never called on XML uploads)
    try:
        pub_ip = get_public_ip(max_age=300)
        if pub_ip:
            info['public_ip'] = pub_ip
    except Exception:
        pass
    try:
        return results, (json.dumps(info) if info else None)
    except (TypeError, ValueError):
        return results, None


ACTIVE_STATUSES = ('Queued', 'Running')      # a scan that is waiting for a worker or being run: not finished, cannot be deleted, blocks a second scan of its target


def _job_seq(job):
    """The job number shown as 'Job #N' everywhere on screen — matches the database id in /scan/<id>."""
    return job.id


def _execute_job(job_id):
    """What a scan worker does with one queued job (scan_runner calls it in a worker thread). EVERY way of starting a scan ends here: the New Scan
    form, Rescan, Drill-down, schedules and "run now", the typed chat, the voice command. All settings are columns of the job row.

    The status changes are conditional updates, so a Cancel that arrives at any moment wins: a job cancelled while it waited is never started
    (the claim finds no 'Queued' row), and one cancelled while it ran stays 'Cancelled' whatever the scan returned (the final write only
    touches a row that is still 'Running'). A crash ends as Failed, never as a job that stays 'Running' for ever."""
    with app.app_context():
        claimed = (ScanJob.query.filter(ScanJob.id == job_id, ScanJob.status == 'Queued')
                   .update({'status': 'Running', 'started_at': now_th()}, synchronize_session=False))
        db.session.commit()
        if not claimed:
            return
        job = ScanJob.query.get(job_id)
        args = (job.target, job.scan_type, job.custom_args, job.timing, job.version_intensity, bool(job.multicast), bool(job.skip_ping), bool(job.all_ports), bool(job.no_dns), bool(job.host_probes), bool(job.gentle), bool(job.udp), job.udp_top)
        info_text = None
        try:
            with scan_runner.controlled(job_id, job.scan_type, bool(job.all_ports), bool(job.gentle), bool(job.udp), job.udp_top):
                results, info_text = scan_with_info(*args)
            data = json.loads(results)
            has_error = bool(data and isinstance(data[0], dict) and data[0].get('error'))
        except Exception as e:
            results, has_error = json.dumps([{'error': 'Scan stopped unexpectedly: %s' % e}]), True
        db.session.rollback()
        (ScanJob.query.filter(ScanJob.id == job_id, ScanJob.status == 'Running')
         .update({'status': 'Failed' if has_error else 'Completed', 'result_data': results, 'scan_info': info_text,
                  'finished_at': now_th()}, synchronize_session=False))
        db.session.commit()
        _notify_job_finished(job_id)          # the bell (never raises; nothing for a job that was cancelled)


scan_runner.init(_execute_job)


def enqueue_scan(job):
    """Hands a committed job (status 'Queued') to the background runner. Returns True, or False when the runner could not take it (then the
    job is marked Failed, so it never waits for ever)."""
    try:
        scan_runner.enqueue(job.id)
        return True
    except Exception as e:
        job.status, job.finished_at = 'Failed', now_th()
        job.result_data = json.dumps([{'error': 'Could not start the scan: %s' % e}])
        db.session.commit()
        return False


def recover_interrupted_jobs():
    """Marks every job that was waiting or running as Failed ("interrupted"). The queue lives in memory and a worker dies with its process, so
    a job that is still 'Queued' or 'Running' when a process starts serving requests can only be one that a restart cut off. (nmap itself, if
    it was running, ends by itself.) Returns how many jobs were marked."""
    cut_off = ScanJob.query.filter(ScanJob.status.in_(ACTIVE_STATUSES)).with_entities(ScanJob.id).all()
    n = (ScanJob.query.filter(ScanJob.status.in_(ACTIVE_STATUSES))
         .update({'status': 'Failed', 'finished_at': now_th(),
                  'result_data': json.dumps([{'error': 'Interrupted: the application restarted while this scan was waiting or running.'}])},
                 synchronize_session=False))
    db.session.commit()
    for (job_id,) in cut_off:                  # the bell says so (once per job; never raises)
        try:
            job = ScanJob.query.get(job_id)
            if job and job.owner_id:
                _notify(job.owner_id, 'scan_interrupted', 'scan', 'amber', {'n': _job_seq(job), 'target': job.target}, '/tasks', job.id)
        except Exception:
            db.session.rollback()
    return n


def _scan_started_redirect(job, endpoint='tasks_page', **values):
    """The answer of a form that starts a scan: queue the job and go to the Tasks page at once with a plain notice (the scan runs in the
    background). The flag makes the page announce the job when it finishes even if that happens before the page's first poll."""
    if not enqueue_scan(job):
        flash(tr('flash.scan_start_failed'), 'danger')
        return redirect(url_for(endpoint, **values))
    session['scan_just_finished'] = job.id
    flash(tr('flash.scan_accepted', target=job.target, n=_job_seq(job)), 'success')
    return redirect(url_for(endpoint, **values))


_jobs_recovered = False


@app.before_request
def _recover_jobs_once():
    """Runs recover_interrupted_jobs() once, in the process that actually serves requests (the dev reloader's parent process never does)."""
    global _jobs_recovered
    if _jobs_recovered:
        return
    _jobs_recovered = True
    try:
        recover_interrupted_jobs()
    except Exception as e:
        db.session.rollback()
        print('could not recover interrupted jobs: %s' % e)
    try:
        recover_interrupted_answers()
    except Exception as e:
        db.session.rollback()
        print('could not recover interrupted answers: %s' % e)


def scan_run_info(job):
    """What the scan reported about its own run (ScanJob.scan_info), cleaned for display; {} when nothing was recorded (an older job).
    Every key is optional, and a key that is missing means "not recorded", never zero or False."""
    try:
        raw = json.loads(job.scan_info) if job.scan_info else {}
    except ValueError:
        raw = {}
    if not isinstance(raw, dict):
        return {}
    out = {}
    if isinstance(raw.get('nmap'), str) and raw['nmap']:
        out['nmap'] = raw['nmap'][:20]
    for key in ('checked', 'up', 'down', 'no_evidence', 'arp_only_total', 'timed_out', 'ports_scanned', 'udp_hosts', 'udp_timed_out', 'udp_not_scanned', 'udp_ports'):
        if isinstance(raw.get(key), int) and not isinstance(raw.get(key), bool) and raw[key] >= 0:
            out[key] = raw[key]
    if isinstance(raw.get('elapsed'), (int, float)) and not isinstance(raw.get('elapsed'), bool) and raw['elapsed'] >= 0:
        out['elapsed'] = round(float(raw['elapsed']), 1)
    for key in ('admin', 'npcap', 'skip_ping', 'no_dns', 'host_probes', 'gentle', 'udp', 'udp_failed'):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    if isinstance(raw.get('udp_error'), str) and raw['udp_error']:
        out['udp_error'] = raw['udp_error'][:200]
    pub_raw = raw.get('public_ip')
    if isinstance(pub_raw, str) and pub_raw.strip():
        try:
            addr = ipaddress.ip_address(pub_raw.strip())
            if not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
                out['public_ip'] = str(addr)
        except ValueError:
            pass
    rows = raw.get('arp_only')
    if isinstance(rows, list):
        out['arp_only'] = [{'ip': str(r.get('ip') or '')[:45], 'mac': str(r.get('mac') or '')[:17], 'vendor': str(r.get('vendor') or '')[:60]}
                           for r in rows[:ARP_ONLY_MAX] if isinstance(r, dict) and r.get('ip')]
    return out


def describe_run(job, lang=None):
    """The scan's own report of its run in `lang` (defaults to the active UI language), for Tasks and scan detail pages:
    {'summary', 'nmap', 'elapsed', 'notes': [{'kind': 'warn' | 'info', 'text'}], 'arp_only': [...], 'arp_only_total'}.
    It says only what was recorded: a job from before scan_info existed gives empty parts, never a guess."""
    lang = lang if lang in i18n.LANGS else ui_lang_now()
    say = lambda key, **kw: i18n.t(key, lang, **kw)
    run = scan_run_info(job)
    skip = bool(run.get('skip_ping') or job.skip_ping)
    n = lambda v: format(v, ',')
    parts = []
    if 'checked' in run:
        parts.append(say('run.checked_skip' if skip else 'run.checked', n=n(run['checked'])))
        if skip:
            if 'up' in run:
                parts.append(say('run.up_evidence', n=n(run['up'])))
            if 'no_evidence' in run:
                parts.append(say('run.no_evidence', n=n(run['no_evidence'])))
        else:
            if 'up' in run:
                parts.append(say('run.up_reply', n=n(run['up'])))
            if 'down' in run:
                parts.append(say('run.down_reply', n=n(run['down'])))
    notes = []
    if run.get('admin') is False:
        notes.append({'kind': 'warn', 'text': say('run.note.not_admin')})
    if run.get('npcap') is False:
        notes.append({'kind': 'warn', 'text': say('run.note.no_npcap')})
    if skip and run.get('no_evidence'):
        notes.append({'kind': 'info', 'text': say('run.note.skip_no_evidence', n=n(run['no_evidence']))})
    elif (not skip and job.scan_type in ('fast_scan', 'intense', 'vuln_scan', 'custom') and run.get('down')
          and run.get('checked', 10 ** 9) <= 8):
        notes.append({'kind': 'info', 'text': say('run.note.suggest_pn', n=n(run['down']))})
    if run.get('host_probes') is True:
        notes.append({'kind': 'info', 'text': say('run.note.host_probes')})
    if run.get('gentle') is True:
        notes.append({'kind': 'info', 'text': say('run.note.gentle')})
    udp_top = getattr(job, 'udp_top', None)
    udp_top = udp_top if udp_top in (100, 1000) else None
    if run.get('udp') is True:
        if udp_top:      # nmap's top N: the count nmap really scanned (it follows the installed nmap-services), else the number asked for
            notes.append({'kind': 'info', 'text': say('run.note.udp_top', n=n(run.get('udp_ports') or udp_top))})
        else:
            notes.append({'kind': 'info', 'text': say('run.note.udp')})
    if run.get('udp_failed') is True:
        msg = say('run.note.udp_failed_cause', cause=run['udp_error']) if run.get('udp_error') else say('run.note.udp_failed')
        notes.append({'kind': 'warn', 'text': msg})
    if run.get('udp_not_scanned'):
        notes.append({'kind': 'warn', 'text': say('run.note.udp_not_scanned', n=n(run['udp_not_scanned']))})
    if run.get('udp_timed_out'):
        notes.append({'kind': 'warn', 'text': say('run.note.udp_timed_out', n=n(run['udp_timed_out']), minutes=udp_host_timeout_minutes(udp_top))})
    if run.get('no_dns') is True:
        notes.append({'kind': 'info', 'text': say('run.note.no_dns')})
    if run.get('ports_scanned') == 65535:
        notes.append({'kind': 'info', 'text': say('run.note.all_ports')})
    if run.get('timed_out'):
        notes.append({'kind': 'warn', 'text': say('run.note.timed_out', n=n(run['timed_out']))})
    if run.get('arp_only_total'):
        notes.append({'kind': 'info', 'text': say('run.note.arp_only', n=n(run['arp_only_total']))})
    return {'summary': ' · '.join(parts), 'nmap': run.get('nmap'), 'elapsed': run.get('elapsed'), 'notes': notes,
            'arp_only': run.get('arp_only', []), 'arp_only_total': run.get('arp_only_total', 0)}


_TIME_UNIT_TH = {'hour': 'ชั่วโมง', 'hours': 'ชั่วโมง', 'minute': 'นาที', 'minutes': 'นาที', 'second': 'วินาที', 'seconds': 'วินาที'}


def localized_job_error(err, lang=None):
    """Display stored runtime scan failure reasons in the viewer's language without altering the stored record."""
    lang = lang if lang in i18n.LANGS else ui_lang_now()
    s = str(err or '')[:500]
    if not s:
        return ''
    if s == 'Interrupted: the application restarted while this scan was waiting or running.':
        return i18n.t('job_err.interrupted', lang)
    if s.startswith('Could not start the scan: '):
        return i18n.t('job_err.start_failed', lang, detail=s[len('Could not start the scan: '):])
    if s.startswith('Scan stopped unexpectedly: '):
        return i18n.t('job_err.stopped', lang, detail=s[len('Scan stopped unexpectedly: '):])
    m = re.match(r'^Scan stopped: it ran longer than its time limit \(([^)]+)\)\.$', s)
    if m:
        limit = m.group(1)
        if lang != 'en':
            limit = re.sub(r'\b(hours?|minutes?|seconds?)\b', lambda mm: _TIME_UNIT_TH.get(mm.group(1), mm.group(1)), limit)
        return i18n.t('job_err.time_limit', lang, limit=limit)
    return s


def _stored_hosts(job):
    """The host list stored for a job, or None when it has none to use (still running, failed, an error result, unreadable text)."""
    try:
        data = json.loads(job.result_data) if job.result_data else None
    except ValueError:
        return None
    if not isinstance(data, list) or (data and isinstance(data[0], dict) and data[0].get('error')):
        return None
    return [h for h in data if isinstance(h, dict)]


def previous_comparable_job(job, base_query=None):
    """The newest EARLIER completed scan the user may see that can be compared with `job`: same target, same scan type, same -Pn choice and, for a
    Custom scan, the same arguments (scan_diff.comparable_key). None when there is none (the first scan of its kind). `base_query` replaces
    visible_scans_query() where there is no request (the worker that makes the bell's notifications passes the owner's own scans)."""
    if job.timestamp is None or job.status != 'Completed' or job.scan_type in (None, 'xml_upload'):
        return None
    key = scan_diff.comparable_key(job.scan_type, job.target, job.skip_ping, job.custom_args, job.all_ports, job.host_probes, job.gentle, job.udp, job.udp_top)
    q = ((base_query if base_query is not None else visible_scans_query())
         .filter(ScanJob.id != job.id, ScanJob.status == 'Completed', ScanJob.scan_type == job.scan_type, ScanJob.target == job.target,
                 ScanJob.result_data.isnot(None), ScanJob.timestamp <= job.timestamp)
         .options(defer(ScanJob.result_data))          # the candidates' (large) results are read only for the one that is picked
         .order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()))
    for cand in q.limit(60):
        if (cand.timestamp, cand.id) >= (job.timestamp, job.id):
            continue
        if scan_diff.comparable_key(cand.scan_type, cand.target, cand.skip_ping, cand.custom_args, cand.all_ports, cand.host_probes, cand.gentle, cand.udp, cand.udp_top) == key and _stored_hosts(cand) is not None:
            return cand
    return None


def scan_changes(job, base_query=None):
    """What changed between `job` and the scan before it of the same kind: {'prev': {id, seq, when}, 'job': {id, seq}, 'diff': scan_diff result},
    or None when there is nothing to compare with."""
    prev = previous_comparable_job(job, base_query)
    now_hosts = _stored_hosts(job)
    if prev is None or now_hosts is None:
        return None
    diff = scan_diff.compare_scans({'scan_type': job.scan_type, 'hosts': _stored_hosts(prev)}, {'scan_type': job.scan_type, 'hosts': now_hosts},
                                   scan_run_info(prev).get('admin'), scan_run_info(job).get('admin'))
    seq = _owner_seq_map({o for o in (job.owner_id, prev.owner_id) if o is not None})
    return {'prev': {'id': prev.id, 'seq': seq.get(prev.id, prev.id), 'when': prev.timestamp.strftime('%Y-%m-%d %H:%M') if prev.timestamp else ''},
            'job': {'id': job.id, 'seq': seq.get(job.id, job.id), 'target': job.target, 'type': job.scan_type,
                    'when': job.timestamp.strftime('%Y-%m-%d %H:%M') if job.timestamp else ''},
            'diff': diff}


# ─────────────────────────────────────────
#  The bell: Activity notifications (2026-11-17, the owner picked option B of docs/design-options/notification-bell/)
# ─────────────────────────────────────────
# A Notification row is made when something happens (a scan ends, a comparison with the scan before finds a new device or a new serious CVE) for
# the owner of the scan AND for every plain user that owner created (they see the owner's scans), so each person has their own read state. The
# row holds a kind and JSON parameters; the Thai / English text is made when the panel asks for it (locales notif.<kind>), so it follows the
# reader's language. Everything is wrapped so a failure here can never break a scan. System warnings (no Administrator, no Npcap) are not
# events: the panel shows them from the live check, with no read state.

NOTIF_KEEP_DAYS = 30
NOTIF_KEEP_MAX = 200
NOTIF_LIST_MAX = 40


def _notify(owner_id, kind, cat, tone, params=None, link=None, job_id=None):
    """Adds one notification for the scan owner and the users that owner created. Never raises."""
    if not owner_id:
        return
    try:
        text = json.dumps(params or {}, ensure_ascii=False)
        recipients = [owner_id] + [uid for (uid,) in User.query.filter(User.created_by == owner_id).with_entities(User.id).all()]
        for uid in recipients:
            db.session.add(Notification(user_id=uid, kind=kind, cat=cat, tone=tone, params=text, link=link, job_id=job_id))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _notify_job_finished(job_id):
    """Called by a worker right after a job ended: 'scan finished' or 'scan failed', then what changed since the scan before it (new devices,
    new Critical / High CVEs, new CISA KEV CVEs). A job that was cancelled makes none."""
    try:
        job = ScanJob.query.get(job_id)
        if not job or not job.owner_id or job.status not in ('Completed', 'Failed'):
            return
        owner = job.owner_id
        n = _job_seq(job)
        link = '/scan/%d' % job.id
        base = {'n': n, 'target': job.target, 'type': job.scan_type,
                'schedule': (job.scan_name or '') if job.triggered_by == 'schedule' else ''}
        if job.status == 'Failed':
            _notify(owner, 'scan_failed', 'scan', 'amber', base, '/tasks', job.id)
            return
        hosts = _stored_hosts(job)
        _notify(owner, 'scan_done', 'scan', 'ok', dict(base, hosts=len(hosts) if hosts is not None else None), link, job.id)
        change = scan_changes(job, ScanJob.query.filter_by(owner_id=owner))
        if not change:
            return
        diff, counts = change['diff'], change['diff']['counts']
        if counts['new_devices']:
            first = diff['new_devices'][0]['ip'] if diff['new_devices'] else ''
            _notify(owner, 'new_devices', 'device', 'info', {'n': counts['new_devices'], 'ip': first if counts['new_devices'] == 1 else '', 'seq': n, 'target': job.target},
                    ('/devices/%s' % first) if counts['new_devices'] == 1 and first else link, job.id)
        rows = diff['new_cves']
        crit = sum(1 for r in rows if r['severity'] == 'CRITICAL')
        high = sum(1 for r in rows if r['severity'] == 'HIGH')
        if crit or high:
            ips = {r['ip'] for r in rows if r['severity'] in ('CRITICAL', 'HIGH')}
            one = next(iter(ips)) if len(ips) == 1 else ''
            _notify(owner, 'new_cves', 'vuln', 'crit' if crit else 'amber', {'crit': crit, 'high': high, 'ip': one, 'seq': n},
                    ('/devices/%s' % one) if one else link, job.id)
        if counts['new_kev']:
            _notify(owner, 'new_kev', 'vuln', 'amber', {'n': counts['new_kev'], 'seq': n}, link, job.id)
    except Exception:
        db.session.rollback()


def _ago_text(created, now):
    sec = max(0, int((now - created).total_seconds())) if created else 0
    if sec < 60:
        return tr('notif.ago.now')
    if sec < 3600:
        return tr('notif.ago.min', n=sec // 60)
    if sec < 86400:
        return tr('notif.ago.hour', n=sec // 3600)
    if sec < 7 * 86400:
        return tr('notif.ago.day', n=sec // 86400)
    return fmt_dt(created, '%Y-%m-%d')


_NOTIF_ICON = {'scan_done': 'circle-check', 'scan_failed': 'alert-triangle', 'scan_interrupted': 'alert-triangle', 'new_devices': 'device-desktop',
               'new_cves': 'shield-exclamation', 'new_kev': 'flame', 'system': 'alert-triangle'}


def _notif_view(n, now):
    """One notification as the panel draws it: text, a second line, an optional tag, an icon, a tone, a link and the time."""
    try:
        p = json.loads(n.params) if n.params else {}
    except ValueError:
        p = {}
    if not isinstance(p, dict):
        p = {}
    meta, tag = '', None
    target = str(p.get('target') or '')
    if n.kind == 'scan_done':
        text = tr('notif.scan_done', n=p.get('n', ''))
        parts = [target]
        if isinstance(p.get('hosts'), int):
            parts.append(tr('notif.m.host_one' if p['hosts'] == 1 else 'notif.m.hosts', n=p['hosts']))
        if p.get('schedule'):
            parts.append(tr('notif.m.schedule', name=p['schedule']))
        meta = ' · '.join(x for x in parts if x)
    elif n.kind == 'scan_failed':
        text, meta = tr('notif.scan_failed', n=p.get('n', '')), target
    elif n.kind == 'scan_interrupted':
        text, meta = tr('notif.scan_interrupted', n=p.get('n', '')), ' · '.join(x for x in (target, tr('notif.m.restarted')) if x)
    elif n.kind == 'new_devices':
        count = int(p.get('n') or 0)
        text = tr('notif.new_device_one', ip=p.get('ip', '')) if count == 1 and p.get('ip') else tr('notif.new_devices', n=count)
        meta = tr('notif.m.job', n=p.get('seq', '')) + (' · ' + target if target else '')
    elif n.kind == 'new_cves':
        crit, high = int(p.get('crit') or 0), int(p.get('high') or 0)
        k = crit + high
        text = tr('notif.new_cves_ip', ip=p['ip'], n=k) if p.get('ip') else tr('notif.new_cves', n=k)
        c_lbl, h_lbl = sev_label('CRITICAL'), sev_label('HIGH')
        meta = ' · '.join(x for x in (('%s %d' % (c_lbl, crit)) if crit else '', ('%s %d' % (h_lbl, high)) if high else '', tr('notif.m.job', n=p.get('seq', ''))) if x)
        tag = [c_lbl, 'crit'] if crit else [h_lbl, 'high']
    elif n.kind == 'new_kev':
        text, meta, tag = tr('notif.new_kev', n=p.get('n', '')), tr('notif.m.job', n=p.get('seq', '')), [tr('notif.tag.kev'), 'kev']
    else:
        text = n.kind
    return {'id': n.id, 'kind': n.kind, 'cat': n.cat, 'tone': n.tone, 'icon': _NOTIF_ICON.get(n.kind, 'bell'), 'text': text, 'meta': meta, 'tag': tag,
            'link': n.link or '', 'time': _ago_text(n.created_at, now), 'unread': n.read_at is None}


def _progress_line(p):
    """(text, percent or None) for one entry of api_jobs_progress, worded with the Tasks page's own texts (tasks.js.*)."""
    if not p:
        return '', None
    if p.get('state') == 'queued':
        return (tr('tasks.js.p_queued_pos', n=p['position']) if p.get('position') else tr('tasks.js.p_queued')), None
    nvd = p.get('nvd')
    if nvd and nvd.get('total', 0) > 0:
        return tr('tasks.js.p_nvd', done=nvd['done'], total=nvd['total']), round(100 * nvd['done'] / nvd['total'])
    if p.get('task') is not None and p.get('percent') is not None:
        task = str(p['task'])
        words = None
        for pattern, key in ((r'^(arp )?ping scan', 'w_ping'), (r'^parallel dns', 'w_dns'), (r'udp scan', 'w_udp'),
                             (r'(connect|syn stealth|ack|window|fin|null|xmas|maimon|sctp \w+) scan', 'w_ports'), (r'^service scan', 'w_service'),
                             (r'^(nse|script)', 'w_nse'), (r'^traceroute', 'w_trace')):
            if re.search(pattern, task, re.I):
                words = tr('tasks.js.' + key)
                break
        text = '%s %d%%' % (words or task or tr('tasks.js.p_scanning'), round(p['percent']))
        if p.get('remaining_s') is not None:
            sec = p['remaining_s']
            left = tr('tasks.js.p_left_sec', n=max(1, sec)) if sec < 60 else tr('tasks.js.p_left_min', n=-(-sec // 60))
            text += tr('tasks.js.p_left_step', left=left)
        return text, p['percent']
    if p.get('elapsed_s') is not None:
        s = p['elapsed_s']
        clock = ('%d:%02d:%02d' % (s // 3600, (s % 3600) // 60, s % 60)) if s >= 3600 else ('%d:%02d' % (s // 60, s % 60))
        return tr('tasks.js.p_elapsed', t=clock), None
    return tr('tasks.js.p_scanning'), None


@app.route('/api/notifications')
@login_required
def api_notifications():
    """The bell. ?brief=1 answers only the two counts (the badge polls this); without it the panel's whole content: the running scans with their
    progress, the system warnings and the newest notifications (read or not). Old ones are deleted here (NOTIF_KEEP_DAYS days, NOTIF_KEEP_MAX each)."""
    now = now_th()
    unread = Notification.query.filter_by(user_id=current_user.id, read_at=None).count()
    active = visible_scans_query().filter(ScanJob.status.in_(ACTIVE_STATUSES))
    out = {'unread': unread, 'running_count': active.count()}
    if not request.args.get('brief'):
        try:
            Notification.query.filter(Notification.user_id == current_user.id, Notification.created_at < now - timedelta(days=NOTIF_KEEP_DAYS)).delete(synchronize_session=False)
            keep = [i for (i,) in Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(NOTIF_KEEP_MAX).with_entities(Notification.id).all()]
            if len(keep) >= NOTIF_KEEP_MAX:
                Notification.query.filter(Notification.user_id == current_user.id, Notification.id < min(keep)).delete(synchronize_session=False)
            db.session.commit()
        except Exception:
            db.session.rollback()
        progress = api_jobs_progress().get_json() or {}
        jobs = active.order_by(ScanJob.timestamp).all()
        seq = _owner_seq_map({j.owner_id for j in jobs if j.owner_id is not None}) if jobs else {}
        running = []
        for j in jobs:
            text, pct = _progress_line(progress.get(str(j.id)))
            running.append({'id': j.id, 'n': seq.get(j.id, j.id), 'target': j.target, 'state': 'queued' if j.status == 'Queued' else 'running', 'text': text, 'percent': pct})
        items = [_notif_view(n, now) for n in Notification.query.filter_by(user_id=current_user.id)
                 .order_by(Notification.created_at.desc(), Notification.id.desc()).limit(NOTIF_LIST_MAX).all()]
        system = [{'id': 'sys%d' % i, 'kind': 'system', 'cat': 'system', 'tone': 'amber', 'icon': 'alert-triangle', 'text': w.get('text', ''), 'meta': '', 'tag': None,
                   'link': '/tasks', 'time': '', 'unread': False} for i, w in enumerate(localized_scan_warnings())]
        out.update({'running': running, 'items': items, 'system': system})
    resp = jsonify(out)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/notifications/read', methods=['POST'])
@login_required
def api_notifications_read():
    """Marks notifications read for the caller only: {"all": true} or {"ids": [..]}. JSON only (no CSRF exists, a form post is a 400)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'JSON required'}), 400
    q = Notification.query.filter_by(user_id=current_user.id, read_at=None)
    if data.get('all') is True:
        pass
    elif isinstance(data.get('ids'), list):
        ids = [i for i in data['ids'][:100] if isinstance(i, int) and not isinstance(i, bool)]
        q = q.filter(Notification.id.in_(ids))
    else:
        return jsonify({'error': 'all or ids required'}), 400
    q.update({'read_at': now_th()}, synchronize_session=False)
    db.session.commit()
    return jsonify({'ok': True, 'unread': Notification.query.filter_by(user_id=current_user.id, read_at=None).count()})


def execute_scheduled_scan(schedule_id, monthly_guard=False):
    with app.app_context():
        schedule = ScheduledScan.query.get(schedule_id)
        if not schedule or not schedule.is_active:
            return
        owner = User.query.get(schedule.owner_id) if schedule.owner_id else None
        if owner is not None and owner.is_suspended:      # a suspended account's schedules wait (they stay saved and run again after it is reactivated)
            return
        if monthly_guard:                 # a monthly schedule for day 29 to 31 fires on days 28 to 31 (see register_apscheduler_job): run only on its day
            today = now_th()
            if today.day != monthly_run_day(today.year, today.month, schedule.day_of_month):
                return

        new_job = ScanJob(
            target=schedule.target,
            scan_type=schedule.scan_type,
            scan_name=schedule.name,
            status='Queued',
            triggered_by='schedule',
            owner_id=schedule.owner_id,
            timing=schedule.timing,
            version_intensity=schedule.version_intensity,
            custom_args=schedule.custom_args if schedule.scan_type == 'custom' else None,
            multicast=False if schedule.scan_type == 'discovery' else None,   # a schedule never listens for mDNS/SSDP
            skip_ping=job_skip_ping(schedule.scan_type, schedule.custom_args, '1' if schedule.skip_ping else ''),
            all_ports=job_all_ports(schedule.scan_type, '1' if schedule.all_ports else ''),
            no_dns=job_no_dns(schedule.scan_type, '1' if schedule.no_dns else ''),
            host_probes=job_probes(schedule.scan_type, '1' if schedule.host_probes else ''),
            gentle=job_gentle(schedule.scan_type, '1' if schedule.gentle else ''),
            udp=job_udp(schedule.scan_type, '1' if schedule.udp else ''),
            udp_top=job_udp_top(schedule.scan_type, job_udp(schedule.scan_type, '1' if schedule.udp else ''), schedule.udp_top),
        )
        db.session.add(new_job)
        schedule.last_run = now_th()
        schedule.next_run = calc_next_run(schedule)
        db.session.commit()
        enqueue_scan(new_job)         # the scan runs in a worker; the scheduler thread is free at once


def register_apscheduler_job(schedule):
    job_id = f'schedule_{schedule.id}'
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    if not schedule.is_active:
        return

    if schedule.repeat == 'daily':
        trigger = CronTrigger(hour=schedule.cron_hour, minute=schedule.cron_minute)
    elif schedule.repeat == 'weekly':
        trigger = CronTrigger(day_of_week=schedule.day_of_week,
                              hour=schedule.cron_hour, minute=schedule.cron_minute)
    elif schedule.repeat == 'monthly':
        dom = int(schedule.day_of_month or 1)
        # A plain cron day of 29, 30 or 31 SKIPS every month that is shorter (day 31 never runs in February, April, June, September, November).
        # Those days fire on each of the days 28 to 31 instead and execute_scheduled_scan(..., monthly_guard=True) runs the scan only on the one
        # that is this month's run day (the chosen day, or the last day of a shorter month).
        trigger = CronTrigger(day='28-31' if dom >= 29 else dom,
                              hour=schedule.cron_hour, minute=schedule.cron_minute)
    else:
        return

    scheduler.add_job(func=execute_scheduled_scan, trigger=trigger,
                      args=[schedule.id, schedule.repeat == 'monthly' and int(schedule.day_of_month or 1) >= 29],
                      id=job_id, replace_existing=True)


_USER_SETTING_PREFIXES = ('ui_theme.', 'ui_lang.', 'chat_button_hidden.', 'chat_hint_seen.', 'voice_autorun.')


def _ensure_user_autoincrement(con):
    """Upgrade an existing SQLite `user` table to INTEGER PRIMARY KEY AUTOINCREMENT once, so deleted user IDs are never reused."""
    cur = con.cursor()
    row = cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='user'").fetchone()
    if not row or 'AUTOINCREMENT' in (row[0] or '').upper():
        return
    con.commit()
    con.execute("PRAGMA foreign_keys = OFF")
    try:
        cur.execute("BEGIN")
        cur.execute("""
            CREATE TABLE user_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20),
                created_by INTEGER REFERENCES user(id),
                created_at DATETIME,
                is_suspended BOOLEAN DEFAULT 0,
                suspended_at DATETIME
            )
        """)
        old_count = cur.execute("SELECT COUNT(*) FROM user").fetchone()[0]
        cur.execute("""
            INSERT INTO user_new (id, username, password_hash, role, created_by, created_at, is_suspended, suspended_at)
            SELECT id, username, password_hash, role, created_by, created_at, is_suspended, suspended_at FROM user
        """)
        new_count = cur.execute("SELECT COUNT(*) FROM user_new").fetchone()[0]
        if new_count != old_count:
            raise RuntimeError("user autoincrement migration row count mismatch")
        cur.execute("DROP TABLE user")
        cur.execute("ALTER TABLE user_new RENAME TO user")
        max_uid = cur.execute("SELECT COALESCE(MAX(id), 0) FROM user").fetchone()[0]
        cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('user', 'user_new')")
        if max_uid > 0:
            cur.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('user', ?)", (max_uid,))
        con.commit()
    except Exception:
        con.rollback()
        raise


def _sweep_orphaned_user_data():
    """Remove per-user records left behind by accounts deleted before full cleanup existed."""
    live_ids = {uid for (uid,) in User.query.with_entities(User.id).all()}
    if not live_ids:
        return
    HistoryQuery.query.filter(~HistoryQuery.owner_id.in_(live_ids)).delete(synchronize_session=False)
    Notification.query.filter(~Notification.user_id.in_(live_ids)).delete(synchronize_session=False)
    ChatAnswer.query.filter(~ChatAnswer.user_id.in_(live_ids)).delete(synchronize_session=False)
    GeminiCall.query.filter(GeminiCall.user_id.isnot(None), ~GeminiCall.user_id.in_(live_ids)).update(
        {'user_id': None}, synchronize_session=False
    )
    stale_keys = []
    for (k,) in AppSetting.query.with_entities(AppSetting.key).all():
        for prefix in _USER_SETTING_PREFIXES:
            if k.startswith(prefix):
                suffix = k[len(prefix):]
                if suffix.isdigit() and int(suffix) not in live_ids:
                    stale_keys.append(k)
                break
    if stale_keys:
        AppSetting.query.filter(AppSetting.key.in_(stale_keys)).delete(synchronize_session=False)
    bad_targets = [s.id for s in SavedTarget.query.all() if not is_valid_target(s.target)]
    if bad_targets:
        SavedTarget.query.filter(SavedTarget.id.in_(bad_targets)).delete(synchronize_session=False)
    db.session.commit()


def _purge_user_data(uids, usernames=()):
    """Delete or unlink every piece of per-user state owned by the given user IDs inside the caller's transaction."""
    if not uids:
        return
    for s in ScheduledScan.query.filter(ScheduledScan.owner_id.in_(uids)).all():
        job_id = f'schedule_{s.id}'
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)
    ScanJob.query.filter(ScanJob.owner_id.in_(uids)).delete(synchronize_session=False)
    ScheduledScan.query.filter(ScheduledScan.owner_id.in_(uids)).delete(synchronize_session=False)
    HistoryQuery.query.filter(HistoryQuery.owner_id.in_(uids)).delete(synchronize_session=False)
    Notification.query.filter(Notification.user_id.in_(uids)).delete(synchronize_session=False)
    ChatAnswer.query.filter(ChatAnswer.user_id.in_(uids)).delete(synchronize_session=False)
    GeminiCall.query.filter(GeminiCall.user_id.in_(uids)).update({'user_id': None}, synchronize_session=False)
    setting_keys = [f'{prefix}{uid}' for uid in uids for prefix in _USER_SETTING_PREFIXES]
    AppSetting.query.filter(AppSetting.key.in_(setting_keys)).delete(synchronize_session=False)
    throttle_keys = [f'user:{u.strip().lower()}' for u in usernames if u and u.strip()]
    if throttle_keys:
        LoginThrottle.query.filter(LoginThrottle.key.in_(throttle_keys)).delete(synchronize_session=False)


# ─────────────────────────────────────────
#  Init DB
# ─────────────────────────────────────────

with app.app_context():
    db.create_all()

    import sqlite3, os
    db_path = os.path.join(app.instance_path, 'scanner.db')
    if os.path.exists(db_path):
        con = sqlite3.connect(db_path)
        cur = con.cursor()

        # Migration: scan_job
        cols = [r[1] for r in cur.execute("PRAGMA table_info(scan_job)")]
        if 'scan_name' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN scan_name VARCHAR(150)")
        if 'owner_id' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN owner_id INTEGER REFERENCES user(id)")
        if 'timing' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN timing INTEGER")
        if 'version_intensity' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN version_intensity INTEGER")
        if 'custom_args' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN custom_args VARCHAR(500)")
        if 'multicast' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN multicast BOOLEAN")
        if 'finished_at' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN finished_at DATETIME")
        if 'skip_ping' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN skip_ping BOOLEAN")
        if 'all_ports' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN all_ports BOOLEAN")
        if 'no_dns' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN no_dns BOOLEAN")
        if 'host_probes' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN host_probes BOOLEAN")
        if 'gentle' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN gentle BOOLEAN")
        if 'udp' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN udp BOOLEAN")
        if 'udp_top' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN udp_top INTEGER")
        if 'scan_info' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN scan_info TEXT")
        if 'started_at' not in cols:
            cur.execute("ALTER TABLE scan_job ADD COLUMN started_at DATETIME")

        # Migration: scheduled_scan
        cols2 = [r[1] for r in cur.execute("PRAGMA table_info(scheduled_scan)")]
        if 'owner_id' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN owner_id INTEGER REFERENCES user(id)")
        if 'custom_args' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN custom_args VARCHAR(500)")
        if 'timing' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN timing INTEGER")
        if 'version_intensity' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN version_intensity INTEGER")
        if 'skip_ping' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN skip_ping BOOLEAN")
        if 'all_ports' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN all_ports BOOLEAN")
        if 'no_dns' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN no_dns BOOLEAN")
        if 'host_probes' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN host_probes BOOLEAN")
        if 'gentle' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN gentle BOOLEAN")
        if 'udp' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN udp BOOLEAN")
        if 'udp_top' not in cols2:
            cur.execute("ALTER TABLE scheduled_scan ADD COLUMN udp_top INTEGER")

        # Migration: user
        cols3 = [r[1] for r in cur.execute("PRAGMA table_info(user)")]
        if 'created_by' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_by INTEGER REFERENCES user(id)")
        if 'created_at' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")
        if 'is_suspended' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN is_suspended BOOLEAN DEFAULT 0")
        if 'suspended_at' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN suspended_at DATETIME")

        con.commit()
        _ensure_user_autoincrement(con)
        con.close()
        db.engine.dispose()

    # สร้าง superadmin ถ้ายังไม่มี
    if not User.query.filter_by(role='superadmin').first():
        hashed_pw = generate_password_hash('admin123')
        superadmin = User(username='admin', password_hash=hashed_pw, role='superadmin')
        db.session.add(superadmin)
        db.session.commit()

    # ล้างข้อมูลค้างของบัญชีที่เคยถูกลบไปก่อนหน้า
    _sweep_orphaned_user_data()

    # migrate: user เดิมที่เป็น role='admin' และไม่มี owner_id ใน scan → set owner_id
    # (กรณี upgrade จาก version เก่า ให้ผูก scan เก่ากับ superadmin)
    superadmin_user = User.query.filter_by(role='superadmin').first()
    if superadmin_user:
        ScanJob.query.filter_by(owner_id=None).update({'owner_id': superadmin_user.id})
        ScheduledScan.query.filter_by(owner_id=None).update({'owner_id': superadmin_user.id})
        db.session.commit()

    for s in ScheduledScan.query.filter_by(is_active=True).all():
        register_apscheduler_job(s)


# ─────────────────────────────────────────
#  AUTH
# ─────────────────────────────────────────

LOGIN_USER_MAX_ATTEMPTS = 5
LOGIN_USER_LOCK_MINUTES = 5
LOGIN_IP_MAX_ATTEMPTS = 10
LOGIN_IP_LOCK_MINUTES = 10


def _login_client_ip():
    return (request.remote_addr or 'unknown').strip()[:64]


def _login_throttle_keys(username_norm, ip):
    keys = []
    if username_norm:
        keys.append((f'user:{username_norm[:100]}', LOGIN_USER_MAX_ATTEMPTS, LOGIN_USER_LOCK_MINUTES))
    if ip:
        keys.append((f'ip:{ip}', LOGIN_IP_MAX_ATTEMPTS, LOGIN_IP_LOCK_MINUTES))
    return keys


def _login_lock_remaining(username_norm, ip, now=None):
    """Remaining lockout seconds across username and IP throttles (0 if not locked)."""
    now = now or now_th()
    keys = [k for k, _, _ in _login_throttle_keys(username_norm, ip)]
    if not keys:
        return 0
    rows = LoginThrottle.query.filter(LoginThrottle.key.in_(keys)).all()
    remaining = 0
    for row in rows:
        if row.locked_until and row.locked_until > now:
            sec = int(math.ceil((row.locked_until - now).total_seconds()))
            if sec > remaining:
                remaining = sec
    return remaining


def _record_login_failure(username_norm, ip, now=None):
    """Record a failed login attempt against both username and IP. Returns lockout seconds if a limit was just reached."""
    now = now or now_th()
    stale_cutoff = now - timedelta(minutes=max(LOGIN_USER_LOCK_MINUTES, LOGIN_IP_LOCK_MINUTES))
    LoginThrottle.query.filter(
        LoginThrottle.first_failed_at < stale_cutoff,
        db.or_(LoginThrottle.locked_until.is_(None), LoginThrottle.locked_until <= now),
    ).delete(synchronize_session=False)

    remaining = 0
    for key, max_attempts, lock_minutes in _login_throttle_keys(username_norm, ip):
        row = LoginThrottle.query.get(key)
        if row is None:
            row = LoginThrottle(key=key, failures=0)
            db.session.add(row)
        window = timedelta(minutes=lock_minutes)
        if row.locked_until and row.locked_until <= now:
            row.failures = 0
            row.first_failed_at = None
            row.locked_until = None
        elif row.first_failed_at and (now - row.first_failed_at) >= window:
            row.failures = 0
            row.first_failed_at = None
        row.failures += 1
        if row.first_failed_at is None:
            row.first_failed_at = now
        if row.failures >= max_attempts:
            row.locked_until = now + window
            sec = int(math.ceil((row.locked_until - now).total_seconds()))
            if sec > remaining:
                remaining = sec
    db.session.commit()
    return remaining


def _clear_user_login_throttle(username):
    """Clear the per-username brute-force counter (called on valid sign-in or admin password reset)."""
    norm = (username or '').strip().lower()
    if norm:
        LoginThrottle.query.filter_by(key=f'user:{norm[:100]}').delete(synchronize_session=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        raw_username = request.form.get('username') or ''
        raw_password = request.form.get('password') or ''
        username_norm = raw_username.strip().lower()
        ip = _login_client_ip()

        wait_sec = _login_lock_remaining(username_norm, ip)
        if wait_sec > 0:
            wait_min = max(1, math.ceil(wait_sec / 60))
            flash(tr('flash.login_locked', minutes=wait_min))
            return render_template('login.html'), 429, {'Retry-After': str(wait_sec)}

        user = User.query.filter_by(username=raw_username).first()
        if user and check_password_hash(user.password_hash, raw_password):
            if user.is_suspended:          # said only after the password was right, so the message does not reveal which names exist
                flash(tr('flash.account_suspended'))
                return render_template('login.html')
            _clear_user_login_throttle(user.username)
            db.session.commit()
            login_user(user)
            session.pop('csrf_token', None)  # rotate CSRF token on sign-in
            return redirect(url_for('dashboard'))

        lock_sec = _record_login_failure(username_norm, ip)
        if lock_sec > 0:
            wait_min = max(1, math.ceil(lock_sec / 60))
            flash(tr('flash.login_locked', minutes=wait_min))
            return render_template('login.html'), 429, {'Retry-After': str(lock_sec)}
        flash(tr('flash.login_invalid'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.pop('csrf_token', None)
    return redirect(url_for('login'))


# ─────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────

_INV_SEV_RANK = {'LOW': 1, 'UNKNOWN': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}


def _parse_job_hosts(job):
    """Valid host dicts (with a non-empty IP) from a completed ScanJob's result_data."""
    if not job or not job.result_data:
        return []
    if job.status and job.status != 'Completed':
        return []
    try:
        data = json.loads(job.result_data)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [d for d in data if isinstance(d, dict) and d.get('ip')]


def _build_device_inventory(history):
    """Single source of truth for physical devices, their latest open ports, and their latest vulnerability-scan CVEs.
    Shared by Dashboard, Devices, Vulnerabilities, and the voice/AI summary so every page reports identical counts:
      * physical devices merge by MAC when known (otherwise by IP), matching devices_page();
      * open ports come from each device's newest non-discovery scan that listed ports (matching device_builder.py);
      * CVEs and evaluated open services come ONLY from each device's newest completed vuln_scan (open ports only), so patched
        CVEs disappear once a newer vuln_scan no longer sees them, while a Fast/Discovery scan never erases an older vuln_scan."""
    buckets = {}
    for job in history:
        for d in _parse_job_hosts(job):
            ip = d.get('ip', '')
            mac = d.get('mac', '')
            mac = mac.upper() if mac and mac != 'Unknown' else ''
            key = ('mac', mac) if mac else ('ip', ip)
            b = buckets.setdefault(key, {'ips': set(), 'records': []})
            b['ips'].add(ip)
            b['records'].append((job, d))

    # Attach MAC-less records to the physical device that owns that IP, only when unambiguous (exact rule from devices_page).
    for key in [k for k in buckets if k[0] == 'ip']:
        owners = [k for k in buckets if k[0] == 'mac' and key[1] in buckets[k]['ips']]
        if len(owners) != 1:
            continue
        src, dst = buckets.pop(key), buckets[owners[0]]
        dst['ips'] |= src['ips']
        dst['records'].extend(src['records'])

    devices = []
    for b in buckets.values():
        records = sorted(
            b['records'],
            key=lambda jr: (jr[0].timestamp or datetime.min, jr[0].id or 0),
            reverse=True,
        )
        ips = []
        for _job, d in records:
            ip = d.get('ip', '')
            if ip and ip not in ips:
                ips.append(ip)
        primary_ip = ips[0]
        last_job, last_host = records[0]

        mac = mac_vendor = hostname = os_name = ''
        os_acc = None
        all_ports_seen = set()
        services = set()
        for _job, d in records:
            if not mac:
                m = d.get('mac', '')
                if m and m != 'Unknown':
                    mac = m.upper()
                    mac_vendor = d.get('mac_vendor', '')
            if not hostname and d.get('hostname'):
                hostname = d['hostname']
            if not os_name:
                guess = str(d.get('os') or '').strip()
                if guess and guess.lower() not in ('unknown', 'up', 'down'):
                    os_name = guess
                    os_acc = os_match_accuracy(d.get('os_accuracy'))
            for p in d.get('ports') or []:
                if isinstance(p, dict):
                    all_ports_seen.add(port_text(p))
            services.update(discovery_service_text(d.get('discovery')))

        # Open ports: strictly from the newest non-discovery scan that listed ports (matching device_builder.py).
        ports_job = ports_host = None
        for job, d in records:
            if isinstance(d.get('ports'), list) and job.scan_type != 'discovery':
                ports_job, ports_host = job, d
                break
        open_labels = set()
        open_port_keys = set()
        open_tcp_ports = set()
        open_ports_detail = []
        if ports_host is not None:
            for p in ports_host.get('ports') or []:
                if not isinstance(p, dict):
                    continue
                is_open = str(p.get('state', '')).lower() == 'open'
                if is_open:
                    lbl = port_text(p)
                    open_labels.add(lbl)
                    ver = str(p.get('version_info') or '').strip()
                    if ver == 'Unknown Version':
                        ver = ''
                    open_ports_detail.append(f'{lbl} ({ver})' if ver else lbl)
                    if port_key(p):
                        open_port_keys.add(port_key(p))
                    if port_proto(p) == 'tcp':
                        open_tcp_ports.add(p.get('port'))
                answered = port_proto(p) == 'tcp' or is_open
                if p.get('name') and answered:
                    services.add(p['name'])
                if p.get('version_info') and p['version_info'] != 'Unknown Version' and answered:
                    services.add(p['version_info'])

        # CVEs and evaluated services: strictly from the newest completed vuln_scan that saw this device (open ports only).
        vuln_job = vuln_host = None
        for job, d in records:
            if job.scan_type == 'vuln_scan':
                vuln_job, vuln_host = job, d
                break

        vuln_open_services = []
        active_cves = {}          # cve_id -> finding dict (one finding per physical device x CVE)
        port_cves = {}            # port_text(p) -> set of active cve_ids on that open port
        worst_key = None
        worst_severity = None
        worst_cvss = None
        if vuln_host is not None:
            vuln_ip = vuln_host.get('ip') or primary_ip
            for p in vuln_host.get('ports') or []:
                if not isinstance(p, dict) or str(p.get('state', '')).lower() != 'open':
                    continue
                cves = p.get('cves') or []
                label = port_text(p)
                vuln_open_services.append({
                    'ip': vuln_ip,
                    'port': str(p.get('port', '')),
                    'proto': port_proto(p),
                    'cves': len(cves),
                    'status': p.get('cve_status'),
                    'version': str(p.get('version_info') or ''),
                })
                for cve in cves:
                    info = cve if isinstance(cve, dict) else {}
                    cid = info.get('cve_id', '') if isinstance(cve, dict) else (cve if isinstance(cve, str) else '')
                    if not cid:
                        continue
                    port_cves.setdefault(label, set()).add(cid)
                    sev = effective_severity(info) or 'UNKNOWN'
                    score = cvss_number(info.get('cvss_score'))
                    if sev in _INV_SEV_RANK:
                        rk = (_INV_SEV_RANK[sev], score if score is not None else -1)
                        if worst_key is None or rk > worst_key:
                            worst_key = rk
                            worst_severity = sev
                            worst_cvss = info.get('cvss_score')
                    if cid not in active_cves:
                        active_cves[cid] = {
                            'cve_id': cid,
                            'severity': sev,
                            'severity_adjusted': severity_adjusted(info),
                            'cvss_score': info.get('cvss_score'),
                            'cvss_num': score,
                            'cwe_name': info.get('cwe_name', ''),
                            'raw_cve': info,
                            'description': info.get('description') or '',
                            'ip': vuln_ip,
                            'primary_ip': primary_ip,
                            'port': p.get('port', ''),
                            'protocol': port_proto(p),
                            'service': p.get('name', ''),
                            'product': re.sub(r'\s+', ' ', str(p.get('version_info') or '')).strip(),
                            'job_id': vuln_job.id,
                            'timestamp': vuln_job.timestamp,
                            'kev': info.get('kev') is True,
                            'kev_added': str(info.get('kev_added') or '')[:10] if info.get('kev') is True else '',
                        }

        devices.append({
            'ip': primary_ip,
            'ips': ips,
            'other_ips': ips[1:],
            'mac': mac,
            'mac_vendor': mac_vendor,
            'hostname': hostname,
            'os': os_name,
            'os_accuracy': os_acc,
            'open_labels': open_labels,
            'open_ports_detail': open_ports_detail,
            'open_port_keys': open_port_keys,
            'open_tcp_ports': open_tcp_ports,
            'all_ports_seen': all_ports_seen,
            'services': services,
            'scan_count': len(records),
            'last_seen': last_job.timestamp,
            'last_scan_id': last_job.id,
            'last_scan_ip': last_host.get('ip') or primary_ip,
            'ports_scan_id': ports_job.id if ports_job else None,
            'vuln_scanned': vuln_job is not None,
            'vuln_scan_id': vuln_job.id if vuln_job else None,
            'vuln_open_services': vuln_open_services,
            'active_cves': active_cves,
            'port_cves': port_cves,
            'worst_severity': worst_severity,
            'worst_cvss': worst_cvss,
            'worst_key': worst_key,
        })

    devices.sort(key=lambda d: _ip_sort_key(d['ip']))
    return devices


def _open_port_and_cve_counts(jobs):
    """(distinct open port keys, active per-device CVE findings) from each device's latest state over the given scan jobs."""
    inv = _build_device_inventory(jobs)
    ports = {k for dev in inv for k in dev['open_port_keys']}
    cve_count = sum(len(dev['active_cves']) for dev in inv)
    return len(ports), cve_count


def _kpi_trend(now, before):
    """The footer trend of a dashboard card: how `now` moved against `before` (the same number without the newest scan).
    None when there is nothing to compare with (before is 0); else {'dir': 'up' | 'down' | 'flat', 'pct': whole percent,
    at least 1 for any change}."""
    if not before:
        return None
    if now == before:
        return {'dir': 'flat', 'pct': 0}
    return {'dir': 'up' if now > before else 'down', 'pct': max(1, round(abs(now - before) / before * 100))}


ALLOWED_FORM_SCAN_TYPES = ('fast_scan', 'discovery', 'intense', 'vuln_scan', 'custom')


@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        if not current_user.is_any_admin:
            abort(403)
        target = (request.form.get('target') or '').strip()
        scan_type = (request.form.get('scan_type') or '').strip()
        if not target or len(target) > 100 or not is_valid_target(target):
            flash(tr('flash.target_invalid', target=target or '—'), 'danger')
            return redirect(url_for('tasks_page'))
        if scan_type not in ALLOWED_FORM_SCAN_TYPES:
            flash(tr('flash.scan_type_invalid'), 'danger')
            return redirect(url_for('tasks_page'))
        scan_name = request.form.get('scan_name', '').strip() or None
        custom_args = request.form.get('custom_args', '').strip() or None
        multicast = scan_type == 'discovery' and request.form.get('multicast') == '1'   # mDNS/SSDP lookup, off unless ticked
        timing, version_intensity = clamp_scan_knobs(request.form.get('timing'), request.form.get('version_intensity'), scan_type=scan_type)
        skip_ping = job_skip_ping(scan_type, custom_args, request.form.get('skip_ping'))
        all_ports = job_all_ports(scan_type, request.form.get('all_ports'))
        no_dns = job_no_dns(scan_type, request.form.get('no_dns'))
        host_probes = job_probes(scan_type, request.form.get('host_probes'))
        gentle = job_gentle(scan_type, request.form.get('gentle'))
        udp = job_udp(scan_type, request.form.get('udp'))
        udp_top = job_udp_top(scan_type, udp, request.form.get('udp_top'))
        if gentle:
            timing = None      # Gentle sets the speed itself
        refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp, udp_top, timing)
        if refusal:
            flash(refusal, 'danger')
            return redirect(url_for('tasks_page'))
        new_job = ScanJob(
            target=target, scan_type=scan_type, scan_name=scan_name,
            status='Queued', triggered_by='manual',
            owner_id=current_user.id, timing=timing, version_intensity=version_intensity,
            custom_args=custom_args if scan_type == 'custom' else None,
            multicast=multicast if scan_type == 'discovery' else None,
            skip_ping=skip_ping,
            all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp, udp_top=udp_top,
        )
        db.session.add(new_job)
        if not SavedTarget.query.filter_by(target=target).first():
            db.session.add(SavedTarget(target=target))
        db.session.commit()
        return _scan_started_redirect(new_job)

    history = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
    latest_scan = history[0] if history else None
    scan_data = _parse_job_hosts(latest_scan)

    from collections import Counter

    # Unified device inventory (shared with Devices and Vulnerabilities pages)
    inventory = _build_device_inventory(history)
    total_devices = len(inventory)

    # Top OS: every physical device is counted ONCE, under its newest real OS guess or 'Unknown'.
    os_counts, os_names = Counter(), {}
    for dev in inventory:
        guess = dev['os']
        family = _os_family(guess) if guess else 'Unknown'
        os_counts[family] += 1
        if guess:
            entry = os_names.setdefault(family, {}).setdefault(guess, {'count': 0, 'acc': []})
            entry['count'] += 1
            if dev['os_accuracy'] is not None:
                entry['acc'].append(dev['os_accuracy'])

    def _acc_range(values):
        return {'acc_n': len(values), 'acc_min': min(values) if values else None, 'acc_max': max(values) if values else None}

    os_rows = []
    for fam, n in sorted(os_counts.items(), key=lambda kv: (kv[0] == 'Unknown', kv[0] == 'Other', -kv[1], kv[0])):
        names = sorted(os_names.get(fam, {}).items(), key=lambda kv: (-kv[1]['count'], kv[0]))
        os_rows.append({'family': fam, 'count': n,
                        'names': [dict(name=nm, count=e['count'], **_acc_range(e['acc'])) for nm, e in names[:5]],
                        **_acc_range([a for _nm, e in names for a in e['acc']])})
    os_acc_any = any(r['acc_n'] for r in os_rows)
    online_devices = sum(1 for d in scan_data if isinstance(d, dict) and (d.get('status', '').lower() in ('up', 'online', 'open') or d.get('ports')))
    offline_devices = len(scan_data) - online_devices

    port_device_counter = Counter()
    port_cve_ids = {}
    for dev in inventory:
        for label in dev['open_labels']:
            port_device_counter[label] += 1
            cids = dev['port_cves'].get(label)
            if cids:
                port_cve_ids.setdefault(label, set()).update(cids)

    top_ports = sorted(port_device_counter.items(),
                       key=lambda kv: (-kv[1], int(kv[0].split('/')[0]) if kv[0].split('/')[0].isdigit() else 10 ** 6, kv[0]))[:6]
    top_ports_detail = [{
        'label': label,
        'count': count,
        'cve_count': len(port_cve_ids.get(label, ())),
        'devices': [{'ip': dev['ip'],
                     'cve_count': len(dev['port_cves'].get(label, ())),
                     'scan_id': (dev['vuln_scan_id'] if dev['port_cves'].get(label) else None) or dev['ports_scan_id'] or dev['last_scan_id']}
                    for dev in inventory if label in dev['open_labels']],
    } for label, count in top_ports]

    # Device Status donut: one slice per physical device, by worst CVE from its newest vuln_scan.
    device_port_data = []
    for dev in inventory:
        severity = dev['worst_severity']
        vuln_scanned = dev['vuln_scanned']
        if severity == 'CRITICAL':
            tier = 'critical'
        elif severity == 'HIGH':
            tier = 'high'
        elif severity == 'MEDIUM':
            tier = 'medium'
        elif severity in ('LOW', 'UNKNOWN'):
            tier = 'low'
        elif vuln_scanned:
            tier = 'clean'
        else:
            tier = 'unscanned'
        if tier in ('critical', 'high', 'medium', 'low', 'clean'):
            scan_id = dev['vuln_scan_id']
        else:
            scan_id = None
        device_port_data.append({
            'ip': dev['ip'], 'count': len(dev['open_labels']), 'color': DEVICE_TIER_COLOR[tier],
            'tier': tier, 'severity': severity, 'vuln_scanned': vuln_scanned,
            'cvss_score': dev['worst_cvss'], 'scan_id': scan_id or dev['last_scan_id'],
        })

    target_scan_counts = Counter(j.target for j in history if j.status == 'Completed')

    # Scan job totals: actual ScanJobs only (matching Tasks and History pages); active schedules are shown separately.
    schedules_all = visible_schedules_query().all()
    task_completed = sum(1 for j in history if j.status == 'Completed')
    task_running   = sum(1 for j in history if j.status in ACTIVE_STATUSES)
    task_cancelled = sum(1 for j in history if j.status == 'Cancelled')
    task_failed    = sum(1 for j in history if j.status == 'Failed')
    task_wait      = sum(1 for s in schedules_all if s.is_active)
    total_tasks    = len(history)

    # Active CVE findings (one per device x CVE from each device's newest vuln_scan — identical to Vulnerabilities page).
    lang_now = ui_lang_now()
    all_cves_list = []
    for dev in inventory:
        for finding in dev['active_cves'].values():
            entry = {
                'id': finding['cve_id'],
                'severity': finding['severity'],
                'port': finding['port'],
                'protocol': finding['protocol'],
                'service': finding['service'],
                'ip': finding['ip'],
                'cvss': finding['cvss_score'],
                'cwe': (cwe_info(finding['raw_cve']) or {}).get('label', ''),
                'description': finding['description'],
                'kev': finding['kev'],
                'hosts': [{'ip': finding['ip'], 'port': finding['port'], 'protocol': finding['protocol'],
                           'service': finding['service'], 'scan_id': finding['job_id']}],
                'more_hosts': 0,
            }
            if finding['severity_adjusted']:
                entry['severity_note'] = severity_note(finding['cvss_score'], lang=lang_now)
            all_cves_list.append(entry)
    total_cves_found = len(all_cves_list)
    total_open_ports = len({k for dev in inventory for k in dev['open_port_keys']})

    # Footer trend of Open Ports and CVE Found: latest state now vs. latest state before the newest completed scan.
    latest_done = next((j for j in history if j.status == 'Completed'), None)
    before_jobs = history[history.index(latest_done) + 1:] if latest_done else []
    ports_before, cves_before = _open_port_and_cve_counts(before_jobs)
    ports_trend = _kpi_trend(total_open_ports, ports_before)
    cve_trend = _kpi_trend(total_cves_found, cves_before)

    ov = _vuln_overview_from_inventory(inventory)
    cve_coverage = ({'services': ov['services'], 'evaluated': ov['found'] + ov['none'], 'found': ov['found'], 'none': ov['none'],
                     'not_evaluated': ov['not_evaluated']} if ov['services'] else None)

    # Job # on screen uses job.id everywhere so it always matches /scan/<id> and never shifts when old jobs are deleted.
    latest_owner_seq = latest_scan.id if latest_scan else None
    owner_seq_map = {j.id: j.id for j in history}

    # ข้อมูลจริงสำหรับ Task Status (แทนที่ placeholder "Job #1, #2, ...")
    def _job_row(j):
        return {
            'id': j.id,
            'seq': owner_seq_map.get(j.id, j.id),
            'target': j.target,
            'type_label': scan_labels().get(j.scan_type, j.scan_type or ''),
            'timestamp': j.timestamp.strftime('%Y-%m-%d %H:%M') if j.timestamp else '—',
        }
    task_complete_jobs  = [_job_row(j) for j in history if j.status == 'Completed']
    task_running_jobs   = [_job_row(j) for j in history if j.status in ACTIVE_STATUSES]
    task_cancelled_jobs = [_job_row(j) for j in history if j.status == 'Cancelled']
    task_failed_jobs    = [_job_row(j) for j in history if j.status == 'Failed']

    task_ring_total = total_tasks
    task_categories = [
        {'key': 'complete',  'count': task_completed, 'color': GOOD_GREEN, 'kind': 'job', 'rows': task_complete_jobs,  'view_all_url': url_for('history_page')},
        {'key': 'running',   'count': task_running,   'color': '#ffc107',  'kind': 'job', 'rows': task_running_jobs,   'view_all_url': url_for('tasks_page')},
        {'key': 'cancelled', 'count': task_cancelled, 'color': '#64748b',  'kind': 'job', 'rows': task_cancelled_jobs, 'view_all_url': url_for('history_page')},
        {'key': 'failed',    'count': task_failed,    'color': '#dc2626',  'kind': 'job', 'rows': task_failed_jobs,    'view_all_url': url_for('history_page')},
    ]

    latest_changes = None
    for j in history[:20]:
        if j.status == 'Completed' and j.scan_type != 'xml_upload':
            latest_changes = scan_changes(j)
            if latest_changes:
                break

    return render_template(
        'dashboard.html',
        latest_changes=latest_changes,
        history=history,
        scan_data=scan_data,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        total_open_ports=total_open_ports,
        top_ports=top_ports,
        top_ports_detail=top_ports_detail,
        device_port_data=device_port_data,
        device_tier_color=DEVICE_TIER_COLOR,
        target_scan_counts=target_scan_counts,
        total_tasks=total_tasks,
        task_completed=task_completed,
        task_cancelled=task_cancelled,
        task_failed=task_failed,
        task_categories=task_categories,
        task_ring_total=task_ring_total,
        task_wait=task_wait,
        latest_owner_seq=latest_owner_seq,
        owner_seq_map=owner_seq_map,
        total_cves_found=total_cves_found,
        ports_trend=ports_trend,
        cve_trend=cve_trend,
        cve_coverage=cve_coverage,
        os_rows=os_rows,
        os_acc_any=os_acc_any,
        task_running=task_running,
        all_cves=all_cves_list,
    )


# ─────────────────────────────────────────
#  HISTORY
# ─────────────────────────────────────────
#  NETWORK TOPOLOGY PAGE
# ─────────────────────────────────────────

_TOPO_NO_OS = ('', 'up', 'down', 'unknown')      # a Discovery scan's "up" and a missing OS are not an OS (the page's isUnknownOs)


def _topology_os_family(h):
    """OS family of a host's OS guess, for the diagram's filter. '' when this record has no real OS name (the page then reads it as Unknown): the
    family is taken from the SAME record that gave the OS name, so it can never belong to an older, different guess."""
    name = str(h.get('os', h.get('status', '')) or '')
    return '' if name.strip().lower() in _TOPO_NO_OS else _os_family(name)


def _topology_os_accuracy(h):
    """nmap's confidence (0-100) in the OS guess of this record, or None when the scan did not keep it (never a guess)."""
    v = h.get('os_accuracy')
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 100 else None


def _topology_risk(h, scan_type):
    """{'tier', 'cve_count'} for one host of ONE vulnerability scan, and {} for every other scan type (only a vulnerability scan looks for CVEs).
    The rules are report_builder's, the same as the device page's risk pill: 'critical' / 'high' / 'medium' / 'low' = the worst CVE (through
    effective_severity), 'clean' = every open service was looked up and none has a CVE, 'unknown' = the scan could not say (a failed lookup, a
    service nmap could not name, no open port). Never 'clean' on a guess."""
    if scan_type != 'vuln_scan':
        return {}
    ports_known = isinstance(h.get('ports'), list)
    open_ports = [p for p in (h.get('ports') or []) if report_builder._is_open(p)]
    cves = report_builder._host_cves(open_ports)
    level, _why = report_builder._host_risk(open_ports, cves, scan_type, ports_known)
    if level == 'none':
        tier = 'clean'
    elif level == 'unknown':
        tier = 'unknown'
    else:
        tier = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium'}.get(cves[0]['severity'], 'low')
    return {'tier': tier, 'cve_count': len(cves)}


def _topology_group(job):
    """A text key: two scans with the same key may be compared with each other (scan_diff.comparable_key: same target, same scan type, same options).
    '' for an XML import, which is never compared. The page uses it to say "new in the latest scan" only against a scan of the same kind."""
    if job.scan_type in (None, 'xml_upload'):
        return ''
    return '|'.join(str(x) for x in scan_diff.comparable_key(job.scan_type, job.target, job.skip_ping, job.custom_args, job.all_ports,
                                                               job.host_probes, job.gentle, job.udp, job.udp_top))


@app.route('/topology')
@login_required
def topology_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()

    owner_seq_map = {j.id: j.id for j in history}

    scans_data = []
    for job in history:
        if job.status != 'Completed' or not job.result_data:
            continue
        try:
            raw = json.loads(job.result_data)
        except Exception:
            continue

        hosts_list = []
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get('hosts', raw.get('results', []))
        else:
            items = []

        for h in items:
            ports = []
            for p in (h.get('ports') or []):
                entry = {
                    'port': p.get('port', ''),
                    'protocol': p.get('protocol', 'tcp'),
                    'state': p.get('state', 'unknown'),
                    'name': p.get('name', ''),
                    'version_info': p.get('version_info', '')
                }
                reason = port_reason(p.get('reason'))      # nmap's reason for the state (absent in scans from before it was kept)
                if reason:
                    entry['reason'] = reason
                ports.append(entry)
            hosts_list.append({
                'ip':         h.get('ip', ''),
                'mac':        h.get('mac', ''),
                'mac_vendor': h.get('mac_vendor', ''),
                'ipv6':       h.get('ipv6', ''),
                'hostname':   h.get('hostname', ''),
                'discovery':  h.get('discovery') or {},
                'vm':         virtual_machine_platform(h.get('mac'), h.get('mac_vendor')),
                'os':         h.get('os', h.get('status', '')),
                'ports':      ports,
                # the path nmap's traceroute found (only an Intense / Vulnerability scan that reached the host stores one): the diagram names
                # the hop before the host as that subnet's router (SubnetTopology.detectGateway, evidence 3)
                'trace_hops': [x for x in (h.get('trace_hops') or [])[:30] if isinstance(x, dict)],
                # for the diagram's OS filter and the pop-up (the family and the confidence come from the same record as the OS name), and the dot colour by risk
                'os_family':   _topology_os_family(h),
                'os_accuracy': _topology_os_accuracy(h),
                **_topology_risk(h, job.scan_type),
            })

        date_str = job.timestamp.strftime('%Y-%m-%d') if job.timestamp else '1970-01-01'
        scans_data.append({
            'job_id':    job.id,
            'job_name':  job.scan_name or job_label(owner_seq_map.get(job.id, job.id)),
            'scan_type': job.scan_type or '',
            'date':      date_str,
            'target':    job.target,
            'group':     _topology_group(job),
            'public_ip': scan_run_info(job).get('public_ip') or '',
            'hosts':     hosts_list
        })

    import json as _json
    # hostnames/mDNS names come from other devices and this JSON is dropped raw into a <script>:
    # < keeps it valid JSON while making "</script>" impossible
    scans_json = _json.dumps(scans_data).replace('<', '\\u003c')
    system_gw = get_system_default_gateway()
    return render_template('network_topology.html', scans_json=scans_json, system_gateway=system_gw, device_tier_color=DEVICE_TIER_COLOR)


@app.route('/api/network/public-ip')
@login_required
def api_network_public_ip():
    """Return this machine's cached outbound public (WAN) IP asynchronously for the Topology diagram."""
    return jsonify({'public_ip': get_public_ip(max_age=600) or ''})


# ─────────────────────────────────────────

@app.route('/history')
@login_required
def history_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
    from collections import defaultdict

    # คำนวณลำดับ scan ของ target เดียวกัน (count badge)
    target_jobs = defaultdict(list)
    for j in history:
        target_jobs[j.target].append(j)
    scan_seq_map = {}
    for target, tlist in target_jobs.items():
        sorted_list = sorted(tlist, key=lambda x: x.timestamp or 0)
        for idx, tj in enumerate(sorted_list, 1):
            scan_seq_map[tj.id] = (idx, len(sorted_list))

    owner_seq_map = {j.id: j.id for j in history}

    return render_template('history.html', history=history,
                           scan_seq_map=scan_seq_map,
                           owner_seq_map=owner_seq_map,
                           adv_fields=adv_fields_for())      # a list: JSON would sort a dict's keys


# ─────────────────────────────────────────
#  HISTORY: ADVANCED FILTER
# ─────────────────────────────────────────
# The filter builder on the History page sends criteria like
#   {"include": [{"field": "type", "values": ["fast_scan"]}, {"field": "port", "values": ["445", "1-1024"]}],
#    "exclude": [{"field": "status", "values": ["Failed"]}]}
# The rows of "include" are ANDed and the values inside a row are ORed. A "scan" field describes the scan job; a "result" field describes
# a host inside its results, and all the result rows of "include" have to hold for the SAME host. A scan is dropped when it matches any one
# row of "exclude". The matching is plain functions (no request needed) so it can be checked without a browser.

ADV_FIELDS = {
    'target':       {'label': 'Target',                 'kind': 'text', 'level': 'scan', 'hint': '192.168.1.0/24'},
    'name':         {'label': 'ชื่องาน',                  'kind': 'text', 'level': 'scan', 'hint': 'ชื่อที่ตั้งไว้'},
    'type':         {'label': 'Type',                   'kind': 'enum', 'level': 'scan',
                     'options': [[k, v] for k, v in SCAN_TYPE_LABELS.items()]},
    'status':       {'label': 'Status',                 'kind': 'enum', 'level': 'scan',
                     'options': [['Completed', 'Completed'], ['Queued', 'Queued'], ['Running', 'Running'], ['Failed', 'Failed'], ['Cancelled', 'Cancelled']]},
    'triggered_by': {'label': 'Triggered By',           'kind': 'enum', 'level': 'scan',
                     'options': [['manual', 'Manual'], ['schedule', 'Schedule'], ['rescan', 'Rescan'], ['drilldown', 'Drill-down'], ['chatbot', 'Assistant']]},
    'date':         {'label': 'วันที่สแกน',               'kind': 'date', 'level': 'scan'},
    'host':         {'label': 'อุปกรณ์ (IP)',             'kind': 'text', 'level': 'result', 'hint': '192.168.1.41 หรือ 192.168.1.0/24'},
    'port':         {'label': 'พอร์ต / บริการที่เปิด',      'kind': 'text', 'level': 'result', 'hint': '445, 1-1024, 161/udp หรือ ssh'},
    'os':           {'label': 'OS',                     'kind': 'text', 'level': 'result', 'hint': 'Windows, Linux...'},
    'cve':          {'label': 'CVE ID',                 'kind': 'text', 'level': 'result', 'hint': 'CVE-2011-2523'},
    'severity':     {'label': 'ระดับ CVE',               'kind': 'enum', 'level': 'result',
                     'options': [['CRITICAL', 'Critical'], ['HIGH', 'High'], ['MEDIUM', 'Medium'], ['LOW', 'Low']]},
}
ADV_MAX_ROWS, ADV_MAX_VALUES, ADV_MAX_LEN, ADV_RECENT_KEEP, ADV_SAVED_MAX = 12, 20, 100, 10, 50
ADV_MAX_SUGGEST = 5          # devices the History search box names when the address it was given matched nothing
_ADV_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def normalize_criteria(raw):
    """The clean {"include": [...], "exclude": [...]} for whatever the browser sent: unknown fields, unknown enum values and empty rows
    are dropped, and the sizes are capped. Never raises."""
    out = {'include': [], 'exclude': []}
    if not isinstance(raw, dict):
        return out
    for section in ('include', 'exclude'):
        rows = raw.get(section)
        for row in (rows if isinstance(rows, list) else [])[:ADV_MAX_ROWS]:
            field = row.get('field') if isinstance(row, dict) else None
            meta = ADV_FIELDS.get(field)
            vals = row.get('values') if isinstance(row, dict) else None
            if not meta or not isinstance(vals, list):
                continue
            vals = [str(v).strip()[:ADV_MAX_LEN] for v in vals[:ADV_MAX_VALUES] if isinstance(v, (str, int))]
            if meta['kind'] == 'enum':
                allowed = {o[0] for o in meta['options']}
                vals = [v for v in vals if v in allowed]
            elif meta['kind'] == 'date':
                vals = (vals + ['', ''])[:2]
                vals = [v if _ADV_DATE.match(v) else '' for v in vals]
                if not any(vals):
                    vals = []
            else:
                vals = [v for v in vals if v]
            if vals:
                out[section].append({'field': field, 'values': vals})
    return out


def _adv_text_hit(text, values):
    text = str(text or '').lower()
    return any(v.lower() in text for v in values)


def _adv_port_hit(port, service, values, protocol='tcp'):
    """A port criterion is a number (445), a range (1-1024), either of them with a protocol (161/udp, 1-1024/tcp) or part of a service name (ssh).
    A number or a range alone matches that port over any protocol; with a protocol it matches that protocol only."""
    number = int(port) if str(port).isdigit() else None
    for v in values:
        m = re.fullmatch(r'(\d+(?:-\d+)?)\s*/\s*(tcp|udp|sctp)', v, re.I)
        if m:
            v = m.group(1)
            if m.group(2).lower() != protocol:
                continue
        if v.isdigit():
            if number is not None and number == int(v):
                return True
        elif re.fullmatch(r'\d+-\d+', v):
            low, high = (int(x) for x in v.split('-'))
            if number is not None and low <= number <= high:
                return True
        elif v.lower() in str(service or '').lower():
            return True
    return False


def _adv_host_hit(ip, values):
    """An address criterion is part of an IP, or a network (192.168.1.0/24) the host has to be inside."""
    for v in values:
        if '/' in v:
            try:
                if ipaddress.ip_address(str(ip)) in ipaddress.ip_network(v, strict=False):
                    return True
            except ValueError:
                pass
        elif v.lower() in str(ip or '').lower():
            return True
    return False


def _adv_scan_row_hit(job, row):
    field, values = row['field'], row['values']
    if field == 'target':
        return _adv_text_hit(job.target, values)
    if field == 'name':
        return _adv_text_hit(job.scan_name, values)
    if field == 'type':
        return (job.scan_type or '') in values
    if field == 'status':
        return (job.status or '') in values
    if field == 'triggered_by':
        return (job.triggered_by or 'manual') in values
    if field == 'date':
        if not job.timestamp:
            return False
        day = job.timestamp.date().isoformat()
        return (not values[0] or day >= values[0]) and (not values[1] or day <= values[1])
    return False


def _adv_host_row_hit(host, row):
    field, values = row['field'], row['values']
    ports = [p for p in (host.get('ports') or []) if isinstance(p, dict)]
    if field == 'host':
        return _adv_host_hit(host.get('ip'), values)
    if field == 'os':
        return _adv_text_hit(host.get('os'), values)
    if field == 'port':
        return any(str(p.get('state', '')).lower() == 'open' and _adv_port_hit(p.get('port'), p.get('name'), values, port_proto(p)) for p in ports)
    cves = [c for p in ports for c in (p.get('cves') or [])]
    if field == 'cve':
        return any(_adv_text_hit(c.get('cve_id') if isinstance(c, dict) else c, values) for c in cves)
    if field == 'severity':
        return any(effective_severity(c) in values for c in cves if isinstance(c, dict))
    return False


def _adv_hosts_of(job):
    if job.status != 'Completed' or not job.result_data:
        return []
    try:
        data = json.loads(job.result_data)
    except Exception:
        return []
    return [h for h in data if isinstance(h, dict) and h.get('ip')] if isinstance(data, list) else []


def scan_matches(job, hosts, criteria):
    """Does this scan satisfy the (normalized) criteria? `hosts` are its result hosts ([] when it has none)."""
    level = lambda row: ADV_FIELDS[row['field']]['level']
    scan_rows = [r for r in criteria['include'] if level(r) == 'scan']
    host_rows = [r for r in criteria['include'] if level(r) == 'result']
    if not all(_adv_scan_row_hit(job, r) for r in scan_rows):
        return False
    if host_rows and not any(all(_adv_host_row_hit(h, r) for r in host_rows) for h in hosts):
        return False
    for row in criteria['exclude']:
        if level(row) == 'scan':
            if _adv_scan_row_hit(job, row):
                return False
        elif any(_adv_host_row_hit(h, row) for h in hosts):
            return False
    return True


def _adv_enum_names(field, lang):
    labels = SCAN_TYPE_LABELS if lang == 'en' else SCAN_TYPE_LABELS_TH
    if field == 'type':
        return {k: labels.get(k, v) for k, v in ADV_FIELDS['type']['options']}
    if field == 'status':
        return {k: i18n.t('status.' + k.lower(), lang) for k, _ in ADV_FIELDS['status']['options']}
    if field == 'triggered_by':
        return {k: i18n.t('history.trig.' + k, lang) for k, _ in ADV_FIELDS['triggered_by']['options']}
    if field == 'severity':
        return {k: sev_label(k, lang) for k, _ in ADV_FIELDS['severity']['options']}
    return dict(ADV_FIELDS[field]['options'])


def adv_fields_for(lang=None):
    """Localized list of Advanced Filter fields for history.html."""
    lang = lang if lang in i18n.LANGS else ui_lang_now()
    out = []
    for key, meta in ADV_FIELDS.items():
        item = dict(meta, key=key, label=i18n.t('history.f.' + key, lang))
        if 'hint' in meta:
            hint_key = 'history.h.' + key
            tr_hint = i18n.t(hint_key, lang)
            item['hint'] = meta['hint'] if tr_hint == hint_key else tr_hint
        if meta['kind'] == 'enum':
            names = _adv_enum_names(key, lang)
            item['options'] = [[k, names.get(k, v)] for k, v in meta['options']]
        out.append(item)
    return out


def describe_criteria(criteria, lang=None):
    """One line that says what a query looks for, e.g. 'Type: Fast Scan · Port: 445 · Exclude Status: Failed'."""
    lang = lang if lang in i18n.LANGS else ui_lang_now()
    def row_text(row):
        meta = ADV_FIELDS[row['field']]
        vals = row['values']
        if meta['kind'] == 'enum':
            names = _adv_enum_names(row['field'], lang)
            vals = [names.get(v, v) for v in vals]
        elif meta['kind'] == 'date':
            d0 = vals[0] if lang == 'en' else ui_year(vals[0])
            d1 = vals[1] if lang == 'en' else ui_year(vals[1])
            vals = [(d0 or '…') + ' – ' + (d1 or '…')]
        return i18n.t('history.f.' + row['field'], lang) + ': ' + ', '.join(vals)
    parts = [row_text(r) for r in criteria['include']] + [i18n.t('adv.exclude', lang, text=row_text(r)) for r in criteria['exclude']]
    return ' · '.join(parts) if parts else i18n.t('adv.none', lang)


def _query_item(q):
    criteria = normalize_criteria(json.loads(q.criteria))
    return {'id': q.id, 'name': q.name or '', 'criteria': criteria, 'summary': describe_criteria(criteria),
            'last_used': q.last_used_at.strftime('%Y-%m-%d %H:%M') if q.last_used_at else ''}


def _criteria_key(criteria):
    return json.dumps(criteria, sort_keys=True, ensure_ascii=False)


def _find_query(criteria):
    key = _criteria_key(criteria)
    for q in HistoryQuery.query.filter_by(owner_id=current_user.id).all():
        try:
            if _criteria_key(normalize_criteria(json.loads(q.criteria))) == key:
                return q
        except Exception:
            continue
    return None


@app.route('/api/history/search', methods=['POST'])
@login_required
def api_history_search():
    """The ids of the scans (among those this user may see) that match the criteria. A search with conditions is also remembered as a
    recent query, unless the page says record=false (it does when it re-runs a query from the URL).
    `suggest` is an address the History search box was given: when no scan matched, the reply also names the devices (in the scans
    this user may see) whose address STARTS with it, so the box can say "did you mean 192.168.1.41?"."""
    payload = request.get_json(silent=True) or {}
    criteria = normalize_criteria(payload.get('criteria'))
    rows = criteria['include'] + criteria['exclude']
    needs_hosts = any(ADV_FIELDS[r['field']]['level'] == 'result' for r in rows)
    suggest = str(payload.get('suggest') or '').strip().lower()[:ADV_MAX_LEN]
    jobs = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    hosts_of = {j.id: _adv_hosts_of(j) for j in jobs} if (needs_hosts or suggest) else {}     # each scan's result is parsed once
    ids = [j.id for j in jobs if scan_matches(j, hosts_of.get(j.id, []), criteria)]
    near = []
    if suggest and not ids:
        near = sorted({str(h['ip']) for hosts in hosts_of.values() for h in hosts
                       if str(h['ip']).lower().startswith(suggest) and str(h['ip']).lower() != suggest}, key=_ip_sort_key)
    if rows and payload.get('record', True):
        existing = _find_query(criteria)
        if existing:
            existing.last_used_at = now_th()
        else:
            db.session.add(HistoryQuery(owner_id=current_user.id, criteria=_criteria_key(criteria), is_saved=False))
        db.session.commit()
        recents = (HistoryQuery.query.filter_by(owner_id=current_user.id, is_saved=False)
                   .order_by(HistoryQuery.last_used_at.desc(), HistoryQuery.id.desc()).all())
        for old in recents[ADV_RECENT_KEEP:]:
            db.session.delete(old)
        db.session.commit()
    return jsonify({'ids': ids, 'matched': len(ids), 'total': len(jobs), 'criteria': criteria, 'summary': describe_criteria(criteria),
                    'suggestions': near[:ADV_MAX_SUGGEST], 'suggestions_total': len(near)})


@app.route('/api/history/queries')
@login_required
def api_history_queries():
    mine = HistoryQuery.query.filter_by(owner_id=current_user.id)
    recent = mine.filter_by(is_saved=False).order_by(HistoryQuery.last_used_at.desc(), HistoryQuery.id.desc()).limit(ADV_RECENT_KEEP).all()
    saved = mine.filter_by(is_saved=True).order_by(HistoryQuery.name).all()
    return jsonify({'recent': [_query_item(q) for q in recent], 'saved': [_query_item(q) for q in saved]})


@app.route('/api/history/queries', methods=['POST'])
@login_required
def api_history_query_save():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get('name') or '').strip()[:100]
    criteria = normalize_criteria(payload.get('criteria'))
    if not name:
        return jsonify({'error': 'กรุณาตั้งชื่อ query'}), 400
    if not (criteria['include'] or criteria['exclude']):
        return jsonify({'error': 'ยังไม่มีเงื่อนไขให้บันทึก'}), 400
    existing = _find_query(criteria)
    if not existing and HistoryQuery.query.filter_by(owner_id=current_user.id, is_saved=True).count() >= ADV_SAVED_MAX:
        return jsonify({'error': 'บันทึกได้สูงสุด %d query' % ADV_SAVED_MAX}), 400
    if existing:
        existing.name, existing.is_saved, existing.last_used_at = name, True, now_th()
        q = existing
    else:
        q = HistoryQuery(owner_id=current_user.id, name=name, criteria=_criteria_key(criteria), is_saved=True)
        db.session.add(q)
    db.session.commit()
    return jsonify(_query_item(q))


@app.route('/api/history/queries/<int:query_id>/delete', methods=['POST'])
@login_required
def api_history_query_delete(query_id):
    q = HistoryQuery.query.filter_by(id=query_id, owner_id=current_user.id).first_or_404()
    db.session.delete(q)
    db.session.commit()
    return jsonify({'ok': True})


# ─────────────────────────────────────────
#  DELETE SCAN HISTORY
# ─────────────────────────────────────────

def _delete_finished_scans(ids):
    """Delete the scans with these ids that are NOT waiting or running. One conditional DELETE per chunk, so a scan that a worker claims between the
    check and the delete is never removed from under it (the runner's own claim is a conditional update too). Nothing else points at a ScanJob row,
    so there is nothing to cascade. Returns (deleted, skipped): `skipped` are the ids that were waiting or running (or already gone)."""
    ids = list(ids)
    deleted = 0
    for k in range(0, len(ids), 500):                  # keep the IN list short (SQLite's limit on variables)
        deleted += (ScanJob.query
                    .filter(ScanJob.id.in_(ids[k:k + 500]), db.or_(ScanJob.status.is_(None), ScanJob.status.notin_(ACTIVE_STATUSES)))
                    .delete(synchronize_session=False))
    db.session.commit()
    return deleted, len(ids) - deleted




@app.route('/history/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    seq = _job_seq(job)                                # the number the pages print ("Job #N"), not the database id
    deleted, skipped = _delete_finished_scans([job.id])
    if deleted:
        flash(tr('flash.delete_one_done', n=seq), 'success')
    else:
        flash(tr('flash.delete_one_active', n=seq), 'warning')
    return redirect(url_for('history_page'))


@app.route('/history/delete-by-target', methods=['POST'])
@login_required
def delete_scans_by_target():
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    target = request.form.get('target', '').strip()
    if not target:
        flash(tr('flash.target_missing'), 'danger')
        return redirect(url_for('history_page'))
    ids = [row[0] for row in visible_scans_query().filter_by(target=target).with_entities(ScanJob.id).all()]
    deleted, skipped = _delete_finished_scans(ids)
    if deleted and skipped:
        flash(tr('flash.delete_target_partial', target=target, n=deleted) + ' ' + tr('flash.skipped_active', n=skipped), 'warning')
    elif deleted:
        flash(tr('flash.delete_target_all', target=target, n=deleted), 'success')
    else:
        flash(tr('flash.delete_target_none', target=target) + ' ' + (tr('flash.skipped_active', n=skipped) if skipped else tr('flash.already_deleted')), 'warning')
    return redirect(url_for('history_page'))


@app.route('/history/bulk-delete', methods=['POST'])
@login_required
def delete_scans_bulk():
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    scan_ids = request.form.getlist('scan_ids')
    if not scan_ids:
        data = request.get_json(silent=True)
        if data and 'scan_ids' in data:
            scan_ids = data['scan_ids']

    clean_ids = []
    for sid in scan_ids:
        try:
            clean_ids.append(int(sid))
        except (ValueError, TypeError):
            continue

    if not clean_ids:
        flash(tr('flash.nothing_selected'), 'warning')
        return redirect(url_for('history_page'))

    # only the scans this user may see, and never one that is waiting or running (the database decides, in the DELETE itself)
    in_scope = [row[0] for row in visible_scans_query().filter(ScanJob.id.in_(clean_ids)).with_entities(ScanJob.id).all()]
    deleted, skipped = _delete_finished_scans(in_scope)
    if deleted and skipped:
        flash(tr('flash.delete_bulk_partial', n=deleted) + ' ' + tr('flash.skipped_active', n=skipped), 'warning')
    elif deleted:
        flash(tr('flash.delete_bulk_all', n=deleted), 'success')
    else:
        flash(tr('flash.delete_bulk_none') + ' ' + (tr('flash.skipped_active', n=skipped) if skipped else tr('flash.selection_not_found')), 'warning')
    return redirect(url_for('history_page'))

# ─────────────────────────────────────────
#  TASKS
# ─────────────────────────────────────────

@app.route("/tasks")
@login_required
def tasks_page():
    schedules = visible_schedules_query().order_by(ScheduledScan.created_at.desc()).all()
    from collections import Counter
    all_jobs = visible_scans_query().all()
    target_scan_counts = Counter(j.target for j in all_jobs if j.status == 'Completed')
    # what the details panel of each schedule shows (a schedule never listens for mDNS/SSDP, so multicast is False)
    schedule_details = {}
    for sc in schedules:
        schedule_details[sc.id] = {
            'name': sc.name, 'target': sc.target, 'repeat': sc.repeat,
            'weekday': sc.day_of_week, 'monthday': sc.day_of_month,
            'time': '%02d:%02d' % (sc.cron_hour, sc.cron_minute),
            'next_run': sc.next_run.strftime('%Y-%m-%d %H:%M') if sc.next_run else '',
            'last_run': sc.last_run.strftime('%Y-%m-%d %H:%M') if sc.last_run else '',
            'created': sc.created_at.strftime('%Y-%m-%d %H:%M') if sc.created_at else '',
            'active': bool(sc.is_active),
            'settings': describe_scan_settings(sc.scan_type, sc.timing, sc.version_intensity, sc.custom_args, False, sc.skip_ping, sc.all_ports, sc.no_dns, sc.host_probes, sc.gentle, sc.udp, sc.udp_top),
        }
    return render_template("tasks.html", schedules=schedules, target_scan_counts=target_scan_counts, schedule_details=schedule_details)


# ─────────────────────────────────────────
#  DEVICES / VULNERABILITIES / REPORTS / SETTINGS
# ─────────────────────────────────────────

def _ip_sort_key(ip):
    """Sort key that puts 192.168.1.40 before 192.168.1.200 (plain string order does not)."""
    parts = ip.split('.')
    return (0, tuple(int(p) for p in parts), '') if len(parts) == 4 and all(p.isdigit() for p in parts) else (1, (), ip)


def _os_family(os_name):
    """Rough OS family of an nmap OS guess, for the Devices filter."""
    s = (os_name or '').lower()
    if not s or s == 'unknown':
        return 'Unknown'
    if 'windows' in s:
        return 'Windows'
    if 'android' in s:                               # before Linux: Android guesses mention the Linux kernel
        return 'Android'
    if 'cisco' not in s and re.search(r'\b(mac ?os|os x|ios|iphone|ipad|apple)\b', s):
        return 'Apple'
    if any(w in s for w in ('linux', 'openwrt', 'ubuntu', 'debian')):
        return 'Linux'
    return 'Other'


@app.route('/devices')
@login_required
def devices_page():
    """รวมอุปกรณ์ที่ไม่ซ้ำกันจากประวัติการสแกนทั้งหมด (ใช้ตรรกะเดียวกับ Dashboard และ Device Detail)"""
    history = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
    inventory = _build_device_inventory(history)

    gateway_ip = (get_system_default_gateway(max_age=30) or {}).get('ip')
    device_list = []
    for e in inventory:
        services_text = ' '.join(e['services'])
        # with several IPs, the gateway / this-PC address is the one the classifier must see
        rule_ip = gateway_ip if gateway_ip in e['ips'] else next((i for i in e['ips'] if is_local_ip(i)), e['ips'][0])
        device_list.append({
            'ip': e['ip'],
            'other_ips': e['other_ips'],
            'mac': e['mac'] or '—',
            'mac_vendor': e['mac_vendor'],
            'os': e['os'] or 'Unknown',
            'os_family': _os_family(e['os']),
            'device_type': guess_device_type(rule_ip, e['mac_vendor'], e['os'], e['open_tcp_ports'], gateway_ip,
                                              services=services_text, hostname=e['hostname'], mac=e['mac']),
            'port_count': len(e['open_labels']),          # open ports from the newest port scan (matching Dashboard & Device Detail)
            'open_ports_list': sorted(e['open_labels']),
            'ports': sorted(e['all_ports_seen']),         # every port seen, in any state: the search box looks through these
            'scan_count': e['scan_count'],
            'last_seen': e['last_seen'].strftime('%Y-%m-%d %H:%M') if e['last_seen'] else '—',
            'last_scan_id': e['last_scan_id'],
            'last_scan_ip': e['last_scan_ip'],
        })

    # options for the filter bar: only values that actually appear, with how many devices each has
    type_counts, os_counts = {}, {}
    for d in device_list:
        type_counts[d['device_type']['label']] = type_counts.get(d['device_type']['label'], 0) + 1
        os_counts[d['os_family']] = os_counts.get(d['os_family'], 0) + 1
    type_options = sorted(type_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    os_options = sorted(os_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    with_ports = sum(1 for d in device_list if d['port_count'] > 0)
    return render_template('devices.html', devices=device_list, type_options=type_options, os_options=os_options,
                           with_ports=with_ports, without_ports=len(device_list) - with_ports)


_VULN_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
VULN_BANDS = (('0-3.9', 0.0, 4.0), ('4-6.9', 4.0, 7.0), ('7-8.9', 7.0, 9.0), ('9-10', 9.0, 10.5))      # the CVSS bands NVD labels Low / Medium / High / Critical


OV_STRIP_MAX = 40            # devices listed under one service row of the Vulnerabilities Overview (the row still says how many there are)


def _vuln_overview_from_inventory(inventory):
    """The numbers behind the Vulnerabilities page's Overview and the Dashboard's CVE coverage caption, computed strictly
    from each device's newest completed vuln_scan (open ports only) so patched CVEs and closed services do not linger."""
    services = []
    cve_rows = []
    for dev in inventory:
        services.extend(dev['vuln_open_services'])
        for finding in dev['active_cves'].values():
            cve_rows.append({
                'ip': finding['ip'],
                'cve_id': finding['cve_id'],
                'sev': finding['severity'],
                'score': finding['cvss_num'],
                'product': finding['product'],
            })

    found = none = 0
    reasons = {'failed': 0, 'no_product': 0, 'legacy': 0}
    for s in services:
        if s['cves'] > 0:
            found += 1
        elif s['status'] == 'ok':
            none += 1
        elif s['status'] == 'failed':
            reasons['failed'] += 1
        elif s['status'] == 'no_product':
            reasons['no_product'] += 1
        elif s['status'] is None and s['version'].strip() in ('', 'Unknown Version'):
            reasons['no_product'] += 1
        else:
            reasons['legacy'] += 1

    per_dev, per_prod = {}, {}
    bands, unscored = [{'label': label, 'count': 0} for label, _lo, _hi in VULN_BANDS], 0
    for r in cve_rows:
        rank = _VULN_SEV_RANK.get(r['sev'], 0)
        e = per_dev.setdefault(r['ip'], {'ip': r['ip'], 'count': 0, 'rank': -1, 'worst': 'UNKNOWN'})
        e['count'] += 1
        if rank > e['rank']:
            e['rank'], e['worst'] = rank, r['sev']
        if r['product'] and r['product'] != 'Unknown Version':
            e = per_prod.setdefault(r['product'], {'product': r['product'], 'per_dev': {}, 'ids': set(), 'rank': -1, 'worst': 'UNKNOWN'})
            e['per_dev'].setdefault(r['ip'], set()).add(r['cve_id'])
            e['ids'].add(r['cve_id'])
            if rank > e['rank']:
                e['rank'], e['worst'] = rank, r['sev']
        if r['score'] is None:
            unscored += 1
        else:
            for b, (_label, lo, hi) in zip(bands, VULN_BANDS):
                if lo <= r['score'] < hi:
                    b['count'] += 1
                    break

    return {
        'services': len(services), 'found': found, 'none': none,
        'not_evaluated': sum(reasons.values()), 'not_evaluated_reasons': reasons,
        'status_recorded': any(s['status'] for s in services),     # False = every scan here is older than the status field
        'cve_total': len(cve_rows), 'device_total': len(per_dev),
        'top_devices': [{'ip': e['ip'], 'count': e['count'], 'worst': e['worst']}
                        for e in sorted(per_dev.values(), key=lambda e: (-e['count'], -e['rank'], _ip_sort_key(e['ip'])))[:5]],
        'top_services': [{'product': e['product'], 'devices': len(e['per_dev']), 'cves': len(e['ids']), 'worst': e['worst'],
                          'device_list': [{'ip': ip, 'cves': len(ids)} for ip, ids in
                                          sorted(e['per_dev'].items(), key=lambda kv: (-len(kv[1]), _ip_sort_key(kv[0])))[:OV_STRIP_MAX]]}
                         for e in sorted(per_prod.values(), key=lambda e: (-len(e['per_dev']), -e['rank'], -len(e['ids']), e['product'].lower()))[:5]],
        'bands': bands, 'unscored': unscored,
    }


def _vuln_overview(history):
    """Compatibility wrapper: builds the Vulnerabilities Overview from the newest vuln_scan per device."""
    return _vuln_overview_from_inventory(_build_device_inventory(history))


@app.route('/vulnerabilities')
@login_required
def vulnerabilities_page():
    """แสดง CVE ที่ยังพบอยู่ใน Vulnerability Scan ล่าสุดของแต่ละอุปกรณ์เท่านั้น (ไม่รวม CVE ที่ถูกแก้ไขไปแล้วจากสแกนเก่า)"""
    history = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
    inventory = _build_device_inventory(history)

    lang_now = ui_lang_now()
    cve_list = []
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}

    for dev in inventory:
        for finding in dev['active_cves'].values():
            sev = finding['severity']
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cve_list.append({
                'cve_id': finding['cve_id'],
                'severity': sev,
                'severity_note': severity_note(finding['cvss_score'], lang=lang_now) if finding['severity_adjusted'] else '',
                'cvss_score': finding['cvss_score'],
                'cwe_name': finding['cwe_name'],
                'cwe': cwe_info(finding['raw_cve'], lang=lang_now),
                'description': finding['description'],
                'ip': finding['ip'],
                'port': finding['port'],
                'protocol': finding['protocol'],
                'service': finding['service'],
                'job_id': finding['job_id'],
                'found_at': finding['timestamp'].strftime('%Y-%m-%d') if finding['timestamp'] else '',
                'kev': finding['kev'],
                'kev_added': finding['kev_added'],
            })

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    cve_list.sort(key=lambda c: (sev_order.get(c['severity'], 5), _ip_sort_key(c['ip']), c['cve_id']))

    # options for the filter bar: only the hosts / CWEs that actually appear, with how many rows each has
    host_counts, cwe_counts = {}, {}
    for c in cve_list:
        host_counts[c['ip']] = host_counts.get(c['ip'], 0) + 1
        w = c['cwe']
        if w:
            entry = cwe_counts.setdefault(w['id'], {'id': w['id'], 'label': w['compact'], 'count': 0})
            entry['count'] += 1

    host_options = sorted(host_counts.items(), key=lambda kv: _ip_sort_key(kv[0]))
    cwe_options = sorted(cwe_counts.values(), key=lambda e: (-e['count'], e['id']))
    return render_template('vulnerabilities.html', cves=cve_list, kev_count=sum(1 for c in cve_list if c['kev']),
                           severity_counts=severity_counts, total_cves=len(cve_list),
                           host_options=host_options, cwe_options=cwe_options,
                           overview=_vuln_overview_from_inventory(inventory))


def _report_row_stats(job):
    """The figures one row of the Reports page shows about a completed scan, so a person can tell which report is worth exporting.
    None means "not known", never zero: a scan that never listed ports has no port count, only a vulnerability scan whose open ports
    were all really looked up (cve_status "ok") may say 0 CVEs, and a scan type that does not look for CVEs has none."""
    out = {'hosts': None, 'ports': None, 'ports_partial': 0, 'cves': None, 'worst': None, 'sev_text': ''}
    try:
        data = json.loads(job.result_data) if job.result_data else None
    except ValueError:
        return out
    if not isinstance(data, list):
        return out
    rows = [h for h in data if isinstance(h, dict)]
    if not rows or rows[0].get('error'):
        return out
    out['hosts'] = len(rows)
    with_ports = [h for h in rows if isinstance(h.get('ports'), list)]
    if not with_ports:
        return out
    open_ports = [p for h in with_ports for p in h['ports'] if isinstance(p, dict) and str(p.get('state') or '').lower() == 'open']
    out['ports'] = len(open_ports)                      # state exactly open, host x port, like the scan report
    # hosts whose ports are not fully known (no list, timed out, nmap left open ports unlisted, or the UDP result is unknown): the figure is
    # "at least N" and 0 CVE is not established
    out['ports_partial'] = sum(1 for h in rows if scan_diff._ports_unknown(h) or scan_diff._udp_unknown(h))
    if job.scan_type == 'vuln_scan':
        sev = [(s, n) for s, n in cve_severity_counts(rows) if n]
        total = sum(n for _, n in sev)
        if total:
            out['cves'] = total
            out['worst'] = sev[0][0]
            out['sev_text'] = ' \u00b7 '.join('%s %d' % (sev_label(s), n) for s, n in sev)
        elif open_ports and not out['ports_partial'] and all(p.get('cve_status') == 'ok' for p in open_ports):
            out['cves'] = 0
    return out


@app.route('/reports')
@login_required
def reports_page():
    """รายการ scan ที่เสร็จสมบูรณ์ พร้อมลิงก์ export CSV / PDF"""
    history = visible_scans_query().filter_by(status='Completed').order_by(ScanJob.timestamp.desc()).all()

    owner_seq_map = {j.id: j.id for j in history}

    from collections import Counter
    stats = {j.id: _report_row_stats(j) for j in history}
    type_options = sorted(Counter(j.scan_type for j in history).items(), key=lambda kv: (-kv[1], str(kv[0])))
    return render_template('reports.html', history=history, owner_seq_map=owner_seq_map, stats=stats, type_options=type_options)


@app.route('/settings')
@login_required
def settings_page():
    ai = _ai_usage_summary() if current_user.is_any_admin else None
    nvd = _nvd_summary() if current_user.is_any_admin else None
    return render_template('settings.html', ai=ai, nvd=nvd, can_change_ai=current_user.is_superadmin)


# ─────────────────────────────────────────
#  API
# ─────────────────────────────────────────

def _target_sort_key(target):
    """Order for the saved-target list: by the first address, numerically (10.5.51.9 before 10.5.51.44; plain string order puts .44 first),
    then by prefix length. Names and IPv6 come after the IPv4 addresses, alphabetically."""
    tokens = (target or '').split()
    first = tokens[0] if tokens else ''
    addr, _, mask = first.partition('/')
    return (_ip_sort_key(addr.split(',')[0]), int(mask) if mask.isdigit() else 0, target or '')


@app.route('/api/scanned-ips')
@login_required
def scanned_ips():
    """The saved targets for the New Scan box. `size` is how many addresses the target names, `kind` is 'net' for more than one and
    'host' for one, `big` that it is over the -Pn limit (`pn_max`). The list is shared by every user. Sorted numerically."""
    saved = SavedTarget.query.all()
    rows = []
    for s in saved:
        size = target_size(s.target)
        rows.append({'id': s.id, 'target': s.target, 'label': s.label or '', 'size': size,
                     'kind': 'net' if size > 1 else 'host',
                     'big': size > PN_MAX_ADDRESSES, 'pn_max': PN_MAX_ADDRESSES})
    rows.sort(key=lambda r: _target_sort_key(r['target']))
    return jsonify(rows)


@app.route('/api/scanned-ips', methods=['POST'])
@login_required
@admin_required
def save_ip():
    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    label = (data.get('label') or '').strip() or None
    if not target:
        return jsonify({'error': 'target required'}), 400
    if len(target) > 100 or not is_valid_target(target):      # the same rule a scan applies; the column holds 100 characters
        return jsonify({'error': 'invalid target'}), 400
    if label and len(label) > 150:
        return jsonify({'error': 'label too long'}), 400
    if SavedTarget.query.filter_by(target=target).first():
        return jsonify({'error': 'already exists'}), 409
    s = SavedTarget(target=target, label=label)
    db.session.add(s)
    db.session.commit()
    return jsonify({'id': s.id, 'target': s.target, 'label': s.label or ''}), 201


@app.route('/api/scanned-ips/<int:ip_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_saved_ip(ip_id):
    s = SavedTarget.query.get_or_404(ip_id)
    db.session.delete(s)
    db.session.commit()
    return jsonify({'deleted': ip_id})


@app.route('/api/jobs/<int:job_id>/details')
@login_required
def api_job_details(job_id):
    """Everything the Tasks page's details panel shows for one job. The results are parsed here, for one job at a time, so the
    3-second job list does not have to carry or parse every scan's result data."""
    job = visible_scans_query().filter_by(id=job_id).first_or_404()
    hosts = open_ports = cves = error = None
    custom_args = job.custom_args
    data = None
    if job.result_data:
        try:
            data = json.loads(job.result_data)
        except ValueError:
            data = None
    if isinstance(data, list):
        if data and isinstance(data[0], dict) and data[0].get('error'):
            error = str(data[0]['error'])[:500]
        else:
            rows = [h for h in data if isinstance(h, dict)]
            hosts = len(rows)
            open_ports = sum(1 for h in rows for p in (h.get('ports') or [])
                             if str(p.get('state') or '').lower() == 'open')       # state exactly open, like everywhere else
            if job.scan_type == 'vuln_scan':
                cves = sum(n for _, n in cve_severity_counts(rows))                # the same total as the report's CVE Found card
            if not custom_args and job.scan_type == 'custom':
                # jobs from before the column existed: a custom scan keeps its validated arguments in every result row
                custom_args = next((h.get('custom_args') for h in rows if h.get('custom_args')), None)
    # When the scan started: the worker's own record, else (a job from before the queue existed, which ran at once) the time it was created.
    # A job still waiting has not started.
    began = job.started_at or (job.timestamp if job.status != 'Queued' else None)
    duration = None
    if job.finished_at and began and job.finished_at >= began:
        duration = int((job.finished_at - began).total_seconds())
    return jsonify({
        'id': job.id, 'status': job.status, 'target': job.target, 'name': job.scan_name or '',
        'triggered_by': job.triggered_by or 'manual',
        'owner': job.owner.username if job.owner else '',
        'created': job.timestamp.strftime('%Y-%m-%d %H:%M:%S') if job.timestamp else '',
        'started': began.strftime('%Y-%m-%d %H:%M:%S') if began else '',
        'finished': job.finished_at.strftime('%Y-%m-%d %H:%M:%S') if job.finished_at else '',
        'duration': duration,
        'hosts': hosts, 'open_ports': open_ports, 'cves': cves, 'error': localized_job_error(error),
        'settings': describe_scan_settings(job.scan_type, job.timing, job.version_intensity, custom_args, job.multicast, job.skip_ping, job.all_ports, job.no_dns, job.host_probes, job.gentle, job.udp, job.udp_top),
        'run': describe_run(job),
    })


@app.route('/api/scan-command')
@login_required
@admin_required
def api_scan_command():
    """What the New Scan dialog's command box shows (like Zenmap's Command line): the nmap arguments the form would run with its CURRENT
    choices. It is built by the same functions a real scan uses (clamp_scan_knobs and job_skip_ping, as the form route does, then
    describe_scan_settings, which calls scan_arguments), so the preview cannot drift from what runs, and it starts and stores nothing.
    Returns describe_scan_settings()'s facts (arguments without the target, steps) plus `internal`: the flags the runner adds by itself
    and the Tasks page does not show either. The page puts the target after the arguments."""
    scan_type = request.args.get('scan_type', 'fast_scan')
    if scan_type not in ('discovery', 'fast_scan', 'intense', 'custom', 'vuln_scan'):
        return jsonify({'error': 'bad scan type'}), 400
    custom_args = (request.args.get('custom_args') or '').strip()[:500] or None
    timing, version_intensity = clamp_scan_knobs(request.args.get('timing'), request.args.get('version_intensity'), scan_type=scan_type)
    skip_ping = job_skip_ping(scan_type, custom_args, request.args.get('skip_ping'))
    multicast = scan_type == 'discovery' and request.args.get('multicast') == '1'
    all_ports = job_all_ports(scan_type, request.args.get('all_ports'))
    no_dns = job_no_dns(scan_type, request.args.get('no_dns'))
    host_probes = job_probes(scan_type, request.args.get('host_probes'))
    gentle = job_gentle(scan_type, request.args.get('gentle'))
    udp = job_udp(scan_type, request.args.get('udp'))
    udp_top = job_udp_top(scan_type, udp, request.args.get('udp_top'))
    settings = describe_scan_settings(scan_type, timing, version_intensity, custom_args, multicast, skip_ping, all_ports, no_dns, host_probes, gentle, udp, udp_top)
    settings['limit'] = {'max_addresses': ALL_PORTS_MAX_ADDRESSES}
    settings['internal'] = '-oX - --stats-every %s' % PROGRESS_EVERY
    resp = jsonify(settings)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


PROGRESS_FRESH_SECONDS = 4 * 3      # nmap is asked to report every 3 s (scanner.PROGRESS_EVERY); a report older than about four of those is not shown


@app.route('/api/jobs/progress')
@login_required
def api_jobs_progress():
    """Where each waiting or running scan the caller may see stands, for the Tasks page: {"<job id>": {...}} and {} when nothing is active.
    It is a separate endpoint on purpose: /api/jobs must not carry anything that changes between two polls (the Tasks table is rebuilt whenever
    that JSON changes), and progress changes at every poll.
      queued:  {state, position}  the place among the jobs still waiting (a job cancelled while it waited stays in the in-memory queue until a
               worker skips it, so the queue is filtered by what the database says)
      running: {state, elapsed_s, ...} plus, only while nmap's last report is fresh, task, percent and remaining_s (a step that ended without a
               new report must not leave an old percentage on screen: unknown stays unknown), or nvd {done, total} during the CVE lookups.
    Percent and remaining belong to the ONE step named in `task`; there is no whole-scan percentage."""
    rows = (visible_scans_query().filter(ScanJob.status.in_(ACTIVE_STATUSES))
            .with_entities(ScanJob.id, ScanJob.status, ScanJob.started_at).all())
    out = {}
    if rows:
        waiting = scan_runner.queue_job_ids()
        still_queued = ({i for (i,) in ScanJob.query.filter(ScanJob.id.in_(waiting), ScanJob.status == 'Queued').with_entities(ScanJob.id).all()}
                        if waiting else set())
        order = [i for i in waiting if i in still_queued]
        now = now_th()
        for job_id, status, started in rows:
            if status == 'Queued':
                entry = {'state': 'queued'}
                if job_id in order:
                    entry['position'] = order.index(job_id) + 1
                out[str(job_id)] = entry
                continue
            entry = {'state': 'running'}
            if started:
                entry['elapsed_s'] = max(0, int((now - started).total_seconds()))
            info = scan_runner.progress_for(job_id)
            fields = info.get('fields') if info else None
            if fields and fields.get('kind') == 'nvd':
                entry['nvd'] = {'done': int(fields.get('done') or 0), 'total': int(fields.get('total') or 0)}
            elif fields and fields.get('kind') == 'nmap' and info.get('age') is not None and info['age'] <= PROGRESS_FRESH_SECONDS:
                entry['task'] = fields.get('task') or ''
                entry['percent'] = fields.get('percent')
                if fields.get('remaining') is not None:
                    entry['remaining_s'] = max(0, int(fields['remaining'] - info['age']))
            out[str(job_id)] = entry
    resp = jsonify(out)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/jobs')
@login_required
def api_jobs():
    total_jobs = visible_scans_query().count()
    jobs = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).limit(100).all()
    from collections import defaultdict
    target_jobs = defaultdict(list)
    for j in jobs:
        target_jobs[j.target].append(j)
    target_seq = {}
    for target, tlist in target_jobs.items():
        sorted_list = sorted(tlist, key=lambda x: x.timestamp or 0)
        for idx, tj in enumerate(sorted_list, 1):
            target_seq[tj.id] = (idx, len(sorted_list))

    owner_seq_map = {j.id: j.id for j in jobs}

    result = []
    for j in jobs:
        seq, total = target_seq.get(j.id, (1, 1))
        finished = j.finished_at
        result.append({
            'id': j.id,
            'owner_seq': owner_seq_map.get(j.id, j.id),
            'scan_name': j.scan_name or '',
            'target': j.target,
            'scan_type': j.scan_type,
            'status': j.status,
            'triggered_by': j.triggered_by or 'manual',
            'timestamp': j.timestamp.strftime('%Y-%m-%d %H:%M:%S') if j.timestamp else '',
            'scan_seq': seq,
            'scan_total': total,
            'timing': j.timing,
            'version_intensity': j.version_intensity,
            'skip_ping': bool(j.skip_ping),
            'all_ports': bool(j.all_ports),
            'no_dns': bool(j.no_dns),
            'host_probes': bool(j.host_probes),
            'gentle': bool(j.gentle),
            'udp': bool(j.udp),
            'udp_top': j.udp_top,
            # for the "scan finished" toast. Only values that do NOT change between two polls: the Tasks page rebuilds its table when this JSON
            # differs from the last poll, so something like "seconds since it finished" would rebuild it every 3 seconds.
            'scan_label': scan_labels().get(j.scan_type, j.scan_type),
            'finished_at': finished.strftime('%Y-%m-%d %H:%M:%S') if finished else '',
            'duration_s': max(0, int((finished - j.timestamp).total_seconds())) if finished and j.timestamp else None,
        })
    resp = jsonify(result)
    resp.headers['X-Server-Time'] = now_th().strftime('%Y-%m-%d %H:%M:%S')       # same clock and format as finished_at, so the page can compare them
    resp.headers['X-Total-Jobs'] = str(total_jobs)
    return resp


# ─────────────────────────────────────────
#  SCAN DETAIL
# ─────────────────────────────────────────

def hidden_port_summary(ports, shown):
    """What sits behind a host's "show more ports" bar in a scan report: the states of the ports after the first `shown`
    ('open' first) and, in a vulnerability scan, how many CVEs of each severity they hold (via effective_severity)."""
    states, severities = {}, {}
    for p in (ports or [])[shown:]:
        if not isinstance(p, dict):
            continue
        state = str(p.get('state') or 'unknown').lower()
        states[state] = states.get(state, 0) + 1
        for cve in (p.get('cves') or []):
            sev = effective_severity(cve)
            if sev not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):         # no label, or one we do not colour: still a CVE
                sev = 'UNKNOWN'
            severities[sev] = severities.get(sev, 0) + 1
    state_order = {'open': 0, 'open|filtered': 1, 'filtered': 2, 'closed': 3}
    return {
        'states': sorted(states.items(), key=lambda kv: (state_order.get(kv[0], 9), kv[0])),
        'severities': [(s, severities[s]) for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN') if s in severities],
    }


app.jinja_env.globals['hidden_port_summary'] = hidden_port_summary


def cve_severity_counts(hosts):
    """CVEs per severity over every port of every host in a scan report (effective_severity, so a CVSS v2-only 10.0 counts as
    Critical): [(severity, n), ...] always for CRITICAL, HIGH, MEDIUM, LOW, and UNKNOWN only when some CVE has no usable label.
    The report's "CVE Found" card shows these next to its total, so the total does not read as "N critical"."""
    counts = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')}
    for host in (hosts or []):
        if isinstance(host, dict):
            for sev, n in hidden_port_summary(host.get('ports'), 0)['severities']:
                counts[sev] += n
    return [(s, n) for s, n in counts.items() if n or s != 'UNKNOWN']


app.jinja_env.globals['cve_severity_counts'] = cve_severity_counts


@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []
    for h in scan_data:   # derived at view time from the MAC, so scans stored before this existed get it too
        if isinstance(h, dict):
            h['vm'] = virtual_machine_platform(h.get('mac'), h.get('mac_vendor'))
    # ?host=<ip> (dashboard device rows, Devices page): show just that device. Only honoured when the IP is
    # really in this scan, so a stale or hand-edited link falls back to the whole report.
    focus_ip = (request.args.get('host') or '').strip()
    total_hosts = sum(1 for h in scan_data if isinstance(h, dict) and h.get('ip'))
    focused = [h for h in scan_data if isinstance(h, dict) and h.get('ip') == focus_ip] if focus_ip else []
    if focused:
        scan_data = focused
    else:
        focus_ip = ''
    host_count = sum(1 for h in scan_data if isinstance(h, dict) and h.get('ip'))
    same_target_jobs = visible_scans_query().filter_by(target=job.target).order_by(ScanJob.timestamp).all()
    target_scan_count = len(same_target_jobs)
    scan_seq = next((i+1 for i, j in enumerate(same_target_jobs) if j.id == job.id), 1)

    owner_seq = job.id

    system_gw = get_system_default_gateway()
    scan_public_ip = scan_run_info(job).get('public_ip') or ''
    template = 'vuln_scan_detail.html' if job.scan_type == 'vuln_scan' else 'scan_detail.html'
    changes = scan_changes(job) if not focus_ip else None       # one device (?host=) is a different question: no whole-scan comparison
    return render_template(template, job=job, scan_data=scan_data, run=describe_run(job), changes=changes,
                           target_scan_count=target_scan_count, scan_seq=scan_seq,
                           owner_seq=owner_seq, system_gateway=system_gw, scan_public_ip=scan_public_ip,
                           focus_ip=focus_ip, total_hosts=total_hosts, host_count=host_count)


def _owner_seq_map(owner_ids):
    """Job id -> displayed Job # (always job.id so screen numbers match /scan/<id> URLs)."""
    seq = {}
    for oid in owner_ids:
        rows = ScanJob.query.filter_by(owner_id=oid).with_entities(ScanJob.id).all()
        for r in rows:
            seq[r.id] = r.id
    return seq


@app.route('/devices/<ip>')
@login_required
def device_detail(ip):
    """One page per device (one IP) over every scan the user may see: who it is, its open ports, its CVEs and where they came from, and which
    scans saw it. The work is in device_builder.build_device; this only fetches the scans (through visible_scans_query, so another admin's
    device is a 404, not a leak)."""
    ip = (ip or '').strip()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        abort(404)
    if '%' in ip:
        abort(404)
    q = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc())
    if ip_obj.version == 4:               # only the scans whose stored result text mentions this address (an IPv6 address can be written several ways)
        q = q.filter(ScanJob.result_data.contains(f'"ip": "{ip}"', autoescape=True))
    jobs = q.all()
    seq = _owner_seq_map({j.owner_id for j in jobs if j.owner_id is not None})
    scans = []
    for j in jobs:
        try:
            hosts = json.loads(j.result_data) if j.result_data else []
        except ValueError:
            hosts = []
        scans.append({'id': j.id, 'seq': seq.get(j.id, j.id), 'scan_type': j.scan_type, 'status': j.status, 'scan_name': j.scan_name,
                      'timestamp': j.timestamp, 'hosts': hosts if isinstance(hosts, list) else []})
    dev = device_builder.build_device(ip, scans, scan_labels())
    if dev is None:
        abort(404)
    return render_template('device_detail.html', dev=dev)


# ─────────────────────────────────────────
#  SCHEDULED SCANS
# ─────────────────────────────────────────

@app.route('/schedules/create', methods=['POST'])
@login_required
@admin_required
def create_schedule():
    target = (request.form.get('target') or '').strip()
    if not target or len(target) > 100 or not is_valid_target(target):
        flash(tr('flash.target_invalid', target=target or '—'), 'danger')
        return redirect(url_for('tasks_page'))
    name = (request.form.get('name') or '').strip()[:100] or target
    scan_type = (request.form.get('scan_type') or '').strip()
    if scan_type not in ALLOWED_FORM_SCAN_TYPES:
        flash(tr('flash.scan_type_invalid'), 'danger')
        return redirect(url_for('tasks_page'))
    repeat = (request.form.get('repeat') or 'daily').strip()
    if repeat not in ('daily', 'weekly', 'monthly'):
        flash(tr('flash.repeat_invalid'), 'danger')
        return redirect(url_for('tasks_page'))
    time_str = (request.form.get('time') or '').strip()
    custom_args = request.form.get('custom_args', '').strip() or None
    timing, version_intensity = clamp_scan_knobs(request.form.get('timing'), request.form.get('version_intensity'), scan_type=scan_type)
    skip_ping = job_skip_ping(scan_type, custom_args, request.form.get('skip_ping'))
    all_ports = job_all_ports(scan_type, request.form.get('all_ports'))
    no_dns = job_no_dns(scan_type, request.form.get('no_dns'))
    host_probes = job_probes(scan_type, request.form.get('host_probes'))
    gentle = job_gentle(scan_type, request.form.get('gentle'))
    udp = job_udp(scan_type, request.form.get('udp'))
    udp_top = job_udp_top(scan_type, udp, request.form.get('udp_top'))
    if gentle:
        timing = None      # Gentle sets the speed itself
    refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp, udp_top, timing)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('tasks_page'))

    try:
        parts = time_str.split(':')
        if len(parts) != 2:
            raise ValueError(time_str)
        hour, minute = int(parts[0]), int(parts[1])
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError(time_str)
    except (TypeError, ValueError):
        flash(tr('flash.time_invalid'), 'danger')
        return redirect(url_for('tasks_page'))

    day_of_week = None
    if repeat == 'weekly':
        try:
            day_of_week = int(request.form.get('day_of_week', 0))
            if not 0 <= day_of_week <= 6:
                raise ValueError(day_of_week)
        except (TypeError, ValueError):
            flash(tr('flash.weekday_invalid'), 'danger')
            return redirect(url_for('tasks_page'))

    day_of_month = None
    if repeat == 'monthly':
        try:
            day_of_month = int(request.form.get('day_of_month', 1))
            if not 1 <= day_of_month <= 31:
                raise ValueError(day_of_month)
        except (TypeError, ValueError):
            flash(tr('flash.day_invalid'), 'danger')
            return redirect(url_for('tasks_page'))

    schedule = ScheduledScan(
        name=name, target=target, scan_type=scan_type,
        cron_hour=hour, cron_minute=minute,
        repeat=repeat, day_of_week=day_of_week, day_of_month=day_of_month,
        is_active=True, created_by=current_user.id,
        owner_id=current_user.id,
        custom_args=custom_args if scan_type == 'custom' else None,
        timing=timing, version_intensity=version_intensity, skip_ping=skip_ping, all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp, udp_top=udp_top,
    )
    schedule.next_run = calc_next_run(schedule)
    db.session.add(schedule)
    db.session.commit()
    register_apscheduler_job(schedule)

    flash(tr('flash.schedule_created', name=name, when=fmt_dt(schedule.next_run)), 'success')
    return redirect(url_for('tasks_page'))


@app.route('/schedules/<int:schedule_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_schedule(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    schedule.is_active = not schedule.is_active
    if schedule.is_active:
        schedule.next_run = calc_next_run(schedule)
    db.session.commit()
    register_apscheduler_job(schedule)
    return jsonify({'is_active': schedule.is_active,
                    'next_run': schedule.next_run.strftime('%Y-%m-%d %H:%M') if schedule.next_run else None})


@app.route('/schedules/<int:schedule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_schedule(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    job_id = f'schedule_{schedule.id}'
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    db.session.delete(schedule)
    db.session.commit()
    flash(tr('flash.schedule_deleted', name=schedule.name), 'success')
    return redirect(url_for('tasks_page'))


@app.route('/tasks/<int:job_id>/cancel', methods=['POST'])
@login_required
@admin_required
def cancel_job(job_id):
    """Stops a scan that is waiting or running. A waiting job is never started (the worker finds it is no longer 'Queued'); a running one has its
    nmap killed through scan_runner. The change of status is one conditional update, so a scan that finished a moment ago is not turned into
    Cancelled, and the worker's own final write cannot undo this one (it only touches a row that is still 'Running')."""
    job = visible_scans_query().filter_by(id=job_id).first_or_404()
    changed = (ScanJob.query.filter(ScanJob.id == job.id, ScanJob.status.in_(ACTIVE_STATUSES))
               .update({'status': 'Cancelled', 'finished_at': now_th()}, synchronize_session=False))
    db.session.commit()
    if not changed:
        return jsonify({'error': 'Job is not running'}), 400
    scan_runner.cancel(job.id)
    return jsonify({'success': True, 'status': 'Cancelled'})


@app.route('/tasks/<int:job_id>/rescan', methods=['POST'])
@login_required
@admin_required
def rescan_job(job_id):
    """สร้าง job ใหม่ด้วย target เดิม + scan_type ที่เลือกใหม่ (เก็บ job เดิมไว้เป็นประวัติ)"""
    original = visible_scans_query().filter_by(id=job_id).first_or_404()

    # ห้าม rescan ถ้า scan มาจาก XML Upload
    if original.scan_type == 'xml_upload':
        flash(tr('flash.rescan_xml'), 'danger')
        return redirect(url_for('tasks_page'))

    # ห้าม rescan ถ้า target นี้กำลังรอคิวหรือ Running อยู่
    running = visible_scans_query().filter(ScanJob.target == original.target, ScanJob.status.in_(ACTIVE_STATUSES)).first()
    if running:
        flash(tr('flash.target_busy', target=original.target), 'danger')
        return redirect(url_for('tasks_page'))

    scan_type   = request.form.get('scan_type', original.scan_type)
    scan_name   = original.scan_name
    target      = original.target
    custom_args = request.form.get('custom_args', '').strip() or None
    multicast = scan_type == 'discovery' and request.form.get('multicast') == '1'   # mDNS/SSDP lookup, off unless ticked
    timing, version_intensity = clamp_scan_knobs(request.form.get('timing'), request.form.get('version_intensity'), scan_type=scan_type)
    skip_ping = job_skip_ping(scan_type, custom_args, request.form.get('skip_ping'))
    all_ports = job_all_ports(scan_type, request.form.get('all_ports'))
    no_dns = job_no_dns(scan_type, request.form.get('no_dns'))
    host_probes = job_probes(scan_type, request.form.get('host_probes'))
    gentle = job_gentle(scan_type, request.form.get('gentle'))
    udp = job_udp(scan_type, request.form.get('udp'))
    udp_top = job_udp_top(scan_type, udp, request.form.get('udp_top'))
    if gentle:
        timing = None      # Gentle sets the speed itself
    refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp, udp_top, timing)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('tasks_page'))

    # เก็บ job เดิมไว้เป็นประวัติ — ไม่ลบ
    # สร้าง job ใหม่เพิ่มเข้าไป
    new_job = ScanJob(
        target=target,
        scan_type=scan_type,
        scan_name=scan_name,
        status='Queued',
        triggered_by='rescan',
        owner_id=current_user.id,
        timing=timing,
        version_intensity=version_intensity,
        custom_args=custom_args if scan_type == 'custom' else None,
        multicast=multicast if scan_type == 'discovery' else None,
        skip_ping=skip_ping,
        all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp, udp_top=udp_top,
    )
    db.session.add(new_job)
    db.session.commit()
    return _scan_started_redirect(new_job)



@app.route('/scan/<int:scan_id>/drilldown', methods=['POST'])
@login_required
@admin_required
def drilldown_scan(scan_id):
    """Progressive Drill-down: สแกน host เฉพาะตัวจากผลสแกนครั้งก่อน"""
    parent_job = visible_scans_query().filter_by(id=scan_id).first_or_404()

    host_ip   = request.form.get('host_ip', '').strip()
    scan_type = request.form.get('scan_type', 'fast_scan')
    custom_args = request.form.get('custom_args', '').strip() or None
    timing, version_intensity = clamp_scan_knobs(request.form.get('timing'), request.form.get('version_intensity'), scan_type=scan_type)
    skip_ping = job_skip_ping(scan_type, custom_args, request.form.get('skip_ping'))
    all_ports = job_all_ports(scan_type, request.form.get('all_ports'))
    no_dns = job_no_dns(scan_type, request.form.get('no_dns'))
    host_probes = job_probes(scan_type, request.form.get('host_probes'))
    gentle = job_gentle(scan_type, request.form.get('gentle'))
    udp = job_udp(scan_type, request.form.get('udp'))
    udp_top = job_udp_top(scan_type, udp, request.form.get('udp_top'))
    if gentle:
        timing = None      # Gentle sets the speed itself

    if not host_ip:
        flash(tr('flash.ip_required'), 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))
    if len(host_ip) > 100 or not is_valid_target(host_ip):
        flash(tr('flash.target_invalid', target=host_ip), 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))
    if scan_type not in ALLOWED_FORM_SCAN_TYPES:
        flash(tr('flash.scan_type_invalid'), 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    refusal = scan_option_refusal(host_ip, skip_ping, all_ports, host_probes, gentle, udp, udp_top, timing)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # ตรวจว่า IP นี้กำลังสแกนอยู่หรือไม่
    running = visible_scans_query().filter(ScanJob.target == host_ip, ScanJob.status.in_(ACTIVE_STATUSES)).first()
    if running:
        flash(tr('flash.target_busy', target=host_ip), 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # สร้าง scan name ที่อ้างอิง parent scan
    parent_label = parent_job.scan_name or job_label(_job_seq(parent_job))
    scan_name = (f'สแกนเจาะลึก: {host_ip} (จาก {parent_label})' if ui_lang_now() != 'en'
                 else f'Drill-down: {host_ip} (from {parent_label})')

    new_job = ScanJob(
        target=host_ip,
        scan_type=scan_type,
        scan_name=scan_name,
        status='Queued',
        triggered_by='drilldown',
        owner_id=current_user.id,
        timing=timing,
        version_intensity=version_intensity,
        custom_args=custom_args if scan_type == 'custom' else None,
        multicast=False if scan_type == 'discovery' else None,   # a drill-down never listens for mDNS/SSDP
        skip_ping=skip_ping,
        all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp, udp_top=udp_top,
    )
    db.session.add(new_job)
    # บันทึก IP ไว้ในรายชื่อ saved targets ถ้ายังไม่มี
    if not SavedTarget.query.filter_by(target=host_ip).first():
        db.session.add(SavedTarget(target=host_ip))
    db.session.commit()
    return _scan_started_redirect(new_job)


@app.route('/schedules/<int:schedule_id>/run_now', methods=['POST'])
@login_required
@admin_required
def run_schedule_now(schedule_id):
    schedule = visible_schedules_query().filter_by(id=schedule_id).first_or_404()
    execute_scheduled_scan(schedule.id)
    flash(tr('flash.schedule_triggered', name=schedule.name), 'success')
    return redirect(url_for('tasks_page'))


# ─────────────────────────────────────────
#  USER MANAGEMENT
# ─────────────────────────────────────────

@app.route('/users')
@login_required
@user_management_required
def user_management():
    if current_user.role == 'superadmin':
        # superadmin เห็น: admin ทุกคน + user ทุกคน (ยกเว้นตัวเอง)
        admins = User.query.filter_by(role='admin').order_by(User.id).all()
        users  = User.query.filter_by(role='user').order_by(User.id).all()
    else:
        # admin เห็น: เฉพาะ user ใต้สังกัดตัวเอง
        admins = []
        users  = User.query.filter_by(role='user', created_by=current_user.id).order_by(User.id).all()

    return render_template('user_management.html', admins=admins, users=users)


@app.route('/users/create', methods=['POST'])
@login_required
@user_management_required
def create_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role     = request.form.get('role', 'user')

    # admin ธรรมดาสร้างได้แค่ user เท่านั้น
    if current_user.role == 'admin' and role != 'user':
        flash(tr('flash.admin_creates_users_only'), 'danger')
        return redirect(url_for('user_management'))

    if not username or not password:
        flash(tr('flash.credentials_required'), 'danger')
        return redirect(url_for('user_management'))

    if User.query.filter_by(username=username).first():
        flash(tr('flash.username_taken', username=username), 'danger')
        return redirect(url_for('user_management'))

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        created_by=current_user.id
    )
    db.session.add(new_user)
    db.session.commit()
    flash(tr('flash.account_created', role=tr('role.' + role), username=username), 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@user_management_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash(tr('flash.cannot_delete_self'), 'danger')
        return redirect(url_for('user_management'))

    # superadmin ลบได้ทุกคน ยกเว้น superadmin ด้วยกัน
    if user.role == 'superadmin':
        flash(tr('flash.cannot_delete_superadmin'), 'danger')
        return redirect(url_for('user_management'))

    # admin ลบได้เฉพาะ user ใต้สังกัดตัวเอง
    if current_user.role == 'admin' and user.created_by != current_user.id:
        abort(403)

    deleted_username = user.username
    deleted_role = user.role

    # ถ้าลบ admin ให้ลบข้อมูลและบัญชีของ user ใต้สังกัดทั้งหมดด้วย
    sub_users = User.query.filter_by(created_by=user.id).all() if user.role == 'admin' else []
    victims = [user] + sub_users
    forgotten = [u.id for u in victims]
    forgotten_names = [u.username for u in victims]

    _purge_user_data(forgotten, forgotten_names)
    for sub_user in sub_users:
        db.session.delete(sub_user)
    db.session.delete(user)
    db.session.commit()
    for uid in forgotten:
        _forget_user_key(uid)

    if deleted_role == 'admin':
        flash(tr('flash.admin_deleted', username=deleted_username), 'success')
    else:
        flash(tr('flash.user_deleted', username=deleted_username), 'success')
    return redirect(url_for('user_management'))


def _set_suspended(user_id, suspend):
    """Suspends or reactivates an account without deleting anything it owns. Who may: a superadmin, any admin or user except a superadmin; an
    admin, only the users they created; nobody, their own account."""
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash(tr('flash.cannot_suspend_self'), 'danger')
        return redirect(url_for('user_management'))
    if user.role == 'superadmin':
        flash(tr('flash.cannot_suspend_superadmin'), 'danger')
        return redirect(url_for('user_management'))
    if current_user.role == 'admin' and user.created_by != current_user.id:
        abort(403)
    user.is_suspended = bool(suspend)
    user.suspended_at = now_th() if suspend else None
    db.session.commit()
    flash(tr('flash.user_suspended' if suspend else 'flash.user_unsuspended', username=user.username), 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/suspend', methods=['POST'])
@login_required
@user_management_required
def suspend_user(user_id):
    return _set_suspended(user_id, True)


@app.route('/users/<int:user_id>/unsuspend', methods=['POST'])
@login_required
@user_management_required
def unsuspend_user(user_id):
    return _set_suspended(user_id, False)


@app.route('/users/<int:user_id>/reassign', methods=['POST'])
@login_required
@superadmin_required
def reassign_user(user_id):
    """ย้าย User ไปสังกัด Admin คนอื่น — เฉพาะ Superadmin เท่านั้นที่ทำได้
    (Admin ปกติไม่มีสิทธิ์เข้าถึง route นี้ เพราะโดน @superadmin_required บล็อกไว้)"""
    user = User.query.get_or_404(user_id)

    # โยกได้เฉพาะ user ธรรมดาเท่านั้น ไม่ใช่ admin/superadmin
    if user.role != 'user':
        flash(tr('flash.move_users_only'), 'danger')
        return redirect(url_for('user_management'))

    new_admin_id = request.form.get('new_admin_id', '').strip()
    if not new_admin_id:
        flash(tr('flash.pick_target_admin'), 'danger')
        return redirect(url_for('user_management'))

    try:
        new_admin_pk = int(new_admin_id)
    except (TypeError, ValueError):
        flash(tr('flash.target_admin_missing'), 'danger')
        return redirect(url_for('user_management'))

    new_admin = User.query.get(new_admin_pk)
    if not new_admin or new_admin.role not in ('admin', 'superadmin'):
        flash(tr('flash.target_admin_missing'), 'danger')
        return redirect(url_for('user_management'))

    old_admin_name = user.creator.username if user.creator else '—'
    user.created_by = new_admin.id
    db.session.commit()
    flash(tr('flash.user_moved', user=user.username, old=old_admin_name, new=new_admin.username), 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@user_management_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)

    # ป้องกัน admin reset password ของ user ที่ไม่ใช่ของตัวเอง
    if current_user.role == 'admin' and user.created_by != current_user.id and user.id != current_user.id:
        abort(403)

    # ป้องกัน reset password ของ superadmin
    if user.role == 'superadmin' and current_user.role != 'superadmin':
        abort(403)

    new_pw = request.form.get('new_password', '').strip()
    if not new_pw:
        flash(tr('flash.new_password_required'), 'danger')
        return redirect(url_for('user_management'))

    user.password_hash = generate_password_hash(new_pw)
    _clear_user_login_throttle(user.username)
    db.session.commit()
    flash(tr('flash.password_reset', user=user.username), 'success')
    return redirect(url_for('user_management'))


# ─────────────────────────────────────────
#  UPLOAD XML
# ─────────────────────────────────────────

@app.route('/upload-xml', methods=['POST'])
@login_required
@admin_required
def upload_xml():
    import xml.etree.ElementTree as ET
    import ipaddress
    import os

    file = request.files.get('nmap_xml')
    if not file or file.filename == '':
        flash(tr('flash.xml_required'), 'danger')
        return redirect(url_for('tasks_page'))

    if not file.filename.lower().endswith('.xml'):
        flash(tr('flash.xml_extension'), 'danger')
        return redirect(url_for('tasks_page'))

    scan_name = request.form.get('xml_scan_name', '').strip() or os.path.splitext(file.filename)[0]

    try:
        xml_content = file.read()
        root = ET.fromstring(xml_content)
    except (ET.ParseError, ValueError, UnicodeDecodeError):
        flash(tr('flash.xml_invalid'), 'danger')
        return redirect(url_for('tasks_page'))

    scan_results = []
    hosts_el = root.findall('host')
    if not hosts_el:
        flash(tr('flash.xml_no_hosts'), 'danger')
        return redirect(url_for('tasks_page'))

    targets_found = []
    skipped_hosts = 0
    for host in hosts_el:
        status_el = host.find('status')
        if status_el is None or status_el.get('state') != 'up':
            continue
        # not `find(ipv4) or find(any)`: a childless element is falsy, so that always took the first <address> (often the MAC)
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find('address')
        ip = addr_el.get('addr', '') if addr_el is not None else ''
        # The address is stored as the host's identity and shown all over the UI, so it has to be a real IP.
        # '%' is refused as well: Python 3.9+ accepts "fe80::1%<any text>" as an IPv6 address with a zone id.
        try:
            ipaddress.ip_address(ip)
            valid_ip = '%' not in ip
        except ValueError:
            valid_ip = False
        if not valid_ip:
            skipped_hosts += 1
            continue
        targets_found.append(ip)
        mac_el = host.find("address[@addrtype='mac']")
        mac = mac_el.get('addr', 'Unknown') if mac_el is not None else 'Unknown'
        mac_vendor = mac_el.get('vendor', '') if mac_el is not None else ''
        osmatch = host.find('.//osmatch')
        os_info = osmatch.get('name', 'Unknown') if osmatch is not None else 'Unknown'
        os_accuracy = os_match_accuracy(osmatch.get('accuracy')) if osmatch is not None else None
        ports = []
        for port_el in host.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None:
                continue
            service_el = port_el.find('service')
            name = service_el.get('name', '') if service_el is not None else ''
            product = service_el.get('product', '') if service_el is not None else ''
            version = service_el.get('version', '') if service_el is not None else ''
            extrainfo = service_el.get('extrainfo', '') if service_el is not None else ''
            full_version = f"{product} {version} {extrainfo}".strip() or 'Unknown Version'
            raw_port = (port_el.get('portid') or '').strip()
            try:
                port_num = int(raw_port)
                if not 1 <= port_num <= 65535:
                    raise ValueError(raw_port)
            except (TypeError, ValueError):
                flash(tr('flash.xml_invalid_port', port=raw_port[:30] or '—'), 'danger')
                return redirect(url_for('tasks_page'))
            entry = {
                'port': port_num,
                'protocol': port_el.get('protocol', 'tcp'),
                'state': state_el.get('state', 'unknown'),
                'name': name,
                'version_info': full_version,
            }
            reason = port_reason(state_el.get('reason'))
            if reason:
                entry['reason'] = reason
            ports.append(entry)
        record = {'ip': ip, 'os': os_info, 'os_accuracy': os_accuracy, 'mac': mac, 'mac_vendor': mac_vendor}
        if host.find('ports') is not None:      # a ping sweep (-sn) file has no <ports>: no list means "ports not scanned", not "0 open" (like a Discovery host)
            record['ports'] = ports
        scan_results.append(record)

    if not scan_results:
        flash(tr('flash.xml_no_valid_ip') if skipped_hosts else tr('flash.xml_no_online'), 'danger')
        return redirect(url_for('tasks_page'))

    if len(targets_found) == 1:
        target_display = targets_found[0]
    elif ui_lang_now() != 'en':
        target_display = f"{targets_found[0]} (และอีก {len(targets_found)-1} เป้าหมาย)"
    else:
        target_display = f"{targets_found[0]} (+{len(targets_found)-1} more)"

    new_job = ScanJob(
        scan_name=scan_name, target=target_display,
        scan_type='xml_upload', status='Completed',
        triggered_by='manual', result_data=json.dumps(scan_results),
        owner_id=current_user.id
    )
    db.session.add(new_job)
    # An imported file's hosts were not scanned by this app, so they are NOT added to the shared saved-target list
    # (a 500-device file used to add 500 rows, and the list has no bulk delete).
    db.session.commit()
    session['scan_just_finished'] = new_job.id
    flash(tr('flash.xml_imported', n=len(scan_results)), 'success')
    if skipped_hosts:
        flash(tr('flash.xml_skipped', n=skipped_hosts), 'warning')
    return redirect(url_for('scan_detail', scan_id=new_job.id))


# ─────────────────────────────────────────
#  EXPORT CSV / PDF
# ─────────────────────────────────────────

@app.route('/scan/<int:scan_id>/export/csv')
@login_required
def export_csv(scan_id):
    import csv, io
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Scan Job ID', 'Target', 'Scan Type', 'Timestamp'])
    writer.writerow([job.id, job.target, SCAN_TYPE_LABELS.get(job.scan_type, job.scan_type),
                     job.timestamp.strftime('%Y-%m-%d %H:%M:%S') if job.timestamp else ''])
    writer.writerow([])
    # The CVE columns (added 2026-11-17, a reviewer noted the CSV held less than the PDF): one row per port and CVE, so a spreadsheet can filter
    # or sort by severity; a port with no CVE keeps ONE row. "CVE Check" says what the lookup could say about the port, so an empty CVE cell is
    # never read as "clean" when it only means "not looked up" (the same unknown-stays-unknown rule as the report). The old 8 columns are unchanged.
    writer.writerow(['IP Address', 'MAC Address', 'OS / Status', 'Port', 'Protocol', 'State', 'Service', 'Version',
                     'CVE ID', 'Severity', 'CVSS Score', 'CWE', 'CISA KEV', 'CVE Check', 'CVE Description'])
    is_vuln = job.scan_type == 'vuln_scan'

    def csv_text(value):
        """Text from a scan or from NVD for a spreadsheet cell: one line, and never starting with = + - @ (a spreadsheet would run it as a formula)."""
        s = re.sub(r'\s+', ' ', str(value if value is not None else '')).strip()
        return ("'" + s) if s[:1] in ('=', '+', '-', '@') else s

    def cve_check(port):
        if not is_vuln:
            return 'Not checked (not a vulnerability scan)'
        if str(port.get('state') or '').lower() != 'open':
            return ''
        status = port.get('cve_status')
        if status == 'ok':
            return 'Checked'
        if status == 'failed':
            return 'NVD lookup failed'
        if status == 'no_product':
            return 'Not searched (no product name)'
        return 'Not recorded (older scan)'

    def cve_rank(c):
        score = cvss_number(c.get('cvss_score')) if isinstance(c, dict) else None
        return (-(score if score is not None else -1), str(c.get('cve_id') or ''))

    for device in scan_data:
        ip = device.get('ip', '')
        mac = device.get('mac', '')
        mac_vendor = device.get('mac_vendor', '')
        mac_display = mac if mac not in ('Unknown', '') else ''
        if mac_display and mac_vendor:
            mac_display = f'{mac_display} ({mac_vendor})'
        os_info = device.get('os') or device.get('status', '')
        ports = device.get('ports', [])
        if ports:
            for port in ports:
                ver = port.get('version_info', '')
                if ver == 'Unknown Version': ver = ''
                base = [ip, mac_display, os_info,
                        port.get('port', ''), (port.get('protocol', 'tcp') or '').lower(),
                        port.get('state', 'unknown') or 'unknown', port.get('name', '') or '—', ver]
                cves = [c for c in (port.get('cves') or []) if isinstance(c, dict)]
                if cves:
                    for c in sorted(cves, key=cve_rank):
                        cwe = cwe_info(c)
                        score = cvss_number(c.get('cvss_score'))
                        writer.writerow(base + [csv_text(c.get('cve_id')), effective_severity(c) or 'UNKNOWN',
                                                ('%.1f' % score) if score is not None else '',
                                                csv_text(cwe['label']) if cwe else '',
                                                'Yes' if c.get('kev') is True else ('No' if c.get('kev') is False else ''),
                                                cve_check(port), csv_text(c.get('description'))])
                else:
                    writer.writerow(base + ['', '', '', '', '', cve_check(port), ''])
        else:
            writer.writerow([ip, mac_display, os_info, '—', '—', '—', 'No ports', '—', '', '', '', '', '', '' if is_vuln else 'Not checked (not a vulnerability scan)', ''])

    output.seek(0)
    from flask import Response
    import re as _re
    custom_name = request.args.get('filename', '').strip()
    if custom_name:
        custom_name = _re.sub(r'[\\/:*?"<>|]', '_', custom_name)
        filename = custom_name + '.csv'
    else:
        filename = f"scan_{job.id}_{job.target.replace('/', '_').replace(' ', '_')}_{job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'}.csv"
    # The UTF-8 byte order mark ("﻿") makes Excel read the file as UTF-8. Without it Excel on Windows assumes Windows-1252 and shows the
    # em dash placeholder as "â€”" and any Thai text (OS, hostname, a scan name) as rubbish.
    return Response('﻿' + output.getvalue(), mimetype='text/csv', headers=_attachment_headers(filename))


def _attachment_headers(filename, inline=False):
    """Content-Disposition for a download (or inline PDF view when inline=True). A name with Thai (or any non-Latin-1) letters
    cannot go into a plain header value, so: an ASCII fallback name plus the RFC 5987 UTF-8 form that browsers prefer."""
    from urllib.parse import quote
    stem, dot, ext = filename.rpartition('.')
    if not dot:
        stem, ext = filename, ''
    ascii_stem = re.sub(r'[\\/:*?"<>|\r\n;]', '_', stem.encode('ascii', 'ignore').decode('ascii')).strip() or 'report'
    ascii_name = ascii_stem + ('.' + ext if ext else '')
    disp = 'inline' if inline else 'attachment'
    return {'Content-Disposition': f"{disp}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}"}


def _export_filename(job, ext):
    """?filename= (what the export dialog sends) or scan_<id>_<target>_<time>, with the extension."""
    custom = (request.args.get('filename') or '').strip()
    if custom:
        return re.sub(r'[\\/:*?"<>|\r\n]', '_', custom)[:150] + '.' + ext
    safe_target = (job.target or '').replace('/', '_').replace(' ', '_').replace('\\', '_')
    return f"scan_{job.id}_{safe_target}_{job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'}.{ext}"


def _report_context(job):
    """What scan_report.html needs for one job: the report (report_builder) and the stored hosts for its diagram."""
    try:
        hosts = json.loads(job.result_data) if job.result_data else []
    except ValueError:
        hosts = []
    if not isinstance(hosts, list):
        hosts = []
    for h in hosts:
        if isinstance(h, dict):
            h['vm'] = virtual_machine_platform(h.get('mac'), h.get('mac_vendor'))      # derived at view time, like the scan page
    custom_args = job.custom_args
    if not custom_args and job.scan_type == 'custom':          # jobs from before the column existed keep the arguments in every result row
        custom_args = next((h.get('custom_args') for h in hosts if isinstance(h, dict) and h.get('custom_args')), None)
    scan = {'id': job.id, 'number': job.id,      # screen Job # and URL /scan/<id> always use the same job.id
            'scan_type': job.scan_type, 'scan_name': job.scan_name, 'target': job.target, 'status': job.status,
            'started': job.timestamp, 'finished': job.finished_at, 'timing': job.timing, 'version_intensity': job.version_intensity,
            'custom_args': custom_args, 'multicast': job.multicast, 'skip_ping': job.skip_ping, 'all_ports': job.all_ports, 'no_dns': job.no_dns, 'host_probes': job.host_probes, 'gentle': job.gentle, 'udp': job.udp, 'udp_top': job.udp_top,
            'nmap_version': scan_run_info(job).get('nmap'),
            'run': describe_run(job, lang='th'), 'run_facts': scan_run_info(job), 'owner': job.owner.username if job.owner else '', 'triggered_by': job.triggered_by or 'manual'}
    try:
        scan['changes'] = scan_changes(job)      # what changed since the earlier scan of the same kind; None = nothing to compare with
    except Exception:                            # the report must never fail because of the comparison: say it could not be made
        app.logger.exception('Report: could not compare scan %s with the one before it', job.id)
        scan['changes'], scan['changes_failed'] = None, True
    r = report_builder.build_report(scan, hosts, now_th(), SCAN_TYPE_LABELS_TH)      # the PDF report is always Thai
    return r, [h for h in hosts if isinstance(h, dict) and h.get('ip')]


def _report_orientation():
    """The page orientation the report is drawn and printed in: 'portrait' (A4, the default since 2026-11-17) or 'landscape' (A4, the older
    layout), from ?orientation=. Anything else is portrait."""
    return 'landscape' if request.args.get('orientation') == 'landscape' else 'portrait'


@app.route('/scan/<int:scan_id>/report')
@login_required
def scan_report(scan_id):
    """The report as a page (the senior's 3-page design): readable on screen, printable with Ctrl+P."""
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    r, scan_data = _report_context(job)
    return render_template('scan_report.html', r=r, scan_data=scan_data, system_gateway=get_system_default_gateway(), print_mode=False,
                           orientation=_report_orientation(), asset=lambda p: url_for('static', filename=p))


@app.route('/scan/<int:scan_id>/export/pdf')
@login_required
def export_pdf(scan_id):
    """The PDF report: the report page printed by a headless Edge / Chrome (report_pdf.py). If no browser can do it (not installed, the
    package missing, a timeout) the old xhtml2pdf export below is used instead, so the button never just fails."""
    from flask import Response
    inline = request.args.get('inline') == '1'
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    r, scan_data = _report_context(job)
    static_root = pathlib.Path(app.static_folder)
    html = render_template('scan_report.html', r=r, scan_data=scan_data, system_gateway=get_system_default_gateway(), print_mode=True,
                           orientation=_report_orientation(), asset=lambda p: (static_root / p).as_uri())
    try:
        pdf = html_to_pdf(html)
    except ReportPdfError as e:
        app.logger.warning('PDF report: the browser engine failed for scan %s (%s); using the old exporter', scan_id, e)
        resp = _export_pdf_legacy(scan_id, inline=inline)
        resp.headers['X-Report-Engine'] = 'legacy'
        return resp
    resp = Response(pdf, mimetype='application/pdf', headers=_attachment_headers(_export_filename(job, 'pdf'), inline=inline))
    resp.headers['X-Report-Engine'] = 'browser'
    return resp


def _export_pdf_legacy(scan_id, inline=False):
    """The old xhtml2pdf export (English, one table, no Thai): kept only as the fallback of export_pdf."""
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    scan_data = json.loads(job.result_data) if job.result_data else []

    timestamp_str = job.timestamp.strftime('%Y-%m-%d %H:%M:%S') if job.timestamp else 'N/A'
    total_hosts = len(scan_data)
    total_ports = sum(1 for d in scan_data if isinstance(d, dict) for p in (d.get('ports') or []) if str(p.get('state', '')).lower() == 'open')   # open ports only, like the report page
    scan_name_display = job.scan_name if job.scan_name else f'Scan #{job.id}'

    is_vuln_scan = job.scan_type in ('vuln', 'vulnerability', 'cve') if hasattr(job, 'scan_type') else False

    rows_html = ''
    for idx, device in enumerate(scan_data):
        ip      = device.get('ip', '') or '—'
        mac     = device.get('mac', '') or ''
        if mac in ('Unknown', ''): mac = '—'
        mac_vendor = device.get('mac_vendor', '') or ''
        mac_display = mac
        if mac != '—' and mac_vendor:
            mac_display = f'{mac} ({mac_vendor[:18]})'
        os_info = (device.get('os') or device.get('status') or '—')
        if len(os_info) > 35: os_info = os_info[:33] + '..'
        ports   = device.get('ports', [])
        bg      = '#f4f7ff' if idx % 2 == 1 else '#ffffff'
        border_top = 'border-top:2px solid #d0d8f0;'

        # xhtml2pdf does NOT support rowspan — repeat IP/MAC/OS on every row
        if not ports:
            rows_html += (
                f'<tr style="background-color:{bg};{border_top}">'
                f'<td class="c-ip">{ip}</td>'
                f'<td class="c-mac">{mac_display}</td>'
                f'<td class="c-os">{os_info}</td>'
                f'<td class="c-port" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-proto" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-state" style="color:#aaa;font-style:italic;">—</td>'
                f'<td class="c-svc" style="color:#aaa;font-style:italic;">No ports</td>'
                f'<td class="c-ver" style="color:#aaa;font-style:italic;">—</td>'
                f'</tr>'
            )
        else:
            for pi, p in enumerate(ports):
                proto  = (p.get('protocol') or 'tcp').lower()
                state  = p.get('state') or 'unknown'
                svc    = p.get('name') or '—'
                ver    = p.get('version_info') or ''
                if ver == 'Unknown Version': ver = ''
                if len(ver) > 45: ver = ver[:43] + '..'

                # Build CVE badges — one per line using nested table (xhtml2pdf-safe)
                cves = p.get('cves') or []
                cve_rows = ''
                for cve in cves[:5]:  # max 5 CVEs to keep row height manageable
                    cve_id   = cve.get('cve_id', '')
                    score    = cve.get('cvss_score', '')
                    sev      = effective_severity(cve)
                    sev_color = {'CRITICAL':'#dc2626','HIGH':'#ea580c','MEDIUM':'#ca8a04','LOW':'#16a34a'}.get(sev,'#64748b')
                    sev_bg    = {'CRITICAL':'#fee2e2','HIGH':'#ffedd5','MEDIUM':'#fef9c3','LOW':'#dcfce7'}.get(sev,'#f1f5f9')
                    score_txt = f'({score})' if score else ''
                    cwe_name  = cve.get('cwe_name', '')
                    cwe_html  = (
                        f' <span style="font-size:6px;color:#475569;background:#f1f5f9;'
                        f'border:1px solid #cbd5e1;border-radius:2px;padding:0px 3px;">'
                        f'{cwe_name}</span>'
                    ) if cwe_name else ''
                    if cve_id:
                        cve_rows += (
                            f'<tr><td style="padding:1px 0;">'
                            f'<span style="background:{sev_bg};color:{sev_color};'
                            f'border:1px solid {sev_color};border-radius:2px;'
                            f'padding:0px 3px;font-size:6.5px;font-weight:bold;">'
                            f'{cve_id}{score_txt}</span>{cwe_html}'
                            f'</td></tr>'
                        )
                extra_cves = len(cves) - 5
                if extra_cves > 0:
                    cve_rows += f'<tr><td style="font-size:6.5px;color:#64748b;padding:1px 0;">+{extra_cves} more</td></tr>'

                if ver and cve_rows:
                    ver_cell = (
                        f'<table style="border-collapse:collapse;width:100%;">'
                        f'<tr><td style="font-size:7.5px;color:#555;padding:0 0 2px 0;">{ver}</td></tr>'
                        f'{cve_rows}'
                        f'</table>'
                    )
                elif cve_rows:
                    ver_cell = (
                        f'<table style="border-collapse:collapse;width:100%;">'
                        f'{cve_rows}'
                        f'</table>'
                    )
                else:
                    ver_cell = ver if ver else '<i style="color:#aaa;">—</i>'

                # Repeat IP/MAC/OS on every row (no rowspan)
                ip_cell  = ip  if pi == 0 else f'<span style="color:#bbb;">{ip}</span>'
                mac_cell = mac_display if pi == 0 else ''
                os_cell  = os_info     if pi == 0 else ''
                bt       = border_top  if pi == 0 else ''

                rows_html += (
                    f'<tr style="background-color:{bg};{bt}">'
                    f'<td class="c-ip">{ip_cell}</td>'
                    f'<td class="c-mac">{mac_cell}</td>'
                    f'<td class="c-os">{os_cell}</td>'
                    f'<td class="c-port">{p.get("port","")}{"/" + port_proto(p) if port_proto(p) != "tcp" else ""}</td>'
                    f'<td class="c-proto">{proto}</td>'
                    f'<td class="c-state">{state}</td>'
                    f'<td class="c-svc">{svc}</td>'
                    f'<td class="c-ver">{ver_cell}</td>'
                    f'</tr>'
                )

    html_content = f'''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Scan Report</title>
<style>
@page {{ size: A4 landscape; margin: 12mm 10mm; }}
body {{ font-family: Arial, sans-serif; font-size: 9px; color: #1a1a2e; margin: 0; padding: 0; }}
.hdr {{ background-color: #0f3460; padding: 10px 14px 8px; margin-bottom: 10px; }}
.hdr-title {{ font-size: 15px; font-weight: bold; color: #ffffff; margin: 0 0 3px 0; }}
.hdr-sub {{ font-size: 8px; color: #a8c7fa; }}
.info-table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
.info-table td {{ width: 25%; padding: 6px 10px; border: 1px solid #dde4f5; background-color: #f8f9ff; vertical-align: top; }}
.lbl {{ font-size: 7px; color: #999; text-transform: uppercase; }}
.val {{ font-size: 11px; font-weight: bold; color: #0f3460; margin-top: 2px; }}
.sec {{ font-size: 10px; font-weight: bold; color: #0f3460; padding-left: 7px; border-left: 4px solid #0f3460; margin: 8px 0 5px; text-transform: uppercase; }}
table.rt {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
table.rt thead tr {{ background-color: #0f3460; }}
table.rt thead th {{ padding: 5px; font-size: 8px; font-weight: bold; color: #ffffff; text-align: left; overflow: hidden; }}
table.rt tbody td {{ padding: 3px 4px; vertical-align: top; border-bottom: 1px solid #e8ecf5; overflow: hidden; word-wrap: break-word; font-family: Arial, sans-serif; font-size: 7.5px; color: #555; }}
.c-ip    {{ width: 11%; font-size: 7.5px; color: #333; }}
.c-mac   {{ width: 13%; font-size: 7.5px; color: #555; }}
.c-os    {{ width: 15%; font-size: 7.5px; color: #555; }}
.c-port  {{ width: 7%;  font-size: 7.5px; color: #333; }}
.c-proto {{ width: 6%;  font-size: 7.5px; color: #555; }}
.c-state {{ width: 6%;  font-size: 7.5px; color: #888; }}
.c-svc   {{ width: 10%; font-size: 7.5px; color: #333; }}
.c-ver   {{ width: 32%; font-size: 7.5px; color: #555; }}
.ftr {{ margin-top: 10px; padding-top: 5px; border-top: 1px solid #dde4f5; font-size: 7.5px; color: #aaa; }}
</style></head><body>
<div class="hdr"><p class="hdr-title">Network Scan Report</p><p class="hdr-sub">{scan_name_display} | Generated {datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")} (Bangkok)</p></div>
<table class="info-table"><tr>
  <td><div class="lbl">Target</div><div class="val" style="font-size:9px;">{job.target}</div></td>
  <td><div class="lbl">Scan Profile</div><div class="val" style="font-size:9px;">{SCAN_TYPE_LABELS.get(job.scan_type, job.scan_type)}</div></td>
  <td><div class="lbl">Timestamp</div><div class="val" style="font-size:9px;">{timestamp_str}</div></td>
  <td><div class="lbl">Hosts / Open Ports</div><div class="val">{total_hosts} hosts &nbsp; {total_ports} ports</div></td>
</tr></table>
<div class="sec">Scan Results</div>
<table class="rt"><thead><tr>
  <th class="c-ip">IP Address</th>
  <th class="c-mac">MAC Address</th>
  <th class="c-os">OS / Status</th>
  <th class="c-port">Port</th>
  <th class="c-proto">Protocol</th>
  <th class="c-state">State</th>
  <th class="c-svc">Service</th>
  <th class="c-ver">Version</th>
</tr></thead><tbody>{rows_html}</tbody></table>
<div class="ftr">ScanPhotodash &nbsp;|&nbsp; Scan Job #{job.id} &nbsp;|&nbsp; Total: {total_hosts} hosts, {total_ports} open ports</div>
</body></html>'''

    from flask import Response
    import io
    try:
        from xhtml2pdf import pisa
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html_content.encode('utf-8'), dest=pdf_buffer, encoding='utf-8')
        if pisa_status.err:
            return Response("PDF generation failed", status=500)
        pdf_buffer.seek(0)
        import re as _re2
        custom_name = request.args.get('filename', '').strip()
        if custom_name:
            custom_name = _re2.sub(r'[\\/:*?"<>|]', '_', custom_name)
            filename = custom_name + '.pdf'
        else:
            safe_target = job.target.replace('/', '_').replace(' ', '_').replace('\\', '_')
            ts_str = job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'
            filename = f"scan_{job.id}_{safe_target}_{ts_str}.pdf"
        return Response(pdf_buffer.read(), mimetype='application/pdf', headers=_attachment_headers(filename, inline=inline))
    except ImportError:
        filename = f"scan_{job.id}_report.html"
        return Response(html_content, mimetype='text/html', headers=_attachment_headers(filename, inline=inline))


# ─────────────────────────────────────────
#  AI CHATBOT API  (Google AI Studio / Gemini)
# ─────────────────────────────────────────

# How many scans, devices and CVEs the AI is shown IN DETAIL (the totals and the Critical / High / Medium / Low counts always cover everything; a device or CVE the
# person asks about by IP or CVE id is added in full whatever the limit). The local model's window is 8192 tokens in all (local_llm.NUM_CTX), so it gets fewer;
# Gemini reads far more, and these are only a size we keep for speed and cost (raised 2026-11-24 from 25 / 100 / 80 at the owner's request).
AI_CONTEXT_LIMITS = {'online': {'scans': 50, 'devices': 200, 'cves': 150},
                     'local': {'scans': 15, 'devices': 50, 'cves': 40}}


def _build_app_context(user_text=''):
    """
    รวบรวมข้อมูลจริงของแอพ (ภาพรวม, อุปกรณ์พร้อม OS/ชนิด, ช่องโหว่ปัจจุบัน, ประวัติสแกน, ตารางเวลา)
    สำหรับ current_user โดยใช้ _build_device_inventory() ชุดเดียวกับ Dashboard / อุปกรณ์ / ช่องโหว่
    เพื่อให้ตัวเลขตรงกัน 100% ไม่นับ CVE ที่แก้ไปแล้ว และดึงรายละเอียดครบถ้วนเมื่อถามเจาะจง IP/CVE/ระดับความเสี่ยง
    """
    try:
        all_jobs = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
        inventory = _build_device_inventory(all_jobs)
        gateway_ip = (get_system_default_gateway(max_age=30) or {}).get('ip')

        compact = (ai_engine() == 'local')
        lim = AI_CONTEXT_LIMITS['local' if compact else 'online']
        max_scans, max_devs, max_cves = lim['scans'], lim['devices'], lim['cves']

        # --- คำนวณภาพรวมครบทุกการสแกน (ตรงกับ Dashboard, Devices และ Vulnerabilities 100%) ---
        total_ports_global = set()
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        kev_count = 0
        tiers = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'clean': 0, 'unscanned': 0}
        device_rows = []
        all_findings = []

        for dev in inventory:
            total_ports_global.update(dev['open_port_keys'])
            services_text = ' '.join(dev['services'])
            rule_ip = gateway_ip if gateway_ip in dev['ips'] else next((i for i in dev['ips'] if is_local_ip(i)), dev['ips'][0])
            dtype = guess_device_type(
                rule_ip, dev['mac_vendor'], dev['os'], dev['open_tcp_ports'], gateway_ip,
                services=services_text, hostname=dev['hostname'], mac=dev['mac'],
            )
            os_name = dev['os'] or 'Unknown'
            os_fam = _os_family(dev['os'])
            w = dev['worst_severity']
            tier = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'UNKNOWN': 'low'}.get(w) or (
                'clean' if dev['vuln_scanned'] else 'unscanned'
            )
            tiers[tier] += 1

            dev_findings = []
            dev_kev = 0
            for finding in dev['active_cves'].values():
                sev = finding['severity'] or 'UNKNOWN'
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                if finding['kev']:
                    kev_count += 1
                    dev_kev += 1
                item = {
                    'ip': finding['ip'],
                    'primary_ip': dev['ip'],
                    'cve_id': finding['cve_id'],
                    'severity': sev,
                    'severity_label': sev + (' (NVD: HIGH, CVSS v2)' if finding['severity_adjusted'] else ''),
                    'cvss': finding['cvss_num'],
                    'kev': finding['kev'],
                    'port': f"{finding['port']}/{finding['protocol']}" if finding['port'] else '',
                    'service': finding['service'] or '',
                    'product': finding['product'] or '',
                    'cwe': finding['cwe_name'] or '',
                    'description': (finding['description'] or '').strip(),
                }
                dev_findings.append(item)
                all_findings.append(item)

            dev_findings.sort(key=lambda f: (
                0 if f['kev'] else 1,
                -_VULN_SEV_RANK.get(f['severity'], 0),
                -(f['cvss'] if f['cvss'] is not None else -1.0),
                f['cve_id'],
            ))

            base_type = dtype['label'].replace(' (likely)', '')
            type_th = _VOICE_TYPE_TH.get(base_type, '')
            type_disp = f"{dtype['label']} ({type_th})" if type_th else dtype['label']
            device_rows.append({
                'ip': dev['ip'],
                'ips': dev['ips'],
                'other_ips': dev['other_ips'],
                'hostname': dev['hostname'] or '',
                'os': os_name,
                'os_family': os_fam,
                'os_accuracy': dev['os_accuracy'],
                'type': dtype['label'],
                'type_disp': type_disp,
                'type_reason': dtype.get('reason') or '',
                'mac': dev['mac'] or '',
                'mac_vendor': dev['mac_vendor'] or '',
                'open_ports': dev.get('open_ports_detail') or sorted(dev['open_labels']),
                'scan_count': dev['scan_count'],
                'last_seen': dev['last_seen'].strftime('%Y-%m-%d %H:%M') if dev['last_seen'] else '-',
                'vuln_scanned': dev['vuln_scanned'],
                'worst_severity': w or ('CLEAN' if dev['vuln_scanned'] else 'UNSCANNED'),
                'cve_count': len(dev_findings),
                'kev_count': dev_kev,
                'findings': dev_findings,
            })

        all_findings.sort(key=lambda f: (
            0 if f['kev'] else 1,
            -_VULN_SEV_RANK.get(f['severity'], 0),
            -(f['cvss'] if f['cvss'] is not None else -1.0),
            _ip_sort_key(f['ip']),
            f['cve_id'],
        ))

        # --- ประวัติสแกนล่าสุด ---
        scan_summaries = []
        for job in all_jobs[:max_scans]:
            hosts_ok = _parse_job_hosts(job) if job.status == 'Completed' else []
            scan_summaries.append({
                'id': job.id,
                'name': job.scan_name or f'งาน #{job.id}',
                'target': job.target,
                'type': job.scan_type,
                'status': job.status,
                'host_count': len(hosts_ok) if job.status == 'Completed' else 0,
                'timestamp': job.timestamp.strftime('%Y-%m-%d %H:%M') if job.timestamp else '-',
            })

        # --- Schedules ---
        schedules = visible_schedules_query().all()
        sched_summaries = [{
            'id': s.id, 'name': s.name, 'target': s.target, 'type': s.scan_type,
            'repeat': s.repeat, 'active': s.is_active,
            'last_run': s.last_run.strftime('%Y-%m-%d %H:%M') if s.last_run else 'ยังไม่เคย',
            'next_run': s.next_run.strftime('%Y-%m-%d %H:%M') if s.next_run else '-',
        } for s in schedules]

        saved_targets = SavedTarget.query.order_by(SavedTarget.created_at.desc()).limit(30).all()
        targets_list = [{'target': t.target, 'label': t.label or ''} for t in saved_targets]

        other_sev = sum(n for k, n in sev_counts.items() if k not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
        stats = {
            'total_scans': len(all_jobs),
            'completed': sum(1 for j in all_jobs if j.status == 'Completed'),
            'failed': sum(1 for j in all_jobs if j.status == 'Failed'),
            'running': sum(1 for j in all_jobs if j.status in ACTIVE_STATUSES),
            'cancelled': sum(1 for j in all_jobs if j.status == 'Cancelled'),
            'total_devices': len(device_rows),
            'total_open_ports': len(total_ports_global),
            'total_cves': len(all_findings),
            'total_schedules': len(schedules),
            'active_schedules': sum(1 for s in schedules if s.is_active),
        }

        ctx_lines = [
            f"=== สรุปภาพรวมทั้งหมดของระบบ CLYLAR (ผู้ใช้: {current_user.username}, role: {current_user.role}) ===",
            "ตัวเลขด้านล่างคำนวณจากฐานข้อมูลทั้งหมดและตรงกับหน้า Dashboard, อุปกรณ์ และช่องโหว่ 100%:",
            f"  - งานสแกนทั้งหมด: {stats['total_scans']} (เสร็จสิ้น {stats['completed']}, ล้มเหลว {stats['failed']}, กำลังทำ/รอคิว {stats['running']}, ยกเลิก {stats['cancelled']})",
            f"  - อุปกรณ์ที่พบทั้งหมด (จากทุกการสแกน): {stats['total_devices']} เครื่อง",
            f"  - พอร์ตที่เปิดอยู่ (ไม่ซ้ำ): {stats['total_open_ports']} พอร์ต",
            f"  - ช่องโหว่ CVE ที่ยังพบอยู่ปัจจุบัน (ไม่รวมที่แก้ไปแล้ว): {stats['total_cves']} รายการ",
            f"    * แยกตามระดับความรุนแรง: Critical={sev_counts['CRITICAL']}, High={sev_counts['HIGH']}, Medium={sev_counts['MEDIUM']}, Low={sev_counts['LOW']}"
            + (f", อื่นๆ={other_sev}" if other_sev else '')
            + f", CISA KEV (ถูกโจมตีจริง)={kev_count}",
            f"  - อุปกรณ์แยกตามความเสี่ยงสูงสุด: Critical={tiers['critical']}, High={tiers['high']}, Medium={tiers['medium']}, Low={tiers['low']}, สแกนช่องโหว่แล้วไม่พบ={tiers['clean']}, ยังไม่เคยสแกนช่องโหว่={tiers['unscanned']}",
            f"  - Scheduled Scan: {stats['total_schedules']} รายการ (เปิดใช้งาน {stats['active_schedules']})",
            "",
        ]

        # --- Query-focused full details (never miss the specific host, CVE, or severity the user asked about) ---
        q_text = str(user_text or '')
        asked_ips = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', q_text)))
        asked_cves = list(dict.fromkeys(c.upper() for c in re.findall(r'cve-\d{4}-\d{4,7}', q_text, re.I)))
        focused_devs = [d for d in device_rows if any(ip in d['ips'] for ip in asked_ips)] if asked_ips else []
        if focused_devs:
            ctx_lines.append("=== รายละเอียดครบถ้วนของอุปกรณ์ที่ผู้ใช้ถามถึง ===")
            for d in focused_devs[:5]:
                alt = f" (IP อื่น: {', '.join(d['other_ips'])})" if d['other_ips'] else ''
                hn = f" | hostname={d['hostname']}" if d['hostname'] else ''
                acc = f" ({d['os_accuracy']}%)" if d['os_accuracy'] is not None else ''
                mac_s = f"{d['mac']} ({d['mac_vendor']})" if d['mac'] and d['mac_vendor'] else (d['mac'] or 'ไม่ทราบ')
                ports_s = ', '.join(d['open_ports']) if d['open_ports'] else 'ไม่มีพอร์ตเปิด'
                ctx_lines.append(
                    f"  อุปกรณ์ {d['ip']}{alt}{hn}\n"
                    f"    - ชนิดอุปกรณ์ (Device Type): {d['type_disp']}" + (f" [เหตุผล: {d['type_reason']}]" if d['type_reason'] else '') + "\n"
                    f"    - ระบบปฏิบัติการ (OS): {d['os']}{acc} (กลุ่ม: {d['os_family']})\n"
                    f"    - MAC: {mac_s} | สแกนแล้ว {d['scan_count']} ครั้ง | ล่าสุด {d['last_seen']}\n"
                    f"    - พอร์ตเปิดทั้งหมด ({len(d['open_ports'])}): {ports_s}\n"
                    f"    - ช่องโหว่ปัจจุบัน: {d['cve_count']} รายการ (ความเสี่ยงสูงสุด: {d['worst_severity']}" + (f", KEV={d['kev_count']}" if d['kev_count'] else '') + ")"
                )
                for f in d['findings']:
                    cvss_s = f"CVSS {f['cvss']:.1f}" if f['cvss'] is not None else 'CVSS -'
                    kev_s = ' [KEV]' if f['kev'] else ''
                    ctx_lines.append(f"      * {f['cve_id']} | {f['severity_label']} | {cvss_s}{kev_s} | {f['port']} {f['service']} {f['product']} | {f['description'][:140]}")
            ctx_lines.append("")

        if asked_cves:
            matched_cves = [f for f in all_findings if f['cve_id'].upper() in asked_cves]
            if matched_cves:
                ctx_lines.append("=== รายละเอียดช่องโหว่ CVE ที่ผู้ใช้ถามถึง ===")
                for f in matched_cves:
                    cvss_s = f"CVSS {f['cvss']:.1f}" if f['cvss'] is not None else 'CVSS -'
                    kev_s = ' [CISA KEV]' if f['kev'] else ''
                    ctx_lines.append(f"  {f['cve_id']} | host={f['ip']} | {f['severity_label']} | {cvss_s}{kev_s} | {f['port']} {f['service']} {f['product']} | {f['description'][:220]}")
                ctx_lines.append("")

        # --- รายการอุปกรณ์ทั้งหมด (พร้อม OS, ชนิดอุปกรณ์, MAC, พอร์ตเปิด, สรุป CVE) ---
        if device_rows:
            shown_devs = device_rows[:max_devs]
            note = f" (แสดง {len(shown_devs)} จากทั้งหมด {len(device_rows)} เครื่อง)" if len(device_rows) > len(shown_devs) else f" ({len(device_rows)} เครื่อง ครบทั้งหมด)"
            ctx_lines.append(f"รายการอุปกรณ์ทั้งหมด{note}:")
            for d in shown_devs:
                ports_s = ', '.join(d['open_ports'][:10]) + (f' (+{len(d["open_ports"]) - 10})' if len(d['open_ports']) > 10 else '') if d['open_ports'] else 'ไม่มีพอร์ตเปิด'
                mac_s = f" | MAC={d['mac']}" + (f" ({d['mac_vendor']})" if d['mac_vendor'] else '') if d['mac'] else ''
                hn_s = f" | host={d['hostname']}" if d['hostname'] else ''
                cve_s = f" | CVE={d['cve_count']} (max={d['worst_severity']}" + (f", KEV={d['kev_count']}" if d['kev_count'] else '') + ")" if d['cve_count'] else (
                    " | CVE=0 (สแกนแล้ว)" if d['vuln_scanned'] else " | CVE=ยังไม่เคยสแกนช่องโหว่"
                )
                ctx_lines.append(f"  {d['ip']} | type={d['type_disp']} | OS={d['os']} [{d['os_family']}]{hn_s}{mac_s} | ports={ports_s}{cve_s}")
            ctx_lines.append("")

        # --- รายการช่องโหว่ปัจจุบัน เรียงจากสำคัญที่สุดก่อน (KEV -> Critical -> High -> Medium -> Low) ---
        if all_findings:
            shown_cves = all_findings[:max_cves]
            shown_keys = {(f['ip'], f['cve_id']) for f in shown_cves}
            q_low = q_text.lower()
            want_sevs = set()
            if any(w in q_low for w in ('critical', 'วิกฤต', 'สูงมาก', 'คริติคอล')):
                want_sevs.add('CRITICAL')
            if any(w in q_low for w in ('high', 'ระดับสูง', 'ความเสี่ยงสูง')):
                want_sevs.add('HIGH')
            if any(w in q_low for w in ('medium', 'ปานกลาง', 'มีเดียม')):
                want_sevs.add('MEDIUM')
            if any(w in q_low for w in ('low', 'ระดับต่ำ', 'ความเสี่ยงต่ำ', 'โลว์')):
                want_sevs.add('LOW')
            extra_cves = [f for f in all_findings[max_cves:] if (f['severity'] in want_sevs or (f['kev'] and any(w in q_low for w in ('kev', 'cisa', 'โจมตีจริง'))))][:40]
            display_cves = shown_cves + [f for f in extra_cves if (f['ip'], f['cve_id']) not in shown_keys]
            cve_note = (
                f" (แสดง {len(display_cves)} รายการสำคัญสูงสุดจากทั้งหมด {len(all_findings)} รายการ — ยึดตัวเลขสรุปด้านบนเป็นหลัก)"
                if len(all_findings) > len(display_cves) else f" ({len(all_findings)} รายการ ครบทั้งหมด)"
            )
            ctx_lines.append(f"ช่องโหว่ CVE ที่ยังพบอยู่ปัจจุบัน{cve_note}:")
            for f in display_cves:
                cvss_s = f"CVSS {f['cvss']:.1f}" if f['cvss'] is not None else 'CVSS -'
                kev_s = ' [KEV]' if f['kev'] else ''
                desc = f['description'][:95] if compact else f['description'][:120]
                ctx_lines.append(f"  {f['ip']} | {f['cve_id']} | {f['severity_label']} | {cvss_s}{kev_s} | {f['port']} {f['service']} | {desc}")
            ctx_lines.append("")

        if scan_summaries:
            scan_note = f" ({len(scan_summaries)} ล่าสุดจากทั้งหมด {stats['total_scans']})" if stats['total_scans'] > len(scan_summaries) else f" ({len(scan_summaries)} งานทั้งหมด)"
            ctx_lines.append(f"ประวัติงานสแกน{scan_note}:")
            for s in scan_summaries:
                ctx_lines.append(
                    f"  [งาน #{s['id']}] {s['name']} | target={s['target']} | type={s['type']} "
                    f"| status={s['status']} | devices={s['host_count']} | {s['timestamp']}"
                )
            ctx_lines.append("")

        if sched_summaries:
            ctx_lines.append(f"Scheduled Scans ({len(sched_summaries)} รายการ):")
            for s in sched_summaries:
                st = 'เปิด' if s['active'] else 'ปิด'
                ctx_lines.append(
                    f"  [{s['id']}] ({st}) {s['name']} | target={s['target']} "
                    f"| {s['repeat']} | last={s['last_run']} | next={s['next_run']}"
                )
            ctx_lines.append("")

        if targets_list:
            ctx_lines.append(f"Saved Targets ({len(targets_list)} รายการ):")
            for t in targets_list[:15]:
                label = f" ({t['label']})" if t['label'] else ''
                ctx_lines.append(f"  {t['target']}{label}")
            ctx_lines.append("")

        return '\n'.join(ctx_lines)

    except Exception as ex:
        return f"[ไม่สามารถโหลดข้อมูลระบบได้: {ex}]"


# ─────────────────────────────────────────
#  AI switch and usage counter (Settings page)
# ─────────────────────────────────────────

def get_setting(key, default=None):
    row = AppSetting.query.get(key)
    return row.value if row is not None else default


def set_setting(key, value):
    row = AppSetting.query.get(key)
    if row is None:
        row = AppSetting(key=key)
        db.session.add(row)
    row.value = value
    db.session.commit()


def chat_button_key(user_id):
    return 'chat_button_hidden.%d' % user_id


def chat_hint_key(user_id):
    return 'chat_hint_seen.%d' % user_id


# "Scan at once" (2026-11-09, the owner asked for it): an admin may skip the confirmation card of a voice or typed scan command, but only for a target that
# cannot reach outside the company network by mistake. Off until the admin turns it on; kept per admin on the server, like the chat button.
VOICE_AUTORUN_MAX_ADDRESSES = 256          # a /24 or smaller
_VOICE_AUTORUN_NETS = tuple(ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))      # private-use space only (not loopback, not documentation ranges)


def voice_autorun_key(user_id):
    return 'voice_autorun.%d' % user_id


def voice_autorun_on(user_id):
    return get_setting(voice_autorun_key(user_id), '0') == '1'


def voice_autorun_allowed(target):
    """True when a scan of `target` may start without the confirmation card: one IPv4 address or network, inside 10/8, 172.16/12 or 192.168/16, of at most 256
    addresses. Anything else (a public address, a bigger range, IPv6, text we cannot read) still asks, whatever the switch says."""
    try:
        net = ipaddress.ip_network(str(target or '').strip(), strict=False)
    except ValueError:
        return False
    if net.version != 4 or net.num_addresses > VOICE_AUTORUN_MAX_ADDRESSES:
        return False
    return any(net.subnet_of(n) for n in _VOICE_AUTORUN_NETS)


def ai_enabled():
    """Whether the chatbot may call Gemini at all (the switch on the Settings page). On unless it was switched off."""
    return get_setting('ai_enabled', '1') != '0'


class AIDisabled(Exception):
    pass


# The two engines of the assistant: 'gemini' (Google's API, the default) or 'local' (a model run by Ollama on this computer, see local_llm.py).
# One choice for the whole system, made by a superadmin; speech to text is not part of it (that stays with Whisper).
def ai_engine():
    try:
        return 'local' if get_setting('ai_engine', 'gemini') == 'local' else 'gemini'
    except Exception:
        return 'gemini'


def local_llm_settings():
    """{url, model, gpu_layers}: what the Settings page saved, else the defaults. gpu_layers None = automatic (the saved text is empty)."""
    url = local_llm.clean_url(get_setting('local_llm_url', '')) or local_llm.DEFAULT_URL
    model = local_llm.clean_model(get_setting('local_llm_model', '')) or local_llm.DEFAULT_MODEL
    saved = get_setting('local_llm_gpu_layers', None)
    ok, layers = local_llm.clean_gpu_layers(saved) if saved is not None else (True, local_llm.DEFAULT_GPU_LAYERS)
    return {'url': url, 'model': model, 'gpu_layers': layers if ok else local_llm.DEFAULT_GPU_LAYERS}


def _local_model_label(model):
    """What the usage table stores in GeminiCall.model for a local call (no new column: 'ollama:' marks it)."""
    return ('ollama:' + model)[:60]


AI_OFF_TEXT = {
    'chat': 'ปิดการใช้ AI อยู่ จึงยังตอบข้อความที่พิมพ์ในแชทไม่ได้ กรุณากดปุ่มไมโครโฟนเพื่อสั่งสแกน เปิดหน้า หรือถามจำนวนอุปกรณ์/ช่องโหว่ '
            'หรือให้ผู้ดูแลระบบระดับสูงสุด (Superadmin) เปิดใช้ AI ที่หน้าตั้งค่า',
    'th': 'ปิดการใช้ AI อยู่ ระบบตอบได้เฉพาะคำสั่งสแกน การเปิดหน้า และคำถามจำนวนอุปกรณ์/พอร์ต/ช่องโหว่ ผู้ดูแลระบบระดับสูงสุด (Superadmin) เปิดใช้ AI ได้ที่หน้าตั้งค่า',
    'en': 'The AI is switched off, so I can only handle scan commands, opening pages and questions about counts. '
          'A superadmin can switch it on in Settings.',
}


GEMINI_KEY_FILE = 'gemini_key'                       # instance/gemini_key: the SHARED key typed on the Settings page (git-ignored)
GEMINI_USER_KEY_DIR = 'gemini_user_keys'             # instance/gemini_user_keys/<user id>: one admin's OWN key (git-ignored)
GEMINI_MODEL_DEFAULT = 'gemini-2.5-flash'           # was gemini-1.5-flash, which Google has retired (2026-11-24); only used when neither Settings nor GEMINI_MODEL names a model
_GEMINI_KEY_RE = re.compile(r'[A-Za-z0-9_.~\-]{20,200}')      # newer AI Studio keys start "AQ." (a dot), older ones "AIza": a dot must be allowed
_GEMINI_MODEL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._\-]{0,59}')


def _current_uid():
    """The signed-in user's id, or None (no request, not signed in)."""
    try:
        return current_user.id if current_user and current_user.is_authenticated else None
    except Exception:
        return None


def personal_keys_allowed():
    """Whether admins may use their own Gemini key (a superadmin can switch it off). On unless switched off."""
    try:
        return get_setting('personal_keys_allowed', '1') != '0'
    except Exception:
        return True


def _user_key_path(uid):
    return pathlib.Path(app.instance_path) / GEMINI_USER_KEY_DIR / ('%d' % int(uid))


def _read_key_file(p):
    try:
        return p.read_text(encoding='utf-8').strip() if p.is_file() else ''
    except OSError:
        return ''


def _forget_user_key(uid):
    """A deleted account must not leave its key behind (SQLite can hand the same id to the next account)."""
    try:
        _user_key_path(uid).unlink()
    except OSError:
        pass


def gemini_key(user_id=None):
    """(key, source). With a user id the order is: that person's own key ('own', only while personal keys are allowed),
    then the shared key typed on the Settings page ('settings'), then GOOGLE_API_KEY in .env ('env'); source None = no key.
    Read on every call, so a change applies at once."""
    if user_id is not None and personal_keys_allowed():
        k = _read_key_file(_user_key_path(user_id))
        if k:
            return k, 'own'
    k = _read_key_file(pathlib.Path(app.instance_path) / GEMINI_KEY_FILE)
    if k:
        return k, 'settings'
    k = os.environ.get('GOOGLE_API_KEY', '').strip()
    return (k, 'env') if k else ('', None)


def gemini_model():
    """The model chosen on the Settings page, else GEMINI_MODEL from .env, else the default."""
    try:
        m = (get_setting('gemini_model', '') or '').strip()
        if m and _GEMINI_MODEL_RE.fullmatch(m):
            return m
    except Exception:
        pass                                              # no app context / no database: fall back to .env
    return os.environ.get('GEMINI_MODEL', GEMINI_MODEL_DEFAULT).strip() or GEMINI_MODEL_DEFAULT


def _redact_key(text):
    """Never let the key reach a log row, a chat reply or a page, whatever an error message happens to contain."""
    text = str(text)
    uid = _current_uid()
    secrets_ = [gemini_key()[0], os.environ.get('GOOGLE_API_KEY', '').strip()]
    if uid is not None:
        secrets_.append(_read_key_file(_user_key_path(uid)))
    for secret in secrets_:
        if secret and secret in text:
            text = text.replace(secret, '***')
    return text


def _record_gemini_call(source, ok, status, usage, model=None):
    """One GeminiCall row per call (Gemini or the local model; `model` says which). Never lets a counting problem break the chat."""
    try:
        u = usage or {}
        db.session.add(GeminiCall(
            user_id=current_user.id if current_user and current_user.is_authenticated else None,
            source=source, ok=ok, status=_redact_key(status)[:200],
            model=model or gemini_model(),
            prompt_tokens=u.get('promptTokenCount'), output_tokens=u.get('candidatesTokenCount'),
            thinking_tokens=u.get('thoughtsTokenCount'), total_tokens=u.get('totalTokenCount')))
        db.session.commit()
    except Exception:
        db.session.rollback()


def _ai_usage_summary():
    """What the Settings page shows: the switch, and the calls / tokens today and this month (Bangkok time)."""
    now = now_th()
    day0 = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def since(t, uid=None):
        q = GeminiCall.query.filter(GeminiCall.timestamp >= t)
        if uid is not None:
            q = q.filter(GeminiCall.user_id == uid)
        rows = q.all()
        is_local = lambda r: str(r.model or '').startswith('ollama:')
        gem = [r for r in rows if not is_local(r)]            # the token rows are Google's quota: a local call spends none of it
        return {'calls': len(rows), 'failed': sum(1 for r in rows if not r.ok), 'voice': sum(1 for r in rows if r.source == 'voice'),
                'local': sum(1 for r in rows if is_local(r)),
                'prompt_tokens': sum(r.prompt_tokens or 0 for r in gem), 'output_tokens': sum(r.output_tokens or 0 for r in gem),
                'total_tokens': sum(r.total_tokens or 0 for r in gem)}

    last = GeminiCall.query.order_by(GeminiCall.id.desc()).first()
    key, source = gemini_key()
    out = {'enabled': ai_enabled(), 'today': since(day0), 'month': since(day0.replace(day=1)),
           'total_calls': GeminiCall.query.count(), 'last': last.timestamp.strftime('%Y-%m-%d %H:%M') if last else None,
           'model': gemini_model(), 'key_set': bool(key), 'key_source': source}
    lm = local_llm_settings()
    out['engine'] = ai_engine()
    out['local_model'] = lm['model']
    # the address and layer count are the superadmin's to see and change; every admin sees which engine answers and with which model
    out['local'] = {'url': lm['url'], 'gpu_layers': lm['gpu_layers'], 'default_layers': local_llm.DEFAULT_GPU_LAYERS,
                    'default_model': local_llm.DEFAULT_MODEL} if current_user.is_authenticated and current_user.is_superadmin else None
    # The key itself is never sent to a browser. Its last 4 characters go only to a superadmin, to tell two keys apart.
    out['key_tail'] = key[-4:] if key and current_user.is_authenticated and current_user.is_superadmin else None
    # What applies to THIS person: their own key (their last 4 characters are theirs to see), else the shared one.
    uid = _current_uid()
    own = _read_key_file(_user_key_path(uid)) if uid is not None else ''
    out['my_key_set'] = bool(own)
    out['my_key_tail'] = own[-4:] if own else None
    out['personal_allowed'] = personal_keys_allowed()
    out['key_in_use'] = gemini_key(uid)[1]
    out['mine'] = {'today': since(day0, uid), 'month': since(day0.replace(day=1), uid)} if uid is not None else None
    return out


@app.route('/api/ai/status')
@login_required
@admin_required
def api_ai_status():
    out = _ai_usage_summary()
    out['can_change'] = current_user.is_superadmin
    return jsonify(out)


@app.route('/api/ai/enabled', methods=['POST'])
@login_required
@superadmin_required
def api_ai_enabled():
    """The switch: {enabled: true | false}. Off means no code path may call Gemini (the chat, the voice fallback)."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get('enabled'), bool):
        return jsonify({'error': 'enabled must be true or false'}), 400
    set_setting('ai_enabled', '1' if data['enabled'] else '0')
    out = _ai_usage_summary()
    out['can_change'] = True
    return jsonify(out)


GEMINI_PROBE_TEXT = {
    'ok':        'คีย์ใช้งานได้ และพบโมเดล {model}',
    'invalid':   'คีย์ไม่ถูกต้อง กรุณาตรวจสอบว่าคัดลอกครบถ้วน',
    'forbidden': 'คีย์ไม่มีสิทธิ์เข้าถึง Gemini API',
    'leaked':    'คีย์นี้ถูก Google ระงับเนื่องจากเคยเปิดเผยต่อสาธารณะ กรุณาสร้างคีย์ใหม่ที่ https://aistudio.google.com/app/apikey',
    'model':     'คีย์ใช้ได้ แต่ไม่พบโมเดล {model}',
    'quota':     'คีย์ใช้ได้ แต่ถูกใช้งานเกินโควตาชั่วคราว กรุณารอสักครู่',
    'network':   'ติดต่อ Google ไม่ได้ กรุณาตรวจสอบการเชื่อมต่ออินเทอร์เน็ต',
    'no_key':    'ยังไม่มีคีย์ให้ทดสอบ',
    'other':     'ทดสอบไม่สำเร็จ (รหัส {code})',
}


def _gemini_probe(key, model):
    """Checks a key and a model name WITHOUT spending tokens: GET models/<model> only reads the model's description.
    The key goes in a header, never in the URL, so no error text can carry it. Returns (status, http code or None)."""
    import requests as req_lib
    try:
        r = req_lib.get('https://generativelanguage.googleapis.com/v1beta/models/' + model,
                        headers={'x-goog-api-key': key}, timeout=15)
    except Exception:
        return 'network', None
    code = r.status_code
    if code == 200:
        return 'ok', code
    try:
        body = (r.text or '').lower()
    except Exception:
        body = ''
    if 'leaked' in body:
        return 'leaked', code
    if code in (400, 401):
        return 'invalid', code
    if code == 403:
        return 'forbidden', code
    if code == 404:
        return 'model', code
    if code == 429:
        return 'quota', code
    return 'other', code


def _json_dict():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _key_from_request():
    """(key, None) for a well-formed key in the request, else (None, error response)."""
    key = _json_dict().get('key')
    if not isinstance(key, str) or not _GEMINI_KEY_RE.fullmatch(key.strip()):
        return None, (jsonify({'error': 'bad_key', 'message': 'รูปแบบคีย์ไม่ถูกต้อง (ใช้ได้เฉพาะตัวอักษร A-Z ตัวเลข _ . ~ และ - ความยาว 20 ถึง 200 ตัว ไม่มีช่องว่าง)'}), 400)
    return key.strip(), None


def _save_key_file(p, key):
    """Write a key atomically (temp file, then replace). Returns an error response, or None when it worked."""
    tmp = p.with_name(p.name + '.tmp')
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(key, encoding='utf-8')
        os.replace(tmp, p)
    except OSError:
        return jsonify({'error': 'write_failed', 'message': 'บันทึกคีย์ไม่สำเร็จ ตรวจสอบสิทธิ์เขียนไฟล์ในโฟลเดอร์ instance'}), 500
    return None


def _delete_key_file(p):
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return jsonify({'error': 'delete_failed', 'message': 'ลบคีย์ไม่สำเร็จ'}), 500
    return None


def _test_key_response(default_key):
    """Test a key: {key?, model?}. With no key in the request, default_key (the one that applies) is tested; with no model,
    the current one. Costs no tokens and is not counted in the usage table."""
    data = _json_dict()
    key = data.get('key')
    key = key.strip() if isinstance(key, str) else ''
    if key and not _GEMINI_KEY_RE.fullmatch(key):
        # not even shaped like a key (a space or another character in it): say so, instead of the message for a key that Google rejected
        return jsonify({'ok': False, 'status': 'invalid', 'message': 'รูปแบบคีย์ไม่ถูกต้อง มีช่องว่างหรืออักขระที่ไม่ใช่ส่วนของคีย์ปนอยู่ กรุณาวางเฉพาะตัวคีย์'})
    if not key:
        key = default_key
    model = data.get('model')
    model = model.strip() if isinstance(model, str) else ''
    if not model:
        model = gemini_model()
    if not _GEMINI_MODEL_RE.fullmatch(model):
        return jsonify({'ok': False, 'status': 'model', 'message': GEMINI_PROBE_TEXT['model'].format(model=model[:60])})
    if not key:
        return jsonify({'ok': False, 'status': 'no_key', 'message': GEMINI_PROBE_TEXT['no_key']})
    status, code = _gemini_probe(key, model)
    return jsonify({'ok': status == 'ok', 'status': status,
                    'message': GEMINI_PROBE_TEXT[status].format(model=model, code=code)})


# The SHARED key: one for the whole app, superadmin only. It is what an admin without a key of their own uses.
@app.route('/api/ai/key', methods=['POST'])
@login_required
@superadmin_required
def api_ai_key():
    """Save the shared Gemini key: {key: "..."}. JSON only. Written to instance/gemini_key (git-ignored, not in the database), never sent back."""
    key, err = _key_from_request()
    if err:
        return err
    err = _save_key_file(pathlib.Path(app.instance_path) / GEMINI_KEY_FILE, key)
    return err or jsonify(_ai_usage_summary())


@app.route('/api/ai/key/clear', methods=['POST'])
@login_required
@superadmin_required
def api_ai_key_clear():
    """Delete the shared key saved on the Settings page. A GOOGLE_API_KEY in .env then applies again, if there is one."""
    err = _delete_key_file(pathlib.Path(app.instance_path) / GEMINI_KEY_FILE)
    return err or jsonify(_ai_usage_summary())


@app.route('/api/ai/key/test', methods=['POST'])
@login_required
@superadmin_required
def api_ai_key_test():
    return _test_key_response(gemini_key()[0])


# An admin's OWN key: used only for that admin's questions to the assistant, on their own Google account.
@app.route('/api/ai/my-key', methods=['POST'])
@login_required
@admin_required
def api_ai_my_key():
    """Save my own Gemini key: {key: "..."}. Refused while a superadmin has switched personal keys off."""
    if not personal_keys_allowed():
        return jsonify({'error': 'personal_off', 'message': 'ผู้ดูแลระบบระดับสูงสุดปิดการใช้คีย์ส่วนตัวอยู่'}), 403
    key, err = _key_from_request()
    if err:
        return err
    err = _save_key_file(_user_key_path(current_user.id), key)
    return err or jsonify(_ai_usage_summary())


@app.route('/api/ai/my-key/clear', methods=['POST'])
@login_required
@admin_required
def api_ai_my_key_clear():
    """Delete my own key. Allowed even while personal keys are switched off, so nobody is stuck with a key they cannot remove."""
    err = _delete_key_file(_user_key_path(current_user.id))
    return err or jsonify(_ai_usage_summary())


@app.route('/api/ai/my-key/test', methods=['POST'])
@login_required
@admin_required
def api_ai_my_key_test():
    """Test a typed key, else the key that applies to me (my own, else the shared one)."""
    return _test_key_response(gemini_key(current_user.id)[0])


@app.route('/api/ai/personal', methods=['POST'])
@login_required
@superadmin_required
def api_ai_personal():
    """The switch for own keys: {allowed: true | false}. Off means every call uses the shared key (own keys stay saved, unused)."""
    data = _json_dict()
    if not isinstance(data.get('allowed'), bool):
        return jsonify({'error': 'allowed must be true or false'}), 400
    set_setting('personal_keys_allowed', '1' if data['allowed'] else '0')
    return jsonify(_ai_usage_summary())


# The model list of the Settings dropdown (2026-11-24): Google's own list for the shared key, so a model that Google has retired, or that this key cannot use,
# is never offered, and no model name has to be kept up to date in the code. Names that are not chat models are left out. When Google cannot be asked
# (no key, no internet, a refused key) the built-in list below is shown and the page says why.
GEMINI_MODEL_FALLBACK = ('gemini-2.5-flash', 'gemini-2.5-flash-lite')
# What the dropdown SUGGESTS: only the Flash and Flash-Lite families (a name written as gemini-[version-]flash[-lite][-latest | -NNN | -preview...]). The assistant
# answers short questions over figures that are already in the prompt, so a Pro model only costs more and answers slower, and Google's list also holds image,
# omni and code-named models (2026-11-24: gemini-nano-banana-*, gemini-omni-*, gemini-4-argon / carbon / hydrogen / neon) that this app has no use for. Any other
# name can still be typed ("Enter a model name"); a model that Google lists but the dropdown does not suggest is not called "missing" (see `known`).
_GEMINI_SUGGEST_RE = re.compile(r'gemini-(?:\d+(?:\.\d+)?-)?flash(?:-lite)?(?:-latest|-\d{3})?')      # no "-preview": a preview model can change or go away without notice (the owner, 2026-11-24)
_GEMINI_NOT_CHAT = ('embedding', 'tts', 'image', 'live', 'audio', 'imagen', 'veo', 'aqa', 'robotics', 'computer-use', 'learnlm', 'vision')
GEMINI_MODELS_URL = 'https://generativelanguage.googleapis.com/v1beta/models'


def _gemini_http_status(r):
    """The status word (as in GEMINI_PROBE_TEXT) for a Google response that is not a 200."""
    code = r.status_code
    try:
        body = (r.text or '').lower()
    except Exception:
        body = ''
    if 'leaked' in body:
        return 'leaked'
    return {400: 'invalid', 401: 'invalid', 403: 'forbidden', 404: 'model', 429: 'quota'}.get(code, 'other')


def _fetch_gemini_models(key):
    """(status, items): every model Google lists for this key ('ok'), or the reason it could not be listed. The key goes in a header, never the URL."""
    import requests as req_lib
    items, token = [], None
    for _ in range(8):                                        # 100 a page: more than a few pages would mean something is wrong
        params = {'pageSize': 100}
        if token:
            params['pageToken'] = token
        try:
            r = req_lib.get(GEMINI_MODELS_URL, headers={'x-goog-api-key': key}, params=params, timeout=15)
        except Exception:
            return 'network', None
        if r.status_code != 200:
            return _gemini_http_status(r), None
        try:
            body = r.json()
        except Exception:
            return 'other', None
        items.extend(body.get('models') or [])
        token = body.get('nextPageToken')
        if not token:
            break
    return 'ok', items


def _gemini_version(model_id):
    m = _GEMINI_VERSION_RE.match(model_id)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else (0, 0)


def _gemini_model_choices(items, suggested_only=True):
    """The models among Google's list, newest version first: [{id, name, preview}]. With suggested_only (the dropdown) only the Flash / Flash-Lite
    families; without it every Gemini model that can write text (used to know which names Google still has)."""
    out, seen = [], set()
    for it in items or []:
        if not isinstance(it, dict):
            continue
        name = str(it.get('name') or '')
        mid = name[7:] if name.startswith('models/') else name
        if mid in seen or not mid.startswith('gemini-') or not _GEMINI_MODEL_RE.fullmatch(mid):
            continue
        if 'generateContent' not in (it.get('supportedGenerationMethods') or []) or any(w in mid for w in _GEMINI_NOT_CHAT):
            continue
        if suggested_only and not _GEMINI_SUGGEST_RE.fullmatch(mid):
            continue
        seen.add(mid)
        out.append({'id': mid, 'name': str(it.get('displayName') or mid)[:60], 'preview': 'preview' in mid or '-exp' in mid})
    out.sort(key=lambda x: (tuple(-v for v in _gemini_version(x['id'])), x['id']))
    return out


@app.route('/api/ai/models')
@login_required
@superadmin_required
def api_ai_models():
    """The models the shared key can use, for the Settings dropdown. Costs no tokens. `source` is 'google' for Google's list and 'builtin' for the fallback."""
    key = gemini_key()[0]
    status, items = _fetch_gemini_models(key) if key else ('no_key', None)
    models = _gemini_model_choices(items) if status == 'ok' else []
    known = [m['id'] for m in _gemini_model_choices(items, suggested_only=False)] if status == 'ok' else []
    if status == 'ok' and not models:
        models = _gemini_model_choices(items, suggested_only=False)       # a key with no Flash model at all: better every model than none
    if status == 'ok' and not models:
        status = 'empty'
    if not models:
        models = [{'id': m, 'name': m, 'preview': False} for m in GEMINI_MODEL_FALLBACK]
    return jsonify({'ok': status == 'ok', 'status': status, 'source': 'google' if status == 'ok' else 'builtin', 'models': models, 'known': known, 'current': gemini_model()})


@app.route('/api/ai/model', methods=['POST'])
@login_required
@superadmin_required
def api_ai_model():
    """Choose the Gemini model: {model: "gemini-2.5-flash"}. An empty value goes back to GEMINI_MODEL in .env."""
    data = request.get_json(silent=True) or {}
    model = data.get('model')
    if not isinstance(model, str):
        return jsonify({'error': 'bad_model', 'message': 'ชื่อโมเดลไม่ถูกต้อง'}), 400
    model = model.strip()
    if model and not _GEMINI_MODEL_RE.fullmatch(model):
        return jsonify({'error': 'bad_model', 'message': 'ชื่อโมเดลไม่ถูกต้อง (ใช้ได้เฉพาะตัวอักษร ตัวเลข จุด ขีดกลาง และขีดล่าง)'}), 400
    set_setting('gemini_model', model)
    return jsonify(_ai_usage_summary())


# ───────────── The local engine (Ollama): choose it, point it at a model, test it. Superadmin only, JSON only. ─────────────
def _local_error_text(code, lang=None):
    """The sentence for a local_llm error code, in the interface language (or `lang`). A code with no sentence of its own gets the general one."""
    known = ('unreachable', 'timeout', 'model_missing', 'not_ollama', 'bad_answer', 'empty')
    key = 'ai.local.err.' + (code if code in known else 'other')
    return i18n.t(key, lang or ui_lang_now(), code=code)


def _local_probe_response(url, model):
    r = local_llm.probe(url, model)
    st = r['status']
    out = {'ok': st == 'ok', 'status': st, 'models': r['models'], 'gpu_percent': r['gpu_percent']}
    known = ('ok', 'model_missing', 'unreachable', 'timeout', 'not_ollama')
    out['message'] = tr('ai.local.probe.' + (st if st in known else 'other'), model=model[:60], code=st)
    if st == 'ok' and r['gpu_percent'] is not None:
        out['message'] += tr('ai.local.probe.gpu', gpu=r['gpu_percent'])
    return out


# ─────────────────────────────────────────
#  The NVD API key (the CVE lookup of the Vulnerability Scan)
#  2026-11-23: it used to be hardcoded in scanner.py. Now: the key a superadmin types here (instance/nvd_key, git-ignored, not in the
#  database), else NVD_API_KEY in .env, else none (NVD still answers, but allows only 5 requests per 30 s, so scanner.py paces the lookups).
# ─────────────────────────────────────────
from scanner import NVD_KEY_RE, set_nvd_key_provider

NVD_KEY_FILE = 'nvd_key'
NVD_PROBE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1'


def nvd_key():
    """(key, source): the key typed on the Settings page ('settings'), else NVD_API_KEY in .env ('env'); ('', None) when there is none.
    A value that is not shaped like an NVD key (a UUID) is ignored. Read on every call, so a change applies at once."""
    k = _read_key_file(pathlib.Path(app.instance_path) / NVD_KEY_FILE)
    if NVD_KEY_RE.fullmatch(k):
        return k, 'settings'
    k = (os.environ.get('NVD_API_KEY') or '').strip()
    return (k, 'env') if NVD_KEY_RE.fullmatch(k) else ('', None)


set_nvd_key_provider(lambda: _read_key_file(pathlib.Path(app.instance_path) / NVD_KEY_FILE))      # the scanner asks for the key at every lookup


def _nvd_summary():
    """What the Settings page may know about the key: whether there is one and where it comes from. Only a superadmin gets its last 4 characters; the key itself never leaves."""
    key, source = nvd_key()
    superadmin = bool(current_user.is_authenticated and current_user.is_superadmin)
    return {'key_set': bool(key), 'key_source': source, 'key_tail': key[-4:] if key and superadmin else None, 'can_change': superadmin}


def _nvd_probe(key):
    """Ask NVD for one CVE with this key. ('ok' | 'invalid' | 'busy' | 'network' | 'other', HTTP code). NVD answers 404 for a key it does not know
    (also a new key that has not been confirmed through the link in NVD's email yet), and 403 / 429 / 503 when it refuses or is busy."""
    import requests as req_lib
    try:
        r = req_lib.get(NVD_PROBE_URL, headers={'apiKey': key, 'User-Agent': 'NetworkScanner/1.0'}, timeout=10)
    except req_lib.RequestException:
        return 'network', None
    code = r.status_code
    if code == 200:
        return 'ok', code
    if code in (401, 404):
        return 'invalid', code
    if code in (403, 429, 503):
        return 'busy', code
    return 'other', code


@app.route('/api/nvd/status')
@login_required
@admin_required
def api_nvd_status():
    return jsonify(_nvd_summary())


@app.route('/api/nvd/key', methods=['POST'])
@login_required
@superadmin_required
def api_nvd_key():
    """Save the NVD key: {key: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}. JSON only. Written to instance/nvd_key (git-ignored), never sent back."""
    key = _json_dict().get('key')
    if not isinstance(key, str) or not NVD_KEY_RE.fullmatch(key.strip()):
        return jsonify({'error': 'bad_key', 'message': tr('nvd.msg.bad_format')}), 400
    err = _save_key_file(pathlib.Path(app.instance_path) / NVD_KEY_FILE, key.strip())
    return err or jsonify(_nvd_summary())


@app.route('/api/nvd/key/clear', methods=['POST'])
@login_required
@superadmin_required
def api_nvd_key_clear():
    """Delete the key saved on the Settings page. NVD_API_KEY in .env then applies again, if there is one."""
    err = _delete_key_file(pathlib.Path(app.instance_path) / NVD_KEY_FILE)
    return err or jsonify(_nvd_summary())


@app.route('/api/nvd/key/test', methods=['POST'])
@login_required
@superadmin_required
def api_nvd_key_test():
    """Test a typed key {key}, else the key that applies now. One small request to NVD; nothing is saved."""
    key = _json_dict().get('key')
    key = key.strip() if isinstance(key, str) else ''
    if key and not NVD_KEY_RE.fullmatch(key):
        return jsonify({'ok': False, 'status': 'bad_format', 'message': tr('nvd.msg.bad_format')})
    if not key:
        key = nvd_key()[0]
    if not key:
        return jsonify({'ok': False, 'status': 'no_key', 'message': tr('nvd.probe.no_key')})
    status, code = _nvd_probe(key)
    return jsonify({'ok': status == 'ok', 'status': status, 'message': tr('nvd.probe.' + status, code=code)})


@app.route('/api/ai/engine', methods=['POST'])
@login_required
@superadmin_required
def api_ai_engine():
    """Choose who answers: {engine: "gemini" | "local"}. Nothing else changes (keys, model and the local settings stay saved)."""
    engine = _json_dict().get('engine')
    if engine not in ('gemini', 'local'):
        return jsonify({'error': 'bad_engine', 'message': tr('ai.local.bad_engine')}), 400
    set_setting('ai_engine', engine)
    return jsonify(_ai_usage_summary())


@app.route('/api/ai/local', methods=['POST'])
@login_required
@superadmin_required
def api_ai_local():
    """Save the local engine's settings: {url?, model?, gpu_layers?}. A field that is not in the request is left as it was. An empty gpu_layers
    means automatic. The address must be this computer."""
    data = _json_dict()
    todo = {}
    if 'url' in data:
        url = local_llm.clean_url(data['url'])
        if not url:
            return jsonify({'error': 'bad_url', 'message': tr('ai.local.bad_url')}), 400
        todo['local_llm_url'] = url
    if 'model' in data:
        model = local_llm.clean_model(data['model'])
        if not model:
            return jsonify({'error': 'bad_model', 'message': tr('ai.local.bad_model')}), 400
        todo['local_llm_model'] = model
    if 'gpu_layers' in data:
        ok, layers = local_llm.clean_gpu_layers(data['gpu_layers'])
        if not ok:
            return jsonify({'error': 'bad_layers', 'message': tr('ai.local.bad_layers', max=local_llm.MAX_GPU_LAYERS)}), 400
        todo['local_llm_gpu_layers'] = '' if layers is None else str(layers)
    for k, v in todo.items():
        set_setting(k, v)
    return jsonify(_ai_usage_summary())


@app.route('/api/ai/local/test', methods=['POST'])
@login_required
@superadmin_required
def api_ai_local_test():
    """Ask the local server what it has: {url?, model?} (what is typed, else what is saved). Costs no tokens, loads nothing and is not counted."""
    data = _json_dict()
    saved = local_llm_settings()
    url = local_llm.clean_url(data['url']) if data.get('url') else saved['url']
    model = local_llm.clean_model(data['model']) if data.get('model') else saved['model']
    if not url:
        return jsonify({'ok': False, 'status': 'bad_url', 'models': [], 'gpu_percent': None, 'message': tr('ai.local.bad_url')})
    if not model:
        return jsonify({'ok': False, 'status': 'bad_model', 'models': [], 'gpu_percent': None, 'message': tr('ai.local.bad_model')})
    return jsonify(_local_probe_response(url, model))


@app.route('/api/ui/chat-button', methods=['POST'])
@login_required
@admin_required
def api_chat_button():
    """Show or hide the floating chat button for THIS admin only: {visible: true | false}. Kept per user, so it holds in every browser."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get('visible'), bool):
        return jsonify({'error': 'visible must be true or false'}), 400
    set_setting(chat_button_key(current_user.id), '0' if data['visible'] else '1')
    return jsonify({'visible': data['visible']})


@app.route('/api/ui/chat-hint', methods=['POST'])
@login_required
@admin_required
def api_chat_hint():
    """Remember that THIS admin has seen the one-time hint beside the speed dial ("you can hide this button in Settings"): {seen: true}. Kept per user on the
    server, so the hint does not come back in another browser. Only `true` is accepted: nothing here can bring the hint back."""
    data = request.get_json(silent=True) or {}
    if data.get('seen') is not True:
        return jsonify({'error': 'seen must be true'}), 400
    set_setting(chat_hint_key(current_user.id), '1')
    return jsonify({'seen': True})


@app.route('/api/ui/voice-autorun', methods=['POST'])
@login_required
@admin_required
def api_voice_autorun():
    """Turn "scan at once" on or off for THIS admin only: {on: true | false}. JSON only (there is no CSRF token, so a form post is a 400)."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get('on'), bool):
        return jsonify({'error': 'on must be true or false'}), 400
    set_setting(voice_autorun_key(current_user.id), '1' if data['on'] else '0')
    return jsonify({'on': data['on']})


def _call_local(system_prompt, messages, max_tokens, source):
    """The same job as the Gemini branch of _call_gemini, done by the local model. Raises local_llm.LocalLLMError (the callers say why in Thai)."""
    lm = local_llm_settings()
    label = _local_model_label(lm['model'])
    try:
        text, usage, note = local_llm.chat(lm['url'], lm['model'], system_prompt, messages, max_tokens, lm['gpu_layers'],
                                           cancel=getattr(_answer_ctx, 'event', None))
    except local_llm.LocalLLMError as e:
        if e.code != 'cancelled':                         # Stop is the person's choice, not a failure of the model
            _record_gemini_call(source, False, 'local: %s' % e, None, model=label)
        raise
    cut = bool((usage or {}).get('truncated'))
    g.ai_cut = cut
    notes = [n for n in (note, 'cut: token limit' if cut else None) if n]
    _record_gemini_call(source, True, 'OK' if not notes else 'OK (%s)' % '; '.join(notes), usage, model=label)
    return text


def _call_gemini(system_prompt, messages, max_tokens=800, source='typed'):
    """The one way to reach the assistant's model: refuses when the Settings switch is off, uses the engine the superadmin chose (Gemini, or the
    local model through _call_local), and keeps a GeminiCall row for the usage counter. The name is from before the local engine existed."""
    if not ai_enabled():
        raise AIDisabled()
    g.ai_cut = False                                      # set again below when this answer is cut at the token limit (see _cut_notice)
    if ai_engine() == 'local':
        return _call_local(system_prompt, messages, max_tokens, source)
    try:
        text, usage, cut = _gemini_request(system_prompt, messages, max_tokens)
    except ValueError as e:
        if 'NO_API_KEY' not in str(e):         # no key = nothing was sent, so nothing to count
            _record_gemini_call(source, False, e, None)
        raise
    except Exception as e:
        _record_gemini_call(source, False, e, None)
        raise
    g.ai_cut = cut
    _record_gemini_call(source, True, 'OK (cut: token limit)' if cut else 'OK', usage)
    return text


# How long an answer may be, in tokens of the answer itself (Thai takes about two characters per token, so 1,536 is about 3,000 characters). It was 900 and 600,
# and an answer that needs more than that (a list of devices with their CVEs) stopped in the middle of a sentence. The local model writes about 14 tokens a second
# on the owner's laptop, so even the whole allowance is about two minutes, inside its 240 s read limit; the Stop button is there for a slow one.
CHAT_MAX_TOKENS_TYPED = 2048
CHAT_MAX_TOKENS_VOICE = 1536


def _ai_was_cut():
    """True when the answer of the last _call_gemini() in this request stopped at the token limit."""
    try:
        return bool(g.ai_cut)
    except Exception:
        return False


def _cut_notice(lang=None):
    """The line added under an answer that was cut, so nobody reads half an answer as a whole one."""
    return i18n.t('chat.truncated', lang or ui_lang_now())


GEMINI_PRO_THINKING = 512            # gemini-2.5-pro cannot switch thinking off (its smallest budget is 128): it gets this much, on top of the answer


GEMINI_MINIMAL_THINKING = 256        # Gemini 3 and later: "minimal" does not guarantee that thinking is off (Google's own words), so the limit gets a little room
_GEMINI_VERSION_RE = re.compile(r'gemini-(\d+)(?:\.(\d+))?-')
_gemini_thinking_refused = set()      # models whose thinking field Google refused with HTTP 400: asked again without it, and never sent it again (until a restart)


def _gemini_major(model):
    """The major version in a model name ("gemini-3.5-flash" gives 3), 0 when the name carries none ("gemini-flash-latest")."""
    m = _GEMINI_VERSION_RE.match((model or '').lower())
    return int(m.group(1)) if m else 0


def _gemini_generation_config(model, max_tokens):
    """The generationConfig of a Gemini request. `maxOutputTokens` counts the model's THINKING tokens as well as the words of the answer, and the
    2.5 models think by default: a real call on this system spent 574 of its 600 tokens thinking and wrote 22 tokens of answer (2026-11-19, the table
    of calls), which is how an answer ends in the middle of a sentence. So the Flash models are told not to think (a chat answer over figures that are
    already in the prompt needs no reasoning, and it is faster and cheaper), Pro gets a fixed thinking allowance added to the limit, and an older
    model (1.5, 2.0) is sent no thinking field at all because it would refuse the request.
    Gemini 3 and later (and the "-latest" names, which point at them) take `thinkingLevel` instead of `thinkingBudget` (sending both is an HTTP 400): Pro
    cannot go below "low", the others take "minimal". This field was written from Google's pages, not from a real call: if Google answers 400 about
    thinking, `_gemini_request` asks again without it (see `_gemini_thinking_refused`)."""
    m = (model or '').lower()
    cfg = {'maxOutputTokens': int(max_tokens)}
    if m.startswith('gemini-2.5-pro'):
        cfg['thinkingConfig'] = {'thinkingBudget': GEMINI_PRO_THINKING}
        cfg['maxOutputTokens'] = int(max_tokens) + GEMINI_PRO_THINKING
    elif m.startswith('gemini-2.5-'):
        cfg['thinkingConfig'] = {'thinkingBudget': 0}
    elif (_gemini_major(m) >= 3 or m.endswith('-latest')) and m not in _gemini_thinking_refused:
        if '-pro' in m:
            cfg['thinkingConfig'] = {'thinkingLevel': 'low'}
            cfg['maxOutputTokens'] = int(max_tokens) + GEMINI_PRO_THINKING
        else:
            cfg['thinkingConfig'] = {'thinkingLevel': 'minimal'}
            cfg['maxOutputTokens'] = int(max_tokens) + GEMINI_MINIMAL_THINKING
    return cfg


def _gemini_request(system_prompt, messages, max_tokens=800):
    """Helper: เรียก Gemini API และคืน (reply string, usageMetadata, cut) หรือ raise Exception. `cut` is True when Gemini stopped because it
    reached the token limit (finishReason MAX_TOKENS): the text is then only the start of the answer."""
    import os, time
    import requests as req_lib
    from dotenv import load_dotenv

    load_dotenv(override=True)
    api_key, _src = gemini_key(_current_uid())
    if not api_key:
        raise ValueError('NO_API_KEY')

    model = gemini_model()
    gemini_contents = []
    for msg in messages:
        role = 'user' if msg['role'] == 'user' else 'model'
        gemini_contents.append({'role': role, 'parts': [{'text': msg['content']}]})

    payload = {
        'system_instruction': {'parts': [{'text': system_prompt}]},
        'contents': gemini_contents,
        'generationConfig': _gemini_generation_config(model, max_tokens)
    }
    # The key goes in a header, not in the URL: a connection error quotes the URL, and that text is stored and shown.
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    headers = {'x-goog-api-key': api_key}

    resp = None
    last_status = None
    for attempt in range(4):
        resp = req_lib.post(url, json=payload, headers=headers, timeout=30)
        last_status = resp.status_code
        if resp.status_code == 429:
            time.sleep(3 * (attempt + 1))
            continue
        break

    if resp is not None and resp.status_code == 400 and 'thinkingConfig' in payload['generationConfig']:
        # Google refused the thinking field of this model (a newer model that wants another form of it, or an older one that has none): ask once more
        # without it, and remember it, so a wrong guess about a model costs one extra request and not an unusable assistant.
        try:
            about_thinking = 'thinking' in str((resp.json().get('error') or {}).get('message', '')).lower()
        except Exception:
            about_thinking = False
        if about_thinking:
            _gemini_thinking_refused.add(model.lower())
            payload['generationConfig'] = {'maxOutputTokens': int(max_tokens)}
            resp = req_lib.post(url, json=payload, headers=headers, timeout=30)
            last_status = resp.status_code

    if last_status == 429:
        raise Exception('QUOTA_429')
    if resp is not None and not resp.ok:
        try:
            err_data = resp.json().get('error', {})
            msg = err_data.get('message', '')
            raise Exception(f"HTTP_{resp.status_code}: {msg}")
        except Exception as json_err:
            if 'HTTP_' in str(json_err):
                raise json_err
            resp.raise_for_status()

    body = resp.json()
    cand = (body.get('candidates') or [{}])[0]
    parts = (cand.get('content') or {}).get('parts') or []
    # every text part that is the answer (a part marked `thought` is the model's own notes, never shown)
    text = ''.join(p.get('text', '') for p in parts if isinstance(p, dict) and not p.get('thought'))
    cut = cand.get('finishReason') == 'MAX_TOKENS'
    if not text.strip() and not cut:
        raise Exception('EMPTY_ANSWER (finishReason %s)' % cand.get('finishReason'))      # blocked, or nothing came: say so, not "KeyError: parts"
    return text, body.get('usageMetadata'), cut


# ───────────── Answers that finish in the background (2026-11-19) ─────────────
# A chat answer used to be written INSIDE the request that asked for it, so leaving the page (which cancels the request) lost it, and a local answer can take
# minutes. Now the chat page sends `async: true`: the request only STARTS the answer (a ChatAnswer row, a ticket, a thread) and the page asks for the result
# with the ticket, from any page, as often as it likes. The thread calls the SAME view the synchronous request would have called, as the same signed-in person
# (a test request context and login_user), so the answering rules, the usage rows and the typed chat's scan command stay ONE code path.
ANSWER_KEEP = timedelta(days=1)                   # rows older than this are deleted when a new answer starts
ANSWER_STALE = timedelta(minutes=15)              # still 'pending' after this long: no thread is behind it any more (three local answers in a row is the longest honest wait)
ANSWER_MAX_PENDING = 3                            # per person: the local model answers one at a time, so a longer queue is only a longer wait
_answer_gate_local = threading.Semaphore(1)       # one graphics card: one local answer at a time (Ollama would queue them anyway; waiting here keeps the ticket honest)
_answer_gate_online = threading.Semaphore(4)
_answer_events = {}                               # ticket -> threading.Event, set when the person pressed Stop (see api_chat_answer_cancel)
_answer_events_lock = threading.Lock()
_answer_ctx = threading.local()                   # the event of the answer the current thread is working on


def _answer_cancelled():
    """True when Stop was pressed for the answer this thread is working on (always False for an ordinary request)."""
    ev = getattr(_answer_ctx, 'event', None)
    return ev is not None and ev.is_set()


def start_background_answer(view, body):
    """Starts `view` (a chat view such as api_chat) in the background with `body` as its JSON, as the signed-in person, and answers 202 with the ticket.
    Answers 429 when this person already has ANSWER_MAX_PENDING answers on the way."""
    uid = current_user.id
    try:
        ChatAnswer.query.filter(ChatAnswer.created_at < now_th() - ANSWER_KEEP).delete(synchronize_session=False)
        waiting = (ChatAnswer.query.filter_by(user_id=uid, status='pending')
                   .filter(ChatAnswer.created_at >= now_th() - ANSWER_STALE).count())
        if waiting >= ANSWER_MAX_PENDING:
            db.session.commit()
            return jsonify({'status': 'busy', 'message': tr('chat.busy')}), 429
        engine = ai_engine()
        row = ChatAnswer(id=secrets.token_hex(16), user_id=uid, status='pending', engine=engine)
        db.session.add(row)
        db.session.commit()
        ticket = row.id
    except Exception:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': tr('chat.answer_start_failed')}), 500
    ev = threading.Event()
    with _answer_events_lock:
        _answer_events[ticket] = ev
    threading.Thread(target=_run_background_answer, args=(ticket, uid, view, dict(body), engine, ev), daemon=True, name='chat-answer').start()
    return jsonify({'status': 'pending', 'ticket': ticket}), 202


def _finish_answer(ticket, status, result=None):
    """Writes the end of a ticket once: only a ticket that is still pending changes (a restart or the stale check may have closed it already)."""
    try:
        ChatAnswer.query.filter_by(id=ticket, status='pending').update(
            {'status': status, 'finished_at': now_th(), 'result': json.dumps(result, ensure_ascii=False) if result is not None else None},
            synchronize_session=False)
        db.session.commit()
    except Exception:
        db.session.rollback()


def _run_background_answer(ticket, uid, view, body, engine, ev):
    gate = _answer_gate_local if engine == 'local' else _answer_gate_online
    try:
        with gate:
            if ev.is_set():                               # Stop was pressed while it waited for its turn: nothing to do
                return
            _answer_ctx.event = ev
            try:
                with app.test_request_context('/api/chat/background', method='POST', json=body):
                    user = User.query.get(uid)
                    if user is None or not login_user(user) or not user.is_any_admin:
                        raise PermissionError('this account cannot ask any more')
                    resp = app.make_response(view())
                    result = resp.get_json(silent=True)
                    if resp.status_code >= 500 or not isinstance(result, dict):
                        raise RuntimeError('the answer view returned %s' % resp.status_code)
                    _finish_answer(ticket, 'done', result)       # does nothing when Stop closed the ticket first
            except Exception as e:
                with app.app_context():
                    if not ev.is_set():
                        print('background answer %s failed: %s' % (ticket[:8], _redact_key(e)))
                    _finish_answer(ticket, 'error')
            finally:
                _answer_ctx.event = None
    finally:
        with _answer_events_lock:
            _answer_events.pop(ticket, None)


@app.route('/api/chat/answer/<ticket>')
@login_required
@admin_required
def api_chat_answer(ticket):
    """Where a background answer is: {status: pending | done | error | interrupted, result?}. Only the person who asked can read it (anything else is a 404)."""
    row = ChatAnswer.query.filter_by(id=str(ticket)[:32], user_id=current_user.id).first()
    if row is None:
        return jsonify({'status': 'gone'}), 404
    if row.status == 'pending' and row.created_at < now_th() - ANSWER_STALE:
        ChatAnswer.query.filter_by(id=row.id, status='pending').update({'status': 'interrupted', 'finished_at': now_th()}, synchronize_session=False)
        db.session.commit()
        row = ChatAnswer.query.filter_by(id=row.id).first()
    out = {'status': row.status}
    if row.status == 'done':
        try:
            out['result'] = json.loads(row.result or 'null')
        except ValueError:
            out['status'] = 'error'
        if not isinstance(out.get('result'), dict):
            out = {'status': 'error'}
    return jsonify(out)


@app.route('/api/chat/answer/<ticket>/cancel', methods=['POST'])
@login_required
@admin_required
def api_chat_answer_cancel(ticket):
    """The Stop button. A pending answer is closed as 'cancelled' and its thread is told to stop: the call to the local model is cut (its connection closes, which makes
    Ollama stop writing, so the graphics card is free again), and an online answer is left to finish and thrown away. An answer that is already done stays done, and
    the person gets it. Answers {status} (the ticket's status after the call); only the person who asked can stop it."""
    row = ChatAnswer.query.filter_by(id=str(ticket)[:32], user_id=current_user.id).first()
    if row is None:
        return jsonify({'status': 'gone'}), 404
    ChatAnswer.query.filter_by(id=row.id, status='pending').update({'status': 'cancelled', 'finished_at': now_th(), 'result': None}, synchronize_session=False)
    db.session.commit()
    row = ChatAnswer.query.filter_by(id=row.id).first()
    if row.status == 'cancelled':
        with _answer_events_lock:
            ev = _answer_events.get(row.id)
        if ev is not None:
            ev.set()
    return jsonify({'status': row.status})


def recover_interrupted_answers():
    """The same idea as recover_interrupted_jobs(): a ticket still 'pending' when a process starts serving can only be one that a restart cut off."""
    n = ChatAnswer.query.filter_by(status='pending').update({'status': 'interrupted', 'finished_at': now_th()}, synchronize_session=False)
    db.session.commit()
    return n


# ─────────────────────────────────────────
#  API: สั่ง Scan ผ่าน Chatbot
# ─────────────────────────────────────────

VALID_SCAN_TYPES = ['fast_scan', 'discovery', 'intense', 'vuln_scan']


def _make_chat_scan_proposal(target, scan_type, scan_name=None, lang='th'):
    """Build a signed confirmation card payload for an AI-proposed scan, enforcing the exact same
    target validation and confirmation guardrail as voice commands (never auto-runs)."""
    st = str(scan_type or 'fast_scan').strip()
    if st not in VALID_SCAN_TYPES:
        st = 'fast_scan'
    chk = voice_commands.check_scan_target(target, lang)
    if not chk['ok']:
        return {
            'intent': 'scan', 'status': 'bad_target', 'reason': chk['reason'],
            'target': str(target or '').strip(), 'message': chk['message'], 'from_chat': True,
        }
    clean_name = str(scan_name or '').strip()[:100]
    token = _voice_signer.dumps({
        'u': current_user.id, 't': chk['target'], 'k': st,
        'n': secrets.token_hex(8), 'src': 'chat', 'sn': clean_name,
    })
    return {
        'intent': 'scan', 'status': 'ok', 'target': chk['target'],
        'scan_type': st, 'scan_label': scan_labels(lang)[st],
        'scan_name': clean_name, 'public': chk['public'],
        'expires_in': VOICE_CONFIRM_SECONDS, 'token': token,
        'autorun': False, 'from_chat': True,
    }


@app.route('/api/chat/scan', methods=['POST'])
@login_required
def api_chat_scan():
    """Deprecated direct-scan bypass: validates the target and requires explicit confirmation via /api/voice/scan."""
    if not current_user.is_any_admin:
        return jsonify({'error': 'permission_denied', 'message': tr('chat.admin_only')}), 403

    data = request.get_json(silent=True) or {}
    target = (data.get('target') or '').strip()
    scan_type = (data.get('scan_type') or 'fast_scan').strip()
    scan_name = (data.get('scan_name') or '').strip() or None
    lang = ui_lang_now()

    if not target:
        return jsonify({'error': 'no_target', 'message': tr('chat.no_target')}), 400
    chk = voice_commands.check_scan_target(target, lang)
    if not chk['ok']:
        return jsonify({'error': 'invalid_target', 'message': chk['message']}), 400
    proposal = _make_chat_scan_proposal(target, scan_type, scan_name=scan_name, lang=lang)
    return jsonify({
        'error': 'confirmation_required',
        'message': 'กรุณายืนยันคำสั่งสแกนก่อนเริ่มทำงาน' if lang != 'en' else 'Please confirm the scan before starting.',
        'scan_proposal': proposal,
    }), 400


# ─────────────────────────────────────────
#  Voice commands (the parser is voice_commands.py)
# ─────────────────────────────────────────
# The browser's speech recognition gives us TEXT. /api/voice/command only works out what it means; for a scan it hands back a
# signed confirmation and starts nothing. /api/voice/scan starts the scan, and only for a confirmation that is valid, not expired, not
# used before and made for this user, so what runs is exactly what the confirmation card showed (the browser cannot change the target).

VOICE_CONFIRM_SECONDS = 120
_voice_signer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='clylar-voice-scan')
_voice_used = {}                    # nonce -> time it was used, so one confirmation starts one scan (a double click must not start two)
_voice_used_lock = threading.Lock()


def _voice_lang(data):
    return 'en' if (data or {}).get('lang') == 'en' else 'th'


@app.route('/api/voice/command', methods=['POST'])
@admin_required
def api_voice_command():
    """What does this text mean? Never starts anything. A scan command comes back with status 'ok' and a `token` to confirm with."""
    data = request.get_json(silent=True) or {}
    text = str(data.get('text') or '')[:300]
    lang = _voice_lang(data)
    alts = data.get('alternatives')
    texts = [text] + ([str(a) for a in alts[:voice_commands.MAX_ALTERNATIVES]] if isinstance(alts, list) else [])
    cmd, used = None, text
    if data.get('expect') == 'target':
        # the page asked "which target?" and is waiting for just an address (a bare address is a command ONLY in that case)
        cmd, _, used = voice_commands.reply_best(texts, lang, data.get('scan_type'))
    if cmd is None:
        cmd, _, used = voice_commands.understand_best(texts, lang)
    cmd['heard_text'] = used                                    # the reading that was understood (may be one of the engine's alternatives)
    cmd['alt_used'] = used != (texts[0] if texts else '')       # the card says so: the engine's other reading was used
    page_path = str(data.get('page_path') or '')[:200]
    if cmd['intent'] == 'scan' and cmd['status'] == 'ok':
        cmd['scan_label'] = scan_labels()[cmd['scan_type']]
        cmd['expires_in'] = VOICE_CONFIRM_SECONDS
        cmd['token'] = _voice_signer.dumps({'u': current_user.id, 't': cmd['target'], 'k': cmd['scan_type'], 'n': secrets.token_hex(8)})
        # "scan at once": the SERVER decides, from this admin's own setting and the target; the page only follows. A refusal is said on the card.
        if voice_autorun_on(current_user.id):
            cmd['autorun'] = voice_autorun_allowed(cmd['target'])
            cmd['autorun_refused'] = not cmd['autorun']
    elif cmd['intent'] == 'fact':
        cmd.update(_voice_answer(cmd, lang))                    # our own code: no AI, no tokens
    elif cmd['intent'] == 'export' and cmd['status'] == 'ok':
        cmd.update(_voice_build_export(cmd, lang, page_path))
    elif cmd['intent'] == 'navigate' and cmd['status'] == 'ok':
        cmd.update(_voice_build_nav(cmd, lang, page_path))      # URLs are always constructed server-side via url_for()
    elif cmd['intent'] == 'unknown':
        cmd['ai_enabled'] = ai_enabled()                        # the page decides whether to ask the AI
        cmd['worth_ai'] = voice_commands.worth_asking_ai(used, data.get('typed') is True)  # noise ("2nd 1.01.208.") is never sent to the AI: it only costs tokens; typed text gets the relaxed rule
        if not cmd['worth_ai']:
            cmd['message'] = voice_commands.not_understood(used, lang)['message']
    return jsonify(cmd)


# ───────────── Voice lab: record the sentences, keep the audio, score what the browser's engine wrote (docs/voice-reliability-plan.md) ─────────────
_voice_lab_lock = threading.Lock()


def _voice_lab_folder(session_id):
    """instance/voice_lab/<user id>/<session>: never served, kept out of git (.gitignore). The session id was validated by voice_lab.valid_session."""
    return pathlib.Path(app.instance_path) / 'voice_lab' / str(current_user.id) / session_id


def _voice_lab_results(folder):
    try:
        data = json.loads((folder / 'results.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


@app.route('/assistant')
@login_required
@admin_required
def assistant_view():
    """The Assistant page: the chat widget (templates/partials/_chat_widget.html, CSS and JavaScript in base.html) laid out as a full page,
    option C of docs/design-options/assistant-voice. Admins only, like the floating chat. Everything typed or spoken goes to the local parser first."""
    return render_template('assistant.html', assistant_page=True)


@app.route('/voice')
@login_required
@admin_required
def voice_view():
    """The Voice page: one big microphone, a ring that follows the voice, and the result under it (option B of docs/design-options/voice-orb). It is NOT a second
    voice engine: it lays out the Assistant's own widget (templates/partials/_chat_widget.html, voice_page branch) so the microphone, Whisper, the parser and
    the confirmation card are the same code as everywhere else (CSS and JavaScript in base.html). Admins only, like the chat."""
    return render_template('voice.html', assistant_page=True, voice_page=True)


@app.route('/voice-lab')
@login_required
@admin_required
def voice_lab_page():
    sid = voice_lab.new_session_id(now_th())
    return render_template('voice_lab.html', prompts=voice_lab.public_prompts(), session_id=sid, folder='instance/voice_lab/%s/%s' % (current_user.id, sid))


@app.route('/api/voice-lab/clip', methods=['POST'])
@admin_required
def api_voice_lab_clip():
    """One recorded sentence: the audio, and the text the browser's own engine wrote for it (when it wrote any). Saved for the later model
    comparison and scored at once with the app's real parser (voice_lab.score), exactly as /api/voice/command would read it."""
    sid, prompt = request.form.get('session', ''), voice_lab.get_prompt(request.form.get('prompt', ''))
    if not voice_lab.valid_session(sid) or prompt is None:
        return jsonify({'error': 'bad_request'}), 400
    f = request.files.get('audio')
    ext = voice_lab.audio_extension(f.mimetype) if f else None
    if not ext:
        return jsonify({'error': 'no_audio'}), 400
    audio = f.read(voice_lab.MAX_AUDIO_BYTES + 1)
    if len(audio) > voice_lab.MAX_AUDIO_BYTES:
        return jsonify({'error': 'too_big'}), 413
    if len(audio) < 200:
        return jsonify({'error': 'empty'}), 400
    try:
        texts = voice_lab.clean_texts(json.loads(request.form.get('texts') or '[]'))
    except ValueError:
        texts = []
    score = voice_lab.score(prompt, texts)
    try:
        duration_ms = max(0, min(int(request.form.get('duration_ms') or 0), 120000))
    except ValueError:
        duration_ms = 0
    record = {'prompt_id': prompt['id'], 'lang': prompt['lang'], 'sentence': prompt['text'], 'expected': prompt['expect'],
              'file': '%s.%s' % (prompt['id'], ext), 'bytes': len(audio), 'duration_ms': duration_ms, 'texts': texts, 'score': score,
              'engine_lang': request.form.get('engine_lang', '')[:12], 'engine_error': request.form.get('engine_error', '')[:60],
              'audio_settings': request.form.get('audio_settings', '')[:500], 'user_agent': (request.headers.get('User-Agent') or '')[:200],
              'saved_at': now_th().isoformat(timespec='seconds')}
    folder = _voice_lab_folder(sid)
    with _voice_lab_lock:
        folder.mkdir(parents=True, exist_ok=True)
        for old in folder.glob(prompt['id'] + '.*'):           # a redo replaces the earlier take
            old.unlink()
        (folder / record['file']).write_bytes(audio)
        results = _voice_lab_results(folder)
        results[prompt['id']] = record
        tmp = folder / 'results.json.tmp'
        tmp.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding='utf-8')
        os.replace(tmp, folder / 'results.json')
    return jsonify({'ok': True, 'score': score, 'bytes': len(audio), 'file': record['file']})


@app.route('/api/voice-lab/summary')
@admin_required
def api_voice_lab_summary():
    sid = request.args.get('session', '')
    if not voice_lab.valid_session(sid):
        return jsonify({'error': 'bad_request'}), 400
    with _voice_lab_lock:
        results = _voice_lab_results(_voice_lab_folder(sid))
    return jsonify(voice_lab.summarize([{'prompt_id': k, 'score': (v or {}).get('score')} for k, v in results.items() if isinstance(v, dict)]))


# ───────────── Local Whisper: the speech-to-text program on this computer (whisper_worker.py, docs/voice-reliability-plan.md section 9) ─────────────
WHISPER_URL = os.environ.get('CLYLAR_WHISPER_URL', 'http://127.0.0.1:5057').rstrip('/')
WHISPER_MAX_AUDIO = 3 * 1024 * 1024
if not re.match(r'^http://(127\.0\.0\.1|localhost)(:\d{2,5})?$', WHISPER_URL):
    WHISPER_URL = 'http://127.0.0.1:5057'          # the worker is only ever on this computer; anything else in the setting is ignored


def _whisper_call(method, path, body=None, timeout=30):
    """Ask the worker. Returns (HTTP status, dict), or (None, {'error': 'unavailable'}) when it is not running or its token is missing."""
    import urllib.request, urllib.error
    try:
        token = (pathlib.Path(app.instance_path) / 'whisper_worker.token').read_text(encoding='utf-8').strip()
    except OSError:
        token = ''
    if not token:
        return None, {'error': 'unavailable'}
    req = urllib.request.Request(WHISPER_URL + path, data=body, method=method, headers={'X-Worker-Token': token, 'Content-Type': 'application/octet-stream'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # never through a proxy (HTTP_PROXY): the audio and the token stay on this computer
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode('utf-8'))
        except ValueError:
            return e.code, {'error': 'worker_error'}
    except (urllib.error.URLError, OSError, ValueError):
        return None, {'error': 'unavailable'}


_m = re.search(r':(\d+)$', WHISPER_URL)
WHISPER_PORT = int(_m.group(1)) if _m else 5057
_whisper_start_lock = threading.Lock()


def _whisper_files():
    """(the Python of the voice-lab folder, the model folder, whisper_worker.py): where the program is started from. The folder comes from the
    environment (CLYLAR_WHISPER_HOME, default Desktop/clylar-whisper-lab) and nothing in a request can change it."""
    lab = pathlib.Path(os.environ.get('CLYLAR_WHISPER_HOME') or (pathlib.Path.home() / 'Desktop' / 'clylar-whisper-lab'))
    py = lab / 'venv' / ('Scripts' if os.name == 'nt' else 'bin') / ('python.exe' if os.name == 'nt' else 'python')
    return py, lab / 'models' / 'thai-large', pathlib.Path(__file__).resolve().with_name('whisper_worker.py')


def _whisper_installed():
    py, model, worker = _whisper_files()
    return py.is_file() and (model / 'model.bin').is_file() and worker.is_file()


def _whisper_process():
    """The Whisper program, wherever it was started from (this page, start_whisper_worker.bat), as a psutil.Process; None when it is not running.
    It is recognised by its command line (whisper_worker.py with our port), never by a number alone: a stale or reused PID is never trusted."""
    try:
        import psutil
    except ImportError:
        return None

    def is_worker(p):
        try:
            cmd = [str(a) for a in p.cmdline()]
        except (psutil.Error, OSError):
            return False
        if not any(os.path.basename(a).lower() == 'whisper_worker.py' for a in cmd):
            return False
        port = cmd[cmd.index('--port') + 1] if '--port' in cmd[:-1] else '5057'        # the program's own default when no port is given
        return port == str(WHISPER_PORT)

    try:
        pid = int((pathlib.Path(app.instance_path) / 'whisper_worker.pid').read_text(encoding='utf-8').strip())
        p = psutil.Process(pid)
        if is_worker(p):
            return p
    except (OSError, ValueError, psutil.Error):
        pass
    for p in psutil.process_iter():
        if p.pid != os.getpid() and is_worker(p):
            return p
    return None


def _whisper_state():
    """{'state': 'running' | 'starting' | 'stopped', 'installed': bool, the program's own facts when it runs, and 'error' (the end of its log) when a start died}."""
    out = {'installed': _whisper_installed()}
    status, j = _whisper_call('GET', '/health', timeout=1.5)
    if status == 200 and j.get('ok'):
        return dict(out, state='running', model=j.get('model'), device=j.get('device'), compute=j.get('compute'), last_seconds=j.get('last_seconds'))
    if _whisper_process() is not None:
        return dict(out, state='starting')
    out['state'] = 'stopped'
    try:                                                           # a start that died leaves its reason in the log (a port in use, a missing library)
        if (pathlib.Path(app.instance_path) / 'whisper_worker.pid').exists():
            tail = (pathlib.Path(app.instance_path) / 'whisper_worker.log').read_bytes()[-6000:].decode('utf-8', 'replace')
            lines = [l.strip() for l in tail.splitlines() if l.strip()]
            if lines and not _whisper_ended_normally(lines):
                out['error'] = lines[-1][:200]
    except OSError:
        pass
    return out


def _whisper_ended_normally(lines):
    """True when the newest run of the program reached 'Listening on' and then simply ended: its window was closed (the Fortran runtime that CUDA loads
    prints 'forrtl: error (200): program aborting due to window-CLOSE event' and a stack of 'Unknown' lines) or it was killed from outside. That is a stop,
    not a failed start, and the Settings card must not call it one. A crash after 'Listening on' (a port in use raises right after that line) and a run that
    never got there ('loading' with nothing after it) are still errors."""
    up = max((i for i, l in enumerate(lines) if 'Listening on' in l), default=-1)
    if up < 0 or any(l.startswith('loading ') for l in lines[up + 1:]):
        return False
    return up == len(lines) - 1 or lines[up + 1].startswith('forrtl: error (200)')


@app.route('/api/voice/whisper/status')
@admin_required
def api_voice_whisper_status():
    """Is the local Whisper program running, starting or stopped? The chat page uses `available` to choose the engine of the microphone; the Settings
    card shows the rest and lets an admin start or stop it."""
    st = _whisper_state()
    st['available'] = st['state'] == 'running'
    return jsonify(st)


@app.route('/api/voice/whisper/start', methods=['POST'])
@admin_required
def api_voice_whisper_start():
    """Start the Whisper program in the background (the model loads in about 10 s: the page polls /status). It keeps running when the app reloads
    or stops, because it is a separate program; /stop ends it."""
    import subprocess
    with _whisper_start_lock:
        st = _whisper_state()
        if st['state'] != 'stopped':
            return jsonify({'ok': True, 'state': st['state']})
        if not st['installed']:
            return jsonify({'error': 'not_installed'}), 409
        py, model, worker = _whisper_files()
        inst = pathlib.Path(app.instance_path)
        try:
            log = open(inst / 'whisper_worker.log', 'ab')
            flags = (0x00000008 | 0x00000200) if os.name == 'nt' else 0        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no window, survives this app
            proc = subprocess.Popen([str(py), str(worker), '--model', str(model), '--instance', app.instance_path, '--port', str(WHISPER_PORT)],
                                    stdout=log, stderr=log, stdin=subprocess.DEVNULL, cwd=str(worker.parent), creationflags=flags,
                                    env=dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1'))
            (inst / 'whisper_worker.pid').write_text(str(proc.pid), encoding='utf-8')
        except OSError as e:
            app.logger.warning('Whisper: could not start the program (%s)', e)
            return jsonify({'error': 'cannot_start'}), 500
    return jsonify({'ok': True, 'state': 'starting'})


@app.route('/api/voice/whisper/stop', methods=['POST'])
@admin_required
def api_voice_whisper_stop():
    """Stop the Whisper program (and anything it started). It is ONE program shared by every admin: stopping it sends everyone's microphone back to the
    browser's engine until someone starts it again. Only a process whose command line is whisper_worker.py with our port is ever touched."""
    p = _whisper_process()
    if p is not None:
        try:
            import psutil
            for child in p.children(recursive=True):
                try:
                    child.kill()
                except psutil.Error:
                    pass
            p.kill()
            p.wait(timeout=10)
        except Exception as e:                     # noqa: BLE001  (it may already be gone; the answer below is what is true now)
            app.logger.info('Whisper: stopping the program: %s', e)
    try:
        (pathlib.Path(app.instance_path) / 'whisper_worker.pid').unlink()
    except OSError:
        pass
    return jsonify({'ok': True, 'state': _whisper_state()['state']})


@app.route('/api/voice/transcribe', methods=['POST'])
@admin_required
def api_voice_transcribe():
    """One spoken command to text with the local Whisper program. Nothing is stored; the text then goes to /api/voice/command like any other
    text, so a scan still needs the confirmation card. form: audio (the recording), lang ('th' | 'en' | 'auto'), first ('th' | 'en': the language
    Auto tries first). Whisper cannot tell Thai from English for these commands (a Thai-tuned model writes English speech as Thai letters), so in
    Auto the preferred language is tried first and the other one only when that text is not a command the app can act on: the parser is the judge.
    The answer is the best reading first and the other one in `alternatives`, exactly what /api/voice/command expects."""
    f = request.files.get('audio')
    if not f or not voice_lab.audio_extension(f.mimetype):
        return jsonify({'error': 'no_audio'}), 400
    audio = f.read(WHISPER_MAX_AUDIO + 1)
    if len(audio) > WHISPER_MAX_AUDIO:
        return jsonify({'error': 'too_big'}), 413
    if len(audio) < 200:
        return jsonify({'error': 'empty'}), 400
    mode = request.form.get('lang')
    order = (['en', 'th'] if request.form.get('first') == 'en' else ['th', 'en']) if mode == 'auto' else ['en' if mode == 'en' else 'th']
    expect_target = request.form.get('expect') == 'target'      # the page asked "which target?": a bare address is the answer, so it is a usable reading
    scan_type = request.form.get('scan_type') or None
    readings, seconds = [], 0.0                      # (language, text) in the order tried
    for lang in order:
        status, j = _whisper_call('POST', '/transcribe?lang=' + lang, audio)
        if not (status == 200 and j.get('ok')):
            if readings:                              # the second try failed: the first reading still stands
                break
            if status is None:
                return jsonify({'error': 'unavailable'}), 503
            return jsonify({'error': 'cannot_transcribe' if status == 422 else 'worker_error'}), (422 if status == 422 else 502)
        text = str(j.get('text') or '')[:300]
        seconds += float(j.get('seconds') or 0)
        readings.append((lang, text))
        answer = voice_commands.parse_target_reply(text, lang, scan_type) if expect_target else None
        if answer is not None:                        # an address was heard: final unless it lost or gained a number (the other language may have it right)
            if not voice_commands.reply_wants_other_reading(answer):
                break
        elif not voice_commands.wants_other_reading(voice_commands.understand(text, lang)):
            break                                     # a command the app can act on, or an address that is wrong as spoken (shown, never replaced): no other language
    texts = [t for _, t in readings]
    # The readings go out in the order they were tried; /api/voice/command applies the SAME rule (understand_best) to choose, notes "the engine's other
    # reading" on the card when it used the second one, and never replaces an address that was wrong as spoken. `language` is the language of the reading it will use.
    used = None
    if expect_target:                                 # the same choice /api/voice/command will make for this answer
        answer, _, used = voice_commands.reply_best(texts, readings[0][0], scan_type)
        if answer is None:
            used = None
    if used is None:
        _, _, used = voice_commands.understand_best(texts, readings[0][0])
    language = next((l for l, t in readings if t == used), readings[0][0])
    alternatives = [t for t in texts[1:] if t.strip() and t != texts[0]]
    return jsonify({'ok': True, 'text': texts[0], 'alternatives': alternatives, 'language': language, 'shown': used, 'tried': [l for l, _ in readings],
                    'seconds': round(seconds, 2)})


_VOICE_PAGE_ENDPOINT = {'dashboard': 'dashboard', 'tasks': 'tasks_page', 'history': 'history_page', 'devices': 'devices_page',
                        'vulnerabilities': 'vulnerabilities_page', 'topology': 'topology_page', 'reports': 'reports_page',
                        'settings': 'settings_page'}
_VOICE_SEV_RANK = {'LOW': 1, 'UNKNOWN': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
_VOICE_SEV_LABEL = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
_VOICE_STATUS_TH = {'Completed': 'เสร็จสิ้น', 'Failed': 'ล้มเหลว', 'Running': 'กำลังทำงาน', 'Queued': 'รอคิว', 'Cancelled': 'ถูกยกเลิก'}
_VOICE_VALID_SEVS = ('critical', 'high', 'medium', 'low')
_VOICE_VALID_OS = ('Windows', 'Linux', 'Android', 'Apple', 'Other', 'Unknown')
_VOICE_VALID_TYPES = tuple(lbl for lbl, _ in DEVICE_TYPES.values())
_VOICE_VALID_STATUSES = ('Completed', 'Failed', 'Running', 'Queued', 'Cancelled')
_VOICE_TYPE_TH = {
    'Router / Gateway': 'เราเตอร์ / เกตเวย์',
    'Virtual Machine': 'เครื่องเสมือน',
    'Computer': 'คอมพิวเตอร์',
    'Phone / Tablet': 'โทรศัพท์ / แท็บเล็ต',
    'Printer': 'เครื่องพิมพ์',
    'Camera': 'กล้อง',
    'Smart TV': 'สมาร์ททีวี',
    'IoT device': 'อุปกรณ์ IoT',
    'Unknown': 'ไม่ทราบ',
}


def _resolve_voice_scan(job_id=None, ip=None, page_path='', completed_only=True):
    """Pick the scan job for a voice export/report/detail command, strictly scoped by visible_scans_query().
    Priority: explicit job_id -> matching ip -> current /scan/<id> page -> latest scan."""
    base = visible_scans_query()
    if job_id is not None:
        job = base.filter_by(id=job_id).first()
        if not job:
            return None, 'job_not_found'
        if completed_only and job.status != 'Completed':
            return job, 'job_not_completed'
        return job, 'ok'

    q = base.filter(ScanJob.status == 'Completed') if completed_only else base
    if ip:
        candidates = q.order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
        for j in candidates:
            if j.target == ip:
                return j, 'ok'
        for j in candidates:
            if not j.result_data or ip not in j.result_data:
                continue
            try:
                hosts = json.loads(j.result_data)
            except Exception:
                continue
            if isinstance(hosts, list) and any(isinstance(h, dict) and h.get('ip') == ip for h in hosts):
                return j, 'ok'
        return None, 'ip_not_found'

    m = re.match(r'^/scan/(\d+)(?:/|$)', str(page_path or '').strip())
    if m:
        cur = base.filter_by(id=int(m.group(1))).first()
        if cur and (not completed_only or cur.status == 'Completed'):
            return cur, 'ok'

    latest = q.order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).first()
    if latest:
        return latest, 'ok'
    return None, 'no_scans'


def _voice_scan_missing_msg(reason, job, job_id, ip, lang):
    th = lang != 'en'
    say = lambda t, e: t if th else e
    if reason == 'job_not_found':
        lbl = job_label(job_id, 'th' if th else 'en')
        return say(f'ไม่พบ{lbl}', f'{lbl} was not found.')
    if reason == 'job_not_completed' and job is not None:
        lbl = job_label(job.id, 'th' if th else 'en')
        st = _VOICE_STATUS_TH.get(job.status, job.status) if th else job.status
        return say(f'{lbl} ยังไม่เสร็จสิ้น (สถานะ: {st})', f'{lbl} is not completed yet (status: {st}).')
    if reason == 'ip_not_found':
        return say(f'ไม่พบผลสแกนที่เสร็จสิ้นของ {ip}', f'No completed scan was found for {ip}.')
    return say('ยังไม่มีงานสแกนที่เสร็จสิ้นในระบบ', 'There is no completed scan yet.')


def _voice_build_export(cmd, lang, page_path):
    """Resolve the scan job and safe server-side export URLs for a voice PDF/CSV command."""
    job, reason = _resolve_voice_scan(
        job_id=cmd.get('job_id'), ip=cmd.get('ip'), page_path=page_path, completed_only=True
    )
    if reason != 'ok' or not job:
        return {'status': 'not_found', 'message': _voice_scan_missing_msg(reason, job, cmd.get('job_id'), cmd.get('ip'), lang)}

    lang_code = 'en' if lang == 'en' else 'th'
    fmt = cmd['format']
    orient = cmd.get('orientation') if cmd.get('orientation') in ('portrait', 'landscape') else None
    orient_kw = {'orientation': orient} if orient else {}
    safe_target = (job.target or '').replace('/', '_').replace(' ', '_').replace('\\', '_')
    ts_str = job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'
    filename = f"scan_{job.id}_{safe_target}_{ts_str}.{fmt}"
    jlbl = f"{job_label(job.id, lang_code)} ({job.target})"

    if fmt == 'pdf':
        return {
            'scan_id': job.id,
            'target': job.target,
            'job_label': jlbl,
            'filename': filename,
            'view_url': url_for('export_pdf', scan_id=job.id, inline='1', **orient_kw),
            'download_url': url_for('export_pdf', scan_id=job.id, **orient_kw),
            'report_url': url_for('scan_report', scan_id=job.id, **orient_kw),
        }
    return {
        'scan_id': job.id,
        'target': job.target,
        'job_label': jlbl,
        'filename': filename,
        'view_url': '',
        'download_url': url_for('export_csv', scan_id=job.id),
        'report_url': url_for('scan_detail', scan_id=job.id),
    }


def _voice_build_nav(cmd, lang, page_path):
    """Build a safe url_for() destination + descriptive page_name for a voice navigation command (with optional filters)."""
    th = lang != 'en'
    lang_code = 'th' if th else 'en'
    say = lambda t, e: t if th else e
    page = cmd['page']
    filters = cmd.get('filters') or {}

    if page == 'scan_detail':
        job_id = filters.get('job_id')
        job, reason = _resolve_voice_scan(
            job_id=job_id, ip=filters.get('ip'), page_path='', completed_only=(job_id is None)
        )
        if reason != 'ok' or not job:
            return {'status': 'not_found', 'message': _voice_scan_missing_msg(reason, job, job_id, filters.get('ip'), lang)}
        if job.status != 'Completed':
            return {'status': 'not_found', 'message': _voice_scan_missing_msg('job_not_completed', job, job.id, None, lang)}
        return {
            'url': url_for('scan_detail', scan_id=job.id),
            'page_name': f"{job_label(job.id, lang_code)} ({job.target})",
        }

    if page == 'scan_report':
        job_id = filters.get('job_id')
        ip = filters.get('ip')
        use_ctx = '' if (filters.get('latest') or job_id or ip) else page_path
        job, reason = _resolve_voice_scan(job_id=job_id, ip=ip, page_path=use_ctx, completed_only=True)
        if reason != 'ok' or not job:
            return {'status': 'not_found', 'message': _voice_scan_missing_msg(reason, job, job_id, ip, lang)}
        return {
            'url': url_for('scan_report', scan_id=job.id),
            'page_name': say(f"รายงาน {job_label(job.id, 'th')} ({job.target})", f"Report {job_label(job.id, 'en')} ({job.target})"),
        }

    if page == 'devices' and filters.get('ip'):
        want_ip = str(filters['ip'])
        f = _voice_collect()
        primary = want_ip if want_ip in f['devices'] else f['ip_alias'].get(want_ip)
        if not primary:
            return {'status': 'not_found', 'message': say(f'ไม่พบอุปกรณ์ {want_ip} ในประวัติการสแกน', f'Device {want_ip} was not found in your scan history.')}
        return {
            'url': url_for('device_detail', ip=primary),
            'page_name': say(f'อุปกรณ์ {primary}', f'Device {primary}'),
        }

    params = {}
    tags = []
    if page == 'vulnerabilities':
        sevs = [s for s in (filters.get('sev') or []) if s in _VOICE_VALID_SEVS]
        if sevs:
            params['sev'] = ','.join(sevs)
            tags.append(', '.join(sev_label(s, lang_code) for s in sevs))
        if filters.get('kev'):
            f = _voice_collect()
            if not f['has_kev']:
                return {'status': 'not_found', 'message': say('ไม่พบช่องโหว่ที่ถูกโจมตีจริง (CISA KEV) ในผลสแกนปัจจุบัน', 'No Known Exploited Vulnerabilities (CISA KEV) were found.')}
            params['kev'] = '1'
            tags.append(say('ถูกโจมตีจริง (KEV)', 'Known Exploited (KEV)'))
        if filters.get('host'):
            params['host'] = str(filters['host'])
            tags.append(str(filters['host']))
        if filters.get('q'):
            params['q'] = str(filters['q'])
            tags.append(str(filters['q']))
    elif page == 'devices':
        if filters.get('os') in _VOICE_VALID_OS:
            params['os'] = filters['os']
            tags.append(filters['os'])
        if filters.get('type') in _VOICE_VALID_TYPES:
            params['type'] = filters['type']
            tags.append(_VOICE_TYPE_TH.get(filters['type'], filters['type']) if th else filters['type'])
        if filters.get('ports') in ('has', 'none'):
            params['ports'] = filters['ports']
            tags.append(say('มีพอร์ตเปิด', 'With open ports') if filters['ports'] == 'has' else say('ไม่มีพอร์ตเปิด', 'No open ports'))
    elif page == 'history':
        if filters.get('status') in _VOICE_VALID_STATUSES:
            params['status'] = filters['status']
            tags.append(_VOICE_STATUS_TH.get(filters['status'], filters['status']) if th else filters['status'])
        if filters.get('type') in SCAN_TYPE_LABELS:
            params['type'] = filters['type']
            tags.append(scan_labels(lang_code).get(filters['type'], filters['type']))
        if filters.get('q'):
            params['q'] = str(filters['q'])
            tags.append(str(filters['q']))
    elif page == 'tasks':
        if filters.get('status') in _VOICE_VALID_STATUSES:
            params['status'] = filters['status']
            tags.append(_VOICE_STATUS_TH.get(filters['status'], filters['status']) if th else filters['status'])
    elif page == 'reports':
        if filters.get('type') in SCAN_TYPE_LABELS:
            params['type'] = filters['type']
            tags.append(scan_labels(lang_code).get(filters['type'], filters['type']))
        if filters.get('q'):
            params['q'] = str(filters['q'])
            tags.append(str(filters['q']))

    base_name = cmd.get('page_name') or voice_commands.PAGES[page][1 if lang == 'en' else 0]
    full_name = f"{base_name} ({', '.join(tags)})" if tags else base_name
    return {'url': url_for(_VOICE_PAGE_ENDPOINT[page], **params), 'page_name': full_name}


def _voice_collect():
    """The figures the dashboard shows, built from the exact same _build_device_inventory() helper so Voice/AI,
    Dashboard, Devices, Vulnerabilities, and Tasks always report matching numbers."""
    history = visible_scans_query().order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()).all()
    inventory = _build_device_inventory(history)
    devices, ip_alias, ports, cves, by_sev, tiers = {}, {}, set(), {}, {}, {}
    has_kev = False
    for dev in inventory:
        ip = dev['ip']
        for other_ip in dev.get('other_ips') or ():
            ip_alias[other_ip] = ip
        ports.update(dev['open_port_keys'])
        sevs = set()
        for cid, finding in dev['active_cves'].items():
            sev = finding['severity']
            sevs.add(sev)
            if finding.get('kev') is True:
                has_kev = True
            cves[(ip, cid)] = {'severity': sev, 'cvss_score': finding['cvss_score']}
            by_sev[sev] = by_sev.get(sev, 0) + 1
        devices[ip] = {
            'vuln_scanned': dev['vuln_scanned'],
            'key': dev['worst_key'],
            'worst': dev['worst_severity'],
            'sevs': sevs,
            'has_cve': bool(dev['active_cves']),
        }
        w = dev['worst_severity']
        tier = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'UNKNOWN': 'low'}.get(w) or (
            'clean' if dev['vuln_scanned'] else 'unscanned'
        )
        tiers.setdefault(tier, []).append(ip)
    return {'scans': len(history), 'devices': devices, 'ip_alias': ip_alias, 'has_kev': has_kev,
            'ports': ports, 'cves': cves, 'cves_by_sev': by_sev, 'tiers': tiers,
            'latest': history[0] if history else None, 'running': [j for j in history if j.status in ACTIVE_STATUSES],
            'schedules': [x for x in visible_schedules_query().all() if x.is_active]}


def _voice_figures_text():
    """The figures above as plain lines for the AI prompt, so it does not have to count from a partial list."""
    f = _voice_collect()
    b = f['cves_by_sev']
    other = sum(n for k, n in b.items() if k not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
    t = f['tiers']
    return '\n'.join([
        f"- อุปกรณ์ที่พบทั้งหมด (ทุกการสแกน): {len(f['devices'])}",
        f"- พอร์ตที่เปิดอยู่ (นับเลขพอร์ตไม่ซ้ำ): {len(f['ports'])}",
        f"- CVE ทั้งหมด (ไม่ซ้ำ): {len(f['cves'])} (Critical {b.get('CRITICAL', 0)}, High {b.get('HIGH', 0)}, Medium {b.get('MEDIUM', 0)}, "
        f"Low {b.get('LOW', 0)}" + (f", อื่นๆ {other}" if other else '') + ')',
        f"- อุปกรณ์แยกตาม CVE ที่แย่ที่สุด: critical {len(t.get('critical', []))}, high {len(t.get('high', []))}, medium {len(t.get('medium', []))}, "
        f"low {len(t.get('low', []))}, สแกนช่องโหว่แล้วไม่พบ {len(t.get('clean', []))}, ยังไม่เคยสแกนช่องโหว่ {len(t.get('unscanned', []))}",
        f"- สแกนที่กำลังทำงานอยู่: {len(f['running'])}",
        f"- จำนวนสแกนทั้งหมดที่มองเห็น: {f['scans']}",
    ])


def _voice_answer(cmd, lang):
    """The answer to a question the parser recognised, as {'answer', 'link', 'link_label'}. Plain facts from _voice_collect(): no AI."""
    f = _voice_collect()
    th = lang != 'en'
    say = lambda t, e: t if th else e
    fact, sev = cmd['fact'], cmd.get('severity')
    lang_code = 'th' if th else 'en'
    label = sev_label(sev, lang_code) if sev else ''
    link = lambda url: {'link': url, 'link_label': say('ดูรายละเอียด', 'See details')}
    no_data = {'answer': say('ยังไม่มีข้อมูลการสแกน', 'There is no scan data yet.')}
    nodev = len(f['devices'])
    vuln_scanned = any(d['vuln_scanned'] for d in f['devices'].values())

    if fact == 'running_scans':
        n = len(f['running'])
        if not n:
            return {'answer': say('ไม่มีสแกนที่กำลังทำงานอยู่', 'No scan is running right now.'), **link(url_for('tasks_page'))}
        names = ', '.join('%s (%s)' % (j.target, scan_labels('th' if th else 'en').get(j.scan_type, j.scan_type or '')) for j in f['running'][:5])
        return {'answer': say('กำลังสแกนอยู่ %d งาน: %s' % (n, names), '%d scan(s) running: %s' % (n, names)), **link(url_for('tasks_page', status='Running'))}

    if fact == 'next_schedule':
        due = sorted((x for x in f['schedules'] if x.next_run), key=lambda x: x.next_run)
        if not due:
            return {'answer': say('ไม่มีการตั้งเวลาสแกนที่เปิดใช้งานอยู่', 'There is no active scheduled scan.'), **link(url_for('tasks_page'))}
        x = due[0]
        when = x.next_run.strftime('%Y-%m-%d %H:%M')
        what = '%s (%s, %s)' % (x.name, x.target, scan_labels('th' if th else 'en').get(x.scan_type, x.scan_type or ''))
        return {'answer': say('สแกนตามเวลาครั้งถัดไป: %s เวลา %s' % (what, when), 'Next scheduled scan: %s at %s' % (what, when)), **link(url_for('tasks_page'))}

    if not f['scans']:
        return no_data

    if fact == 'latest_scan':
        j = f['latest']
        hosts = None
        try:
            data = json.loads(j.result_data) if j.result_data else None
            if isinstance(data, list) and not (data and isinstance(data[0], dict) and data[0].get('error')):
                hosts = len(data)
        except Exception:
            pass
        kind = scan_labels(lang_code).get(j.scan_type, j.scan_type or '')
        when = j.timestamp.strftime('%Y-%m-%d %H:%M') if j.timestamp else '-'
        text = say('สแกนล่าสุด: %s (%s) สถานะ %s เมื่อ %s' % (j.target, kind, _VOICE_STATUS_TH.get(j.status, j.status), when),
                   'Latest scan: %s (%s), %s, at %s' % (j.target, kind, j.status, when))
        if hosts is not None:
            text += say(' พบ %d อุปกรณ์' % hosts, ', %d device(s) found' % hosts)
        return {'answer': text, **link(url_for('scan_detail', scan_id=j.id) if j.status == 'Completed' else url_for('tasks_page'))}

    if fact == 'count_ports':
        return {'answer': say('พอร์ตที่เปิดอยู่ %d พอร์ต (นับเลขพอร์ตไม่ซ้ำ จากทุกการสแกน)' % len(f['ports']),
                              '%d distinct open ports across all scans.' % len(f['ports'])), **link(url_for('dashboard'))}

    vuln_url = url_for('vulnerabilities_page', sev=sev) if sev else url_for('vulnerabilities_page')

    if fact == 'count_devices':
        if not sev:
            return {'answer': say('พบอุปกรณ์ทั้งหมด %d เครื่อง (จากทุกการสแกน)' % nodev, '%d device(s) found across all scans.' % nodev), **link(url_for('devices_page'))}
        n = sum(1 for d in f['devices'].values() if sev.upper() in d['sevs'])
        text = say('%d เครื่องมี CVE ระดับ %s อย่างน้อย 1 รายการ' % (n, label), '%d device(s) have at least one %s CVE.' % (n, label))
        if not vuln_scanned:
            text += say(' (ยังไม่เคยสแกนช่องโหว่ จึงยังไม่มีข้อมูล CVE)', ' (No vulnerability scan has been run yet, so there is no CVE data.)')
        return {'answer': text, **link(vuln_url)}

    if fact == 'count_cves':
        b, total = f['cves_by_sev'], len(f['cves'])
        if sev:
            n = b.get(sev.upper(), 0)
            text = say('CVE ระดับ %s มี %d รายการ จากทั้งหมด %d รายการ (ไม่ซ้ำกัน)' % (label, n, total), '%d %s CVE(s) out of %d distinct CVEs.' % (n, label, total))
        else:
            other = sum(n for k, n in b.items() if k not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
            parts = '%s %d, %s %d, %s %d, %s %d' % (
                sev_label('CRITICAL', lang_code), b.get('CRITICAL', 0),
                sev_label('HIGH', lang_code), b.get('HIGH', 0),
                sev_label('MEDIUM', lang_code), b.get('MEDIUM', 0),
                sev_label('LOW', lang_code), b.get('LOW', 0),
            )
            if other:
                parts += say(', อื่น ๆ %d' % other, ', other %d' % other)
            text = say('พบ CVE ทั้งหมด %d รายการ (ไม่ซ้ำกัน): %s' % (total, parts), '%d distinct CVEs: %s' % (total, parts))
        if not vuln_scanned:
            text += say(' (ยังไม่เคยสแกนช่องโหว่ จึงยังไม่มีข้อมูล CVE)', ' (No vulnerability scan has been run yet, so there is no CVE data.)')
        return {'answer': text, **link(vuln_url)}

    if fact == 'devices_with_cves':
        want = sev.upper() if sev else None
        ips = sorted((ip for ip, d in f['devices'].items() if (want in d['sevs'] if want else d['has_cve'])), key=_ip_sort_key)
        what = label + ' ' if label else ''
        if not ips:
            text = say('ไม่พบอุปกรณ์ที่มี CVE %sระดับนี้' % ('ระดับ ' + label + ' ' if label else ''), 'No device has a %sCVE.' % what)
            if not vuln_scanned:
                text += say(' (ยังไม่เคยสแกนช่องโหว่)', ' (No vulnerability scan has been run yet.)')
            return {'answer': text, **link(vuln_url)}
        shown = ', '.join(ips[:10])
        more = len(ips) - 10
        text = say('%d เครื่องมี CVE %s: %s' % (len(ips), ('ระดับ ' + label) if label else '', shown), '%d device(s) with a %sCVE: %s' % (len(ips), what, shown))
        if more > 0:
            text += say(' และอีก %d เครื่อง' % more, ' and %d more' % more)
        return {'answer': text, 'items': ips[:10], **link(vuln_url)}

    return no_data


def _voice_system_prompt(lang, page_context, user_text='', typed=False):
    """The prompt for a question the parser did not recognise. Unlike the typed chat's it has NO scan ability: a voice/assistant
    command can only start a scan through the confirmation card."""
    if typed:
        intro = "คุณคือ CLYLAR Assistant ผู้ช่วยสำหรับระบบ CLYLAR Network Scanner ผู้ใช้กำลังพิมพ์ถามในหน้าผู้ช่วย\nตอบชัดเจน กระชับ อ้างอิงข้อมูลจริงและบริบทจากการสนทนาก่อนหน้า ตอบเป็นภาษา%sตามที่ผู้ใช้ถาม" % ('อังกฤษ' if lang == 'en' else 'ไทย')
        scan_hint = 'ถ้าผู้ใช้อยากสแกน ให้บอกให้พิมพ์คำสั่งสแกนโดยตรง เช่น "สแกน 192.168.1.1" เพื่อเปิดการ์ดยืนยัน'
    else:
        intro = "คุณคือ CLYLAR Assistant ผู้ช่วยสำหรับระบบ CLYLAR Network Scanner ผู้ใช้กำลังถามด้วยเสียง\nตอบสั้น กระชับ ฟังง่าย (ไม่เกิน 3-4 ประโยค ไม่ใช้ตาราง) ตอบเป็นภาษา%sตามที่ผู้ใช้พูด" % ('อังกฤษ' if lang == 'en' else 'ไทย')
        scan_hint = 'คุณสั่ง Scan เองไม่ได้ ถ้าผู้ใช้อยากสแกน ให้บอกให้พูดว่า "scan <IP>" เช่น "scan 192.168.1.1"'
    return f"""{intro}

=== หน้าที่ผู้ใช้กำลังดูอยู่ ===
{page_context or '(ไม่ทราบ)'}

{_build_app_context(user_text=user_text)}

กติกา:
- ใช้ตัวเลขจากส่วน "สรุปภาพรวมทั้งหมดของระบบ CLYLAR" เป็นหลัก ห้ามนับเอาเองจากรายการที่แสดงไม่ครบ
- เมื่อถูกถามเรื่องระบบปฏิบัติการ (OS) หรือชนิดอุปกรณ์ (Device Type) ให้ตอบจากฟิลด์ OS และ type ที่มีในข้อมูลจริง อย่าเดาจากพอร์ต ถ้าเป็น Unknown ให้บอกว่ายังตรวจไม่พบ OS
- {scan_hint}
- ถ้าไม่มีข้อมูลในระบบ ให้บอกตรงๆ ว่าไม่พบ อย่าเดา
- น้ำเสียงสุภาพ เป็นกลาง ไม่ใช้ emoji หรือสัญลักษณ์ตกแต่ง"""


def _strip_scan_marker(reply):
    """The voice AI is told it cannot scan, but if it writes a scan command anyway (##SCAN_CMD## + a JSON line) it is cut out and ignored."""
    return re.sub(r'##SCAN_CMD##[^\n]*(\n\s*\{[^\n]*\})?', '', str(reply or '')).replace('##SCAN_CMD##', '').strip()


def _sanitize_chat_messages(raw_messages, fallback_text=''):
    """Clean and bound a conversation history list before sending to the LLM (last 12 turns)."""
    out = []
    if isinstance(raw_messages, list):
        for m in raw_messages[-12:]:
            if not isinstance(m, dict):
                continue
            role = m.get('role')
            content = str(m.get('content') or '').strip()[:2000]
            if role in ('user', 'assistant') and content:
                out.append({'role': role, 'content': content})
    ft = str(fallback_text or '').strip()[:2000]
    if ft and (not out or out[-1]['role'] != 'user' or out[-1]['content'] != ft):
        out.append({'role': 'user', 'content': ft})
    return out


@app.route('/api/voice/ask', methods=['POST'])
@admin_required
def api_voice_ask():
    """A voice or /assistant typed question the local parser did not recognise, for the AI.
    Body: {text, lang, typed, messages?, page_context}. It can never start a scan directly."""
    data = request.get_json(silent=True) or {}
    lang = _voice_lang(data)
    is_typed = data.get('typed') is True
    text = str(data.get('text') or '').strip()[:300]
    if not voice_commands.worth_asking_ai(text, is_typed):
        return jsonify({'status': 'too_short', 'message': voice_commands.not_understood(text, lang)['message']})
    if not ai_enabled():
        return jsonify({'status': 'ai_off', 'message': AI_OFF_TEXT['en' if lang == 'en' else 'th']})
    if data.get('async') is True:                     # the Assistant page: the answer is written in the background, see start_background_answer
        return start_background_answer(api_voice_ask, {k: v for k, v in data.items() if k != 'async'})
    conv_messages = _sanitize_chat_messages(data.get('messages'), text) if is_typed else [{'role': 'user', 'content': text}]
    focus_text = ' '.join(m['content'] for m in conv_messages[-6:] if m['role'] == 'user')
    call_source = 'typed' if is_typed else 'voice'
    try:
        reply = _call_gemini(
            _voice_system_prompt(lang, str(data.get('page_context') or '')[:1000], user_text=focus_text, typed=is_typed),
            conv_messages,
            max_tokens=CHAT_MAX_TOKENS_TYPED if is_typed else CHAT_MAX_TOKENS_VOICE,
            source=call_source,
        )
    except AIDisabled:
        return jsonify({'status': 'ai_off', 'message': AI_OFF_TEXT['en' if lang == 'en' else 'th']})
    except local_llm.LocalLLMError as e:
        return jsonify({'status': 'error', 'message': _local_error_text(e.code, lang)})
    except Exception as e:
        err = str(e)
        if 'NO_API_KEY' in err:
            msg = ('ยังไม่ได้ตั้งค่าคีย์ API ของ Gemini ผู้ดูแลระบบระดับสูงสุดตั้งได้ที่หน้าตั้งค่า', 'The Gemini API key is not set. A superadmin can set it in Settings.')
        elif '429' in err:
            msg = ('AI ถูกใช้งานเยอะเกินไป กรุณารอสักครู่', 'The AI is busy (quota). Please wait a moment.')
        elif 'HTTP_404' in err:
            msg = ('ไม่พบโมเดล %s (Google อาจยกเลิกแล้ว) ผู้ดูแลระบบระดับสูงสุดเลือกโมเดลใหม่ได้ที่หน้าตั้งค่า' % gemini_model(),
                   'The model %s was not found (Google may have retired it). A superadmin can choose another in Settings.' % gemini_model())
        elif '401' in err or '403' in err or '400' in err or 'leaked' in err.lower():
            msg = ('คีย์ API ของ Gemini ไม่ถูกต้องหรือไม่มีสิทธิ์', 'The Gemini API key is not valid or not allowed.')
        else:
            msg = ('เรียก AI ไม่สำเร็จ ลองใหม่อีกครั้ง', 'The AI call failed. Please try again.')
        return jsonify({'status': 'error', 'message': msg[1 if lang == 'en' else 0]})
    answer = _strip_scan_marker(reply)
    if _ai_was_cut():
        answer = (answer + '\n\n' + _cut_notice('en' if lang == 'en' else 'th')).strip()
    return jsonify({'status': 'ok', 'reply': answer or ('ไม่มีคำตอบ' if lang != 'en' else 'No answer.'), 'source': 'ai',
                    'engine': ai_engine(), 'cut': _ai_was_cut()})


@app.route('/api/voice/scan', methods=['POST'])
@admin_required
def api_voice_scan():
    """Starts the scan the user confirmed. Body: {token, lang}. Answers at once; the scan runs in the background (see the Tasks page)."""
    data = request.get_json(silent=True) or {}
    lang = _voice_lang(data)
    say = lambda th, en: en if lang == 'en' else th
    try:
        claim = _voice_signer.loads(str(data.get('token') or ''), max_age=VOICE_CONFIRM_SECONDS)
    except SignatureExpired:
        return jsonify({'status': 'expired', 'message': say('หมดเวลายืนยัน กรุณาสั่งใหม่อีกครั้ง', 'The confirmation expired. Please give the command again.')}), 400
    except BadSignature:
        return jsonify({'status': 'invalid', 'message': say('การยืนยันไม่ถูกต้อง กรุณาสั่งใหม่', 'The confirmation is not valid. Please give the command again.')}), 400
    if not isinstance(claim, dict) or claim.get('u') != current_user.id:
        return jsonify({'status': 'invalid', 'message': say('การยืนยันนี้ไม่ใช่ของบัญชีนี้', 'This confirmation belongs to another account.')}), 403
    target, scan_type = str(claim.get('t') or ''), str(claim.get('k') or '')
    # the token is ours, but check again anyway: the same rules as when it was made
    if scan_type not in VALID_SCAN_TYPES or not voice_commands.validate_target(target)[0]:
        return jsonify({'status': 'invalid', 'message': say('เป้าหมายหรือประเภทสแกนไม่ถูกต้อง', 'The target or scan type is not valid.')}), 400

    with _voice_used_lock:
        now = time.time()
        for n, t in list(_voice_used.items()):
            if now - t > VOICE_CONFIRM_SECONDS + 60:
                del _voice_used[n]
        nonce = str(claim.get('n') or '')
        if not nonce or nonce in _voice_used:
            return jsonify({'status': 'already_started', 'message': say('คำสั่งนี้เริ่มสแกนไปแล้ว', 'This command has already started its scan.')}), 409
        _voice_used[nonce] = now

    default_name = say('สั่งจากแชท AI', 'AI chat command') if claim.get('src') == 'chat' else say('สั่งด้วยเสียง', 'Voice command')
    scan_name = str(claim.get('sn') or '').strip()[:100] or default_name
    new_job = ScanJob(
        target=target, scan_type=scan_type, scan_name=scan_name,
        status='Queued', triggered_by='chatbot', owner_id=current_user.id,
        multicast=False if scan_type == 'discovery' else None)
    db.session.add(new_job)
    if not SavedTarget.query.filter_by(target=target).first():
        db.session.add(SavedTarget(target=target))
    db.session.commit()
    if not enqueue_scan(new_job):
        return jsonify({'status': 'error', 'message': say('เริ่มสแกนไม่ได้', 'Could not start the scan.')}), 500
    label = scan_labels()[scan_type]
    seq = _job_seq(new_job)      # the number every page shows as "Job #N" (the job's place in this admin's list); job_id stays the database id the stop button needs
    return jsonify({'status': 'started', 'job_id': new_job.id, 'job_seq': seq, 'target': target, 'scan_type': scan_type, 'scan_label': label,
                    'message': say('เริ่มสแกน %s (%s) แล้ว งาน #%d ดูความคืบหน้าได้ที่หน้างานสแกน' % (target, label, seq),
                                   'Started %s on %s (job #%d). Follow it on the Tasks page.' % (label, target, seq))})


@app.route('/api/chat', methods=['POST'])
@admin_required
def api_chat():
    """AI Chatbot — with live app data, page context, and scan command support
    เฉพาะ admin/superadmin เท่านั้น (ผู้ใช้ role 'user' ไม่มีสิทธิ์ใช้งาน)"""
    data = request.get_json()
    if not data or 'messages' not in data:
        return jsonify({'error': 'Invalid request'}), 400

    if not ai_enabled():     # the Settings switch; the typed chat has no local answers yet, so it says so
        return jsonify({'reply': AI_OFF_TEXT['chat'], 'scan_result': None, 'source': 'local'})
    if data.get('async') is True:                     # the popup chat: the answer is written in the background, see start_background_answer
        return start_background_answer(api_chat, {k: v for k, v in data.items() if k != 'async'})

    messages     = _sanitize_chat_messages(data.get('messages', []))
    page_context = data.get('page_context', '')   # ส่งมาจาก JS ทุก request
    focus_text   = ' '.join(m['content'] for m in messages[-6:] if m['role'] == 'user')

    # ดึงข้อมูลจริงของแอพแบบ real-time (ใช้ _build_device_inventory() ชุดเดียวกับ Dashboard/Devices/Vulnerabilities)
    app_context = _build_app_context(user_text=focus_text)

    SYSTEM_PROMPT = f"""คุณคือ CLYLAR Assistant ผู้ช่วย AI สำหรับระบบ CLYLAR Network Scanner
คุณมีสิทธิ์เข้าถึงข้อมูลจริงของระบบที่อัปเดตล่าสุด และรู้ว่าผู้ใช้กำลังดูหน้าไหน

=== ข้อมูลหน้าที่ผู้ใช้กำลังดูอยู่ ===
{page_context if page_context else '(ไม่ทราบหน้าปัจจุบัน)'}

{app_context}

=== ความสามารถพิเศษ: เสนอคำสั่ง Scan (ต้องให้ผู้ใช้กดยืนยันก่อนเสมอ) ===
เมื่อผู้ใช้สั่งให้สแกนอย่างชัดเจน ให้ส่ง JSON พิเศษในบรรทัดแรกเพื่อให้ระบบสร้างการ์ดยืนยัน (ระบบจะยังไม่เริ่มสแกนจนกว่าผู้ใช้จะกดยืนยัน):
##SCAN_CMD##
{{"action":"scan","target":"<IPV4_OR_CIDR_MAX_16>","scan_type":"<TYPE>","scan_name":"<NAME_OPTIONAL>"}}

ประเภท scan ที่รองรับ:
- fast_scan     → Fast Scan (เร็ว แนะนำสำหรับสแกนทั่วไป)
- discovery     → Discovery (ค้นหาอุปกรณ์ในเครือข่าย)
- intense       → Intense Scan (ละเอียด ใช้เวลานาน)
- vuln_scan     → Vulnerability Scan CVE (ตรวจช่องโหว่)

กติกาการเสนอคำสั่งสแกน:
- ใส่ ##SCAN_CMD## เฉพาะเมื่อผู้ใช้สั่งให้สแกนจริงเท่านั้น ห้ามใส่เมื่อผู้ใช้แค่ถามคำถามสมมติหรือขอคำอธิบาย
- รองรับเฉพาะ IPv4 หรือช่วง CIDR ไม่เกิน /16 (เช่น 192.168.1.1 หรือ 192.168.1.0/24)
- ถ้าผู้ใช้ไม่ได้ระบุ scan_type ให้ใช้ fast_scan เป็นค่าเริ่มต้น ถ้าไม่ได้ระบุ target ให้ถามก่อน อย่าเดา
- ข้อความอธิบายหลัง JSON ให้บอกผู้ใช้ว่าเตรียมคำสั่งสแกนไว้ให้ตรวจสอบและกดยืนยันแล้ว (อย่าบอกว่าเริ่มสแกนแล้ว)

=== แนวทางตอบ ===
- ใช้ตัวเลขจากส่วน "สรุปภาพรวมทั้งหมดของระบบ CLYLAR" เป็นหลัก ห้ามนับเอาเองจากรายการที่อาจถูกจำกัดจำนวน
- เมื่อถูกถามเรื่องระบบปฏิบัติการ (OS) หรือชนิดอุปกรณ์ (Device Type) ให้ตอบจากฟิลด์ OS และ type ที่มีในข้อมูลจริง ห้ามเดาจากพอร์ต ถ้าเป็น Unknown ให้บอกตรงๆ ว่ายังตรวจไม่พบ OS
- ตอบเป็นภาษาไทยเป็นหลัก ถ้าผู้ใช้ถามภาษาอังกฤษก็ตอบภาษาอังกฤษได้
- ตอบสั้นกระชับ ชัดเจน สุภาพ น้ำเสียงเป็นกลางแบบผู้ช่วยในระบบ ไม่ใช้ emoji หรือสัญลักษณ์ตกแต่ง
- ถ้าถามเรื่องที่ไม่มีข้อมูลในระบบ ให้บอกตรงๆ ว่าไม่พบข้อมูล"""

    try:
        reply = _call_gemini(SYSTEM_PROMPT, messages, max_tokens=CHAT_MAX_TOKENS_TYPED, source='typed')
        if _answer_cancelled():                           # Stop was pressed while the model wrote: nobody reads this, and a scan it asked for must not start
            return jsonify({'reply': '', 'scan_result': None, 'scan_proposal': None, 'source': 'ai', 'engine': ai_engine(), 'cancelled': True})

        # ตรวจว่า AI เสนอคำสั่งสแกนหรือไม่ — จะไม่รันสแกนเองทันที แต่ตรวจเป้าหมายและสร้างการ์ดยืนยันแบบเดียวกับคำสั่งเสียง
        scan_result = None
        scan_proposal = None
        clean_reply = reply
        if '##SCAN_CMD##' in reply:
            try:
                parts = reply.split('##SCAN_CMD##', 1)
                json_and_rest = parts[1].strip()
                first_line_end = json_and_rest.find('\n')
                json_str = (json_and_rest if first_line_end < 0 else json_and_rest[:first_line_end]).strip()
                cmd = json.loads(json_str)

                if cmd.get('action') == 'scan' and current_user.is_any_admin:
                    target    = str(cmd.get('target') or '').strip()
                    scan_type = str(cmd.get('scan_type') or 'fast_scan').strip()
                    scan_name = str(cmd.get('scan_name') or '').strip() or None
                    scan_proposal = _make_chat_scan_proposal(target, scan_type, scan_name=scan_name, lang=ui_lang_now())

                # ตัด ##SCAN_CMD## + JSON ออกจาก reply ที่แสดง
                rest_text = json_and_rest[first_line_end:].strip() if first_line_end >= 0 else ''
                pre_text  = parts[0].strip()
                clean_reply = (pre_text + '\n' + rest_text).strip()
            except Exception:
                clean_reply = _strip_scan_marker(reply)

        if _ai_was_cut():
            clean_reply = (clean_reply + '\n\n' + _cut_notice()).strip()
        return jsonify({
            'reply': clean_reply, 'scan_result': scan_result, 'scan_proposal': scan_proposal,
            'source': 'ai', 'engine': ai_engine(), 'cut': _ai_was_cut(),
        })

    except local_llm.LocalLLMError as e:
        return jsonify({'kind': 'warn', 'reply': _local_error_text(e.code)}), 200
    except ValueError as e:
        if 'NO_API_KEY' in str(e):
            return jsonify({'kind': 'warn', 'reply': 'ยังไม่ได้ตั้งค่าคีย์ API ของ Gemini ผู้ดูแลระบบระดับสูงสุดตั้งได้ที่หน้าตั้งค่า'}), 200
    except Exception as e:
        err = str(e)
        if 'QUOTA_429' in err:
            return jsonify({'kind': 'warn', 'reply': 'Gemini API เต็ม quota ชั่วคราว กรุณารอสักครู่'}), 200
        if '429' in err:
            return jsonify({'kind': 'warn', 'reply': 'AI ถูกใช้งานเยอะเกินไป กรุณารอสักครู่'}), 200
        if 'HTTP_404' in err:
            return jsonify({'kind': 'warn', 'reply': 'ไม่พบโมเดล %s (Google อาจยกเลิกแล้ว) ผู้ดูแลระบบระดับสูงสุดเลือกโมเดลใหม่ได้ที่หน้าตั้งค่า' % gemini_model()}), 200
        if '400' in err:
            return jsonify({'kind': 'warn', 'reply': 'คีย์ API ของ Gemini ไม่ถูกต้องหรือโมเดลไม่รองรับ'}), 200
        if 'leaked' in err.lower():
            return jsonify({'kind': 'warn', 'reply': 'คีย์นี้ถูก Google ระงับเนื่องจากเคยเปิดเผยต่อสาธารณะ กรุณาสร้างคีย์ใหม่ที่ https://aistudio.google.com/app/apikey แล้วตั้งค่าที่หน้าตั้งค่า'}), 200
        if '403' in err:
            return jsonify({'kind': 'warn', 'reply': 'คีย์ API ไม่มีสิทธิ์เข้าถึง Gemini'}), 200
        if '401' in err:
            return jsonify({'kind': 'warn', 'reply': 'คีย์ API ของ Gemini ไม่ถูกต้องหรือหมดอายุ กรุณาตรวจสอบที่หน้าตั้งค่า หรือในไฟล์ .env (แก้แล้วใช้ได้ทันที ไม่ต้องรีสตาร์ตระบบ)'}), 200
        return jsonify({'kind': 'warn', 'reply': f'เกิดข้อผิดพลาด: {_redact_key(err)}'}), 200
    
    

# ─────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────

def _error_page(code):
    """One page for 403, 404 and 500: it does not extend base.html, so it works for a visitor who is not signed in and when the page itself failed. The
    theme and the language are the visitor's own (cookie or saved choice). Paths under /api/ answer with JSON instead."""
    if request.path.startswith('/api/'):
        return jsonify({'error': {403: 'forbidden', 404: 'not_found', 500: 'server_error'}[code]}), code
    return render_template('error.html', code=code), code


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'csrf_failed', 'message': tr('err.400.text')}), 400
    return render_template('error.html', code=400), 400


@app.errorhandler(403)
def forbidden(e):
    return _error_page(403)


@app.errorhandler(404)
def not_found(e):
    return _error_page(404)


@app.errorhandler(500)
def server_error(e):
    return _error_page(500)


if __name__ == '__main__':
    # reloader_type='stat': the auto-reloader decides a file changed by its modification time. The default on a machine that has `watchdog` installed
    # (streamlit pulls it in) is the watchdog reloader, which on Windows also reports a file being merely READ (its last-access time) as a change and
    # restarts the server. The first PDF export imports xhtml2pdf and dozens of stdlib files lazily, so it restarted the server in the middle of the
    # request: "The connection was reset". A real edit still reloads.
    # The stat reloader walks every folder on sys.path ONCE A SECOND and stats every .py file it finds. Werkzeug skips only the system Python's own folders,
    # so packages installed with `pip install --user` (about 29,000 files, 11,000 of them .py, on this machine) were re-walked every second: one pass took 3 to
    # 4 seconds, the reloader thread never slept and kept a core busy, and the pages answered slower (measured 2026-11-13). Telling it to skip the site-packages
    # folders brings a pass down to about 20 ms; the project's own files are still watched, so an edit still reloads.
    try:
        import site
        from werkzeug import _reloader
        _reloader._stat_ignore_scan = tuple(_reloader._stat_ignore_scan) + tuple(os.path.abspath(p) for p in [site.getusersitepackages()] + site.getsitepackages())
    except Exception:            # a Werkzeug that changed this internal: the reloader then works as before, only slower
        pass
    app.run(debug=True, reloader_type='stat')
