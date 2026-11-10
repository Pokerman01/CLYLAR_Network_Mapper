from dotenv import load_dotenv
load_dotenv()  # โหลด .env อัตโนมัติ (GOOGLE_API_KEY, GEMINI_MODEL)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.orm import defer
from models import db, User, ScanJob, ScheduledScan, SavedTarget, HistoryQuery, AppSetting, GeminiCall
from scanner import (port_reason, port_reason_label, PORT_REASON_TH, run_network_scan, run_vuln_scan, get_system_default_gateway,
                     get_scan_capabilities, get_local_adapters, mac_note, guess_device_type,
                     clamp_scan_knobs, clamp_skip_ping, clamp_all_ports, clamp_no_dns, clamp_probes, clamp_gentle, clamp_udp, port_proto, port_key, port_text, udp_unavailable_th, udp_limit_error, UDP_MAX_ADDRESSES, options_conflict_th, gentle_limit_error, GENTLE_MAX_ADDRESSES, ports_limit_error, ALL_PORTS_MAX_ADDRESSES, ARP_ONLY_MAX, describe_scan_settings, discovery_service_text, virtual_machine_platform, is_local_ip,
                     effective_severity, severity_adjusted, severity_note, cvss_number, os_match_accuracy,
                     target_size, is_valid_target, PN_MAX_ADDRESSES, PROGRESS_EVERY)
from cwe_data import cwe_info
import voice_commands
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

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'


def mac_note_html(ip, mac='', vendor='', dash=True):
    """Badge explaining a missing/unresolvable MAC; '—' (dash=True) or nothing when there is nothing to explain."""
    note = mac_note(ip, mac, vendor)
    if note:
        return Markup('<span class="badge" style="background:#f1f5f9;color:#475569;border:1px solid #e2e8f0;'
                      'font-weight:500;font-size:.7rem;" title="{}">{}</span>').format(note['tip'], note['label'])
    return Markup('<span class="text-muted">—</span>') if dash else Markup('')


app.jinja_env.globals['mac_note_html'] = mac_note_html
app.jinja_env.globals['cwe_info'] = cwe_info   # official CWE id / name / link for a stored CVE record
app.jinja_env.globals['voice_help_examples'] = voice_commands.HELP_EXAMPLES      # the chat's help panel (base.html)
# the severity to show for a stored CVE record: NVD's label, with a CVSS v2-only 9.0+ shown as CRITICAL (see scanner.effective_severity)
app.jinja_env.globals['effective_severity'] = effective_severity
app.jinja_env.globals['port_reason_label'] = port_reason_label     # Thai words for nmap's reason of a port state (None when not recorded)
app.jinja_env.globals['PORT_REASON_TH'] = PORT_REASON_TH
app.jinja_env.globals['severity_adjusted'] = severity_adjusted
app.jinja_env.globals['severity_note'] = severity_note
# The dashboard's "good" green: the donut's "No Findings" slice and the Task Status "Complete" bar. One value for both, also
# handed to dashboard.html, where inkOf() swaps it for a deeper shade whenever it is used as a text colour.
GOOD_GREEN = '#1cb454'
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

@app.template_filter('scan_label')
def scan_label_filter(value):
    return SCAN_TYPE_LABELS.get(value, value)

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

# --- APScheduler ---
scheduler = BackgroundScheduler(timezone="Asia/Bangkok")
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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

THAI_MONTHS = ['', 'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน', 'พฤษภาคม', 'มิถุนายน',
               'กรกฎาคม', 'สิงหาคม', 'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม']


@app.context_processor
def inject_layout_context():
    now = now_th()
    notif_count = 0
    if current_user.is_authenticated:
        try:
            notif_count = visible_scans_query().filter(ScanJob.status.in_(ACTIVE_STATUSES)).count()      # waiting or running
        except Exception:
            notif_count = 0
    chat_button_hidden = False       # the floating chat button is only drawn for admins; each of them may hide it (Settings page)
    voice_autorun = False            # "scan at once": this admin chose to skip the confirmation card for a safe target (see voice_autorun_allowed)
    chat_ai_on = True                # the chat's status line: "AI ปิดอยู่" when the Settings switch has the AI off
    if current_user.is_authenticated and current_user.is_any_admin:
        try:
            chat_button_hidden = get_setting(chat_button_key(current_user.id), '0') == '1'
            chat_ai_on = ai_enabled()
            voice_autorun = voice_autorun_on(current_user.id)
        except Exception:
            chat_button_hidden = False
    return {
        'now_year': now.year,
        'thai_date_today': f"{now.day} {THAI_MONTHS[now.month]} {now.year + 543}",
        'notification_count': notif_count,
        'scan_warnings': get_scan_capabilities()['warnings'],
        # the id of the scan a form just ran before redirecting here (set by the routes below), shown once as the "scan finished" notice; it does not
        # depend on the browser's storage or on the page having seen the scan run
        'scan_just_finished': session.pop('scan_just_finished', None),
        'chat_button_hidden': chat_button_hidden,
        'chat_ai_on': chat_ai_on,
        'voice_autorun': voice_autorun,
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
        dom = schedule.day_of_month or 1
        try:
            candidate = base.replace(day=dom)
        except ValueError:
            import calendar
            last_day = calendar.monthrange(base.year, base.month)[1]
            candidate = base.replace(day=last_day)
        if candidate <= now:
            if candidate.month == 12:
                candidate = candidate.replace(year=candidate.year + 1, month=1)
            else:
                candidate = candidate.replace(month=candidate.month + 1)
        return candidate
    return base


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


def scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp=False):
    """The Thai sentence for a form route that refuses a new scan because of how its options combine or how big the target is, else None: probes with -Pn, Gentle
    with all ports, all ports on more than 64 addresses, Gentle on more than 1,024, the UDP option without Administrator / Npcap or on more than 64 addresses. The scanner repeats these checks as a backstop, but that only fails the job
    after it was queued; the person should be told at once."""
    conflict = options_conflict_th(bool(skip_ping), bool(all_ports), bool(host_probes), bool(gentle))
    if conflict:
        return conflict
    refusal = all_ports_refusal(target, all_ports)
    if refusal:
        return refusal
    if gentle and gentle_limit_error(target):
        return ('สแกนแบบนุ่มนวลรองรับไม่เกิน %s ที่อยู่ (ช่วง /22) แต่เป้าหมายนี้มี %s ที่อยู่ กรุณาลดช่วงเป้าหมายหรือยกเลิกตัวเลือกนี้'
                % (format(GENTLE_MAX_ADDRESSES, ','), format(target_size(target), ',')))
    if udp:
        if udp_unavailable_th():
            return udp_unavailable_th()
        if udp_limit_error(target):
            return ('การสแกน UDP รองรับไม่เกิน %d ที่อยู่ (ช่วง /26) แต่เป้าหมายนี้มี %s ที่อยู่ กรุณาลดช่วงเป้าหมายหรือยกเลิกตัวเลือกนี้'
                    % (UDP_MAX_ADDRESSES, format(target_size(target), ',')))
    return None


def all_ports_refusal(target, all_ports):
    """The Thai sentence for a form route that refuses a new scan of too many addresses with "all ports" on, else None. The scanner has the same
    check as a backstop, but that one only fails the job after it was queued; the person should be told at once."""
    if all_ports and ports_limit_error(target):
        n = target_size(target)
        return ('สแกนทุกพอร์ต (1-65535) รองรับไม่เกิน %d ที่อยู่ (ช่วง /26) แต่เป้าหมายนี้มี %s ที่อยู่ กรุณาลดช่วงเป้าหมายหรือยกเลิกตัวเลือกนี้'
                % (ALL_PORTS_MAX_ADDRESSES, format(n, ',')))
    return None


def scan_with_info(target, scan_type, custom_args=None, timing=None, version_intensity=None, multicast=False, skip_ping=False, all_ports=False, no_dns=False, host_probes=False, gentle=False, udp=False):
    """Runs the scanner and returns (result text, the run's scan_info as JSON text or None). One place, so every way of starting a scan
    records the same things about the run."""
    info = {}
    if scan_type == 'vuln_scan':
        results = run_vuln_scan(target, timing=timing, version_intensity=version_intensity, skip_ping=bool(skip_ping), info=info, all_ports=bool(all_ports), no_dns=bool(no_dns),
                               host_probes=bool(host_probes), gentle=bool(gentle), udp=bool(udp))
    else:
        results = run_network_scan(target, scan_type, custom_args=custom_args, timing=timing, version_intensity=version_intensity,
                                   multicast=multicast, skip_ping=bool(skip_ping), info=info, all_ports=bool(all_ports), no_dns=bool(no_dns),
                               host_probes=bool(host_probes), gentle=bool(gentle), udp=bool(udp))
    try:
        return results, (json.dumps(info) if info else None)
    except (TypeError, ValueError):
        return results, None


ACTIVE_STATUSES = ('Queued', 'Running')      # a scan that is waiting for a worker or being run: not finished, cannot be deleted, blocks a second scan of its target


def _job_seq(job):
    """The number the app shows as "Job #N" for a job that was just created: its place in its owner's list by time (see _owner_seq_map)."""
    return ScanJob.query.filter(
        ScanJob.owner_id == job.owner_id,
        db.or_(ScanJob.timestamp < job.timestamp, db.and_(ScanJob.timestamp == job.timestamp, ScanJob.id <= job.id))).count()


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
        args = (job.target, job.scan_type, job.custom_args, job.timing, job.version_intensity, bool(job.multicast), bool(job.skip_ping), bool(job.all_ports), bool(job.no_dns), bool(job.host_probes), bool(job.gentle), bool(job.udp))
        info_text = None
        try:
            with scan_runner.controlled(job_id, job.scan_type, bool(job.all_ports), bool(job.gentle), bool(job.udp)):
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
    n = (ScanJob.query.filter(ScanJob.status.in_(ACTIVE_STATUSES))
         .update({'status': 'Failed', 'finished_at': now_th(),
                  'result_data': json.dumps([{'error': 'Interrupted: the application restarted while this scan was waiting or running.'}])},
                 synchronize_session=False))
    db.session.commit()
    return n


def _scan_started_redirect(job, endpoint='tasks_page', **values):
    """The answer of a form that starts a scan: queue the job and go to the Tasks page at once with a plain notice (the scan runs in the
    background). The flag makes the page announce the job when it finishes even if that happens before the page's first poll."""
    if not enqueue_scan(job):
        flash('เริ่มสแกนไม่ได้ กรุณาลองใหม่อีกครั้ง', 'danger')
        return redirect(url_for(endpoint, **values))
    session['scan_just_finished'] = job.id
    flash(f'รับคำสั่งสแกน {job.target} แล้ว (งาน #{_job_seq(job)}) ระบบจะแจ้งเมื่อสแกนเสร็จ', 'success')
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
    for key in ('checked', 'up', 'down', 'no_evidence', 'arp_only_total', 'timed_out', 'ports_scanned', 'udp_hosts', 'udp_timed_out', 'udp_not_scanned'):
        if isinstance(raw.get(key), int) and not isinstance(raw.get(key), bool) and raw[key] >= 0:
            out[key] = raw[key]
    if isinstance(raw.get('elapsed'), (int, float)) and not isinstance(raw.get('elapsed'), bool) and raw['elapsed'] >= 0:
        out['elapsed'] = round(float(raw['elapsed']), 1)
    for key in ('admin', 'npcap', 'skip_ping', 'no_dns', 'host_probes', 'gentle', 'udp', 'udp_failed'):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    if isinstance(raw.get('udp_error'), str) and raw['udp_error']:
        out['udp_error'] = raw['udp_error'][:200]
    rows = raw.get('arp_only')
    if isinstance(rows, list):
        out['arp_only'] = [{'ip': str(r.get('ip') or '')[:45], 'mac': str(r.get('mac') or '')[:17], 'vendor': str(r.get('vendor') or '')[:60]}
                           for r in rows[:ARP_ONLY_MAX] if isinstance(r, dict) and r.get('ip')]
    return out


def describe_run(job):
    """The scan's own report of its run in plain Thai, for the Tasks panel and the scan pages (one wording for both):
    {'summary', 'nmap', 'elapsed', 'notes': [{'kind': 'warn' | 'info', 'text'}], 'arp_only': [...], 'arp_only_total'}.
    It says only what was recorded: a job from before scan_info existed gives empty parts, never a guess."""
    run = scan_run_info(job)
    skip = bool(run.get('skip_ping') or job.skip_ping)
    n = lambda v: format(v, ',')
    parts = []
    if 'checked' in run:
        parts.append('ตรวจ %s IP' % n(run['checked']) + (' (ข้ามการ ping)' if skip else ''))
        if skip:
            if 'up' in run:
                parts.append('พบหลักฐานว่ามีเครื่อง %s' % n(run['up']))
            if 'no_evidence' in run:
                parts.append('ไม่พบหลักฐาน %s' % n(run['no_evidence']))
        else:
            if 'up' in run:
                parts.append('ตอบกลับ %s' % n(run['up']))
            if 'down' in run:
                parts.append('ไม่ตอบ %s' % n(run['down']))
    notes = []
    if run.get('admin') is False:
        notes.append({'kind': 'warn', 'text': 'สแกนครั้งนี้รันโดยไม่มีสิทธิ์ Administrator/root — อุปกรณ์ที่บล็อก ping อาจหายไป และอ่าน MAC / ระบบปฏิบัติการได้ไม่ครบ'})
    if run.get('npcap') is False:
        notes.append({'kind': 'warn', 'text': 'ไม่พบ Npcap ตอนสแกน — nmap ใช้ ping แทน ARP จึงอาจพลาดอุปกรณ์ที่บล็อก ping'})
    if skip and run.get('no_evidence'):
        notes.append({'kind': 'info', 'text': 'ที่อยู่ %s ที่ไม่มีอะไรตอบกลับไม่ถูกแสดงเป็นอุปกรณ์ — เครื่องที่ปิดกั้นทุกพอร์ตกับที่อยู่ว่างแยกกันไม่ได้' % n(run['no_evidence'])})
    elif (not skip and job.scan_type in ('fast_scan', 'intense', 'vuln_scan', 'custom') and run.get('down')
          and run.get('checked', 10 ** 9) <= 8):
        notes.append({'kind': 'info', 'text': 'มี %s IP ที่ไม่ตอบ ซึ่งอาจเป็นอุปกรณ์ที่บล็อก ping — สแกนซ้ำโดยเปิด "ข้ามการ ping (-Pn)" เพื่อลองพอร์ตโดยตรง' % n(run['down'])})
    if run.get('host_probes') is True:
        notes.append({'kind': 'info', 'text': 'ตรวจหาอุปกรณ์ที่ไม่ตอบ ping ด้วยการลองเชื่อมต่อพอร์ตที่พบบ่อยและ ICMP เพิ่มเติม ในวงเดียวกันระบบใช้ ARP อยู่แล้ว ผลจึงต่างจากเดิมเฉพาะอุปกรณ์ที่อยู่หลังเราเตอร์'})
    if run.get('gentle') is True:
        notes.append({'kind': 'info', 'text': 'สแกนแบบนุ่มนวล: ส่งแพ็กเก็ตช้าและจำกัดอัตรา ลองซ้ำไม่เกิน 2 ครั้ง จึงใช้เวลานานกว่าปกติมาก และพอร์ตที่แพ็กเก็ตสูญหายอาจแสดงเป็น filtered'})
    if run.get('udp') is True:
        notes.append({'kind': 'info', 'text': 'รอบที่ 2 สแกน UDP 12 พอร์ตที่พบบ่อย (53, 67, 69, 123, 137, 161, 500, 520, 623, 1434, 1900, 5060) กับอุปกรณ์ที่รอบแรกพบว่าออนไลน์ '
                                             'พอร์ต UDP ที่ไม่ตอบกลับจะแสดงเป็น open|filtered ซึ่งหมายถึงไม่ทราบว่าเปิดหรือถูกกรอง ไม่ใช่พอร์ตที่เปิด และระบบไม่ค้นหา CVE ให้พอร์ตนั้น'})
    if run.get('udp_failed') is True:
        notes.append({'kind': 'warn', 'text': 'รอบสแกน UDP ทำงานไม่สำเร็จ จึงไม่มีผลพอร์ต UDP ของสแกนนี้ ผลพอร์ต TCP ไม่ได้รับผลกระทบ' + (' (สาเหตุ: %s)' % run['udp_error'] if run.get('udp_error') else '')})
    if run.get('udp_not_scanned'):
        notes.append({'kind': 'warn', 'text': '%s เครื่องไม่ได้สแกน UDP (เป็นที่อยู่ที่ไม่ใช่ IPv4 หรือ nmap ไม่รายงานผล) จึงไม่ทราบพอร์ต UDP ของเครื่องนั้น' % format(run['udp_not_scanned'], ',')})
    if run.get('udp_timed_out'):
        notes.append({'kind': 'warn', 'text': '%s เครื่องใช้เวลาสแกน UDP เกิน 10 นาที nmap จึงข้ามเครื่องนั้น และไม่ทราบพอร์ต UDP ของเครื่องนั้น' % format(run['udp_timed_out'], ',')})
    if run.get('no_dns') is True:
        notes.append({'kind': 'info', 'text': 'ไม่ได้ค้นหาชื่ออุปกรณ์ผ่าน DNS (-n) อุปกรณ์ที่ไม่มีชื่อแสดงจึงไม่ได้แปลว่าไม่มีชื่อ (ชื่อ NetBIOS ที่ถามจากตัวอุปกรณ์ยังอ่านได้)'})
    if run.get('ports_scanned') == 65535:
        notes.append({'kind': 'info', 'text': 'สแกนพอร์ต TCP ทั้งหมด 1-65535 ของแต่ละเครื่อง รายการแสดงเฉพาะพอร์ตที่ nmap แยกรายงาน ส่วนที่เหลือเป็นสถานะเดียวกันที่ nmap สรุปรวมไว้ (ปิดหรือถูกกรอง)'})
    if run.get('timed_out'):
        notes.append({'kind': 'warn', 'text': '%s เครื่องใช้เวลาเกิน 45 นาที nmap จึงข้ามเครื่องนั้น และไม่ทราบพอร์ตของเครื่องนั้น (ไม่ได้แปลว่าไม่มีพอร์ตเปิด)' % n(run['timed_out'])})
    if run.get('arp_only_total'):
        notes.append({'kind': 'info', 'text': 'ตาราง ARP ของเครื่องนี้รู้จักอีก %s อุปกรณ์ในช่วงที่สแกน ซึ่งสแกนไม่ได้รายงานว่าออนไลน์ (เคยติดต่อกับเครื่องนี้ไม่นานมานี้ ข้อมูลอาจเก่า)' % n(run['arp_only_total'])})
    return {'summary': ' · '.join(parts), 'nmap': run.get('nmap'), 'elapsed': run.get('elapsed'), 'notes': notes,
            'arp_only': run.get('arp_only', []), 'arp_only_total': run.get('arp_only_total', 0)}


def _stored_hosts(job):
    """The host list stored for a job, or None when it has none to use (still running, failed, an error result, unreadable text)."""
    try:
        data = json.loads(job.result_data) if job.result_data else None
    except ValueError:
        return None
    if not isinstance(data, list) or (data and isinstance(data[0], dict) and data[0].get('error')):
        return None
    return [h for h in data if isinstance(h, dict)]


def previous_comparable_job(job):
    """The newest EARLIER completed scan the user may see that can be compared with `job`: same target, same scan type, same -Pn choice and, for a
    Custom scan, the same arguments (scan_diff.comparable_key). None when there is none (the first scan of its kind)."""
    if job.timestamp is None or job.status != 'Completed' or job.scan_type in (None, 'xml_upload'):
        return None
    key = scan_diff.comparable_key(job.scan_type, job.target, job.skip_ping, job.custom_args, job.all_ports, job.host_probes, job.gentle, job.udp)
    q = (visible_scans_query()
         .filter(ScanJob.id != job.id, ScanJob.status == 'Completed', ScanJob.scan_type == job.scan_type, ScanJob.target == job.target,
                 ScanJob.result_data.isnot(None), ScanJob.timestamp <= job.timestamp)
         .options(defer(ScanJob.result_data))          # the candidates' (large) results are read only for the one that is picked
         .order_by(ScanJob.timestamp.desc(), ScanJob.id.desc()))
    for cand in q.limit(60):
        if (cand.timestamp, cand.id) >= (job.timestamp, job.id):
            continue
        if scan_diff.comparable_key(cand.scan_type, cand.target, cand.skip_ping, cand.custom_args, cand.all_ports, cand.host_probes, cand.gentle, cand.udp) == key and _stored_hosts(cand) is not None:
            return cand
    return None


def scan_changes(job):
    """What changed between `job` and the scan before it of the same kind: {'prev': {id, seq, when}, 'job': {id, seq}, 'diff': scan_diff result},
    or None when there is nothing to compare with."""
    prev = previous_comparable_job(job)
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


def execute_scheduled_scan(schedule_id):
    with app.app_context():
        schedule = ScheduledScan.query.get(schedule_id)
        if not schedule or not schedule.is_active:
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
        trigger = CronTrigger(day=schedule.day_of_month,
                              hour=schedule.cron_hour, minute=schedule.cron_minute)
    else:
        return

    scheduler.add_job(func=execute_scheduled_scan, trigger=trigger,
                      args=[schedule.id], id=job_id, replace_existing=True)


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

        # Migration: user
        cols3 = [r[1] for r in cur.execute("PRAGMA table_info(user)")]
        if 'created_by' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_by INTEGER REFERENCES user(id)")
        if 'created_at' not in cols3:
            cur.execute("ALTER TABLE user ADD COLUMN created_at DATETIME")

        con.commit()
        con.close()

    # สร้าง superadmin ถ้ายังไม่มี
    if not User.query.filter_by(role='superadmin').first():
        hashed_pw = generate_password_hash('admin123')
        superadmin = User(username='admin', password_hash=hashed_pw, role='superadmin')
        db.session.add(superadmin)
        db.session.commit()

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ─────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────

def _open_port_and_cve_counts(jobs):
    """(distinct open port numbers, distinct CVE ids) over the given scan jobs: the two numbers on the dashboard's Open Ports and
    CVE Found cards. Only ports in state `open` count, the same rule as the loop in dashboard()."""
    ports, cve_ids = set(), set()
    for job in jobs:
        try:
            job_data = json.loads(job.result_data) if job.result_data else []
        except Exception:
            continue
        for d in job_data:
            for p in (d.get('ports') or []) if isinstance(d, dict) else []:
                if str(p.get('state', '')).lower() != 'open':
                    continue
                if port_key(p):
                    ports.add(port_key(p))
                for cve in (p.get('cves') or []):
                    cve_id = cve if isinstance(cve, str) else (cve.get('cve_id', '') if isinstance(cve, dict) else '')
                    if cve_id:
                        cve_ids.add(cve_id)
    return len(ports), len(cve_ids)


def _kpi_trend(now, before):
    """The footer trend of a dashboard card: how `now` moved against `before` (the same number without the newest scan).
    None when there is nothing to compare with (before is 0); else {'dir': 'up' | 'down' | 'flat', 'pct': whole percent,
    at least 1 for any change}. These are totals over all history, so in practice they only go up or stay flat."""
    if not before:
        return None
    if now == before:
        return {'dir': 'flat', 'pct': 0}
    return {'dir': 'up' if now > before else 'down', 'pct': max(1, round(abs(now - before) / before * 100))}


@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        if not current_user.is_any_admin:
            abort(403)
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
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
        if gentle:
            timing = None      # Gentle sets the speed itself
        refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp)
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
            all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp,
        )
        db.session.add(new_job)
        if target and not SavedTarget.query.filter_by(target=target).first():
            db.session.add(SavedTarget(target=target))
        db.session.commit()
        return _scan_started_redirect(new_job)

    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    latest_scan = history[0] if history else None
    scan_data = json.loads(latest_scan.result_data) if latest_scan and latest_scan.result_data else []

    from collections import Counter
    # ระดับความรุนแรงของ CVE เรียงจากน้อยไปมาก ใช้หา "worst severity" ต่ออุปกรณ์
    SEVERITY_RANK = {'LOW': 1, 'UNKNOWN': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

    all_device_map = {}
    device_vuln_scanned_ips = set()   # IP ที่เคยผ่าน vuln_scan อย่างน้อย 1 ครั้ง
    device_worst_severity = {}        # ip -> severity (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN) ที่รุนแรงที่สุดที่เคยพบ
    device_worst_cvss = {}            # ip -> cvss_score ของ CVE ที่รุนแรงที่สุด (ถ้ามี)
    device_worst_key = {}             # ip -> (severity rank, CVSS score) of that CVE: what a new candidate has to beat
    device_last_scan_id = {}          # ip -> job.id ของ scan ล่าสุดที่พบอุปกรณ์นี้ (history เรียง desc แล้ว)
    device_worst_scan_id = {}         # ip -> job.id ของ scan ที่พบ CVE ตัวที่แสดงเป็น "Worst CVE"
    device_os = {}                    # ip -> the newest scan's real OS guess (Unknown / up / down are not an OS), for the Top OS card
    device_os_acc = {}                # ip -> nmap's confidence in THAT guess (from the same scan record; absent when the scan did not keep it)
    device_vuln_scan_id = {}          # ip -> job.id ของ vuln_scan ล่าสุดที่พบอุปกรณ์นี้
    port_device_scan = {}             # (port label, ip) -> job.id of the newest scan in which that device had that port open
    port_cve_ids = {}                 # port label -> the CVE ids found on that port (open ports only), for the Open Ports pop-up
    port_device_cves = {}             # (port label, ip) -> the CVE ids found on that device's port: a CVE belongs to one device
    port_cve_scan = {}                # (port label, ip) -> job.id of the newest scan that found a CVE on that device's port
    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            ip = d.get('ip', '')
            if not ip:
                continue
            if ip not in all_device_map:
                all_device_map[ip] = set()
            if ip not in device_last_scan_id:
                device_last_scan_id[ip] = job.id
            if ip not in device_os:       # newest scan first, so the first real guess is the newest one
                guess = str(d.get('os') or '').strip()
                if guess and guess.lower() not in ('unknown', 'up', 'down'):
                    device_os[ip] = guess
                    acc = os_match_accuracy(d.get('os_accuracy'))
                    if acc is not None:
                        device_os_acc[ip] = acc
            if job.scan_type == 'vuln_scan':
                device_vuln_scanned_ips.add(ip)
                device_vuln_scan_id.setdefault(ip, job.id)
            for p in d.get('ports', []):
                if str(p.get('state', '')).lower() != 'open':
                    continue
                label = port_text(p)
                all_device_map[ip].add(label)
                port_device_scan.setdefault((label, ip), job.id)       # history is newest first, so the first one seen is the newest
                for cve in p.get('cves', []):
                    cid = cve.get('cve_id') if isinstance(cve, dict) else (cve if isinstance(cve, str) else '')
                    if cid:
                        port_cve_ids.setdefault(label, set()).add(cid)
                        port_device_cves.setdefault((label, ip), set()).add(cid)
                        port_cve_scan.setdefault((label, ip), job.id)
                    sev = effective_severity(cve)     # '' for a record that is not a dict
                    if sev in SEVERITY_RANK:
                        # worst = highest severity, then highest CVSS score within it (a CRITICAL 10.0 beats a CRITICAL 9.8)
                        score = cvss_number(cve.get('cvss_score'))
                        key = (SEVERITY_RANK[sev], score if score is not None else -1)
                        if ip not in device_worst_key or key > device_worst_key[ip]:
                            device_worst_key[ip] = key
                            device_worst_severity[ip] = sev
                            device_worst_cvss[ip] = cve.get('cvss_score')
                            device_worst_scan_id[ip] = job.id

    total_devices = len(all_device_map)
    # Top OS: every device is counted ONCE, under the family of its newest real OS guess or under 'Unknown', so the rows add up to total_devices and
    # nothing is left out. Known families first, biggest first; 'Other' and then 'Unknown' last.
    os_counts, os_names = Counter(), {}
    for ip in all_device_map:
        guess = device_os.get(ip)
        family = _os_family(guess) if guess else 'Unknown'
        os_counts[family] += 1
        if guess:
            entry = os_names.setdefault(family, {}).setdefault(guess, {'count': 0, 'acc': []})
            entry['count'] += 1
            if ip in device_os_acc:
                entry['acc'].append(device_os_acc[ip])

    def _acc_range(values):
        return {'acc_n': len(values), 'acc_min': min(values) if values else None, 'acc_max': max(values) if values else None}

    # nmap's confidence per family and per OS guess: the lowest and highest of the devices that HAVE one recorded (a mean would hide a weak guess), and
    # how many of them that is. A device whose scan did not keep it (every scan from before this field) is not counted, never filled in.
    os_rows = []
    for fam, n in sorted(os_counts.items(), key=lambda kv: (kv[0] == 'Unknown', kv[0] == 'Other', -kv[1], kv[0])):
        names = sorted(os_names.get(fam, {}).items(), key=lambda kv: (-kv[1]['count'], kv[0]))
        os_rows.append({'family': fam, 'count': n,
                        'names': [dict(name=nm, count=e['count'], **_acc_range(e['acc'])) for nm, e in names[:5]],
                        **_acc_range([a for _nm, e in names for a in e['acc']])})
    os_acc_any = any(r['acc_n'] for r in os_rows)
    online_devices = sum(1 for d in scan_data if d.get('status', '').lower() in ('up', 'online', 'open') or d.get('ports'))
    offline_devices = len(scan_data) - online_devices

    port_device_counter = Counter()
    for ip, ports in all_device_map.items():
        for p in ports:
            port_device_counter[p] += 1
    # the labels come out of sets, whose order changes from one server start to the next, so ports with the same device count are put in port-number
    # order (Counter.most_common left ties in that random order: the list reshuffled itself, and which tied port made the top 6 changed too)
    top_ports = sorted(port_device_counter.items(),
                       key=lambda kv: (-kv[1], int(kv[0].split('/')[0]) if kv[0].split('/')[0].isdigit() else 10 ** 6, kv[0]))[:6]
    # what the Open Ports pop-up needs per top port: the devices that have it open and, for each, how many CVEs were found on that
    # device's port and the scan to link to (the one that found them, else the newest where the port was open). A CVE belongs to a
    # device, so the counts are per device; 'cve_count' on the port is the distinct CVEs over all of its devices.
    top_ports_detail = [{
        'label': label,
        'count': count,
        'cve_count': len(port_cve_ids.get(label, ())),
        'devices': [{'ip': ip,
                     'cve_count': len(port_device_cves.get((label, ip), ())),
                     'scan_id': port_cve_scan.get((label, ip)) or port_device_scan.get((label, ip)) or device_last_scan_id.get(ip)}
                    for ip in sorted((i for i, labels in all_device_map.items() if label in labels), key=_ip_sort_key)],
    } for label, count in top_ports]

    # จัดกลุ่มอุปกรณ์ตาม "ความเสี่ยงจริง" (worst CVE severity) แทนจำนวน port ที่เปิด
    # ป้องกันการเข้าใจผิดว่า port เยอะ = เสี่ยงเยอะ — อุปกรณ์ที่ยังไม่เคยสแกนหาช่องโหว่
    # จะถูกจัดเป็น "unscanned" (เป็นกลาง ไม่ตัดสินว่าเสี่ยงหรือปลอดภัย) แทนที่จะเดาจาก port count
    # หนึ่งอุปกรณ์ = หนึ่งกลุ่ม ตาม CVE ที่แย่ที่สุด; สี 6 กลุ่มนี้ dashboard.html อ่านจากตรงนี้ (device_tier_color) ที่เดียว
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
    device_port_data = []
    for ip, ports in sorted(all_device_map.items()):
        count = len(ports)
        severity = device_worst_severity.get(ip)
        vuln_scanned = ip in device_vuln_scanned_ips
        if severity == 'CRITICAL':
            tier = 'critical'
        elif severity == 'HIGH':
            tier = 'high'
        elif severity == 'MEDIUM':
            tier = 'medium'
        elif severity in ('LOW', 'UNKNOWN'):      # an unlabelled CVE ranks with Low (see SEVERITY_RANK)
            tier = 'low'
        elif vuln_scanned:
            tier = 'clean'
        else:
            tier = 'unscanned'
        # แถวนี้ต้องลิงก์ไปที่ scan ที่ให้ข้อมูลที่แถวพูดถึงจริง ๆ ไม่ใช่แค่ scan ล่าสุดที่เจอ IP นี้:
        # "Worst CVE" -> scan ที่พบ CVE นั้น, "No CVEs" -> vuln scan ล่าสุด, ที่เหลือ -> scan ล่าสุดที่เจอ
        if tier in ('critical', 'high', 'medium', 'low'):
            scan_id = device_worst_scan_id.get(ip)
        elif tier == 'clean':
            scan_id = device_vuln_scan_id.get(ip)
        else:
            scan_id = None
        device_port_data.append({
            'ip': ip, 'count': count, 'color': DEVICE_TIER_COLOR[tier],
            'tier': tier, 'severity': severity, 'vuln_scanned': vuln_scanned,
            'cvss_score': device_worst_cvss.get(ip), 'scan_id': scan_id or device_last_scan_id.get(ip),
        })

    from collections import Counter as _Counter
    target_scan_counts = _Counter(j.target for j in history if j.status == 'Completed')

    all_jobs = visible_scans_query().all()
    schedules_all = visible_schedules_query().all()
    task_completed = sum(1 for j in all_jobs if j.status == 'Completed')
    task_running   = sum(1 for j in all_jobs if j.status in ACTIVE_STATUSES)      # a scan waiting for a worker counts with the running ones
    task_failed    = sum(1 for j in all_jobs if j.status == 'Failed')
    task_wait      = sum(1 for s in schedules_all if s.is_active)
    total_tasks    = len(all_jobs) + task_wait

    all_ports_global = set()
    total_cves_found = 0
    cves_by_id = {}        # one entry per CVE for the CVE detail modal (newest scan first, so its data comes from the newest scan)
    cve_host_keys = {}     # cve_id -> {(ip, port)} already listed under that CVE
    MAX_CVE_HOSTS = 8      # affected devices listed per CVE in the modal; any others are only counted
    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            for p in d.get('ports', []):
                if str(p.get('state', '')).lower() != 'open':
                    continue
                if port_key(p):
                    all_ports_global.add(port_key(p))
                for cve in p.get('cves', []):
                    cve_id = cve if isinstance(cve, str) else cve.get('cve_id', '')
                    if not cve_id:
                        continue
                    info = cve if isinstance(cve, dict) else {}
                    entry = cves_by_id.get(cve_id)
                    if entry is None:
                        total_cves_found += 1
                        entry = cves_by_id[cve_id] = {
                            'id': cve_id,
                            'severity': info.get('severity') or 'unknown',
                            'port': p.get('port', ''),
                            'protocol': port_proto(p),
                            'service': p.get('name', ''),
                            'ip': d.get('ip', ''),
                            'cvss': info.get('cvss_score'),
                            'cwe': (cwe_info(info) or {}).get('label', ''),
                            'description': info.get('description') or '',
                            'kev': info.get('kev') is True,
                            'hosts': [],
                            'more_hosts': 0,
                        }
                        cve_host_keys[cve_id] = set()
                    else:   # fill whatever the newest scan lacked from older ones
                        if entry['cvss'] is None and info.get('cvss_score') is not None:
                            entry['cvss'] = info['cvss_score']
                        entry['cwe'] = entry['cwe'] or (cwe_info(info) or {}).get('label', '')
                        entry['description'] = entry['description'] or info.get('description') or ''
                        entry['kev'] = entry['kev'] or info.get('kev') is True
                    host_key = (d.get('ip', ''), p.get('port', ''), port_proto(p))
                    if d.get('ip') and host_key not in cve_host_keys[cve_id]:
                        cve_host_keys[cve_id].add(host_key)
                        if len(entry['hosts']) < MAX_CVE_HOSTS:
                            # scan_id is the newest scan that found this CVE on this device, for the link to its report
                            entry['hosts'].append({'ip': d['ip'], 'port': p.get('port', ''), 'protocol': port_proto(p),
                                                   'service': p.get('name', ''), 'scan_id': job.id})
                        else:
                            entry['more_hosts'] += 1
    # the pop-up shows the same label as the Vulnerabilities page. Done after the loop, because an entry's CVSS score can be
    # filled in from an older scan than the one its label came from (see scanner.effective_severity)
    for entry in cves_by_id.values():
        record = {'severity': entry['severity'], 'cvss_score': entry['cvss']}
        if severity_adjusted(record):
            entry['severity'] = effective_severity(record)
            entry['severity_note'] = severity_note(entry['cvss'])
    all_cves_list = list(cves_by_id.values())
    total_open_ports = len(all_ports_global)

    # footer trend of the Open Ports and CVE Found cards: the totals now against the totals without the newest completed scan
    latest_done = next((j for j in history if j.status == 'Completed'), None)
    before_jobs = history[history.index(latest_done) + 1:] if latest_done else []
    ports_before, cves_before = _open_port_and_cve_counts(before_jobs)
    ports_trend = _kpi_trend(total_open_ports, ports_before)
    cve_trend = _kpi_trend(total_cves_found, cves_before)
    # the CVE Found card says how much of what the vulnerability scans looked at could actually be evaluated (the Overview's coverage, in one line)
    ov = _vuln_overview([j for j in history if j.scan_type == 'vuln_scan'])
    cve_coverage = ({'services': ov['services'], 'evaluated': ov['found'] + ov['none'], 'found': ov['found'], 'none': ov['none'],
                     'not_evaluated': ov['not_evaluated']} if ov['services'] else None)

    # คำนวณ owner_seq ของ latest_scan เพื่อโชว์ #N ที่ถูกต้องใน dashboard
    latest_owner_seq = None
    if latest_scan and latest_scan.owner_id is not None:
        owner_jobs_sorted = ScanJob.query.filter_by(owner_id=latest_scan.owner_id).order_by(ScanJob.timestamp).all()
        latest_owner_seq = next((i+1 for i, j in enumerate(owner_jobs_sorted) if j.id == latest_scan.id), latest_scan.id)

    # เหมือนกับ history_page/api_jobs: ให้ "Job #N" ตรงกับ owner_seq (ไม่ใช่ global id)
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in history if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

    # ข้อมูลจริงสำหรับ Task Status (แทนที่ placeholder "Job #1, #2, ...")
    def _job_row(j):
        return {
            'id': j.id,
            'seq': owner_seq_map.get(j.id, j.id),
            'target': j.target,
            'type_label': SCAN_TYPE_LABELS.get(j.scan_type, j.scan_type or ''),
            'timestamp': j.timestamp.strftime('%Y-%m-%d %H:%M') if j.timestamp else '—',
        }
    task_complete_jobs = [_job_row(j) for j in history if j.status == 'Completed']
    task_running_jobs = [_job_row(j) for j in history if j.status in ACTIVE_STATUSES]
    task_failed_jobs = [_job_row(j) for j in history if j.status == 'Failed']
    task_wait_schedules = [{
        'id': s.id,
        'seq': idx,
        'name': s.name,
        'target': s.target,
        'repeat': s.repeat,
        'next_run': s.next_run.strftime('%Y-%m-%d %H:%M') if s.next_run else '—',
    } for idx, s in enumerate((s for s in schedules_all if s.is_active), 1)]

    task_ring_total = task_completed + task_wait + task_running + task_failed
    task_categories = [
        {
            'key': 'complete', 'label': 'Complete', 'thai': 'สแกนเสร็จสิ้น',
            'count': task_completed, 'color': GOOD_GREEN, 'kind': 'job',
            'timestamp_label': 'Completed', 'rows': task_complete_jobs,
            'view_all_url': url_for('history_page'), 'view_all_label': 'more completed scans',
        },
        {
            'key': 'wait', 'label': 'Wait Schedule', 'thai': 'รอตามกำหนด',
            'count': task_wait, 'color': '#3b82f6', 'kind': 'schedule',
            'timestamp_label': 'Next Run', 'rows': task_wait_schedules,
            'view_all_url': url_for('tasks_page'), 'view_all_label': 'more scheduled scans',
        },
        {
            'key': 'running', 'label': 'Running', 'thai': 'กำลังทำงานหรือรอคิว',
            'count': task_running, 'color': '#ffc107', 'kind': 'job',
            'timestamp_label': 'Started', 'rows': task_running_jobs,
            'view_all_url': url_for('history_page'), 'view_all_label': 'more running scans',
        },
        {
            'key': 'failed', 'label': 'Failed', 'thai': 'ล้มเหลว',
            'count': task_failed, 'color': '#dc2626', 'kind': 'job',
            'timestamp_label': 'Failed At', 'rows': task_failed_jobs,
            'view_all_url': url_for('history_page'), 'view_all_label': 'more failed scans',
        },
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

@app.route('/topology')
@login_required
def topology_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()

    # เหมือนกับ history_page/dashboard: ให้ "Job #N" ตรงกับ owner_seq (ไม่ใช่ global id)
    # ที่จะมีช่องว่างเมื่อ job เก่าถูกลบไปแล้ว
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in history if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

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
            })

        date_str = job.timestamp.strftime('%Y-%m-%d') if job.timestamp else '1970-01-01'
        scans_data.append({
            'job_id':    job.id,
            'job_name':  job.scan_name or f'Job #{owner_seq_map.get(job.id, job.id)}',
            'scan_type': job.scan_type or '',
            'date':      date_str,
            'target':    job.target,
            'hosts':     hosts_list
        })

    import json as _json
    # hostnames/mDNS names come from other devices and this JSON is dropped raw into a <script>:
    # < keeps it valid JSON while making "</script>" impossible
    scans_json = _json.dumps(scans_data).replace('<', '\\u003c')
    system_gw = get_system_default_gateway()
    return render_template('network_topology.html', scans_json=scans_json, system_gateway=system_gw)


# ─────────────────────────────────────────

@app.route('/history')
@login_required
def history_page():
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
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

    # คำนวณลำดับ scan ของแต่ละ owner แยกกัน (#1, #2, #3 ...)
    # ดึงจาก DB โดยตรงตาม owner_id จริงๆ ไม่ผ่าน visible_scans_query
    # เพื่อให้นับถูก: admin สแกนครั้งแรก = #1 เสมอ ไม่สนว่า global id เป็นเท่าไหร่
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in history if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

    return render_template('history.html', history=history,
                           scan_seq_map=scan_seq_map,
                           owner_seq_map=owner_seq_map,
                           adv_fields=[dict(key=k, **v) for k, v in ADV_FIELDS.items()])      # a list: JSON would sort a dict's keys


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
                     'options': [['manual', 'Manual'], ['schedule', 'Schedule'], ['rescan', 'Rescan'], ['drilldown', 'Drill-down']]},
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


def describe_criteria(criteria):
    """One line that says what a query looks for, e.g. "Type: Fast Scan · พอร์ต: 445 · ยกเว้น Status: Failed"."""
    def row_text(row):
        meta = ADV_FIELDS[row['field']]
        vals = row['values']
        if meta['kind'] == 'enum':
            names = dict(meta['options'])
            vals = [names.get(v, v) for v in vals]
        elif meta['kind'] == 'date':
            vals = [(vals[0] or '…') + ' – ' + (vals[1] or '…')]
        return meta['label'] + ': ' + ', '.join(vals)
    parts = [row_text(r) for r in criteria['include']] + ['ยกเว้น ' + row_text(r) for r in criteria['exclude']]
    return ' · '.join(parts) if parts else 'ไม่มีเงื่อนไข'


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


SKIPPED_ACTIVE_TEXT = 'ข้าม {n} งานที่กำลังทำงานหรือรอคิว (ต้องยกเลิกงานก่อนจึงจะลบได้)'


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
        flash(f'ลบงานสแกน #{seq} เรียบร้อยแล้ว', 'success')
    else:
        flash(f'ลบงานสแกน #{seq} ไม่ได้ เพราะงานนี้กำลังทำงานหรือรอคิว กรุณายกเลิกงานก่อน', 'warning')
    return redirect(url_for('history_page'))


@app.route('/history/delete-by-target', methods=['POST'])
@login_required
def delete_scans_by_target():
    # เฉพาะ admin และ superadmin เท่านั้นที่ลบได้
    if not current_user.is_any_admin:
        abort(403)
    target = request.form.get('target', '').strip()
    if not target:
        flash('ไม่พบเป้าหมายที่ระบุ', 'danger')
        return redirect(url_for('history_page'))
    ids = [row[0] for row in visible_scans_query().filter_by(target=target).with_entities(ScanJob.id).all()]
    deleted, skipped = _delete_finished_scans(ids)
    if deleted and skipped:
        flash(f'ลบงานสแกนของ {target} {deleted} รายการเรียบร้อยแล้ว ' + SKIPPED_ACTIVE_TEXT.format(n=skipped), 'warning')
    elif deleted:
        flash(f'ลบงานสแกนของ {target} ทั้งหมด {deleted} รายการเรียบร้อยแล้ว', 'success')
    else:
        flash(f'ไม่มีงานสแกนของ {target} ที่ลบได้ ' + (SKIPPED_ACTIVE_TEXT.format(n=skipped) if skipped else 'งานเหล่านี้ถูกลบไปแล้ว'), 'warning')
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
        flash('ไม่ได้เลือกรายการที่จะลบ', 'warning')
        return redirect(url_for('history_page'))

    # only the scans this user may see, and never one that is waiting or running (the database decides, in the DELETE itself)
    in_scope = [row[0] for row in visible_scans_query().filter(ScanJob.id.in_(clean_ids)).with_entities(ScanJob.id).all()]
    deleted, skipped = _delete_finished_scans(in_scope)
    if deleted and skipped:
        flash(f'ลบงานสแกน {deleted} รายการเรียบร้อยแล้ว ' + SKIPPED_ACTIVE_TEXT.format(n=skipped), 'warning')
    elif deleted:
        flash(f'ลบงานสแกนทั้งหมด {deleted} รายการเรียบร้อยแล้ว', 'success')
    else:
        flash('ไม่มีงานสแกนที่ลบได้ ' + (SKIPPED_ACTIVE_TEXT.format(n=skipped) if skipped else 'ไม่พบรายการที่เลือก'), 'warning')
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
            'settings': describe_scan_settings(sc.scan_type, sc.timing, sc.version_intensity, sc.custom_args, False, sc.skip_ping, sc.all_ports, sc.no_dns, sc.host_probes, sc.gentle, sc.udp),
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
    """รวมอุปกรณ์ที่ไม่ซ้ำกันจากประวัติการสแกนทั้งหมด (เรียงจากล่าสุดไปเก่าสุด)"""
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    # One row per physical device: keyed by MAC when the scan saw one (DHCP can hand the same
    # device a new IP, and an old IP to a different device), otherwise by IP.
    devices = {}
    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            ip = d.get('ip', '')
            if not ip:
                continue
            mac = d.get('mac', '')
            mac = mac.upper() if mac and mac != 'Unknown' else ''
            key = ('mac', mac) if mac else ('ip', ip)
            if key not in devices:
                devices[key] = {
                    'ips': [],
                    'mac': mac,
                    'mac_vendor': d.get('mac_vendor', ''),
                    'os': d.get('os', ''),
                    'hostname': d.get('hostname', ''),
                    'ports': set(),
                    'open_ports': set(),
                    'open_labels': set(),         # "port/service" of the ports seen in state open: what "Open Ports" counts
                    'services': set(),
                    'scan_count': 0,
                    'last_seen': job.timestamp,
                    'last_scan_id': job.id,
                    'last_scan_ip': ip,           # the address it had in that scan (may differ from ips[0] after a merge)
                }
            entry = devices[key]
            if ip not in entry['ips']:
                entry['ips'].append(ip)           # newest scan first, so ips[0] is the current address
            entry['scan_count'] += 1
            # newest scan wins, but fill gaps from older scans (e.g. newest scan had no MAC / OS)
            if not entry['mac'] and mac:
                entry['mac'], entry['mac_vendor'] = mac, d.get('mac_vendor', '')
            if (not entry['os'] or entry['os'] == 'Unknown') and d.get('os') and d.get('os') != 'Unknown':
                entry['os'] = d['os']
            if not entry['hostname'] and d.get('hostname'):
                entry['hostname'] = d['hostname']
            for p in d.get('ports', []):
                entry['ports'].add(port_text(p))
                if str(p.get('state', 'open')).lower() == 'open':
                    if port_proto(p) == 'tcp':      # guess_device_type() reads TCP port numbers; a UDP 161 is not a TCP 161
                        entry['open_ports'].add(p.get('port'))
                    entry['open_labels'].add(port_text(p))
                answered = port_proto(p) == 'tcp' or str(p.get('state', 'open')).lower() == 'open'      # nmap names an unanswered UDP port by its number only
                if p.get('name') and answered:
                    entry['services'].add(p['name'])
                if p.get('version_info') and p['version_info'] != 'Unknown Version' and answered:
                    entry['services'].add(p['version_info'])
            entry['services'].update(discovery_service_text(d.get('discovery')))

    # a record with no MAC belongs to the device that owns its IP -- but only if exactly one does
    for key in [k for k in devices if k[0] == 'ip']:
        owners = [k for k in devices if k[0] == 'mac' and key[1] in devices[k]['ips']]
        if len(owners) != 1:
            continue
        src, dst = devices.pop(key), devices[owners[0]]
        dst['ports'] |= src['ports']
        dst['open_ports'] |= src['open_ports']
        dst['open_labels'] |= src['open_labels']
        dst['services'] |= src['services']
        dst['scan_count'] += src['scan_count']
        if (not dst['os'] or dst['os'] == 'Unknown') and src['os'] and src['os'] != 'Unknown':
            dst['os'] = src['os']
        dst['hostname'] = dst['hostname'] or src['hostname']
        if src['last_seen'] and (not dst['last_seen'] or src['last_seen'] > dst['last_seen']):
            dst['last_seen'], dst['last_scan_id'], dst['last_scan_ip'] = src['last_seen'], src['last_scan_id'], src['last_scan_ip']

    gateway_ip = (get_system_default_gateway(max_age=30) or {}).get('ip')
    device_list = []
    for e in devices.values():
        services_text = ' '.join(e['services'])
        # with several IPs, the gateway / this-PC address is the one the classifier must see
        rule_ip = gateway_ip if gateway_ip in e['ips'] else next((i for i in e['ips'] if is_local_ip(i)), e['ips'][0])
        device_list.append({
            'ip': e['ips'][0],
            'other_ips': e['ips'][1:],
            'mac': e['mac'] or '—',
            'mac_vendor': e['mac_vendor'],
            'os': e['os'] or 'Unknown',
            'os_family': _os_family(e['os']),
            'device_type': guess_device_type(rule_ip, e['mac_vendor'], e['os'], e['open_ports'], gateway_ip,
                                              services=services_text, hostname=e['hostname'], mac=e['mac']),
            'port_count': len(e['open_labels']),          # open ports only: a filtered port is not an open one
            'open_ports_list': sorted(e['open_labels']),
            'ports': sorted(e['ports']),                  # every port seen, in any state: the search box looks through these
            'scan_count': e['scan_count'],
            'last_seen': e['last_seen'].strftime('%Y-%m-%d %H:%M') if e['last_seen'] else '—',
            'last_scan_id': e['last_scan_id'],
            'last_scan_ip': e['last_scan_ip'],
        })
    device_list.sort(key=lambda x: _ip_sort_key(x['ip']))

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


def _vuln_overview(history):
    """The numbers behind the Vulnerabilities page's Overview, from the same vulnerability scans (newest first) as the CVE table.
    COVERAGE counts every OPEN service the scans looked up in NVD, by what its NEWEST scan says (the stored `cve_status`):
      found          it has CVEs
      none           NVD was asked and knows none ('ok')
      not_evaluated  nothing can be said about it: the lookup 'failed', nmap named no product ('no_product'), or the scan is older than the
                     status field ('legacy': a service with no CVEs and no status). An old record whose version_info is 'Unknown Version' is
                     still 'no_product': the stored record itself shows there was nothing to search for, so that is a fact, not a guess.
    A CVE is counted once per (device, CVE id), like the table; the severity goes through effective_severity().
    BANDS count those CVEs by their CVSS score; a CVE with no score is `unscored`, never put in a band.
    A service row also carries the devices that have it (`device_list`: address and its CVE count for that service, most CVEs first, at most
    OV_STRIP_MAX), so the page can answer "which device?" under the row."""
    services, cve_rows = {}, {}
    for job in history:
        if not job.result_data:
            continue
        try:
            data = json.loads(job.result_data)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for d in data:
            ip = d.get('ip', '') if isinstance(d, dict) else ''
            if not ip:
                continue
            for p in d.get('ports', []) or []:
                if str(p.get('state', '')).lower() != 'open':
                    continue
                cves = p.get('cves') or []
                key = (ip, str(p.get('port', '')), port_proto(p))
                if key not in services:                       # newest scan first: the first record of a service is its newest
                    services[key] = {'cves': len(cves), 'status': p.get('cve_status'), 'version': str(p.get('version_info') or '')}
                for cve in cves:
                    cve_id = cve.get('cve_id', '')
                    if cve_id and (ip, cve_id) not in cve_rows:
                        cve_rows[(ip, cve_id)] = {'ip': ip, 'cve_id': cve_id, 'sev': effective_severity(cve) or 'UNKNOWN',
                                                  'score': cvss_number(cve.get('cvss_score')), 'product': re.sub(r'\s+', ' ', str(p.get('version_info') or '')).strip()}

    found = none = 0
    reasons = {'failed': 0, 'no_product': 0, 'legacy': 0}
    for s in services.values():
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
    for r in cve_rows.values():
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
        'status_recorded': any(s['status'] for s in services.values()),     # False = every scan here is older than the status field
        'cve_total': len(cve_rows), 'device_total': len(per_dev),
        'top_devices': [{'ip': e['ip'], 'count': e['count'], 'worst': e['worst']}
                        for e in sorted(per_dev.values(), key=lambda e: (-e['count'], -e['rank'], _ip_sort_key(e['ip'])))[:5]],
        'top_services': [{'product': e['product'], 'devices': len(e['per_dev']), 'cves': len(e['ids']), 'worst': e['worst'],
                          'device_list': [{'ip': ip, 'cves': len(ids)} for ip, ids in
                                          sorted(e['per_dev'].items(), key=lambda kv: (-len(kv[1]), _ip_sort_key(kv[0])))[:OV_STRIP_MAX]]}
                         for e in sorted(per_prod.values(), key=lambda e: (-len(e['per_dev']), -e['rank'], -len(e['ids']), e['product'].lower()))[:5]],
        'bands': bands, 'unscored': unscored,
    }


@app.route('/vulnerabilities')
@login_required
def vulnerabilities_page():
    """รวม CVE ที่ไม่ซ้ำกัน (ตาม IP + CVE ID) จาก Vulnerability Scan ทั้งหมด"""
    history = visible_scans_query().filter_by(scan_type='vuln_scan').order_by(ScanJob.timestamp.desc()).all()
    seen = set()
    cve_list = []
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}

    for job in history:
        if not job.result_data:
            continue
        try:
            job_data = json.loads(job.result_data)
        except Exception:
            continue
        for d in job_data:
            ip = d.get('ip', '')
            for p in d.get('ports', []):
                for cve in (p.get('cves') or []):
                    cve_id = cve.get('cve_id', '')
                    key = (ip, cve_id)
                    if not cve_id or key in seen:
                        continue
                    seen.add(key)
                    sev = effective_severity(cve) or 'UNKNOWN'
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    cve_list.append({
                        'cve_id': cve_id,
                        'severity': sev,
                        # set only when sev is not the label NVD gave: the page shows an (i) with this as its tooltip
                        'severity_note': severity_note(cve.get('cvss_score')) if severity_adjusted(cve) else '',
                        'cvss_score': cve.get('cvss_score'),
                        'cwe_name': cve.get('cwe_name', ''),
                        'cwe': cwe_info(cve),
                        'description': cve.get('description', ''),
                        'ip': ip,
                        'port': p.get('port', ''),
                        'protocol': port_proto(p),
                        'service': p.get('name', ''),
                        'job_id': job.id,
                        'found_at': job.timestamp.strftime('%Y-%m-%d') if job.timestamp else '',
                        'kev': cve.get('kev') is True,      # on CISA's Known Exploited list, as NVD said when the scan looked it up; absent in older scans = not recorded
                        'kev_added': str(cve.get('kev_added') or '')[:10] if cve.get('kev') is True else '',
                    })

    sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
    cve_list.sort(key=lambda c: sev_order.get(c['severity'], 5))

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
                           overview=_vuln_overview(history))


@app.route('/reports')
@login_required
def reports_page():
    """รายการ scan ที่เสร็จสมบูรณ์ พร้อมลิงก์ export CSV / PDF"""
    history = visible_scans_query().filter_by(status='Completed').order_by(ScanJob.timestamp.desc()).all()

    # เหมือนกับ history_page/dashboard: ให้ "Job #N" ตรงกับ owner_seq (ไม่ใช่ global id)
    # ที่จะมีช่องว่างเมื่อ job เก่าถูกลบไปแล้ว
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in history if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

    return render_template('reports.html', history=history, owner_seq_map=owner_seq_map)


@app.route('/settings')
@login_required
def settings_page():
    ai = _ai_usage_summary() if current_user.is_any_admin else None
    return render_template('settings.html', ai=ai, can_change_ai=current_user.is_superadmin)


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
        'hosts': hosts, 'open_ports': open_ports, 'cves': cves, 'error': error,
        'settings': describe_scan_settings(job.scan_type, job.timing, job.version_intensity, custom_args, job.multicast, job.skip_ping, job.all_ports, job.no_dns, job.host_probes, job.gentle, job.udp),
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
    settings = describe_scan_settings(scan_type, timing, version_intensity, custom_args, multicast, skip_ping, all_ports, no_dns, host_probes, gentle, udp)
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
    jobs = visible_scans_query().order_by(ScanJob.timestamp.desc()).limit(100).all()
    from collections import defaultdict
    target_jobs = defaultdict(list)
    for j in jobs:
        target_jobs[j.target].append(j)
    target_seq = {}
    for target, tlist in target_jobs.items():
        sorted_list = sorted(tlist, key=lambda x: x.timestamp or 0)
        for idx, tj in enumerate(sorted_list, 1):
            target_seq[tj.id] = (idx, len(sorted_list))

    # คำนวณลำดับ scan ของแต่ละ owner แยกกัน (#1, #2, #3 ...)
    # เหมือนกับที่ history และ dashboard ใช้
    owner_seq_map = {}
    unique_owner_ids = {j.owner_id for j in jobs if j.owner_id is not None}
    for oid in unique_owner_ids:
        owner_all = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp).all()
        for idx, tj in enumerate(owner_all, 1):
            owner_seq_map[tj.id] = idx

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
            # for the "scan finished" toast. Only values that do NOT change between two polls: the Tasks page rebuilds its table when this JSON
            # differs from the last poll, so something like "seconds since it finished" would rebuild it every 3 seconds.
            'scan_label': SCAN_TYPE_LABELS.get(j.scan_type, j.scan_type),
            'finished_at': finished.strftime('%Y-%m-%d %H:%M:%S') if finished else '',
            'duration_s': max(0, int((finished - j.timestamp).total_seconds())) if finished and j.timestamp else None,
        })
    resp = jsonify(result)
    resp.headers['X-Server-Time'] = now_th().strftime('%Y-%m-%d %H:%M:%S')       # same clock and format as finished_at, so the page can compare them
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
    total_hosts = len(scan_data)
    focused = [h for h in scan_data if isinstance(h, dict) and h.get('ip') == focus_ip] if focus_ip else []
    if focused:
        scan_data = focused
    else:
        focus_ip = ''
    same_target_jobs = visible_scans_query().filter_by(target=job.target).order_by(ScanJob.timestamp).all()
    target_scan_count = len(same_target_jobs)
    scan_seq = next((i+1 for i, j in enumerate(same_target_jobs) if j.id == job.id), 1)

    # คำนวณลำดับของ job นี้ในบรรดา scan ทั้งหมดของ owner จริงๆ (ดึงตรงจาก DB)
    all_owner_jobs = ScanJob.query.filter_by(owner_id=job.owner_id).order_by(ScanJob.timestamp).all()
    owner_seq = next((i+1 for i, j in enumerate(all_owner_jobs) if j.id == job.id), job.id)

    system_gw = get_system_default_gateway()
    template = 'vuln_scan_detail.html' if job.scan_type == 'vuln_scan' else 'scan_detail.html'
    changes = scan_changes(job) if not focus_ip else None       # one device (?host=) is a different question: no whole-scan comparison
    return render_template(template, job=job, scan_data=scan_data, run=describe_run(job), changes=changes,
                           target_scan_count=target_scan_count, scan_seq=scan_seq,
                           owner_seq=owner_seq, system_gateway=system_gw,
                           focus_ip=focus_ip, total_hosts=total_hosts)


def _owner_seq_map(owner_ids):
    """Job id -> the number the app shows as "Job #N" (the job's place in its owner's list by time), as scan_detail and History count it."""
    seq = {}
    for oid in owner_ids:
        rows = ScanJob.query.filter_by(owner_id=oid).order_by(ScanJob.timestamp, ScanJob.id).with_entities(ScanJob.id).all()
        for i, r in enumerate(rows, 1):
            seq[r.id] = i
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
    dev = device_builder.build_device(ip, scans, SCAN_TYPE_LABELS)
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
    name = request.form.get('name')
    target = request.form.get('target')
    scan_type = request.form.get('scan_type')
    repeat = request.form.get('repeat', 'daily')
    time_str = request.form.get('time', '00:00')
    custom_args = request.form.get('custom_args', '').strip() or None
    timing, version_intensity = clamp_scan_knobs(request.form.get('timing'), request.form.get('version_intensity'), scan_type=scan_type)
    skip_ping = job_skip_ping(scan_type, custom_args, request.form.get('skip_ping'))
    all_ports = job_all_ports(scan_type, request.form.get('all_ports'))
    no_dns = job_no_dns(scan_type, request.form.get('no_dns'))
    host_probes = job_probes(scan_type, request.form.get('host_probes'))
    gentle = job_gentle(scan_type, request.form.get('gentle'))
    udp = job_udp(scan_type, request.form.get('udp'))
    if gentle:
        timing = None      # Gentle sets the speed itself
    refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('tasks_page'))

    try:
        hour, minute = map(int, time_str.split(':'))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError(time_str)
    except ValueError:
        flash('Invalid time format', 'danger')
        return redirect(url_for('tasks_page'))

    day_of_week = int(request.form.get('day_of_week', 0)) if repeat == 'weekly' else None
    day_of_month = int(request.form.get('day_of_month', 1)) if repeat == 'monthly' else None

    schedule = ScheduledScan(
        name=name, target=target, scan_type=scan_type,
        cron_hour=hour, cron_minute=minute,
        repeat=repeat, day_of_week=day_of_week, day_of_month=day_of_month,
        is_active=True, created_by=current_user.id,
        owner_id=current_user.id,
        custom_args=custom_args if scan_type == 'custom' else None,
        timing=timing, version_intensity=version_intensity, skip_ping=skip_ping, all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp,
    )
    schedule.next_run = calc_next_run(schedule)
    db.session.add(schedule)
    db.session.commit()
    register_apscheduler_job(schedule)

    flash(f'Schedule "{name}" created! Next run: {schedule.next_run.strftime("%Y-%m-%d %H:%M")}', 'success')
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
    flash(f'Schedule "{schedule.name}" deleted.', 'success')
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
        flash('❌ ไม่สามารถ Rescan ได้ เนื่องจาก scan นี้มาจาก XML Upload', 'danger')
        return redirect(url_for('tasks_page'))

    # ห้าม rescan ถ้า target นี้กำลังรอคิวหรือ Running อยู่
    running = visible_scans_query().filter(ScanJob.target == original.target, ScanJob.status.in_(ACTIVE_STATUSES)).first()
    if running:
        flash(f'❌ Target "{original.target}" กำลังสแกนอยู่ กรุณารอให้เสร็จก่อน', 'danger')
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
    if gentle:
        timing = None      # Gentle sets the speed itself
    refusal = scan_option_refusal(target, skip_ping, all_ports, host_probes, gentle, udp)
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
        all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp,
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
    if gentle:
        timing = None      # Gentle sets the speed itself

    if not host_ip:
        flash('กรุณาระบุ IP ที่ต้องการสแกน', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    refusal = scan_option_refusal(host_ip, skip_ping, all_ports, host_probes, gentle, udp)
    if refusal:
        flash(refusal, 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # ตรวจว่า IP นี้กำลังสแกนอยู่หรือไม่
    running = visible_scans_query().filter(ScanJob.target == host_ip, ScanJob.status.in_(ACTIVE_STATUSES)).first()
    if running:
        flash(f'❌ Target "{host_ip}" กำลังสแกนอยู่ กรุณารอให้เสร็จก่อน', 'danger')
        return redirect(url_for('scan_detail', scan_id=scan_id))

    # สร้าง scan name ที่อ้างอิง parent scan
    parent_label = parent_job.scan_name or f'Scan #{_job_seq(parent_job)}'      # the number the app shows, not the database id
    scan_name = f'Drill-down: {host_ip} (from {parent_label})'

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
        all_ports=all_ports, no_dns=no_dns, host_probes=host_probes, gentle=gentle, udp=udp,
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
    flash(f'Schedule "{schedule.name}" triggered manually!', 'success')
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
        flash('Admin สามารถสร้างได้เฉพาะ User เท่านั้น', 'danger')
        return redirect(url_for('user_management'))

    if not username or not password:
        flash('กรุณากรอก username และ password', 'danger')
        return redirect(url_for('user_management'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" มีอยู่แล้ว', 'danger')
        return redirect(url_for('user_management'))

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role,
        created_by=current_user.id
    )
    db.session.add(new_user)
    db.session.commit()
    flash(f'สร้าง {role} "{username}" สำเร็จ', 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@user_management_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('ไม่สามารถลบตัวเองได้', 'danger')
        return redirect(url_for('user_management'))

    # superadmin ลบได้ทุกคน ยกเว้น superadmin ด้วยกัน
    if user.role == 'superadmin':
        flash('ไม่สามารถลบ Superadmin ได้', 'danger')
        return redirect(url_for('user_management'))

    # admin ลบได้เฉพาะ user ใต้สังกัดตัวเอง
    if current_user.role == 'admin' and user.created_by != current_user.id:
        abort(403)

    deleted_username = user.username
    deleted_role = user.role

    # ถ้าลบ admin ให้ลบ ScanJob + ScheduledScan + user ใต้สังกัดทั้งหมดก่อน
    if user.role == 'admin':
        sub_users = User.query.filter_by(created_by=user.id).all()
        for sub_user in sub_users:
            # ลบ ScanJob และ ScheduledScan ของ sub_user ด้วย
            ScanJob.query.filter_by(owner_id=sub_user.id).delete()
            ScheduledScan.query.filter_by(owner_id=sub_user.id).delete()
            db.session.delete(sub_user)
        # ลบ ScanJob และ ScheduledScan ของ admin เอง
        ScanJob.query.filter_by(owner_id=user.id).delete()
        ScheduledScan.query.filter_by(owner_id=user.id).delete()
    else:
        # ลบ ScanJob และ ScheduledScan ของ user ธรรมดา
        ScanJob.query.filter_by(owner_id=user.id).delete()
        ScheduledScan.query.filter_by(owner_id=user.id).delete()

    forgotten = [user.id] + ([u.id for u in sub_users] if user.role == 'admin' else [])
    db.session.delete(user)
    db.session.commit()
    for uid in forgotten:
        _forget_user_key(uid)

    if deleted_role == 'admin':
        flash(f'ลบ Admin "{deleted_username}" และ User ใต้สังกัดทั้งหมดแล้ว', 'success')
    else:
        flash(f'ลบ "{deleted_username}" แล้ว', 'success')
    return redirect(url_for('user_management'))


@app.route('/users/<int:user_id>/reassign', methods=['POST'])
@login_required
@superadmin_required
def reassign_user(user_id):
    """ย้าย User ไปสังกัด Admin คนอื่น — เฉพาะ Superadmin เท่านั้นที่ทำได้
    (Admin ปกติไม่มีสิทธิ์เข้าถึง route นี้ เพราะโดน @superadmin_required บล็อกไว้)"""
    user = User.query.get_or_404(user_id)

    # โยกได้เฉพาะ user ธรรมดาเท่านั้น ไม่ใช่ admin/superadmin
    if user.role != 'user':
        flash('ย้ายสังกัดได้เฉพาะ User เท่านั้น', 'danger')
        return redirect(url_for('user_management'))

    new_admin_id = request.form.get('new_admin_id', '').strip()
    if not new_admin_id:
        flash('กรุณาเลือก Admin ปลายทาง', 'danger')
        return redirect(url_for('user_management'))

    new_admin = User.query.get(int(new_admin_id))
    if not new_admin or new_admin.role not in ('admin', 'superadmin'):
        flash('ไม่พบ Admin ปลายทางที่เลือก', 'danger')
        return redirect(url_for('user_management'))

    old_admin_name = user.creator.username if user.creator else '—'
    user.created_by = new_admin.id
    db.session.commit()
    flash(f'ย้าย User "{user.username}" จาก "{old_admin_name}" ไปสังกัด "{new_admin.username}" สำเร็จ', 'success')
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
        flash('กรุณากรอก password ใหม่', 'danger')
        return redirect(url_for('user_management'))

    user.password_hash = generate_password_hash(new_pw)
    db.session.commit()
    flash(f'Reset password ของ "{user.username}" สำเร็จ', 'success')
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
        flash('กรุณาเลือกไฟล์ XML', 'danger')
        return redirect(url_for('tasks_page'))

    if not file.filename.lower().endswith('.xml'):
        flash('ไฟล์ต้องเป็น .xml เท่านั้น', 'danger')
        return redirect(url_for('tasks_page'))

    scan_name = request.form.get('xml_scan_name', '').strip() or os.path.splitext(file.filename)[0]

    try:
        xml_content = file.read()
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        flash('ไฟล์ XML ไม่ถูกต้อง', 'danger')
        return redirect(url_for('tasks_page'))

    scan_results = []
    hosts_el = root.findall('host')
    if not hosts_el:
        flash('ไม่พบข้อมูล host ในไฟล์ XML', 'danger')
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
            entry = {
                'port': int(port_el.get('portid', 0)),
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
        flash('ไม่พบ host ที่มี IP address ถูกต้องในไฟล์ XML' if skipped_hosts else 'ไม่พบ host ที่ online ในไฟล์ XML', 'danger')
        return redirect(url_for('tasks_page'))

    target_display = targets_found[0] if len(targets_found) == 1 else f"{targets_found[0]} (+{len(targets_found)-1} more)"

    new_job = ScanJob(
        scan_name=scan_name, target=target_display,
        scan_type='xml_upload', status='Completed',
        triggered_by='manual', result_data=json.dumps(scan_results),
        owner_id=current_user.id
    )
    db.session.add(new_job)
    for ip in set(targets_found):
        if not SavedTarget.query.filter_by(target=ip).first():
            db.session.add(SavedTarget(target=ip))
    db.session.commit()
    session['scan_just_finished'] = new_job.id
    flash(f'นำเข้าไฟล์ XML สำเร็จ! พบ {len(scan_results)} host', 'success')
    if skipped_hosts:
        flash(f'ข้าม {skipped_hosts} host ที่ IP address ไม่ถูกต้อง', 'warning')
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
    writer.writerow(['IP Address', 'MAC Address', 'OS / Status', 'Port', 'Protocol', 'State', 'Service', 'Version'])

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
                writer.writerow([ip, mac_display, os_info,
                                  port.get('port', ''), (port.get('protocol', 'tcp') or '').lower(),
                                  port.get('state', 'unknown') or 'unknown', port.get('name', '') or '—', ver])
        else:
            writer.writerow([ip, mac_display, os_info, '—', '—', '—', 'No ports', '—'])

    output.seek(0)
    from flask import Response
    import re as _re
    custom_name = request.args.get('filename', '').strip()
    if custom_name:
        custom_name = _re.sub(r'[\\/:*?"<>|]', '_', custom_name)
        filename = custom_name + '.csv'
    else:
        filename = f"scan_{job.id}_{job.target.replace('/', '_').replace(' ', '_')}_{job.timestamp.strftime('%Y%m%d_%H%M%S') if job.timestamp else 'export'}.csv"
    return Response(output.getvalue(), mimetype='text/csv', headers=_attachment_headers(filename))


def _attachment_headers(filename):
    """Content-Disposition for a download. A name with Thai (or any non-Latin-1) letters cannot go into a plain header value, so: an ASCII
    fallback name plus the RFC 5987 UTF-8 form that browsers prefer."""
    from urllib.parse import quote
    stem, dot, ext = filename.rpartition('.')
    if not dot:
        stem, ext = filename, ''
    ascii_stem = re.sub(r'[\\/:*?"<>|\r\n;]', '_', stem.encode('ascii', 'ignore').decode('ascii')).strip() or 'report'
    ascii_name = ascii_stem + ('.' + ext if ext else '')
    return {'Content-Disposition': f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}"}


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
    scan = {'id': job.id, 'number': _owner_seq_map({job.owner_id}).get(job.id, job.id) if job.owner_id is not None else job.id,      # id = the database id (URLs); number = the "Job #N" every page shows
            'scan_type': job.scan_type, 'scan_name': job.scan_name, 'target': job.target, 'status': job.status,
            'started': job.timestamp, 'finished': job.finished_at, 'timing': job.timing, 'version_intensity': job.version_intensity,
            'custom_args': custom_args, 'multicast': job.multicast, 'skip_ping': job.skip_ping, 'all_ports': job.all_ports, 'nmap_version': scan_run_info(job).get('nmap'),
            'run': describe_run(job), 'run_facts': scan_run_info(job), 'owner': job.owner.username if job.owner else '', 'triggered_by': job.triggered_by or 'manual'}
    try:
        scan['changes'] = scan_changes(job)      # what changed since the earlier scan of the same kind; None = nothing to compare with
    except Exception:                            # the report must never fail because of the comparison: say it could not be made
        app.logger.exception('Report: could not compare scan %s with the one before it', job.id)
        scan['changes'], scan['changes_failed'] = None, True
    r = report_builder.build_report(scan, hosts, now_th(), SCAN_TYPE_LABELS)
    return r, [h for h in hosts if isinstance(h, dict) and h.get('ip')]


@app.route('/scan/<int:scan_id>/report')
@login_required
def scan_report(scan_id):
    """The report as a page (the senior's 3-page design): readable on screen, printable with Ctrl+P."""
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    r, scan_data = _report_context(job)
    return render_template('scan_report.html', r=r, scan_data=scan_data, system_gateway=get_system_default_gateway(), print_mode=False,
                           asset=lambda p: url_for('static', filename=p))


@app.route('/scan/<int:scan_id>/export/pdf')
@login_required
def export_pdf(scan_id):
    """The PDF report: the report page printed by a headless Edge / Chrome (report_pdf.py). If no browser can do it (not installed, the
    package missing, a timeout) the old xhtml2pdf export below is used instead, so the button never just fails."""
    from flask import Response
    job = visible_scans_query().filter_by(id=scan_id).first_or_404()
    r, scan_data = _report_context(job)
    static_root = pathlib.Path(app.static_folder)
    html = render_template('scan_report.html', r=r, scan_data=scan_data, system_gateway=get_system_default_gateway(), print_mode=True,
                           asset=lambda p: (static_root / p).as_uri())
    try:
        pdf = html_to_pdf(html)
    except ReportPdfError as e:
        app.logger.warning('PDF report: the browser engine failed for scan %s (%s); using the old exporter', scan_id, e)
        resp = _export_pdf_legacy(scan_id)
        resp.headers['X-Report-Engine'] = 'legacy'
        return resp
    resp = Response(pdf, mimetype='application/pdf', headers=_attachment_headers(_export_filename(job, 'pdf')))
    resp.headers['X-Report-Engine'] = 'browser'
    return resp


def _export_pdf_legacy(scan_id):
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
        return Response(pdf_buffer.read(), mimetype='application/pdf', headers=_attachment_headers(filename))
    except ImportError:
        filename = f"scan_{job.id}_report.html"
        return Response(html_content, mimetype='text/html', headers=_attachment_headers(filename))


# ─────────────────────────────────────────
#  AI CHATBOT API  (Google AI Studio / Gemini)
# ─────────────────────────────────────────

def _build_app_context():
    """
    รวบรวมข้อมูลจริงของแอพ (scan history, jobs, schedules, targets)
    สำหรับ current_user เพื่อส่งเป็น context ให้ Gemini
    """
    try:
        # --- Scan History (ล่าสุด 20 รายการ) ---
        scans = visible_scans_query().order_by(ScanJob.timestamp.desc()).limit(20).all()
        scan_summaries = []
        all_ips = {}   # ip → set of "port/service"
        all_ports_global = set()
        vuln_summary = []
        seen_vulns = set()

        for job in scans:
            entry = {
                'id': job.id,
                'name': job.scan_name or f'Scan #{job.id}',
                'target': job.target,
                'type': job.scan_type,
                'status': job.status,
                'timestamp': job.timestamp.strftime('%Y-%m-%d %H:%M') if job.timestamp else '-',
                'triggered_by': job.triggered_by,
            }
            if job.result_data:
                try:
                    hosts = json.loads(job.result_data)
                    host_count = len(hosts)
                    entry['host_count'] = host_count

                    # รวบรวม IP / port
                    for h in hosts:
                        ip = h.get('ip', '')
                        if ip:
                            if ip not in all_ips:
                                all_ips[ip] = set()
                            for p in h.get('ports', []):
                                label = port_text(p)
                                if str(p.get('state', '')).lower() == 'open':
                                    all_ips[ip].add(label)
                                    if port_key(p):
                                        all_ports_global.add(port_key(p))

                        # CVE / Vuln
                        for p in h.get('ports', []):
                            for cve in (p.get('cves') or []):
                                cve_id = cve.get('cve_id', '')
                                if not cve_id or (ip, cve_id) in seen_vulns:
                                    continue
                                seen_vulns.add((ip, cve_id))
                                vuln_summary.append({
                                    'ip': ip,
                                    'cve': cve_id,
                                    # same label the pages show; says so when it differs from NVD's, so the bot can explain it
                                    'severity': effective_severity(cve) + (' (NVD: HIGH, CVSS v2)' if severity_adjusted(cve) else ''),
                                    'description': (cve.get('description', '') or '')[:120],
                                })
                except Exception:
                    entry['host_count'] = 0
            scan_summaries.append(entry)

        # --- Schedules ---
        schedules = visible_schedules_query().all()
        sched_summaries = []
        for s in schedules:
            sched_summaries.append({
                'id': s.id,
                'name': s.name,
                'target': s.target,
                'type': s.scan_type,
                'repeat': s.repeat,
                'active': s.is_active,
                'last_run': s.last_run.strftime('%Y-%m-%d %H:%M') if s.last_run else 'ยังไม่เคย',
                'next_run': s.next_run.strftime('%Y-%m-%d %H:%M') if s.next_run else '-',
            })

        # --- Saved Targets ---
        saved_targets = SavedTarget.query.order_by(SavedTarget.created_at.desc()).limit(30).all()
        targets_list = [{'target': t.target, 'label': t.label or ''} for t in saved_targets]

        # --- สถิติรวม ---
        all_jobs = visible_scans_query().all()
        stats = {
            'total_scans': len(all_jobs),
            'completed': sum(1 for j in all_jobs if j.status == 'Completed'),
            'failed': sum(1 for j in all_jobs if j.status == 'Failed'),
            'running': sum(1 for j in all_jobs if j.status in ACTIVE_STATUSES),
            'total_unique_ips': len(all_ips),
            'total_open_ports': len(all_ports_global),
            'total_schedules': len(schedules),
            'active_schedules': sum(1 for s in schedules if s.is_active),
            'total_vulns_found': len(vuln_summary),
        }

        # --- สร้าง context string ---
        ctx_lines = [
            f"=== ข้อมูลระบบ CLYLAR ณ ปัจจุบัน (ผู้ใช้: {current_user.username}, role: {current_user.role}) ===",
            "",
            f"📊 สถิติภาพรวม:",
            f"  - Scan ทั้งหมด: {stats['total_scans']} (สำเร็จ {stats['completed']}, ล้มเหลว {stats['failed']}, กำลังทำ {stats['running']})",
            f"  - IP ที่พบทั้งหมด: {stats['total_unique_ips']} เครื่อง",
            f"  - Port ที่เปิดอยู่ (unique): {stats['total_open_ports']} port",
            f"  - Scheduled Scan: {stats['total_schedules']} รายการ (active {stats['active_schedules']})",
            f"  - ช่องโหว่ CVE ที่พบ: {stats['total_vulns_found']} รายการ",
            "",
        ]

        if scan_summaries:
            ctx_lines.append("📋 ประวัติ Scan ล่าสุด (20 รายการ):")
            for s in scan_summaries:
                ctx_lines.append(
                    f"  [{s['id']}] {s['name']} | target={s['target']} | type={s['type']} "
                    f"| status={s['status']} | hosts={s.get('host_count','?')} | {s['timestamp']}"
                )
            ctx_lines.append("")

        if all_ips:
            ctx_lines.append(f"🖥️ IP ที่ค้นพบ ({len(all_ips)} เครื่อง):")
            for ip, ports in sorted(all_ips.items())[:40]:  # จำกัด 40 IP
                ports_str = ', '.join(sorted(ports)[:10]) if ports else 'ไม่พบ port'
                ctx_lines.append(f"  {ip}: {ports_str}")
            ctx_lines.append("")

        if vuln_summary:
            ctx_lines.append(f"⚠️ ช่องโหว่ CVE ที่พบ (สูงสุด 20 รายการ):")
            for v in vuln_summary[:20]:
                ctx_lines.append(f"  {v['ip']} | {v['cve']} | severity={v['severity']} | {v['description']}")
            ctx_lines.append("")

        if sched_summaries:
            ctx_lines.append(f"⏰ Scheduled Scans ({len(sched_summaries)} รายการ):")
            for s in sched_summaries:
                status_icon = '✅' if s['active'] else '⏸️'
                ctx_lines.append(
                    f"  {status_icon} [{s['id']}] {s['name']} | target={s['target']} "
                    f"| {s['repeat']} | last={s['last_run']} | next={s['next_run']}"
                )
            ctx_lines.append("")

        if targets_list:
            ctx_lines.append(f"🎯 Saved Targets ({len(targets_list)} รายการ):")
            for t in targets_list:
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


AI_OFF_TEXT = {
    'chat': 'ปิดการใช้ AI (Gemini) อยู่ จึงยังตอบข้อความที่พิมพ์ในแชทไม่ได้ กรุณากดปุ่มไมโครโฟนเพื่อสั่งสแกน เปิดหน้า หรือถามจำนวนอุปกรณ์/ช่องโหว่ '
            'หรือให้ผู้ดูแลระบบระดับสูงสุด (Superadmin) เปิดใช้ AI ที่หน้าตั้งค่า',
    'th': 'ปิดการใช้ AI (Gemini) อยู่ ระบบตอบได้เฉพาะคำสั่งสแกน การเปิดหน้า และคำถามจำนวนอุปกรณ์/พอร์ต/ช่องโหว่ ผู้ดูแลระบบระดับสูงสุด (Superadmin) เปิดใช้ AI ได้ที่หน้าตั้งค่า',
    'en': 'AI (Gemini) is switched off, so I can only handle scan commands, opening pages and questions about counts. '
          'A superadmin can switch it on in Settings.',
}


GEMINI_KEY_FILE = 'gemini_key'                       # instance/gemini_key: the SHARED key typed on the Settings page (git-ignored)
GEMINI_USER_KEY_DIR = 'gemini_user_keys'             # instance/gemini_user_keys/<user id>: one admin's OWN key (git-ignored)
GEMINI_MODEL_DEFAULT = 'gemini-1.5-flash'
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


def _record_gemini_call(source, ok, status, usage):
    """One GeminiCall row per call. Never lets a counting problem break the chat."""
    try:
        u = usage or {}
        db.session.add(GeminiCall(
            user_id=current_user.id if current_user and current_user.is_authenticated else None,
            source=source, ok=ok, status=_redact_key(status)[:200],
            model=gemini_model(),
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
        return {'calls': len(rows), 'failed': sum(1 for r in rows if not r.ok), 'voice': sum(1 for r in rows if r.source == 'voice'),
                'prompt_tokens': sum(r.prompt_tokens or 0 for r in rows), 'output_tokens': sum(r.output_tokens or 0 for r in rows),
                'total_tokens': sum(r.total_tokens or 0 for r in rows)}

    last = GeminiCall.query.order_by(GeminiCall.id.desc()).first()
    key, source = gemini_key()
    out = {'enabled': ai_enabled(), 'today': since(day0), 'month': since(day0.replace(day=1)),
           'total_calls': GeminiCall.query.count(), 'last': last.timestamp.strftime('%Y-%m-%d %H:%M') if last else None,
           'model': gemini_model(), 'key_set': bool(key), 'key_source': source}
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


def _call_gemini(system_prompt, messages, max_tokens=800, source='typed'):
    """The one way to reach Gemini: refuses when the Settings switch is off, and keeps a GeminiCall row for the usage counter."""
    if not ai_enabled():
        raise AIDisabled()
    try:
        text, usage = _gemini_request(system_prompt, messages, max_tokens)
    except ValueError as e:
        if 'NO_API_KEY' not in str(e):         # no key = nothing was sent, so nothing to count
            _record_gemini_call(source, False, e, None)
        raise
    except Exception as e:
        _record_gemini_call(source, False, e, None)
        raise
    _record_gemini_call(source, True, 'OK', usage)
    return text


def _gemini_request(system_prompt, messages, max_tokens=800):
    """Helper: เรียก Gemini API และคืน (reply string, usageMetadata) หรือ raise Exception"""
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
        'generationConfig': {'maxOutputTokens': max_tokens}
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
    return body['candidates'][0]['content']['parts'][0]['text'], body.get('usageMetadata')


# ─────────────────────────────────────────
#  API: สั่ง Scan ผ่าน Chatbot
# ─────────────────────────────────────────

VALID_SCAN_TYPES = ['fast_scan', 'discovery', 'intense', 'vuln_scan']

@app.route('/api/chat/scan', methods=['POST'])
@login_required
def api_chat_scan():
    """รับ target + scan_type แล้วรัน scan จริง — เรียกจาก chatbot"""
    if not current_user.is_any_admin:
        return jsonify({'error': 'permission_denied', 'message': 'เฉพาะผู้ดูแลระบบเท่านั้นที่สั่งสแกนได้'}), 403

    data = request.get_json()
    target    = (data.get('target') or '').strip()
    scan_type = (data.get('scan_type') or 'fast_scan').strip()
    scan_name = (data.get('scan_name') or '').strip() or None

    if not target:
        return jsonify({'error': 'no_target', 'message': 'กรุณาระบุ Target (IP หรือ hostname)'}), 400
    if scan_type not in VALID_SCAN_TYPES:
        scan_type = 'fast_scan'

    try:
        new_job = ScanJob(
            target=target, scan_type=scan_type, scan_name=scan_name,
            status='Queued', triggered_by='chatbot',
            owner_id=current_user.id,
            multicast=False if scan_type == 'discovery' else None
        )
        db.session.add(new_job)
        if not SavedTarget.query.filter_by(target=target).first():
            db.session.add(SavedTarget(target=target))
        db.session.commit()

        # The scan runs in the background, so the reply can no longer carry its results: it says the scan was accepted and where to follow it.
        if not enqueue_scan(new_job):
            return jsonify({'status': 'failed', 'job_id': new_job.id, 'message': 'เริ่มสแกนไม่ได้ กรุณาลองใหม่อีกครั้ง'}), 200
        return jsonify({'status': 'started', 'job_id': new_job.id, 'target': target, 'scan_type': scan_type,
                        'message': f'รับคำสั่งสแกน {target} แล้ว (งาน #{_job_seq(new_job)}) ดูความคืบหน้าได้ที่หน้างานสแกน'}), 200

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'เกิดข้อผิดพลาด: {str(e)}'}), 200


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
    if cmd['intent'] == 'scan' and cmd['status'] == 'ok':
        cmd['scan_label'] = SCAN_TYPE_LABELS[cmd['scan_type']]
        cmd['expires_in'] = VOICE_CONFIRM_SECONDS
        cmd['token'] = _voice_signer.dumps({'u': current_user.id, 't': cmd['target'], 'k': cmd['scan_type'], 'n': secrets.token_hex(8)})
        # "scan at once": the SERVER decides, from this admin's own setting and the target; the page only follows. A refusal is said on the card.
        if voice_autorun_on(current_user.id):
            cmd['autorun'] = voice_autorun_allowed(cmd['target'])
            cmd['autorun_refused'] = not cmd['autorun']
    elif cmd['intent'] == 'fact':
        cmd.update(_voice_answer(cmd, lang))                    # our own code: no AI, no tokens
    elif cmd['intent'] == 'navigate' and cmd['status'] == 'ok':
        cmd['url'] = url_for(_VOICE_PAGE_ENDPOINT[cmd['page']])   # the page key is ours, so the spoken words can never choose a URL
    elif cmd['intent'] == 'unknown':
        cmd['ai_enabled'] = ai_enabled()                        # the page decides whether to ask the AI
        cmd['worth_ai'] = voice_commands.worth_asking_ai(used)  # noise ("2nd 1.01.208.") is never sent to the AI: it only costs tokens
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


def _voice_collect():
    """The figures the dashboard shows, worked out the same way as dashboard() does (all visible history, newest scan first): devices =
    distinct IPs, open ports = distinct port numbers whose state is open, CVEs = distinct CVE ids on open ports with the label the
    dashboard shows (effective_severity), a device's tier = its worst CVE. test_voice_facts compares them with the dashboard."""
    history = visible_scans_query().order_by(ScanJob.timestamp.desc()).all()
    devices, ports, cves = {}, set(), {}
    for job in history:
        if not job.result_data:
            continue
        try:
            data = json.loads(job.result_data)
        except Exception:
            continue
        if not isinstance(data, list):
            continue
        for d in data:
            ip = d.get('ip', '') if isinstance(d, dict) else ''
            if not ip:
                continue
            dev = devices.setdefault(ip, {'vuln_scanned': False, 'key': None, 'worst': None, 'sevs': set(), 'has_cve': False})
            if job.scan_type == 'vuln_scan':
                dev['vuln_scanned'] = True
            for p in d.get('ports', []):
                if str(p.get('state', '')).lower() != 'open':
                    continue
                if port_key(p):
                    ports.add(port_key(p))
                for cve in p.get('cves', []):
                    cid = cve.get('cve_id') if isinstance(cve, dict) else (cve if isinstance(cve, str) else '')
                    if not cid:
                        continue
                    info = cve if isinstance(cve, dict) else {}
                    dev['has_cve'] = True
                    sev = effective_severity(cve)
                    if sev in _VOICE_SEV_RANK:
                        dev['sevs'].add(sev)
                        score = cvss_number(info.get('cvss_score'))
                        key = (_VOICE_SEV_RANK[sev], score if score is not None else -1)
                        if dev['key'] is None or key > dev['key']:
                            dev['key'], dev['worst'] = key, sev
                    entry = cves.get(cid)
                    if entry is None:
                        cves[cid] = {'severity': info.get('severity') or 'unknown', 'cvss_score': info.get('cvss_score')}
                    elif entry['cvss_score'] is None and info.get('cvss_score') is not None:
                        entry['cvss_score'] = info['cvss_score']
    by_sev = {}
    for entry in cves.values():
        label = effective_severity(entry)
        by_sev[label] = by_sev.get(label, 0) + 1
    tiers = {}
    for ip, dev in devices.items():
        w = dev['worst']
        tier = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'UNKNOWN': 'low'}.get(w) or ('clean' if dev['vuln_scanned'] else 'unscanned')
        tiers.setdefault(tier, []).append(ip)
    return {'scans': len(history), 'devices': devices, 'ports': ports, 'cves': cves, 'cves_by_sev': by_sev, 'tiers': tiers,
            'latest': history[0] if history else None, 'running': [j for j in history if j.status == 'Running'],
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
    label = _VOICE_SEV_LABEL.get(sev, '')
    link = lambda url: {'link': url, 'link_label': say('ดูรายละเอียด', 'See details')}
    no_data = {'answer': say('ยังไม่มีข้อมูลการสแกน', 'There is no scan data yet.')}
    nodev = len(f['devices'])
    vuln_scanned = any(d['vuln_scanned'] for d in f['devices'].values())

    if fact == 'running_scans':
        n = len(f['running'])
        if not n:
            return {'answer': say('ไม่มีสแกนที่กำลังทำงานอยู่', 'No scan is running right now.'), **link(url_for('tasks_page'))}
        names = ', '.join('%s (%s)' % (j.target, SCAN_TYPE_LABELS.get(j.scan_type, j.scan_type or '')) for j in f['running'][:5])
        return {'answer': say('กำลังสแกนอยู่ %d งาน: %s' % (n, names), '%d scan(s) running: %s' % (n, names)), **link(url_for('tasks_page'))}

    if fact == 'next_schedule':
        due = sorted((x for x in f['schedules'] if x.next_run), key=lambda x: x.next_run)
        if not due:
            return {'answer': say('ไม่มีการตั้งเวลาสแกนที่เปิดใช้งานอยู่', 'There is no active scheduled scan.'), **link(url_for('tasks_page'))}
        x = due[0]
        when = x.next_run.strftime('%Y-%m-%d %H:%M')
        what = '%s (%s, %s)' % (x.name, x.target, SCAN_TYPE_LABELS.get(x.scan_type, x.scan_type or ''))
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
        kind = SCAN_TYPE_LABELS.get(j.scan_type, j.scan_type or '')
        when = j.timestamp.strftime('%Y-%m-%d %H:%M') if j.timestamp else '-'
        text = say('สแกนล่าสุด: %s (%s) สถานะ %s เมื่อ %s' % (j.target, kind, _VOICE_STATUS_TH.get(j.status, j.status), when),
                   'Latest scan: %s (%s), %s, at %s' % (j.target, kind, j.status, when))
        if hosts is not None:
            text += say(' พบ %d อุปกรณ์' % hosts, ', %d device(s) found' % hosts)
        return {'answer': text, **link(url_for('scan_detail', scan_id=j.id) if j.status == 'Completed' else url_for('tasks_page'))}

    if fact == 'count_ports':
        return {'answer': say('พอร์ตที่เปิดอยู่ %d พอร์ต (นับเลขพอร์ตไม่ซ้ำ จากทุกการสแกน)' % len(f['ports']),
                              '%d distinct open ports across all scans.' % len(f['ports'])), **link(url_for('dashboard'))}

    if fact == 'count_devices':
        if not sev:
            return {'answer': say('พบอุปกรณ์ทั้งหมด %d เครื่อง (จากทุกการสแกน)' % nodev, '%d device(s) found across all scans.' % nodev), **link(url_for('devices_page'))}
        n = sum(1 for d in f['devices'].values() if sev.upper() in d['sevs'])
        text = say('%d เครื่องมี CVE ระดับ %s อย่างน้อย 1 รายการ' % (n, label), '%d device(s) have at least one %s CVE.' % (n, label))
        if not vuln_scanned:
            text += say(' (ยังไม่เคยสแกนช่องโหว่ จึงยังไม่มีข้อมูล CVE)', ' (No vulnerability scan has been run yet, so there is no CVE data.)')
        return {'answer': text, **link(url_for('vulnerabilities_page'))}

    if fact == 'count_cves':
        b, total = f['cves_by_sev'], len(f['cves'])
        if sev:
            n = b.get(sev.upper(), 0)
            text = say('CVE ระดับ %s มี %d รายการ จากทั้งหมด %d รายการ (ไม่ซ้ำกัน)' % (label, n, total), '%d %s CVE(s) out of %d distinct CVEs.' % (n, label, total))
        else:
            other = sum(n for k, n in b.items() if k not in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
            parts = 'Critical %d, High %d, Medium %d, Low %d' % (b.get('CRITICAL', 0), b.get('HIGH', 0), b.get('MEDIUM', 0), b.get('LOW', 0))
            if other:
                parts += say(', อื่น ๆ %d' % other, ', other %d' % other)
            text = say('พบ CVE ทั้งหมด %d รายการ (ไม่ซ้ำกัน): %s' % (total, parts), '%d distinct CVEs: %s' % (total, parts))
        if not vuln_scanned:
            text += say(' (ยังไม่เคยสแกนช่องโหว่ จึงยังไม่มีข้อมูล CVE)', ' (No vulnerability scan has been run yet, so there is no CVE data.)')
        return {'answer': text, **link(url_for('vulnerabilities_page'))}

    if fact == 'devices_with_cves':
        want = sev.upper() if sev else None
        ips = sorted((ip for ip, d in f['devices'].items() if (want in d['sevs'] if want else d['has_cve'])), key=_ip_sort_key)
        what = label + ' ' if label else ''
        if not ips:
            text = say('ไม่พบอุปกรณ์ที่มี CVE %sระดับนี้' % ('ระดับ ' + label + ' ' if label else ''), 'No device has a %sCVE.' % what)
            if not vuln_scanned:
                text += say(' (ยังไม่เคยสแกนช่องโหว่)', ' (No vulnerability scan has been run yet.)')
            return {'answer': text, **link(url_for('vulnerabilities_page'))}
        shown = ', '.join(ips[:10])
        more = len(ips) - 10
        text = say('%d เครื่องมี CVE %s: %s' % (len(ips), ('ระดับ ' + label) if label else '', shown), '%d device(s) with a %sCVE: %s' % (len(ips), what, shown))
        if more > 0:
            text += say(' และอีก %d เครื่อง' % more, ' and %d more' % more)
        return {'answer': text, 'items': ips[:10], **link(url_for('vulnerabilities_page'))}

    return no_data


def _voice_system_prompt(lang, page_context):
    """The prompt for a question the parser did not recognise. Unlike the typed chat's it has NO scan ability: a voice request can only
    start a scan through the confirmation card."""
    return f"""คุณคือ CLYLAR Assistant ผู้ช่วยสำหรับระบบ CLYLAR Network Scanner ผู้ใช้กำลังถามด้วยเสียง
ตอบสั้น กระชับ ฟังง่าย (ไม่เกิน 3-4 ประโยค ไม่ใช้ตาราง) ตอบเป็นภาษา{'อังกฤษ' if lang == 'en' else 'ไทย'}ตามที่ผู้ใช้พูด

=== ตัวเลขที่ระบบคำนวณแล้ว (แม่นยำ ตรงกับหน้า Dashboard) ===
{_voice_figures_text()}

=== หน้าที่ผู้ใช้กำลังดูอยู่ ===
{page_context or '(ไม่ทราบ)'}

=== ข้อมูลระบบ (แสดงเพียง Scan ล่าสุด 20 รายการ และ CVE 20 รายการแรก) ===
{_build_app_context()}

กติกา:
- ถ้าตัวเลขในส่วน "ตัวเลขที่ระบบคำนวณแล้ว" ขัดกับรายการด้านล่าง ให้เชื่อส่วนตัวเลขที่คำนวณแล้ว
- คุณสั่ง Scan เองไม่ได้ ถ้าผู้ใช้อยากสแกน ให้บอกให้พูดว่า "scan <IP>" เช่น "scan 192.168.1.1"
- ถ้าไม่มีข้อมูลในระบบ ให้บอกตรงๆ ว่าไม่พบ อย่าเดา
- น้ำเสียงสุภาพ เป็นกลาง ไม่ใช้ emoji หรือสัญลักษณ์ตกแต่ง"""


def _strip_scan_marker(reply):
    """The voice AI is told it cannot scan, but if it writes a scan command anyway (##SCAN_CMD## + a JSON line) it is cut out and ignored."""
    return re.sub(r'##SCAN_CMD##[^\n]*(\n\s*\{[^\n]*\})?', '', str(reply or '')).replace('##SCAN_CMD##', '').strip()


@app.route('/api/voice/ask', methods=['POST'])
@admin_required
def api_voice_ask():
    """A spoken question the parser did not recognise, for the AI. Body: {text, lang, page_context}. It can never start a scan."""
    data = request.get_json(silent=True) or {}
    lang = _voice_lang(data)
    text = str(data.get('text') or '').strip()[:300]
    if not voice_commands.worth_asking_ai(text):
        return jsonify({'status': 'too_short', 'message': voice_commands.not_understood(text, lang)['message']})
    if not ai_enabled():
        return jsonify({'status': 'ai_off', 'message': AI_OFF_TEXT['en' if lang == 'en' else 'th']})
    try:
        reply = _call_gemini(_voice_system_prompt(lang, str(data.get('page_context') or '')[:1000]),
                             [{'role': 'user', 'content': text}], max_tokens=600, source='voice')
    except AIDisabled:
        return jsonify({'status': 'ai_off', 'message': AI_OFF_TEXT['en' if lang == 'en' else 'th']})
    except Exception as e:
        err = str(e)
        if 'NO_API_KEY' in err:
            msg = ('ยังไม่ได้ตั้งค่าคีย์ API ของ Gemini ผู้ดูแลระบบระดับสูงสุดตั้งได้ที่หน้าตั้งค่า', 'The Gemini API key is not set. A superadmin can set it in Settings.')
        elif '429' in err:
            msg = ('AI ถูกใช้งานเยอะเกินไป กรุณารอสักครู่', 'The AI is busy (quota). Please wait a moment.')
        elif '401' in err or '403' in err or '400' in err or 'leaked' in err.lower():
            msg = ('คีย์ API ของ Gemini ไม่ถูกต้องหรือไม่มีสิทธิ์', 'The Gemini API key is not valid or not allowed.')
        else:
            msg = ('เรียก AI ไม่สำเร็จ ลองใหม่อีกครั้ง', 'The AI call failed. Please try again.')
        return jsonify({'status': 'error', 'message': msg[1 if lang == 'en' else 0]})
    return jsonify({'status': 'ok', 'reply': _strip_scan_marker(reply) or ('ไม่มีคำตอบ' if lang != 'en' else 'No answer.'), 'source': 'ai'})


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

    new_job = ScanJob(
        target=target, scan_type=scan_type, scan_name=say('สั่งด้วยเสียง', 'Voice command'),
        status='Queued', triggered_by='chatbot', owner_id=current_user.id,
        multicast=False if scan_type == 'discovery' else None)
    db.session.add(new_job)
    if not SavedTarget.query.filter_by(target=target).first():
        db.session.add(SavedTarget(target=target))
    db.session.commit()
    if not enqueue_scan(new_job):
        return jsonify({'status': 'error', 'message': say('เริ่มสแกนไม่ได้', 'Could not start the scan.')}), 500
    label = SCAN_TYPE_LABELS[scan_type]
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

    messages     = data.get('messages', [])
    page_context = data.get('page_context', '')   # ส่งมาจาก JS ทุก request

    # ดึงข้อมูลจริงของแอพแบบ real-time
    app_context = _build_app_context()

    SYSTEM_PROMPT = f"""คุณคือ CLYLAR Assistant ผู้ช่วย AI สำหรับระบบ CLYLAR Network Scanner
คุณมีสิทธิ์เข้าถึงข้อมูลจริงของระบบที่อัปเดตล่าสุด และรู้ว่าผู้ใช้กำลังดูหน้าไหน

=== ข้อมูลหน้าที่ผู้ใช้กำลังดูอยู่ ===
{page_context if page_context else '(ไม่ทราบหน้าปัจจุบัน)'}

=== ข้อมูลระบบ ===
{app_context}

=== ความสามารถพิเศษ: สั่ง Scan ===
คุณสามารถสั่ง Scan Network ได้โดยตรงผ่าน chatbot
เมื่อผู้ใช้ต้องการ scan ให้ตอบกลับด้วย JSON format พิเศษดังนี้ (ต้องเป็น JSON บรรทัดแรกสุด):
##SCAN_CMD##
{{"action":"scan","target":"<IP_OR_HOST>","scan_type":"<TYPE>","scan_name":"<NAME_OPTIONAL>"}}

ประเภท scan ที่รองรับ:
- fast_scan     → Fast Scan (เร็ว แนะนำสำหรับสแกนทั่วไป)
- discovery     → Discovery (ค้นหา host ในเครือข่าย)
- intense       → Intense Scan (ละเอียด ใช้เวลานาน)
- vuln_scan     → Vulnerability Scan CVE (ตรวจช่องโหว่)

ตัวอย่าง: ถ้าผู้ใช้พูดว่า "scan 192.168.1.1" หรือ "สแกน 10.0.0.1 แบบ intense"
ให้ตอบ:
##SCAN_CMD##
{{"action":"scan","target":"192.168.1.1","scan_type":"fast_scan"}}
แล้วตามด้วยข้อความอธิบาย

ถ้าผู้ใช้ไม่ได้ระบุ scan_type ให้ใช้ fast_scan เป็นค่าเริ่มต้น
ถ้าผู้ใช้ไม่ได้ระบุ target ให้ถามก่อน อย่าเดา

=== แนวทางตอบ ===
- ใช้ข้อมูลจริงจากระบบและหน้าปัจจุบันในการตอบ
- ตอบเป็นภาษาไทยเป็นหลัก ถ้าผู้ใช้ถามภาษาอังกฤษก็ตอบภาษาอังกฤษได้
- ตอบสั้นกระชับ ชัดเจน สุภาพ น้ำเสียงเป็นกลางแบบผู้ช่วยในระบบ ไม่ใช้ emoji หรือสัญลักษณ์ตกแต่ง
- ถ้าถามเรื่องที่ไม่มีข้อมูลในระบบ ให้บอกตรงๆ ว่าไม่พบข้อมูล"""

    try:
        reply = _call_gemini(SYSTEM_PROMPT, messages, max_tokens=900)

        # ตรวจว่า Gemini ต้องการสั่ง scan หรือไม่
        scan_result = None
        clean_reply = reply
        if '##SCAN_CMD##' in reply:
            try:
                parts = reply.split('##SCAN_CMD##', 1)
                json_and_rest = parts[1].strip()
                # หา JSON block (บรรทัดแรก)
                first_line_end = json_and_rest.find('\n')
                json_str = json_and_rest if first_line_end < 0 else json_and_rest[:first_line_end]
                json_str = json_str.strip()
                cmd = json.loads(json_str)

                if cmd.get('action') == 'scan' and current_user.is_any_admin:
                    target    = cmd.get('target', '').strip()
                    scan_type = cmd.get('scan_type', 'fast_scan').strip()
                    scan_name = cmd.get('scan_name', '').strip() or None
                    if scan_type not in VALID_SCAN_TYPES:
                        scan_type = 'fast_scan'

                    if target:
                        # รัน scan จริง
                        new_job = ScanJob(
                            target=target, scan_type=scan_type, scan_name=scan_name,
                            status='Queued', triggered_by='chatbot',
                            owner_id=current_user.id,
                            multicast=False if scan_type == 'discovery' else None
                        )
                        db.session.add(new_job)
                        if not SavedTarget.query.filter_by(target=target).first():
                            db.session.add(SavedTarget(target=target))
                        db.session.commit()

                        # The scan runs in the background: the card says it was accepted (the results are on the Tasks page when it is done).
                        if enqueue_scan(new_job):
                            scan_result = {'status': 'started', 'job_id': new_job.id, 'seq': _job_seq(new_job),
                                           'target': target, 'scan_type': scan_type}
                        else:
                            scan_result = {'status': 'failed', 'job_id': new_job.id, 'error': 'เริ่มสแกนไม่ได้ กรุณาลองใหม่อีกครั้ง'}

                # ตัด ##SCAN_CMD## + JSON ออกจาก reply ที่แสดง
                rest_text = json_and_rest[first_line_end:].strip() if first_line_end >= 0 else ''
                pre_text  = parts[0].strip()
                clean_reply = (pre_text + '\n' + rest_text).strip()
            except Exception:
                pass  # ถ้า parse ไม่ได้ ใช้ reply ปกติ

        return jsonify({'reply': clean_reply, 'scan_result': scan_result, 'source': 'ai'})

    except ValueError as e:
        if 'NO_API_KEY' in str(e):
            return jsonify({'kind': 'warn', 'reply': 'ยังไม่ได้ตั้งค่าคีย์ API ของ Gemini ผู้ดูแลระบบระดับสูงสุดตั้งได้ที่หน้าตั้งค่า'}), 200
    except Exception as e:
        err = str(e)
        if 'QUOTA_429' in err:
            return jsonify({'kind': 'warn', 'reply': 'Gemini API เต็ม quota ชั่วคราว กรุณารอสักครู่'}), 200
        if '429' in err:
            return jsonify({'kind': 'warn', 'reply': 'AI ถูกใช้งานเยอะเกินไป กรุณารอสักครู่'}), 200
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

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


if __name__ == '__main__':
    # reloader_type='stat': the auto-reloader decides a file changed by its modification time. The default on a machine that has `watchdog` installed
    # (streamlit pulls it in) is the watchdog reloader, which on Windows also reports a file being merely READ (its last-access time) as a change and
    # restarts the server. The first PDF export imports xhtml2pdf and dozens of stdlib files lazily, so it restarted the server in the middle of the
    # request: "The connection was reset". A real edit still reloads.
    app.run(debug=True, reloader_type='stat')
