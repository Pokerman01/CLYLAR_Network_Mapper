from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Bangkok")

def now_th():
    return datetime.now(TZ).replace(tzinfo=None)

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    # role: 'superadmin' | 'admin' | 'user'
    role = db.Column(db.String(20), default='user')
    # admin ที่สร้าง user/admin คนนี้
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=now_th)

    subordinates = db.relationship('User', backref=db.backref('creator', remote_side=[id]),
                                   foreign_keys=[created_by])

    @property
    def is_superadmin(self):
        return self.role == 'superadmin'

    @property
    def is_any_admin(self):
        return self.role in ('admin', 'superadmin')


class ScanJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_name = db.Column(db.String(150), nullable=True)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50))
    status = db.Column(db.String(20), default='Running')
    timestamp = db.Column(db.DateTime, default=now_th)
    result_data = db.Column(db.Text)
    triggered_by = db.Column(db.String(20), default='manual')
    # admin/superadmin ที่เป็นเจ้าของ scan นี้
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    # -T0..-T4 และ --version-intensity 0-9 ที่ใช้จริงตอนสแกน (NULL = ใช้ค่า default ของ scan_type นั้น)
    timing = db.Column(db.Integer, nullable=True)
    version_intensity = db.Column(db.Integer, nullable=True)
    # Custom scans: the arguments the user typed. Discovery: whether it also listened for mDNS/SSDP.
    # NULL = not recorded (a job from before this existed, or a setting that scan type does not have).
    custom_args = db.Column(db.String(500), nullable=True)
    multicast = db.Column(db.Boolean, nullable=True)
    # when the scan stopped (Completed or Failed); NULL while it runs and for jobs from before this was recorded
    finished_at = db.Column(db.DateTime, nullable=True)
    # when a worker started running the scan. `timestamp` is when the job was created (it also fixes the job's "Job #N" place and must never
    # change), and a queued job can wait before it runs. NULL = not recorded (a job from before the queue existed, or one still waiting).
    started_at = db.Column(db.DateTime, nullable=True)
    # -Pn ("treat all hosts as online") was used: True / False. NULL for Discovery, XML imports and jobs from before the option existed
    # (those did not use it).
    skip_ping = db.Column(db.Boolean, nullable=True)
    # "Scan all ports 1-65535" was used: True / False. NULL for Discovery, Custom, XML imports and jobs from before the option existed
    # (those scanned the scan type's usual port list).
    all_ports = db.Column(db.Boolean, nullable=True)
    # "Do not look up device names through DNS" (-n) was used: True / False. NULL for Custom scans, XML imports and jobs from before the option
    # existed (those looked names up).
    no_dns = db.Column(db.Boolean, nullable=True)
    # "Find devices that ignore ping" (host-discovery probes) and the Gentle scan were used: True / False. NULL for Custom scans, XML imports (and Gentle for
    # Discovery) and for jobs from before the options existed (those used neither).
    host_probes = db.Column(db.Boolean, nullable=True)
    gentle = db.Column(db.Boolean, nullable=True)
    # Also scan the common UDP ports (a second nmap run on the hosts found up): True / False for Intense and Vulnerability scans, NULL for the other types
    # and for jobs from before the option existed (those did no UDP).
    udp = db.Column(db.Boolean, nullable=True)
    # What the scan reported about the run itself, as JSON text (see scanner.finish_scan / capture_run): nmap version, how many addresses it
    # checked and how many answered, whether it had Administrator rights, devices only this PC's ARP table knew. NULL = not recorded.
    scan_info = db.Column(db.Text, nullable=True)

    owner = db.relationship('User', foreign_keys=[owner_id])


class AppSetting(db.Model):
    """A setting for the whole app, as key / text value (a new table, so db.create_all() adds it to an existing database).
    Keys in use: 'ai_enabled' ('1' / '0': whether the chatbot may call Gemini at all; missing = on);
    'chat_button_hidden.<user id>' ('1' = that admin hid the floating chat button; missing = shown)."""
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.String(500), nullable=True)
    updated_at = db.Column(db.DateTime, default=now_th, onupdate=now_th)


class GeminiCall(db.Model):
    """One row per call to the Gemini API, so the real usage can be seen on the Settings page. The token counts are the ones Google
    reports back (usageMetadata); NULL when a call failed before it got an answer."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=now_th, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    source = db.Column(db.String(10))                 # 'typed' (the chat box) or 'voice'
    ok = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(200), nullable=True)  # 'OK', or why it failed
    model = db.Column(db.String(60), nullable=True)
    prompt_tokens = db.Column(db.Integer, nullable=True)
    output_tokens = db.Column(db.Integer, nullable=True)
    thinking_tokens = db.Column(db.Integer, nullable=True)
    total_tokens = db.Column(db.Integer, nullable=True)


class HistoryQuery(db.Model):
    """A query of the History page's advanced filter. Every search is kept as a "recent" one (the newest 10 per user); one the user
    names and saves has is_saved set and stays until they delete it. `criteria` is the JSON the filter builder produces."""
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    criteria = db.Column(db.Text, nullable=False)
    is_saved = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now_th)
    last_used_at = db.Column(db.DateTime, default=now_th)


class SavedTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(100), unique=True, nullable=False)
    label = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=now_th)


class ScheduledScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(100), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    cron_hour = db.Column(db.Integer, nullable=False)
    cron_minute = db.Column(db.Integer, default=0)
    repeat = db.Column(db.String(20), default='daily')
    day_of_week = db.Column(db.Integer, nullable=True)
    day_of_month = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=now_th)
    last_run = db.Column(db.DateTime, nullable=True)
    next_run = db.Column(db.DateTime, nullable=True)
    # custom nmap args สำหรับ scan_type == 'custom'
    custom_args = db.Column(db.String(500), nullable=True)
    # -T0..-T4 และ --version-intensity 0-9 (NULL = ใช้ค่า default ของ scan_type นั้น)
    timing = db.Column(db.Integer, nullable=True)
    version_intensity = db.Column(db.Integer, nullable=True)
    skip_ping = db.Column(db.Boolean, nullable=True)       # -Pn, see ScanJob.skip_ping
    all_ports = db.Column(db.Boolean, nullable=True)       # see ScanJob.all_ports
    no_dns = db.Column(db.Boolean, nullable=True)          # see ScanJob.no_dns
    host_probes = db.Column(db.Boolean, nullable=True)     # see ScanJob.host_probes
    gentle = db.Column(db.Boolean, nullable=True)          # see ScanJob.gentle
    udp = db.Column(db.Boolean, nullable=True)             # see ScanJob.udp
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    # owner ของ schedule (admin/superadmin)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
