"""Everything the scan report (templates/scan_report.html) shows, worked out from ONE stored scan.

Pure functions: no Flask, no database, no I/O. `build_report()` takes plain values and returns a plain dict, so it can be tested
with synthetic scans (test_report_builder.py) and the template only has to draw what it is given.

The report has five sections: 1 summary (page 1, fixed), 2 findings (the CVE table and the per-host table, starts on page 2 and may flow),
3 network diagram, 4 asset inventory (may flow), 5 appendix (fixed). Their data is `summary`, `findings`, the diagram's own script,
`groups` and `appendix` in the dict `build_report()` returns.

The rule behind every number and label here is the owner's: if the app does not know a thing, the report says "ยังไม่ทราบ" /
"ไม่ได้บันทึกไว้" or leaves it out. It never fills the gap with a guess:
  * a host is "ไม่พบ CVE" only when EVERY open service of it was really looked up and the lookup answered (`cve_status` 'ok');
  * a scan that never looked for CVEs (Fast, Discovery, ...) gives "ยังไม่ทราบ", not "ปกติ";
  * device types come from scanner.guess_device_type() and are always shown as a guess ("คาดเดา" when the evidence is thin);
  * "N IP" scanned is shown only when the target can be counted exactly or nmap said so;
  * a sentence about the run (no Administrator rights, no Npcap, -Pn, the ARP cache) is written only when the run recorded that fact.
"""
import ipaddress
import re

from cwe_data import cwe_info
from scanner import (ALL_PORTS_HOST_TIMEOUT, UDP_HOST_TIMEOUT, UDP_PORTS, UDP_TOP_CHOICES, describe_scan_settings, effective_severity, guess_device_type, os_match_accuracy,
                     port_reason, port_reason_label, udp_host_timeout, virtual_machine_platform)

SYSTEM_NAME = 'Clylar'

# risk levels, in the order the report shows them
LEVELS = [
    ('high', 'สูง'),
    ('med', 'ปานกลาง'),
    ('low', 'ต่ำ'),
    ('none', 'ไม่พบ CVE'),
    ('unknown', 'ยังไม่ทราบ'),
]
LEVEL_LABEL = dict(LEVELS)
_SEV_TO_LEVEL = {'CRITICAL': 'high', 'HIGH': 'high', 'MEDIUM': 'med', 'LOW': 'low', 'UNKNOWN': 'low', '': 'low'}   # UNKNOWN ranks with Low, like the dashboard
_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
_LEVEL_RANK = {'high': 3, 'med': 2, 'low': 1}

TYPE_LABEL = {
    'router': 'Router / Gateway', 'vm': 'เครื่องเสมือน (VM)', 'computer': 'คอมพิวเตอร์', 'phone': 'โทรศัพท์ / แท็บเล็ต',
    'printer': 'เครื่องพิมพ์', 'camera': 'กล้อง IP', 'tv': 'Smart TV', 'iot': 'อุปกรณ์ IoT', 'unknown': 'ไม่ทราบ',
}

def _minutes(spec):
    """'45m' -> 45: the per-host limits the scanner puts on nmap, so the words below say the number the scanner really uses. Anything else gives None and
    the number is left out of the sentence (never a made-up one)."""
    m = re.fullmatch(r'(\d{1,3})m', str(spec or ''))
    return int(m.group(1)) if m else None


HOST_MIN = _minutes(ALL_PORTS_HOST_TIMEOUT)           # nmap --host-timeout of "scan all ports" and of Gentle (the same 45 minutes)
UDP_MIN = _minutes(UDP_HOST_TIMEOUT)                  # nmap --host-timeout of the UDP run of the 12 common ports (a top-N run has its own: udp_host_timeout(top))
N_UDP_PORTS = len(UDP_PORTS)
UDP_PORT_LIST = ', '.join(str(p) for p in UDP_PORTS)
MAX_UDP_PORTS = 65535                                 # the largest UDP port count a recorded `udp_ports` may have (anything above is not a count of ports)
UDP_UNLISTED_NOTE = 'nmap ไม่แสดงรายพอร์ต'               # said after every count that nmap printed only as a total (udp_unlisted)
# The scan report page's own words for a host that ran out of its --host-timeout (locales scan.host_timeout): the host's ports were never read.
HOST_TIMEOUT_TEXT = 'หมดเวลาต่อเครื่อง' + (f' ({HOST_MIN} นาที)' if HOST_MIN else '') + ' ไม่ทราบพอร์ต'


def _udp_timeout_text(minutes):
    """'ใช้เวลาสแกน UDP เกิน 10 นาที': the host ran out of the UDP run's --host-timeout (10 minutes for the 12 common ports, 15 for the top 100, 45 for the top 1000)."""
    return 'ใช้เวลาสแกน UDP เกิน' + (f' {minutes} นาที' if minutes else 'เวลาที่กำหนด')


UDP_TIMEOUT_TEXT = _udp_timeout_text(UDP_MIN)
UDP_FAILED_TEXT = 'รอบสแกน UDP ทำงานไม่สำเร็จ'
UDP_UNKNOWN_TEXT = 'ไม่ทราบพอร์ต UDP'                  # said wherever "ไม่พบ CVE" is said for a host whose UDP result is unknown (its TCP ports were looked up)
UDP_NOT_SCANNED_TEXT = 'ไม่ได้สแกน UDP (เป็นที่อยู่ที่ไม่ใช่ IPv4 หรือ nmap ไม่รายงานผล)'
UDP_SECOND_RUN_TARGETS = '<อุปกรณ์ที่รอบแรกพบว่าออนไลน์>'     # the Tasks page's own placeholder for the hosts of the UDP run (they are only known when the first run is over)
MAX_UDP_ERROR = 120                                   # characters of nmap's own reason for a failed UDP run that are printed (the app keeps 200)


def _timed_out_hosts(n):
    return f'ไม่ทราบพอร์ตเพราะหมดเวลา {n} เครื่อง'

STEP_TEXT = {
    'nvd_lookup': 'ค้นหา CVE จาก NVD ตามชื่อและเวอร์ชันของบริการที่พบ',
    'mdns_ssdp': 'ฟังการตอบกลับ mDNS / SSDP ระหว่างสแกน',
    'gateway_probe': 'ตรวจหา default gateway ของเครื่องที่สแกน',
    'udp_pass': f'รอบที่ 2: สแกน UDP {N_UDP_PORTS} พอร์ตที่พบบ่อยกับอุปกรณ์ที่รอบแรกพบว่าออนไลน์',      # the Tasks page's words
}


def _udp_tier(settings, facts):
    """What the UDP second run of THIS scan looked at (so no sentence says "12 ports" about a top-N run): {'top': None | 100 | 1000, 'n': ports, 'minutes': per-host limit}.
    top is 100 or 1000 only when the job recorded it with the UDP option on (settings['udp_top'], already checked by scanner.describe_scan_settings); None is the 12 common
    ports, also every job from before the choice, and then n and minutes are the old constants. n for a top-N run is the number of UDP ports nmap really scanned
    (facts['udp_ports'], it follows the installed nmap-services) when the run recorded one that makes sense, else the number that was asked for. minutes is
    nmap's --host-timeout of that tier (scanner.udp_host_timeout), None when it cannot be read (the sentence then leaves the number out)."""
    top = settings.get('udp_top') if settings.get('udp') is True and settings.get('udp_top') in UDP_TOP_CHOICES else None
    if top is None:
        return {'top': None, 'n': N_UDP_PORTS, 'minutes': UDP_MIN}
    n = facts.get('udp_ports')
    n = n if isinstance(n, int) and not isinstance(n, bool) and 0 < n <= min(MAX_UDP_PORTS, top) else top      # a top-N run never scans more than N
    return {'top': top, 'n': n, 'minutes': _minutes(udp_host_timeout(top))}


def _udp_step_text(tier):
    """The words of the 'udp_pass' step in appendix A, for the range this scan used."""
    if not tier['top']:
        return STEP_TEXT['udp_pass']
    return f"รอบที่ 2: สแกนพอร์ต UDP {tier['n']:,} อันดับแรกของ nmap กับอุปกรณ์ที่รอบแรกพบว่าออนไลน์ โดยไม่ตรวจเวอร์ชันของบริการ"


STATUS_NOTICE = {
    'Failed': 'งานสแกนนี้ล้มเหลว ผลที่แสดงอาจไม่สมบูรณ์หรือไม่มีเลย',
    'Cancelled': 'งานสแกนนี้ถูกยกเลิก ผลที่แสดงอาจไม่สมบูรณ์',
    'Running': 'งานสแกนนี้ยังทำงานอยู่ ผลที่แสดงเป็นเพียงบางส่วน',
}

MAX_PORT_LINES = 14      # open ports listed per host in the inventory (the rest become "+N พอร์ต")
MAX_NOT_OPEN_GROUPS = 3   # (state, reason) groups named in the 'ports that are not open' line of an inventory row; the rest become '+N กลุ่ม'
MAX_STATE_TEXT = 24      # longest port state printed (nmap's own are under 15 characters; anything longer is cut)
MAX_HOSTS_IN_TIP = 12    # hosts named in a chart row's tooltip / a tile's note
MAX_RUN_SUMMARY = 200     # longest 'how many IP nmap checked' line kept (the real ones are under 100 characters)
MAX_FINDING_ROWS = 40    # rows of the findings table: every Critical and High row is ALWAYS shown, Medium / Low / Unknown rows fill up to this many in total
MAX_HOST_ROWS = 20       # hosts of the per-host table on page 2 (the worst first, the rest become "และอีก N host")
MAX_CHANGE_ITEMS = 8     # items per list in "changes since the previous scan" (appendix B); "+N" says how many more there are
MAX_CHANGE_LINES = 8     # printed lines of ALL lists of appendix B together (a list of devices is one paragraph, about 4 to a line). The appendix is one fixed
                         # page; with 8 lines even five long lists keep every heading, its true count and at least one item, at a readable zoom
MAX_FINDING_DESC = 120   # characters of NVD's description kept in a findings row (the scanner stores at most 300)
TOP_FINDINGS = 3         # rows of "ควรตรวจสอบก่อน" on page 1
MAX_MATCH_EXAMPLES = 3   # ports named as examples in the match note on page 2
MAX_WHO = 40             # longest owner name printed
MAX_TARGET_TEXT = 400    # longest target text printed on page 1; a longer one is cut WITH a marker saying so (a 90-network target made page 1 two pages)
MAX_COMMAND_TEXT = 400   # the same for the printed nmap command (it holds the target too)
MAX_NAME_TEXT = 150      # the same for the scan name in the header band (the database column holds 150)


# ---------------------------------------------------------------- small helpers
def _ip(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


# Private-use space only. Python's ip.is_private is wider (it also covers documentation ranges such as 203.0.113.0/24 and other reserved
# blocks), which would put those on the "internal" side although they are not addresses of an internal network.
_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7')]


def _scope(ip_obj):
    """'internal' for private-use, loopback and link-local addresses, 'external' for the rest, 'unknown' when it is not an IP."""
    if ip_obj is None:
        return 'unknown'
    if ip_obj.is_loopback or ip_obj.is_link_local or any(ip_obj in net for net in _PRIVATE_NETS if net.version == ip_obj.version):
        return 'internal'
    return 'external'


def _fmt_dt(d):
    return d.strftime('%Y-%m-%d %H:%M:%S') if d else ''


def _duration_text(seconds):
    if seconds is None or seconds < 0:
        return ''
    if seconds < 60:
        return f'{seconds} วินาที'
    m, s = divmod(seconds, 60)
    if m < 60:
        return f'{m} นาที {s} วินาที'
    h, m = divmod(m, 60)
    return f'{h} ชั่วโมง {m} นาที'


def target_address_count(target):
    """How many addresses a target covers, or None when that cannot be counted exactly (then the report shows no "/ N IP").
    Understands single IPs, CIDR blocks and a last-octet range (192.168.1.10-50), separated by spaces or commas."""
    tokens = [t for t in re.split(r'[\s,]+', (target or '').strip()) if t]
    if not tokens:
        return None
    total = 0
    for tok in tokens:
        try:
            if '/' in tok:
                net = ipaddress.ip_network(tok, strict=False)
                if net.version != 4:
                    return None
                total += net.num_addresses
            elif '-' in tok and tok.count('.') == 3:
                head, tail = tok.rsplit('-', 1)
                first = ipaddress.ip_address(head)
                last = int(tail)
                last_start = int(head.rsplit('.', 1)[1])
                if first.version != 4 or not tail.isdigit() or last < last_start or last > 255:
                    return None
                total += last - last_start + 1
            else:
                ipaddress.ip_address(tok)
                total += 1
        except ValueError:
            return None
    return total


def _hosts_text(ips):
    ips = list(ips)
    if not ips:
        return 'ไม่มี'
    shown = ', '.join(ips[:MAX_HOSTS_IN_TIP])
    return shown + (f' และอีก {len(ips) - MAX_HOSTS_IN_TIP}' if len(ips) > MAX_HOSTS_IN_TIP else '')


def _clip(text, n):
    text = ' '.join(str(text or '').split())
    return text if len(text) <= n else text[:n - 1].rstrip() + '…'


def _clip_marked(text, n):
    """Text for a fixed page: up to n characters as they are (whitespace folded); longer text is cut and SAYS so, with its true length. Never a silent cut."""
    text = ' '.join(str(text or '').split())
    return text if len(text) <= n else text[:n].rstrip() + f' … (แสดงบางส่วน, {len(text)} ตัวอักษร)'


def _run_summary(run):
    """The scan's own line about how many IP addresses nmap checked ("ตรวจ 256 IP · ตอบกลับ 12 · ไม่ตอบ 244"), from app.describe_run()'s 'summary'.
    Only real text counts: anything else (a missing run, no key, a number, a list) gives '' and the page shows nothing, never a zero or a guess.
    It stays plain text (the template escapes it); line breaks are folded and it is cut at MAX_RUN_SUMMARY."""
    text = run.get('summary') if isinstance(run, dict) else None
    return _clip(text, MAX_RUN_SUMMARY) if isinstance(text, str) else ''


# ---------------------------------------------------------------- per host
def _is_open(p):
    return isinstance(p, dict) and str(p.get('state') or '').lower() == 'open'


def _port_number(p):
    """The port as a number for sorting; text that is not a number sorts as 0 (the report must never fail on stored text)."""
    try:
        return int(p.get('port') or 0)
    except (TypeError, ValueError):
        return 0


def _product(p):
    v = str(p.get('version_info') or '').strip()
    return '' if v in ('', 'Unknown Version') else v


def _port_status(p):
    """'ok' / 'failed' / 'no_product' / 'unrecorded' for an open port, from its stored cve_status. A scan from before the field existed has none
    ("not recorded", never a guess), except that an old open port with no product name is still known to have had nothing to search for.
    An old record that already holds CVEs was evidently looked up, so it counts as evaluated."""
    st = p.get('cve_status')
    if st in ('ok', 'failed', 'no_product'):
        return st
    if p.get('cves'):
        return 'ok'
    return 'no_product' if not _product(p) else 'unrecorded'


def _score(c):
    try:
        return float(c.get('cvss_score'))
    except (TypeError, ValueError):
        return None


def _kev_of(c):
    """True / False only when the record really says so (NVD answered: listed or not in CISA's Known Exploited catalog); a record without the
    key, or with anything else, is "not recorded" (None) and gets no tag and no count."""
    k = c.get('kev')
    return k if isinstance(k, bool) else None


def _merge_kev(a, b):
    if a is True or b is True:
        return True
    if a is False or b is False:
        return False
    return None


def _sev_class(sev):
    return {'CRITICAL': 'crit', 'HIGH': 'high', 'MEDIUM': 'med', 'LOW': 'low'}.get(sev, 'unknown')


def _sev_name(sev):
    return {'CRITICAL': 'วิกฤต', 'HIGH': 'สูง', 'MEDIUM': 'ปานกลาง', 'LOW': 'ต่ำ'}.get(sev, 'ไม่ทราบ')


def _ip_sort(ip):
    o = _ip(ip)
    return (o.version, int(o), '') if o else (9, 0, str(ip))


def _host_cves(open_ports):
    """The host's CVEs, one entry per CVE id (the highest score wins), the worst first."""
    best = {}
    for p in open_ports:
        for c in (p.get('cves') or []):
            if not isinstance(c, dict) or not c.get('cve_id'):
                continue
            sev = effective_severity(c)
            entry = {'id': str(c['cve_id']), 'score': _score(c), 'severity': sev, 'level': _SEV_TO_LEVEL.get(sev, 'low'), 'kev': _kev_of(c)}
            old = best.get(entry['id'])
            kev = _merge_kev(old['kev'], entry['kev']) if old else entry['kev']
            if old is None or (entry['score'] or -1) > (old['score'] or -1):
                best[entry['id']] = entry
            best[entry['id']]['kev'] = kev
    return sorted(best.values(), key=lambda e: (-_SEV_RANK.get(e['severity'], 0), -(e['score'] if e['score'] is not None else -1), e['id']))


def _sev_counts(cves):
    """{'critical', 'high', 'medium', 'low', 'unknown'} -> how many of these (distinct) CVEs; a label that is none of the four counts as unknown."""
    out = dict.fromkeys(('critical', 'high', 'medium', 'low', 'unknown'), 0)
    for c in cves:
        out[c['severity'].lower() if c['severity'] in _SEV_RANK else 'unknown'] += 1
    return out


def _max_text(cves):
    """'High 7.5' for the worst CVE of a host ('' when there is none); a CVSS v2-only 9.8 reads 'Critical 9.8' (effective_severity)."""
    if not cves:
        return ''
    top = cves[0]
    return _sev_name(top['severity']) + (f" {top['score']:.1f}" if top['score'] is not None else '')


def _count_of(value):
    """A positive whole number (not a bool), else 0: how many open ports nmap collapsed (`ports_unlisted`), read from stored text, so anything else is no claim."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _unlisted_tail(unlisted):
    return f'ไม่รวมพอร์ตที่เปิดอีก {unlisted:,} พอร์ตซึ่ง nmap ไม่ได้แยกรายงาน'


def _unlisted_only(unlisted):
    return f'มีพอร์ตที่เปิด {unlisted:,} พอร์ตซึ่ง nmap ไม่ได้แยกรายงาน'


def _eval_text(ports_known, n_open, n_ok, scan_type, timed_out=False, unlisted=0, udp_unknown=False):
    """How much of a host's open ports were really looked up for CVEs, in one phrase (page 2's host table and page 4's inventory).
    timed_out: the host ran out of nmap's per-host limit (its ports are unknown, which is not the same as "not scanned").
    unlisted: how many open ports nmap collapsed into one line without naming them (they were never looked up).
    udp_unknown: the host's UDP result is unknown (the UDP run failed, ran out of time or never covered it): its TCP ports were looked up, its UDP ports are not known."""
    if not ports_known:
        return 'หมดเวลา ไม่ทราบพอร์ต' if timed_out else 'ไม่ได้สแกนพอร์ต'
    udp = f' ({UDP_UNKNOWN_TEXT})' if udp_unknown else ''
    if n_open == 0:
        return (_unlisted_only(unlisted) if unlisted else 'ไม่มีพอร์ตที่เปิด') + udp
    if scan_type != 'vuln_scan' and n_ok == 0:
        return 'ไม่ได้ค้นหา CVE' + udp
    gaps = ([_unlisted_tail(unlisted)] if unlisted else []) + ([UDP_UNKNOWN_TEXT] if udp_unknown else [])
    return f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต' + (' (' + ' · '.join(gaps) + ')' if gaps else '')


def _host_risk(open_ports, cves, scan_type, ports_known=True, timed_out=False, unlisted=0, udp_unknown=False):
    """(level key, one-line reason). See the module docstring: only what was really checked is called "ไม่พบ CVE".
    ports_known False = the scan has no port list for this host (a Discovery scan never looks at ports): that is not "0 open".
    timed_out (with ports_known False): the host ran out of nmap's per-host limit, so its ports are unknown for that reason.
    unlisted: open ports nmap did not list one by one; they were never looked up, so a host is never "ไม่พบ CVE" while there are some.
    udp_unknown: the host's UDP result is unknown. Its level does NOT change (its TCP ports were evaluated, and the device page says the same), but where the
    answer is "ไม่พบ CVE" the reason says that UDP ports are not known.
    Callers that pass none of these get the old answer exactly (device_builder and the topology page call this with 3 or 4 arguments)."""
    if not ports_known and not cves:
        return 'unknown', (HOST_TIMEOUT_TEXT + ' จึงยังไม่ได้ตรวจ CVE') if timed_out else 'ไม่ได้สแกนพอร์ต จึงยังไม่ได้ตรวจ CVE'
    n_open = len(open_ports)
    statuses = [_port_status(p) for p in open_ports]
    n_ok = statuses.count('ok')
    if cves:
        level = max((c['level'] for c in cves), key=lambda k: _LEVEL_RANK[k])
        reason = '' if n_ok == n_open else f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต'
        if unlisted:
            reason = f'{reason} ({_unlisted_tail(unlisted)})' if reason else _unlisted_tail(unlisted)
        return level, reason
    if n_open == 0:
        if unlisted:
            return 'unknown', _unlisted_only(unlisted) + ' จึงยังประเมิน CVE ไม่ได้'
        return 'unknown', 'ไม่มีพอร์ตที่เปิดให้ตรวจ CVE'
    if scan_type != 'vuln_scan' and n_ok == 0:
        return 'unknown', 'การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE)'
    if n_ok == n_open and unlisted:
        return 'unknown', f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต ({_unlisted_tail(unlisted)})'
    if n_ok == n_open:
        return 'none', 'ไม่พบ CVE จากพอร์ตที่ตรวจ' + (f' ({UDP_UNKNOWN_TEXT})' if udp_unknown else '')
    why = []
    for key, text in (('failed', 'ค้นหา NVD ไม่สำเร็จ'), ('no_product', 'nmap ระบุผลิตภัณฑ์ไม่ได้'), ('unrecorded', 'สแกนรุ่นเก่าไม่ได้บันทึกสถานะ')):
        if statuses.count(key):
            why.append(f'{text} {statuses.count(key)}')
    return 'unknown', f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต (' + ', '.join(why) + ')'


def _vuln_unevaluated_reason(rows):
    """Why a VULNERABILITY scan could evaluate no service at all, in the words of the two CVE tiles (the scan DID look for CVEs, so it must never say
    it did not). Names one cause only when every open port has that one status; when the causes are mixed it says "this or that", and a scan from before
    cve_status existed (nothing recorded) is "not recorded", never "failed". Needs the rows before their private _open_ports are dropped."""
    states = {_port_status(p) for r in rows for p in r['_open_ports']}
    if not states:                       # no open port to look up (or no host at all)
        extra = ''
        if any(r['timed_out'] for r in rows):          # the host was scanned but ran out of time: say that, not "not scanned"
            extra = ' หรือไม่ทราบพอร์ตเพราะหมดเวลา'
        elif any(not r['ports_known'] for r in rows):
            extra = ' หรือไม่ได้สแกนพอร์ต'
        if any(r['unlisted'] or r['udp_open_unlisted'] for r in rows):           # open ports that nmap did not list one by one were never looked up
            extra += ' หรือมีพอร์ตที่เปิดซึ่ง nmap ไม่ได้แยกรายงาน'
        return 'ไม่มีพอร์ตที่เปิดให้ค้นหา CVE' + extra
    if states == {'failed'}:
        return 'ค้นหา CVE จาก NVD ไม่สำเร็จ'
    if states == {'no_product'}:
        return 'nmap ระบุผลิตภัณฑ์ของบริการไม่ได้ จึงไม่มีข้อมูลให้ค้นหา CVE'
    if 'unrecorded' in states and states <= {'unrecorded', 'no_product'}:
        return 'สแกนรุ่นเก่า ไม่ได้บันทึกว่าค้นหา CVE สำเร็จหรือไม่'
    return 'ค้นหา CVE จาก NVD ไม่สำเร็จหรือไม่มีข้อมูลให้ค้นหา'


def _vuln_unevaluated_text(rows):
    return 'ยังไม่ทราบ: ' + _vuln_unevaluated_reason(rows)


def _device_type(h, open_ports):
    try:
        g = guess_device_type(h.get('ip', ''), h.get('mac_vendor') or '', h.get('os') if h.get('os') not in ('Unknown', None) else '',
                              [p.get('port') for p in open_ports], None,
                              ' '.join(f"{p.get('name') or ''} {_product(p)}" for p in open_ports), h.get('hostname') or '', h.get('mac') or '')
    except Exception:                      # a guess must never break the report
        return 'unknown', TYPE_LABEL['unknown'], False
    key = g.get('key') if g.get('key') in TYPE_LABEL else 'unknown'
    likely = g.get('confidence') == 'likely' and key != 'unknown'
    return key, TYPE_LABEL[key] + (' (คาดเดา)' if likely else ''), likely


def _group_of(ip_obj):
    """(sort key, group title) of the host's subnet group."""
    if ip_obj is None:
        return (9, 0, ''), 'ไม่ทราบที่อยู่'
    if _scope(ip_obj) == 'external':
        return (3, 0, ''), 'ภายนอก (Internet)'
    if ip_obj.is_loopback:
        return (2, 0, ''), 'เครื่องสแกนเอง (loopback)'
    if ip_obj.version == 4:
        net = ipaddress.ip_network(f'{ip_obj}/24', strict=False)
    else:
        net = ipaddress.ip_network(f'{ip_obj}/64', strict=False)
    return (0 if ip_obj.version == 4 else 1, int(net.network_address), ''), str(net)


UNSURE_STATE = 'open|filtered'      # nmap could not tell whether the port is open or filtered (a UDP port that did not answer): unknown, NOT "not open"


def _group_line(groups):
    """'state N (reason), state N ...' for {(state, reason): n}: biggest group first, at most MAX_NOT_OPEN_GROUPS groups named, "+N กลุ่ม" for the rest."""
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1] is None, kv[0][1] or ''))
    named = [f"{state} {n}" + (f" ({port_reason_label(reason)})" if reason else '') for (state, reason), n in ordered[:MAX_NOT_OPEN_GROUPS]]
    more = len(ordered) - MAX_NOT_OPEN_GROUPS
    return ', '.join(named) + (f' +{more} กลุ่ม' if more > 0 else '')


def _not_open(ports):
    """The ports that are NOT open, as short lines: (text, count, reasoned, unsure_text, unsure_count). Grouped by (state, nmap's reason), biggest group first,
    at most MAX_NOT_OPEN_GROUPS groups named and "+N กลุ่ม" for the rest. The counts are exact. A group whose ports have no recorded reason (a scan from before
    `reason` was kept, or text that is not a plain nmap reason) shows only the state and the count: no "unknown reason" words. Nothing in the list that
    is not a port record is counted. '' / 0 when there is nothing to say. `reasoned` is True when at least one of these ports carries a reason.
    A port whose state is `open|filtered` (a UDP port that did not answer) is NOT "not open": nmap does not know. It gets its own line,
    "ไม่ทราบว่าเปิดหรือถูกกรองอีก N พอร์ต: ...", and is not in `text` or `count`."""
    groups, unsure = {}, {}
    total = n_unsure = 0
    for p in ports:
        if not isinstance(p, dict) or _is_open(p):
            continue
        state = _clip(str(p.get('state') or '').lower(), MAX_STATE_TEXT) or 'ไม่ทราบสถานะ'
        key = (state, port_reason(p.get('reason')))
        if state == UNSURE_STATE:
            unsure[key] = unsure.get(key, 0) + 1
            n_unsure += 1
        else:
            groups[key] = groups.get(key, 0) + 1
            total += 1
    text = f'ไม่เปิดอีก {total} พอร์ต: ' + _group_line(groups) if total else ''
    unsure_text = f'ไม่ทราบว่าเปิดหรือถูกกรองอีก {n_unsure} พอร์ต: ' + _group_line(unsure) if n_unsure else ''
    return text, total, any(reason for (_, reason) in list(groups) + list(unsure)), unsure_text, n_unsure


def _udp_unlisted(h, ports_known):
    """The `udp_unlisted` of a host as {state: count}: the states a top-N UDP run printed only as a count (nmap lists a state port by port only while it covers 25 ports
    or fewer). Read from stored text, so only a dict with positive whole counts counts and a state is a short lowercase text; anything else is no claim ({}). Like the other
    UDP flags it says nothing about a host whose ports were never scanned."""
    raw = h.get('udp_unlisted') if ports_known else None
    if not isinstance(raw, dict):
        return {}
    out = {}
    for state, n in raw.items():
        n, state = _count_of(n), _clip(str(state or '').lower(), MAX_STATE_TEXT)
        if n and state:
            out[state] = out.get(state, 0) + n
    return out


def _udp_unlisted_text(counts):
    """The inventory line for the UDP ports nmap gave only as a count, other than `open` (that state makes the host's UDP result unknown and has its own words):
    `open|filtered` first, as "unknown whether open or filtered" (never "closed", never open), then every other state under nmap's own word, at most MAX_NOT_OPEN_GROUPS
    of them, all followed by one unit ("พอร์ต UDP"). The reason nmap lists no port numbers is said (with "nmap") when the line holds the unknown part, because there the
    reader needs it; a line of only closed / filtered counts says it shorter, so it does not take three lines of a narrow column. '' when there is nothing to say."""
    parts = []
    unsure = counts.get(UNSURE_STATE, 0)
    if unsure:
        parts.append(f'ไม่ทราบว่าเปิดหรือถูกกรอง {unsure:,}')
    others = sorted(((s, n) for s, n in counts.items() if s not in ('open', UNSURE_STATE)), key=lambda kv: (-kv[1], kv[0]))
    parts += [f'{s} {n:,}' for s, n in others[:MAX_NOT_OPEN_GROUPS]]
    if len(others) > MAX_NOT_OPEN_GROUPS:
        parts.append(f'+{len(others) - MAX_NOT_OPEN_GROUPS} กลุ่ม')
    if not parts:
        return ''
    return ' · '.join(parts) + ' พอร์ต UDP ' + (f'({UDP_UNLISTED_NOTE})' if unsure else '(ไม่แสดงรายพอร์ต)')


def _host_row(h, scan_type, udp_min=UDP_MIN):
    # a host has a port list only when 'ports' is a list (even an empty one: then 0 open is a fact); a missing key, null or anything else
    # means the scan never looked at this host's ports, which is NOT the same as "none open"
    ports_known = isinstance(h.get('ports'), list)
    open_ports = sorted([p for p in (h.get('ports') if ports_known else []) if _is_open(p)], key=lambda p: (_port_number(p), str(p.get('protocol') or '')))
    cves = _host_cves(open_ports)
    # Why the ports of this host are unknown or incomplete, when the scan recorded it (each only for a host whose flag is exactly True / a positive count):
    #   timed_out    nmap gave up on the host (--host-timeout); the scanner then removes its `ports`, so this only applies to a host with no port list
    #   unlisted     open ports nmap collapsed into one <extraports state="open"> line: they exist but were never named, so never looked up
    #   udp_*        the UDP run failed / ran out of time / never covered this host: its UDP ports are unknown (not "no UDP port found")
    #   udp_unlisted a top-N UDP run gave some states only as a count (nmap lists a state port by port only up to 25 ports): `open` makes the host's UDP result unknown
    #                (and, like the TCP `unlisted`, those open ports were never looked up, so the host is never "ไม่พบ CVE"); `open|filtered` and the others are real information
    #                that is never counted as open and says only what it says
    timed_out = (not ports_known) and h.get('timed_out') is True
    unlisted = _count_of(h['ports_unlisted'].get('open')) if ports_known and isinstance(h.get('ports_unlisted'), dict) else 0
    udp_flags = {key: ports_known and h.get(key) is True for key in ('udp_failed', 'udp_timed_out', 'udp_not_scanned')}
    udp_why = [text for key, text in (('udp_failed', UDP_FAILED_TEXT), ('udp_timed_out', _udp_timeout_text(udp_min)), ('udp_not_scanned', UDP_NOT_SCANNED_TEXT)) if udp_flags[key]]
    udp_counts = _udp_unlisted(h, ports_known)
    udp_open_unlisted = udp_counts.get('open', 0)
    if udp_open_unlisted:
        udp_why.append(f'มีพอร์ต UDP ที่เปิด {udp_open_unlisted:,} พอร์ตซึ่ง nmap ไม่ได้แยกรายงาน')
    gap = unlisted + udp_open_unlisted          # open ports nobody named (TCP and UDP): they were never looked up, so the level and the evaluation text count them
    level, reason = _host_risk(open_ports, cves, scan_type, ports_known, timed_out, gap, bool(udp_why))
    type_key, type_label, type_likely = _device_type(h, open_ports)
    mac = (h.get('mac') or '').strip()
    mac = '' if mac.lower() in ('', 'unknown') else mac
    os_name = (h.get('os') or '').strip()
    os_name = '' if os_name.lower() in ('', 'unknown', 'up', 'down') else os_name
    ports = [{'text': f"{p.get('port')}/{p.get('protocol') or 'tcp'} {p.get('name') or ''}".strip(), 'product': _clip(_product(p), 42)}
             for p in open_ports[:MAX_PORT_LINES]]
    n_ok = sum(1 for p in open_ports if _port_status(p) == 'ok')
    # a host whose ports were never scanned has nothing to say about ports that are not open (that is "unknown", not "none")
    not_open_text, not_open_count, not_open_reasoned, unsure_text, unsure_count = _not_open(h.get('ports')) if ports_known else ('', 0, False, '', 0)
    return {
        'ip': h.get('ip', ''), 'hostname': (h.get('hostname') or '').strip(), 'mac': mac, 'mac_vendor': (h.get('mac_vendor') or '').strip(),
        'vm': virtual_machine_platform(mac, h.get('mac_vendor') or ''), 'os': _clip(os_name, 60), 'local': bool(h.get('local')),
        # nmap's confidence in the OS guess: only from THIS record and only with a real OS name (never from another scan's guess)
        'os_confidence': os_match_accuracy(h.get('os_accuracy')) if os_name else None,
        'type_key': type_key, 'type_label': type_label, 'type_likely': type_likely, 'type_name': TYPE_LABEL[type_key],      # type_name without the "(คาดเดา)" so the page can keep that on one line
        'not_open_text': not_open_text, 'not_open_count': not_open_count, 'not_open_reasoned': not_open_reasoned,
        'unsure_text': unsure_text, 'unsure_count': unsure_count,                 # open|filtered: its own line, it is not "not open"
        'timed_out': timed_out, 'timed_out_text': HOST_TIMEOUT_TEXT if timed_out else '',
        'unlisted': unlisted, 'unlisted_text': f'มีพอร์ตที่เปิดอีก {unlisted:,} พอร์ตซึ่ง nmap ไม่ได้แยกรายงาน' if unlisted else '',
        'udp_failed': udp_flags['udp_failed'], 'udp_timed_out': udp_flags['udp_timed_out'], 'udp_not_scanned': udp_flags['udp_not_scanned'],
        'udp_unknown': bool(udp_why), 'udp_note': ('ไม่ทราบพอร์ต UDP: ' + ', '.join(udp_why)) if udp_why else '',
        'udp_open_unlisted': udp_open_unlisted, 'udp_unsure_unlisted': udp_counts.get(UNSURE_STATE, 0), 'udp_unlisted_text': _udp_unlisted_text(udp_counts),
        'ports_known': ports_known, 'open_count': len(open_ports), 'ports': ports, 'ports_more': max(0, len(open_ports) - MAX_PORT_LINES),
        'risk': level, 'risk_label': LEVEL_LABEL[level], 'risk_reason': reason,
        'cve_total': len(cves), 'sev_counts': _sev_counts(cves), 'max_text': _max_text(cves),
        'eval_ok': n_ok, 'eval_text': _eval_text(ports_known, len(open_ports), n_ok, scan_type, timed_out, gap, bool(udp_why)),
        'protocols': [str(p.get('protocol') or 'tcp').lower() for p in open_ports],
        '_cve_all': cves, '_open_ports': open_ports,
    }


# ---------------------------------------------------------------- page 2: the findings
def _weakness(c):
    """'Other (NVD-CWE-Other)' / 'Improper Input Validation (CWE-20)': the official name NVD shows plus the ID. A record whose ID cannot be read keeps its
    stored short label; one with neither is ''. Never raises on stored text."""
    try:
        info = cwe_info(c)
    except Exception:
        info = None
    if info:
        name = info['name'] if info['name'] and len(info['name']) <= 56 else (info['compact'] or info['name'])
        return _clip(f"{name} ({info['id']})" if name else info['id'], 80)
    return _clip(c.get('cwe_name') or '', 60)


def _finding_rows(rows):
    """One row per host x port x CVE (the same count as the scan page's CVE card), worst first: effective severity, then CVSS score, then CVE id, then
    host and port. A CVE listed twice on one port is one row (the higher score). Only CVEs on ports whose state is exactly `open`."""
    out = []
    for r in rows:
        for p in r['_open_ports']:
            best = {}
            for c in (p.get('cves') or []):
                if not isinstance(c, dict) or not c.get('cve_id'):
                    continue
                cid = str(c['cve_id'])
                old = best.get(cid)
                kev = _merge_kev(old['kev'], _kev_of(c)) if old else _kev_of(c)
                score = _score(c)
                if old is None or (score if score is not None else -1) > (old['score'] if old['score'] is not None else -1):
                    sev = effective_severity(c)
                    best[cid] = {'ip': r['ip'], 'hostname': r['hostname'], 'port': f"{p.get('port')}/{p.get('protocol') or 'tcp'}",
                                 'service': _clip(p.get('name') or '', 30), 'product': _clip(_product(p), 60),
                                 'versionless': bool(_product(p)) and not re.search(r'\d', _product(p)),
                                 'sev': sev, 'sev_key': _sev_class(sev), 'sev_label': _sev_name(sev), 'score': score, 'cve_id': _clip(cid, 60),
                                 'weakness': _weakness(c), 'description': _clip(c.get('description') or '', MAX_FINDING_DESC),
                                 '_sort': (-_SEV_RANK.get(sev, 0), -(score if score is not None else -1), cid, _ip_sort(r['ip']), _port_number(p))}
                best[cid]['kev'] = kev
            out.extend(best.values())
    out.sort(key=lambda x: x['_sort'])
    for x in out:
        x.pop('_sort')
    return out


def _host_table(rows):
    """The per-host table of page 2: the worst hosts first (high, medium, low, then the ones that could not be evaluated, then the clean ones),
    most CVEs first inside a level. The counts are of DISTINCT CVE ids on that host; a host that could not be evaluated has no counts ("—"), never zeros."""
    order = {'high': 5, 'med': 4, 'low': 3, 'unknown': 2, 'none': 1}
    items = []
    for r in rows:
        c = r['sev_counts']
        items.append({'ip': r['ip'], 'hostname': r['hostname'], 'local': r['local'], 'risk': r['risk'], 'risk_label': r['risk_label'],
                      'c': c['critical'], 'h': c['high'], 'm': c['medium'], 'l': c['low'], 'u': c['unknown'], 'total': r['cve_total'],
                      'counts_known': r['risk'] != 'unknown', 'eval_text': r['eval_text']})
    items.sort(key=lambda x: (-order[x['risk']], -x['c'], -x['h'], -x['m'], -x['l'], -x['u'], _ip_sort(x['ip'])))
    return items[:MAX_HOST_ROWS], len(items), max(0, len(items) - MAX_HOST_ROWS)


def _match_notes(frows, multi_host):
    """What the reader should know about how the CVEs were matched. Only what the data says: the search text itself is not stored, so nothing is
    claimed about it; a service text with no digit in it is reported as exactly that."""
    notes = ['CVE ในตารางนี้จับคู่จากชื่อและเวอร์ชันของบริการที่ nmap อ่านได้กับ NVD แบบคีย์เวิร์ด (ไม่ใช่ CPE) '
             'ผลที่ได้อาจเป็น CVE ของเวอร์ชันอื่นหรือผลิตภัณฑ์ที่ไม่ตรงกับเครื่องนี้ ควรตรวจสอบก่อนสรุปว่าเป็นช่องโหว่จริง']
    seen = {}
    for x in frows:
        if x['versionless']:
            seen.setdefault((x['ip'], x['port']), x)
    if seen:
        ex = sorted(seen.values(), key=lambda x: (_ip_sort(x['ip']), int(x['port'].split('/')[0]) if x['port'].split('/')[0].isdigit() else 0))
        names = [(f"{x['ip']} " if multi_host else '') + f"{x['port']} {x['product']}" for x in ex[:MAX_MATCH_EXAMPLES]]
        notes.append(f"{len(seen)} พอร์ตที่พบ CVE มีข้อความบริการจาก nmap ที่ไม่มีตัวเลขเวอร์ชัน (เช่น {', '.join(names)}) "
                     'ผลที่ได้อาจตรงกับเวอร์ชันเก่าหรือผลิตภัณฑ์ที่ไม่ตรงกับเครื่องนี้')
    return notes


def _findings(rows, scan_type, distinct, unevaluated_text):
    """Page 2: the CVE table (every Critical and High row, then Medium / Low / Unknown up to MAX_FINDING_ROWS in total) and the per-host table.
    `distinct` is the number of distinct CVE ids of the whole scan (the tile's number), None when nothing could be evaluated."""
    frows = _finding_rows(rows)
    total = len(frows)
    n_crit_high = sum(1 for x in frows if x['sev'] in ('CRITICAL', 'HIGH'))
    keep = max(n_crit_high, MAX_FINDING_ROWS)
    shown, hidden = frows[:keep], frows[keep:]
    for i, x in enumerate(shown, 1):
        x['n'] = i
    hidden_count = {}
    for x in hidden:
        hidden_count[x['sev_label']] = hidden_count.get(x['sev_label'], 0) + 1
    hidden_text = ' · '.join(f'{k} {hidden_count[k]}' for k in ('ปานกลาง', 'ต่ำ', 'ไม่ทราบ') if hidden_count.get(k))
    ips = {x['ip'] for x in frows}
    single_ip = next(iter(ips)) if len(ips) == 1 else ''
    tail = 'เรียงตามความรุนแรงแล้วคะแนน CVSS · จับคู่จากชื่อและเวอร์ชันของบริการ ยังไม่ผ่านการยืนยัน'
    if not frows:
        sub = ''
    elif total == distinct:
        sub = f'CVE ทั้ง {total} รายการ' + (f'ของ {single_ip} ' if single_ip else 'ของสแกนนี้ ') + tail
    else:
        sub = (f'ตารางนี้มี {total} แถว (นับทีละอุปกรณ์ × พอร์ต × CVE) ส่วน CVE ที่ไม่ซ้ำกันของทั้งสแกนมี {distinct} รายการ '
               f'(ตามกล่อง "CVE ที่พบ" หัวข้อ 1) ' + tail)
    looked = scan_type == 'vuln_scan'
    if frows:
        empty = ''
    elif not rows:
        empty = 'ไม่มีอุปกรณ์ในผลสแกนนี้ จึงไม่มี CVE ให้แสดง'
    elif distinct is not None:
        empty = 'ไม่พบ CVE จากพอร์ตที่ตรวจ ไม่ได้แปลว่าปลอดภัย (ค้นหาจากชื่อและเวอร์ชันของบริการด้วยคีย์เวิร์ดเท่านั้น)'
    elif looked:
        empty = unevaluated_text
    else:
        empty = 'การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่ทราบว่ามีช่องโหว่หรือไม่ (ไม่ได้แปลว่าไม่มี) ใช้สแกนช่องโหว่ (CVE) เพื่อค้นหา CVE'
    notes = _match_notes(frows, len(rows) > 1) if looked and frows else []
    hosts, hosts_total, hosts_more = _host_table(rows)
    for x in frows:
        x.pop('versionless', None)
    return {'looked': looked, 'rows': shown, 'total': total, 'distinct': distinct, 'hidden': len(hidden), 'hidden_text': hidden_text,
            'show_host': len(ips) > 1, 'single_ip': single_ip, 'sub': sub, 'empty': empty,
            'hosts': hosts, 'hosts_total': hosts_total, 'hosts_more': hosts_more, 'match_notes': notes}, frows


# ---------------------------------------------------------------- page 1: the summary
def _status_counts(rows):
    out = dict.fromkeys(('ok', 'failed', 'no_product', 'unrecorded'), 0)
    for r in rows:
        for p in r['_open_ports']:
            out[_port_status(p)] += 1
    return out


_NOT_DONE = {'Running': 'ยังทำงานอยู่', 'Failed': 'ล้มเหลว', 'Cancelled': 'ถูกยกเลิก'}


def _badge(rows, frows, scan_type, n_evaluated, status, udp_gap=''):
    """The scan's overall level, in the host levels' own words. A level of สูง / กลาง / ต่ำ is the worst host's (a floor: a host that could not be
    evaluated may be worse). "ไม่พบ CVE" only when EVERY host was evaluated and clean AND the scan is Completed (the hosts of a Running, Failed or Cancelled
    scan are only the part that was scanned). Everything else is "ยังไม่ทราบ", with the reason.
    udp_gap: when the UDP result of some host (or of the whole scan) is unknown, "ไม่พบ CVE" is still the answer (the TCP ports were evaluated) but its detail says
    "every KNOWN port" and names the gap, never "every open port"."""
    with_cves = [r for r in rows if r['cve_total']]
    if with_cves and frows:
        level = max((r['risk'] for r in with_cves), key=lambda k: _LEVEL_RANK[k])
        top = frows[0]
        detail = f"ระดับสูงสุดที่พบ: {top['sev_label']}" + (f" (CVSS {top['score']:.1f})" if top['score'] is not None else '')
        if top['sev_key'] == 'unknown':
            detail += ' (ไม่มีระดับความรุนแรง จึงนับรวมในระดับต่ำ)'
        detail += f" บนพอร์ต {top['port']}" + (f" ของ {top['ip']}" if len(rows) > 1 else '')
    elif rows and all(r['risk'] == 'none' for r in rows) and status != 'Completed':
        level, detail = 'unknown', f"สแกนนี้{_NOT_DONE.get(status, 'ยังไม่เสร็จสมบูรณ์')} ผลเป็นเพียงบางส่วน จึงยังบอกไม่ได้ว่า \"ไม่พบ CVE\""
    elif rows and all(r['risk'] == 'none' for r in rows):
        level = 'none'
        detail = (f'ค้นหาครบทุกพอร์ตที่เปิดเท่าที่ทราบแล้วไม่พบ CVE ({udp_gap} · การค้นหาไม่พบ ไม่ได้รับรองว่าปลอดภัย)' if udp_gap
                  else 'ค้นหาครบทุกพอร์ตที่เปิดแล้วไม่พบ CVE (การค้นหาไม่พบ ไม่ได้รับรองว่าปลอดภัย)')
    else:
        level = 'unknown'
        if not rows:
            detail = 'ไม่มีอุปกรณ์ในผลสแกนนี้'
        elif n_evaluated == 0 and scan_type == 'vuln_scan':
            detail = _vuln_unevaluated_reason(rows)
        elif n_evaluated == 0:
            detail = 'การสแกนนี้ไม่ได้ค้นหา CVE'
        else:
            detail = f'ไม่พบ CVE ในส่วนที่ประเมินได้ แต่ประเมินได้เพียง {n_evaluated} จาก {len(rows)} เครื่อง'
    return {'key': level, 'label': LEVEL_LABEL[level], 'detail': detail}


def _lead(rows, scan_type, tiles, facts, skip_ping, total_ips, status_counts):
    """The one-paragraph summary as a list of {'text', 'bold'} pieces (join them with a space). Each fact is said only when it is known."""
    n_hosts = len(rows)
    checked = facts.get('checked') if isinstance(facts.get('checked'), int) and not isinstance(facts.get('checked'), bool) and facts.get('checked') >= 0 else None
    if checked is not None:
        head = f'ตรวจ {checked:,} IP' + (' (ข้ามการ ping)' if skip_ping else '')
    elif total_ips and total_ips >= n_hosts:
        head = f'เป้าหมาย {total_ips:,} IP'
    else:
        head = ''
    if n_hosts == 0:
        found = 'ไม่พบอุปกรณ์ในผลสแกนนี้'
    elif n_hosts == 1:
        found = f"พบอุปกรณ์ 1 เครื่อง ({rows[0]['ip']})"
    else:
        found = f'พบอุปกรณ์ {n_hosts} เครื่อง'
    pieces = [((head + ' ' + found).strip(), False)]
    if rows:
        not_scanned = [r for r in rows if not r['ports_known']]
        timed = [r for r in not_scanned if r['timed_out']]            # scanned, but nmap gave up on them: their ports are unknown for THAT reason
        plain = [r for r in not_scanned if not r['timed_out']]        # the scan never looked at their ports
        open_total = sum(r['open_count'] for r in rows)
        if len(not_scanned) == n_hosts:
            pieces.append((HOST_TIMEOUT_TEXT if not plain else 'การสแกนนี้ไม่ได้ตรวจพอร์ต' if not timed
                           else f'ไม่ทราบพอร์ตของทุกเครื่อง (ไม่ได้สแกนพอร์ต {len(plain)} เครื่อง · {_timed_out_hosts(len(timed))})', False))
        else:
            s = 'ไม่พบพอร์ตที่เปิด' if open_total == 0 else f'มีพอร์ตที่เปิด {open_total} พอร์ต'
            # what the number leaves out, in ONE parenthesis (each part only when it is true of this scan)
            leaves = []
            if not_scanned:
                known = n_hosts - len(not_scanned)
                if not timed:
                    leaves.append(f'นับเฉพาะ {known} เครื่องที่สแกนพอร์ต')
                else:
                    leaves.append(f'นับเฉพาะ {known} เครื่องที่ทราบพอร์ต')
                    if plain:
                        leaves.append(f'ไม่ได้สแกนพอร์ต {len(plain)} เครื่อง')
                    leaves.append(_timed_out_hosts(len(timed)))
            unlisted_hosts = [r for r in rows if r['unlisted']]
            if unlisted_hosts:                                        # open ports nmap did not name are not in the number
                leaves.append(f'ไม่รวมพอร์ตที่เปิดซึ่ง nmap ไม่ได้แยกรายงานใน {len(unlisted_hosts)} เครื่อง')
            udp_hosts = [r for r in rows if r['udp_unknown']]
            if udp_hosts:                                             # and no UDP port is known for these
                leaves.append(f'ไม่ทราบพอร์ต UDP ของ {len(udp_hosts)} เครื่อง')
            if leaves:
                s += ' (' + ' · '.join(leaves) + ')'
            pieces.append((s, False))
        n_cve = tiles['cves']['value']
        if n_cve is None:
            pieces.append((_vuln_unevaluated_reason(rows) if scan_type == 'vuln_scan' else 'การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่ทราบระดับความเสี่ยง', False))
        else:
            if n_cve:
                pieces += [('ค้นหา CVE จากชื่อและเวอร์ชันของบริการได้', False), (f'{n_cve} รายการ', True)]
            else:
                pieces.append(('ไม่พบ CVE จากพอร์ตที่ตรวจ', False))
            total_ports = sum(status_counts.values())
            s = f"ประเมินได้ {status_counts['ok']} จาก {total_ports} พอร์ต"
            why = []
            if status_counts['no_product']:
                why.append(f"nmap ระบุผลิตภัณฑ์ไม่ได้ จึงไม่ได้ค้นหา {status_counts['no_product']} พอร์ต")
            if status_counts['failed']:
                why.append(f"ค้นหา NVD ไม่สำเร็จ {status_counts['failed']} พอร์ต")
            if status_counts['unrecorded']:
                why.append(f"สแกนรุ่นเก่าไม่ได้บันทึกสถานะ {status_counts['unrecorded']} พอร์ต")
            pieces.append((s + (' (' + ' · '.join(why) + ')' if why else ''), False))
    return [{'text': t, 'bold': b} for t, b in pieces]


def _fact_count(facts, key, rows, row_key):
    """How many hosts a fact is about: the number the run recorded when it is a positive count, else the number of hosts that carry the flag (0 = nothing to say)."""
    n = facts.get(key)
    if isinstance(n, int) and not isinstance(n, bool) and n > 0:
        return n
    return sum(1 for r in rows if r.get(row_key))


def _limits(scan_type, facts, skip_ping, rows=(), settings=None):
    """The "what this result cannot tell you" box. A bullet about the run is written only when the run recorded that fact (admin False, npcap False,
    -Pn used, an ARP-cache note > 0, hosts that timed out, a UDP run that failed, no DNS, Gentle ...); the keyword-match bullet only when a CVE lookup
    was part of the scan; the last one is always there. The words of the new bullets are the scan run notes' own (app.describe_run, locales run.note.*)."""
    settings = settings or {}
    out = []
    if scan_type == 'vuln_scan':
        out.append('CVE จับคู่จากชื่อและเวอร์ชันของบริการกับ NVD (สูงสุด 5 รายการต่อพอร์ต) ยังไม่ผ่านการยืนยันว่าใช้ได้กับเครื่องนี้')
    else:
        out.append('การสแกนนี้ไม่ได้ค้นหา CVE ระดับความเสี่ยงของอุปกรณ์จึงเป็น "ยังไม่ทราบ" ไม่ได้แปลว่าปลอดภัย')
    if scan_type == 'xml_upload':
        out.append('ผลนี้นำเข้าจากไฟล์ XML ของ nmap ระบบไม่ได้เป็นผู้สแกน ความครบถ้วนของผลขึ้นอยู่กับคำสั่งที่สร้างไฟล์นั้น')
    if facts.get('admin') is False:
        out.append('สแกนครั้งนี้รันโดยไม่มีสิทธิ์ Administrator/root อุปกรณ์ที่บล็อก ping อาจหายไป และอ่าน MAC / ระบบปฏิบัติการได้ไม่ครบ')
    if facts.get('npcap') is False:
        out.append('ไม่พบ Npcap ตอนสแกน nmap ใช้ ping แทน ARP จึงอาจพลาดอุปกรณ์ที่บล็อก ping')
    if skip_ping:
        s = 'สแกนครั้งนี้ข้ามการ ping (-Pn) nmap จึงลองพอร์ตของทุกที่อยู่'
        if isinstance(facts.get('no_evidence'), int) and not isinstance(facts.get('no_evidence'), bool) and facts['no_evidence'] > 0:
            s += f" ที่อยู่ {facts['no_evidence']:,} ที่ไม่มีอะไรตอบกลับไม่ถูกแสดงเป็นอุปกรณ์"
        out.append(s + ' (เครื่องที่ปิดกั้นทุกพอร์ตกับที่อยู่ว่างแยกกันไม่ได้)')
    arp = facts.get('arp_only_total')
    if isinstance(arp, int) and not isinstance(arp, bool) and arp > 0:
        out.append(f'ตาราง ARP ของเครื่องที่สแกนรู้จักอีก {arp:,} อุปกรณ์ในช่วงที่สแกน ซึ่งสแกนไม่ได้รายงานว่าออนไลน์ (ข้อมูลอาจเก่า) จึงไม่นับรวมในรายงานนี้')
    # ---- what the scan options and the hosts' own flags leave unknown (each only when it was recorded)
    n = _fact_count(facts, 'timed_out', rows, 'timed_out')
    if n:
        out.append(f'{n:,} เครื่องใช้เวลาเกิน {HOST_MIN} นาที nmap จึงข้ามเครื่องนั้น และไม่ทราบพอร์ตของเครื่องนั้น (ไม่ได้หมายความว่าไม่มีพอร์ตที่เปิด)' if HOST_MIN
                   else f'{n:,} เครื่องใช้เวลาเกินที่กำหนด nmap จึงข้ามเครื่องนั้น และไม่ทราบพอร์ตของเครื่องนั้น (ไม่ได้หมายความว่าไม่มีพอร์ตที่เปิด)')
    n = sum(1 for r in rows if r.get('unlisted'))
    if n:
        out.append(f'{n:,} เครื่องมีพอร์ตที่เปิดซึ่ง nmap ไม่ได้แยกรายงานหมายเลขพอร์ต จึงไม่ได้ค้นหา CVE ของพอร์ตเหล่านั้น')
    udp_failed = facts.get('udp_failed') is True or any(r.get('udp_failed') for r in rows)
    tier = _udp_tier(settings, facts)          # the range of the UDP run: the 12 common ports, or nmap's top 100 / top 1000 (no service versions)
    if settings.get('udp') is True or facts.get('udp') is True:
        if not udp_failed:
            what = (f"สแกนพอร์ต UDP {tier['n']:,} อันดับแรกของ nmap โดยไม่ตรวจเวอร์ชันของบริการ" if tier['top'] else f'สแกน UDP เฉพาะ {N_UDP_PORTS} พอร์ตที่พบบ่อย')
            out.append(f'{what} พอร์ต UDP ที่แสดงเป็น open|filtered หมายถึงไม่ทราบว่าเปิดหรือถูกกรอง '
                       'จึงไม่นับเป็นพอร์ตที่เปิดและไม่ค้นหา CVE ให้พอร์ตนั้น')
    if udp_failed:
        cause = facts.get('udp_error')
        cause = _clip(cause, MAX_UDP_ERROR) if isinstance(cause, str) else ''
        out.append(f'{UDP_FAILED_TEXT} จึงไม่มีผลพอร์ต UDP ของสแกนนี้ ผลพอร์ต TCP ไม่ได้รับผลกระทบ' + (f' (สาเหตุ: {cause})' if cause else ''))
    n = _fact_count(facts, 'udp_not_scanned', rows, 'udp_not_scanned')
    if n:
        out.append(f'{n:,} เครื่อง{UDP_NOT_SCANNED_TEXT} จึงไม่ทราบพอร์ต UDP ของเครื่องนั้น')
    n = _fact_count(facts, 'udp_timed_out', rows, 'udp_timed_out')
    if n:
        out.append(f"{n:,} เครื่อง{_udp_timeout_text(tier['minutes'])} nmap จึงข้ามเครื่องนั้น และไม่ทราบพอร์ต UDP ของเครื่องนั้น")
    # a top-N run: nmap gave some states only as a total (udp_unlisted). Only when a host really carries it, and only what it says: how many devices, which state
    n_unsure, n_open = sum(1 for r in rows if r.get('udp_unsure_unlisted')), sum(1 for r in rows if r.get('udp_open_unlisted'))
    if n_unsure or n_open:
        said = ([f'{n_unsure:,} เครื่องที่ทราบเพียงจำนวนพอร์ต UDP ที่ไม่ทราบว่าเปิดหรือถูกกรอง'] if n_unsure else [])             + ([f'{n_open:,} เครื่องที่ทราบเพียงจำนวนพอร์ต UDP ที่เปิด (ไม่ได้ค้นหา CVE ของพอร์ตเหล่านั้น)'] if n_open else [])
        out.append('nmap ไม่แสดงรายพอร์ตเมื่อสถานะหนึ่งมีเกิน 25 พอร์ต จึงมี ' + ' และ '.join(said))
    if settings.get('no_dns') is True or facts.get('no_dns') is True:
        out.append('ไม่ได้ค้นหาชื่ออุปกรณ์ผ่าน DNS (-n) อุปกรณ์ที่ไม่แสดงชื่อจึงไม่ได้หมายความว่าไม่มีชื่อ (ชื่อ NetBIOS ที่ถามจากตัวอุปกรณ์ยังอ่านได้)')
    if settings.get('gentle') is True or facts.get('gentle') is True:
        out.append('สแกนแบบนุ่มนวล ส่งแพ็กเก็ตช้าและจำกัดอัตรา ส่งซ้ำไม่เกิน 2 ครั้ง พอร์ตที่แพ็กเก็ตสูญหายอาจแสดงเป็นถูกกรอง (filtered) ทั้งที่เปิดอยู่')
    out.append('เป็นผล ณ เวลาที่สแกน ไม่ได้รับรองว่าปลอดภัยหรือไม่ปลอดภัยหลังจากนี้')
    return out


_TRIGGER_TEXT = {'manual': 'สั่งเอง', 'rescan': 'สแกนซ้ำ', 'drilldown': 'เจาะลึกจากผลสแกนเดิม', 'chatbot': 'สั่งผ่านแชต/เสียง'}


def _who_text(owner, triggered_by, scan_type):
    """Who ordered the scan and how, in plain Thai. A schedule's owner is the owner of the SCHEDULE, not the person who ran it, so it is worded so.
    Nothing is invented: no owner and no known way gives ''."""
    owner = _clip(owner, MAX_WHO) if isinstance(owner, str) else ''
    if triggered_by == 'schedule':
        return f'สแกนตามเวลาที่ตั้งไว้ (เจ้าของตารางเวลา: {owner})' if owner else 'สแกนตามเวลาที่ตั้งไว้ (ไม่ได้บันทึกชื่อเจ้าของ)'
    how = 'นำเข้าไฟล์ XML' if scan_type == 'xml_upload' else _TRIGGER_TEXT.get(triggered_by)
    if owner and how:
        return f'{owner} ({how})'
    if owner:
        return owner
    return f'{how} (ไม่ได้บันทึกชื่อผู้ใช้)' if how else ''


# ---------------------------------------------------------------- page 5: the appendix
def _timing_text(info):
    if not isinstance(info, dict):
        return None
    src, v = info.get('source'), info.get('value')
    if src == 'custom':
        return 'ตามคำสั่งที่กำหนดเอง'
    if v is None or src in ('none', 'unused'):
        return None
    return {'set': f'T{v} (ตั้งไว้)', 'type-default': f'T{v} (ค่าเริ่มต้นของประเภทนี้)', 'nmap-default': f'ค่าเริ่มต้นของ nmap (T{v})',
            'gentle': f'T{v} (ตั้งโดยโหมดสแกนแบบนุ่มนวล)'}.get(src)       # Gentle replaces the Timing control: its own T2


def _intensity_text(info):
    if not isinstance(info, dict):
        return None
    src, v = info.get('source'), info.get('value')
    if v is None or src in ('none', 'unused', 'custom'):
        return None
    return {'set': f'{v} (ตั้งไว้)', 'type-default': f'{v} (ค่าเริ่มต้นของประเภทนี้)'}.get(src)


def _appendix_scan(scan, settings, label, steps, facts, nmap_version, run_summary, who):
    """Appendix A: the facts about the run as {'k', 'v'} rows. A fact the scan did not record has no row."""
    rows = []

    def add(k, v):
        if v:
            rows.append({'k': k, 'v': v})
    add('ชื่องาน', _clip(scan.get('scan_name') or '', 60))
    add('ประเภท', label)
    add('Timing', _timing_text(settings.get('timing')))
    add('Version intensity', _intensity_text(settings.get('intensity')))
    if settings.get('skip_ping') is not None:
        add('ตรวจ ping', 'ข้ามการ ping (-Pn)' if settings['skip_ping'] else 'ปกติ (ไม่ได้ข้ามการ ping)')
    # the options added later: a row only when the option was ON (a scan without them, or from before them, keeps exactly its old rows). The words are the
    # Tasks page's details panel's own.
    if settings.get('all_ports') is True or facts.get('ports_scanned') == 65535:
        add('พอร์ตที่สแกน', 'TCP ทุกพอร์ต (1-65535)')
    if settings.get('no_dns') is True or facts.get('no_dns') is True:
        add('ชื่ออุปกรณ์ (DNS)', 'ไม่ค้นหา (-n)')
    if settings.get('host_probes') is True or facts.get('host_probes') is True:
        add('ตรวจหาอุปกรณ์ที่ไม่ตอบ ping', 'เปิด (ลองเชื่อมต่อพอร์ตที่พบบ่อย) มีผลกับอุปกรณ์ที่อยู่หลังเราเตอร์เป็นหลัก')
    if settings.get('gentle') is True or facts.get('gentle') is True:
        add('สแกนแบบนุ่มนวล', 'เปิด (ช้าลงมาก จำกัดอัตรา)')
    if settings.get('scan_type') == 'discovery':
        m = settings.get('multicast')
        add('ฟังการตอบกลับ mDNS / SSDP', 'ไม่ได้บันทึกไว้' if m is None else ('ใช่' if m else 'ไม่ใช่'))
    add('ขั้นตอนเพิ่มเติม', ' · '.join(steps))
    perms = [t for t in (('มี Administrator' if facts.get('admin') else 'ไม่มี Administrator') if isinstance(facts.get('admin'), bool) else '',
                         ('มี Npcap' if facts.get('npcap') else 'ไม่มี Npcap') if isinstance(facts.get('npcap'), bool) else '') if t]
    add('สิทธิ์ตอนสแกน', ' · '.join(perms))
    add('nmap', f'nmap {nmap_version}' if nmap_version else '')
    el = facts.get('elapsed')
    if isinstance(el, (int, float)) and not isinstance(el, bool) and el >= 0:
        add('nmap ใช้เวลา', f'{el:.1f} วินาที' if el < 60 else _duration_text(int(round(el))))
    add('ผลการตรวจ', run_summary)
    add('ผู้สั่งสแกน', who)
    return rows


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def _shown_number(number, fallback):
    """The "Job #N" a reader sees. `number` is the app's own sequence (scan['number'], prev['seq']): the place of the job in its owner's list, the
    number every page of the app shows. When it is not a positive whole number (a caller that does not send it, or rubbish) the database id is
    printed instead, exactly as before. The id itself stays in `job_id` for the URLs."""
    return number if isinstance(number, int) and not isinstance(number, bool) and number > 0 else fallback


def _changes_view(changes, failed, scan_type, status='', udp_top=None):
    """Appendix B. `changes` is app.scan_changes()'s {'prev': {id, seq, when}, 'diff': scan_diff.compare_scans(...)} or None. The earlier scan is named by prev['seq'] (the number the app shows), else by its id. The words follow scan_diff's rules:
    a device missing from the newer scan is "ไม่พบในสแกนนี้" (never "gone"), a port is "ไม่เปิดแล้ว" (never "closed"), a CVE the older scan could not
    judge is counted and never listed. At most MAX_CHANGE_ITEMS per list ("+N" counts the real total). A value that cannot be read says the
    comparison could not be made.
    A host whose PORTS are unknown in either scan (no port list, timed out, open ports nmap did not list) is left out of the comparison of ports and CVEs by
    scan_diff, which says so with the caveat 'ports_unknown' and counts['ports_not_compared']; a host whose UDP result is unknown (the UDP run failed, ran out
    of time or never reached it) has only its UDP ports left out ('udp_unknown', counts['udp_not_compared']). A note repeats each here, only when the
    caveat is there AND its count is a positive whole number (never an invented number). udp_top: this scan's top-N UDP range (None = the 12 common ports): then a
    host can also be left out because nmap gave its open UDP ports only as a count, and the note names that cause too (the key of the comparison holds the range, so the
    earlier scan is of the same range)."""
    if failed:
        return {'state': 'failed', 'text': 'เทียบกับสแกนก่อนหน้าไม่ได้'}
    if changes is None:
        if scan_type == 'xml_upload':                  # an import is never compared (app.previous_comparable_job)
            return {'state': 'none', 'text': 'สแกนที่นำเข้าจากไฟล์ XML ไม่ได้เทียบกับสแกนก่อนหน้า'}
        if status != 'Completed':                      # nor is a scan that failed, was cancelled or is still running
            return {'state': 'none', 'text': 'สแกนนี้ไม่สำเร็จหรือยังไม่เสร็จ จึงไม่ได้เทียบ'}
        return {'state': 'none', 'text': 'ยังไม่มีสแกนก่อนหน้าแบบเดียวกันให้เทียบ'}
    try:
        prev, d = changes['prev'], changes['diff']
        counts = d['counts']
        if not (isinstance(prev, dict) and isinstance(prev.get('id'), int) and isinstance(d, dict) and isinstance(counts, dict)):
            raise ValueError('unreadable')
        when = str(prev.get('when') or '')
        vs = f"เทียบกับ งาน #{_shown_number(prev.get('seq'), prev['id'])}" + (f' ({_clip(when, 30)})' if when else '')
        lines = []

        def group(title, lst, total, fmt, inline=False):
            shown = [fmt(x) for x in (lst or [])[:MAX_CHANGE_ITEMS]]
            if shown:
                lines.append({'title': title, 'items': shown, 'more': max(0, total - len(shown)), 'inline': inline})

        dev = lambda x: {'text': _clip(x['ip'], 45), 'kev': False}
        group(f"อุปกรณ์ใหม่ {counts['new_devices']}", d.get('new_devices'), counts['new_devices'], dev, inline=True)
        group(f"ไม่พบในสแกนนี้ {counts['missing_devices']}", d.get('missing_devices'), counts['missing_devices'], dev, inline=True)

        def port_item(x):
            parts = ([f"เปิดเพิ่ม {', '.join(x['opened'])}"] if x.get('opened') else []) + ([f"ไม่เปิดแล้ว {', '.join(x['closed'])}"] if x.get('closed') else [])
            return {'text': _clip(f"{x['ip']}: " + ' · '.join(parts), 140), 'kev': False}
        group(f"พอร์ตที่เปลี่ยน: เปิดเพิ่ม {counts['ports_opened']} · ไม่เปิดแล้ว {counts['ports_closed']}", d.get('port_changes'), counts['port_changes'], port_item)

        def cve_item(x, why=''):
            sev = str(x.get('severity') or '').upper()
            cvss = x.get('cvss')
            return {'text': _clip(f"{x['cve_id']} · {_sev_name(sev)}" + (f' {cvss:.1f}' if isinstance(cvss, (int, float)) else '') + f" · {x['ip']} {x['port']}" + why, 160),
                    'kev': x.get('kev') is True}
        group(f"CVE ใหม่ {counts['new_cves']}", d.get('new_cves'), counts['new_cves'], cve_item)
        group(f"CVE ที่ไม่พบในสแกนนี้ {counts['fixed_cves']}", d.get('fixed_cves'), counts['fixed_cves'],
              lambda x: cve_item(x, ' · พอร์ตนี้ไม่เปิดแล้ว' if x.get('reason') == 'port_closed' else ' · ค้นหาแล้วไม่พบ'))
        notes = []
        caveats = d.get('caveats') if isinstance(d.get('caveats'), (list, tuple)) else []
        ports_gap = 'ports_unknown' in caveats and _int(counts.get('ports_not_compared')) > 0
        if d.get('missing_devices'):
            notes.append('ไม่พบ ไม่ได้แปลว่าปิดเครื่อง อุปกรณ์อาจบล็อก ping หรือปิดอยู่ชั่วคราว')
        if ports_gap:
            notes.append(f"ไม่ได้นำพอร์ตและ CVE ของ {counts['ports_not_compared']} เครื่องมาเทียบ เพราะไม่ทราบพอร์ตของเครื่องนั้นในสแกนใดสแกนหนึ่ง "
                         "(หมดเวลาต่อเครื่อง หรือมีพอร์ตที่เปิดซึ่ง nmap ไม่ได้แยกรายงาน)")
        if 'udp_unknown' in caveats and _int(counts.get('udp_not_compared')) > 0:
            causes = ('รอบสแกน UDP ทำงานไม่สำเร็จ ใช้เวลาสแกน UDP เกินกำหนด ไม่ได้สแกน UDP หรือมีพอร์ต UDP ที่เปิดซึ่ง nmap ไม่ได้แยกรายงาน' if udp_top
                      else 'รอบสแกน UDP ทำงานไม่สำเร็จ ใช้เวลาสแกน UDP เกินกำหนด หรือไม่ได้สแกน UDP')
            notes.append(f"ไม่ได้นำพอร์ต UDP ของ {counts['udp_not_compared']} เครื่องมาเทียบ เพราะไม่ทราบพอร์ต UDP ของเครื่องนั้นในสแกนใดสแกนหนึ่ง ({causes})")
        if _int(d.get('cve_unjudged')):
            notes.append(f"มี {d['cve_unjudged']} CVE ที่บอกไม่ได้ว่าใหม่หรือเก่า เพราะการค้นหา CVE ของสแกนใดสแกนหนึ่งไม่สำเร็จหรือไม่ได้บันทึกสถานะไว้ (นับแล้ว แต่ไม่ได้แสดงในรายการ)")
        if 'admin_differs' in caveats:
            notes.append('สองครั้งนี้รันด้วยสิทธิ์ต่างกัน (Administrator กับไม่ใช่) อุปกรณ์จึงอาจต่างกันโดยที่เครือข่ายไม่ได้เปลี่ยนจริง')
        cost = lambda g: -(-len(g['items']) // 4) if g['inline'] else len(g['items'])          # printed lines of a list
        while sum(cost(g) for g in lines) > MAX_CHANGE_LINES:                   # the page has room for so many lines: trim the longest list first
            longest = max((g for g in lines if len(g['items']) > 1), key=cost, default=None)
            if longest is None:
                break
            longest['items'].pop()
            longest['more'] += 1
        if lines:
            return {'state': 'changes', 'vs': vs, 'text': '', 'lines': lines, 'notes': notes}
        # "nothing changed" must not claim the ports of the hosts that were left out (their ports are unknown, not unchanged)
        same = (('ไม่พบความเปลี่ยนแปลงของอุปกรณ์ และของพอร์ตที่เปิดและ CVE ในเครื่องที่เทียบได้' if ports_gap else 'ไม่พบความเปลี่ยนแปลงของอุปกรณ์ พอร์ตที่เปิด และ CVE ที่เทียบได้') if d.get('cve_compared')
                else 'ไม่พบความเปลี่ยนแปลงของอุปกรณ์' + ((' และของพอร์ตที่เปิดในเครื่องที่เทียบได้' if ports_gap else 'และพอร์ตที่เปิด') if scan_type not in ('discovery', 'xml_upload') else ''))
        return {'state': 'same', 'vs': vs, 'text': same, 'lines': [], 'notes': notes}
    except Exception:
        return {'state': 'failed', 'text': 'เทียบกับสแกนก่อนหน้าไม่ได้'}


METHOD_STEPS = [
    'nmap ตรวจพอร์ตที่เปิดและอ่านชื่อ/เวอร์ชันของบริการ',
    'ระบบค้นหา NVD ด้วย CPE ที่มีเวอร์ชันเมื่อ nmap ระบุได้ หรือค้นด้วยชื่อผลิตภัณฑ์และเวอร์ชันแล้วคัดกรองตามช่วงเวอร์ชันและระบบปฏิบัติการที่ได้รับผลกระทบ',
    'เก็บผลสูงสุด 5 รายการต่อพอร์ต',
    'ความรุนแรงใช้คะแนน CVSS ที่ NVD ให้ (v3.1 ก่อน แล้ว v3.0 แล้ว v2) CVE ที่ได้คะแนน v2 อย่างเดียวและ 9.0 ขึ้นไป ระบบแสดงเป็นวิกฤต',
]
SCALE = [
    {'label': 'วิกฤต', 'range': '9.0 – 10.0', 'key': 'crit'}, {'label': 'สูง', 'range': '7.0 – 8.9', 'key': 'high'},
    {'label': 'ปานกลาง', 'range': '4.0 – 6.9', 'key': 'med'}, {'label': 'ต่ำ', 'range': '0.1 – 3.9', 'key': 'low'}, {'label': 'ไม่มี', 'range': '0.0', 'key': 'unknown'},
]
# the definition of "ไม่พบ CVE" when some host's UDP result is unknown (that host keeps the level, but did not have every open port checked)
LEVEL_NONE_UDP_TEXT = 'ค้นหาครบทุกพอร์ตที่เปิดเท่าที่ทราบแล้วไม่พบ CVE (หากไม่ทราบพอร์ต UDP ของเครื่องใด รายงานระบุไว้ที่เครื่องนั้น)'
LEVEL_TEXT = {
    'high': 'มี CVE ระดับวิกฤตหรือสูง',
    'med': 'CVE ที่รุนแรงที่สุดเป็นระดับปานกลาง',
    'low': 'CVE ที่รุนแรงที่สุดเป็นระดับต่ำ (CVE ที่ไม่มีระดับความรุนแรงนับรวมที่นี่)',
    'none': 'ค้นหาครบทุกพอร์ตที่เปิดแล้วไม่พบ CVE',
    'unknown': 'ประเมินไม่ได้ (ไม่ได้ค้นหา CVE, ค้นหาไม่สำเร็จ, nmap ระบุผลิตภัณฑ์ไม่ได้, ไม่ได้สแกนพอร์ต หรือไม่มีพอร์ตที่เปิด) ไม่ได้แปลว่าปลอดภัย',
}


def _not_said(scan_type, skip_ping, reasons=None, all_ports=False, udp=False, host_probes=False, udp_tier=None, udp_unlisted=False):
    """Appendix D: what this report does not say. Each sentence is written only when it is true of this kind of scan.
    reasons: None = this scan has no port that is not open (nothing to add), True = at least one such port carries nmap's reason (the inventory shows
    it), False = such ports exist but none has a recorded reason (an older scan): the sentence says so and never promises reasons.
    all_ports: ports 1-65535 were scanned, so "ports outside the range" is not true; it says what the lists of ports that are not open show instead.
    udp: the second (UDP) run was made: only its 12 ports were looked at, and a port that did not answer is "open|filtered", which is not open.
    udp_tier: _udp_tier() of this scan. With a top-N range (100 / 1000) the sentence says THAT: nmap's own frequency ranking, no service versions, and that the ranking
    was not made for telecom equipment (so a port such equipment uses, GTP for one, may be missing); with None it is exactly the 12-port sentence.
    udp_unlisted: some host carries `udp_unlisted` (states nmap printed only as a count); with a top-N range the note about nmap's 25-port rule is there in any case.
    host_probes: the extra probes were sent, so the ping sentence says what they did not catch."""
    out = ['ไม่ได้ยืนยันว่าช่องโหว่ใช้โจมตีได้จริง (ไม่ได้ทดสอบเจาะระบบ)',
           'ไม่ใช่รายการช่องโหว่ที่ครบถ้วน เป็นเพียง CVE ที่ NVD จับคู่ได้จากชื่อและเวอร์ชันของบริการ (สูงสุด 5 รายการต่อพอร์ต)']
    if scan_type == 'vuln_scan':
        out.append('บริการที่ nmap ระบุผลิตภัณฑ์ไม่ได้ ไม่ได้ถูกค้นหา CVE และแสดงเป็น "ยังไม่ทราบ"')
    if scan_type != 'discovery':
        out.append('พอร์ตที่เป็น filtered หรือ closed ไม่ถูกนำมาประเมิน (นับเฉพาะพอร์ตที่ open)'
                   + (' เหตุผลที่ nmap ให้ไว้แสดงในหัวข้อ 4 เฉพาะพอร์ตที่สแกนบันทึกเหตุผลไว้' if reasons else ' สแกนนี้ไม่ได้บันทึกเหตุผลที่ nmap ให้ไว้ของพอร์ตเหล่านี้' if reasons is False else ''))
    ports_scanned = scan_type not in ('discovery', 'xml_upload')
    if ports_scanned and udp:
        out.append('พอร์ต UDP ที่แสดงเป็น open|filtered หมายถึงไม่ทราบว่าเปิดหรือถูกกรอง จึงไม่นับเป็นพอร์ตที่เปิดและไม่ค้นหา CVE ให้พอร์ตนั้น')
    if ports_scanned:
        if all_ports:
            out.append('สแกนนี้ตรวจพอร์ต TCP ทุกพอร์ต (1-65535) รายการพอร์ตที่ไม่เปิดในหัวข้อ 4 แสดงเฉพาะพอร์ตที่ nmap แยกรายงาน '
                       'ส่วนที่เหลือ nmap สรุปเป็นจำนวนรวมตามสถานะ (มักเป็นสถานะปิด หรือสถานะถูกกรอง)')
            if not udp:
                out.append('ไม่ได้ตรวจพอร์ต UDP')
        else:
            out.append('พอร์ตนอกช่วงที่การสแกนนี้ตรวจจะไม่ปรากฏในผล')
        if udp:
            top = bool(udp_tier and udp_tier.get('top'))
            if top:
                out.append(f"ตรวจพอร์ต UDP {udp_tier['n']:,} อันดับแรกของ nmap โดยไม่ตรวจเวอร์ชันของบริการ อันดับนี้เป็นของ nmap เอง จัดจากความถี่ที่พบพอร์ต UDP เปิดบนอินเทอร์เน็ต "
                           'ไม่ได้เลือกมาสำหรับอุปกรณ์โทรคมนาคม พอร์ตที่อุปกรณ์ประเภทนี้ใช้จึงอาจไม่อยู่ในรายการ (เช่น GTP) พอร์ต UDP อื่นจึงไม่ปรากฏในผล')
            else:
                out.append(f'ตรวจพอร์ต UDP เพียง {N_UDP_PORTS} พอร์ตที่พบบ่อย ({UDP_PORT_LIST}) พอร์ต UDP อื่นจึงไม่ปรากฏในผล')
            if top or udp_unlisted:      # how to read a device with no UDP port listed
                out.append('nmap ไม่แสดงรายพอร์ตเมื่อสถานะหนึ่งมีเกิน 25 พอร์ต อุปกรณ์หนึ่งจึงอาจไม่แสดงพอร์ต UDP เลยทั้งที่มีหลายพอร์ตไม่ตอบกลับ'
                           + (' จำนวนรวมของแต่ละสถานะแสดงไว้ในหัวข้อ 4' if udp_unlisted else ''))
    if scan_type != 'xml_upload' and not skip_ping:
        out.append('อุปกรณ์ที่บล็อกทั้ง ping และพอร์ตที่ลองเชื่อมต่อเพิ่ม อาจไม่ถูกพบ' if host_probes else 'อุปกรณ์ที่บล็อก ping อาจไม่ถูกพบ')
    out.append('เป็นผล ณ เวลาที่สแกน ไม่ได้รับรองว่าปลอดภัยหรือไม่ปลอดภัยหลังจากนี้')
    out.append('ไม่มีข้อมูลวิธีแก้ไขในรายงานนี้ เพราะระบบไม่ได้เก็บข้อมูลดังกล่าว')
    return out


# ---------------------------------------------------------------- the portrait frame: the cover, the contents page and "about this report"
# (2026-11-17: the A4 PORTRAIT layout is the default, the landscape one is an export option. Everything below is orientation-free data: the template draws it only
# in portrait, so the landscape page, and every text it prints, is exactly what it was.)
MAX_TOC_GROUPS = 5         # subnet groups named under "รายการอุปกรณ์ที่พบ" on the contents page (the rest are counted, not listed)
MAX_RUNNING_TARGET = 30    # characters of the target printed in the running header of every portrait page (the cover and section 1 have the whole text)
COVER_KICKER_VULN = 'รายงานผลการสแกนเครือข่าย'
COVER_TITLE_VULN = ('รายงานการประเมิน', 'ช่องโหว่ของเครือข่าย')      # a vulnerability scan: it did look for CVEs
COVER_TITLE_SCAN = ('รายงานผลการสแกนเครือข่าย',)                     # every other type: it did not, so the title does not say "ช่องโหว่"
COVER_KICKER_XML = 'นำเข้าจากไฟล์ XML ของ nmap (ไม่ได้สแกนจากระบบ)'


def _cover_titles(scan_type, status='', evaluated_any=True):
    """(kicker or None, title lines): what the cover may claim. Only a vulnerability scan that ran to its end is a "vulnerability assessment": one that failed, was
    cancelled or is still running did not assess anything (its cover says what happened), so it gets the plain title like every other scan. The same for a completed one in which no
    open port was really looked up (every lookup failed, nmap named no product, no open port): evaluated_any False."""
    return (COVER_KICKER_VULN, COVER_TITLE_VULN) if (scan_type == 'vuln_scan' and status not in _NOT_DONE and evaluated_any) else (None, COVER_TITLE_SCAN)


def _cover_risk(badge, scan_type, status='', is_upload=False):
    """The box under the key facts on the cover. It follows the badge of section 1 exactly (a level only from the worst host, "ไม่พบ CVE" only when every host was
    evaluated and the scan is Completed, "ยังไม่ทราบ" with its reason otherwise). A scan that did not look for CVEs and found none says so instead of showing a pill;
    an imported file has no CVE results at all. A level from a scan that did not finish is what was found so far, and says so."""
    key = badge['key']
    if scan_type != 'vuln_scan' and key == 'unknown':
        if is_upload:
            return {'pill': '', 'key': 'unknown', 'title': 'ไฟล์ที่นำเข้าไม่มีผลการค้นหา CVE',
                    'text': 'จึงยังไม่ทราบระดับความเสี่ยง รายงานนี้แสดงเฉพาะผลที่มีอยู่ในไฟล์'}
        return {'pill': '', 'key': 'unknown', 'title': 'การสแกนนี้ไม่ได้ค้นหา CVE',
                'text': 'จึงยังไม่ทราบระดับความเสี่ยง รายงานนี้แสดงเฉพาะผลที่การสแกนตรวจได้ หากต้องการค้นหา CVE ให้ใช้สแกนช่องโหว่ (CVE)'}
    worst = 'ระดับความเสี่ยงสูงสุดที่พบ (ผลยังไม่ครบ)' if status in _NOT_DONE else 'ระดับความเสี่ยงสูงสุดของสแกนนี้'
    title = {'high': worst, 'med': worst, 'low': worst, 'none': 'ผลการค้นหา CVE'}.get(key, 'ระดับความเสี่ยงของสแกนนี้')
    return {'pill': badge['label'], 'key': key, 'title': title, 'text': badge['detail'] + ' ดูรายละเอียดในหัวข้อ 1'}


def _cover_notice(scan_type):
    text = 'รายงานนี้แสดงผล ณ เวลาที่สแกน และไม่ได้รับรองว่าปลอดภัยหรือไม่ปลอดภัยหลังจากนั้น'
    if scan_type == 'vuln_scan':
        text += ' CVE ได้จากการจับคู่ชื่อและเวอร์ชันของบริการกับฐานข้อมูล NVD และยังไม่ได้ยืนยันว่ามีผลกับอุปกรณ์ที่พบจริง'
    else:
        text += ' สิ่งที่ไม่ทราบแสดงเป็น "ยังไม่ทราบ" ไม่ใช้การคาดเดา'
    return {'lead': 'ข้อควรทราบ', 'text': text}


def _about_paras(scan_type):
    """"เกี่ยวกับรายงานนี้": plain sentences that are true for every scan type (the one about CVEs is the only part that depends on the type)."""
    paras = ['รายงานนี้จัดทำโดยระบบ Clylar และสรุปผลการสแกนเครือข่ายหนึ่งครั้ง แบ่งเป็น 5 หัวข้อ ได้แก่ สรุปผลโดยย่อ สรุปผลที่พบ แผนภาพเครือข่าย รายการอุปกรณ์ที่พบ และภาคผนวก']
    if scan_type == 'vuln_scan':
        paras.append('สิ่งที่ไม่ทราบจะแสดงเป็น "ยังไม่ทราบ" เสมอ ไม่ใช้การคาดเดา และ "ไม่พบ CVE" หมายถึงค้นหาแล้วไม่พบเท่านั้น ไม่ได้รับรองว่าปลอดภัย')
    elif scan_type == 'xml_upload':
        paras.append('สิ่งที่ไม่ทราบจะแสดงเป็น "ยังไม่ทราบ" เสมอ ไม่ใช้การคาดเดา ไฟล์ที่นำเข้าไม่มีผลการค้นหา CVE จึงยังไม่ทราบระดับความเสี่ยงของอุปกรณ์')
    else:
        paras.append('สิ่งที่ไม่ทราบจะแสดงเป็น "ยังไม่ทราบ" เสมอ ไม่ใช้การคาดเดา การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่ทราบระดับความเสี่ยงของอุปกรณ์')
    return paras


APPENDIX_TOC = [['A. ข้อมูลการสแกนโดยละเอียด', 'B. เปลี่ยนแปลงจากสแกนก่อนหน้า', 'C. วิธีค้นหา CVE'],
                ['D. สิ่งที่รายงานนี้ไม่ได้บอก', 'E. ระดับความรุนแรง (CVSS)', 'F. ระดับความเสี่ยงของอุปกรณ์']]


def _contents(findings, groups):
    """The contents page. Titles only: the PAGE of a section that flows (2 and 4) is measured in the browser after layout and written in by the page's script, so
    it is never a guess; the fixed pages (about = 2, section 1 = 3) are known. `anchor` names the element of the page whose page is wanted ('toc-...' ids)."""
    s2 = []
    if findings.get('rows'):
        s2.append({'title': 'ตาราง CVE เรียงตามความรุนแรง', 'anchor': 'toc-find'})
    if findings.get('hosts'):
        s2.append({'title': 'สรุปตามอุปกรณ์', 'anchor': 'toc-hosts'})
    s4 = [{'title': ('เครือข่ายย่อย ' if '/' in g['title'] else '') + g['title'], 'anchor': f'toc-g{i}'} for i, g in enumerate(groups[:MAX_TOC_GROUPS])]
    more = len(groups) - MAX_TOC_GROUPS
    if more > 0:
        s4.append({'title': f'และอีก {more} กลุ่ม', 'anchor': ''})
    return [
        {'key': 'about', 'num': '', 'title': 'เกี่ยวกับรายงานนี้', 'page': 2, 'subs': []},
        {'key': 's1', 'num': 1, 'title': 'สรุปผลโดยย่อ', 'page': 3, 'subs': [{'title': 'ระดับความเสี่ยง และตัวเลขสำคัญ', 'page': 3}, {'title': 'รายการที่ควรตรวจสอบก่อน และข้อจำกัดของผลนี้', 'page': 3}]},
        {'key': 's2', 'num': 2, 'title': 'สรุปผลที่พบ', 'page': None, 'anchor': 'toc-s2', 'subs': s2},
        {'key': 's3', 'num': 3, 'title': 'แผนภาพเครือข่าย', 'page': None, 'anchor': 'toc-s3', 'subs': []},
        {'key': 's4', 'num': 4, 'title': 'รายการอุปกรณ์ที่พบ', 'page': None, 'anchor': 'toc-s4', 'subs': s4},
        {'key': 's5', 'num': 5, 'title': 'ภาคผนวก', 'page': None, 'anchor': 'toc-s5', 'subs': [{'title': ' · '.join(line), 'anchor': 'toc-s5'} for line in APPENDIX_TOC]},
    ]


# ---------------------------------------------------------------- the whole report
def build_report(scan, hosts, now, type_labels=None):
    """scan: dict with id (the database id, for URLs), number (optional: the "Job #N" the app shows, printed in the header and footers; a missing or
    bad one prints the id), scan_type, scan_name, target, status, started, finished (datetimes or None), timing, version_intensity,
    custom_args, multicast, skip_ping, all_ports, no_dns, host_probes, gentle, udp, udp_top (the job's columns: all of them go to scanner.describe_scan_settings, which
    builds the command the scan really ran; None = not applicable or a job from before the option; udp_top is 100 or 1000 for a UDP run of nmap's top N ports, None for the 12 common ones), nmap_version, run (app.describe_run), and, all optional: run_facts (app.scan_run_info: a missing key = not
    recorded), owner (the owner's username), triggered_by ('manual' | 'rescan' | 'drilldown' | 'schedule' | 'chatbot'), changes (app.scan_changes() or
    None) and changes_failed (True when that comparison raised). hosts: the parsed result_data list. now: a datetime for "created at".
    type_labels: scan type -> name. Returns the plain dict the template draws (see the keys at the end of this function)."""
    type_labels = type_labels or {}
    scan_type = scan.get('scan_type') or ''
    job_number = _shown_number(scan.get('number'), scan.get('id'))      # the "Job #N" the app shows (scan['number']); scan['id'] (the database id) stays in job_id for the URLs
    rows_in =[h for h in (hosts or []) if isinstance(h, dict) and h.get('ip')]
    error = next((str(h['error'])[:300] for h in (hosts or []) if isinstance(h, dict) and h.get('error')), '')
    # ALL the settings the scan was started with go to scanner.describe_scan_settings, which builds the arguments with the same function the scan ran with
    # (scanner.scan_arguments): a scan with all ports, no DNS, extra probes, Gentle or the UDP pass (and its range, udp_top) prints the command that really ran,
    # never the plain default
    settings = describe_scan_settings(scan_type, scan.get('timing'), scan.get('version_intensity'), scan.get('custom_args'), scan.get('multicast'),
                                      scan.get('skip_ping'), scan.get('all_ports'), scan.get('no_dns'), scan.get('host_probes'), scan.get('gentle'), scan.get('udp'),
                                      scan.get('udp_top'))
    facts = scan.get('run_facts') if isinstance(scan.get('run_facts'), dict) else {}      # what the run recorded about itself; a missing key = not recorded
    udp_tier = _udp_tier(settings, facts)            # the range of the UDP run (12 common ports, or nmap's top 100 / 1000): every UDP sentence below is about THAT run
    rows = [_host_row(h, scan_type, udp_tier['minutes']) for h in rows_in]

    # ---- the header cells
    args = (settings.get('arguments') or '').strip()
    if scan_type == 'xml_upload':
        command, command_note = '', 'นำเข้าจากไฟล์ XML จึงไม่มีคำสั่งที่ใช้สแกน'
    elif args:
        command, command_note = _clip_marked(f"nmap {args} {scan.get('target') or ''}".strip(), MAX_COMMAND_TEXT), ''
    else:
        command, command_note = '', 'ไม่ได้บันทึกคำสั่งไว้ (งานเก่า)'
    # the UDP option is a SECOND nmap run, on the hosts the first run found up (known only when that run is over), so its command ends with a placeholder
    command_udp = (_clip_marked(f"nmap {settings['udp_arguments']} {UDP_SECOND_RUN_TARGETS}", MAX_COMMAND_TEXT)
                   if settings.get('udp') and settings.get('udp_arguments') else '')
    steps = [(_udp_step_text(udp_tier) if s == 'udp_pass' else STEP_TEXT[s]) for s in settings.get('steps', []) if s in STEP_TEXT]
    skip_ping = bool(settings.get('skip_ping') or facts.get('skip_ping') is True or scan.get('skip_ping'))
    started, finished = scan.get('started'), scan.get('finished')
    duration = int((finished - started).total_seconds()) if started and finished and finished >= started else None
    is_upload = scan_type == 'xml_upload'
    label = type_labels.get(scan_type, scan_type or '—')
    total_ips = target_address_count(scan.get('target'))

    # ---- tiles
    n_hosts = len(rows)
    scopes = [_scope(_ip(r['ip'])) for r in rows]
    open_total = sum(r['open_count'] for r in rows)
    proto_counts = {}
    for r in rows:
        for pr in r['protocols']:
            proto_counts[pr] = proto_counts.get(pr, 0) + 1
    evaluated = [r for r in rows if r['risk'] != 'unknown']
    high_hosts = [r['ip'] for r in rows if r['risk'] == 'high']
    all_cves = {}
    for r in rows:
        for c in r['_cve_all']:
            old = all_cves.get(c['id'])
            kev = _merge_kev(old['kev'], c['kev']) if old else c['kev']
            if old is None or (c['score'] or -1) > (old['score'] or -1):
                all_cves[c['id']] = dict(c, product=next((_product(p) or p.get('name') or '' for p in r['_open_ports']
                                                            if any(isinstance(x, dict) and x.get('cve_id') == c['id'] for x in (p.get('cves') or []))), ''))
            all_cves[c['id']]['kev'] = kev
    top_cve = max(all_cves.values(), key=lambda c: (c['score'] if c['score'] is not None else -1), default=None)

    # the CVE tile's breakdown counts what the tile counts (the distinct CVE ids of the whole scan), so its numbers add up to the tile's number
    sev_counts = dict.fromkeys(('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'), 0)
    for c in all_cves.values():
        sev_counts[c['severity'] if c['severity'] in sev_counts else 'UNKNOWN'] += 1

    tiles = {
        'hosts': {'value': n_hosts, 'of': total_ips if (total_ips and total_ips >= n_hosts) else None,
                  'sub': f"ภายใน {scopes.count('internal')} | ภายนอก {scopes.count('external')}"},
        'ports': {'value': open_total, 'sub': ' | '.join(f'{k.upper()} {v}' for k, v in sorted(proto_counts.items())) or 'ไม่พบพอร์ตที่เปิด'},
    }
    not_scanned = [r for r in rows if not r['ports_known']]
    timed = [r for r in not_scanned if r['timed_out']]       # nmap gave up on these hosts (--host-timeout): their ports are unknown for that reason
    plain = [r for r in not_scanned if not r['timed_out']]   # the scan never looked at their ports
    if rows and len(not_scanned) == len(rows):       # no host has a port list: no count (not 0); say WHY, in the words that are true
        tiles['ports'] = {'value': None, 'sub': 'ยังไม่ทราบ: ' + (HOST_TIMEOUT_TEXT if not plain else 'การสแกนนี้ไม่ได้ตรวจพอร์ต' if not timed
                                                                  else f'ไม่ได้สแกนพอร์ต {len(plain)} เครื่อง · ไม่ทราบพอร์ตเพราะหมดเวลา {len(timed)} เครื่อง')}
    elif not_scanned:                                # the count is of the hosts that were port-scanned; say how many were not (no number is made up for them)
        if plain:
            tiles['ports']['sub'] += f' | ไม่ได้สแกนพอร์ต {len(plain)} เครื่อง'
        if timed:
            tiles['ports']['sub'] += f' | ไม่ทราบพอร์ตเพราะหมดเวลา {len(timed)} เครื่อง'
    if rows and len(not_scanned) < len(rows):
        n_unlisted, n_udp_unknown = sum(1 for r in rows if r['unlisted']), sum(1 for r in rows if r['udp_unknown'])
        if n_unlisted:                               # open ports nmap did not name are not in the number
            tiles['ports']['sub'] += f' | ไม่รวมพอร์ตที่เปิดซึ่ง nmap ไม่ได้แยกรายงาน {n_unlisted} เครื่อง'
        if n_udp_unknown:                            # the UDP result of these hosts is unknown, so the number leaves UDP out for them
            tiles['ports']['sub'] += f' | ไม่ทราบพอร์ต UDP {n_udp_unknown} เครื่อง'
    if not evaluated and scan_type == 'vuln_scan':       # it did look; say what happened (the reason of each host is on page 3)
        why = _vuln_unevaluated_text(rows)
        tiles['high'] = {'value': None, 'sub': why + ' (ดูเหตุผลของแต่ละอุปกรณ์ในหัวข้อ 4)'}
        tiles['cves'] = {'value': None, 'sub': why, 'breakdown': []}
    elif not evaluated:                                   # a scan that never looks for CVEs
        tiles['high'] = {'value': None, 'sub': 'ยังไม่ทราบ: การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE)'}
        tiles['cves'] = {'value': None, 'sub': 'ยังไม่ทราบ: ใช้สแกนช่องโหว่ (CVE) เพื่อค้นหา CVE', 'breakdown': []}
    else:
        tiles['high'] = {'value': len(high_hosts), 'sub': (_hosts_text(high_hosts) if high_hosts else 'ไม่มีอุปกรณ์ที่พบ CVE ระดับสูง')
                         + ('' if len(evaluated) == n_hosts else f' (ประเมินได้ {len(evaluated)} จาก {n_hosts} เครื่อง)')}
        cve_sub = (f"CVSS สูงสุด {top_cve['score']:.1f}" + (f" ({_clip(top_cve['product'], 34)})" if top_cve['product'] else '')) if top_cve and top_cve['score'] is not None \
            else ('พบ CVE แต่ไม่มีคะแนน CVSS' if all_cves else 'ไม่พบ CVE จากพอร์ตที่ตรวจ')
        # Critical, High, Medium and Low always (a zero says "none of those"), Unknown only when some CVE has no usable label; nothing when there is no CVE
        breakdown = [{'key': k.lower(), 'label': _sev_name(k), 'n': n} for k, n in sev_counts.items() if all_cves and (n or k != 'UNKNOWN')]
        tiles['cves'] = {'value': len(all_cves), 'sub': cve_sub, 'breakdown': breakdown}

    # ---- the two bar charts
    type_counts = {}
    for r in rows:
        type_counts.setdefault(r['type_key'], []).append(r['ip'])
    device_types = sorted(({'key': k, 'label': TYPE_LABEL[k], 'count': len(v), 'hosts': _hosts_text(v)} for k, v in type_counts.items()),
                          key=lambda d: (-d['count'], d['label']))
    risk_levels = [{'key': k, 'label': name, 'count': sum(1 for r in rows if r['risk'] == k), 'hosts': _hosts_text([r['ip'] for r in rows if r['risk'] == k])}
                   for k, name in LEVELS]
    for chart in (device_types, risk_levels):
        top = max((c['count'] for c in chart), default=0)
        for c in chart:
            c['pct'] = round(c['count'] * 100 / top, 1) if top else 0

    # ---- the inventory, grouped by subnet
    buckets = {}
    for r in sorted(rows, key=lambda r: ((_ip(r['ip']).version, int(_ip(r['ip']))) if _ip(r['ip']) else (9, 0))):
        key, title = _group_of(_ip(r['ip']))
        buckets.setdefault((key, title), []).append(r)
    groups, n = [], 0
    for (key, title), items in sorted(buckets.items(), key=lambda kv: kv[0][0]):
        for it in items:
            n += 1
            it['n'] = n
        sub = f'{len(items)} เครื่อง' + (' | มีเครื่องสแกนอยู่ในวงนี้' if any(i['local'] for i in items) else '')
        groups.append({'title': title, 'subtitle': sub, 'rows': items})
    # ---- page 2 (findings), page 1 (summary) and page 5 (appendix): all of them need the private keys, so they are built before those are dropped
    distinct = tiles['cves']['value']                    # None when no service could be evaluated
    findings, frows = _findings(rows, scan_type, distinct, _vuln_unevaluated_text(rows))
    status_counts = _status_counts(rows)
    kev_known = [c['kev'] for c in all_cves.values() if c['kev'] is not None]
    run_summary = _run_summary(scan.get('run'))
    nmap_version = str(scan.get('nmap_version') or '')[:20]
    who = _who_text(scan.get('owner'), scan.get('triggered_by'), scan_type)
    multi = len(rows) > 1
    top = [{'n': i, 'sev_key': x['sev_key'], 'sev_label': x['sev_label'], 'score': x['score'], 'cve_id': x['cve_id'], 'kev': x['kev'],
            'where': ' · '.join(t for t in ((x['ip'] if multi else ''), f"พอร์ต {x['port']}" + (f" {x['product']}" if x['product'] else ''), x['weakness']) if t)}
           for i, x in enumerate(frows[:TOP_FINDINGS], 1)]
    if distinct:
        sev_rows = [{'key': _sev_class(k), 'label': _sev_name(k), 'n': n, 'pct': round(n * 100 / distinct, 1)} for k, n in sev_counts.items() if n or k != 'UNKNOWN']
    else:
        sev_rows = []
    if frows:
        top_empty = ''
    elif distinct is not None:
        top_empty = 'ไม่พบ CVE จากพอร์ตที่ตรวจ จึงไม่มีรายการให้เรียงลำดับ (ไม่ได้แปลว่าปลอดภัย)'
    elif scan_type == 'vuln_scan':
        top_empty = _vuln_unevaluated_text(rows)
    else:
        top_empty = 'การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่มีรายการให้เรียงลำดับ ใช้สแกนช่องโหว่ (CVE) เพื่อค้นหา CVE'
    if not frows:
        top_note = ''
    elif findings['hidden']:                              # say "all" only when nothing was cut
        top_note = ('เรียงตามความรุนแรงแล้วคะแนน CVSS เท่านั้น ไม่ได้ประเมินว่าโจมตีได้จริง '
                    f"หัวข้อ 2 แสดง {len(findings['rows'])} จาก {findings['total']} รายการ ส่วนที่เหลือดูได้ในหน้ารายงานผลสแกนในระบบ")
    else:
        top_note = 'เรียงตามความรุนแรงแล้วคะแนน CVSS เท่านั้น ไม่ได้ประเมินว่าโจมตีได้จริง รายการครบอยู่ในหัวข้อ 2'
    n_udp_unknown = sum(1 for r in rows if r['udp_unknown'])
    if n_udp_unknown:
        udp_gap = f'{UDP_UNKNOWN_TEXT} ของ {n_udp_unknown} เครื่อง'
    elif facts.get('udp_failed') is True:                  # only the scan said so (no host carries the flag): still not "every open port"
        udp_gap = f'{UDP_UNKNOWN_TEXT} เพราะ{UDP_FAILED_TEXT}'
    else:
        udp_gap = ''
    n_none_udp = sum(1 for r in rows if r['risk'] == 'none' and r['udp_unknown'])
    risk_note = f'กลุ่ม "ไม่พบ CVE" มี {n_none_udp} เครื่องที่{UDP_UNKNOWN_TEXT} จึงค้นหา CVE ได้เฉพาะพอร์ตที่ทราบ' if n_none_udp else ''
    dot_note = f'สำหรับอุปกรณ์ที่{UDP_UNKNOWN_TEXT} สีของจุดนับจากพอร์ตที่เปิดเท่าที่ทราบ' if n_udp_unknown else ''
    summary = {
        'badge': _badge(rows, frows, scan_type, len(evaluated), scan.get('status'), udp_gap),
        'lead': _lead(rows, scan_type, tiles, facts, skip_ping, total_ips, status_counts),
        'sev': sev_rows,
        'kev': {'n': sum(1 for k in kev_known if k), 'of': len(kev_known)} if kev_known else None,
        'top': top, 'top_empty': top_empty, 'top_note': top_note,
        'limits': _limits(scan_type, facts, skip_ping, rows, settings),
    }
    appendix = {
        'scan': _appendix_scan(scan, settings, label, steps, facts, nmap_version, run_summary, who),
        'changes': _changes_view(scan.get('changes'), bool(scan.get('changes_failed')), scan_type, scan.get('status'), udp_tier['top']),
        'method': {'lead': '' if scan_type == 'vuln_scan' else 'การสแกนนี้ไม่ได้ค้นหา CVE ถ้าใช้สแกนช่องโหว่ (CVE) ระบบจะทำตามขั้นตอนนี้:',
                   'steps': list(METHOD_STEPS), 'note': 'บริการที่ nmap ระบุผลิตภัณฑ์ไม่ได้ ไม่ถูกค้นหา และแสดงเป็น "ยังไม่ทราบ" ไม่ใช่ "ไม่พบ CVE"'},
        'limits': _not_said(scan_type, skip_ping, (any(r['not_open_reasoned'] for r in rows) if any(r['not_open_count'] for r in rows) else None),
                            all_ports=settings.get('all_ports') is True or facts.get('ports_scanned') == 65535, udp=settings.get('udp') is True or facts.get('udp') is True,
                            host_probes=settings.get('host_probes') is True or facts.get('host_probes') is True, udp_tier=udp_tier,
                            udp_unlisted=any(r['udp_unlisted_text'] or r['udp_open_unlisted'] for r in rows)),
        'scale': SCALE, 'scale_note': 'CVE ที่ NVD ให้คะแนนด้วย CVSS v2 อย่างเดียวและได้ 9.0 ขึ้นไป ระบบนับเป็นวิกฤต (v2 ไม่มีระดับวิกฤต)',
        'levels': [{'key': k, 'label': name, 'text': (LEVEL_NONE_UDP_TEXT if (k == 'none' and udp_gap) else LEVEL_TEXT[k])} for k, name in LEVELS],
    }
    for r in rows:
        r.pop('_cve_all'); r.pop('_open_ports')

    # ---- notes that keep the reader honest
    notes = ['แสดงเฉพาะพอร์ตที่ open']                      # the two that sit under the heading of the inventory; the rest go under the table
    if scan_type == 'vuln_scan' and findings['hidden']:
        notes.append(f"หัวข้อ 2 แสดง CVE {len(findings['rows'])} จาก {findings['total']} รายการ ส่วนที่เหลือดูได้ในหน้ารายงานผลสแกนในระบบ (หัวข้อนี้แสดงเพียงสรุปของแต่ละอุปกรณ์)")
    elif scan_type == 'vuln_scan':
        notes.append('รายละเอียด CVE ทั้งหมดอยู่ในหัวข้อ 2 (หัวข้อนี้แสดงเพียงสรุปของแต่ละอุปกรณ์)')
    else:
        notes.append('การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE) ระดับความเสี่ยงจึงเป็น "ยังไม่ทราบ"')
    footnotes = ['ประเภทอุปกรณ์เป็นการคาดเดาจาก OS ผู้ผลิต MAC พอร์ตและชื่อบริการ ไม่ใช่ข้อเท็จจริง']
    if any(r['ports_more'] for r in rows):
        footnotes.append(f'แสดงสูงสุด {MAX_PORT_LINES} พอร์ตต่ออุปกรณ์ ข้อมูลครบถ้วนอยู่ในหน้ารายงานในระบบ')

    # ---- the portrait frame (cover, contents, about): plain data, drawn only by the portrait layout
    status = scan.get('status') or ''
    kicker, title_lines = _cover_titles(scan_type, status, status_counts['ok'] > 0)
    if is_upload:
        kicker = COVER_KICKER_XML
    elif kicker is None:
        kicker = label
    name_clipped = _clip_marked(scan.get('scan_name'), MAX_NAME_TEXT)
    when_text = _fmt_dt(started)
    if when_text and finished and duration is not None and not is_upload:
        when_text += f' (ใช้เวลา {_duration_text(duration)})'            # only when both times are recorded
    cover_rows = [{'k': 'เป้าหมาย', 'v': _clip_marked(scan.get('target'), MAX_TARGET_TEXT) or '—', 'mono': True},
                  {'k': 'ประเภทการสแกน', 'v': label},
                  {'k': 'นำเข้าเมื่อ' if is_upload else 'สแกนเมื่อ', 'v': when_text or 'ไม่ได้บันทึกไว้'}]
    if status in _NOT_DONE:
        cover_rows.append({'k': 'สถานะงาน', 'v': _NOT_DONE[status]})
    if who:
        cover_rows.append({'k': 'ผู้สั่งสแกน', 'v': who})
    cover_rows.append({'k': 'งานสแกน', 'v': f'งาน #{job_number}'})
    if now:
        cover_rows.append({'k': 'สร้างรายงานเมื่อ', 'v': now.strftime('%Y-%m-%d %H:%M') + ' (Asia/Bangkok)'})
    cover = {'kicker': kicker, 'title': list(title_lines), 'title_flat': ''.join(title_lines),
             'scan_line': (name_clipped + ' · ' + label if name_clipped else label) if kicker != label else name_clipped, 'rows': cover_rows,      # the kicker already says the type for most scans
             'risk': _cover_risk(summary['badge'], scan_type, status, is_upload), 'notice': _cover_notice(scan_type)}

    return {
        'cover': cover, 'contents': _contents(findings, groups), 'about': _about_paras(scan_type),
        'running_target': _clip(scan.get('target'), MAX_RUNNING_TARGET),
        'system_name': SYSTEM_NAME,
        'title': 'รายงานผลการสแกนเครือข่าย',
        'subtitle': f"รายงานผลการสแกนเครือข่าย | งาน #{job_number} | {_clip_marked(scan.get('scan_name'), MAX_NAME_TEXT) or label}",
        'created_text': f"สร้างรายงาน {now.strftime('%Y-%m-%d %H:%M')} (Asia/Bangkok)" if now else '',
        'job_id': scan.get('id'), 'job_number': job_number, 'scan_type': scan_type, 'type_label': label, 'scan_name': scan.get('scan_name') or '',
        'status': scan.get('status') or '', 'notice': STATUS_NOTICE.get(scan.get('status') or '', ''), 'error': error,
        'source_label': label, 'source_tag': 'ไฟล์ที่อัปโหลด' if is_upload else 'สแกนจากระบบ',
        'target': _clip_marked(scan.get('target'), MAX_TARGET_TEXT), 'started_text': _fmt_dt(started), 'finished_text': _fmt_dt(finished), 'duration_text': _duration_text(duration),
        'command': command, 'command_note': command_note, 'command_udp': command_udp, 'steps': steps,
        'nmap_version': nmap_version,                      # from the scan's own XML; empty for scans that did not keep it
        'run_summary': run_summary,                        # "ตรวจ N IP · ตอบกลับ M · ไม่ตอบ K"; empty for a scan that did not keep it
        'who_text': who,                                   # who ordered the scan and how; empty when the report was not given it
        'tiles': tiles, 'device_types': device_types, 'risk_levels': risk_levels, 'risk_note': risk_note, 'dot_note': dot_note,
        'summary': summary, 'findings': findings, 'appendix': appendix,
        'groups': groups, 'host_count': n_hosts, 'notes': notes, 'footnotes': footnotes,
        'running_head': f"{'รายงานผลการสแกนเครือข่าย'} | งาน #{job_number}",
        'running_date': f"สแกนเมื่อ {started.strftime('%Y-%m-%d %H:%M')}" if started else '',
    }
