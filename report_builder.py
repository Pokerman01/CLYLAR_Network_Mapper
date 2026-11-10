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
  * device types come from scanner.guess_device_type() and are always shown as a guess ("น่าจะ" when the evidence is thin);
  * "N IP" scanned is shown only when the target can be counted exactly or nmap said so;
  * a sentence about the run (no Administrator rights, no Npcap, -Pn, the ARP cache) is written only when the run recorded that fact.
"""
import ipaddress
import re

from cwe_data import cwe_info
from scanner import (describe_scan_settings, effective_severity, guess_device_type, os_match_accuracy, port_reason, port_reason_label, virtual_machine_platform)

SYSTEM_NAME = 'Clylar'

# risk levels, in the order the report shows them
LEVELS = [
    ('high', 'สูง'),
    ('med', 'กลาง'),
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

STEP_TEXT = {
    'nvd_lookup': 'ค้นหา CVE จาก NVD ตามชื่อและเวอร์ชันของบริการที่พบ',
    'mdns_ssdp': 'ฟังการตอบกลับ mDNS / SSDP ระหว่างสแกน',
    'gateway_probe': 'ตรวจหา default gateway ของเครื่องที่สแกน',
}
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
    return {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}.get(sev, 'Unknown')


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


def _eval_text(ports_known, n_open, n_ok, scan_type):
    """How much of a host's open ports were really looked up for CVEs, in one phrase (page 2's host table and page 4's inventory)."""
    if not ports_known:
        return 'ไม่ได้สแกนพอร์ต'
    if n_open == 0:
        return 'ไม่มีพอร์ตที่เปิด'
    if scan_type != 'vuln_scan' and n_ok == 0:
        return 'ไม่ได้ค้นหา CVE'
    return f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต'


def _host_risk(open_ports, cves, scan_type, ports_known=True):
    """(level key, one-line reason). See the module docstring: only what was really checked is called "ไม่พบ CVE".
    ports_known False = the scan has no port list for this host (a Discovery scan never looks at ports): that is not "0 open"."""
    if not ports_known and not cves:
        return 'unknown', 'ไม่ได้สแกนพอร์ต จึงยังไม่ได้ตรวจ CVE'
    n_open = len(open_ports)
    statuses = [_port_status(p) for p in open_ports]
    n_ok = statuses.count('ok')
    if cves:
        level = max((c['level'] for c in cves), key=lambda k: _LEVEL_RANK[k])
        reason = '' if n_ok == n_open else f'ประเมินได้ {n_ok} จาก {n_open} พอร์ต'
        return level, reason
    if n_open == 0:
        return 'unknown', 'ไม่มีพอร์ตที่เปิดให้ตรวจ CVE'
    if scan_type != 'vuln_scan' and n_ok == 0:
        return 'unknown', 'การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE)'
    if n_ok == n_open:
        return 'none', 'ไม่พบ CVE จากพอร์ตที่ตรวจ'
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
        return 'ไม่มีพอร์ตที่เปิดให้ค้นหา CVE' + (' หรือไม่ได้สแกนพอร์ต' if any(not r['ports_known'] for r in rows) else '')
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
    return key, TYPE_LABEL[key] + (' (น่าจะ)' if likely else ''), likely


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


def _not_open(ports):
    """The ports that are NOT open, as one short line: (text, count, reasoned). Grouped by (state, nmap's reason), biggest group first, at most
    MAX_NOT_OPEN_GROUPS groups named and "+N กลุ่ม" for the rest. The count is exact. A group whose ports have no recorded reason (a scan from before
    `reason` was kept, or text that is not a plain nmap reason) shows only the state and the count: no "unknown reason" words. Nothing in the list that
    is not a port record is counted. '' / 0 when there is nothing to say. `reasoned` is True when at least one of these ports carries a reason."""
    groups = {}
    total = 0
    for p in ports:
        if not isinstance(p, dict) or _is_open(p):
            continue
        state = _clip(str(p.get('state') or '').lower(), MAX_STATE_TEXT) or 'ไม่ทราบสถานะ'
        key = (state, port_reason(p.get('reason')))
        groups[key] = groups.get(key, 0) + 1
        total += 1
    if not total:
        return '', 0, False
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1] is None, kv[0][1] or ''))
    named = [f"{state} {n}" + (f" ({port_reason_label(reason)})" if reason else '') for (state, reason), n in ordered[:MAX_NOT_OPEN_GROUPS]]
    more = len(ordered) - MAX_NOT_OPEN_GROUPS
    text = f'ไม่เปิดอีก {total} พอร์ต: ' + ', '.join(named) + (f' +{more} กลุ่ม' if more > 0 else '')
    return text, total, any(reason for (_, reason) in groups)


def _host_row(h, scan_type):
    # a host has a port list only when 'ports' is a list (even an empty one: then 0 open is a fact); a missing key, null or anything else
    # means the scan never looked at this host's ports, which is NOT the same as "none open"
    ports_known = isinstance(h.get('ports'), list)
    open_ports = sorted([p for p in (h.get('ports') if ports_known else []) if _is_open(p)], key=lambda p: (_port_number(p), str(p.get('protocol') or '')))
    cves = _host_cves(open_ports)
    level, reason = _host_risk(open_ports, cves, scan_type, ports_known)
    type_key, type_label, type_likely = _device_type(h, open_ports)
    mac = (h.get('mac') or '').strip()
    mac = '' if mac.lower() in ('', 'unknown') else mac
    os_name = (h.get('os') or '').strip()
    os_name = '' if os_name.lower() in ('', 'unknown', 'up', 'down') else os_name
    ports = [{'text': f"{p.get('port')}/{p.get('protocol') or 'tcp'} {p.get('name') or ''}".strip(), 'product': _clip(_product(p), 42)}
             for p in open_ports[:MAX_PORT_LINES]]
    n_ok = sum(1 for p in open_ports if _port_status(p) == 'ok')
    # a host whose ports were never scanned has nothing to say about ports that are not open (that is "unknown", not "none")
    not_open_text, not_open_count, not_open_reasoned = _not_open(h.get('ports')) if ports_known else ('', 0, False)
    return {
        'ip': h.get('ip', ''), 'hostname': (h.get('hostname') or '').strip(), 'mac': mac, 'mac_vendor': (h.get('mac_vendor') or '').strip(),
        'vm': virtual_machine_platform(mac, h.get('mac_vendor') or ''), 'os': _clip(os_name, 60), 'local': bool(h.get('local')),
        # nmap's confidence in the OS guess: only from THIS record and only with a real OS name (never from another scan's guess)
        'os_confidence': os_match_accuracy(h.get('os_accuracy')) if os_name else None,
        'type_key': type_key, 'type_label': type_label, 'type_likely': type_likely, 'type_name': TYPE_LABEL[type_key],      # type_name without the "(น่าจะ)" so the page can keep that on one line
        'not_open_text': not_open_text, 'not_open_count': not_open_count, 'not_open_reasoned': not_open_reasoned,
        'ports_known': ports_known, 'open_count': len(open_ports), 'ports': ports, 'ports_more': max(0, len(open_ports) - MAX_PORT_LINES),
        'risk': level, 'risk_label': LEVEL_LABEL[level], 'risk_reason': reason,
        'cve_total': len(cves), 'sev_counts': _sev_counts(cves), 'max_text': _max_text(cves),
        'eval_ok': n_ok, 'eval_text': _eval_text(ports_known, len(open_ports), n_ok, scan_type),
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
    hidden_text = ' · '.join(f'{k} {hidden_count[k]}' for k in ('Medium', 'Low', 'Unknown') if hidden_count.get(k))
    ips = {x['ip'] for x in frows}
    single_ip = next(iter(ips)) if len(ips) == 1 else ''
    tail = 'เรียงตามความรุนแรงแล้วคะแนน CVSS · จับคู่จากชื่อและเวอร์ชันของบริการ ยังไม่ผ่านการยืนยัน'
    if not frows:
        sub = ''
    elif total == distinct:
        sub = f'CVE ทั้ง {total} รายการ' + (f'ของ {single_ip} ' if single_ip else 'ของสแกนนี้ ') + tail
    else:
        sub = (f'ตารางนี้มี {total} แถว (นับทีละ host × พอร์ต × CVE) ส่วน CVE ที่ไม่ซ้ำกันของทั้งสแกนมี {distinct} รายการ '
               f'(ตามกล่อง "CVE ที่พบ" หัวข้อ 1) ' + tail)
    looked = scan_type == 'vuln_scan'
    if frows:
        empty = ''
    elif not rows:
        empty = 'ไม่มี host ในผลสแกนนี้ จึงไม่มี CVE ให้แสดง'
    elif distinct is not None:
        empty = 'ไม่พบ CVE จากพอร์ตที่ตรวจ ไม่ได้แปลว่าปลอดภัย (ค้นหาจากชื่อและเวอร์ชันของบริการด้วยคีย์เวิร์ดเท่านั้น)'
    elif looked:
        empty = unevaluated_text
    else:
        empty = 'การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่ทราบว่ามีช่องโหว่หรือไม่ (ไม่ได้แปลว่าไม่มี) ใช้ Vulnerability Scan เพื่อค้นหา CVE'
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


def _badge(rows, frows, scan_type, n_evaluated, status):
    """The scan's overall level, in the host levels' own words. A level of สูง / กลาง / ต่ำ is the worst host's (a floor: a host that could not be
    evaluated may be worse). "ไม่พบ CVE" only when EVERY host was evaluated and clean AND the scan is Completed (the hosts of a Running, Failed or Cancelled
    scan are only the part that was scanned). Everything else is "ยังไม่ทราบ", with the reason."""
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
        level, detail = 'none', 'ค้นหาครบทุกพอร์ตที่เปิดแล้วไม่พบ CVE (การค้นหาไม่พบ ไม่ได้รับรองว่าปลอดภัย)'
    else:
        level = 'unknown'
        if not rows:
            detail = 'ไม่มี host ในผลสแกนนี้'
        elif n_evaluated == 0 and scan_type == 'vuln_scan':
            detail = _vuln_unevaluated_reason(rows)
        elif n_evaluated == 0:
            detail = 'การสแกนนี้ไม่ได้ค้นหา CVE'
        else:
            detail = f'ไม่พบ CVE ในส่วนที่ประเมินได้ แต่ประเมินได้เพียง {n_evaluated} จาก {len(rows)} host'
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
        open_total = sum(r['open_count'] for r in rows)
        if len(not_scanned) == n_hosts:
            pieces.append(('การสแกนนี้ไม่ได้ตรวจพอร์ต', False))
        else:
            s = 'ไม่พบพอร์ตที่เปิด' if open_total == 0 else f'มีพอร์ตที่เปิด {open_total} พอร์ต'
            if not_scanned:
                s += f' (นับเฉพาะ {n_hosts - len(not_scanned)} เครื่องที่สแกนพอร์ต)'
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


def _limits(scan_type, facts, skip_ping):
    """The "what this result cannot tell you" box. A bullet about the run is written only when the run recorded that fact (admin False, npcap False,
    -Pn used, an ARP-cache note > 0); the keyword-match bullet only when a CVE lookup was part of the scan; the last one is always there."""
    out = []
    if scan_type == 'vuln_scan':
        out.append('CVE จับคู่จากชื่อและเวอร์ชันของบริการกับ NVD (สูงสุด 5 รายการต่อพอร์ต) ยังไม่ผ่านการยืนยันว่าใช้ได้กับเครื่องนี้')
    else:
        out.append('การสแกนนี้ไม่ได้ค้นหา CVE ระดับความเสี่ยงของ host จึงเป็น "ยังไม่ทราบ" ไม่ได้แปลว่าปลอดภัย')
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
    return {'set': f'T{v} (ตั้งไว้)', 'type-default': f'T{v} (ค่าเริ่มต้นของประเภทนี้)', 'nmap-default': f'ค่าเริ่มต้นของ nmap (T{v})'}.get(src)


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


def _changes_view(changes, failed, scan_type, status=''):
    """Appendix B. `changes` is app.scan_changes()'s {'prev': {id, seq, when}, 'diff': scan_diff.compare_scans(...)} or None. The earlier scan is named by prev['seq'] (the number the app shows), else by its id. The words follow scan_diff's rules:
    a device missing from the newer scan is "ไม่พบในสแกนนี้" (never "gone"), a port is "ไม่เปิดแล้ว" (never "closed"), a CVE the older scan could not
    judge is counted and never listed. At most MAX_CHANGE_ITEMS per list ("+N" counts the real total). A value that cannot be read says the
    comparison could not be made."""
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
        vs = f"เทียบกับ Scan Job #{_shown_number(prev.get('seq'), prev['id'])}" + (f' ({_clip(when, 30)})' if when else '')
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
        if d.get('missing_devices'):
            notes.append('ไม่พบ ไม่ได้แปลว่าปิดเครื่อง อุปกรณ์อาจบล็อก ping หรือปิดอยู่ชั่วคราว')
        if _int(d.get('cve_unjudged')):
            notes.append(f"มี {d['cve_unjudged']} CVE ที่บอกไม่ได้ว่าใหม่หรือเก่า เพราะการค้นหา CVE ของสแกนใดสแกนหนึ่งไม่สำเร็จหรือไม่ได้บันทึกสถานะไว้ (นับแล้ว แต่ไม่ได้แสดงในรายการ)")
        if 'admin_differs' in (d.get('caveats') or []):
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
        same = ('ไม่พบความเปลี่ยนแปลงของอุปกรณ์ พอร์ตที่เปิด และ CVE ที่เทียบได้' if d.get('cve_compared')
                else 'ไม่พบความเปลี่ยนแปลงของอุปกรณ์' + ('และพอร์ตที่เปิด' if scan_type not in ('discovery', 'xml_upload') else ''))
        return {'state': 'same', 'vs': vs, 'text': same, 'lines': [], 'notes': notes}
    except Exception:
        return {'state': 'failed', 'text': 'เทียบกับสแกนก่อนหน้าไม่ได้'}


METHOD_STEPS = [
    'nmap ตรวจพอร์ตที่เปิดและอ่านชื่อ/เวอร์ชันของบริการ',
    'ระบบค้นหา NVD ด้วยข้อความชื่อผลิตภัณฑ์และเวอร์ชันที่ nmap อ่านได้ (คีย์เวิร์ด ไม่ใช่การจับคู่ CPE)',
    'เก็บผลสูงสุด 5 รายการต่อพอร์ต',
    'ความรุนแรงใช้คะแนน CVSS ที่ NVD ให้ (v3.1 ก่อน แล้ว v3.0 แล้ว v2) CVE ที่ได้คะแนน v2 อย่างเดียวและ 9.0 ขึ้นไป ระบบแสดงเป็น Critical',
]
SCALE = [
    {'label': 'Critical', 'range': '9.0 – 10.0', 'key': 'crit'}, {'label': 'High', 'range': '7.0 – 8.9', 'key': 'high'},
    {'label': 'Medium', 'range': '4.0 – 6.9', 'key': 'med'}, {'label': 'Low', 'range': '0.1 – 3.9', 'key': 'low'}, {'label': 'None', 'range': '0.0', 'key': 'unknown'},
]
LEVEL_TEXT = {
    'high': 'มี CVE ระดับ Critical หรือ High',
    'med': 'CVE ที่รุนแรงที่สุดเป็น Medium',
    'low': 'CVE ที่รุนแรงที่สุดเป็น Low (CVE ที่ไม่มีระดับความรุนแรงนับรวมที่นี่)',
    'none': 'ค้นหาครบทุกพอร์ตที่เปิดแล้วไม่พบ CVE',
    'unknown': 'ประเมินไม่ได้ (ไม่ได้ค้นหา CVE, ค้นหาไม่สำเร็จ, nmap ระบุผลิตภัณฑ์ไม่ได้, ไม่ได้สแกนพอร์ต หรือไม่มีพอร์ตที่เปิด) ไม่ได้แปลว่าปลอดภัย',
}


def _not_said(scan_type, skip_ping, reasons=None):
    """Appendix D: what this report does not say. Each sentence is written only when it is true of this kind of scan.
    reasons: None = this scan has no port that is not open (nothing to add), True = at least one such port carries nmap's reason (the inventory shows
    it), False = such ports exist but none has a recorded reason (an older scan): the sentence says so and never promises reasons."""
    out = ['ไม่ได้ยืนยันว่าช่องโหว่ใช้โจมตีได้จริง (ไม่ได้ทดสอบเจาะระบบ)',
           'ไม่ใช่รายการช่องโหว่ที่ครบถ้วน เป็นเพียง CVE ที่ NVD จับคู่ได้จากชื่อและเวอร์ชันของบริการ (สูงสุด 5 รายการต่อพอร์ต)']
    if scan_type == 'vuln_scan':
        out.append('บริการที่ nmap ระบุผลิตภัณฑ์ไม่ได้ ไม่ได้ถูกค้นหา CVE และแสดงเป็น "ยังไม่ทราบ"')
    if scan_type != 'discovery':
        out.append('พอร์ตที่เป็น filtered หรือ closed ไม่ถูกนำมาประเมิน (นับเฉพาะพอร์ตที่ open)'
                   + (' เหตุผลที่ nmap ให้ไว้แสดงในหัวข้อ 4 เฉพาะพอร์ตที่สแกนบันทึกเหตุผลไว้' if reasons else ' สแกนนี้ไม่ได้บันทึกเหตุผลที่ nmap ให้ไว้ของพอร์ตเหล่านี้' if reasons is False else ''))
    if scan_type not in ('discovery', 'xml_upload'):
        out.append('พอร์ตนอกช่วงที่การสแกนนี้ตรวจจะไม่ปรากฏในผล')
    if scan_type != 'xml_upload' and not skip_ping:
        out.append('อุปกรณ์ที่บล็อก ping อาจไม่ถูกพบ')
    out.append('เป็นผล ณ เวลาที่สแกน ไม่ได้รับรองว่าปลอดภัยหรือไม่ปลอดภัยหลังจากนี้')
    out.append('ไม่มีข้อมูลวิธีแก้ไขในรายงานนี้ เพราะระบบไม่ได้เก็บข้อมูลดังกล่าว')
    return out


# ---------------------------------------------------------------- the whole report
def build_report(scan, hosts, now, type_labels=None):
    """scan: dict with id (the database id, for URLs), number (optional: the "Job #N" the app shows, printed in the header and footers; a missing or
    bad one prints the id), scan_type, scan_name, target, status, started, finished (datetimes or None), timing, version_intensity,
    custom_args, multicast, skip_ping, nmap_version, run (app.describe_run), and, all optional: run_facts (app.scan_run_info: a missing key = not
    recorded), owner (the owner's username), triggered_by ('manual' | 'rescan' | 'drilldown' | 'schedule' | 'chatbot'), changes (app.scan_changes() or
    None) and changes_failed (True when that comparison raised). hosts: the parsed result_data list. now: a datetime for "created at".
    type_labels: scan type -> name. Returns the plain dict the template draws (see the keys at the end of this function)."""
    type_labels = type_labels or {}
    scan_type = scan.get('scan_type') or ''
    job_number = _shown_number(scan.get('number'), scan.get('id'))      # the "Job #N" the app shows (scan['number']); scan['id'] (the database id) stays in job_id for the URLs
    rows_in =[h for h in (hosts or []) if isinstance(h, dict) and h.get('ip')]
    error = next((str(h['error'])[:300] for h in (hosts or []) if isinstance(h, dict) and h.get('error')), '')
    rows = [_host_row(h, scan_type) for h in rows_in]

    # ---- the header cells
    settings = describe_scan_settings(scan_type, scan.get('timing'), scan.get('version_intensity'), scan.get('custom_args'), scan.get('multicast'),
                                      scan.get('skip_ping'))
    args = (settings.get('arguments') or '').strip()
    if scan_type == 'xml_upload':
        command, command_note = '', 'นำเข้าจากไฟล์ XML จึงไม่มีคำสั่งที่ใช้สแกน'
    elif args:
        command, command_note = _clip_marked(f"nmap {args} {scan.get('target') or ''}".strip(), MAX_COMMAND_TEXT), ''
    else:
        command, command_note = '', 'ไม่ได้บันทึกคำสั่งไว้ (งานเก่า)'
    steps = [STEP_TEXT[s] for s in settings.get('steps', []) if s in STEP_TEXT]
    facts = scan.get('run_facts') if isinstance(scan.get('run_facts'), dict) else {}      # what the run recorded about itself; a missing key = not recorded
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
    if rows and len(not_scanned) == len(rows):       # no host has a port list: the scan never looked at ports, so there is no count (not 0)
        tiles['ports'] = {'value': None, 'sub': 'ยังไม่ทราบ: การสแกนนี้ไม่ได้ตรวจพอร์ต'}
    elif not_scanned:                                # the count is of the hosts that were port-scanned; say how many were not (no number is made up for them)
        tiles['ports']['sub'] += f' | ไม่ได้สแกนพอร์ต {len(not_scanned)} host'
    if not evaluated and scan_type == 'vuln_scan':       # it did look; say what happened (the reason of each host is on page 3)
        why = _vuln_unevaluated_text(rows)
        tiles['high'] = {'value': None, 'sub': why + ' (ดูเหตุผลของแต่ละ host ในหัวข้อ 4)'}
        tiles['cves'] = {'value': None, 'sub': why, 'breakdown': []}
    elif not evaluated:                                   # a scan that never looks for CVEs
        tiles['high'] = {'value': None, 'sub': 'ยังไม่ทราบ: การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE)'}
        tiles['cves'] = {'value': None, 'sub': 'ยังไม่ทราบ: ใช้ Vulnerability Scan เพื่อค้นหา CVE', 'breakdown': []}
    else:
        tiles['high'] = {'value': len(high_hosts), 'sub': (_hosts_text(high_hosts) if high_hosts else 'ไม่มี host ที่พบ CVE ระดับสูง')
                         + ('' if len(evaluated) == n_hosts else f' (ประเมินได้ {len(evaluated)} จาก {n_hosts} host)')}
        cve_sub = (f"CVSS สูงสุด {top_cve['score']:.1f}" + (f" ({_clip(top_cve['product'], 34)})" if top_cve['product'] else '')) if top_cve and top_cve['score'] is not None \
            else ('พบ CVE แต่ไม่มีคะแนน CVSS' if all_cves else 'ไม่พบ CVE จากพอร์ตที่ตรวจ')
        # Critical, High, Medium and Low always (a zero says "none of those"), Unknown only when some CVE has no usable label; nothing when there is no CVE
        breakdown = [{'key': k.lower(), 'label': k.title(), 'n': n} for k, n in sev_counts.items() if all_cves and (n or k != 'UNKNOWN')]
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
        sub = f'{len(items)} host' + (' | มีเครื่องสแกนอยู่ในวงนี้' if any(i['local'] for i in items) else '')
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
        top_empty = 'การสแกนนี้ไม่ได้ค้นหา CVE จึงยังไม่มีรายการให้เรียงลำดับ ใช้ Vulnerability Scan เพื่อค้นหา CVE'
    if not frows:
        top_note = ''
    elif findings['hidden']:                              # say "all" only when nothing was cut
        top_note = ('เรียงตามความรุนแรงแล้วคะแนน CVSS เท่านั้น ไม่ได้ประเมินว่าโจมตีได้จริง '
                    f"หัวข้อ 2 แสดง {len(findings['rows'])} จาก {findings['total']} รายการ ส่วนที่เหลือดูได้ในหน้ารายงานผลสแกนในระบบ")
    else:
        top_note = 'เรียงตามความรุนแรงแล้วคะแนน CVSS เท่านั้น ไม่ได้ประเมินว่าโจมตีได้จริง รายการครบอยู่ในหัวข้อ 2'
    summary = {
        'badge': _badge(rows, frows, scan_type, len(evaluated), scan.get('status')),
        'lead': _lead(rows, scan_type, tiles, facts, skip_ping, total_ips, status_counts),
        'sev': sev_rows,
        'kev': {'n': sum(1 for k in kev_known if k), 'of': len(kev_known)} if kev_known else None,
        'top': top, 'top_empty': top_empty, 'top_note': top_note,
        'limits': _limits(scan_type, facts, skip_ping),
    }
    appendix = {
        'scan': _appendix_scan(scan, settings, label, steps, facts, nmap_version, run_summary, who),
        'changes': _changes_view(scan.get('changes'), bool(scan.get('changes_failed')), scan_type, scan.get('status')),
        'method': {'lead': '' if scan_type == 'vuln_scan' else 'การสแกนนี้ไม่ได้ค้นหา CVE ถ้าใช้ Vulnerability Scan ระบบจะทำตามขั้นตอนนี้:',
                   'steps': list(METHOD_STEPS), 'note': 'บริการที่ nmap ระบุผลิตภัณฑ์ไม่ได้ ไม่ถูกค้นหา และแสดงเป็น "ยังไม่ทราบ" ไม่ใช่ "ไม่พบ CVE"'},
        'limits': _not_said(scan_type, skip_ping, (any(r['not_open_reasoned'] for r in rows) if any(r['not_open_count'] for r in rows) else None)),
        'scale': SCALE, 'scale_note': 'CVE ที่ NVD ให้คะแนนด้วย CVSS v2 อย่างเดียวและได้ 9.0 ขึ้นไป ระบบนับเป็น Critical (v2 ไม่มีระดับ Critical)',
        'levels': [{'key': k, 'label': name, 'text': LEVEL_TEXT[k]} for k, name in LEVELS],
    }
    for r in rows:
        r.pop('_cve_all'); r.pop('_open_ports')

    # ---- notes that keep the reader honest
    notes = ['แสดงเฉพาะพอร์ตที่ open']                      # the two that sit under the heading of the inventory; the rest go under the table
    if scan_type == 'vuln_scan' and findings['hidden']:
        notes.append(f"หัวข้อ 2 แสดง CVE {len(findings['rows'])} จาก {findings['total']} รายการ ส่วนที่เหลือดูได้ในหน้ารายงานผลสแกนในระบบ (หัวข้อนี้แสดงเพียงสรุปของแต่ละ host)")
    elif scan_type == 'vuln_scan':
        notes.append('รายละเอียด CVE ทั้งหมดอยู่ในหัวข้อ 2 (หัวข้อนี้แสดงเพียงสรุปของแต่ละ host)')
    else:
        notes.append('การสแกนนี้ไม่ได้ตรวจช่องโหว่ (CVE) ระดับความเสี่ยงจึงเป็น "ยังไม่ทราบ"')
    footnotes = ['ประเภทอุปกรณ์เป็นการคาดเดาจาก OS ผู้ผลิต MAC พอร์ตและชื่อบริการ ไม่ใช่ข้อเท็จจริง']
    if any(r['ports_more'] for r in rows):
        footnotes.append(f'แสดงสูงสุด {MAX_PORT_LINES} พอร์ตต่อ host ข้อมูลครบถ้วนอยู่ในหน้ารายงานในระบบ')

    return {
        'system_name': SYSTEM_NAME,
        'title': 'รายงานผลการสแกนเครือข่าย',
        'subtitle': f"Network Scan Report | Scan Job #{job_number} | {_clip_marked(scan.get('scan_name'), MAX_NAME_TEXT) or label}",
        'created_text': f"สร้างรายงาน {now.strftime('%Y-%m-%d %H:%M')} (Asia/Bangkok)" if now else '',
        'job_id': scan.get('id'), 'job_number': job_number, 'scan_type': scan_type, 'type_label': label, 'scan_name': scan.get('scan_name') or '',
        'status': scan.get('status') or '', 'notice': STATUS_NOTICE.get(scan.get('status') or '', ''), 'error': error,
        'source_label': label, 'source_tag': 'ไฟล์ที่อัปโหลด' if is_upload else 'สแกนจากระบบ',
        'target': _clip_marked(scan.get('target'), MAX_TARGET_TEXT), 'started_text': _fmt_dt(started), 'finished_text': _fmt_dt(finished), 'duration_text': _duration_text(duration),
        'command': command, 'command_note': command_note, 'steps': steps,
        'nmap_version': nmap_version,                      # from the scan's own XML; empty for scans that did not keep it
        'run_summary': run_summary,                        # "ตรวจ N IP · ตอบกลับ M · ไม่ตอบ K"; empty for a scan that did not keep it
        'who_text': who,                                   # who ordered the scan and how; empty when the report was not given it
        'tiles': tiles, 'device_types': device_types, 'risk_levels': risk_levels,
        'summary': summary, 'findings': findings, 'appendix': appendix,
        'groups': groups, 'host_count': n_hosts, 'notes': notes, 'footnotes': footnotes,
        'running_head': f"{'รายงานผลการสแกนเครือข่าย'} | Scan Job #{job_number}",
        'running_date': f"สแกนเมื่อ {started.strftime('%Y-%m-%d %H:%M')}" if started else '',
    }
