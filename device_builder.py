"""Everything the device page (templates/device_detail.html) shows about ONE device (one IP), worked out from all the scans that saw it.

Pure functions: no Flask, no database, no I/O. `build_device()` takes plain values and returns a plain dict, so it is tested with synthetic scans
(test_device_builder.py) and the template only draws what it is given. It shares its rules with report_builder.py (the PDF report):

  * every fact comes from the NEWEST scan that knows it (a Fast Scan that did not see an OS does not erase the OS an Intense Scan saw);
  * CVEs come only from the newest VULNERABILITY scan that saw the device, and the page says which scan, and when. A Fast Scan never looked
    for CVEs, so "no CVE in the latest scan" is never shown as "no CVE";
  * "ไม่พบ CVE" only when every open service of the device was really looked up and the lookup answered; anything else is "ยังไม่ทราบ", with
    the reason, per service;
  * a port that is open in a NEWER scan than the CVE scan is listed as "not checked for CVEs yet".
"""
import ipaddress
import re
from urllib.parse import urlparse

import report_builder as rb
from cwe_data import cwe_info
from scanner import DEVICE_TYPES, guess_device_type, os_match_accuracy, port_reason, port_reason_label, severity_adjusted, severity_note

_CVE_ID = re.compile(r'^CVE-\d{4}-\d{4,}$')
_SEV_WORD = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low'}
_STATUS_TEXT = {
    'failed': 'ค้นหา NVD ไม่สำเร็จ จึงยังไม่ทราบ',
    'no_product': 'nmap ระบุผลิตภัณฑ์ไม่ได้ จึงไม่ได้ค้นหา CVE',
    'unrecorded': 'สแกนรุ่นเก่า ไม่ได้บันทึกว่าค้นหา CVE สำเร็จหรือไม่',
}
MAX_DESCRIPTION = 1000
MAX_REFS_SHOWN = 5
MAX_AFFECTED_SHOWN = 6
_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_VECTOR = re.compile(r'^[A-Za-z0-9:/.]{1,120}$')
# How a CVE is attacked, in plain Thai, from the fixed CVSS words the scanner kept (detail['attack']); the order is the order they are read in.
# v3 and v2 say it with different fields (v2 has no "privileges / user interaction", it has "authentication"). A value that is not in these tables is left out.
_ATTACK_ORDER = {'3': ('av', 'ac', 'pr', 'ui'), '2': ('av', 'ac', 'au')}
_ATTACK_WORDS = {
    '3': {'av': {'NETWORK': 'ผ่านเครือข่าย', 'ADJACENT_NETWORK': 'ต้องอยู่เครือข่ายเดียวกัน', 'LOCAL': 'ต้องเข้าถึงเครื่องโดยตรง', 'PHYSICAL': 'ต้องอยู่ที่ตัวเครื่อง'},
          'ac': {'LOW': 'ไม่ซับซ้อน', 'HIGH': 'ซับซ้อน'},
          'pr': {'NONE': 'ไม่ต้องล็อกอิน', 'LOW': 'ต้องมีบัญชีสิทธิ์ต่ำ', 'HIGH': 'ต้องมีบัญชีสิทธิ์สูง'},
          'ui': {'NONE': 'ไม่ต้องให้ผู้ใช้ทำอะไร', 'REQUIRED': 'ต้องให้ผู้ใช้ทำบางอย่าง'}},
    '2': {'av': {'NETWORK': 'ผ่านเครือข่าย', 'ADJACENT_NETWORK': 'ต้องอยู่เครือข่ายเดียวกัน', 'LOCAL': 'ต้องเข้าถึงเครื่องโดยตรง'},
          'ac': {'LOW': 'ไม่ซับซ้อน', 'MEDIUM': 'ซับซ้อนปานกลาง', 'HIGH': 'ซับซ้อน'},
          'au': {'NONE': 'ไม่ต้องล็อกอิน', 'SINGLE': 'ต้องล็อกอินหนึ่งครั้ง', 'MULTIPLE': 'ต้องล็อกอินหลายครั้ง'}},
}
# NVD's own status for a CVE record; anything else is shown as NVD wrote it
_STATUS_WORDS = {'Analyzed': 'วิเคราะห์แล้ว', 'Modified': 'วิเคราะห์แล้ว (มีการแก้ไขภายหลัง)', 'Awaiting Analysis': 'รอ NVD วิเคราะห์',
                 'Undergoing Analysis': 'NVD กำลังวิเคราะห์', 'Received': 'NVD เพิ่งได้รับ', 'Deferred': 'NVD ระงับการวิเคราะห์', 'Rejected': 'ถูกยกเลิก'}
# reference tags worth a chip (NVD's own words): the ones that point at something to DO or to read first. Third Party Advisory is on almost every link and Mailing List /
# VDB Entry say little, so they are not shown.
_REF_CHIPS = ('Exploit', 'Patch', 'Mitigation', 'Vendor Advisory')
MAX_REF_PATH = 40


def _when(d):
    return d.strftime('%Y-%m-%d %H:%M') if d else ''


def _clean(value, bad=('', 'unknown')):
    v = str(value or '').strip()
    return '' if v.lower() in bad else v


def _source(job):
    return {'id': job['id'], 'seq': job['seq'], 'type': job['scan_type'], 'type_label': job.get('type_label') or job['scan_type'],
            'when': _when(job.get('timestamp')), 'status': job.get('status') or ''}


def _list(value):
    return value if isinstance(value, list) else []


def _version_text(row):
    """The version part of an affected-product row: one version, a range, or every version."""
    if row.get('ver'):
        return str(row['ver'])
    parts = []
    for key, fmt in (('si', 'ตั้งแต่ {}'), ('se', 'หลัง {}'), ('ei', 'ถึง {} (รวม)'), ('ee', 'ก่อน {}')):
        if row.get(key):
            parts.append(fmt.format(row[key]))
    return ' '.join(parts) or 'ทุกเวอร์ชัน'


def _cve_detail(c):
    """What the device page shows under "รายละเอียดเพิ่มเติม" for one CVE, in Thai, from the `detail` block the scanner kept; None when the scan
    did not record one (a scan from before it existed: that is "not recorded", never an empty or guessed block). Every part is checked again here,
    because the stored text came from outside: a date, a fixed CVSS word, an http(s) link."""
    d = c.get('detail')
    if not isinstance(d, dict):
        return None
    ver = '2' if d.get('cvss_version') == '2' else '3'
    attack = d.get('attack') if isinstance(d.get('attack'), dict) else {}
    words = [_ATTACK_WORDS[ver][k][attack[k]] for k in _ATTACK_ORDER[ver] if isinstance(attack.get(k), str) and attack[k] in _ATTACK_WORDS[ver][k]]
    vector = str(d.get('vector') or '')
    status = str(d.get('status') or '')

    rows = [r for r in _list(d.get('affected')) if isinstance(r, dict) and (r.get('v') or r.get('p'))]
    total = d['affected_total'] if isinstance(d.get('affected_total'), int) and d['affected_total'] >= len(rows) else len(rows)
    shown = [' '.join(f"{r.get('v') or ''} {r.get('p') or ''}".replace('_', ' ').split()) + ' ' + _version_text(r) for r in rows[:MAX_AFFECTED_SHOWN]]

    refs = []
    for r in _list(d.get('refs')):
        if not isinstance(r, dict):
            continue
        url = str(r.get('u') or '')
        parts = urlparse(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or len(url) > 300 or any(ch in url for ch in ' <>"\'\\'):
            continue
        tags = [t for t in _REF_CHIPS if t in _list(r.get('t'))]
        path = (parts.path if parts.path != '/' else '') + (('?' + parts.query) if parts.query else '')
        refs.append({'url': url, 'host': parts.hostname.lower().removeprefix('www.')[:60], 'path': path[:MAX_REF_PATH] + ('…' if len(path) > MAX_REF_PATH else ''), 'tags': tags})
    refs_total = d['refs_total'] if isinstance(d.get('refs_total'), int) and d['refs_total'] >= len(refs) else len(refs)

    kev = d.get('kev') if c.get('kev') is True and isinstance(d.get('kev'), dict) else None
    return {
        'attack': words, 'vector': vector if _VECTOR.match(vector) else '', 'cvss_version': ('v2' if ver == '2' else 'v3') if (words or vector) else '',
        'published': d['published'] if _DATE.match(str(d.get('published') or '')) else '',
        'modified': d['modified'] if _DATE.match(str(d.get('modified') or '')) else '',
        'status': _STATUS_WORDS.get(status) or (status if re.fullmatch(r'[A-Za-z ]{1,40}', status) else ''),
        'affected': {'rows': shown, 'more': max(0, total - len(shown)), 'none': total == 0},
        'refs': refs[:MAX_REFS_SHOWN], 'refs_more': max(0, refs_total - min(len(refs), MAX_REFS_SHOWN)),
        'has_exploit': any('Exploit' in r['tags'] for r in refs[:MAX_REFS_SHOWN]),
        'kev': {'action': _clean(kev.get('action')), 'due': kev['due'] if _DATE.match(str(kev.get('due') or '')) else '', 'name': _clean(kev.get('name'))} if kev else None,
    }


def _description(c):
    """(text, cut): the whole description when the scan kept it (detail['full'], up to 1000 characters), else the first 300 characters older scans kept.
    `cut` says the text stops before NVD's description does, so the page can end it with "…" instead of stopping in the middle of a word."""
    stored = str(c.get('description') or '')
    d = c.get('detail') if isinstance(c.get('detail'), dict) else None
    if d is not None:
        text = ' '.join(str(d.get('full') or stored).split())
        return text[:MAX_DESCRIPTION], d.get('desc_cut') is True or len(text) > MAX_DESCRIPTION
    text = ' '.join(stored.split())
    return text[:MAX_DESCRIPTION], len(stored) >= 300             # an older scan kept exactly the first 300 characters: a text that long is (almost surely) cut


def _safe_detail(c):
    try:
        return _cve_detail(c)
    except Exception:
        return None


def _cve_item(c):
    sev = rb.effective_severity(c)
    try:
        score = float(c.get('cvss_score'))
    except (TypeError, ValueError):
        score = None
    cid = str(c.get('cve_id'))
    weak = cwe_info(c)
    desc, cut = _description(c)
    return {
        'id': cid, 'nvd_url': f'https://nvd.nist.gov/vuln/detail/{cid}' if _CVE_ID.match(cid) else '',
        'severity': sev, 'sev_word': _SEV_WORD.get(sev, 'Unknown'), 'level': rb._SEV_TO_LEVEL.get(sev, 'low'),
        'adjusted_note': severity_note(score) if (severity_adjusted(c) and score is not None) else '',
        'score': score, 'label': rb._clip(c.get('cwe_name') or '', 80),
        'cwe': {'id': weak['id'], 'name': weak['compact'] or weak['name'] or weak['id'], 'url': weak['url']} if weak else None,
        'description': desc + ('…' if cut and desc else ''), 'detail': _safe_detail(c),
        # on CISA's Known Exploited list, as NVD said when the scan looked it up (absent in older scans = not recorded, so no tag)
        'kev': c.get('kev') is True, 'kev_added': str(c.get('kev_added') or '')[:10] if c.get('kev') is True else '',
    }


def _sort_cves(items):
    return sorted(items, key=lambda e: (-rb._SEV_RANK.get(e['severity'], 0), -(e['score'] if e['score'] is not None else -1), e['id']))


def _guess_type(ip, vendor, os_name, open_ports, hostname, mac):
    """(key, Thai label, reason, likely): guess_device_type with its reason, which report_builder does not keep."""
    try:
        g = guess_device_type(ip, vendor, os_name, [p.get('port') for p in open_ports], None,
                              ' '.join(f"{p.get('name') or ''} {rb._product(p)}" for p in open_ports), hostname, mac)
    except Exception:                                               # a guess must never break the page
        return 'unknown', rb.TYPE_LABEL['unknown'], '', False
    key = g.get('key') if g.get('key') in rb.TYPE_LABEL else 'unknown'
    likely = g.get('confidence') == 'likely' and key != 'unknown'
    return key, rb.TYPE_LABEL[key] + (' (น่าจะ)' if likely else ''), g.get('reason') or '', likely


OTHER_PORT_ROWS = 40          # ports that are not open and are listed one by one; the counts above them are always exact
_STATE_WORD = re.compile(r'[a-z]+(?:\|[a-z]+)*')


def _port_state(p):
    """A port's state as plain lowercase text ('open|filtered' is its own state), 'unknown' when it is missing or not plain text."""
    v = str(p.get('state') or '').strip().lower()
    return v if 0 < len(v) <= 24 and _STATE_WORD.fullmatch(v) else 'unknown'


def _other_ports(ports):
    """The ports of a scan that are NOT open, grouped by (state, nmap's reason) so a device whose ports are all filtered can say why.
    The reason is what nmap recorded (None when the scan did not keep one: scans from before it was kept); nothing is guessed."""
    others = [p for p in ports if isinstance(p, dict) and not rb._is_open(p)]
    groups = {}
    for p in others:
        key = (_port_state(p), port_reason(p.get('reason')))
        groups[key] = groups.get(key, 0) + 1
    ordered = sorted(groups.items(), key=lambda kv: (-kv[1], kv[0][0], kv[0][1] is None, kv[0][1] or ''))
    rows = sorted(others, key=lambda p: (int(p.get('port') or 0) if str(p.get('port') or '').isdigit() else 0, str(p.get('protocol') or '')))
    return {'total': len(others),
            'groups': [{'state': st, 'reason': rs, 'text': port_reason_label(rs), 'count': n} for (st, rs), n in ordered],
            'rows': [{'port': p.get('port'), 'protocol': str(p.get('protocol') or 'tcp').lower(), 'name': p.get('name') or '', 'state': _port_state(p),
                      'reason': port_reason(p.get('reason')), 'text': port_reason_label(p.get('reason'))} for p in rows[:OTHER_PORT_ROWS]],
            'more': max(0, len(others) - OTHER_PORT_ROWS)}



def build_device(ip, jobs, type_labels=None):
    """ip: the address (a string). jobs: the scans that may contain it, NEWEST FIRST, each a dict with id, seq (the number the app shows as
    "Job #"), scan_type, status, scan_name, timestamp, hosts (the parsed result_data list). Returns None when no scan has this device."""
    type_labels = type_labels or {}
    want = rb._ip(ip)
    if want is None:
        return None
    seen = []                                                       # (job, host) newest first
    for job in jobs:
        job = dict(job, type_label=type_labels.get(job.get('scan_type'), job.get('scan_type') or ''))
        hosts = job.get('hosts') if isinstance(job.get('hosts'), list) else []
        host = next((h for h in hosts if isinstance(h, dict) and rb._ip(h.get('ip')) == want), None)
        if host is not None:
            seen.append((job, host))
    if not seen:
        return None

    def newest(getter):
        return next((v for v in (getter(h) for _, h in seen) if v), '')

    hostname = newest(lambda h: _clean(h.get('hostname'), ('',)))
    mac = newest(lambda h: _clean(h.get('mac')))
    vendor = newest(lambda h: _clean(h.get('mac_vendor'), ('',)))
    os_name = newest(lambda h: _clean(h.get('os'), ('', 'unknown', 'up', 'down')))
    # nmap's confidence in that guess: from the SAME scan record that gave the name (an older scan's percentage is about an older guess), None when it was not kept
    os_accuracy = next((os_match_accuracy(h.get('os_accuracy')) for _, h in seen if _clean(h.get('os'), ('', 'unknown', 'up', 'down'))), None)

    # ---- open ports: from the newest scan that listed ports (a Discovery scan does not)
    ports_job = ports_host = None
    ports_i = None
    for i, (job, host) in enumerate(seen):
        if isinstance(host.get('ports'), list) and job.get('scan_type') != 'discovery':
            ports_job, ports_host, ports_i = job, host, i
            break
    ports = None
    open_ports = []
    if ports_job:
        open_ports = sorted([p for p in ports_host['ports'] if rb._is_open(p)], key=lambda p: (int(p.get('port') or 0), str(p.get('protocol') or '')))
        ports = {'source': _source(ports_job), 'other_count': len([p for p in ports_host['ports'] if isinstance(p, dict) and not rb._is_open(p)]),
                 'others': _other_ports(ports_host['ports']),
                 'rows': [{'port': p.get('port'), 'protocol': str(p.get('protocol') or 'tcp').lower(), 'name': p.get('name') or '', 'product': rb._clip(rb._product(p), 80)}
                          for p in open_ports]}

    # ---- CVEs: only from a vulnerability scan, the newest one that saw this device
    cve_job = cve_host = None
    cve_i = None
    for i, (job, host) in enumerate(seen):
        if job.get('scan_type') == 'vuln_scan':
            cve_job, cve_host, cve_i = job, host, i
            break
    cves = None
    risk = {'key': 'unknown', 'label': rb.LEVEL_LABEL['unknown'], 'reason': 'ยังไม่เคยตรวจ CVE ของเครื่องนี้ (ยังไม่มีผลจาก Vulnerability Scan)'}
    if cve_job:
        cve_ports = sorted([p for p in (cve_host.get('ports') or []) if rb._is_open(p)], key=lambda p: (int(p.get('port') or 0), str(p.get('protocol') or '')))
        groups, counts = [], {'ok': 0, 'failed': 0, 'no_product': 0, 'unrecorded': 0}
        for p in cve_ports:
            st = rb._port_status(p)
            counts[st] += 1
            items = _sort_cves([_cve_item(c) for c in (p.get('cves') or []) if isinstance(c, dict) and c.get('cve_id')])
            groups.append({'port': p.get('port'), 'protocol': str(p.get('protocol') or 'tcp').lower(), 'name': p.get('name') or '',
                           'product': rb._clip(rb._product(p), 80), 'status': st, 'items': items,
                           'status_text': (f'{len(items)} CVE' if items else 'ไม่พบ CVE') if st == 'ok' else _STATUS_TEXT[st]})
        unique = rb._host_cves(cve_ports)
        level, reason = rb._host_risk(cve_ports, unique, 'vuln_scan')
        # a port open in a NEWER scan that this CVE scan never saw
        unchecked = []
        if ports_job is not None and ports_i < cve_i:
            looked = {(int(p.get('port') or 0), str(p.get('protocol') or 'tcp').lower()) for p in cve_ports}
            unchecked = [r for r in ports['rows'] if (int(r['port'] or 0), r['protocol']) not in looked]
        has_detail = any(i['detail'] is not None for g in groups for i in g['items'])
        cves = {'source': _source(cve_job), 'groups': groups, 'detail_recorded': has_detail, 'total': len(unique), 'open_count': len(cve_ports), 'evaluated': counts['ok'], 'counts': counts,
                'level': level, 'level_label': rb.LEVEL_LABEL[level], 'reason': reason, 'unchecked_ports': unchecked}
        risk = {'key': level, 'label': rb.LEVEL_LABEL[level], 'reason': reason}
        if unchecked and risk['key'] in ('none',):
            risk = {'key': 'unknown', 'label': rb.LEVEL_LABEL['unknown'], 'reason': f'มี {len(unchecked)} พอร์ตที่เปิดในสแกนล่าสุด แต่ยังไม่เคยถูกตรวจ CVE'}

    # ---- device type: a guess, from what we know now
    guess_ports = open_ports or ([p for p in (cve_host.get('ports') or []) if rb._is_open(p)] if cve_host else [])
    type_key, type_label, type_reason, type_likely = _guess_type(str(want), vendor, os_name, guess_ports, hostname, mac)

    # ---- history
    history = []
    for job, host in seen:
        is_vuln = job.get('scan_type') == 'vuln_scan'
        has_ports = isinstance(host.get('ports'), list) and job.get('scan_type') != 'discovery'
        history.append({
            'id': job['id'], 'seq': job['seq'], 'type_label': job['type_label'], 'status': job.get('status') or '', 'when': _when(job.get('timestamp')),
            'scan_name': job.get('scan_name') or '',
            'open_count': len([p for p in host['ports'] if rb._is_open(p)]) if has_ports else None,
            'cve_count': len(rb._host_cves([p for p in (host.get('ports') or []) if rb._is_open(p)])) if is_vuln else None,
            'is_ports_source': job is ports_job, 'is_cve_source': job is cve_job,
        })
    stamps = [j['timestamp'] for j, _ in seen if j.get('timestamp')]
    return {
        'ip': str(want), 'hostname': hostname, 'mac': mac, 'mac_vendor': vendor, 'vm': rb.virtual_machine_platform(mac, vendor), 'os': os_name, 'os_accuracy': os_accuracy,
        'local': any(bool(h.get('local')) for _, h in seen), 'scope': rb._scope(want),
        'type_key': type_key, 'type_label': type_label, 'type_reason': type_reason, 'type_likely': type_likely, 'type_icon': DEVICE_TYPES.get(type_key, DEVICE_TYPES['unknown'])[1],
        'first_seen': _when(min(stamps)) if stamps else '', 'last_seen': _when(max(stamps)) if stamps else '', 'scan_count': len(seen),
        'risk': risk, 'ports': ports, 'cves': cves, 'history': history,
    }
