"""What changed between two scans of the same target (the "changes since the last scan" card of the scan pages and the dashboard).

Pure functions: no Flask, no database, no I/O, so they can be tested with synthetic scans (test_scan_diff.py). The app picks the two scans
(`comparable_key` says which scans may be compared) and this module says what differs.

The owner's rule applies here too: what is not known is not claimed.
  * Only scans of the SAME target and the SAME kind are compared (same scan type, same -Pn choice, same custom arguments). A Fast Scan looks at
    100 ports and an Intense Scan at 1000, so comparing them would report "new ports" that were only never looked at.
  * A device that is missing from the newer scan is reported as "not found in this scan", never as "gone": it may have blocked ping or been off.
  * A port is "no longer open", not "closed": nmap may now see it as filtered.
  * A CVE is called NEW only when the older scan could have shown it (the device or port was new, or that service's CVE lookup answered "ok"),
    and called NOT FOUND NOW only when the newer scan really looked (`cve_status` "ok") or the port is no longer open. A lookup that failed, or a
    scan from before `cve_status` existed, makes it "not judged", counted but never listed as a change.
"""
from scanner import effective_severity, cvss_number

_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
MAX_ROWS = 50           # rows kept per list (the counts keep the true totals)


def comparable_key(scan_type, target, skip_ping=None, custom_args=None, all_ports=None, host_probes=None, gentle=None, udp=None):
    """Two scans may be compared only when their keys are equal. NULL and False for -Pn and for "all ports" are the same thing (the options did not exist
    before); a scan of all 65,535 ports and one of the usual list see different things, so they are never compared. The same for the host-discovery probes
    (they find devices a plain run cannot) and a Gentle scan (fewer retries and a per-host limit). -n only changes names, so it is not in the key."""
    return (str(target or '').strip(), str(scan_type or ''), bool(skip_ping), ' '.join(str(custom_args or '').split()) if scan_type == 'custom' else '', bool(all_ports),
            bool(host_probes), bool(gentle), bool(udp))


def _hosts(scan):
    out = {}
    for h in (scan.get('hosts') or []):
        if isinstance(h, dict) and h.get('ip') and not h.get('error'):
            out.setdefault(str(h['ip']), h)
    return out


def _open_ports(host):
    ports = {}
    for p in (host.get('ports') or []):
        if isinstance(p, dict) and str(p.get('state') or '').lower() == 'open' and p.get('port') not in (None, ''):
            ports[(_port_number(p.get('port')), str(p.get('protocol') or 'tcp'))] = p
    return ports


def _port_number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _port_label(key, p):
    name = str(p.get('name') or '').strip() if isinstance(p, dict) else ''
    return '%s/%s%s' % (key[0], key[1], (' ' + name) if name and name != 'unknown' else '')


def _cves(host):
    """{(port key, cve id): the CVE record} from the OPEN ports of one host, plus {port key: cve_status or None}."""
    found, status = {}, {}
    for key, p in _open_ports(host).items():
        status[key] = p.get('cve_status')
        for c in (p.get('cves') or []):
            if isinstance(c, dict) and c.get('cve_id'):
                found[(key, str(c['cve_id']))] = c
    return found, status


def _cve_row(ip, key, c, **extra):
    row = {'ip': ip, 'port': '%s/%s' % key, 'cve_id': str(c.get('cve_id')), 'severity': effective_severity(c) or 'UNKNOWN',
           'cvss': cvss_number(c.get('cvss_score')), 'kev': c.get('kev') is True}
    row.update(extra)
    return row


def _cve_sort(row):
    return (-_SEV_RANK.get(row['severity'], 0), -(row['cvss'] if row['cvss'] is not None else -1), row['ip'], row['cve_id'])


def _ip_key(ip):
    try:
        return tuple(int(x) for x in str(ip).split('.'))
    except ValueError:
        return (999, 999, 999, 999, str(ip))


def compare_scans(prev, cur, prev_admin=None, cur_admin=None):
    """What differs in `cur` compared with the earlier scan `prev`. Both are {'scan_type', 'hosts': [host dicts as stored]}; prev_admin / cur_admin
    say whether each run had Administrator rights (None = not recorded).
    Returns {'new_devices', 'missing_devices', 'port_changes', 'new_cves', 'fixed_cves', 'cve_compared', 'cve_unjudged', 'caveats', 'counts',
    'changed'}; the lists are capped at MAX_ROWS and counts hold the true totals."""
    scan_type = str(cur.get('scan_type') or '')
    ph, ch = _hosts(prev), _hosts(cur)
    has_ports = scan_type not in ('discovery', 'xml_upload')

    new_devices = [{'ip': ip, 'os': _real_os(ch[ip]), 'mac': _real_mac(ch[ip]), 'vendor': str(ch[ip].get('mac_vendor') or '')}
                   for ip in sorted(set(ch) - set(ph), key=_ip_key)]
    missing = [{'ip': ip, 'os': _real_os(ph[ip]), 'mac': _real_mac(ph[ip]), 'vendor': str(ph[ip].get('mac_vendor') or '')}
               for ip in sorted(set(ph) - set(ch), key=_ip_key)]

    port_changes = []
    if has_ports:
        for ip in sorted(set(ph) & set(ch), key=_ip_key):
            if ph[ip].get('ports') is None or ch[ip].get('ports') is None:
                continue
            before, after = _open_ports(ph[ip]), _open_ports(ch[ip])
            opened = sorted(set(after) - set(before))
            closed = sorted(set(before) - set(after))
            if opened or closed:
                port_changes.append({'ip': ip, 'opened': [_port_label(k, after[k]) for k in opened], 'closed': [_port_label(k, before[k]) for k in closed]})

    new_cves, fixed_cves, unjudged = [], [], 0
    cve_compared = scan_type == 'vuln_scan'
    if cve_compared:
        for ip in sorted(ch, key=_ip_key):
            now, now_status = _cves(ch[ip])
            if ip not in ph:
                new_cves += [_cve_row(ip, k, c, basis='new_device') for (k, _), c in now.items()]
                continue
            was, was_status = _cves(ph[ip])
            was_ids = {cid for (_, cid) in was}
            for (key, cid), c in now.items():
                if (key, cid) in was or cid in was_ids:
                    continue
                if key not in was_status:                          # the port was not open before: its CVEs are new with it
                    new_cves.append(_cve_row(ip, key, c, basis='new_port'))
                elif was_status[key] == 'ok':                      # the earlier lookup of this very service answered, and had not found it
                    new_cves.append(_cve_row(ip, key, c, basis='newly_found'))
                else:                                              # failed / no product / not recorded: it may have been there all along
                    unjudged += 1
            now_ids = {cid for (_, cid) in now}
            for (key, cid), c in was.items():
                if cid in now_ids:
                    continue
                if key not in now_status:
                    fixed_cves.append(_cve_row(ip, key, c, reason='port_closed'))
                elif now_status[key] == 'ok':
                    fixed_cves.append(_cve_row(ip, key, c, reason='not_found'))
                else:
                    unjudged += 1
        new_cves.sort(key=_cve_sort)
        fixed_cves.sort(key=_cve_sort)

    caveats = []
    if prev_admin is not None and cur_admin is not None and prev_admin != cur_admin:
        caveats.append('admin_differs')       # one run had Administrator rights and the other did not: devices can differ for that reason alone
    counts = {'new_devices': len(new_devices), 'missing_devices': len(missing), 'port_changes': len(port_changes),
              'ports_opened': sum(len(x['opened']) for x in port_changes), 'ports_closed': sum(len(x['closed']) for x in port_changes),
              'new_cves': len(new_cves), 'fixed_cves': len(fixed_cves),
              'new_kev': sum(1 for x in new_cves if x['kev'])}
    return {'new_devices': new_devices[:MAX_ROWS], 'missing_devices': missing[:MAX_ROWS], 'port_changes': port_changes[:MAX_ROWS],
            'new_cves': new_cves[:MAX_ROWS], 'fixed_cves': fixed_cves[:MAX_ROWS], 'cve_compared': cve_compared, 'cve_unjudged': unjudged,
            'caveats': caveats, 'counts': counts,
            'changed': bool(new_devices or missing or port_changes or new_cves or fixed_cves)}


def _real_os(host):
    value = str(host.get('os') or '').strip()
    return '' if value.lower() in ('', 'unknown', 'up', 'down') else value


def _real_mac(host):
    value = str(host.get('mac') or '').strip()
    return '' if value.lower() in ('', 'unknown') else value
