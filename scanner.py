import nmap
from nmap.nmap import PortScanner as _RealPortScanner, PortScannerTimeout   # the real class, even when a test has put a fake at nmap.PortScanner
import html
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from xml.etree import ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from cwe_data import CWE_SHORT_NAMES

try:   # optional: instant, shell-free adapter lookup. Without it we fall back to PowerShell / `ip`.
    import psutil
except ImportError:
    psutil = None


# ---------------------------------------------------------------------------
# MAC vendor lookup
#   1) offline: nmap's own OUI file (nmap-mac-prefixes)
#   2) optional online fallback (api.macvendors.com), OFF unless
#      MAC_LOOKUP_ONLINE=1 is set in .env. Results are cached in
#      instance/mac_vendor_cache.json (keyed by the 3-byte OUI).
# ---------------------------------------------------------------------------
_OUI_DB = None
_OUI_LOCK = threading.Lock()

_ONLINE_CACHE = None
_ONLINE_LOCK = threading.Lock()
_ONLINE_LAST_CALL = 0.0
_ONLINE_BLOCKED_UNTIL = 0.0
_ONLINE_TIMEOUT = 2
_ONLINE_MIN_INTERVAL = 1.1   # free tier allows ~1 request/second
_ONLINE_COOLDOWN = 60        # pause online lookups after an HTTP 429
_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'mac_vendor_cache.json')


def _normalize_mac(mac):
    """Return 12 upper-case hex digits, or None if this isn't a usable MAC."""
    if not mac:
        return None
    digits = re.sub(r'[^0-9a-fA-F]', '', str(mac))
    if len(digits) != 12 or not re.fullmatch(r'[0-9a-fA-F]{12}', digits):
        return None
    return digits.upper()


def _is_device_mac(mac12):
    """A real unicast MAC: not all-zero, not broadcast, not multicast."""
    return bool(mac12) and mac12 not in ('000000000000', 'FFFFFFFFFFFF') and not (int(mac12[:2], 16) & 1)


def _is_randomized_mac(mac12):
    """Locally-administered bit set (2nd hex digit 2, 6, A or E): a private/random MAC, no vendor exists."""
    return bool(int(mac12[:2], 16) & 0x02)


def _nmap_prefix_file_candidates():
    paths = []
    exe = shutil.which('nmap')
    if exe:
        paths.append(os.path.join(os.path.dirname(os.path.realpath(exe)), 'nmap-mac-prefixes'))
    for base in (os.environ.get('ProgramFiles(x86)'), os.environ.get('ProgramFiles')):
        if base:
            paths.append(os.path.join(base, 'Nmap', 'nmap-mac-prefixes'))
    paths += ['/usr/share/nmap/nmap-mac-prefixes', '/usr/local/share/nmap/nmap-mac-prefixes',
              '/opt/homebrew/share/nmap/nmap-mac-prefixes']
    return paths


def _load_oui_db():
    """Load nmap-mac-prefixes once. Returns {} if the file can't be found."""
    global _OUI_DB
    if _OUI_DB is not None:
        return _OUI_DB
    with _OUI_LOCK:
        if _OUI_DB is not None:
            return _OUI_DB
        db = {}
        for path in _nmap_prefix_file_candidates():
            if not os.path.isfile(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2 and re.fullmatch(r'[0-9A-Fa-f]{6}', parts[0]):
                            db[parts[0].upper()] = parts[1].strip()
                if db:
                    break
            except OSError:
                continue
        _OUI_DB = db
        return _OUI_DB


def _online_lookup_enabled():
    return os.environ.get('MAC_LOOKUP_ONLINE', '').strip().lower() in ('1', 'true', 'yes', 'on')


def _load_online_cache():
    global _ONLINE_CACHE
    if _ONLINE_CACHE is None:
        try:
            with open(_CACHE_PATH, 'r', encoding='utf-8') as f:
                data = json.load(f)
            _ONLINE_CACHE = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            _ONLINE_CACHE = {}
    return _ONLINE_CACHE


def _save_online_cache():
    try:
        os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
        tmp = _CACHE_PATH + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(_ONLINE_CACHE, f, ensure_ascii=False, indent=1)
        os.replace(tmp, _CACHE_PATH)
    except OSError:
        pass


def _lookup_vendor_online(oui):
    """Ask api.macvendors.com for a 3-byte OUI (only the OUI is sent, never the full MAC). Never raises."""
    global _ONLINE_LAST_CALL, _ONLINE_BLOCKED_UNTIL
    with _ONLINE_LOCK:
        cache = _load_online_cache()
        if oui in cache:
            return cache[oui]
        now = time.time()
        if now < _ONLINE_BLOCKED_UNTIL:
            return ''
        wait = _ONLINE_MIN_INTERVAL - (now - _ONLINE_LAST_CALL)
        if wait > 0:
            time.sleep(wait)
        _ONLINE_LAST_CALL = time.time()

        prefix = ':'.join(oui[i:i + 2] for i in range(0, 6, 2))
        req = urllib.request.Request(
            f'https://api.macvendors.com/{prefix}',
            headers={'User-Agent': 'NetworkScanner/1.0'}
        )
        try:
            with urllib.request.urlopen(req, timeout=_ONLINE_TIMEOUT) as resp:
                vendor = resp.read().decode('utf-8', errors='ignore').strip()
            if vendor and not vendor.startswith('{'):
                cache[oui] = vendor
                _save_online_cache()
                return vendor
        except urllib.error.HTTPError as e:
            if e.code == 404:
                cache[oui] = ''          # genuinely unknown OUI: remember it
                _save_online_cache()
            elif e.code == 429:
                _ONLINE_BLOCKED_UNTIL = time.time() + _ONLINE_COOLDOWN
        except Exception:
            pass                          # offline / timeout: don't cache, try again later
        return ''


def lookup_mac_vendor(mac):
    """Vendor name for a MAC address, or '' if unknown. Offline first; online only if enabled."""
    mac12 = _normalize_mac(mac)
    if not mac12:
        return ''
    oui = mac12[:6]
    vendor = _load_oui_db().get(oui, '')
    if vendor:
        return vendor
    if _online_lookup_enabled() and not _is_randomized_mac(mac12):
        return _lookup_vendor_online(oui)
    return ''


# ---------------------------------------------------------------------------
# This PC's own network adapters (IP, prefix, MAC). nmap can't ARP-read the
# MAC of the machine it runs on, so we read it from the OS instead
# (psutil if installed, otherwise PowerShell / ipconfig on Windows, `ip` on Linux).
# ---------------------------------------------------------------------------
_ADAPTERS_CACHE = {'ts': 0.0, 'data': []}
_ADAPTERS_LOCK = threading.Lock()

_PS_ADAPTERS = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
    "$a = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; "
    "[pscustomobject]@{ip=$_.IPAddress; prefix=$_.PrefixLength; name=$_.InterfaceAlias; mac=$a.MacAddress} } "
    "| ConvertTo-Json -Compress"
)


def _run_cmd(cmd, timeout):
    kwargs = {}
    if sys.platform == 'win32':
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout, **kwargs)


def _format_mac(mac):
    """'aa-bb-cc-dd-ee-ff' -> 'AA:BB:CC:DD:EE:FF'; '' for anything that isn't a real device MAC."""
    mac12 = _normalize_mac(mac)
    return ':'.join(mac12[i:i + 2] for i in range(0, 12, 2)) if mac12 and _is_device_mac(mac12) else ''


def _adapters_windows_powershell():
    out = _run_cmd(['powershell', '-NoProfile', '-NonInteractive', '-Command', _PS_ADAPTERS], 12)
    data = json.loads(out.decode('utf-8', errors='ignore'))
    if isinstance(data, dict):
        data = [data]
    return [{'ip': d.get('ip') or '', 'prefix': d.get('prefix'), 'name': d.get('name') or '',
             'mac': _format_mac(d.get('mac'))} for d in data if d.get('ip')]


def _adapters_windows_ipconfig():
    """Fallback if PowerShell is unavailable. Relies only on 'IPv4' and the MAC pattern, so it survives localized Windows."""
    out = _run_cmd(['ipconfig', '/all'], 8).decode('latin-1', errors='ignore')
    adapters, cur = [], None

    def flush():
        if cur and cur['ips']:
            for ip in cur['ips']:
                adapters.append({'ip': ip, 'prefix': cur['prefix'], 'name': cur['name'], 'mac': cur['mac']})

    for line in out.splitlines():
        if line.strip() and not line[0].isspace() and line.rstrip().endswith(':'):
            flush()
            cur = {'name': line.rstrip().rstrip(':').strip(), 'mac': '', 'ips': [], 'prefix': None}
            continue
        if cur is None:
            continue
        m = re.search(r'\b([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\b', line)
        if m and not cur['mac']:
            cur['mac'] = _format_mac(m.group(1))
        if 'IPv4' in line:
            m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
            if m:
                cur['ips'].append(m.group(1))
        else:
            m = re.search(r'\b(255(?:\.\d{1,3}){3})\b', line)
            if m and cur['prefix'] is None:
                try:
                    cur['prefix'] = ipaddress.ip_network('0.0.0.0/' + m.group(1)).prefixlen
                except ValueError:
                    pass
    flush()
    return adapters


def _adapters_linux():
    out = _run_cmd(['ip', '-o', '-4', 'addr', 'show'], 5).decode('utf-8', errors='ignore')
    adapters = []
    for line in out.splitlines():
        m = re.match(r'\d+:\s+(\S+)\s+inet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d+)', line)
        if not m:
            continue
        dev, ip, prefix = m.group(1), m.group(2), int(m.group(3))
        mac = ''
        try:
            with open(f'/sys/class/net/{dev}/address', 'r') as f:
                mac = _format_mac(f.read().strip())
        except OSError:
            pass
        adapters.append({'ip': ip, 'prefix': prefix, 'name': dev, 'mac': mac})
    return adapters


def _adapters_psutil():
    adapters = []
    for name, addrs in psutil.net_if_addrs().items():
        mac = next((m for m in (_format_mac(a.address) for a in addrs if a.family == psutil.AF_LINK) if m), '')
        for a in addrs:
            if a.family == socket.AF_INET and a.address:
                prefix = None
                if a.netmask:
                    try:
                        prefix = ipaddress.ip_network('0.0.0.0/' + a.netmask).prefixlen
                    except ValueError:
                        pass
                adapters.append({'ip': a.address, 'prefix': prefix, 'name': name, 'mac': mac})
    return adapters


def get_local_adapters(max_age=None):
    """IPv4 adapters of the machine running the scanner: [{'ip','prefix','name','mac'}]. Cached; never raises."""
    if max_age is None:
        max_age = 30 if psutil else 300   # psutil is instant, so refresh often; the shell fallbacks cost ~2s
    now = time.time()
    with _ADAPTERS_LOCK:
        if _ADAPTERS_CACHE['data'] and now - _ADAPTERS_CACHE['ts'] < max_age:
            return _ADAPTERS_CACHE['data']
        data = []
        if psutil:
            try:
                data = _adapters_psutil()
            except Exception:
                data = []
        if not data:
            try:
                if sys.platform == 'win32':
                    try:
                        data = _adapters_windows_powershell()
                    except Exception:
                        data = _adapters_windows_ipconfig()
                else:
                    data = _adapters_linux()
            except Exception:
                data = []
        _ADAPTERS_CACHE['data'] = data
        _ADAPTERS_CACHE['ts'] = now
        return data


def is_loopback_ip(ip):
    ip = (ip or '').strip()
    return ip.startswith('127.') or ip == '::1'


def is_local_ip(ip):
    """True if the IP belongs to the machine running the scanner."""
    ip = (ip or '').strip()
    return is_loopback_ip(ip) or any(a['ip'] == ip for a in get_local_adapters())


def annotate_local_hosts(results):
    """Fill MAC + vendor for hosts that are this PC's own adapters (nmap can't read those via ARP)."""
    try:
        by_ip = {a['ip']: a for a in get_local_adapters()}
        for h in results:
            ip = (h.get('ip') or '').strip()
            if not ip:
                continue
            if is_loopback_ip(ip):
                h['local'] = True
                h['adapter'] = 'Loopback'
                continue
            a = by_ip.get(ip)
            if not a:
                continue
            h['local'] = True
            h['adapter'] = a['name']
            cur = h.get('mac')
            if (not cur or cur == 'Unknown') and a.get('mac'):
                h['mac'] = a['mac']
                h['mac_vendor'] = lookup_mac_vendor(a['mac'])
    except Exception:
        pass
    return results


_ARP_CACHE = {'ts': 0.0, 'data': {}}
_ARP_LOCK = threading.Lock()


def get_arp_table(max_age=5):
    """{ip: MAC} from the OS ARP cache (Windows `arp -a`, Linux /proc/net/arp, macOS `arp -an`). Never raises."""
    now = time.time()
    with _ARP_LOCK:
        if max_age and _ARP_CACHE['ts'] and now - _ARP_CACHE['ts'] < max_age:
            return _ARP_CACHE['data']
        table = {}
        try:
            if sys.platform.startswith('linux') and os.path.exists('/proc/net/arp'):
                with open('/proc/net/arp', 'r') as f:
                    next(f, None)   # header
                    for row in f:
                        rp = row.split()
                        # IP  HWtype  Flags  HWaddr  Mask  Device ; Flags 0x0 = incomplete entry
                        if len(rp) >= 4 and rp[2] != '0x0':
                            mac = _format_mac(rp[3])
                            if mac:
                                table[rp[0]] = mac
            else:
                cmd = ['arp', '-a'] if sys.platform == 'win32' else ['arp', '-an']
                out = _run_cmd(cmd, 6).decode('latin-1', errors='ignore')
                for line in out.splitlines():
                    m_ip = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', line)
                    m_mac = re.search(r'\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b', line)
                    if not (m_ip and m_mac):
                        continue
                    # macOS prints octets without leading zeros ("0:1a:..."), so pad them first
                    mac = _format_mac(''.join(o.zfill(2) for o in re.split(r'[:-]', m_mac.group(1))))
                    if mac:
                        table[m_ip.group(1)] = mac
        except Exception:
            pass
        _ARP_CACHE['data'] = table
        _ARP_CACHE['ts'] = now
        return table


def fill_missing_macs_from_arp(results):
    """nmap only reports a MAC when it can send ARP itself (admin rights + Npcap, same subnet).
    For hosts it found but gave no MAC for, read the MAC from the OS ARP cache instead.
    Loopback is skipped on purpose: it has no MAC."""
    try:
        missing = [h for h in results
                   if (h.get('ip') or '').strip() and not is_loopback_ip(h['ip']) and not _normalize_mac(h.get('mac'))]
        if not missing:
            return results
        table = get_arp_table(max_age=0)   # fresh read: the scan has just touched these hosts
        for h in missing:
            mac = table.get(h['ip'].strip())
            if mac:
                h['mac'] = mac
                h['mac_vendor'] = h.get('mac_vendor') or lookup_mac_vendor(mac)
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# IPv6 (OS neighbor-discovery cache -> MAC -> IPv6, the IPv6 equivalent of ARP)
#   nmap itself never looks for IPv6 here: every scan in this app targets an
#   IPv4 address/range, and nmap only does IPv6 discovery when explicitly
#   told to (-6) against an address you already know. There's no way to
#   derive "this IPv4 host's IPv6 address" from an IPv4-only scan. The best
#   we can do locally is read the OS's own IPv6 neighbor table (populated by
#   NDP, IPv6's version of ARP) and match it to a MAC we already resolved.
#   This only finds devices the OS has recently exchanged IPv6 traffic with
#   (in practice: usually just the router) -- it is not a substitute for a
#   real IPv6 scan.
# ---------------------------------------------------------------------------
_IPV6_CACHE = {'ts': 0.0, 'data': {}}
_IPV6_LOCK = threading.Lock()


def _ipv6_neighbors_windows():
    """{MAC: ipv6} from `netsh interface ipv6 show neighbors`."""
    out = _run_cmd(['netsh', 'interface', 'ipv6', 'show', 'neighbors'], 8).decode('latin-1', errors='ignore')
    mapping = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2 or ':' not in parts[0]:
            continue
        addr = parts[0]
        if addr.lower().startswith('ff'):   # multicast (solicited-node etc.), not a real device address
            continue
        mac = _format_mac(parts[1])
        if not mac:
            continue
        state = ' '.join(parts[2:]).lower()
        if 'unreachable' in state or 'incomplete' in state:
            continue
        mapping.setdefault(mac, addr)
    return mapping


def _ipv6_neighbors_linux():
    """{MAC: ipv6} from `ip -6 neighbor show`."""
    out = _run_cmd(['ip', '-6', 'neighbor', 'show'], 6).decode('utf-8', errors='ignore')
    mapping = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts or ':' not in parts[0]:
            continue
        addr = parts[0]
        if addr.lower().startswith('ff') or 'lladdr' not in parts:
            continue
        idx = parts.index('lladdr')
        if idx + 1 >= len(parts):
            continue
        mac = _format_mac(parts[idx + 1])
        if not mac:
            continue
        state = parts[-1].upper()
        if state in ('FAILED', 'INCOMPLETE'):
            continue
        mapping.setdefault(mac, addr)
    return mapping


def _ipv6_neighbors_macos():
    """{MAC: ipv6} from `ndp -an`. Best-effort: untested on real macOS, always safe to fail."""
    out = _run_cmd(['ndp', '-an'], 6).decode('utf-8', errors='ignore')
    mapping = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or ':' not in parts[0]:
            continue
        addr = parts[0].split('%')[0]
        if addr.lower().startswith('ff'):
            continue
        mac = _format_mac(parts[1])
        if not mac:
            continue
        state = parts[-1].upper()
        if state in ('N', 'INCOMPLETE'):   # ndp: N = no reply / incomplete
            continue
        mapping.setdefault(mac, addr)
    return mapping


def get_ipv6_neighbors(max_age=5):
    """{MAC: ipv6_address} from the OS's IPv6 neighbor table. Cached; never raises."""
    now = time.time()
    with _IPV6_LOCK:
        if max_age and _IPV6_CACHE['ts'] and now - _IPV6_CACHE['ts'] < max_age:
            return _IPV6_CACHE['data']
        mapping = {}
        try:
            if sys.platform == 'win32':
                mapping = _ipv6_neighbors_windows()
            elif sys.platform.startswith('linux'):
                mapping = _ipv6_neighbors_linux()
            elif sys.platform == 'darwin':
                mapping = _ipv6_neighbors_macos()
        except Exception:
            mapping = {}
        _IPV6_CACHE['data'] = mapping
        _IPV6_CACHE['ts'] = now
        return mapping


def fill_ipv6_from_neighbors(results):
    """Attach `ipv6` to hosts whose already-resolved MAC appears in the OS IPv6 neighbor table.
    Usually only finds the router -- most LAN devices never show up here unless this PC has
    actually exchanged IPv6 traffic with them."""
    try:
        by_mac = get_ipv6_neighbors()
        if not by_mac:
            return results
        for h in results:
            if h.get('ipv6'):
                continue
            mac = _format_mac(h.get('mac'))
            if mac and mac in by_mac:
                h['ipv6'] = by_mac[mac]
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# Hostname (reverse DNS, then NetBIOS on Windows) -- many devices broadcast
# their own name, which is often a stronger device-type signal than the MAC
# vendor alone (e.g. a phone's self-chosen name, or a PC's computer name).
# Looked up once per scan and cached into result_data, not on every page load.
# ---------------------------------------------------------------------------
def _reverse_dns(ip, timeout=1.0):
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name.split('.')[0]   # drop the domain suffix, keep the short device-chosen label
    except Exception:
        return ''
    finally:
        socket.setdefaulttimeout(old)


def _netbios_name(ip, timeout=2):
    """Windows-only: the registered NetBIOS machine name, via `nbtstat -A <ip>`."""
    if sys.platform != 'win32':
        return ''
    try:
        out = _run_cmd(['nbtstat', '-A', ip], timeout).decode('latin-1', errors='ignore')
        for line in out.splitlines():
            parts = line.split()
            # typical row: "MYPC            <00>  UNIQUE      Registered"
            if len(parts) >= 3 and parts[1] == '<00>' and parts[2].upper() == 'UNIQUE':
                return parts[0].strip()
    except Exception:
        pass
    return ''


def _resolve_hostname(ip, use_dns=True):
    # the name is chosen by the other device (and ends up in pages), so keep it single-line and markup-free
    # use_dns=False (the -n option): no question goes to a DNS server; NetBIOS asks the device itself and is not DNS
    return _clip((_reverse_dns(ip) if use_dns else '') or _netbios_name(ip), 63)


def fill_hostnames(results, max_workers=8, per_host_timeout=2.5, use_dns=True):
    """Attach `hostname` to hosts that don't already have one. Runs lookups in parallel under a
    single shared deadline: socket.setdefaulttimeout() does not reliably bound gethostbyaddr()
    on every system, so per_host_timeout is enforced from the outside instead, across ALL hosts
    together (not per host -- waiting up to per_host_timeout for *each* straggler in turn would
    make the total cost grow with the number of slow hosts instead of staying flat). Stragglers
    are left to finish (or not) in the background rather than blocking the scan on them."""
    try:
        targets = [h for h in results
                   if (h.get('ip') or '').strip() and not h.get('hostname') and not is_loopback_ip(h['ip'])]
        if not targets:
            return results
        ex = ThreadPoolExecutor(max_workers=min(max_workers, len(targets)))
        try:
            futures = {ex.submit(_resolve_hostname, h['ip'], use_dns): h for h in targets}
            try:
                for fut in as_completed(futures, timeout=per_host_timeout):
                    h = futures[fut]
                    try:
                        name = fut.result()
                        if name:
                            h['hostname'] = name
                    except Exception:
                        pass
            except FuturesTimeoutError:
                pass   # shared deadline hit: whatever hasn't resolved yet is left without a hostname
        finally:
            ex.shutdown(wait=False)
    except Exception:
        pass
    return results


def mac_note(ip, mac='', vendor=''):
    """Short reason for a missing / unresolvable MAC: {'label','tip'} or None when nothing needs explaining."""
    mac12 = _normalize_mac(mac)
    if mac12:
        if not vendor and _is_randomized_mac(mac12):
            return {'label': 'Private MAC',
                    'tip': 'MAC ที่ซอฟต์แวร์กำหนดเอง (เช่น ฟีเจอร์ความเป็นส่วนตัวของมือถือ หรือ virtual adapter) จึงไม่มีชื่อผู้ผลิต'}
        return None
    ip = (ip or '').strip()
    if is_loopback_ip(ip):
        return {'label': 'This PC (loopback)', 'tip': 'ที่อยู่ loopback ของเครื่องนี้ ไม่มี MAC address'}
    adapters = get_local_adapters()
    if any(a['ip'] == ip for a in adapters):
        return {'label': 'This PC', 'tip': 'เป็นการ์ดเครือข่ายของเครื่องที่รันโปรแกรมนี้ แต่ไม่พบ MAC'}
    try:
        addr = ipaddress.ip_address(ip)
        for a in adapters:
            if a.get('prefix') is None:
                continue
            if addr in ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False):
                return {'label': 'Not returned',
                        'tip': 'อยู่ในเครือข่ายเดียวกัน แต่ nmap ไม่ส่ง MAC กลับมา — ลองรันด้วยสิทธิ์ Administrator และติดตั้ง Npcap'}
    except ValueError:
        pass
    return {'label': 'Other subnet',
            'tip': 'อยู่คนละเครือข่าย (หรือเครือข่ายเสมือน) จึงอ่าน MAC ผ่าน ARP ไม่ได้'}


# ---------------------------------------------------------------------------
# Can nmap do its best work on this machine? (admin/root + Npcap)
# ---------------------------------------------------------------------------
_CAPS_CACHE = {'ts': 0.0, 'data': None}


def get_scan_capabilities(max_age=300):
    """{'is_admin','npcap','nmap','warnings':[...]} (Thai warnings). Cached; never raises."""
    now = time.time()
    if _CAPS_CACHE['data'] is not None and now - _CAPS_CACHE['ts'] < max_age:
        return _CAPS_CACHE['data']
    try:
        nmap_found = shutil.which('nmap') is not None
        if sys.platform == 'win32':
            import ctypes
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
            root = os.environ.get('SystemRoot', r'C:\Windows')
            npcap = any(os.path.exists(os.path.join(root, 'System32', *p))
                        for p in (('Npcap', 'wpcap.dll'), ('wpcap.dll',)))
        else:
            is_admin = (os.geteuid() == 0)
            npcap = True
        warnings = []
        if not nmap_found:
            warnings.append({'text': 'ไม่พบ nmap ใน PATH — ไม่สามารถสแกนได้', 'tip': ''})
        if not is_admin:
            admin_tip = (
                'การสแกนจะทำงานได้อย่างสมบูรณ์เมื่อรันโปรแกรมด้วยสิทธิ์ผู้ดูแลระบบ Administrator หรือ root เท่านั้น '
                'หากไม่มีสิทธิ์ดังกล่าว ผลการตรวจสอบระบบปฏิบัติการและที่อยู่ MAC ของอุปกรณ์อาจไม่ครบถ้วน'
            )
            warnings.append({
                'text': 'โปรแกรมไม่ได้รันด้วยสิทธิ์ Administrator/root — ตรวจ OS และอ่าน MAC ของอุปกรณ์ไม่ได้ครบ',
                'tip': admin_tip,
            })
        if not npcap:
            warnings.append({'text': 'ไม่พบ Npcap — nmap จะใช้ ping แทน ARP ทำให้พลาดอุปกรณ์ที่บล็อก ping', 'tip': ''})
        data = {'is_admin': is_admin, 'npcap': npcap, 'nmap': nmap_found, 'warnings': warnings}
    except Exception:
        data = {'is_admin': True, 'npcap': True, 'nmap': True, 'warnings': []}
    _CAPS_CACHE['data'] = data
    _CAPS_CACHE['ts'] = now
    return data


# ---------------------------------------------------------------------------
# mDNS (Bonjour) + SSDP (UPnP) discovery, used by the Discovery scan.
# Phones, TVs, printers and smart-home gear announce themselves on multicast even when they
# ignore ping and have no open ports -- exactly where MAC-vendor / port heuristics have nothing
# to go on. Plain UDP sockets, no extra dependency. Replies come back unicast to our own
# ephemeral port (SSDP by design; mDNS via the QU "unicast response" bit), so we never bind
# port 5353 and never clash with the OS's own mDNS service. Multicast only reaches the local
# network segment: anything routed away simply doesn't answer.
# ---------------------------------------------------------------------------
_MDNS_DEST = ('224.0.0.251', 5353)
_SSDP_DEST = ('239.255.255.250', 1900)
_MDNS_META = '_services._dns-sd._udp.local'   # "which service types do you offer?"
_MDNS_TYPES = (
    '_airplay._tcp', '_raop._tcp', '_googlecast._tcp', '_ipp._tcp', '_ipps._tcp', '_printer._tcp',
    '_pdl-datastream._tcp', '_http._tcp', '_https._tcp', '_smb._tcp', '_afpovertcp._tcp', '_ssh._tcp',
    '_hap._tcp', '_homekit._tcp', '_companion-link._tcp', '_apple-mobdev2._tcp', '_spotify-connect._tcp',
    '_sonos._tcp', '_hue._tcp', '_esphomelib._tcp', '_matter._tcp', '_device-info._tcp', '_rtsp._tcp',
    '_workstation._tcp', '_mediaremotetv._tcp', '_amzn-wplay._tcp',
)
_MDNS_TXT_MODEL_KEYS = ('md', 'model', 'ty', 'product', 'rpmd', 'usb_mdl', 'am')
_SSDP_SEARCH = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
_OPAQUE_NAME = re.compile(r'^[0-9a-f]{12,}(?:-[0-9a-f]+)*$', re.I)   # uuid-like hostnames say nothing


def _clip(text, n):
    """Single-line, length-capped, markup-free text: these strings are chosen by arbitrary devices on the LAN."""
    return re.sub(r'[<>\x00-\x1f\x7f]', '', ' '.join(str(text).split()))[:n]


def _strip_local(name):
    return re.sub(r'\.local\.?$', '', name, flags=re.I)


def _dns_name(buf, off):
    """Read a (possibly compressed) DNS name -> (name, offset just past it in the original record)."""
    labels, end, jumped = [], off, False
    for _ in range(128):                     # bounds both long names and compression-pointer loops
        if off >= len(buf):
            raise ValueError('truncated name')
        n = buf[off]
        if n == 0:
            return '.'.join(labels), (off + 1 if not jumped else end)
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError('truncated pointer')
            if not jumped:
                end = off + 2
            jumped = True
            off = ((n & 0x3F) << 8) | buf[off + 1]
            continue
        if n & 0xC0:
            raise ValueError('bad label')
        if off + 1 + n > len(buf):
            raise ValueError('truncated label')
        labels.append(buf[off + 1:off + 1 + n].decode('utf-8', 'replace'))
        off += 1 + n
    raise ValueError('name too long or pointer loop')


def _mdns_query(names):
    """One mDNS packet asking for the PTR records of `names`, with the QU (unicast reply) bit set."""
    pkt = struct.pack('!6H', 0, 0, len(names), 0, 0, 0)
    for name in names:
        for label in name.split('.'):
            raw = label.encode('ascii')
            pkt += bytes([len(raw)]) + raw
        pkt += b'\x00' + struct.pack('!HH', 12, 0x8001)
    return pkt


def _parse_mdns(data):
    """Records of an mDNS response as {'ptr','srv','a','txt'} lists, or None if it isn't a response.
    Input comes from whatever is on the network, so every read is bounds-checked and a bad
    record just ends parsing (what was read before it is kept)."""
    if len(data) < 12:
        return None
    flags, qd, an, ns, ar = struct.unpack('!HHHHH', data[2:12])
    if not flags & 0x8000:
        return None
    out = {'ptr': [], 'srv': [], 'a': [], 'txt': []}
    off = 12
    try:
        for _ in range(min(qd, 16)):
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(min(an + ns + ar, 200)):
            owner, off = _dns_name(data, off)
            if off + 10 > len(data):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack('!HHIH', data[off:off + 10])
            off += 10
            end = off + rdlen
            if end > len(data):
                break
            if rtype == 12:
                out['ptr'].append((owner, _dns_name(data, off)[0]))
            elif rtype == 33 and rdlen >= 7:
                out['srv'].append((owner, struct.unpack('!H', data[off + 4:off + 6])[0], _dns_name(data, off + 6)[0]))
            elif rtype == 1 and rdlen == 4:
                out['a'].append((owner, socket.inet_ntoa(data[off:end])))
            elif rtype == 16:
                kv, p = {}, off
                while p < end:
                    n = data[p]
                    item = data[p + 1:min(p + 1 + n, end)].decode('utf-8', 'replace')
                    p += 1 + n
                    if '=' in item:
                        k, v = item.split('=', 1)
                        kv[k.lower()] = v
                out['txt'].append((owner, kv))
            off = end
    except (ValueError, struct.error, IndexError):
        pass
    return out


def _parse_ssdp(data):
    """Header dict (lower-case names) of an SSDP search response, or None."""
    lines = data[:4096].decode('latin-1', 'replace').split('\r\n')
    if not lines or not lines[0].upper().startswith('HTTP/1.'):
        return None
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def _summarize_mdns(parsed):
    """One device's mDNS replies -> {'name','services','models'}."""
    services, models, hosts, fns, instances = set(), [], [], [], []
    for p in parsed:
        for owner, target in p['ptr']:
            o = owner.lower()
            svc = target if o == _MDNS_META else (owner if ('._tcp.' in o or '._udp.' in o) else '')
            svc = _strip_local(svc).lower()
            if svc.startswith('_'):
                services.add(svc)
            if o != _MDNS_META and '._' in target and not target.startswith('_'):
                instances.append(target.split('._', 1)[0])
        hosts += [_strip_local(t) for _o, _port, t in p['srv']]
        hosts += [_strip_local(o) for o, _ip in p['a']]
        for _o, kv in p['txt']:
            if kv.get('fn'):
                fns.append(kv['fn'])
            for key in _MDNS_TXT_MODEL_KEYS:
                if kv.get(key) and kv[key] not in models:
                    models.append(kv[key])
    name = next((h for h in hosts if h and not _OPAQUE_NAME.match(h)), '') \
        or (fns[0] if fns else '') or (instances[0] if instances else '')
    return {'name': _clip(name, 60), 'services': sorted(_clip(s, 80) for s in services)[:20],
            'models': [_clip(m, 60) for m in models][:6]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch_upnp_description(location, src_ip, timeout=2.0, max_bytes=65536):
    """friendlyName / manufacturer / model / type of a UPnP device from its description XML. Only
    fetched from the very host that answered: a device can advertise any URL, and we must not be
    steered at other machines. No redirects, no proxy, size-capped, read with regexes (no XML parser)."""
    try:
        u = urllib.parse.urlsplit(location)
        if u.scheme != 'http' or u.hostname != src_ip:
            return {}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
        req = urllib.request.Request(location, headers={'User-Agent': 'CLYLAR-scanner'})
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode('utf-8', 'replace')
    except Exception:
        return {}
    out = {}
    for tag, key in (('friendlyName', 'friendly_name'), ('manufacturer', 'manufacturer'),
                     ('modelName', 'model'), ('deviceType', 'device_type')):
        m = re.search(r'<%s>\s*([^<]{1,160}?)\s*</%s>' % (tag, tag), body, re.I)
        if m:
            out[key] = _clip(html.unescape(m.group(1)), 80)
    return out


def _fetch_descriptions(locations, timeout=2.5):
    """{ip: description dict}, fetched in parallel under one shared deadline."""
    out = {}
    if not locations:
        return out
    ex = ThreadPoolExecutor(max_workers=min(8, len(locations)))
    try:
        futures = {ex.submit(_fetch_upnp_description, loc, ip, timeout): ip for ip, loc in locations.items()}
        try:
            for fut in as_completed(futures, timeout=timeout + 0.5):
                try:
                    d = fut.result()
                except Exception:
                    d = {}
                if d:
                    out[futures[fut]] = d
        except FuturesTimeoutError:
            pass
    finally:
        ex.shutdown(wait=False)
    return out


def _probe_adapter(local_ip, listen_for, mdns_dest, ssdp_dest):
    """Send the SSDP + mDNS queries out of one network adapter and collect every raw reply:
    [(source_ip, bytes)]. The queries go out three times (UDP is lossy); listening lasts `listen_for` s."""
    replies = []
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((local_ip, 0))
        for opt, val in ((socket.IP_MULTICAST_IF, socket.inet_aton(local_ip)), (socket.IP_MULTICAST_TTL, 2)):
            try:
                sock.setsockopt(socket.IPPROTO_IP, opt, val)
            except OSError:
                pass
        names = [_MDNS_META] + [t + '.local' for t in _MDNS_TYPES]
        packets = [(_SSDP_SEARCH, ssdp_dest)]
        packets += [(_mdns_query(names[i:i + 9]), mdns_dest) for i in range(0, len(names), 9)]
        deadline = time.time() + listen_for
        sends, next_send = 0, 0.0
        while time.time() < deadline:
            now = time.time()
            if sends < 3 and now >= next_send:
                for pkt, dest in packets:
                    try:
                        sock.sendto(pkt, dest)
                    except OSError:
                        pass
                sends += 1
                next_send = now + 0.8
            if not select.select([sock], [], [], min(0.2, max(0.0, deadline - now)))[0]:
                continue
            try:
                data, src = sock.recvfrom(9216)
            except OSError:
                continue   # Windows reports an ICMP "port unreachable" from an earlier send as a recv error
            if len(replies) < 2000:
                replies.append((src[0], data))
    except OSError:
        pass
    finally:
        if sock:
            sock.close()
    return replies


def _target_contains(target, ip):
    """Is IPv4 `ip` inside an nmap-style target spec (CIDR, single IP, or per-octet ranges like 10.0.0-3.1-50)?
    Hostnames / IPv6 tokens never match."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    octets = [int(x) for x in str(addr).split('.')]
    for tok in re.split(r'[\s,]+', target or ''):
        if not tok:
            continue
        if '/' in tok:
            try:
                if addr in ipaddress.ip_network(tok, strict=False):
                    return True
            except ValueError:
                pass
            continue
        parts = tok.split('.')
        if len(parts) != 4:
            continue
        ok = True
        for spec, actual in zip(parts, octets):
            if re.fullmatch(r'\d{1,3}', spec):
                ok = int(spec) == actual
            elif re.fullmatch(r'\d{1,3}-\d{1,3}', spec):
                lo, hi = (int(x) for x in spec.split('-'))
                ok = lo <= actual <= hi
            else:
                ok = False
            if not ok:
                break
        if ok:
            return True
    return False


def discover_multicast_services(target=None, listen_for=3.0, adapters=None,
                                mdns_dest=_MDNS_DEST, ssdp_dest=_SSDP_DEST):
    """Ask the local network what is on it: {ip: {'name', 'mdns': {...}, 'ssdp': {...}}}.
    `target` (nmap target spec) limits the UPnP description downloads to hosts we care about.
    `adapters` / `*_dest` exist so tests can aim it at a local fake responder. Never raises."""
    try:
        if adapters is None:
            adapters = [a['ip'] for a in get_local_adapters()
                        if a.get('ip') and not is_loopback_ip(a['ip']) and not a['ip'].startswith('169.254.')]
        adapters = list(dict.fromkeys(adapters))[:6]
        if not adapters:
            return {}
        raw = []
        with ThreadPoolExecutor(max_workers=len(adapters)) as ex:
            for replies in ex.map(lambda ip: _probe_adapter(ip, listen_for, mdns_dest, ssdp_dest), adapters):
                raw.extend(replies)

        mdns_by_ip, ssdp_by_ip = {}, {}
        for src, data in raw:
            if data[:5].upper() == b'HTTP/':
                h = _parse_ssdp(data)
                if not h:
                    continue
                d = ssdp_by_ip.setdefault(src, {'types': set(), 'server': '', 'location': ''})
                d['server'] = d['server'] or h.get('server', '')
                d['location'] = d['location'] or h.get('location', '')
                for t in (h.get('st', ''), h.get('usn', '').split('::')[-1]):
                    if t.lower().startswith('urn:'):
                        d['types'].add(t)
            else:
                p = _parse_mdns(data)
                if p:
                    mdns_by_ip.setdefault(src, []).append(p)

        wanted = {ip: d['location'] for ip, d in ssdp_by_ip.items()
                  if d['location'] and (target is None or _target_contains(target, ip))}
        descriptions = _fetch_descriptions(wanted)

        found = {}
        for ip in set(mdns_by_ip) | set(ssdp_by_ip):
            info = {}
            m = _summarize_mdns(mdns_by_ip.get(ip, []))
            if m['services'] or m['models']:
                info['mdns'] = {'services': m['services'], 'models': m['models']}
            s = ssdp_by_ip.get(ip)
            if s:
                ssdp = {'server': _clip(s['server'], 120), 'types': sorted(_clip(t, 120) for t in s['types'])[:8]}
                ssdp.update(descriptions.get(ip, {}))
                info['ssdp'] = {k: v for k, v in ssdp.items() if v}
            name = m['name'] or (info.get('ssdp') or {}).get('friendly_name', '')
            if name:
                info['name'] = name
            if info:
                found[ip] = info
        return found
    except Exception:
        return {}


def merge_discovery(results, found, target=None):
    """Fold mDNS/SSDP findings into a Discovery scan's host list, in place. Hosts nmap already
    found get a `discovery` block and, if they have none yet, a `hostname`. Hosts nmap missed
    (typically ones that drop ping) are added if they answered on multicast from inside `target`."""
    by_ip = {h.get('ip'): h for h in results}
    for ip, info in (found or {}).items():
        h = by_ip.get(ip)
        if h is None:
            if target is not None and not _target_contains(target, ip):
                continue
            h = {'ip': ip, 'status': 'up', 'mac': 'Unknown', 'mac_vendor': '', 'discovered_via': 'mDNS/SSDP'}
            results.append(h)
            by_ip[ip] = h
        disc = {k: info[k] for k in ('mdns', 'ssdp') if info.get(k)}
        if disc:
            h['discovery'] = disc
        if info.get('name') and not h.get('hostname'):
            h['hostname'] = info['name']
    return results


def discovery_service_text(discovery):
    """Flat list of strings from a host's `discovery` block, for guess_device_type()'s `services` text."""
    out = []
    if not isinstance(discovery, dict):
        return out
    m = discovery.get('mdns') or {}
    out += [str(x) for x in list(m.get('services') or []) + list(m.get('models') or [])]
    s = discovery.get('ssdp') or {}
    out += [str(x) for x in (s.get('types') or [])]
    out += [str(s[k]) for k in ('friendly_name', 'manufacturer', 'model', 'server') if s.get(k)]
    return out


# ---------------------------------------------------------------------------
# Rough device-type guess from OS / MAC vendor / open ports / service banners / hostname
# (a hint, not a fact)
# ---------------------------------------------------------------------------
_ROUTER_OS = ('openwrt', 'routeros', 'dd-wrt', 'tomato', 'cisco ios', 'junos', 'vyos', 'mikrotik', 'router',
              'gateway', 'firewall', 'pfsense', 'fortigate', 'access point')
_NET_VENDORS = ('tp-link', 'tplink', 'd-link', 'tenda', 'zte', 'huawei', 'cisco', 'mikrotik', 'routerboard',
                'ubiquiti', 'netgear', 'zyxel', 'juniper', 'aruba', 'linksys', 'mercusys', 'totolink',
                'fiberhome', 'arris', 'technicolor', 'sagemcom', 'ruijie', 'h3c', 'fortinet')
_PRINTER_VENDORS = ('brother', 'epson', 'ricoh', 'lexmark', 'kyocera', 'xerox', 'konica', 'canon')
_CAMERA_VENDORS = ('hikvision', 'dahua', 'axis comm', 'reolink', 'foscam', 'ezviz', 'amcrest', 'uniview', 'vivotek')
_TV_VENDORS = ('roku', 'vizio', 'tcl ', 'hisense')
_IOT_VENDORS = ('espressif', 'tuya', 'shelly', 'allterco', 'itead', 'sonoff', 'raspberry', 'amazon technologies',
                'nest labs', 'sonos', 'signify', 'philips lighting', 'broadlink', 'yeelight')

# Text found in nmap -sV's service name / product-version banner for an open port.
# More specific than a vendor OUI: a banner describes the actual product, not just the chip maker.
_PRINTER_SERVICE_HINTS = ('printer', 'ipp', 'airprint', 'jetdirect', 'photosmart', 'officejet', 'laserjet',
                          'pdl-datastream')
_CAMERA_SERVICE_HINTS = ('rtsp', 'onvif', 'ipcam', 'dvr', 'nvr', 'webcam', 'axis-video')
_TV_SERVICE_HINTS = ('googlecast', 'chromecast', 'airplay', 'roku', 'samsungtv', 'samsung tv',
                      'dial_multiscreen', 'smarttv', 'smart tv', 'appletv', 'tizen', 'webos', 'bravia', '[tv]')
_IOT_SERVICE_HINTS = ('mqtt', 'homekit', 'home assistant', 'hue bridge', 'philips-hue', 'tuya',
                      '_hap._tcp', 'esphomelib', 'miio', '_matter._tcp', '_hue._tcp')
_ROUTER_SERVICE_HINTS = ('upnp igd', 'internet gateway device', 'dd-wrt', 'openwrt',
                         'internetgatewaydevice', 'miniupnpd')
_WINDOWS_SERVICE_HINTS = ('microsoft-ds', 'netbios-ssn', 'microsoft windows rpc', 'microsoft-windows')
_COMPUTER_SERVICE_HINTS = _WINDOWS_SERVICE_HINTS + ('macbook', 'imac', 'macmini', 'macpro')
_PHONE_SERVICE_HINTS = ('_apple-mobdev', 'iphone', 'ipad')   # iOS devices advertise these over Bonjour

# Text found in a resolved hostname (reverse DNS / NetBIOS). Devices often broadcast their own
# name, which can be far more specific than a MAC vendor alone (e.g. a Samsung MAC + hostname
# "sm-g991b" is unambiguously a Galaxy phone, where the vendor alone could be a phone or a TV).
_PHONE_HOSTNAME_HINTS = ('iphone', 'ipad', 'android', 'galaxy', 'sm-g', 'sm-a', 'sm-n', 'sm-s',
                          'redmi', 'xiaomi', 'oneplus', 'pixel', 'oppo', 'vivo-')
_COMPUTER_HOSTNAME_HINTS = ('desktop-', 'laptop-', 'macbook', 'imac', 'pc-')
_IOT_HOSTNAME_HINTS = ('esp32', 'esp8266', 'sonoff', 'shelly', 'tasmota', 'raspberrypi', 'espressif')
_TV_HOSTNAME_HINTS = ('chromecast', 'roku', 'appletv', 'android-tv', 'smarttv')
_PRINTER_HOSTNAME_HINTS = ('printer', 'hp-', 'epson', 'canon-', 'brother-')

# MAC prefixes (OUIs) that hypervisors give their virtual NICs. A VM that runs no services has no
# open ports and no OS fingerprint (nmap needs an open port to fingerprint), but its MAC still
# gives the hypervisor away.
_VM_OUIS = {'000c29': 'VMware', '005056': 'VMware', '000569': 'VMware', '001c14': 'VMware',
            '080027': 'VirtualBox', '00155d': 'Hyper-V', '00163e': 'Xen', '001c42': 'Parallels',
            '525400': 'QEMU/KVM'}


def virtual_machine_platform(mac='', vendor=''):
    """'VMware' / 'VirtualBox' / ... when the MAC is a hypervisor's virtual NIC, else ''."""
    mac12 = _normalize_mac(mac)
    if mac12 and mac12[:6].lower() in _VM_OUIS:
        return _VM_OUIS[mac12[:6].lower()]
    v = (vendor or '').lower()
    for token, name in (('vmware', 'VMware'), ('virtualbox', 'VirtualBox'), ('parallels', 'Parallels')):
        if token in v:
            return name
    return ''


DEVICE_TYPES = {
    'router':   ('Router / Gateway', 'ti-router'),
    'vm':       ('Virtual Machine', 'ti-server-2'),
    'computer': ('Computer', 'ti-device-desktop'),
    'phone':    ('Phone / Tablet', 'ti-device-mobile'),
    'printer':  ('Printer', 'ti-printer'),
    'camera':   ('Camera', 'ti-camera'),
    'tv':       ('Smart TV', 'ti-device-tv'),
    'iot':      ('IoT device', 'ti-cpu'),
    'unknown':  ('Unknown', 'ti-help'),
}


def guess_device_type(ip, vendor='', os_name='', open_ports=(), gateway_ip=None, services='', hostname='', mac=''):
    """Return {'key','label','icon','reason','confidence'}.
    A few facts decide on their own (default gateway, this PC, a hypervisor's virtual NIC). Every
    other clue adds points to a type -- strong clues (an unambiguous OS, a telltale service or
    hostname) 3-4, weak ones (a vendor, a private MAC) 1-2 -- and the best-supported type wins.
    A thin or narrow lead is labelled "(likely)"; a tie gives Unknown with both sides' reasons.
    `services` is the combined service-name/version text (nmap -sV, mDNS/SSDP); `hostname` is a
    reverse-DNS/NetBIOS/mDNS name."""
    v = (vendor or '').lower()
    o = (os_name or '').lower()
    svc = (services or '').lower()
    h = (hostname or '').lower()
    ports = {int(p) for p in open_ports if str(p).isdigit()}

    def result(key, reason, confidence='high'):
        label, icon = DEVICE_TYPES[key]
        if confidence == 'likely':
            label += ' (likely)'
        return {'key': key, 'label': label, 'icon': icon, 'reason': reason[:1].upper() + reason[1:],
                'confidence': confidence}

    if gateway_ip and ip == gateway_ip:
        return result('router', 'Default gateway of this network')
    if is_local_ip(ip):
        return result('computer', 'This PC')

    scores, why = {}, {}

    def add(key, points, reason):
        scores[key] = scores.get(key, 0) + points
        why.setdefault(key, []).append(reason)

    def has(text, hints):
        return any(t in text for t in hints)

    if has(o, _ROUTER_OS):
        add('router', 3, f'OS guess: {os_name}')
    if has(svc, _ROUTER_SERVICE_HINTS):
        add('router', 4, 'router / UPnP gateway service')

    vm = virtual_machine_platform(mac, vendor)
    if vm and 'router' not in scores:            # a VM running a router OS (pfSense...) is still a router
        known_os = os_name and os_name != 'Unknown' and not re.fullmatch(r'up|down', o)
        return result('vm', f'MAC is a {vm} virtual NIC' + (f' (guest OS: {os_name})' if known_os else ''))

    mobile_os = bool(re.search(r'\bios\b|iphone|ipad|android', o))
    if mobile_os and 'android' not in o and re.search(r'windows|mac os|macos|linux \d', o):
        add('phone', 1, f'OS guess is ambiguous ({os_name})')      # e.g. "macOS 11 - 13 or iOS 16"
        add('computer', 1, f'OS guess is ambiguous ({os_name})')
    elif mobile_os:
        add('phone', 4, f'OS: {os_name}')
    elif re.search(r'windows|mac os|macos', o):
        add('computer', 3, f'OS: {os_name}')
    elif re.search(r'linux|ubuntu|debian|freebsd', o):
        add('computer', 1, f'OS: {os_name}')                       # routers, NAS and IoT run Linux too

    if has(h, _PHONE_HOSTNAME_HINTS):
        add('phone', 3, f'hostname looks like a phone ({hostname})')
    if has(svc, _PHONE_SERVICE_HINTS):
        add('phone', 3, 'advertises itself as an iPhone/iPad')
    if has(svc, _COMPUTER_SERVICE_HINTS):
        add('computer', 3, 'Windows/Mac file-sharing service or model')
    if has(h, _COMPUTER_HOSTNAME_HINTS):
        add('computer', 3, f'hostname looks like a PC ({hostname})')
    if ports & {9100, 515, 631}:
        add('printer', 3, 'printer port open')
    if has(svc, _PRINTER_SERVICE_HINTS):
        add('printer', 3, 'printer service')
    if has(v, _PRINTER_VENDORS):
        add('printer', 2, f'printer vendor ({vendor})')
    if has(h, _PRINTER_HOSTNAME_HINTS):
        add('printer', 2, f'hostname ({hostname})')
    if ports & {554, 8554, 37777, 34567}:
        add('camera', 2, 'video-streaming port open')
    if has(svc, _CAMERA_SERVICE_HINTS):
        add('camera', 3, 'camera / streaming service')
    if has(v, _CAMERA_VENDORS):
        add('camera', 3, f'camera vendor ({vendor})')
    if ports & {8008, 8009, 8060}:
        add('tv', 2, 'cast/TV port open')
    if has(svc, _TV_SERVICE_HINTS):
        add('tv', 3, 'cast / TV service')
    if has(v, _TV_VENDORS):
        add('tv', 2, f'TV vendor ({vendor})')
    if has(h, _TV_HOSTNAME_HINTS):
        add('tv', 3, f'hostname ({hostname})')
    if has(v, _IOT_VENDORS):
        add('iot', 2, f'IoT vendor ({vendor})')
    if has(svc, _IOT_SERVICE_HINTS):
        add('iot', 3, 'smart-home service')
    if has(h, _IOT_HOSTNAME_HINTS):
        add('iot', 3, f'hostname ({hostname})')
    if has(v, _NET_VENDORS):
        add('router', 2 if ports & {53, 80, 443, 22, 23, 8080} else 1, f'network-equipment vendor ({vendor})')
    mac12 = _normalize_mac(mac)
    if mac12 and _is_randomized_mac(mac12):
        add('phone', 1, 'private (randomised) MAC, which phones and tablets use by default')

    if not scores:
        return result('unknown', 'Not enough information')
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top_key, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    if top == second:
        tied = [k for k, s in ranked if s == top]
        return result('unknown', 'Conflicting clues: ' + ' vs '.join(
            f"{DEVICE_TYPES[k][0]} ({', '.join(why[k])})" for k in tied))
    confidence = 'high' if top >= 3 and top - second >= 2 else 'likely'
    return result(top_key, '; '.join(why[top_key]), confidence)


def is_valid_target(target):
    if not target:
        return False
    tokens = target.split()
    for token in tokens:
        if token.startswith('-'):
            return False
        if not re.fullmatch(r'[a-zA-Z0-9.:/,\-]+', token):
            return False
    return True


def get_outbound_local_ip():
    """Find the local IP of the network interface used for active outbound routing."""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return None


def _valid_gateway(gw):
    """A usable IPv4 next-hop (not 0.0.0.0, loopback, link-local or 'On-link')."""
    if not re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', gw or ''):
        return False
    try:
        a = ipaddress.ip_address(gw)
    except ValueError:
        return False
    return not (a.is_unspecified or a.is_loopback or a.is_link_local or a.is_multicast)


def _arp_lookup(ip, max_age=5):
    """MAC of `ip` from the OS ARP cache ('' if not cached)."""
    return get_arp_table(max_age).get(ip, '')


def _gateway_mac(gw_ip):
    """Gateway MAC from the ARP cache; if the cache is cold, ping once to populate it and look again."""
    mac = _arp_lookup(gw_ip)
    if mac:
        return mac
    try:
        ping = ['ping', '-n', '1', '-w', '800', gw_ip] if sys.platform == 'win32' else ['ping', '-c', '1', '-W', '1', gw_ip]
        _run_cmd(ping, 4)
    except Exception:
        pass   # a failed/blocked ping still creates the ARP entry
    return _arp_lookup(gw_ip, max_age=0)


_PS_DEFAULT_ROUTE = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | ForEach-Object { "
    "$ip = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue "
    "| Select-Object -First 1).IPAddress; "
    "[pscustomobject]@{gw=$_.NextHop; iface=$ip; metric=($_.RouteMetric + $_.InterfaceMetric)} } "
    "| ConvertTo-Json -Compress"
)


def _gateway_candidates_windows():
    candidates = []
    try:
        output = _run_cmd(['cmd', '/c', 'route', 'print', '0.0.0.0'], 5).decode('latin-1', errors='ignore')
        for line in output.splitlines():
            parts = line.strip().split()
            # Destination Netmask Gateway Interface Metric
            # 0.0.0.0     0.0.0.0 192.168.1.1 192.168.1.41 30
            if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0' and _valid_gateway(parts[2]):
                try:
                    metric = int(parts[4])
                except ValueError:
                    metric = 9999
                candidates.append({'ip': parts[2], 'interface': parts[3], 'metric': metric})
    except Exception:
        pass

    if not candidates:   # route.exe missing/unparseable: ask PowerShell instead
        try:
            out = _run_cmd(['powershell', '-NoProfile', '-NonInteractive', '-Command', _PS_DEFAULT_ROUTE], 12)
            data = json.loads(out.decode('utf-8', errors='ignore'))
            if isinstance(data, dict):
                data = [data]
            for d in data:
                if _valid_gateway(d.get('gw')):
                    candidates.append({'ip': d['gw'], 'interface': d.get('iface') or '',
                                       'metric': int(d.get('metric') or 9999)})
        except Exception:
            pass
    return candidates


def _gateway_candidates_linux():
    candidates = []
    try:
        output = _run_cmd(['ip', 'route', 'show', 'default'], 5).decode('utf-8', errors='ignore')
        for line in output.splitlines():
            m = re.search(r'default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+dev\s+(\S+))?(?:.*metric\s+(\d+))?', line)
            if m and _valid_gateway(m.group(1)):
                candidates.append({'ip': m.group(1), 'interface': m.group(2) or '',
                                   'metric': int(m.group(3)) if m.group(3) else 100})
    except Exception:
        pass

    if not candidates:   # no `ip` command (minimal container): read the kernel routing table
        try:
            with open('/proc/net/route', 'r') as f:
                next(f, None)
                for row in f:
                    c = row.split()
                    if len(c) >= 8 and c[1] == '00000000':
                        gw = socket.inet_ntoa(struct.pack('<L', int(c[2], 16)))
                        if _valid_gateway(gw):
                            candidates.append({'ip': gw, 'interface': c[0], 'metric': int(c[6])})
        except Exception:
            pass
    return candidates


def _detect_default_gateway():
    try:
        if sys.platform == 'win32':
            candidates = _gateway_candidates_windows()
            active_local_ip = get_outbound_local_ip()
            adapters = {a['ip']: a for a in get_local_adapters()}

            def on_link(c):
                # a gateway outside its own interface's subnet is suspicious (VPN/odd routes): rank it lower
                a = adapters.get(c['interface'])
                if a and a.get('prefix') is not None:
                    try:
                        return ipaddress.ip_address(c['ip']) in ipaddress.ip_network(f"{a['ip']}/{a['prefix']}", strict=False)
                    except ValueError:
                        return True
                return True

            for c in candidates:
                c['is_active'] = bool(active_local_ip and c['interface'] == active_local_ip)
            # Prefer the active outbound interface, then on-link gateways, then lowest metric
            candidates.sort(key=lambda c: (not c['is_active'], not on_link(c), c['metric']))
        else:
            candidates = _gateway_candidates_linux()
            candidates.sort(key=lambda c: c['metric'])

        if not candidates:
            return None
        best = candidates[0]
        gw_mac = _gateway_mac(best['ip'])
        return {
            'ip': best['ip'],
            'interface': best['interface'],
            'metric': best['metric'],
            'mac': gw_mac,
            'mac_vendor': lookup_mac_vendor(gw_mac),
        }
    except Exception:
        return None


_GW_CACHE = {'ts': 0.0, 'data': None}


def get_system_default_gateway(max_age=0):
    """
    Detect the local system's default gateway: {'ip','interface','metric','mac','mac_vendor'} or None.
    Works on Windows (route print, PowerShell fallback) and Linux (ip route, /proc/net/route fallback).
    With several adapters (Wi-Fi, Ethernet, VPN, VMware/WSL) it prefers the active outbound interface,
    then an on-link gateway, then the lowest metric.
    max_age > 0 reuses a result detected that many seconds ago (for pages that call this often).
    """
    if max_age and _GW_CACHE['data'] is not None and time.time() - _GW_CACHE['ts'] < max_age:
        return _GW_CACHE['data']
    gw = _detect_default_gateway()
    if max_age:
        _GW_CACHE['data'] = gw
        _GW_CACHE['ts'] = time.time()
    return gw


def clamp_scan_knobs(timing=None, version_intensity=None, scan_type=None):
    """Normalize user-supplied -T0..-T4 timing and --version-intensity 0-9. Never raises; missing
    or invalid input returns None for that knob, meaning "use this scan type's own default".
    Knobs that scan_type never actually applies are also forced to None here, so a value left
    over in a hidden form field never gets persisted/displayed as if it had been used."""
    t = None
    if timing not in (None, ''):
        try:
            t = max(0, min(4, int(timing)))   # T5 ("insane") is excluded everywhere in this app
        except (TypeError, ValueError):
            t = None
    vi = None
    if version_intensity not in (None, ''):
        try:
            vi = max(0, min(9, int(version_intensity)))
        except (TypeError, ValueError):
            vi = None
    if scan_type == 'custom':
        t, vi = None, None   # Custom sets both via its own raw nmap arguments instead
    elif scan_type == 'discovery':
        vi = None            # -sn never reads a service banner, so intensity is meaningless
    return t, vi


def clamp_skip_ping(value, scan_type=None):
    """The "treat all hosts as online" (-Pn) choice from a form: True / False, or None when the scan type cannot use it.
    Discovery is only a ping sweep (with -Pn every address would come back "up"), an XML import runs nothing, and a Custom
    scan takes -Pn from its own arguments, so a value left in a hidden form field is never stored as if it had been used."""
    if scan_type not in ('fast_scan', 'intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


def clamp_all_ports(value, scan_type=None):
    """The "scan all ports 1-65535" choice from a form: True / False, or None when the scan type cannot use it (Discovery looks at no ports,
    an XML import runs nothing, a Custom scan picks its own ports with -p). A value left in a hidden form field is never stored as if it had been used."""
    if scan_type not in ('fast_scan', 'intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


def clamp_no_dns(value, scan_type=None):
    """The "do not look up device names through DNS" (-n) choice from a form: True / False, or None when the scan type cannot use it (an XML import runs
    nothing and a Custom scan names its own flags). Discovery CAN use it: its ping sweep looks names up too."""
    if scan_type not in ('discovery', 'fast_scan', 'intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


HOST_PROBE_ARGS = '-PE -PP -PS22,23,80,443,445,3389,8080 -PA80,443'      # "find devices that ignore ping": ICMP echo + timestamp, SYN and ACK probes to common ports
GENTLE_EXTRA_ARGS = '--max-retries 2 --max-rate 50 --host-timeout 45m'      # a rate cap (packets per second, all hosts together), two retries, a per-host limit
GENTLE_ARGS = '-T2 ' + GENTLE_EXTRA_ARGS
GENTLE_MAX_ADDRESSES = 1024         # a Gentle scan is slow per host (about 10 to 40 times a normal one), so a whole /21 would never finish in its time limit
GENTLE_TIME_LIMIT = 8 * 3600        # the job's time limit with Gentle on (scan_runner.time_limit_for); a guess to revise after a real lab timing


def clamp_probes(value, scan_type=None):
    """The "find devices that ignore ping" (host-discovery probes) choice from a form: True / False, or None when the scan type cannot use it (an XML import
    runs nothing, a Custom scan names its own flags). Discovery CAN use it: that is where it helps most."""
    if scan_type not in ('discovery', 'fast_scan', 'intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


def clamp_gentle(value, scan_type=None):
    """The Gentle scan choice from a form: True / False for the three port scans, None otherwise (Discovery sends a handful of probes, a Custom scan names its own)."""
    if scan_type not in ('fast_scan', 'intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


UDP_PORTS = (53, 67, 69, 123, 137, 161, 500, 520, 623, 1434, 1900, 5060)      # DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE, RIP, IPMI, SQL Browser, SSDP, SIP
UDP_PORT_SPEC = 'U:' + ','.join(str(p) for p in UDP_PORTS)
UDP_HOST_TIMEOUT = '10m'
UDP_MAX_ADDRESSES = 64              # the same bound as "scan all ports"; the UDP run only visits the hosts the first run found up, but a /25 is not what it was sized for
UDP_TIME_LIMIT = 6 * 3600           # the job's time limit when the option is on (scan_runner.time_limit_for): UDP answers are slow (ICMP rate limits)


def clamp_udp(value, scan_type=None):
    """The "also scan common UDP ports" choice from a form: True / False for Intense and Vulnerability scans, None for every other type (a Fast Scan is
    meant to be quick, Discovery looks at no ports, a Custom scan names its own flags, an XML import runs nothing)."""
    if scan_type not in ('intense', 'vuln_scan'):
        return None
    return str(value or '').strip().lower() in ('1', 'true', 'on', 'yes')


def udp_arguments(t=None, no_dns=False, gentle=False):
    """The arguments of the SECOND nmap run, the UDP one: UDP only (-sU -p U:...), the 12 ports in UDP_PORTS, light service detection, no OS detection and no scripts,
    two retries and ten minutes per host, -Pn because the hosts are already known to be up (a UDP-filtered host must not be dropped by a ping that it also ignores).
    Gentle adds its -T2 and rate cap, otherwise a chosen timing is used. A UDP scan alone never touches a TCP port: `-sS -sU -p U:...` would scan no TCP, and
    `-sU --top-ports` would change the first run, so this is a separate run, not an option of that one."""
    args = f'-sU -p {UDP_PORT_SPEC} -sV --version-intensity 0 --max-retries 2 --host-timeout {UDP_HOST_TIMEOUT} -Pn'
    if gentle:
        args += ' -T2 --max-rate 50'
    elif t is not None:
        args += f' -T{t}'
    if no_dns:
        args += ' -n'
    return args


def udp_limit_error(target, udp=True):
    """The error text (as stored scan results) when the UDP option is asked for on more than UDP_MAX_ADDRESSES addresses, else None."""
    if not udp:
        return None
    n = target_size(target)
    if n > UDP_MAX_ADDRESSES:
        return json.dumps([{"error": "The UDP scan is limited to %d addresses (a /26); this target has %s. Use a smaller range or untick the option."
                                     % (UDP_MAX_ADDRESSES, format(n, ','))}])
    return None


def udp_unavailable():
    """The English error text when this machine cannot do a UDP scan, else None. nmap sends and reads raw UDP packets and ICMP errors, which needs Administrator /
    root and, on Windows, Npcap; without them nmap falls back to something that cannot tell `closed` from `open|filtered`, so the app refuses instead of storing
    a scan that looks like it worked. A missing nmap is not reported here (the scan page already warns about it and the scan fails by itself)."""
    caps = get_scan_capabilities()
    if caps.get('nmap') is False:
        return None
    if not caps.get('is_admin'):
        return 'The UDP scan needs Administrator (or root) rights, and the application is not running with them.'
    if not caps.get('npcap'):
        return 'The UDP scan needs Npcap, which was not found on this computer.'
    return None


def udp_unavailable_th():
    """The same, in Thai, for a form route's message."""
    caps = get_scan_capabilities()
    if caps.get('nmap') is False:
        return None
    if not caps.get('is_admin'):
        return 'การสแกน UDP ต้องรันโปรแกรมด้วยสิทธิ์ Administrator หรือ root แต่ขณะนี้โปรแกรมไม่ได้รันด้วยสิทธิ์ดังกล่าว'
    if not caps.get('npcap'):
        return 'การสแกน UDP ต้องติดตั้ง Npcap แต่ไม่พบบนเครื่องนี้'
    return None


def options_conflict(skip_ping=False, all_ports=False, host_probes=False, gentle=False):
    """The English error text when two options that cannot work together are both on, else None. -Pn treats every address as online WITHOUT asking, the probes ask
    in a different way: nmap's behaviour with both depends on argument order, so the app refuses the pair. Gentle scans 65,535 ports at about 2.5 probes a second
    per host, i.e. hours per host, and the per-host limit would cut every host off."""
    if skip_ping and host_probes:
        return "Finding devices that ignore ping (host probes) and -Pn cannot be used together: -Pn treats every address as online without asking. Turn one of them off."
    if gentle and all_ports:
        return "Gentle scan and scanning all ports cannot be used together: at Gentle speed 65,535 ports take hours per device. Turn one of them off."
    return None


def options_conflict_th(skip_ping=False, all_ports=False, host_probes=False, gentle=False):
    """The same, in Thai, for a form route's message."""
    if skip_ping and host_probes:
        return 'ตัวเลือกตรวจหาอุปกรณ์ที่ไม่ตอบ ping กับการข้ามการ ping (-Pn) ใช้ร่วมกันไม่ได้ กรุณาเลือกอย่างใดอย่างหนึ่ง'
    if gentle and all_ports:
        return 'การสแกนแบบนุ่มนวลกับการสแกนทุกพอร์ตใช้ร่วมกันไม่ได้ เพราะที่ความเร็วนี้ 65,535 พอร์ตใช้เวลาหลายชั่วโมงต่อเครื่อง กรุณาเลือกอย่างใดอย่างหนึ่ง'
    return None


def gentle_limit_error(target, gentle=True):
    """The error text (as stored scan results) when a Gentle scan is asked for on more than GENTLE_MAX_ADDRESSES addresses, else None."""
    if not gentle:
        return None
    n = target_size(target)
    if n > GENTLE_MAX_ADDRESSES:
        return json.dumps([{"error": "Gentle scan is limited to %s addresses (a /22); this target has %s. Use a smaller range or untick the option."
                                     % (format(GENTLE_MAX_ADDRESSES, ','), format(n, ','))}])
    return None


ALL_PORTS_MAX_ADDRESSES = 64        # work = addresses x 65,535 ports; a /26. Measured on loopback only, so raise it after a real /26 has been timed
ALL_PORTS_HOST_TIMEOUT = '45m'      # nmap gives up on ONE host after this long; the whole-job time limit would throw the whole run away
ALL_PORTS_TIME_LIMIT = 6 * 3600     # the job's time limit when the option is on (scan_runner.time_limit_for)
DEFAULT_VERSION_INTENSITY = 7      # used when a scan type that reads banners is run without its own --version-intensity
DEEP_SCAN_DEFAULT_TIMING = 4       # Intense and Vulnerability scans run -T4 unless a timing was chosen


def scan_arguments(scan_type, t=None, vi=None, skip_ping=False, all_ports=False, no_dns=False, host_probes=False, gentle=False):
    """The nmap arguments of a scan type; t and vi are the values after clamp_scan_knobs (None = that type's own default).
    skip_ping adds -Pn (do not check whether a host answers first, scan every address) to the three port scans; Discovery ignores it.
    all_ports (the three port scans only) scans ports 1-65535 instead of the scan's usual list and adds --host-timeout, so one silent host cannot use up the whole
    job; nmap refuses -F together with -p, so Fast replaces -F by -p-. With it off every string is exactly what it was before the option existed.
    no_dns adds -n (nmap does no reverse DNS) to all four scans that look at hosts, Discovery included; it is always the last argument.
    host_probes adds HOST_PROBE_ARGS (Discovery and the three port scans; the caller refuses it together with -Pn). gentle (the three port scans) REPLACES the
    timing: -T2, a rate cap, two retries and a per-host limit, and Intense / Vulnerability drop -A's default scripts (the app never stores their output) in favour of
    -sV -O --traceroute, which gives the same stored data with far fewer probes.
    run_network_scan and run_vuln_scan build their nmap command here, and the Tasks page describes a job with this same
    function (see describe_scan_settings), so what the page says was run is what was run. A Custom scan runs the user's own
    validated arguments and an XML import runs nothing: both give ''."""
    dns = ' -n' if no_dns else ''
    probes = (' ' + HOST_PROBE_ARGS) if host_probes else ''
    if scan_type == 'discovery':
        return '-sn' + probes + (f' -T{t}' if t is not None else '') + dns
    pn = ' -Pn' if skip_ping else ''
    guard = f' --host-timeout {ALL_PORTS_HOST_TIMEOUT}'
    if scan_type == 'fast_scan':
        return (('-p-' if all_ports else '-F') + f' -sV --version-intensity {vi if vi is not None else DEFAULT_VERSION_INTENSITY} -O' + ((' ' + GENTLE_ARGS) if gentle else (f' -T{t}' if t is not None else '')) + pn + probes
                + (guard if all_ports else '') + dns)
    if scan_type in ('intense', 'vuln_scan'):
        vint = vi if vi is not None else DEFAULT_VERSION_INTENSITY
        if gentle:
            return f'-T2 -sV -O --traceroute -v --version-intensity {vint} ' + GENTLE_EXTRA_ARGS + pn + probes + dns
        return (f'-T{t if t is not None else DEEP_SCAN_DEFAULT_TIMING} -A -v --version-intensity {vint}' + pn + probes
                + (' -p-' + guard if all_ports else '') + dns)
    return ''


def describe_scan_settings(scan_type, timing=None, version_intensity=None, custom_args=None, multicast=None, skip_ping=None, all_ports=None, no_dns=None, host_probes=None, gentle=None, udp=None):
    """What a job or a schedule ran with, for the Tasks page's details panel. No I/O and nothing is guessed: a value that
    was not recorded stays None. Words belong to the page; this returns facts:
      arguments  the nmap arguments (without the target); for Custom, the arguments as saved ('' when not recorded)
      timing     {'value': int|None, 'source': 'set' | 'nmap-default' | 'type-default' | 'custom' | 'none'}
      intensity  {'value': int|None, 'source': 'set' | 'type-default' | 'unused' | 'custom' | 'none'}
      multicast  True / False for Discovery (None = not recorded, or not a Discovery scan)
      skip_ping  True when -Pn was used, False when it was not (a job from before the option existed did not use it), None for
                 Discovery and XML imports, which cannot use it
      all_ports  True when ports 1-65535 were scanned, False when the scan's usual list was (a job from before the option existed did), None for
                 Discovery, XML imports and Custom scans (a Custom scan names its own ports)
      no_dns     True when device names were NOT looked up through DNS (-n), False when they were (a job from before the option existed did),
                 None for XML imports and Custom scans
      host_probes True when the scan also probed common ports to find devices that ignore ping, False when it did not (a job from before the option existed
                 did not), None for XML imports and Custom scans
      gentle     True for a Gentle scan (its `timing` source is 'gentle'), False when it was not, None for Discovery, XML imports and Custom scans
      udp        True when a second nmap run scanned the common UDP ports (Intense and Vulnerability scans only), False when it did not (a job from before the
                 option existed did not), None for the other types; udp_arguments is that run's arguments (its target is the hosts the first run found up)
      steps      extra things the scan does besides the nmap run: 'gateway_probe', 'mdns_ssdp', 'nvd_lookup', 'udp_pass', 'xml_import'"""
    t, vi = clamp_scan_knobs(timing, version_intensity, scan_type=scan_type)
    steps = []
    if scan_type == 'custom':
        info_t, info_vi = {'value': None, 'source': 'custom'}, {'value': None, 'source': 'custom'}
        arguments = (custom_args or '').strip()
    elif scan_type == 'xml_upload':
        info_t, info_vi = {'value': None, 'source': 'none'}, {'value': None, 'source': 'none'}
        arguments = ''
        steps.append('xml_import')
    else:
        arguments = scan_arguments(scan_type, t, vi, bool(skip_ping), bool(all_ports) and scan_type != 'discovery', bool(no_dns), bool(host_probes),
                                   bool(gentle) and scan_type in ('fast_scan', 'intense', 'vuln_scan'))
        if gentle and scan_type in ('fast_scan', 'intense', 'vuln_scan'):
            info_t = {'value': 2, 'source': 'gentle'}
        elif scan_type in ('intense', 'vuln_scan'):
            info_t = {'value': t, 'source': 'set'} if t is not None else {'value': DEEP_SCAN_DEFAULT_TIMING, 'source': 'type-default'}
        else:
            info_t = {'value': t, 'source': 'set'} if t is not None else {'value': 3, 'source': 'nmap-default'}
        if scan_type == 'discovery':
            info_vi = {'value': None, 'source': 'unused'}
        else:
            info_vi = {'value': vi, 'source': 'set'} if vi is not None else {'value': DEFAULT_VERSION_INTENSITY, 'source': 'type-default'}
        if scan_type == 'discovery':
            steps.append('gateway_probe')
            if multicast:
                steps.append('mdns_ssdp')
        if scan_type == 'vuln_scan':
            steps.append('nvd_lookup')
    if scan_type in ('discovery', 'xml_upload'):
        pn = None
    elif scan_type == 'custom':
        pn = '-Pn' in arguments.split()
    else:
        pn = bool(skip_ping)
    ap = bool(all_ports) if scan_type in ('fast_scan', 'intense', 'vuln_scan') else None
    nd = bool(no_dns) if scan_type in ('discovery', 'fast_scan', 'intense', 'vuln_scan') else None
    hp = bool(host_probes) if scan_type in ('discovery', 'fast_scan', 'intense', 'vuln_scan') else None
    gt = bool(gentle) if scan_type in ('fast_scan', 'intense', 'vuln_scan') else None
    ud = bool(udp) if scan_type in ('intense', 'vuln_scan') else None
    if ud:
        steps.append('udp_pass')
    return {'scan_type': scan_type, 'arguments': arguments, 'timing': info_t, 'intensity': info_vi,
            'multicast': (bool(multicast) if multicast is not None else None) if scan_type == 'discovery' else None,
            'skip_ping': pn, 'all_ports': ap, 'no_dns': nd, 'host_probes': hp, 'gentle': gt, 'udp': ud,
            'udp_arguments': udp_arguments(t, bool(no_dns), bool(gentle)) if ud else None, 'steps': steps}


def os_match_accuracy(value):
    """nmap's confidence (0-100) in its best OS match as a whole number, or None when there is none or it is not a sensible number.
    python-nmap hands it over as text ('96'); a stored scan has it as a number. A scan from before it was kept has none: that is "not recorded", never a guess."""
    try:
        n = int(float(str(value).strip()))
    except (TypeError, ValueError, OverflowError):          # OverflowError: the text 'inf'
        return None
    return n if 0 <= n <= 100 else None


# nmap's REASON for a port state ("syn-ack", "conn-refused", "no-response" ...). nmap always writes it into its XML, with or without the --reason
# flag, and python-nmap hands it over, so no nmap argument changes. It is stored as `reason` next to `state`; a scan from before this was kept has
# none (= not recorded). It is plain lowercase text from nmap, so anything else (markup, a long text, a number) is dropped, never stored.
_PORT_REASON = re.compile(r'[a-z0-9]+(?:-[a-z0-9]+)*')
PORT_REASON_TH = {
    'syn-ack': 'พอร์ตตอบรับการเชื่อมต่อ',
    'conn-refused': 'ปฏิเสธการเชื่อมต่อ',
    'reset': 'ตอบกลับ RST แสดงว่าพอร์ตปิด',
    'no-response': 'ไม่มีการตอบกลับ',
    'admin-prohibited': 'ICMP แจ้งว่าถูกห้ามโดยผู้ดูแล',
    'host-unreach': 'ICMP แจ้งว่าไปถึงอุปกรณ์ไม่ได้',
    'net-unreach': 'ICMP แจ้งว่าไปถึงเครือข่ายไม่ได้',
    'port-unreach': 'ICMP แจ้งว่าไม่มีพอร์ตนี้',
    'udp-response': 'UDP ตอบกลับ',
    'tcp-response': 'TCP ตอบกลับ',
    'proto-response': 'ตอบกลับตามโปรโตคอล',
    'echo-reply': 'ตอบกลับ ping',
    'arp-response': 'ตอบกลับ ARP',
}


def port_reason(value):
    """nmap's reason for a port state as clean lowercase text, or None when there is none or it is not a plain nmap reason."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    return v if 0 < len(v) <= 40 and _PORT_REASON.fullmatch(v) else None


def port_reason_label(value):
    """The Thai words for a stored reason; a reason this table does not know is returned as nmap wrote it; nothing is None."""
    v = port_reason(value)
    return PORT_REASON_TH.get(v, v) if v else None


def _keep_reason(entry, port_data):
    """Add `reason` to a port record when nmap gave a usable one."""
    r = port_reason(port_data.get('reason'))
    if r:
        entry['reason'] = r


_PORT_PROTOCOL = re.compile(r'[a-z]{2,8}')


def port_proto(p):
    """The protocol of a stored port record, lowercase: 'tcp', 'udp', 'sctp'. A record without one (every scan from before UDP stored TCP only) or with
    something that is not a protocol name is 'tcp'."""
    v = str(p.get('protocol') or '').strip().lower() if isinstance(p, dict) else ''
    return v if _PORT_PROTOCOL.fullmatch(v) else 'tcp'


def port_key(p):
    """What identifies a port: (port number as text, protocol), or None when the record has no port number. 53/tcp and 53/udp are two ports; counting or
    grouping ports by number alone would merge them. The state is not part of the key."""
    if not isinstance(p, dict) or p.get('port') in (None, ''):
        return None
    return (str(p.get('port')), port_proto(p))


def port_text(p):
    """The "port/service" label the dashboard, the Devices page and the chatbot use. A TCP port is exactly what it always was ("80/http"); any other
    protocol says so ("161/snmp (UDP)"), so the same number over two protocols gives two labels. It starts with the port number, which the pages split on."""
    base = f"{p.get('port')}/{p.get('name', '?')}"
    proto = port_proto(p)
    return base if proto == 'tcp' else f"{base} ({proto.upper()})"


# ---------------------------------------------------------------------------
# What nmap itself said about a run. python-nmap keeps most of its XML (hosts, ports, OS, the counts) but not the nmap version or the
# traceroute hops, so the raw XML is read here. Nothing in this block is a guess: a value nmap did not give is None / absent, and a
# scan from before this existed simply has no "scan_info" (= not recorded).
# ---------------------------------------------------------------------------
def _xml_int(value, high=2 ** 31):
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= high else None


def _xml_float(value, high=1e9):
    try:
        n = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return round(n, 3) if 0 <= n <= high else None      # NaN fails the comparison, so it ends up None as well


def parse_run_xml(xml_text):
    """Facts from nmap's `-oX` text: {'version', 'up', 'down', 'total', 'elapsed', 'hops': {ip: [hop, ...]}, 'distance': {ip: n}}.
    up / down / total are nmap's own count of the addresses it checked (`<hosts up= down= total=>`), a hop is
    {'ttl', 'ip', 'rtt', 'host'}. A part the XML does not have is None / empty; text that is not nmap XML gives {}. Never raises.
    Text that comes from the network (a hop's name) is cleaned with _clip()."""
    try:
        if isinstance(xml_text, (bytes, bytearray)):
            xml_text = bytes(xml_text).decode('utf-8', 'replace')
        if not isinstance(xml_text, str) or '<nmaprun' not in xml_text:
            return {}
        root = ET.fromstring(xml_text)
        if root.tag != 'nmaprun':
            return {}
        facts = {'version': _clip(root.get('version') or '', 20) or None, 'up': None, 'down': None, 'total': None,
                 'elapsed': None, 'hops': {}, 'distance': {}, 'timedout': set(), 'extraports': {}}
        stats = root.find('runstats/hosts')
        if stats is not None:
            facts['up'], facts['down'], facts['total'] = (_xml_int(stats.get(k)) for k in ('up', 'down', 'total'))
        finished = root.find('runstats/finished')
        if finished is not None:
            facts['elapsed'] = _xml_float(finished.get('elapsed'))
        for host in root.findall('host'):
            ip = next(((a.get('addr') or '').strip() for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')), '')
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if host.get('timedout') == 'true':          # --host-timeout ran out: nmap gives no <ports> for this host at all
                facts['timedout'].add(ip)
            extra = []
            for ep in host.findall('ports/extraports'):          # the one state nmap does not list port by port ("65509 closed")
                state, count = (ep.get('state') or '').strip().lower(), _xml_int(ep.get('count'), 65535)
                if count and 0 < len(state) <= 24 and re.fullmatch(r'[a-z]+(?:\|[a-z]+)*', state):
                    extra.append({'state': state, 'count': count})
            if extra:
                facts['extraports'][ip] = extra
            dist = host.find('distance')
            if dist is not None and _xml_int(dist.get('value'), 255) is not None:
                facts['distance'][ip] = _xml_int(dist.get('value'), 255)
            hops = []
            for hop in host.findall('trace/hop'):
                hop_ip, ttl = (hop.get('ipaddr') or '').strip(), _xml_int(hop.get('ttl'), 255)
                try:
                    ipaddress.ip_address(hop_ip)
                except ValueError:
                    continue
                if ttl is not None:
                    hops.append({'ttl': ttl, 'ip': hop_ip, 'rtt': _xml_float(hop.get('rtt'), 1e6), 'host': _clip(hop.get('host') or '', 80)})
            if hops:
                facts['hops'][ip] = sorted(hops, key=lambda h: h['ttl'])
        return facts
    except Exception:
        return {}


HOST_EVIDENCE_STATES = ('open', 'closed', 'unfiltered')   # a port that answered, even "closed" (a reset came back from the host)
ARP_ONLY_MAX = 30                                         # how many "known to this PC's ARP table but not found by the scan" rows are kept
PN_NOTHING_ANSWERED = ('With -Pn nmap treated every address as online, but nothing answered on any of them: no open or closed port and no MAC '
                       'address. The target is offline or filters everything, and the scan cannot tell which.')


PN_MAX_ADDRESSES = 1024      # -Pn scans EVERY address; a scan runs inside a web request, so a big range would hold it for hours


def target_size(target):
    """How many addresses an nmap-style target names: CIDR, per-octet ranges (10.0.0-3.1-50), single IPs and names (1 each), joined by
    spaces or commas. IPv6 networks count their real size. Never raises; an unreadable token counts as 1."""
    total = 0
    for tok in re.split(r'[\s,]+', target or ''):
        if not tok:
            continue
        try:
            if '/' in tok:
                total += ipaddress.ip_network(tok, strict=False).num_addresses
                continue
            parts = tok.split('.')
            n = 1
            if len(parts) == 4:
                for spec in parts:
                    m = re.fullmatch(r'(\d{1,3})-(\d{1,3})', spec)
                    if m:
                        lo, hi = int(m.group(1)), int(m.group(2))
                        n *= max(1, hi - lo + 1) if lo <= hi else 1
            total += n
        except ValueError:
            total += 1
    return total


def pn_limit_error(target):
    """The error text (as stored scan results) when -Pn is asked for on more than PN_MAX_ADDRESSES addresses, else None."""
    n = target_size(target)
    if n > PN_MAX_ADDRESSES:
        return json.dumps([{"error": "-Pn scans every address, so it is limited to %d addresses (a /22); this target has %s. "
                                     "Use a smaller range or turn -Pn off." % (PN_MAX_ADDRESSES, format(n, ','))}])
    return None


def ports_limit_error(target, all_ports=True):
    """The error text (as stored scan results) when "all ports" is asked for on more than ALL_PORTS_MAX_ADDRESSES addresses, else None.
    Every address gets 65,535 probes, and a host that drops them takes many minutes, so the work is bounded here; the form routes check it too."""
    if not all_ports:
        return None
    n = target_size(target)
    if n > ALL_PORTS_MAX_ADDRESSES:
        return json.dumps([{"error": "Scanning all 65,535 ports is limited to %d addresses (a /26); this target has %s. "
                                     "Use a smaller range or untick the option." % (ALL_PORTS_MAX_ADDRESSES, format(n, ','))}])
    return None


def host_has_evidence(host):
    """Did anything answer for this host? A MAC address from nmap (it only gets one when the host answered its ARP), or a port
    that is open, closed or unfiltered. A port that is only "filtered" is not evidence: it is what an empty address looks like too."""
    if not isinstance(host, dict):
        return False
    if _normalize_mac(host.get('mac')):
        return True
    return any(str(p.get('state') or '').lower() in HOST_EVIDENCE_STATES for p in (host.get('ports') or []) if isinstance(p, dict))


def arp_unlisted(results, target, table=None):
    """Devices in this computer's ARP cache that lie inside `target` but that the scan did not list: [{'ip', 'mac', 'vendor'}], by address.
    The cache only holds what this PC talked to recently (an entry can be a few minutes stale), and broadcast / multicast entries never
    get in (get_arp_table keeps real device MACs only). None when the cache could not be read."""
    try:
        table = get_arp_table(max_age=0) if table is None else table
        listed = {str(h.get('ip') or '').strip() for h in results if isinstance(h, dict)}
        rows = []
        for ip, mac in table.items():
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip in listed or addr.version != 4 or addr.is_multicast or addr.is_loopback or addr.is_unspecified or addr.is_link_local:
                continue
            if _target_contains(target, ip):
                rows.append({'ip': ip, 'mac': mac, 'vendor': lookup_mac_vendor(mac) or ''})
        return sorted(rows, key=lambda r: tuple(int(x) for x in r['ip'].split('.')))
    except Exception:
        return None


def note_capabilities(info):
    """Whether this machine could do nmap's best work when the scan ran (Administrator / root, Npcap), so a scan page can say
    "this run had no Administrator rights" about THAT scan and not about how the app runs now."""
    try:
        caps = get_scan_capabilities()
        info['admin'] = bool(caps.get('is_admin'))
        info['npcap'] = bool(caps.get('npcap'))
    except Exception:
        pass


def capture_run(nm, info=None):
    """Reads nmap's raw XML after nm.scan(), puts what it said about the run into `info` (nmap, checked, up, down, elapsed) and
    returns the parsed facts (hops, distance) for finish_scan(). A scanner object with no raw output gives {} and leaves `info` alone."""
    try:
        facts = parse_run_xml(nm.get_nmap_last_output())
    except Exception:
        facts = {}
    if info is not None:
        if facts.get('version'):
            info['nmap'] = facts['version']
        for key, name in (('total', 'checked'), ('up', 'up'), ('down', 'down'), ('elapsed', 'elapsed')):
            if facts.get(key) is not None:
                info[name] = facts[key]
    return facts


def finish_scan(results, facts=None, info=None, skip_ping=False, target=None, all_ports=False):
    """The last step every scan shares, on the host list before it is stored:
      - traceroute hops from nmap's XML become `trace_hops`, but only a path that REACHED the host (its last hop is the host itself) and
        whose last two hops are consecutive (nmap leaves out a hop that did not answer, so after a gap the listed hop before the host
        may be two routers back), because the diagram names "the hop before the host" as that host's router;
      - with -Pn nmap reports every address as online, so only the hosts something answered for are kept (host_has_evidence) and the
        rest are counted in info['no_evidence'] instead of becoming hundreds of "devices";
      - devices this PC's ARP cache knows inside the target that the scan did not list go to info['arp_only'] (not into the results);
      - a host that ran out of --host-timeout has its `ports` removed and `timed_out` set: no port list means "ports not scanned", while an empty
        list would say "0 open found", which is false; a host whose OPEN ports nmap collapsed into <extraports state="open"> gets `ports_unlisted`
        ({"open": N}) so it is not read as "0 open" (collapsed closed / filtered ports are the normal case and are not recorded per host);
      - with all_ports, info['ports_scanned'] = 65535, so "no other open port" is not read as "nothing else exists".
    Returns the host list to store. Never raises."""
    facts = facts or {}
    info = info if info is not None else {}
    try:
        for h in results:
            hops = (facts.get('hops') or {}).get(h.get('ip')) if isinstance(h, dict) else None
            if hops and hops[-1]['ip'] == h.get('ip') and (len(hops) == 1 or hops[-1]['ttl'] - hops[-2]['ttl'] == 1):
                h['trace_hops'] = hops
        timedout, extraports = facts.get('timedout') or set(), facts.get('extraports') or {}
        for h in results:
            ip = h.get('ip') if isinstance(h, dict) else None
            if ip in timedout:
                h.pop('ports', None)
                h['timed_out'] = True
            collapsed_open = sum(e['count'] for e in extraports.get(ip, []) if e['state'] == 'open')
            if collapsed_open:
                h['ports_unlisted'] = {'open': collapsed_open}
        info['skip_ping'] = bool(skip_ping)
        if all_ports:
            info['ports_scanned'] = 65535
        if skip_ping:
            kept = [h for h in results if host_has_evidence(h)]
            info['no_evidence'] = len(results) - len(kept)
            info['up'] = len(kept)
            info.pop('down', None)       # with -Pn nmap never found out which addresses are down
            results = kept
        if timedout:
            info['timed_out'] = len([h for h in results if isinstance(h, dict) and h.get('timed_out')])
    except Exception:
        pass
    if target:
        rows = arp_unlisted(results, target)
        if rows is not None:
            info['arp_only_total'] = len(rows)
            if rows:
                info['arp_only'] = rows[:ARP_ONLY_MAX]
    return results


# ---------------------------------------------------------------------------
# Controlled nmap runs: a scan that can be cancelled, or stopped at a time limit (the background runner, scan_runner.py, sets this up).
# python-nmap's own scan() starts nmap with subprocess.Popen and never hands the process over, so it cannot be stopped from outside;
# ControlledScanner is the same scan() with the process kept. Nothing here changes what a scan finds or how its result is read.
# ---------------------------------------------------------------------------
class ScanStopped(Exception):
    """A scan was stopped on purpose: cancelled, or past its time limit. The text becomes the job's error (run_network_scan and
    run_vuln_scan turn any exception into one error row)."""


def kill_process_tree(proc):
    """Stop OUR nmap and anything it started. On Windows `proc.kill()` can leave children running, so `taskkill /T` is used."""
    try:
        if proc.poll() is not None:
            return
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15, check=False)
        if proc.poll() is None:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _limit_words(seconds):
    """A time limit in plain words, for the error a timed-out scan stores."""
    if seconds >= 3600 and seconds % 3600 == 0:
        n = int(seconds // 3600)
        return '%d hour%s' % (n, '' if n == 1 else 's')
    if seconds >= 60 and seconds % 60 == 0:
        n = int(seconds // 60)
        return '%d minute%s' % (n, '' if n == 1 else 's')
    return '%g second%s' % (seconds, '' if seconds == 1 else 's')


PROGRESS_EVERY = '3s'             # how often nmap is asked to report (--stats-every); only a scan that has a ScanControl asks for it
_TASK_PROGRESS = re.compile(rb'<taskprogress\s([^>]*?)/?>')
_XML_ATTR = re.compile(rb'([A-Za-z_][\w-]*)="([^"]*)"')


def _find_task_progress(data):
    """(the newest <taskprogress .../> in `data` as {'task', 'percent', 'remaining'}, the offset where that tag ends), or (None, 0).
    Tags nmap wrote but whose numbers cannot be read are skipped."""
    found, end = None, 0
    for m in _TASK_PROGRESS.finditer(data or b''):
        attrs = dict(_XML_ATTR.findall(m.group(1)))
        try:
            percent = float(attrs[b'percent'])
        except (KeyError, ValueError):
            continue
        if percent != percent:                 # NaN
            continue
        try:
            remaining = max(0, int(float(attrs[b'remaining'])))
        except (KeyError, ValueError, OverflowError):
            remaining = None                   # nmap does not always know; "unknown" stays unknown
        task = html.unescape(attrs.get(b'task', b'').decode('utf-8', 'replace'))    # nmap XML-escapes the name; plain text from here on
        task = re.sub(r'[\x00-\x1f\x7f]', '', task).strip()[:60]
        found, end = {'task': task, 'percent': round(min(100.0, max(0.0, percent)), 1), 'remaining': remaining}, m.end()
    return found, end


def parse_task_progress(data):
    """The newest nmap progress report in a piece of its XML output: {'task', 'percent', 'remaining'} ('remaining' in seconds, None when nmap
    gave none), or None. nmap only prints these when asked (--stats-every) and each one is about ONE step of the scan (ping, port scan,
    service scan ...), so a percentage is never a whole-scan percentage."""
    return _find_task_progress(data)[0]


class ScanControl:
    """What can be told to one running scan: cancel it, or stop it when its time is up. One per job; the worker thread running the scan
    makes it current with set_control(). `time_limit` is in seconds (None = no limit). It also holds the latest progress the scan reported,
    for the Tasks page (in memory only: it matters while the scan runs)."""

    def __init__(self, time_limit=None):
        self.cancelled = threading.Event()
        self.time_limit = time_limit
        self.deadline = (time.monotonic() + time_limit) if time_limit else None
        self.timed_out = False
        self._lock = threading.Lock()
        self._proc = None
        self._progress = None
        self._progress_at = None

    def set_progress(self, **fields):
        """Replaces the progress (kind 'nmap': task, percent, remaining; kind 'nvd': done, total). Callable from any thread."""
        with self._lock:
            self._progress = dict(fields)
            self._progress_at = time.monotonic()

    def progress_snapshot(self):
        """(a copy of the latest progress fields, seconds since they were set), or (None, None) when nothing was reported yet."""
        with self._lock:
            if self._progress is None:
                return None, None
            return dict(self._progress), time.monotonic() - self._progress_at

    def attach(self, proc):
        with self._lock:
            self._proc = proc

    def detach(self):
        with self._lock:
            self._proc = None

    def cancel(self):
        """Called from another thread (the Cancel button): flags the scan and kills the nmap process that is running right now."""
        self.cancelled.set()
        with self._lock:
            proc = self._proc
        if proc is not None:
            kill_process_tree(proc)

    def raise_if_cancelled(self):
        if self.cancelled.is_set():
            raise ScanStopped('Scan cancelled.')

    def check(self):
        """Raises ScanStopped when the scan must not go on: cancelled, or past its time limit."""
        self.raise_if_cancelled()
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.timed_out = True
            raise ScanStopped('Scan stopped: it ran longer than its time limit (%s).' % _limit_words(self.time_limit))


_control_local = threading.local()


def set_control(ctl):
    """Makes `ctl` the control of the scan running in THIS thread (None clears it). Another thread's scan never sees it."""
    _control_local.ctl = ctl


def current_control():
    return getattr(_control_local, 'ctl', None)


def check_scan_control():
    """For long loops inside a scan (the NVD lookups): raises ScanStopped when this thread's scan was cancelled or is out of time."""
    ctl = current_control()
    if ctl is not None:
        ctl.check()


def set_scan_progress(**fields):
    """Reports progress of the scan running in THIS thread (does nothing when it has no control: the CLI, the tests)."""
    ctl = current_control()
    if ctl is not None:
        ctl.set_progress(**fields)


class ControlledScanner(_RealPortScanner):
    """python-nmap's PortScanner whose scan() can be cancelled or stopped at a deadline (see the section header). Same command line, same
    handling of nmap's stderr, same XML analysis; with no control set it behaves like the stock scan()."""

    def _command(self, hosts, ports, arguments, sudo):
        args = [self._nmap_path, '-oX', '-'] + shlex.split(hosts) + (['-p', ports] if ports is not None else []) + shlex.split(arguments)
        if current_control() is not None:
            # Only asks nmap to REPORT how far a step is (a <taskprogress> element in the XML): it changes nothing a scan finds. Like the
            # -oX - above it is not part of the command the Tasks page shows. A scan without a control (the CLI, the tests) is unchanged.
            args += ['--stats-every', PROGRESS_EVERY]
        return (['sudo'] + args) if sudo else args

    @staticmethod
    def _drain(stream, sink, on_chunk=None):
        """Reads a pipe to its end into `sink`, so output is available (and parsed) while nmap still runs."""
        try:
            while True:
                chunk = stream.read1(65536) if hasattr(stream, 'read1') else stream.read(65536)
                if not chunk:
                    return
                sink.extend(chunk)
                if on_chunk is not None:
                    on_chunk(chunk)
        except (OSError, ValueError):          # the pipe was closed under us (nmap was killed)
            return

    @staticmethod
    def _wait(proc, ctl, timeout):
        """Waits for nmap in one-second slices, so a cancel or a deadline is noticed within a second, while two reader threads drain stdout
        and stderr (communicate() would hold everything back until nmap exits). Returns (stdout bytes, stderr bytes) like communicate()."""
        out, err = bytearray(), bytearray()
        tail = [b'']

        def feed(chunk):
            # the newest progress report in what arrived; `tail` keeps what followed the last complete tag, so a tag split between two reads
            # is found, and an old tag is never reported twice (that would make a stale report look fresh)
            data = tail[0] + chunk
            found, end = _find_task_progress(data)
            tail[0] = data[end:][-512:] if found else data[-512:]
            if found is not None and ctl is not None:
                found['kind'] = 'nmap'
                ctl.set_progress(**found)

        readers = [threading.Thread(target=ControlledScanner._drain, args=(proc.stdout, out, feed), daemon=True),
                   threading.Thread(target=ControlledScanner._drain, args=(proc.stderr, err), daemon=True)]
        try:
            proc.stdin.close()                 # nmap reads no input; communicate() used to close this
        except Exception:
            pass
        for r in readers:
            r.start()
        started = time.monotonic()
        while True:
            try:
                proc.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass
            stop = None
            if ctl is not None:
                try:
                    ctl.check()
                except ScanStopped as e:
                    stop = e
            if stop is None and timeout and time.monotonic() - started >= timeout:
                stop = PortScannerTimeout('Timeout from nmap process')
            if stop is not None:
                kill_process_tree(proc)
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                for r in readers:
                    r.join(2)
                raise stop
        for r in readers:                      # nmap has exited and its pipes close with it; a stray child holding one must not hang us
            r.join(3)
        return bytes(out), bytes(err)

    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False, timeout=0):
        assert isinstance(hosts, str) and isinstance(arguments, str) and (ports is None or isinstance(ports, str)), 'hosts, ports and arguments must be text'
        ctl = current_control()
        if ctl is not None:
            ctl.check()
        proc = subprocess.Popen(self._command(hosts, ports, arguments, sudo), bufsize=100000,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if ctl is not None:
            ctl.attach(proc)
        try:
            out, err = self._wait(proc, ctl, timeout)
        finally:
            if ctl is not None:
                ctl.detach()
        if ctl is not None:
            ctl.raise_if_cancelled()          # cancel() killed nmap: what it printed is half a document, never analyse it
        self._nmap_last_output = out

        nmap_err = bytes.decode(err)
        nmap_err_keep_trace = []
        nmap_warn_keep_trace = []
        if len(nmap_err) > 0:                 # as python-nmap does: "Warning: ..." lines are kept apart from real errors
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    if regex_warning.search(line) is not None:
                        nmap_warn_keep_trace.append(line + os.linesep)
                    else:
                        nmap_err_keep_trace.append(nmap_err)
        return self.analyse_nmap_xml_scan(nmap_xml_output=self._nmap_last_output, nmap_err=nmap_err,
                                          nmap_err_keep_trace=nmap_err_keep_trace, nmap_warn_keep_trace=nmap_warn_keep_trace)


def new_scanner():
    """The scanner object a scan runs on: a ControlledScanner, unless nmap.PortScanner was replaced (the test files and the test copy put a
    fake there, before or after this module is imported), in which case that replacement is used, so every existing fake keeps working."""
    cls = nmap.PortScanner
    return ControlledScanner() if cls is _RealPortScanner else cls()


# ---- Custom scan arguments (2026-11-08) -------------------------------------------------------------------------------------
# The server runs as Administrator, so the text a person types for a Custom scan must never reach nmap as anything but the listed
# flags and their checked values. The first version looked at "--top-ports=..." as ONE flag and never looked at its value, and the
# checked text was joined with spaces and split again by python-nmap, so  --top-ports="1 --script=exploit"  became two options, and a
# bare word after a flag with no value (-sS localhost) became an extra TARGET that skipped every target check. Now:
#   * the raw text may hold only letters, digits, spaces and  , : = _ -  (no quote, backslash, slash, dot, dollar, newline ...),
#     so no token can hold whitespace or be re-split, and the checked tokens are exactly what nmap receives;
#   * every token is a listed flag or the value of the flag before it; a flag that takes no value is never followed by a word;
#   * each value has its own range (-p ports 1-65535, --top-ports 1-1000, --version-intensity 0-9).
# test_custom_args.py protects all of it (a list of refused texts, 60,000 random ones, and the round trip through shlex).
CUSTOM_ARGS_MAX_CHARS = 500          # the same as the database column that keeps them
CUSTOM_ARGS_MAX_TOKENS = 40
CUSTOM_TOP_PORTS_MAX = 1000
_CUSTOM_ARGS_CHARS = re.compile(r'[A-Za-z0-9 ,:=_-]+')
_PORT_ITEM = re.compile(r'(?:[TU]:)?(?:([0-9]{1,5})(?:-([0-9]{1,5}))?|[A-Za-z][A-Za-z0-9_-]{0,31})')
_UINT = re.compile(r'[0-9]{1,5}')


def _custom_port_list(value):
    """-p value: ports and ranges 1-65535 (80,443,1-1024), an optional T: / U: in front of an item, or a service name (http)."""
    if len(value) > 200:
        return 'the port list is too long'
    for item in value.split(','):
        m = _PORT_ITEM.fullmatch(item)
        if not m:
            return 'expected ports such as 80,443 or 1-1024'
        if m.group(1) is not None:
            low = int(m.group(1))
            high = int(m.group(2)) if m.group(2) is not None else low
            if not (1 <= low <= 65535 and 1 <= high <= 65535) or low > high:
                return 'ports must be 1-65535 and a range must go upwards'
    return None


def _custom_top_ports(value):
    if not _UINT.fullmatch(value) or not 1 <= int(value) <= CUSTOM_TOP_PORTS_MAX:
        return 'expected a number from 1 to %d' % CUSTOM_TOP_PORTS_MAX
    return None


def _custom_intensity(value):
    if not _UINT.fullmatch(value) or int(value) > 9:
        return 'expected a number from 0 to 9'
    return None


# flags that take no value, and flags that take one (with the check of that value)
CUSTOM_FLAGS_PLAIN = frozenset({
    '-sV', '-sS', '-sT', '-sU', '-sN', '-sF', '-sX',      # scan types (-sN / -sF / -sX never report "open": see CLAUDE.md)
    '-sC',                                                # default scripts
    '-F',                                                 # fast scan (100 ports)
    '-T0', '-T1', '-T2', '-T3', '-T4',                    # timing (T5 is not allowed)
    '--open',                                             # show open ports only
    '-O',                                                 # OS detection
    '-Pn',                                                # treat every host as online (limited by pn_limit_error)
})
CUSTOM_FLAGS_VALUE = {
    '-p': _custom_port_list,
    '--top-ports': _custom_top_ports,
    '--version-intensity': _custom_intensity,
}
ALLOWED_FLAGS = CUSTOM_FLAGS_PLAIN | frozenset(CUSTOM_FLAGS_VALUE)


def validate_custom_args(text):
    """Check the arguments typed for a Custom scan. Returns (tokens, None) when every token is a listed flag or the checked value of
    one, else (None, reason). The tokens joined with single spaces are what nmap receives, and splitting that text again gives the
    same tokens back (checked here, so nothing can slip in between the check and the command)."""
    if not isinstance(text, str) or not text.strip():
        return None, 'No arguments given.'
    if len(text) > CUSTOM_ARGS_MAX_CHARS:
        return None, 'Arguments are too long (at most %d characters).' % CUSTOM_ARGS_MAX_CHARS
    if not _CUSTOM_ARGS_CHARS.fullmatch(text):
        return None, 'Arguments may only contain letters, digits, spaces and , : = _ - (quotes, slashes and other symbols are not accepted).'
    words = text.split()
    if len(words) > CUSTOM_ARGS_MAX_TOKENS:
        return None, 'Too many arguments (at most %d).' % CUSTOM_ARGS_MAX_TOKENS
    tokens = []
    i = 0
    while i < len(words):
        word = words[i]
        i += 1
        if not word.startswith('-'):
            return None, 'Unexpected word: %s. Every argument must be a listed flag starting with - (a flag that takes a value is followed by it).' % word[:40]
        flag, equals, inline = word.partition('=')
        if flag not in ALLOWED_FLAGS:
            return None, 'Flag not allowed: %s. Allowed flags: %s' % (flag[:40], ', '.join(sorted(ALLOWED_FLAGS)))
        if flag in CUSTOM_FLAGS_PLAIN:
            if equals:
                return None, '%s does not take a value.' % flag
            tokens.append(word)
            continue
        if equals:
            if flag == '-p':
                return None, '-p takes its value as a separate word, for example -p 80,443.'
            value = inline
            tokens.append(word)
        else:
            if i >= len(words) or words[i].startswith('-'):
                return None, '%s needs a value.' % flag
            value = words[i]
            i += 1
            tokens.extend([word, value])
        problem = CUSTOM_FLAGS_VALUE[flag](value)
        if problem:
            return None, 'Invalid value for %s: %s.' % (flag, problem)
    try:
        again = shlex.split(' '.join(tokens))
    except ValueError:
        again = None
    if again != tokens:
        return None, 'Arguments could not be checked safely.'
    return tokens, None


def _is_ipv4(value):
    try:
        return ipaddress.ip_address(str(value or '').strip()).version == 4
    except ValueError:
        return False


def _nm_host_has_evidence(host):
    """host_has_evidence() for a live python-nmap host object (used before finish_scan has built the stored records): a MAC nmap read, or a port that answered."""
    try:
        if _normalize_mac(host['addresses'].get('mac')):
            return True
        return any(str(d.get('state') or '').lower() in HOST_EVIDENCE_STATES for proto in host.all_protocols() for d in host[proto].values())
    except Exception:
        return False


def _port_entry(port, proto, port_data):
    """One stored port record from a python-nmap port dict (the same shape every scan type stores)."""
    full_version = f"{port_data.get('product', '')} {port_data.get('version', '')} {port_data.get('extrainfo', '')}".strip() or "Unknown Version"
    entry = {'port': port, 'protocol': proto, 'state': port_data.get('state'), 'name': port_data.get('name'), 'version_info': full_version}
    _keep_reason(entry, port_data)
    return entry


def run_udp_pass(ips, t=None, no_dns=False, gentle=False, info=None):
    """The second nmap run of the UDP option, on the IPv4 addresses the first run found up. Returns
    {'ports': {ip: [(port, python-nmap port dict), ...]}, 'timedout': {ip, ...}, 'failed': bool}. Records udp_hosts / udp_timed_out / udp_failed in `info`.
    A run that fails (nmap refused, a crash) is reported as failed and leaves the first run's result alone; a cancel or the time limit (ScanStopped) is NOT
    swallowed, it stops the whole scan like anywhere else."""
    info = info if info is not None else {}
    out = {'ports': {}, 'timedout': set(), 'failed': False}
    ips = [ip for ip in ips if _is_ipv4(ip)]
    info['udp_hosts'] = len(ips)
    if not ips:
        return out
    check_scan_control()
    try:
        nm = new_scanner()
        nm.scan(hosts=' '.join(ips), arguments=udp_arguments(t, no_dns, gentle))
        try:
            problem = (nm.scaninfo() or {}).get('error')      # python-nmap parks nmap's stderr text here and raises only when the XML is unreadable
        except Exception:
            problem = None
        if problem:
            raise RuntimeError(' '.join(str(x) for x in problem) if isinstance(problem, (list, tuple)) else str(problem))
        try:
            timedout = (parse_run_xml(nm.get_nmap_last_output()) or {}).get('timedout') or set()
        except Exception:
            timedout = set()
        for ip in nm.all_hosts():
            if ip not in ips:
                continue
            host = nm[ip]
            out['ports'][ip] = [(port, host['udp'][port]) for port in host['udp'].keys()] if 'udp' in host.all_protocols() else []
        out['timedout'] = {ip for ip in timedout if ip in ips}
    except ScanStopped:
        raise
    except Exception as e:
        out = {'ports': {}, 'timedout': set(), 'failed': True}
        info['udp_failed'] = True
        info['udp_error'] = _clip(str(e), 200)      # why, so a failed run is not a mystery
    if out['timedout']:
        info['udp_timed_out'] = len(out['timedout'])
    return out


def add_udp_ports(results, t=None, no_dns=False, gentle=False, info=None):
    """Runs the UDP pass on the hosts of a finished host list (those with a port list that the first run did not give up on) and appends the UDP ports to each host's
    `ports`, after its TCP ports. A host whose UDP run ran out of time gets `udp_timed_out`, and every host the pass was meant for gets `udp_failed` when the
    run failed: both are separate from the TCP `timed_out`. Returns the same list."""
    wanted = [h for h in results if isinstance(h, dict) and isinstance(h.get('ports'), list) and not h.get('timed_out')]
    hosts = [h for h in wanted if _is_ipv4(h.get('ip'))]
    got = run_udp_pass([h['ip'] for h in hosts], t, no_dns, gentle, info)
    not_scanned = 0
    for h in wanted:
        if h not in hosts or (not got['failed'] and h['ip'] not in got['ports'] and h['ip'] not in got['timedout']):
            h['udp_not_scanned'] = True      # an IPv6 host, or one nmap did not report: no UDP result is not "no UDP port"
            not_scanned += 1
    if not_scanned:
        info['udp_not_scanned'] = not_scanned
    for h in hosts:
        for port, data in got['ports'].get(h['ip'], []):
            h['ports'].append(_port_entry(port, 'udp', data))
        if h['ip'] in got['timedout']:
            h['udp_timed_out'] = True
        if got['failed']:
            h['udp_failed'] = True
    return results


def run_network_scan(target_ip, scan_type='discovery', custom_args=None, timing=None, version_intensity=None, multicast=False,
                     skip_ping=False, info=None, all_ports=False, no_dns=False, host_probes=False, gentle=False, udp=False):
    if not is_valid_target(target_ip):
        return json.dumps([{"error": "Invalid target specified."}])

    nm = new_scanner()
    scan_results = []
    t, vi = clamp_scan_knobs(timing, version_intensity)
    info = info if info is not None else {}      # filled with what nmap reported about the run; the caller stores it (ScanJob.scan_info)
    note_capabilities(info)
    facts = {}
    skip_ping = bool(skip_ping) and scan_type in ('fast_scan', 'intense')      # Discovery cannot use it, Custom reads -Pn from its own arguments
    if skip_ping and pn_limit_error(target_ip):
        return pn_limit_error(target_ip)
    all_ports = bool(all_ports) and scan_type in ('fast_scan', 'intense')      # the other types look at no ports or name their own
    no_dns = bool(no_dns) and scan_type in ('discovery', 'fast_scan', 'intense')      # a Custom scan names its own flags
    if no_dns:
        info['no_dns'] = True      # so a missing hostname is not read as "this device has no name"
    host_probes = bool(host_probes) and scan_type in ('discovery', 'fast_scan', 'intense')
    gentle = bool(gentle) and scan_type in ('fast_scan', 'intense')
    if options_conflict(skip_ping, all_ports, host_probes, gentle):
        return json.dumps([{"error": options_conflict(skip_ping, all_ports, host_probes, gentle)}])
    if gentle and gentle_limit_error(target_ip):
        return gentle_limit_error(target_ip)
    udp = bool(udp) and scan_type == 'intense'      # Fast is meant to be quick, Discovery looks at no ports, Custom names its own flags
    if udp and udp_unavailable():
        return json.dumps([{"error": udp_unavailable()}])
    if udp and udp_limit_error(target_ip):
        return udp_limit_error(target_ip)
    if host_probes:
        info['host_probes'] = True
    if gentle:
        info['gentle'] = True
    if udp:
        info['udp'] = True
    if all_ports and ports_limit_error(target_ip):
        return ports_limit_error(target_ip)

    try:
        if scan_type == 'discovery':
            # Optional (multicast=True, off by default): mDNS/SSDP listening runs alongside the ping sweep,
            # so it adds no waiting time of its own
            mc_pool = mc_future = None
            if multicast:
                mc_pool = ThreadPoolExecutor(max_workers=1)
                mc_future = mc_pool.submit(discover_multicast_services, target_ip)
            nm.scan(hosts=target_ip, arguments=scan_arguments('discovery', t, vi, False, False, no_dns, host_probes))
            facts = capture_run(nm, info)

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                    mac_vendor = nm[host].get('vendor', {}).get(mac_address, '') or lookup_mac_vendor(mac_address)
                    scan_results.append({
                        'ip': host,
                        'status': 'up',
                        'mac': mac_address,
                        'mac_vendor': mac_vendor
                    })

            # Check if local default gateway was missed because it drops ICMP ping
            sys_gw = get_system_default_gateway()
            if sys_gw and sys_gw.get('ip'):
                gw_ip = sys_gw['ip']
                found_ips = {r['ip'] for r in scan_results}
                if gw_ip not in found_ips:
                    in_target = False
                    try:
                        import ipaddress
                        if '/' in target_ip:
                            in_target = ipaddress.ip_address(gw_ip) in ipaddress.ip_network(target_ip, strict=False)
                        elif '-' in target_ip:
                            base = target_ip.split('-')[0].rsplit('.', 1)[0]
                            in_target = gw_ip.startswith(base + '.')
                        elif target_ip == gw_ip:
                            in_target = True
                    except Exception:
                        pass

                    if in_target:
                        try:
                            gw_nm = new_scanner()
                            gw_nm.scan(hosts=gw_ip, arguments='-Pn -p 53,80,443,8080 --open' + (' -n' if no_dns else ''))
                            if gw_ip in gw_nm.all_hosts() and gw_nm[gw_ip].state() == 'up':
                                mac_addr = gw_nm[gw_ip]['addresses'].get('mac', sys_gw.get('mac') or 'Unknown')
                                mac_vndr = gw_nm[gw_ip].get('vendor', {}).get(mac_addr) or sys_gw.get('mac_vendor') or lookup_mac_vendor(mac_addr)
                                scan_results.append({
                                    'ip': gw_ip,
                                    'status': 'up',
                                    'mac': mac_addr,
                                    'mac_vendor': mac_vndr,
                                    'stealth_gateway': True
                                })
                        except Exception:
                            pass

            # Names/services from multicast; also catches hosts that dropped the ping sweep
            if mc_future is not None:
                try:
                    merge_discovery(scan_results, mc_future.result(timeout=10), target_ip)
                except Exception:
                    pass
                mc_pool.shutdown(wait=False)
        elif scan_type == 'fast_scan':
            # ใช้ -sV เพื่อดึงเวอร์ชันของ Service และ -O ตรวจ OS
            nm.scan(hosts=target_ip, arguments=scan_arguments('fast_scan', t, vi, skip_ping, all_ports, no_dns, host_probes, gentle))
            facts = capture_run(nm, info)

            for host in nm.all_hosts():
                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]

                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')

                            full_version = f"{product} {version} {extrainfo}".strip()
                            if not full_version:
                                full_version = "Unknown Version"

                            entry = {
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            }
                            _keep_reason(entry, port_data)
                            ports.append(entry)

                os_info = 'Unknown'
                os_accuracy = None
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']
                    os_accuracy = os_match_accuracy(nm[host]['osmatch'][0].get('accuracy'))

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '') or lookup_mac_vendor(mac_address)

                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'os_accuracy': os_accuracy,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports
                })

        elif scan_type == 'intense':
            # Intense Scan: -T4 -A -v (OS, version, script, traceroute, aggressive timing)
            nm.scan(hosts=target_ip, arguments=scan_arguments('intense', t, vi, skip_ping, all_ports, no_dns, host_probes, gentle))
            facts = capture_run(nm, info)

            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue
                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]

                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')

                            full_version = f"{product} {version} {extrainfo}".strip()
                            if not full_version:
                                full_version = "Unknown Version"

                            entry = {
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            }
                            _keep_reason(entry, port_data)
                            ports.append(entry)

                os_info = 'Unknown'
                os_accuracy = None
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']
                    os_accuracy = os_match_accuracy(nm[host]['osmatch'][0].get('accuracy'))

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '') or lookup_mac_vendor(mac_address)

                trace_hops = []
                if 'trace' in nm[host] and 'hops' in nm[host]['trace']:
                    trace_hops = nm[host]['trace']['hops']
                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'os_accuracy': os_accuracy,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports,
                    'trace_hops': trace_hops
                })

        elif scan_type == 'custom' and custom_args:
            # Custom nmap arguments typed by the user: only listed flags with checked values (see validate_custom_args above)
            validated_tokens, args_error = validate_custom_args(custom_args)
            if args_error:
                return json.dumps([{"error": args_error}])

            safe_args = ' '.join(validated_tokens)
            skip_ping = '-Pn' in validated_tokens
            if skip_ping and pn_limit_error(target_ip):
                return pn_limit_error(target_ip)
            nm.scan(hosts=target_ip, arguments=safe_args)
            facts = capture_run(nm, info)

            for host in nm.all_hosts():
                # แสดงเฉพาะ host ที่ state == 'up' เท่านั้น
                if nm[host].state() != 'up':
                    continue

                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')
                            full_version = f"{product} {version} {extrainfo}".strip() or "Unknown Version"
                            entry = {
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            }
                            _keep_reason(entry, port_data)
                            ports.append(entry)

                os_info = 'Unknown'
                os_accuracy = None
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']
                    os_accuracy = os_match_accuracy(nm[host]['osmatch'][0].get('accuracy'))

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '') or lookup_mac_vendor(mac_address)

                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'os_accuracy': os_accuracy,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports,
                    'custom_args': safe_args
                })

        scan_results = finish_scan(scan_results, facts, info, skip_ping, target_ip, all_ports)
        if udp and scan_results:
            scan_results = add_udp_ports(scan_results, t, no_dns, gentle, info)      # after finish_scan: only hosts that really answered, and its -Pn filter has run
        if not scan_results:
            if skip_ping and info.get('no_evidence'):
                return json.dumps([{"error": PN_NOTHING_ANSWERED}])
            return json.dumps([{"error": "Scan completed but no hosts found. The target may be offline, or the arguments may not have produced results (e.g. missing -sn for discovery or -p for port scan)."}])

        return json.dumps(fill_hostnames(fill_ipv6_from_neighbors(fill_missing_macs_from_arp(annotate_local_hosts(scan_results))), use_dns=False)
                          if no_dns else fill_hostnames(fill_ipv6_from_neighbors(fill_missing_macs_from_arp(annotate_local_hosts(scan_results)))))

    except Exception as e:
        return json.dumps([{"error": str(e)}])


# CVSS v3 and later call 9.0-10.0 "Critical". CVSS v2 has no such band (7.0-10.0 is all "High"), and NVD only ever scored
# older CVEs (roughly before 2016) with v2, so for those NVD's own label comes back as HIGH even at a score of 10.0.
CVSS_CRITICAL_FROM = 9.0


def cvss_number(value):
    """A CVSS base score as a float, or None when value is not a score between 0 and 10 (None, text, a bool, NaN ...)."""
    if isinstance(value, bool):
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= 10 else None      # every comparison with NaN is False, so NaN ends up here too


def _stored_severity(cve):
    """The label NVD gave a stored CVE record, upper-cased; '' when it has none (or the record is not a dict)."""
    return str(cve.get('severity') or '').strip().upper() if isinstance(cve, dict) else ''


def effective_severity(cve):
    """The severity label to show for a stored CVE record: NVD's own label, except that HIGH with a score of 9.0 or more
    becomes CRITICAL. NVD gives that combination only to CVEs it scored with CVSS v2 alone (v3 would have said CRITICAL),
    and everyone reads 9.0-10.0 as Critical. The stored record keeps NVD's label, so everything that shows or counts a
    CVE's severity has to go through here. '' when the record has no label."""
    stored = _stored_severity(cve)
    score = cvss_number(cve.get('cvss_score')) if isinstance(cve, dict) else None
    if stored == 'HIGH' and score is not None and score >= CVSS_CRITICAL_FROM:
        return 'CRITICAL'
    return stored


def severity_adjusted(cve):
    """True when effective_severity() shows a different label from the one NVD gave."""
    return effective_severity(cve) != _stored_severity(cve)


def severity_note(score):
    """Thai tooltip for a label that effective_severity() raised from NVD's HIGH to CRITICAL."""
    n = cvss_number(score)
    shown = f'{n:.1f}' if n is not None else ''
    return f'NVD ให้ระดับ High (CVSS v2 ไม่มีระดับ Critical) แต่คะแนน {shown} อยู่ในช่วง Critical (9.0–10.0)'


# ---- the extra facts about a CVE that the device page shows under "รายละเอียดเพิ่มเติม". NVD sends all of it in the SAME answer we already read.
# Every value is checked against what NVD documents (a date, one of the fixed CVSS words, an http(s) address) and anything else is left out, so
# a missing key means "NVD did not say", never a guess. The top-level `description` of a CVE keeps its first 300 characters (older pages show that
# as it is); the full text, up to NVD_DESC_FULL, goes in detail['full'] when it is longer.
NVD_DESC_FULL = 1000
NVD_REFS_MAX = 8
NVD_AFFECTED_MAX = 12
NVD_REF_FIRST = ('Exploit', 'Patch', 'Mitigation', 'Vendor Advisory', 'Third Party Advisory')      # NVD's own reference tags, shown first
_NVD_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}$')
_NVD_VECTOR = re.compile(r'^[A-Za-z0-9:/.]{1,120}$')
_NVD_URL = re.compile(r'^https?://[^\s<>"\'\\]{1,290}$')
# the fixed words of CVSS v3 (version '3') and v2 (version '2'): field key -> (key in NVD's cvssData, the values NVD can send)
_NVD_ATTACK = {
    '3': (('av', 'attackVector', ('NETWORK', 'ADJACENT_NETWORK', 'LOCAL', 'PHYSICAL')), ('ac', 'attackComplexity', ('LOW', 'HIGH')),
          ('pr', 'privilegesRequired', ('NONE', 'LOW', 'HIGH')), ('ui', 'userInteraction', ('NONE', 'REQUIRED'))),
    '2': (('av', 'accessVector', ('NETWORK', 'ADJACENT_NETWORK', 'LOCAL')), ('ac', 'accessComplexity', ('LOW', 'MEDIUM', 'HIGH')),
          ('au', 'authentication', ('NONE', 'SINGLE', 'MULTIPLE'))),
}


def _nvd_date(value):
    v = str(value or '')[:10]
    return v if _NVD_DATE.match(v) else ''


def _cpe_parts(criteria):
    """(part, vendor, product, version) of a CPE 2.3 name (`cpe:2.3:a:vendor:product:version:...`; a colon inside a value is written `\\:`), or None."""
    parts = re.split(r'(?<!\\):', str(criteria or ''))
    if len(parts) < 6 or parts[0] != 'cpe' or parts[1] != '2.3' or parts[2] not in ('a', 'o', 'h'):
        return None
    clean = lambda x: _clip(re.sub(r'\\(.)', r'\1', x), 60)
    ver = clean(parts[5])
    return parts[2], clean(parts[3]), clean(parts[4]), '' if ver in ('*', '-') else ver


def nvd_detail(cve_item, metric=None, description=''):
    """The extra facts about one CVE from NVD's answer (see the comment above). `metric` is (key, metric dict) of the CVSS block the score came
    from, so the way it is attacked agrees with the score that is shown. Never raises on odd shapes: a part NVD shaped oddly is just left out."""
    d = {}
    for key, name in (('published', 'published'), ('modified', 'lastModified')):
        v = _nvd_date(cve_item.get(name))
        if v:
            d[key] = v
    status = str(cve_item.get('vulnStatus') or '')
    if re.fullmatch(r'[A-Za-z ]{1,40}', status):
        d['status'] = status

    # how it is attacked: from the same CVSS block that gave the score
    if metric:
        mkey, m = metric
        data = m.get('cvssData') or {}
        ver = '2' if mkey == 'cvssMetricV2' else '3'
        attack = {}
        for short, field, allowed in _NVD_ATTACK[ver]:
            v = str(data.get(field) or '').upper()
            if v in allowed:
                attack[short] = v
        if attack:
            d['attack'] = attack
        d['cvss_version'] = ver
        vec = str(data.get('vectorString') or '')
        if _NVD_VECTOR.match(vec):
            d['vector'] = vec

    # links, NVD's own tags (Exploit, Patch, ...), the useful ones first; the same address is listed once
    refs, seen = [], {}
    for r in cve_item.get('references') or []:
        if not isinstance(r, dict):
            continue
        url = str(r.get('url') or '').strip()
        if not _NVD_URL.match(url):
            continue
        tags = [t for t in (r.get('tags') or []) if isinstance(t, str) and re.fullmatch(r'[A-Za-z /-]{1,30}', t)]
        if url in seen:
            seen[url]['t'] += [t for t in tags if t not in seen[url]['t']]
            continue
        seen[url] = {'u': url, 't': tags}
        refs.append(seen[url])
    first = lambda r: min([NVD_REF_FIRST.index(t) for t in r['t'] if t in NVD_REF_FIRST] or [len(NVD_REF_FIRST)])
    d['refs_total'] = len(refs)
    d['refs'] = sorted(refs, key=first)[:NVD_REFS_MAX]                    # sorted() is stable: NVD's order is kept inside a group

    # which products and versions NVD says are affected (only the entries marked vulnerable, not the "running on" conditions)
    affected, seen_a = [], set()
    for cfg in cve_item.get('configurations') or []:
        for node in (cfg.get('nodes') or []) if isinstance(cfg, dict) else []:
            for match in (node.get('cpeMatch') or []) if isinstance(node, dict) else []:
                if not isinstance(match, dict) or match.get('vulnerable') is not True:
                    continue
                cpe = _cpe_parts(match.get('criteria'))
                if not cpe:
                    continue
                row = {'k': cpe[0], 'v': cpe[1], 'p': cpe[2]}
                if cpe[3]:
                    row['ver'] = cpe[3]
                for short, name in (('si', 'versionStartIncluding'), ('se', 'versionStartExcluding'), ('ei', 'versionEndIncluding'), ('ee', 'versionEndExcluding')):
                    v = _clip(match.get(name) or '', 40)
                    if v:
                        row[short] = v
                ident = tuple(sorted(row.items()))
                if ident not in seen_a:
                    seen_a.add(ident)
                    affected.append(row)
    d['affected_total'] = len(affected)
    d['affected'] = affected[:NVD_AFFECTED_MAX]

    # CISA's own words for a known-exploited CVE
    if cve_item.get('cisaExploitAdd'):
        k = {}
        due = _nvd_date(cve_item.get('cisaActionDue'))
        if due:
            k['due'] = due
        for key, name, n in (('action', 'cisaRequiredAction', 300), ('name', 'cisaVulnerabilityName', 150)):
            v = _clip(cve_item.get(name) or '', n)
            if v:
                k[key] = v
        if k:
            d['kev'] = k

    # the whole description, when the first 300 characters (what `description` keeps) are not all of it
    text = ' '.join(str(description or '').split())
    if text != ' '.join(str(description or '')[:300].split()):
        d['full'] = text[:NVD_DESC_FULL]
    d['desc_cut'] = len(text) > NVD_DESC_FULL
    return d


def lookup_cves_nvd_status(product, version, max_results=5):
    """Query the NVD API for CVEs matching a product/version string. Returns (cves, status):
    'ok'         the answer came and was read; `cves` may be empty (NVD knows no CVE for that text)
    'failed'     the lookup did not work (network, rate limit, an unreadable answer): the empty list says NOTHING about the service
    'no_product' nmap named no product, so there was nothing to search and no request was made
    "Nothing found" and "could not look" used to look the same, so a failed lookup showed up as a clean service."""
    import urllib.request
    import urllib.parse

    NVD_API_KEY = "b92e0f90-6616-404b-a76e-14e29597d524"

    if not product or product.strip() == '':
        return [], 'no_product'

    keyword = f"{product} {version}".strip()
    params = urllib.parse.urlencode({
        'keywordSearch': keyword,
        'resultsPerPage': max_results,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"

    try:
        req = urllib.request.Request(url, headers={
            'apiKey': NVD_API_KEY,
            'User-Agent': 'NetworkScanner/1.0'
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_item = vuln.get('cve', {})
            cve_id = cve_item.get('id', '')
            # Description (English preferred)
            descs = cve_item.get('descriptions', [])
            description = next((d['value'] for d in descs if d.get('lang') == 'en'), '')

            # CVSS score and severity (try v31, then v30, then v2)
            metrics = cve_item.get('metrics', {})
            cvss_score = None
            severity = 'UNKNOWN'
            chosen = None
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = m.get('baseSeverity', cvss_data.get('baseSeverity', 'UNKNOWN'))
                    chosen = (key, m)
                    break

            # CWE name from weaknesses (ชื่อหมวดหมู่ช่องโหว่)
            cwe_id = cwe_name = None
            for w in cve_item.get('weaknesses', []):
                for desc in w.get('description', []):
                    value = desc.get('value', '')
                    if value in CWE_SHORT_NAMES:
                        cwe_id, cwe_name = value, CWE_SHORT_NAMES[value]
                        break
                    elif value.startswith('CWE-'):
                        cwe_id, cwe_name = value, value  # fallback: show CWE ID itself
                        break
                if cwe_name:
                    break

            entry = {
                'cve_id': cve_id,
                'description': description[:300] if description else '',
                'cvss_score': cvss_score,
                'severity': severity.upper() if severity else 'UNKNOWN',
                'cwe_name': cwe_name or '',
                'cwe_id': cwe_id or '',
                # CISA's Known Exploited Vulnerabilities catalog, as NVD reports it (`cisaExploitAdd` = the date CISA listed it). NVD's
                # answer is the whole truth at lookup time, so False is stored too; a record from before this field has no `kev` key.
                'kev': bool(cve_item.get('cisaExploitAdd')),
            }
            if entry['kev']:
                entry['kev_added'] = str(cve_item.get('cisaExploitAdd'))[:10]
            try:
                entry['detail'] = nvd_detail(cve_item, chosen, description)
            except Exception:
                pass                                    # the extra facts are a bonus: if NVD shaped something oddly the CVE still keeps everything it had before
            cves.append(entry)
        return cves, 'ok'
    except Exception:
        return [], 'failed'


def lookup_cves_nvd(product, version, max_results=5):
    """The CVEs only (lookup_cves_nvd_status() also says whether the lookup worked)."""
    return lookup_cves_nvd_status(product, version, max_results)[0]


def run_vuln_scan(target_ip, timing=None, version_intensity=None, skip_ping=False, info=None, all_ports=False, no_dns=False, host_probes=False, gentle=False, udp=False):
    """
    Vulnerability Scan: nmap -sV -O to detect services + OS, then query NVD API for CVEs.
    Returns same structure as other scans but each port has a 'cves' list.
    """
    if not is_valid_target(target_ip):
        return json.dumps([{"error": "Invalid target specified."}])

    nm = new_scanner()
    scan_results = []
    t, vi = clamp_scan_knobs(timing, version_intensity)
    info = info if info is not None else {}      # see run_network_scan
    note_capabilities(info)
    skip_ping = bool(skip_ping)
    if skip_ping and pn_limit_error(target_ip):
        return pn_limit_error(target_ip)
    all_ports = bool(all_ports)
    if all_ports and ports_limit_error(target_ip):
        return ports_limit_error(target_ip)
    no_dns = bool(no_dns)
    if no_dns:
        info['no_dns'] = True
    host_probes, gentle = bool(host_probes), bool(gentle)
    if options_conflict(skip_ping, all_ports, host_probes, gentle):
        return json.dumps([{"error": options_conflict(skip_ping, all_ports, host_probes, gentle)}])
    if gentle and gentle_limit_error(target_ip):
        return gentle_limit_error(target_ip)
    udp = bool(udp)
    if udp and udp_unavailable():
        return json.dumps([{"error": udp_unavailable()}])
    if udp and udp_limit_error(target_ip):
        return udp_limit_error(target_ip)
    if host_probes:
        info['host_probes'] = True
    if gentle:
        info['gentle'] = True
    if udp:
        info['udp'] = True

    try:
        nm.scan(hosts=target_ip, arguments=scan_arguments('vuln_scan', t, vi, skip_ping, all_ports, no_dns, host_probes, gentle))
        facts = capture_run(nm, info)

        # The UDP option: a second nmap run on the hosts the first one found up (before the NVD loop, which then looks at the UDP ports it found as well). Under -Pn
        # nmap calls every address up, so only the hosts something answered for are tried, like finish_scan() keeps only those.
        udp_ports, udp_timedout, udp_failed, gave_up, udp_skipped = {}, set(), False, set(), 0
        if udp:
            gave_up = facts.get('timedout') or set()
            got = run_udp_pass([h for h in nm.all_hosts() if nm[h].state() == 'up' and h not in gave_up and (not skip_ping or _nm_host_has_evidence(nm[h]))],
                               t, no_dns, gentle, info)
            udp_ports, udp_timedout, udp_failed = got['ports'], got['timedout'], got['failed']

        # How many open ports the NVD lookups below will ask about: an exact count (the lookups can take minutes), reported as progress.
        try:
            to_look = sum(1 for h in nm.all_hosts() if nm[h].state() == 'up'
                          for proto in nm[h].all_protocols() for d in nm[h][proto].values() if d.get('state') == 'open')
            to_look += sum(1 for h in nm.all_hosts() if nm[h].state() == 'up' for _p, d in udp_ports.get(h, []) if d.get('state') == 'open')
        except Exception:
            to_look = 0
        looked = 0
        nvd_memo = {}        # (product, version) -> (cves, cve_status): one NVD question per distinct service in this scan; a failed answer is asked again
        if to_look:
            set_scan_progress(kind='nvd', done=0, total=to_look)

        for host in nm.all_hosts():
            if nm[host].state() != 'up':
                continue

            ports = []
            items = [(proto, port, nm[host][proto][port]) for proto in nm[host].all_protocols() for port in nm[host][proto].keys()]
            items += [('udp', port, d) for port, d in udp_ports.get(host, [])]
            if items:
                for proto, port, port_data in items:
                    product = port_data.get('product', '')
                    version = port_data.get('version', '')
                    extrainfo = port_data.get('extrainfo', '')
                    full_version = f"{product} {version} {extrainfo}".strip() or "Unknown Version"

                    # Only reachable services can be matched to CVEs. Keep
                    # other Nmap states in the report without CVE lookups.
                    check_scan_control()      # a cancel or the time limit also stops the NVD lookups that follow nmap
                    if port_data.get('state') == 'open':
                        memo_key = (product, version)
                        if memo_key in nvd_memo:
                            cves, cve_status = nvd_memo[memo_key]
                        else:
                            cves, cve_status = lookup_cves_nvd_status(product, version)
                            if cve_status in ('ok', 'no_product'):
                                nvd_memo[memo_key] = (cves, cve_status)
                    else:
                        cves, cve_status = [], None
                    if port_data.get('state') == 'open':
                        looked += 1
                        set_scan_progress(kind='nvd', done=looked, total=max(to_look, looked))

                    entry = {
                        'port': port,
                        'protocol': proto,
                        'state': port_data.get('state'),
                        'name': port_data.get('name'),
                        'version_info': full_version,
                        'cves': cves,
                    }
                    _keep_reason(entry, port_data)
                    if cve_status:      # 'ok' | 'failed' | 'no_product'; only open ports are looked up. Scans from before this field have none (= not recorded)
                        entry['cve_status'] = cve_status
                    ports.append(entry)

            os_info = 'Unknown'
            os_accuracy = None
            if nm[host].get('osmatch'):
                os_info = nm[host]['osmatch'][0]['name']
                os_accuracy = os_match_accuracy(nm[host]['osmatch'][0].get('accuracy'))

            mac_address = nm[host]['addresses'].get('mac', 'Unknown')
            mac_vendor = nm[host].get('vendor', {}).get(mac_address, '') or lookup_mac_vendor(mac_address)

            scan_results.append({
                'ip': host,
                'os': os_info,
                'os_accuracy': os_accuracy,
                'mac': mac_address,
                'mac_vendor': mac_vendor,
                'ports': ports,
            })
            if host in udp_timedout:
                scan_results[-1]['udp_timed_out'] = True
            if udp and not udp_failed and host not in udp_ports and host not in udp_timedout and host not in gave_up:
                scan_results[-1]['udp_not_scanned'] = True      # an IPv6 host, a -Pn address nothing answered for that still got a record, or one nmap did not report
                udp_skipped += 1
            if udp_failed:
                scan_results[-1]['udp_failed'] = True

        scan_results = finish_scan(scan_results, facts, info, skip_ping, target_ip, all_ports)
        if udp_skipped:
            info['udp_not_scanned'] = len([h for h in scan_results if isinstance(h, dict) and h.get('udp_not_scanned')])
        if not scan_results:
            if skip_ping and info.get('no_evidence'):
                return json.dumps([{"error": PN_NOTHING_ANSWERED}])
            return json.dumps([{"error": "No hosts found. The target may be offline or have no open ports."}])

        return json.dumps(fill_hostnames(fill_ipv6_from_neighbors(fill_missing_macs_from_arp(annotate_local_hosts(scan_results))), use_dns=False)
                          if no_dns else fill_hostnames(fill_ipv6_from_neighbors(fill_missing_macs_from_arp(annotate_local_hosts(scan_results)))))

    except Exception as e:
        return json.dumps([{"error": str(e)}])
