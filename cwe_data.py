"""CWE reference data: the official weakness names NVD shows, and helpers that work out what a stored CVE record refers to."""
import json
import os
import re

# Official names, from MITRE's CWE catalog (cwe_names.json: cwec_v4.20, 2026-04-30, every weakness and category in it,
# fetched from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip). They are the same text NVD prints in the "CWE Name"
# column of a CVE's Weakness Enumeration table. To refresh the file, download that zip again and rebuild it.
# 'NVD-CWE-*' are NVD's own two catch-all buckets and are not in the catalog.
_CATALOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cwe_names.json')


def _load_catalog():
    try:
        with open(_CATALOG_FILE, encoding='utf-8') as f:
            return json.load(f)['names']
    except (OSError, ValueError, KeyError):    # missing or damaged file: names degrade to the bare ID
        return {}


CWE_OFFICIAL_NAMES = dict(_load_catalog(), **{'NVD-CWE-Other': 'Other', 'NVD-CWE-noinfo': 'Insufficient Information'})

# The short, hand-written labels the app used before it carried official names. New scans still store one in
# 'cwe_name' (and the chips on the scan report still show it); records saved before 'cwe_id' existed are mapped
# back to their ID through it.
CWE_SHORT_NAMES = {
    'CWE-20':  'Improper Input Validation',
    'CWE-22':  'Path Traversal',
    'CWE-74':  'Injection',
    'CWE-77':  'Command Injection',
    'CWE-78':  'OS Command Injection',
    'CWE-79':  'Cross-Site Scripting (XSS)',
    'CWE-89':  'SQL Injection',
    'CWE-94':  'Code Injection',
    'CWE-119': 'Buffer Overflow',
    'CWE-120': 'Buffer Copy Without Checking Size',
    'CWE-121': 'Stack-Based Buffer Overflow',
    'CWE-122': 'Heap-Based Buffer Overflow',
    'CWE-125': 'Out-of-Bounds Read',
    'CWE-134': 'Format String Vulnerability',
    'CWE-189': 'Numeric Errors',
    'CWE-190': 'Integer Overflow',
    'CWE-191': 'Integer Underflow',
    'CWE-200': 'Information Exposure',
    'CWE-255': 'Credentials Management',
    'CWE-264': 'Permissions & Privileges',
    'CWE-269': 'Improper Privilege Management',
    'CWE-287': 'Improper Authentication',
    'CWE-294': 'Authentication Bypass',
    'CWE-295': 'Certificate Validation',
    'CWE-310': 'Cryptographic Issues',
    'CWE-320': 'Key Management Errors',
    'CWE-326': 'Inadequate Encryption Strength',
    'CWE-327': 'Broken/Risky Crypto',
    'CWE-330': 'Weak Randomness',
    'CWE-352': 'Cross-Site Request Forgery (CSRF)',
    'CWE-362': 'Race Condition',
    'CWE-369': 'Divide By Zero',
    'CWE-400': 'Uncontrolled Resource Consumption',
    'CWE-401': 'Memory Leak',
    'CWE-404': 'Improper Resource Shutdown',
    'CWE-416': 'Use After Free',
    'CWE-434': 'Unrestricted File Upload',
    'CWE-476': 'NULL Pointer Dereference',
    'CWE-502': 'Deserialization of Untrusted Data',
    'CWE-601': 'Open Redirect',
    'CWE-611': 'XML External Entity (XXE)',
    'CWE-668': 'Exposure of Resource',
    'CWE-674': 'Uncontrolled Recursion',
    'CWE-681': 'Incorrect Conversion',
    'CWE-693': 'Protection Mechanism Failure',
    'CWE-732': 'Incorrect Permission Assignment',
    'CWE-755': 'Improper Exception Handling',
    'CWE-787': 'Out-of-Bounds Write',
    'CWE-798': 'Hardcoded Credentials',
    'CWE-824': 'Uninitialized Pointer',
    'CWE-843': 'Type Confusion',
    'CWE-862': 'Missing Authorization',
    'CWE-863': 'Incorrect Authorization',
    'CWE-918': 'Server-Side Request Forgery (SSRF)',
    'CWE-noinfo': 'Unspecified Vulnerability',
    'NVD-CWE-noinfo': 'Unspecified Vulnerability',
    'NVD-CWE-Other': 'Other Vulnerability Type',
}

# Plain-language explanations (in Thai, like the rest of the UI) written for this app, not quoted from NVD,
# of what NVD's two catch-all buckets mean. They start with "หมายเหตุจากแอป" (note from this app).
CWE_NOTES = {
    'NVD-CWE-Other': "หมายเหตุจากแอป: NVD จัดประเภท CVE ตามชุดย่อยของรายการ CWE เท่านั้น NIST จึงจัดช่องโหว่นี้เป็น 'Other' เพราะไม่อยู่ในชุดย่อยดังกล่าว",
    'NVD-CWE-noinfo': "หมายเหตุจากแอป: NIST มีข้อมูลไม่เพียงพอที่จะจัดประเภทช่องโหว่นี้",
}

COMPACT_LIMIT = 40  # characters of an official name shown before the "show more" dots

_NUMBERED = re.compile(r'(?i)cwe-0*(\d+)')
_ALIAS = re.compile(r"\('([^']+)'\)\s*$")     # the "('SQL Injection')" tail many official names end with


def normalize_cwe_id(value):
    """'cwe-078' -> 'CWE-78', 'CWE-noinfo' -> 'NVD-CWE-noinfo'; '' when value is not a CWE ID."""
    v = (value or '').strip()
    if v.lower() in ('cwe-noinfo', 'nvd-cwe-noinfo'):
        return 'NVD-CWE-noinfo'
    if v.lower() == 'nvd-cwe-other':
        return 'NVD-CWE-Other'
    m = _NUMBERED.fullmatch(v)
    return 'CWE-' + m.group(1) if m else ''


_SHORT_TO_ID = {}
for _id, _short in CWE_SHORT_NAMES.items():
    _SHORT_TO_ID.setdefault(_short, normalize_cwe_id(_id))


def cwe_id_of(cve):
    """The CWE ID a stored CVE record refers to. Records saved before 'cwe_id' existed only hold 'cwe_name':
    either the bare ID (an unknown CWE) or one of the old short labels."""
    cid = normalize_cwe_id(cve.get('cwe_id'))
    if cid:
        return cid
    name = (cve.get('cwe_name') or '').strip()
    return normalize_cwe_id(name) or _SHORT_TO_ID.get(name, '')


def cwe_url(cwe_id):
    m = _NUMBERED.fullmatch(cwe_id)
    return f'https://cwe.mitre.org/data/definitions/{m.group(1)}.html' if m else 'https://nvd.nist.gov/vuln/categories'


def compact_name(name):
    """Short form of an official name for tight spaces: the quoted alias it ends with
    ("... ('SQL Injection')" -> "SQL Injection"), else the name cut at a word boundary."""
    m = _ALIAS.search(name)
    if m:
        return m.group(1)
    if len(name) <= COMPACT_LIMIT:
        return name
    cut = name[:COMPACT_LIMIT].rsplit(' ', 1)[0]
    if cut.count('(') > cut.count(')'):          # never stop inside a parenthesis
        cut = cut[:cut.rfind('(')]
    return cut.rstrip(' ,;:-')


def cwe_info(cve):
    """What to show for a CVE record's weakness, or None when it has none.
    {'id', 'name' (official, '' if not in the table), 'compact', 'more' (compact differs from name), 'url', 'label'}"""
    cid = cwe_id_of(cve) if isinstance(cve, dict) else normalize_cwe_id(cve)
    if not cid:
        return None
    name = CWE_OFFICIAL_NAMES.get(cid, '')
    compact = compact_name(name) if name else ''
    return {'id': cid, 'name': name, 'compact': compact, 'more': bool(name) and compact != name,
            'url': cwe_url(cid), 'label': f'{cid} · {name}' if name else cid, 'note': CWE_NOTES.get(cid, '')}
