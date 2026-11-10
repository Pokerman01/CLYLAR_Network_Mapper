"""Voice lab: the sentences the owner reads aloud to measure how well a speech engine writes our commands.

The lab page records each sentence (audio + what the browser's own engine wrote) so the SAME recordings can later be run through other
engines (local Whisper, see docs/voice-reliability-plan.md) and every engine is scored the same way: by what the app itself would do with
the text, which is the only thing that matters ("exact" = the confirmation card would show the right target and scan type).

Pure functions: no Flask, no files, no network (app.py saves the clips). Tested in test_voice_lab.py.
"""
import re
import voice_commands


def _scan(pid, lang, text, target, scan_type):
    return {'id': pid, 'lang': lang, 'text': text, 'expect': {'intent': 'scan', 'target': target, 'scan_type': scan_type}}


def _page(pid, lang, text, page):
    return {'id': pid, 'lang': lang, 'text': text, 'expect': {'intent': 'navigate', 'page': page}}


def _fact(pid, lang, text, fact):
    return {'id': pid, 'lang': lang, 'text': text, 'expect': {'intent': 'fact', 'fact': fact}}


# 15 English and 15 Thai. The addresses are the shapes people really scan (home / office / lab / loopback / a /24), the types are all four a
# voice command can name, and two non-scan commands per language show whether ordinary words are heard better than numbers. The last three of each
# language (13 to 15, added 2026-11-09) say a network with the word "slash" / "ทับ" / "สแลช": the owner's real results wrote it as a dot
# ("192.142.1.0.24") or as other words, so these let the SAME audio be compared across engines and across Whisper hints. Count the scan sentences
# of the older 01 to 10 and the three /24 sentences separately when comparing with an earlier session.
PROMPTS = [
    _scan('en01', 'en', 'scan 192.168.1.1', '192.168.1.1', 'fast_scan'),
    _scan('en02', 'en', 'scan 10.0.0.5', '10.0.0.5', 'fast_scan'),
    _scan('en03', 'en', 'scan 192.168.1.41', '192.168.1.41', 'fast_scan'),
    _scan('en04', 'en', 'vulnerability scan 192.168.1.41', '192.168.1.41', 'vuln_scan'),
    _scan('en05', 'en', 'intense scan 172.16.0.10', '172.16.0.10', 'intense'),
    _scan('en06', 'en', 'discovery 192.168.1.0/24', '192.168.1.0/24', 'discovery'),
    _scan('en07', 'en', 'scan 192.168.100.254', '192.168.100.254', 'fast_scan'),
    _scan('en08', 'en', 'scan 127.0.0.1', '127.0.0.1', 'fast_scan'),
    _scan('en09', 'en', 'scan 10.10.20.30', '10.10.20.30', 'fast_scan'),
    _scan('en10', 'en', 'vulnerability scan 192.168.0.100', '192.168.0.100', 'vuln_scan'),
    _page('en11', 'en', 'show devices', 'devices'),
    _fact('en12', 'en', 'how many devices', 'count_devices'),
    _scan('en13', 'en', 'scan 192.168.1.0 slash 24', '192.168.1.0/24', 'fast_scan'),
    _scan('en14', 'en', 'vulnerability scan 10.0.0.0 slash 24', '10.0.0.0/24', 'vuln_scan'),
    _scan('en15', 'en', 'intense scan 172.16.5.0 slash 24', '172.16.5.0/24', 'intense'),
    _scan('th01', 'th', 'สแกน 192.168.1.1', '192.168.1.1', 'fast_scan'),
    _scan('th02', 'th', 'สแกน 10.0.0.5', '10.0.0.5', 'fast_scan'),
    _scan('th03', 'th', 'สแกน 192.168.1.41', '192.168.1.41', 'fast_scan'),
    _scan('th04', 'th', 'สแกนช่องโหว่ 192.168.1.41', '192.168.1.41', 'vuln_scan'),
    _scan('th05', 'th', 'สแกนแบบละเอียด 172.16.0.10', '172.16.0.10', 'intense'),
    _scan('th06', 'th', 'ดิสคัฟเวอรี่ 192.168.1.0/24', '192.168.1.0/24', 'discovery'),
    _scan('th07', 'th', 'สแกน 192.168.100.254', '192.168.100.254', 'fast_scan'),
    _scan('th08', 'th', 'สแกน 127.0.0.1', '127.0.0.1', 'fast_scan'),
    _scan('th09', 'th', 'สแกน 10.10.20.30', '10.10.20.30', 'fast_scan'),
    _scan('th10', 'th', 'สแกนช่องโหว่ 192.168.0.100', '192.168.0.100', 'vuln_scan'),
    _page('th11', 'th', 'เปิดหน้าอุปกรณ์', 'devices'),
    _fact('th12', 'th', 'มีกี่อุปกรณ์', 'count_devices'),
    _scan('th13', 'th', 'สแกน 192.168.1.0 ทับ 24', '192.168.1.0/24', 'fast_scan'),
    _scan('th14', 'th', 'สแกนช่องโหว่ 10.0.0.0 สแลช 24', '10.0.0.0/24', 'vuln_scan'),
    _scan('th15', 'th', 'สแกนแบบละเอียด 172.16.5.0 ทับ 24', '172.16.5.0/24', 'intense'),
]
_BY_ID = {p['id']: p for p in PROMPTS}

MAX_TEXTS = voice_commands.MAX_ALTERNATIVES          # the engine's best reading and its alternatives, like the app sends them
MAX_TEXT_LEN = 300                                    # the same cut the app makes
MAX_AUDIO_BYTES = 3 * 1024 * 1024                     # a command is a few seconds; 3 MB is far more than any real clip
_SESSION_RE = re.compile(r'\d{8}-\d{6}')      # matched with fullmatch: '$' would also accept a trailing newline, and this becomes a folder name
_AUDIO_EXT = {'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mp4': 'mp4', 'audio/wav': 'wav', 'audio/x-wav': 'wav', 'audio/mpeg': 'mp3'}


def get_prompt(pid):
    return _BY_ID.get(str(pid or ''))


def public_prompts():
    """What the page needs: id, language, the sentence, and what kind of command it is."""
    return [{'id': p['id'], 'lang': p['lang'], 'text': p['text'], 'kind': p['expect']['intent']} for p in PROMPTS]


def new_session_id(now):
    return now.strftime('%Y%m%d-%H%M%S')


def valid_session(s):
    return bool(_SESSION_RE.fullmatch(str(s or '')))


def audio_extension(mimetype):
    """The file extension for a recorded clip, from its type (parameters such as ';codecs=opus' are ignored); None when it is not audio we keep."""
    return _AUDIO_EXT.get(str(mimetype or '').split(';')[0].strip().lower())


def clean_texts(texts):
    """What the engine wrote, best reading first, as the app would receive it: strings only, cut, no duplicates, at most MAX_TEXTS."""
    out = []
    for t in texts if isinstance(texts, list) else []:
        t = str(t or '')[:MAX_TEXT_LEN]
        if t.strip() and t not in out:
            out.append(t)
    return out[:MAX_TEXTS]


def _digits(text):
    """The digits of a reading, Thai numerals included, or None when it holds none (numbers said as words are resolved by the parser instead)."""
    s = str(text or '').translate(str.maketrans('๐๑๒๓๔๕๖๗๘๙', '0123456789'))
    d = re.findall(r'\d', s)
    return ''.join(d) if d else None


def _edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def digit_note(expected_target, text):
    """Why an address came out wrong, from the digits only: 'same_digits' (the dots are the problem), 'lost' / 'extra' (one digit fewer / more),
    'off2' (two edits), 'different', or None when the text holds no digits to compare."""
    want, got = _digits(expected_target), _digits(text)
    if want is None or got is None:
        return None
    if want == got:
        return 'same_digits'
    d = _edit_distance(want, got)
    if d == 1:
        return 'lost' if len(got) < len(want) else 'extra' if len(got) > len(want) else 'one_wrong'
    return 'off2' if d == 2 else 'different'


def score(prompt, texts, lang=None):
    """How the app would do with what the engine wrote. Returns:
      ok        True only when the command is exactly the one that was read (target and scan type, or the same page / question)
      category  exact | wrong_type | wrong_target | refused | not_a_command | other_command | no_text
      heard     the engine's best reading;  used  the reading the app would use (it may be one of the alternatives)
      reason    why an address was refused (the parser's own code), when it was
      digits    digit_note() for a scan prompt that is not exact
      best_ok   True when the best reading ALONE would have been exact (False with the alternatives only helping, or not at all)"""
    lang = lang or prompt['lang']
    exp = prompt['expect']
    texts = clean_texts(texts)
    if not texts:
        return {'ok': False, 'category': 'no_text', 'heard': '', 'used': '', 'reason': None, 'digits': None, 'best_ok': False}
    cmd, _, used = voice_commands.understand_best(texts, lang)
    best_cmd = voice_commands.understand(texts[0], lang)
    cat, reason = _category(exp, cmd)
    out = {'ok': cat == 'exact', 'category': cat, 'heard': texts[0], 'used': used, 'reason': cmd.get('reason') if cat == 'refused' else None,
           'digits': None, 'best_ok': _category(exp, best_cmd)[0] == 'exact'}
    if cat != 'exact' and exp['intent'] == 'scan':
        out['digits'] = digit_note(exp['target'], texts[0])
    return out


def _category(exp, cmd):
    """(category, reason) of one parser result against what was meant."""
    intent = cmd.get('intent')
    if exp['intent'] == 'scan':
        if intent == 'scan':
            if cmd.get('status') != 'ok':
                return 'refused', cmd.get('reason')
            if cmd.get('target') != exp['target']:
                return 'wrong_target', None
            return ('exact', None) if cmd.get('scan_type') == exp['scan_type'] else ('wrong_type', None)
    elif exp['intent'] == 'navigate':
        if intent == 'navigate' and cmd.get('status') == 'ok':
            return ('exact', None) if cmd.get('page') == exp['page'] else ('other_command', None)
    elif exp['intent'] == 'fact':
        if intent == 'fact' and cmd.get('status') == 'ok':
            return ('exact', None) if cmd.get('fact') == exp['fact'] and not cmd.get('severity') else ('other_command', None)
    if intent == 'unknown':
        return 'not_a_command', None
    return 'other_command', None


def summarize(rows):
    """rows: [{'prompt_id', 'score'}]. Counts for a whole session: how many were exact, overall and per language and per kind of command."""
    out = {'total': 0, 'exact': 0, 'by_lang': {}, 'by_kind': {}, 'categories': {}}
    for r in rows:
        p, s = get_prompt(r.get('prompt_id')), r.get('score') or {}
        if not p:
            continue
        out['total'] += 1
        ok = bool(s.get('ok'))
        out['exact'] += ok
        for key, group in ((p['lang'], 'by_lang'), (p['expect']['intent'], 'by_kind')):
            g = out[group].setdefault(key, {'total': 0, 'exact': 0})
            g['total'] += 1
            g['exact'] += ok
        c = s.get('category') or 'no_text'
        out['categories'][c] = out['categories'].get(c, 0) + 1
    return out
