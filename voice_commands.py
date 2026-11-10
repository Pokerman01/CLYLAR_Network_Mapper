"""Voice commands: turns what the browser's speech recognition heard (Thai and/or English) into a command.

Deterministic on purpose, no AI: the same words always give the same command, nothing is invented and it costs no tokens.
This module only decides what was MEANT. It never runs anything: app.py starts a scan, and only after the user has confirmed the card
built from this result.

parse_command(text, lang) -> dict     (scans only)
    intent   'scan' | 'unknown'      ('unknown' = not a command we know; the caller may hand it to something else)
    status   'ok' | 'need_target' | 'bad_target' | 'ambiguous' | 'unsupported'   (only for intent 'scan')
    target, scan_type, type_defaulted, public     (status 'ok')
    message  one short sentence in `lang` ('th' or 'en') for every status except 'ok' / 'unknown'
    reason, suggestion   (status 'bad_target') why it was refused; for "192.142.1.0.24" (a spoken "slash" written as a dot) the refusal is
             unchanged but its message also says which network may have been meant, and `suggestion` holds that text ("192.142.1.0/24").
             It is text for the person only: it is never a target and nothing may act on it.
             reason 'tail_number' / 'tail_sign': a complete address FOLLOWED by a number that could be a network size ("192.168.1.0 24",
             "... stash 24", "... สแลช ยี่สิบสี่" heard as "หัก ยืบ สี่") or by a sign word with no size ("... slash"). Taking the address alone would scan
             ONE device while the person may have meant the network, and dropping the tail silently is not allowed, so the answer is a refusal
             that says what was heard and how to say it (see "a size that may have been dropped" below). Like `suggestion`, it also carries the
             `scan_type` named so far (like need_target), so the page can keep it while the person says the address again.

understand(text, lang) -> dict     (what the server calls: scans, then questions about the data, then "open a page")
    intent 'fact'      {'fact': 'count_devices' | 'count_ports' | 'count_cves' | 'devices_with_cves' | 'latest_scan' | 'running_scans'
                        | 'next_schedule', 'severity': 'critical' | 'high' | 'medium' | 'low' | None}   answered by app.py, never by AI
    intent 'navigate'  {'status': 'ok', 'page': key of PAGES}  or  {'status': 'ambiguous', 'message'}
    anything else is exactly what parse_command() said

Rules that keep it safe (a wrong guess here would scan the wrong machine):
  * a scan needs an explicit scan word (scan / สแกน / discovery ...); a bare IP is never a command
  * the address must be complete and valid; it is never completed, rounded or "fixed" (192.168.1.300 is refused, not turned into .30)
  * a number (0 to 32) or a "slash" left after a complete address may be a network size the engine lost: it is asked about, never dropped and never
    turned into a /24 by guessing ("scan 192.168.1.0 24" is a refusal, not a scan of one device; tail_number / tail_sign, see _flag_tail)
  * more than one address, or two different scan types, is refused: the user is asked to say one
  * questions, results and negations ("what was the last scan", "don't scan ...", "ผลสแกนล่าสุด") are not commands
  * ranges larger than a /16 are refused by voice (they can be typed)
"""
import ipaddress
import re
import unicodedata

MIN_PREFIX = 16   # voice refuses a range larger than this (a /8 is 16 million addresses)
SCAN_TYPES = ('discovery', 'fast_scan', 'intense', 'vuln_scan')   # the types that can be spoken

_THAI_DIGITS = str.maketrans('๐๑๒๓๔๕๖๗๘๙', '0123456789')


def _clean(text):
    """Lower case, Thai digits to 0-9, one space between words. NFKC also folds full-width digits (and turns 'ำ' into 'ํา',
    which is why every Thai keyword below goes through this too)."""
    s = unicodedata.normalize('NFKC', str(text or '')).translate(_THAI_DIGITS).lower()
    return re.sub(r'\s+', ' ', s).strip()


def _group(words):
    """One regex for a list of words: Latin words must stand alone, Thai words match anywhere (Thai has no spaces)."""
    parts = []
    for w in sorted({_clean(w) for w in words}, key=len, reverse=True):
        esc = re.escape(w).replace(r'\ ', r'\s+')
        parts.append(r'(?<![a-z0-9])%s(?![a-z0-9])' % esc if w.isascii() else esc)
    return re.compile('|'.join(parts))


# ───────────── words ─────────────
_VERB = _group(['scan', 'scanning', 'สแกน', 'แสกน', 'สะแกน'])
# What the browser's engine sometimes writes for "scan" (measured on the owner's voice: "scan 192.180.0.0" came back as "2nd 1.01.208.").
# Used ONLY as the first word of the text AND with an address-like thing after it, so "my skin 10.0.0.1" is still not a command. The
# confirmation card always shows what was heard, so a wrong reading can only be cancelled, never run unseen.
_MISHEARD_VERB = re.compile(r'^(?:2nd|skin|scam|scand|scant|skan|sgan|stan|scann)(?![a-z0-9])')
# these name a scan by themselves ("discovery 10.0.0.0/24"), so they count as the scan word too
_IMPLICIT_VERB = _group(['discovery', 'discover', 'ping sweep', 'find hosts', 'find devices', 'ดิสคัฟ', 'ค้นหาอุปกรณ์', 'ค้นหาเครื่อง', 'หาอุปกรณ์'])

_TYPE_WORDS = {
    'discovery':  _group(['discovery', 'discover', 'ping sweep', 'find hosts', 'find devices', 'ดิสคัฟ', 'ค้นหาอุปกรณ์', 'ค้นหาเครื่อง', 'หาอุปกรณ์']),
    'vuln_scan':  _group(['vulnerability', 'vulnerabilities', 'vulnerable', 'vuln', 'cve', 'ช่องโหว่', 'วัลเนอ']),
    'intense':    _group(['intense', 'intensive', 'deep', 'detailed', 'thorough', 'ละเอียด', 'อินเท', 'ลึก', 'เข้มข้น']),
    'fast_scan':  _group(['fast', 'quick', 'quickly', 'rapid', 'เร็ว', 'ด่วน', 'ฟาสต์', 'ควิก']),
}
_UNSUPPORTED = _group(['custom', 'กำหนดเอง', 'คัสตอม', 'xml'])   # their arguments cannot be spoken reliably

# questions, results and negations are never a command (the caller can send them elsewhere)
_NOT_A_COMMAND = _group([
    'what', 'how', 'why', 'when', 'where', 'which', 'who', 'did', 'does', 'was', 'were', 'failed',
    'result', 'results', 'history', 'last', 'latest', 'previous', 'status', 'summary', 'report',
    "don't", 'dont', 'do not', 'not', 'never', 'cancel', 'stop', 'without',
    'ผล', 'ล่าสุด', 'ประวัติ', 'สถานะ', 'สรุป', 'รายงาน', 'อะไร', 'ทำไม', 'อย่างไร', 'ยังไง', 'เมื่อไร', 'เมื่อไหร่', 'ไหน', 'กี่', 'เท่าไร', 'เท่าไหร่',
    'ไม่', 'อย่า', 'ยกเลิก', 'หยุด', 'ห้าม'])

# words that may surround a bare "scan": if nothing else is left the user just forgot the target
_FILLER = _group([
    'please', 'can you', 'could you', 'would you', 'i want to', 'i would like to', "i'd like to", 'lets', "let's", 'let us', 'now', 'a', 'an', 'the',
    'run', 'start', 'do', 'perform', 'new', 'network', 'ip', 'address', 'host', 'hosts', 'device', 'devices', 'scan', 'scanning', 'scans', 'for', 'of', 'on', 'to', 'me',
    'ช่วย', 'กรุณา', 'โปรด', 'ขอ', 'หน่อย', 'ด้วย', 'ครับ', 'ค่ะ', 'คะ', 'นะ', 'สั่ง', 'เริ่ม', 'ทำ', 'อยาก', 'ต้องการ', 'ให้', 'ผม', 'ฉัน', 'หนู',
    'เดี๋ยวนี้', 'ตอนนี้', 'แบบ', 'การ', 'เครือข่าย', 'เครื่อง', 'อุปกรณ์', 'สแกน', 'แสกน'])

# ───────────── spoken numbers ─────────────
_EN_UNIT = {'zero': 0, 'oh': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9}
_EN_TEEN = {'ten': 10, 'eleven': 11, 'twelve': 12, 'thirteen': 13, 'fourteen': 14, 'fifteen': 15, 'sixteen': 16, 'seventeen': 17,
            'eighteen': 18, 'nineteen': 19}
_EN_TENS = {'twenty': 20, 'thirty': 30, 'forty': 40, 'fifty': 50, 'sixty': 60, 'seventy': 70, 'eighty': 80, 'ninety': 90}
_TH_DIGIT = {'ศูนย์': 0, 'หนึ่ง': 1, 'สอง': 2, 'สาม': 3, 'สี่': 4, 'ห้า': 5, 'หก': 6, 'เจ็ด': 7, 'แปด': 8, 'เก้า': 9}
_TH_WORDS = list(_TH_DIGIT) + ['เอ็ด', 'ยี่', 'สิบ', 'ร้อย']
_EN_WORDS = list(_EN_UNIT) + list(_EN_TEEN) + list(_EN_TENS) + ['hundred', 'and']


def _alt(words, latin):
    words = sorted((_clean(w) for w in words), key=len, reverse=True)
    body = '|'.join(re.escape(w) for w in words)
    return r'(?<![a-z])(?:%s)(?![a-z])' % body if latin else '(?:%s)' % body


_TOKEN = re.compile(
    r'(?P<num>\d+)'
    r'|(?P<dot>\.|(?<![a-z])(?:dot|point)(?![a-z])|จุด)'
    r'|(?P<slash>/|(?<![a-z])slash(?![a-z])|สแลช|ทับ)'
    r'|(?P<en>' + _alt(_EN_WORDS, True) + r')'
    r'|(?P<th>' + _alt(_TH_WORDS, False) + r')')


def _eval_en(vals):
    """English number words of one octet: 'one nine two' -> 192 (digits read one by one), 'one ninety two' -> 192, 'two fifty five' -> 255,
    'one hundred and ten' -> 110, 'twenty five' -> 25. None when the words do not make a number."""
    kinds = ''.join(k for k, _ in vals)
    if len(vals) == 1:
        return vals[0][1]
    if set(kinds) == {'u'}:
        digits = ''.join(str(n) for _, n in vals)
        return int(digits) if len(digits) <= 3 else None
    i, total = 0, 0
    if kinds[0] == 'u' and kinds[1:2] == 'h' and vals[0][1] > 0:
        total, i = vals[0][1] * 100, 2
    elif kinds[0] == 'h':
        total, i = 100, 1
    elif kinds[0] == 'u' and kinds[1:2] in ('t', 'y') and vals[0][1] > 0:   # "one ninety two": the hundred is left out when spoken
        total, i = vals[0][1] * 100, 1
    rest, rk = vals[i:], kinds[i:]
    if rk == '':
        return total
    if rk in ('t', 'y'):
        return total + rest[0][1]
    if rk == 'yu' and rest[1][1] > 0:
        return total + rest[0][1] + rest[1][1]
    if rk == 'u' and total and rest[0][1] > 0:
        return total + rest[0][1]
    return None


def _eval_th(words):
    """Thai number words of one octet: 'หนึ่งเก้าสอง' -> 192 (digits one by one), 'หนึ่งร้อยเก้าสิบสอง' -> 192, 'ยี่สิบเอ็ด' -> 21."""
    if 'สิบ' not in words and 'ร้อย' not in words:
        digits = []
        for w in words:
            if w in _TH_DIGIT:
                digits.append(str(_TH_DIGIT[w]))
            elif w == 'เอ็ด':
                digits.append('1')
            else:
                return None
        s = ''.join(digits)
        return int(s) if 1 <= len(s) <= 3 else None
    value, cur, stage = 0, None, 0      # stage: 0 start, 1 after ร้อย, 2 after สิบ
    for w in words:
        if w in _TH_DIGIT or w in ('เอ็ด', 'ยี่'):
            if cur is not None:
                return None
            cur = _TH_DIGIT.get(w, 1 if w == 'เอ็ด' else 2)
        elif w == 'ร้อย':
            if stage != 0 or cur == 0:
                return None
            value += (1 if cur is None else cur) * 100
            cur, stage = None, 1
        elif w == 'สิบ':
            if stage == 2 or cur == 0:
                return None
            value += (1 if cur is None else cur) * 10
            cur, stage = None, 2
    return value + (cur or 0)


def _phrase_value(kind, words):
    if kind == 'th':
        return _eval_th(words)
    vals = []
    for w in words:
        if w in _EN_UNIT:
            vals.append(('u', _EN_UNIT[w]))
        elif w in _EN_TEEN:
            vals.append(('t', _EN_TEEN[w]))
        elif w in _EN_TENS:
            vals.append(('y', _EN_TENS[w]))
        elif w == 'hundred':
            vals.append(('h', 100))
    return _eval_en(vals)


def _items(s):
    """The numbers, dots and slashes of the text, in order. Spoken number words that follow each other become ONE number.
    Each item: {'t': 'num'|'dot'|'slash', 'v': int|None, 'a','b': position, 'spoken': bool, 'digits': str}"""
    toks = [(m.lastgroup, m.group(), m.start(), m.end()) for m in _TOKEN.finditer(s)]
    items, i = [], 0
    while i < len(toks):
        kind, txt, a, b = toks[i]
        if kind == 'num':
            # more than 9 digits is not an octet whatever it is; the cap also keeps int() away from absurdly long input
            items.append({'t': 'num', 'v': int(txt) if len(txt) <= 9 else 10 ** 9, 'a': a, 'b': b, 'spoken': False, 'digits': txt})
            i += 1
        elif kind in ('dot', 'slash'):
            items.append({'t': kind, 'v': None, 'a': a, 'b': b, 'spoken': False, 'digits': ''})
            i += 1
        elif kind == 'and':       # not reached: 'and' is an 'en' token, handled below
            i += 1
        else:                     # a run of number words of one language
            run, j, end = [], i, b
            while j < len(toks) and toks[j][0] == kind and (j == i or s[end:toks[j][2]].strip() == ''):
                w = toks[j][1]
                if w == 'and':
                    nxt = toks[j + 1] if j + 1 < len(toks) else None
                    if run and run[-1] == 'hundred' and nxt and nxt[0] == kind and nxt[1] != 'and':
                        end = toks[j][3]; j += 1
                        continue
                    break
                run.append(w); end = toks[j][3]; j += 1
            if not run:           # a lone "and"
                i += 1
                continue
            items.append({'t': 'num', 'v': _phrase_value(kind, run), 'a': a, 'b': end, 'spoken': True, 'digits': ''})
            i = j
    return items


def _joined(s, x, y):
    return s[x['b']:y['a']].strip() == ''


# ───────────── a size that may have been dropped ─────────────
# "scan 192.168.1.0 24", "... stash 24", "... slash" and a Thai engine's "สแลช ยี่สิบสี่" written as "หัก ยืบ สี่" all END with an address that is complete,
# so the scan would cover ONE device while the person may have meant the network. The parser does not guess the size and does not drop it silently
# either: a number that could be a prefix length (0 to 32; the parser accepts only 16 to 32, but a heard "4" is exactly the mis-hearing) within
# TAIL_WORDS words after the address, or a sign word ("slash", "ทับ", "/") with no size, is a REFUSAL that says what was heard and how to say it
# (reasons tail_number and tail_sign). When in doubt it asks: a needless question costs a few seconds, a silently narrowed scan costs trust.
# Words BEFORE the address are not looked at. A good "slash 24" is not a tail (it is the prefix), and neither is a number above 32 (a port, a count).
TAIL_WORDS = 3     # how many other words may stand between the address and the number (or the sign); punctuation alone does not count as a word
# These words say the number is something else (a port, a repeat count, a length of time). The ONE place to extend: a word missing here only means
# one more question, a word added here means a number next to it is never asked about, so keep the lists short.
#   BEFORE: they stand right before the number ("port 22", "x 3");   AFTER: right after it ("3 times", "2 minutes", "สองครั้ง", "3x").
# "for" is deliberately NOT a cue: "for 2 minutes" is excused by "minutes", but "for 24" with nothing after it is still asked about.
# A sign word anywhere between the address and the number cancels the excuse ("slash 24 minutes" is still a size).
_NOT_A_SIZE_BEFORE = re.compile(r'(?:%s)[\s:=#.]*$' % _group(['port', 'ports', 'port number', 'x', 'พอร์ต', 'พอร์ตหมายเลข']).pattern)
_NOT_A_SIZE_AFTER = re.compile(r'\s*(?:%s)' % _group([
    'time', 'times', 'x', 'minute', 'minutes', 'min', 'mins', 'second', 'seconds', 'sec', 'secs', 'hour', 'hours', 'hr', 'hrs', 'day', 'days',
    'round', 'rounds', 'port', 'ports', 'ครั้ง', 'นาที', 'วินาที', 'ชั่วโมง', 'วัน', 'รอบ', 'พอร์ต']).pattern)


def _words(text):
    """How many words a stretch of text holds: whitespace-separated pieces that contain a letter or a digit ("," or "." alone is not a word)."""
    return sum(1 for w in text.split() if re.search(r'[^\W_]', w))


def _flag_tail(s, items, used, res, chain, k):
    """`res` is a complete, valid address WITHOUT a prefix (from _check), `chain` its numbers and k the index of the first item after it. When a
    number that could be a network size, or a sign word with no size, follows within TAIL_WORDS words, turn `res` into a refusal: problem
    'tail_number' / 'tail_sign', no target, `tail` (the words heard after the address) and `heard` (the address and those words). For a
    number, `suggestion` is the network _check() itself would accept for that address and number (text only, nothing acts on it).
    `heard` shows the address as the parser read it (digits, even when it was spoken in words, which would fill the whole message) and the
    tail exactly as heard."""
    end, sign, addr = res['b'], None, res['target']
    for j in range(k, len(items)):
        if j in used:                                       # the next address starts here: not a tail (and two addresses are 'ambiguous' anyway)
            break
        it = items[j]
        if _words(s[end:it['a']]) > TAIL_WORDS:
            break
        if it['t'] == 'slash':
            sign = sign or it
        elif it['t'] == 'num' and (it['v'] is None or 0 <= it['v'] <= 32) \
                and (sign is not None or not (_NOT_A_SIZE_BEFORE.search(s[end:it['a']]) or _NOT_A_SIZE_AFTER.match(s[it['b']:]))):
            tail = s[end:it['b']].strip(' ,.;:!?-–')
            res.update(problem='tail_number', target='', public=False, tail=tail, heard=addr + ' ' + tail)
            as_network = _check(s, chain, it)
            if not as_network['problem']:
                res['suggestion'] = as_network['target']
            return
    if sign is not None:
        tail = s[end:sign['b']].strip(' ,.;:!?-–')
        res.update(problem='tail_sign', target='', public=False, tail=tail, heard=addr + ' ' + tail)


def _find_targets(s):
    """Every address-like thing in the text: a list of {'text', 'problem', 'target', 'a', 'b'}. problem is '' when it is a valid
    address, else 'incomplete' | 'too_many' | 'octet' | 'prefix' | 'reserved' | 'too_large' | 'port' | 'tail_number' | 'tail_sign'."""
    items = _items(s)
    found, used, i = [], set(), 0          # found: (result, its numbers, its prefix item or None, index of the first item after it)
    while i < len(items):
        it = items[i]
        if it['t'] != 'num':
            i += 1
            continue
        chain, k = [it], i + 1
        while k + 1 < len(items) and items[k]['t'] == 'dot' and items[k + 1]['t'] == 'num' \
                and _joined(s, items[k - 1], items[k]) and _joined(s, items[k], items[k + 1]):
            chain += [items[k + 1]]
            k += 2
        prefix = None
        if len(chain) >= 2 and k + 1 < len(items) and items[k]['t'] == 'slash' and items[k + 1]['t'] == 'num' \
                and _joined(s, chain[-1], items[k]) and _joined(s, items[k], items[k + 1]):
            prefix = items[k + 1]
            k += 2
        if len(chain) >= 2:
            found.append((_check(s, chain, prefix), chain, prefix, k))
            used.update(range(i, k))
            i = k
        else:
            i += 1
    # "192 168 1 1": exactly four numerals in a row with no dots (numbers that are not part of a dotted address). A "slash 24" joined to them is
    # their prefix, exactly as after a dotted address ("192 168 1 0 slash 24" used to lose the /24 without a word).
    run = []
    for idx in range(len(items) + 1):
        ok = idx < len(items) and idx not in used and items[idx]['t'] == 'num' and not items[idx]['spoken'] \
            and (not run or _joined(s, run[-1], items[idx]))
        if ok:
            run.append(items[idx])
            continue
        if len(run) == 4:
            prefix, k = None, idx
            if idx + 1 < len(items) and items[idx]['t'] == 'slash' and items[idx + 1]['t'] == 'num' \
                    and _joined(s, run[-1], items[idx]) and _joined(s, items[idx], items[idx + 1]):
                prefix, k = items[idx + 1], idx + 2
            found.append((_check(s, run, prefix), run, prefix, k))
            used.update(range(idx - 4, k))
        run = [items[idx]] if idx < len(items) and idx not in used and items[idx]['t'] == 'num' and not items[idx]['spoken'] else []
    found.sort(key=lambda f: f[0]['a'])
    for res, chain, prefix, k in found:
        if not res['problem'] and prefix is None:        # a complete address with no size of its own: is something left after it that looks like one?
            _flag_tail(s, items, used, res, chain, k)
    return [f[0] for f in found]


def _check(s, chain, prefix_item):
    shown = s[chain[0]['a']:(prefix_item or chain[-1])['b']].strip()
    res = {'text': shown, 'problem': '', 'target': '', 'public': False, 'a': chain[0]['a'], 'b': (prefix_item or chain[-1])['b']}
    if re.match(r':\d', s[res['b']:res['b'] + 2]):    # "192.168.1.1:80": a voice scan covers the whole host, so a port is refused, not dropped
        res['problem'] = 'port'
        return res
    if len(chain) < 4:
        res['problem'] = 'incomplete'
        return res
    if len(chain) > 4:
        res['problem'] = 'too_many'
        # "192.142.1.0.24": Whisper and the browser engine often write the spoken "slash" as a dot. The refusal stands (nothing is fixed, no
        # target is set); but when the first four numbers are an address the parser accepts and the fifth is a prefix it accepts, the
        # message may SAY what was perhaps meant. The accepted-or-not decision is _check()'s own, so the hint can never offer a network
        # (a /8, a reserved address, a number above 255) that the parser would refuse itself. Text only: nothing reads `suggestion`.
        if len(chain) == 5 and prefix_item is None:
            as_network = _check(s, chain[:4], chain[4])
            if not as_network['problem']:
                res['suggestion'] = as_network['target']
        return res
    octets = []
    for c in chain:
        if c['v'] is None or not 0 <= c['v'] <= 255 or len(c['digits']) > 3:
            res['problem'], res['bad'] = 'octet', (c['digits'] or ('' if c['v'] is None else str(c['v'])) or '?')
            return res
        octets.append(c['v'])
    if octets[0] == 0 or octets[0] >= 224:       # 0.x.x.x, multicast and broadcast are not hosts
        res['problem'] = 'reserved'
        return res
    target = '.'.join(str(o) for o in octets)
    if prefix_item is not None:
        p = prefix_item['v']
        if p is None or not 0 <= p <= 32:
            res['problem'] = 'prefix'
            return res
        if p < MIN_PREFIX:
            res['problem'] = 'too_large'
            return res
        target += '/%d' % p
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        res['problem'] = 'octet'
        return res
    res['target'], res['public'] = target, not net.is_private
    return res


def validate_target(text):
    """(True, '') when `text` is an IPv4 address or CIDR that a voice scan may use, else (False, reason). Used again by the server
    before it starts a confirmed scan."""
    t = str(text or '').strip()
    if not re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?', t):
        return False, 'octet'
    found = _find_targets(_clean(t))
    if len(found) != 1 or found[0]['problem'] or found[0]['target'] != t:
        return False, (found[0]['problem'] if len(found) == 1 and found[0]['problem'] else 'octet')
    return True, ''


# ───────────── messages ─────────────
_MSG = {
    'need_target': {'th': 'จะสแกนอุปกรณ์ใด พูดหรือพิมพ์ที่อยู่ IP เช่น 192.168.1.1',
                    'en': 'Which target? Say an IP address such as 192.168.1.1.'},
    'incomplete':  {'th': 'ที่อยู่ IP ไม่ครบ 4 ส่วน (ได้ยินว่า "{x}") กรุณาพูดใหม่',
                    'en': 'That IP address is not complete (heard "{x}"). Please say it again.'},
    'too_many':    {'th': 'ที่อยู่ IP มีมากกว่า 4 ส่วน (ได้ยินว่า "{x}") กรุณาพูดใหม่',
                    'en': 'That IP address has more than 4 parts (heard "{x}"). Please say it again.'},
    # the same refusal, for five numbers whose last one could have been the prefix after a "slash" (see _check): it only says what may have been meant
    'too_many_net': {'th': 'ที่อยู่ IP มีมากกว่า 4 ส่วน (ได้ยินว่า "{x}") หากหมายถึงเครือข่าย {net} ให้พูดว่า "ทับ {p}" ต่อท้ายที่อยู่ IP มิฉะนั้นกรุณาพูดใหม่',
                     'en': 'That IP address has more than 4 parts (heard "{x}"). Did you mean the network {net}? Say "slash {p}" after the address. Otherwise, please say it again.'},
    # a number (or a sign word) after a complete address: the size of a network may have been heard and lost; see _flag_tail. {x} = the words heard after
    # the address, {heard} = the address with them. The Thai "ทับ" is what people say (the parser also takes "สแลช"), so it is kept in the quotes.
    'tail_number': {'th': 'ได้ยินว่า "{x}" ต่อท้ายที่อยู่ IP ("{heard}") หากหมายถึงเครือข่าย ให้พูดคำว่า "ทับ" และขนาด 16 ถึง 32 ต่อท้ายที่อยู่ IP เช่น "ทับ 24" หากหมายถึงอุปกรณ์เครื่องเดียว ให้พูดเฉพาะที่อยู่ IP',
                    'en': 'I heard "{x}" after the address ("{heard}"). If you meant a network, say "slash" and a size from 16 to 32 after the address, for example "slash 24". For one device, say only the address.'},
    'tail_number_net': {'th': 'ได้ยินว่า "{x}" ต่อท้ายที่อยู่ IP ("{heard}") หากหมายถึงเครือข่าย {net} ให้พูดว่า "ทับ {p}" ต่อท้ายที่อยู่ IP หากหมายถึงอุปกรณ์เครื่องเดียว ให้พูดเฉพาะที่อยู่ IP',
                        'en': 'I heard "{x}" after the address ("{heard}"). For the network {net}, say "slash {p}" after the address. For one device, say only the address.'},
    'tail_sign':   {'th': 'ได้ยินคำว่า "{x}" ต่อท้ายที่อยู่ IP ("{heard}") แต่ไม่ได้ยินขนาดเครือข่าย หากหมายถึงเครือข่าย ให้พูดขนาดต่อท้ายที่อยู่ IP เช่น "ทับ 24" หากหมายถึงอุปกรณ์เครื่องเดียว ให้พูดเฉพาะที่อยู่ IP',
                    'en': 'I heard "{x}" after the address ("{heard}") but no network size. If you meant a network, say the size after it, for example "slash 24". For one device, say only the address.'},
    'octet':       {'th': 'ตัวเลขของ IP ต้องอยู่ระหว่าง 0-255 (ได้ยินว่า "{x}") กรุณาพูดใหม่',
                    'en': 'Each part of an IP address must be 0-255 (heard "{x}"). Please say it again.'},
    'prefix':      {'th': 'ขนาดเครือข่ายหลัง / ต้องอยู่ระหว่าง 0-32 (ได้ยินว่า "{x}")',
                    'en': 'The number after the slash must be 0-32 (heard "{x}").'},
    'reserved':    {'th': 'ที่อยู่ "{x}" ไม่ใช่ที่อยู่ที่สแกนได้ (0.x.x.x, มัลติแคสต์ หรือบรอดแคสต์)',
                    'en': '"{x}" is not an address that can be scanned (0.x.x.x, multicast or broadcast).'},
    'port':        {'th': 'คำสั่งเสียงสแกนทั้งอุปกรณ์ ยังระบุหมายเลขพอร์ตไม่ได้ (ได้ยินว่า "{x}")',
                    'en': 'Voice scans cover the whole host; a port number cannot be given (heard "{x}").'},
    'too_large':   {'th': 'ช่วงนี้ใหญ่เกินไปสำหรับคำสั่งเสียง (ต้องเป็น /16 หรือเล็กกว่า) หากจำเป็นให้พิมพ์คำสั่งเอง',
                    'en': 'That range is too large for a voice command (a /16 or smaller). Type it if you really need it.'},
    'many_targets': {'th': 'ได้ยินหลายเป้าหมาย ({x}) กรุณาสั่งทีละเป้าหมาย',
                     'en': 'I heard several targets ({x}). Please give one target at a time.'},
    'many_types':  {'th': 'ได้ยินหลายประเภทการสแกน ({x}) กรุณาระบุประเภทเดียว',
                    'en': 'I heard more than one scan type ({x}). Please name just one.'},
    'many_pages':  {'th': 'ได้ยินหลายหน้า ({x}) กรุณาบอกทีละหน้า',
                    'en': 'I heard several pages ({x}). Please name one page.'},
    'unsupported': {'th': 'คำสั่งเสียงยังไม่รองรับ Custom Scan หรือ XML (พิมพ์สั่งเองได้)',
                    'en': 'Voice commands do not support Custom or XML scans. You can type them.'},
    'not_understood': {'th': 'ไม่เข้าใจคำสั่ง (ได้ยินว่า "{x}") ลองพูดใหม่ เช่น "สแกน 192.168.1.1"',
                       'en': 'I did not understand that (heard "{x}"). Please try again, for example "scan 192.168.1.1".'},
}


def _cut(x, n=40):
    x = str(x)
    return x[:n] + '…' if len(x) > n else x      # the heard text is echoed back, so it is kept short


def _msg(code, lang, x='', **more):
    return _MSG[code]['en' if lang == 'en' else 'th'].format(x=_cut(x), **more)


def _unknown():
    return {'intent': 'unknown', 'status': '', 'message': ''}


def _scan(status, lang, code, x='', **extra):
    out = {'intent': 'scan', 'status': status, 'message': _msg(code, lang, x)}
    out.update(extra)
    return out


def _bad_target(t, lang, scan_type=None):
    """The refusal for an address-like thing with a problem (t comes from _find_targets). It is always status 'bad_target' with the parser's
    own `reason`, never a target and never usable. For "192.142.1.0.24" (see _check) the message also says which network may have been meant
    and how to say it, and the result carries that network as `suggestion`: text for the person, nothing acts on it. The same for a number after
    an address (reasons tail_number / tail_sign, see _flag_tail); those also carry `scan_type` (the type named so far, or None) so the page can
    keep it for the sentence that repeats the address."""
    sug = t.get('suggestion')
    if t['problem'] in ('tail_number', 'tail_sign'):
        more = {'heard': _cut(t['heard'], 60)}
        if sug:
            more.update(net=sug, p=sug.rsplit('/', 1)[1])
        out = {'intent': 'scan', 'status': 'bad_target', 'reason': t['problem'], 'scan_type': scan_type,
               'message': _msg('tail_number_net' if sug else t['problem'], lang, t['tail'], **more)}
        if sug:
            out['suggestion'] = sug
        return out
    if t['problem'] == 'too_many' and sug:
        return {'intent': 'scan', 'status': 'bad_target', 'reason': 'too_many', 'suggestion': sug,
                'message': _msg('too_many_net', lang, t['text'], net=sug, p=sug.rsplit('/', 1)[1])}
    return _scan('bad_target', lang, t['problem'], t.get('bad') or t['text'], reason=t['problem'])


# ───────────── the parser ─────────────
# "192, 180, 0, 0" and "192-180-0-0" are an address written with another separator. Only tried when the text has no address otherwise,
# so "192.168.1.1, 192.168.1.2" is still two targets.
_ODD_SEPARATOR = re.compile(r'(?<=\d)\s*[,\-–]\s*(?=\d)')


def _only_type(s):
    """The one scan type named in the text, or None (none or several)."""
    types = [k for k, rx in _TYPE_WORDS.items() if rx.search(s)]
    picked = ['vuln_scan'] if 'vuln_scan' in types and 'discovery' not in types else types
    return picked[0] if len(picked) == 1 else None


def parse_command(text, lang='th'):
    s = _clean(text)
    if not s or _NOT_A_COMMAND.search(s):
        return _unknown()
    targets = _find_targets(s)
    if not targets and _ODD_SEPARATOR.search(s):
        fixed = _ODD_SEPARATOR.sub('.', s)
        targets = _find_targets(fixed)
        if targets:
            s = fixed
    verb_guessed = False
    if not (_VERB.search(s) or _IMPLICIT_VERB.search(s)):
        # "2nd 192.180.0.0": a mishearing of "scan" counts only as the first word, with an address after it and nothing else around
        # ("2nd place 192.168.1.1" is not a command)
        if targets and _MISHEARD_VERB.match(s):
            rest = s
            for t in reversed(targets):
                rest = rest[:t['a']] + ' ' + rest[t['b']:]
            rest = _MISHEARD_VERB.sub(' ', rest, count=1)
            for rx in (_FILLER, *_TYPE_WORDS.values()):
                rest = rx.sub(' ', rest)
            if re.sub(r'[\s.,!?]+', '', rest) != '':
                return _unknown()
            verb_guessed = True
        else:
            return _unknown()                       # an address with no scan word is never a command

    types = [k for k, rx in _TYPE_WORDS.items() if rx.search(s)]
    if _UNSUPPORTED.search(s):
        return _scan('unsupported', lang, 'unsupported')

    if not targets:
        # "scan" / "fast scan please": the user only forgot the target. Anything else ("scan results of ...") is not for us.
        rest = s
        for rx in (_FILLER, *_TYPE_WORDS.values(), _VERB):
            rest = rx.sub(' ', rest)
        if re.sub(r'[\s.,!?]+', '', rest) == '':
            return _scan('need_target', lang, 'need_target', scan_type=_only_type(s))    # the page may keep the type for the next sentence
        return _unknown()
    if len(targets) > 1:
        return _scan('ambiguous', lang, 'many_targets', ', '.join(t['text'] for t in targets))
    t = targets[0]
    if t['problem']:
        return _bad_target(t, lang, _only_type(s))

    # "vulnerability" already includes the deep scan, so "detailed vulnerability scan" is a vulnerability scan; other mixes are unclear
    picked = ['vuln_scan'] if 'vuln_scan' in types and 'discovery' not in types else types
    if len(picked) > 1:
        return _scan('ambiguous', lang, 'many_types', ', '.join(picked))
    scan_type = picked[0] if picked else 'fast_scan'
    return {'intent': 'scan', 'status': 'ok', 'message': '', 'target': t['target'], 'scan_type': scan_type,
            'type_defaulted': not picked, 'public': t['public'], 'heard': s, 'verb_guessed': verb_guessed}


def parse_target_reply(text, lang='th', scan_type=None):
    """The answer to "which target?": just an address ("192.168.1.1"), no scan word needed. Only the page that asked the question may call
    this (it knows it is waiting). Returns a scan result like parse_command(), or None when the text holds no address at all, so the
    caller can treat it as a normal sentence instead. scan_type is the type the user named earlier ("vulnerability scan"), if any."""
    s = _clean(text)
    if not s or _NOT_A_COMMAND.search(s):
        return None
    targets = _find_targets(s)
    if not targets and _ODD_SEPARATOR.search(s):
        fixed = _ODD_SEPARATOR.sub('.', s)
        targets = _find_targets(fixed)
        if targets:
            s = fixed
    if not targets:
        return None
    if _UNSUPPORTED.search(s):
        return _scan('unsupported', lang, 'unsupported')
    if len(targets) > 1:
        return _scan('ambiguous', lang, 'many_targets', ', '.join(t['text'] for t in targets))
    t = targets[0]
    named = _only_type(s)
    if scan_type not in SCAN_TYPES:
        scan_type = None
    picked = named or scan_type
    if t['problem']:
        return _bad_target(t, lang, picked)
    return {'intent': 'scan', 'status': 'ok', 'message': '', 'target': t['target'], 'scan_type': picked or 'fast_scan',
            'type_defaulted': not picked, 'public': t['public'], 'heard': s, 'verb_guessed': False}


# ───────────── pages and questions about the data ─────────────
# What the chat's help panel offers as examples. Every phrase here is checked against the parser in test_voice_lab.py (scan -> a good scan command, ask ->
# a question we answer ourselves, open -> a page), so the help can never promise something the parser does not understand.
HELP_EXAMPLES = {
    'scan': {
        'th': ['สแกน 192.168.1.1', 'สแกนช่องโหว่ 192.168.1.41', 'สแกนแบบละเอียด 10.0.0.5', 'ค้นหาอุปกรณ์ 192.168.1.0/24'],
        'en': ['scan 192.168.1.1', 'vulnerability scan 192.168.1.41', 'intense scan 10.0.0.5', 'discovery 192.168.1.0/24'],
    },
    'ask': {
        'th': ['มีกี่อุปกรณ์', 'มีกี่พอร์ตที่เปิด', 'มีช่องโหว่ critical กี่รายการ', 'อุปกรณ์ไหนมีช่องโหว่ critical บ้าง', 'สแกนล่าสุดคืออะไร', 'กำลังสแกนอยู่ไหม', 'สแกนตามเวลาครั้งถัดไปคือเมื่อไร'],
        'en': ['how many devices', 'how many open ports', 'how many critical CVEs', 'which devices have critical CVEs', 'what was the latest scan', 'is a scan running', 'when is the next scheduled scan'],
    },
    'open': {
        'th': ['ไปหน้าอุปกรณ์', 'เปิดหน้าช่องโหว่', 'เปิดแดชบอร์ด', 'ไปหน้ารายงาน', 'เปิดแผนผังเครือข่าย'],
        'en': ['show devices', 'show vulnerabilities', 'open the dashboard', 'open reports', 'show network topology'],
    },
}

PAGES = {   # key: (Thai name, English name); app.py maps the key to the URL, so the text spoken can never choose a URL
    'dashboard': ('แดชบอร์ด', 'Dashboard'), 'tasks': ('งานสแกน', 'Tasks'), 'history': ('ประวัติการสแกน', 'Scan history'),
    'devices': ('อุปกรณ์', 'Devices'), 'vulnerabilities': ('ช่องโหว่', 'Vulnerabilities'), 'topology': ('แผนผังเครือข่าย', 'Network topology'),
    'reports': ('รายงาน', 'Reports'), 'settings': ('ตั้งค่า', 'Settings'),
}
_PAGE_WORDS = {
    'dashboard': _group(['dashboard', 'home page', 'main page', 'แดชบอร์ด', 'หน้าหลัก', 'หน้าแรก']),
    'tasks': _group(['tasks', 'task list', 'task page', 'งานสแกน']),
    'history': _group(['history', 'ประวัติ']),
    'devices': _group(['devices', 'device list', 'อุปกรณ์']),
    'vulnerabilities': _group(['vulnerabilities', 'vulnerability list', 'cve list', 'cves page', 'ช่องโหว่']),
    'topology': _group(['topology', 'network map', 'network diagram', 'network topology', 'แผนผัง', 'ผังเครือข่าย']),
    'reports': _group(['reports', 'report', 'รายงาน']),
    'settings': _group(['settings', 'setting', 'ตั้งค่า']),
}
_NAV_VERB = _group(['open', 'go to', 'go', 'show', 'show me', 'take me to', 'navigate to', 'navigate', 'display', 'view', 'bring up', 'see',
                    'เปิด', 'ไปที่', 'ไปหน้า', 'ไป', 'แสดง', 'ดู', 'พาไป', 'ขอดู', 'หน้า'])
_NEGATION = _group(["don't", 'dont', 'do not', 'not', 'never', 'cancel', 'stop', 'ไม่', 'อย่า', 'ยกเลิก', 'หยุด', 'ห้าม'])
_QUESTION = _group(['what', 'how', 'why', 'which', 'who', 'อะไร', 'ทำไม', 'อย่างไร', 'ยังไง', 'กี่', 'เท่าไร', 'เท่าไหร่', 'ไหน'])

_COUNT = _group(['how many', 'number of', 'count of', 'count', 'total number', 'กี่', 'จำนวน'])
_WHICH = _group(['which', 'what devices', 'list', 'เครื่องไหน', 'อุปกรณ์ไหน', 'ไหนบ้าง', 'อะไรบ้าง'])
_DEVICE = _group(['devices', 'device', 'hosts', 'host', 'machines', 'computers', 'ip addresses', 'ips', 'อุปกรณ์', 'เครื่อง', 'โฮสต์'])
_PORT = _group(['ports', 'port', 'พอร์ต'])
_CVE = _group(['cves', 'cve', 'vulnerabilities', 'vulnerability', 'vulns', 'ช่องโหว่'])
_SCAN_W = _group(['scan', 'scans', 'สแกน'])
_LATEST = _group(['latest', 'last', 'most recent', 'recent', 'ล่าสุด'])
_RUNNING = _group(['running', 'in progress', 'ongoing', 'กำลังสแกน', 'ทำงานอยู่', 'กำลังทำงาน'])
_NEXT = _group(['next', 'upcoming', 'ถัดไป', 'ครั้งหน้า', 'ครั้งต่อไป'])
_SCHEDULE = _group(['schedule', 'scheduled', 'schedules', 'ตามเวลา', 'ตั้งเวลา', 'กำหนดเวลา', 'ตารางเวลา'])
# a time window we do not compute: such a question goes to the AI instead of getting an all-time number that would be wrong
_TIME_SCOPE = _group(['today', 'yesterday', 'tonight', 'this week', 'this month', 'this year', 'last week', 'last month', 'last year',
                      'วันนี้', 'เมื่อวาน', 'สัปดาห์นี้', 'อาทิตย์นี้', 'เดือนนี้', 'ปีนี้', 'ที่ผ่านมา'])
# The severity words in Thai letters: a Thai speaker (or a Thai speech engine, Whisper writes English loanwords in Thai script) says คริติคอล, not
# "critical". Only longer, specific spellings are listed: a short one matches inside other words (ไฮ starts ไฮบริด / ไฮเวย์ / ไฮไลต์ / ไฮเปอร์,
# โล is in โลก / โลหะ, and สโลว์ is "slow").
_CRITICAL_TH = [stem + end for stem in ('คริติ', 'ครีติ') for end in ('คอล', 'กอล', 'คัล', 'กัล', 'เคิล', 'เคิ้ล', 'เกิล')]
_MEDIUM_TH = ['มีเดียม', 'มีเดี่ยม', 'มีเดี้ยม', 'มิเดียม']
# ไฮ is the usual Thai spelling of "high", so it is accepted, but only when it stands where a severity stands: after ช่องโหว่ / ระดับ / ความรุนแรง / ที่เป็น /
# CVE or at the start of a word group (a space or the start of the text), and before a question word (กี่ บ้าง ทั้งหมด ...) or the end. In ไฮบริด,
# ช่องโหว่ไฮบริด or ไฮเวย์ it is not the severity; _severity_doubt() then sends such a question to the AI instead of answering it for all severities.
# (Keep ำ out of this pattern, or run it through _clean() first: the text it is matched against has been NFKC-folded.)
_HIGH_TH = (r'(?:(?<=ช่องโหว่)|(?<=ระดับ)|(?<=ความรุนแรง)|(?<=ที่เป็น)|(?<=cve)|(?<=ซีวีอี)|(?<=\s)|^)'
            r'ไฮ(?=$|\s|กี่|บ้าง|ทั้งหมด|เท่า|มี|หรือ|ไหม|อยู่|ใน|ที่|และ)')
_LOW_TH = r'(?<!ส)โลว'     # โลว์ (and โลว when the engine drops the silent ์), but not สโลว์
_SEVERITY = [('critical', _group(['critical', 'วิกฤต', 'วิกฤติ'] + _CRITICAL_TH)),
             ('high', re.compile(_group(['high', 'สูง']).pattern + '|' + _HIGH_TH)),
             ('medium', _group(['medium', 'กลาง'] + _MEDIUM_TH)),
             ('low', re.compile(_group(['low', 'ต่ำ']).pattern + '|' + _LOW_TH))]

# A question that names a severity we cannot filter by must not be answered as if it had named none: "how many severe vulnerabilities" would get
# the number of ALL CVEs. So these make a CVE / device question `unknown` (it goes to the AI) instead of silently dropping the filter. Three kinds:
#   * other words for a level (severe, moderate, important, ร้ายแรง, the adjective รุนแรง; ปานกลาง is Medium and handled above). "ความรุนแรง" is the
#     noun "severity" and is fine ("how many CVEs by severity" is answered with the breakdown), so only the adjective counts
#   * a degree of one of the four (highest, lowest, highly, สูงสุด, ต่ำกว่า): "the highest CVEs" is not "the High CVEs"
#   * a Thai spelling that looks like one of the four words but is not in the lists above (คริตติคอล, มีเดีย, ไฮบริด): checked only on what is left
#     after the recognised severity words are cut out, so คริติคอล itself never counts as doubt
# It is a list, not a proof: a level word nobody thought of still gets through. Keep it to words that cannot be anything but a level.
_OTHER_LEVEL = re.compile(_group([
    'severe', 'severely', 'serious', 'seriously', 'moderate', 'moderately', 'important', 'major', 'minor', 'urgent', 'dangerous', 'negligible',
    'informational', 'extreme', 'extremely', 'highly', 'critically', 'highest', 'higher', 'lowest', 'lower',
    'ร้ายแรง', 'อันตราย', 'เร่งด่วน', 'สำคัญ', 'เล็กน้อย', 'โมเดอเรต', 'ซีเวียร์', 'ไมเนอร์', 'เมเจอร์',
    'สูงสุด', 'สูงที่สุด', 'สูงกว่า', 'ต่ำสุด', 'ต่ำที่สุด', 'ต่ำกว่า']).pattern + '|' + _clean(r'(?<!ความ)รุนแรง'))
_LEVEL_SHAPE = re.compile('ค[รล][ิี][ตทดธ]|ไฮ|ม[ีิ]เด[ีิ][่้]?ย|โลว')


def _severity_doubt(s):
    """True when the text names a level of severity that the filter in _SEVERITY would not apply (see above)."""
    if _OTHER_LEVEL.search(s):
        return True
    rest = s
    for _, rx in _SEVERITY:
        rest = rx.sub(' ', rest)
    return bool(_LEVEL_SHAPE.search(rest))


def _parse_fact(s):
    """A question about the data that app.py can answer exactly (the same figures as the dashboard), or None."""
    if _TIME_SCOPE.search(s) or re.search(r'\d', s):       # "today", "port 80", "last 5 scans", an address: not an all-time figure
        return None
    sev = [k for k, rx in _SEVERITY if rx.search(s)]
    if len(sev) > 1:
        return None
    sev = sev[0] if sev else None
    count, which, latest = _COUNT.search(s), _WHICH.search(s), _LATEST.search(s)
    dev, port, cve, scan = _DEVICE.search(s), _PORT.search(s), _CVE.search(s), _SCAN_W.search(s)
    fact = None
    if _NEXT.search(s) and _SCHEDULE.search(s):
        fact = 'next_schedule'
    elif _RUNNING.search(s) and scan:
        fact = 'running_scans'
    elif latest and scan and not count and not (dev or port or cve):
        fact = 'latest_scan'
    elif latest:
        return None                                          # "how many devices did the last scan find": a narrower question than we answer
    elif which and dev and cve:
        fact = 'devices_with_cves'
    elif count and dev and (cve or sev):
        fact = 'count_devices'
    elif count and cve:
        fact = 'count_cves'
    elif count and port:
        fact = 'count_ports'
    elif count and dev:
        fact = 'count_devices'
    if not fact:
        return None
    if fact in ('count_devices', 'count_cves', 'devices_with_cves') and _severity_doubt(s):
        return None                                          # a level we cannot filter by: not "all severities" (see _OTHER_LEVEL)
    return {'intent': 'fact', 'status': 'ok', 'fact': fact, 'severity': sev, 'message': ''}


def _parse_nav(s, lang):
    """"Open the devices page": needs a word for opening AND a page name. Returns None when it is not that."""
    if _NEGATION.search(s) or _QUESTION.search(s) or not _NAV_VERB.search(s):
        return None
    pages = [k for k, rx in _PAGE_WORDS.items() if rx.search(s)]
    if not pages:
        return None
    if len(pages) > 1:
        return {'intent': 'navigate', 'status': 'ambiguous', 'message': _msg('many_pages', lang, ', '.join(PAGES[k][0 if lang != 'en' else 1] for k in pages))}
    return {'intent': 'navigate', 'status': 'ok', 'page': pages[0], 'page_name': PAGES[pages[0]][1 if lang == 'en' else 0], 'message': ''}


def understand(text, lang='th'):
    r = parse_command(text, lang)
    if r['intent'] == 'scan':                                # a scan word always wins: "scan ..." is never taken for anything else
        return r
    s = _clean(text)
    if not s:
        return r
    return _parse_fact(s) or _parse_nav(s, lang) or r


# ───────────── what the speech engine offers ─────────────
MAX_ALTERNATIVES = 5
# When the best reading holds an address that lost or gained a number the engine's other readings may have it right. A refusal of any
# other kind ("300" is not an octet, a /8, a port ...) means the speaker really said something wrong, so it is shown, never replaced.
# tail_number / tail_sign (a size that may have been dropped, see _flag_tail) are in the set too: a reading that lost the sign is exactly what
# the engine's other reading of the same audio may have right.
_TAIL_REASONS = ('tail_number', 'tail_sign')
_RETRY_REASONS = ('incomplete', 'too_many') + _TAIL_REASONS


def is_usable(r):
    """True when a parser result is something the app can act on: a scan with a good target, a question about the data, or a page to open."""
    return (r['intent'] == 'scan' and r['status'] == 'ok') or r['intent'] == 'fact' or (r['intent'] == 'navigate' and r['status'] == 'ok')


_usable = is_usable


def _replaces(first, r):
    """May the engine's other reading `r` take the place of the best reading `first` (a refusal or not a command; None when it held no address)?
    Only a reading the app can act on. One more rule for a best reading refused because a SIZE may have been dropped (tail_number / tail_sign):
    it is replaced only by a reading that names the network itself (a scan target with a "/"), never by one that is just the bare address.
    That reading is the same audio with the tail lost, which would put the silent one-device scan back through the side door; the person is
    asked instead."""
    if not _usable(r):
        return False
    if first is not None and first.get('reason') in _TAIL_REASONS and r['intent'] == 'scan' and '/' not in r['target']:
        return False
    return True


def _readings(texts):
    seen = []
    for t in texts or []:
        t = str(t or '')[:300]
        if t.strip() and t not in seen:
            seen.append(t)
    return seen[:MAX_ALTERNATIVES]


def reply_best(texts, lang='th', scan_type=None):
    """understand_best() for the answer to "which target?" (see parse_target_reply). Returns (result or None, index, text); None means
    no reading holds an address, so the caller treats the text as a normal sentence."""
    seen = _readings(texts)
    if not seen:
        return None, 0, ''
    first = parse_target_reply(seen[0], lang, scan_type)
    if first is not None and first.get('reason') not in _RETRY_REASONS:      # a good answer, or an address that is wrong as spoken
        return first, 0, seen[0]
    for i, t in enumerate(seen[1:], 1):
        r = parse_target_reply(t, lang, scan_type)
        if r is not None and _replaces(first, r):
            return r, i, t
    return first, 0, seen[0]


def wants_other_reading(r):
    """The ONE rule for "is the engine's other reading worth looking at?": only when this result is not a command at all, or is an address that
    lost or gained a number, or one followed by a number or sign that may be a lost network size (tail_number / tail_sign). An address that is
    wrong as spoken (a number above 255, a reserved address, a /8, a port, two addresses) is shown, never replaced, and a usable command needs
    nothing else. understand_best() and the Whisper route (which tries a second language) both use it."""
    return r['intent'] == 'unknown' or (r['intent'] == 'scan' and r.get('reason') in _RETRY_REASONS)


def reply_wants_other_reading(r):
    """wants_other_reading() for the answer to "which target?" (r comes from parse_target_reply): True only for an address that lost or gained a
    number, or may have lost its network size. A good address, or one that is wrong as spoken, is final; None (no address in the text) is False
    too, so the caller falls back to the normal rule."""
    return r is not None and r.get('reason') in _RETRY_REASONS


def understand_best(texts, lang='th'):
    """texts: what the engine heard, its best reading first and then its alternatives. Returns (result, index, text): the first reading
    that is a usable command, but only when the best one was not a command or was an address with a missing or extra number. The digits of
    a reading are never edited: an alternative is the engine's own other transcript, and the confirmation card shows the text used."""
    seen = _readings(texts)
    if not seen:
        return _unknown(), 0, ''
    first = understand(seen[0], lang)
    if not wants_other_reading(first):
        return first, 0, seen[0]
    for i, t in enumerate(seen[1:], 1):
        r = understand(t, lang)
        if _replaces(first, r):
            return r, i, t
    return first, 0, seen[0]


def worth_asking_ai(text):
    """False for what is clearly not a sentence ("2nd 1.01.208.", a single word, noise): asking the AI about it only costs tokens."""
    s = _clean(text)
    return len(re.findall(r'[a-z]{3,}', s)) >= 2 or len(re.findall(r'[ก-ฮ]', s)) >= 6


def not_understood(text, lang='th'):
    return {'intent': 'unknown', 'status': '', 'message': _msg('not_understood', lang, str(text or '').strip())}
