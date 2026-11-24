"""Interface text in Thai and English: t('key') returns the text for the chosen language.

The texts live in two flat JSON files, locales/th.json and locales/en.json (the same keys in both). Rules:
- a key that is missing in the chosen language falls back to Thai, and a key that is missing everywhere is returned as the key itself, so a gap is
  VISIBLE on the page and never blank;
- a text is plain text (no HTML): Jinja escapes it. `{name}` marks a value that the caller fills in: t('tasks.started', n=5);
- check_i18n.py (in .claude/tools) lists keys that exist in only one file.
No Flask code here: the app decides which language is current (see ui_lang_now() in app.py)."""
import json
import os
import time

LANGS = ('th', 'en')
DEFAULT_LANG = 'th'

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'locales')
_cache = {}          # lang -> (modification stamp, {key: text})
_checked = {}        # lang -> when the files were last looked at
RECHECK_SECONDS = 1.0


def _files(lang):
    """locales/<lang>.json first, then every locales/<lang>/*.json in name order (one file per page keeps the work of several people apart;
    a key in a later file wins)."""
    out = [os.path.join(_DIR, '%s.json' % lang)]
    folder = os.path.join(_DIR, lang)
    if os.path.isdir(folder):
        out += [os.path.join(folder, n) for n in sorted(os.listdir(folder)) if n.endswith('.json')]
    return [p for p in out if os.path.isfile(p)]


def catalog(lang):
    """The texts of one language. A file that changed on disk is read again (so a restart is not needed while editing)."""
    hit = _cache.get(lang)
    now = time.monotonic()
    if hit is not None and now - _checked.get(lang, 0.0) < RECHECK_SECONDS:
        return hit[1]                      # a page asks for hundreds of texts: the disk is looked at once a second, not once per text (that was 3 ms each)
    _checked[lang] = now
    files = _files(lang)
    try:
        stamp = tuple((p, os.path.getmtime(p)) for p in files)
    except OSError:
        return {}
    if hit is None or hit[0] != stamp:
        data = {}
        for path in files:
            try:
                with open(path, encoding='utf-8') as f:
                    data.update(json.load(f))
            except (OSError, ValueError):
                pass
        hit = (stamp, {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str)})
        _cache[lang] = hit
    return hit[1]


def t(key, lang=None, **values):
    lang = lang if lang in LANGS else DEFAULT_LANG
    text = catalog(lang).get(key)
    if text is None and lang != DEFAULT_LANG:
        text = catalog(DEFAULT_LANG).get(key)
    if text is None:
        return key
    if values:
        try:
            return text.format(**values)
        except (KeyError, IndexError, ValueError):
            return text
    return text


def missing():
    """{lang: sorted keys that the other language has and this one lacks}: what a translator still has to write."""
    th, en = set(catalog('th')), set(catalog('en'))
    return {'th': sorted(en - th), 'en': sorted(th - en)}
