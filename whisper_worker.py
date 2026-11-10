"""Clylar Whisper worker: turns a short spoken command into text with a LOCAL faster-whisper model.

A separate program on purpose (docs/voice-reliability-plan.md, section 9): the model stays loaded while the Flask dev server reloads, the app's own
Python environment needs no new packages, and when this program is not running the app simply keeps using the browser's speech engine.
It is NOT imported by app.py. Run it with the Python of the environment that has faster-whisper (the voice-lab folder's venv):

    <lab>\\venv\\Scripts\\python.exe whisper_worker.py --model <lab>\\models\\thai-large --instance <project>\\instance

Safety:
  * it listens on 127.0.0.1 only, and every request must carry the secret in the X-Worker-Token header (a random token kept in
    <instance>/whisper_worker.token, created on first start; app.py reads the same file), so another program on this computer cannot use it;
  * one request at a time, a request body of at most MAX_AUDIO_BYTES, nothing is written to disk and nothing is kept;
  * the hint given to the model (HINTS) holds command words only and NO address: a hint with example addresses made a model copy an address
    from the hint into its answer.
"""
import argparse
import glob
import io
import json
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_AUDIO_BYTES = 3 * 1024 * 1024
DEFAULT_PORT = 5057
MAX_NEW_TOKENS = 96          # a spoken command is far shorter; the cap stops a model that loops on repeated words (a Thai-pinned model hearing English did, for 20 s)
LANGS = ('th', 'en')
# Words only, NO digit and no example address (see the docstring).
# 2026-11-09, tried and NOT kept: a hint that names the spoken sign of a network ("slash" / "ทับ" / "สแลช"), because the model wrote "192.168.1.0 slash 24" as
# "192.168.1.0.24" (the slash became a dot). Measured on the 24 recorded voice-lab clips with .claude/tools/whisper_hint_ab.py (CPU, same settings as below):
# English, 15 clips (11 plain addresses, 4 spoken /24): the original hint 10 exact (plain 10 of 11, /24 0 of 4: all four wrote the slash as a dot,
# "192.168.1.0.24"); the sentence "A network is written as an address, the word slash, and the prefix length" 12 exact (/24 3 of 4, plain 9 of 11: it broke
# 192.168.0.100, "one by two, dot one six eight"); the shorter sentence "A network is written with a slash." and a hint that only added the words to the list: no
# change at all. The long sentence works by making the model SPELL numbers in words ("... dot zero slash twenty four"), the same mode that garbles a plain
# address, so it trades one failure for another. Thai: every hint gives the same result (plain Thai 11 of 11; "ทับ" is heard, "สแลช" is not). The original stays.
# The /24 failure is handled in voice_commands.py instead (the refusal says what was probably meant and asks). Re-run whisper_hint_ab.py for any new hint.
HINTS = {
    'en': 'scan, vulnerability scan, intense scan, discovery, show devices, how many devices. IP addresses are written with digits and dots.',
    'th': 'สแกน สแกนช่องโหว่ สแกนแบบละเอียด ดิสคัฟเวอรี่ เปิดหน้า อุปกรณ์ ที่อยู่ไอพีเขียนเป็นตัวเลขคั่นด้วยจุด',
}
DEFAULT_LANG = 'th'


def pick_language(value):
    """th or en; anything else is the default (the app always sends one of the two)."""
    v = str(value or '').strip().lower()
    return v if v in LANGS else DEFAULT_LANG


def load_or_create_token(instance_dir):
    """The shared secret: instance/whisper_worker.token (the app reads the same file). Created on first start."""
    path = os.path.join(instance_dir, 'whisper_worker.token')
    try:
        token = open(path, encoding='utf-8').read().strip()
        if len(token) >= 16:
            return token
    except OSError:
        pass
    token = secrets.token_hex(24)
    os.makedirs(instance_dir, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(token)
    return token


def add_cuda_dlls():
    """On Windows the CUDA libraries installed with pip (nvidia-cublas-cu12, nvidia-cudnn-cu12) must be put on the DLL search path."""
    root = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), '..', 'Lib', 'site-packages', 'nvidia')
    for d in glob.glob(os.path.join(root, '*', 'bin')):
        d = os.path.abspath(d)
        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(d)
        os.environ['PATH'] = d + os.pathsep + os.environ.get('PATH', '')


class Engine:
    """The loaded model and the one transcription at a time. `model` is anything with faster-whisper's transcribe(), so tests can fake it."""

    def __init__(self, model, info):
        self.model = model
        self.info = info                      # {model, device, compute}: what /health reports
        self.lock = threading.Lock()
        self.last_seconds = None
        self.count = 0

    def transcribe(self, audio_bytes, lang):
        lang = pick_language(lang)
        with self.lock:
            t0 = time.time()
            segments, info = self.model.transcribe(io.BytesIO(audio_bytes), language=lang, initial_prompt=HINTS[lang], beam_size=5, vad_filter=True,
                                                   condition_on_previous_text=False, without_timestamps=True, max_new_tokens=MAX_NEW_TOKENS,
                                                   temperature=0.0)      # no retry at higher temperatures: for a short command the first answer is the one that counts, and each retry cost seconds
            text = ' '.join(s.text.strip() for s in segments).strip()
            self.last_seconds = round(time.time() - t0, 2)
            self.count += 1
            return {'text': text, 'seconds': self.last_seconds, 'audio_s': round(getattr(info, 'duration', 0.0) or 0.0, 2), 'language': lang}


def _warm_up(model):
    """One second of silence through the model, so that a broken GPU setup (a missing CUDA library) fails NOW, at start, and not on the first command."""
    import numpy as np
    segments, _ = model.transcribe(np.zeros(16000, dtype='float32'), language='en', beam_size=1, vad_filter=False, without_timestamps=True, max_new_tokens=4)
    list(segments)


def load_model(path, device, compute):
    """Load on the GPU and warm it up; if either fails (no CUDA libraries, no memory) fall back to the CPU and say so. Returns (model, info)."""
    from faster_whisper import WhisperModel
    name = os.path.basename(path.rstrip('\\/'))
    try:
        model = WhisperModel(path, device=device, compute_type=compute)
        if device != 'cpu':
            _warm_up(model)
        return model, {'model': name, 'device': device, 'compute': compute}
    except Exception as e:           # noqa: BLE001  (any load or warm-up failure: try the CPU)
        if device == 'cpu':
            raise
        print('could not use %s (%s); using the CPU, which is slow' % (device, str(e)[:160]), flush=True)
        return WhisperModel(path, device='cpu', compute_type='int8'), {'model': name, 'device': 'cpu', 'compute': 'int8'}


def make_handler(engine, token):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'ClylarWhisper/1'
        timeout = 30                          # a client that stalls (sends nothing for 30 s) is dropped

        def log_message(self, fmt, *args):                    # no per-request log lines (they would hold nothing useful and no audio)
            pass

        def _send(self, code, obj):
            body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            return secrets.compare_digest(self.headers.get('X-Worker-Token', '').encode('utf-8', 'replace'), token.encode('utf-8'))       # bytes: a non-ASCII header must not raise

        def do_GET(self):
            if self.path.split('?')[0] != '/health':
                return self._send(404, {'error': 'not_found'})
            if not self._authorized():
                return self._send(403, {'error': 'forbidden'})
            self._send(200, dict(engine.info, ok=True, last_seconds=engine.last_seconds, count=engine.count))

        def do_POST(self):
            path, _, query = self.path.partition('?')
            try:
                n = int(self.headers.get('Content-Length') or 0)
            except ValueError:
                n = 0
            if n > MAX_AUDIO_BYTES:                          # refused without reading it
                self.close_connection = True
                return self._send(413, {'error': 'too_big'})
            audio = self.rfile.read(n) if n > 0 else b''    # the body is always read before any answer, so the reply is not lost in a reset connection
            if path != '/transcribe':
                return self._send(404, {'error': 'not_found'})
            if not self._authorized():
                return self._send(403, {'error': 'forbidden'})
            if not audio:
                return self._send(400, {'error': 'empty'})
            lang = dict(p.split('=', 1) for p in query.split('&') if '=' in p).get('lang')
            try:
                self._send(200, dict(engine.transcribe(audio, lang), ok=True))
            except Exception as e:           # noqa: BLE001  (an undecodable clip must not stop the worker)
                import traceback
                print('transcribe failed (%d bytes of audio, lang=%s): %s' % (len(audio), lang, traceback.format_exc()), flush=True)      # the reason goes to the log (instance/whisper_worker.log): the page only shows the code
                self._send(422, {'error': 'cannot_transcribe', 'detail': str(e)[:120]})
    return Handler


class Server(ThreadingHTTPServer):
    allow_reuse_address = False         # on Windows SO_REUSEADDR lets a second worker share the port: a second start must fail instead
    daemon_threads = True               # one thread per connection, so a stalled client cannot block the others (the engine itself still runs one request at a time)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--model', required=True, help='folder of a CTranslate2 Whisper model')
    ap.add_argument('--instance', required=True, help="the app's instance folder (the shared token is kept there)")
    ap.add_argument('--port', type=int, default=DEFAULT_PORT)
    ap.add_argument('--device', default='cuda')
    ap.add_argument('--compute', default='int8_float16')
    a = ap.parse_args()
    add_cuda_dlls()
    token = load_or_create_token(a.instance)
    print('loading %s on %s ...' % (a.model, a.device), flush=True)
    t0 = time.time()
    model, info = load_model(a.model, a.device, a.compute)
    engine = Engine(model, info)
    print('loaded in %.1f s (%s, %s). Listening on 127.0.0.1:%d' % (time.time() - t0, info['device'], info['compute'], a.port), flush=True)
    Server(('127.0.0.1', a.port), make_handler(engine, token)).serve_forever()


if __name__ == '__main__':
    main()
