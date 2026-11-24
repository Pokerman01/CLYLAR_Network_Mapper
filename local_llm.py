"""A local language model (Ollama) as the other engine of the assistant, next to Gemini.

Only the text answers come through here: the typed chat and the voice fallback. Speech to text stays with Whisper (whisper_worker.py).
No Flask and no database in this file, so test_local_llm.py can run it against a fake server.

What it talks to: Ollama's own HTTP API (/api/chat, /api/tags, /api/ps), because that API accepts per-request options such as `num_gpu`
(how many layers of the model go on the graphics card) and `num_ctx` (the context size). The OpenAI-style endpoint does not.

Rules, each tested:
- the server address must be this computer (localhost, 127.x.x.x, ::1): the prompt carries summary figures of the scan data and must not
  be aimed at another machine by a typo or by a setting. No proxy is ever used (an NT HTTP_PROXY must not see the prompt);
- nothing here guesses: a missing model, a server that is not there, a timeout and an answer with no text are each their own error code;
- a model that "thinks" aloud (Qwen3-based Typhoon) has its <think> block cut out, and an answer that was only thinking is an error, not an empty bubble;
- a call can be STOPPED (chat(..., cancel=<threading.Event>)): the call owns its socket and reads it in slices of a tenth of a second, so an event that another
  thread sets ends the call within a tenth of a second and closes the connection, which is how Ollama learns the answer is no longer wanted and stops generating
  (a stopped answer should not keep the graphics card busy for a minute). A blocking read cannot be woken from another thread on Windows, hence the slices."""
import http.client
import io
import ipaddress
import json
import re
import select
import socket
import ssl
import time
from urllib.parse import urlsplit

import requests

DEFAULT_URL = 'http://127.0.0.1:11434'          # where Ollama listens unless told otherwise
DEFAULT_MODEL = 'scb10x/typhoon2.5-qwen3-4b'    # the name of the official Ollama build (Q4_K_M, `ollama pull scb10x/typhoon2.5-qwen3-4b`); the Settings page lists what is really installed
DEFAULT_GPU_LAYERS = 20                         # of 36 in a 4B Qwen3 model: leaves room for Whisper on a 6 GB card (an estimate, not measured)
NUM_CTX = 8192                                  # context window asked for; Ollama's own default (2048 to 4096) cuts the data part of our prompts
KEEP_ALIVE = '5m'                               # how long Ollama keeps the model loaded after an answer (then the card's memory is free again)
TEMPERATURE = 0.3                               # factual answers about the user's own data: little invention
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 240                              # a non-streaming answer arrives whole; 900 tokens at a few tokens a second is minutes
PROBE_TIMEOUT = 6
MAX_GPU_LAYERS = 200
_MODEL_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/@\-]{0,99}')
_THINK_RE = re.compile(r'<think>.*?</think>', re.DOTALL | re.IGNORECASE)


class LocalLLMError(Exception):
    """`code` says what went wrong: unreachable, timeout, model_missing, not_ollama, bad_answer, empty, http_<status>."""
    def __init__(self, code, detail=''):
        super().__init__(code if not detail else '%s: %s' % (code, detail))
        self.code = code
        self.detail = detail


def clean_url(text):
    """'http://host:port' for a plain address of THIS computer, else None. No path, query, user name or other host."""
    text = str(text or '').strip().rstrip('/')
    if not text or len(text) > 100:
        return None
    if '://' not in text:
        text = 'http://' + text
    try:
        parts = urlsplit(text)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not host or '@' in parts.netloc:       # an '@' is a user name, even an empty one
        return None
    if parts.path not in ('', '/') or parts.query or parts.fragment:
        return None
    if host != 'localhost':
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return None
        except ValueError:
            return None
    if port is not None and not 1 <= port <= 65535:
        return None
    if host == 'localhost':
        host = '127.0.0.1'                      # Ollama listens on IPv4; "localhost" can make Windows try IPv6 first and stall
    shown = '[%s]' % host if ':' in host else host
    return '%s://%s:%d' % (parts.scheme, shown, port or 11434)


def clean_model(text):
    text = str(text or '').strip()
    return text if _MODEL_RE.fullmatch(text) else None


def clean_gpu_layers(value):
    """(ok, layers). Empty = automatic (None): Ollama decides from the memory that is free when the model loads. Else a whole number 0 to 200
    (0 = all on the processor). A bool, a fraction or a negative number is refused."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return True, None
    if isinstance(value, bool):
        return False, None
    if isinstance(value, float) and value == int(value):
        value = int(value)
    if isinstance(value, str) and value.strip().isascii() and value.strip().isdigit():       # not other scripts' digits
        value = int(value.strip())
    if isinstance(value, int) and 0 <= value <= MAX_GPU_LAYERS:
        return True, value
    return False, None


def strip_thinking(text):
    """Removes <think>...</think>. An opening tag that never closes (the answer ran out of tokens while thinking) drops everything from it on."""
    text = _THINK_RE.sub('', str(text or ''))
    low = text.lower()
    if '<think>' in low:
        text = text[:low.index('<think>')]
    return text.replace('</think>', '').strip()


def _session():
    s = requests.Session()
    s.trust_env = False                 # never through a proxy from the environment, and no .netrc
    return s


def build_payload(model, system_prompt, messages, max_tokens, gpu_layers, think=False):
    msgs = [{'role': 'system', 'content': str(system_prompt)}]
    for m in messages or []:
        msgs.append({'role': 'user' if m.get('role') == 'user' else 'assistant', 'content': str(m.get('content', ''))})
    options = {'num_predict': int(max_tokens), 'num_ctx': NUM_CTX, 'temperature': TEMPERATURE}
    if gpu_layers is not None:
        options['num_gpu'] = int(gpu_layers)
    payload = {'model': model, 'messages': msgs, 'stream': False, 'keep_alive': KEEP_ALIVE, 'options': options}
    if think is not None:
        payload['think'] = think        # asks a model that can think to answer at once (an older Ollama ignores the field)
    return payload


def _error_text(raw):
    try:
        e = json.loads(raw.decode('utf-8', 'replace')).get('error')
        return str(e)[:200] if e else ''
    except Exception:
        return ''


class _Replay:
    """Hands bytes that were already read to http.client, which only wants something with makefile()."""
    def __init__(self, data):
        self._data = data

    def makefile(self, *args, **kwargs):
        return io.BytesIO(self._data)


def _post_json(url, path, payload, cancel=None):
    """POSTs one JSON body and reads the whole answer on a socket of our own, in slices of a tenth of a second, so `cancel` (a threading.Event) is noticed at once.
    Returns (status, body bytes). Raises LocalLLMError: cancelled, timeout (nothing arrived for READ_TIMEOUT seconds), unreachable, bad_answer.
    No proxy is ever used (nothing here reads the environment)."""
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port
    body = json.dumps(payload).encode('utf-8')
    head = ('POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
            % (path, host, port, len(body))).encode('ascii')
    sock = None
    try:
        if cancel is not None and cancel.is_set():
            raise LocalLLMError('cancelled')
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        if parts.scheme == 'https':
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(head + body)
        buf = bytearray()
        last = time.monotonic()
        while True:
            if cancel is not None and cancel.is_set():
                raise LocalLLMError('cancelled')
            if time.monotonic() - last > READ_TIMEOUT:
                raise LocalLLMError('timeout')
            ready = select.select([sock], [], [], 0.1)[0]
            if not ready and not (hasattr(sock, 'pending') and sock.pending()):
                continue
            chunk = sock.recv(65536)
            if not chunk:                                     # the server closed the connection: that is the end of the answer ("Connection: close")
                break
            buf += chunk
            last = time.monotonic()
        try:
            resp = http.client.HTTPResponse(_Replay(bytes(buf)))
            resp.begin()
            return resp.status, resp.read()
        except (http.client.HTTPException, ValueError, OSError):
            raise LocalLLMError('bad_answer')
    except LocalLLMError:
        raise
    except socket.timeout:
        raise LocalLLMError('timeout')
    except OSError as e:
        raise LocalLLMError('unreachable', type(e).__name__)
    finally:
        if sock is not None:
            try:
                sock.close()                                  # also what tells Ollama to stop generating when the call was cancelled
            except Exception:
                pass


def chat(url, model, system_prompt, messages, max_tokens=800, gpu_layers=None, cancel=None):
    """(text, usage, note). `usage` has the same keys Gemini reports (promptTokenCount, candidatesTokenCount, totalTokenCount) so the usage
    table can count both. `note` is None, or a warning about the call (the prompt filled the whole context window, so its start may be cut).
    `cancel`: a threading.Event; setting it from another thread stops the call (LocalLLMError code 'cancelled') and closes the connection to Ollama."""
    payload = build_payload(model, system_prompt, messages, max_tokens, gpu_layers)
    status, raw_body = 0, b''
    for attempt in range(2):
        status, raw_body = _post_json(url, '/api/chat', payload, cancel)
        if status == 400 and 'think' in payload and 'think' in _error_text(raw_body).lower():
            payload = dict(payload)
            del payload['think']                  # this model or this Ollama does not take the option: ask again without it
            continue
        break
    if status == 404:
        raise LocalLLMError('model_missing', _error_text(raw_body))
    if not 200 <= status < 300:
        raise LocalLLMError('http_%d' % status, _error_text(raw_body))
    try:
        body = json.loads(raw_body.decode('utf-8'))
        raw = body['message']['content']
    except Exception:
        raise LocalLLMError('bad_answer')
    text = strip_thinking(raw)
    if not text:
        raise LocalLLMError('empty')
    pin, pout = body.get('prompt_eval_count'), body.get('eval_count')
    pin = pin if isinstance(pin, int) else None
    pout = pout if isinstance(pout, int) else None
    usage = {'promptTokenCount': pin, 'candidatesTokenCount': pout,
             'totalTokenCount': (pin or 0) + (pout or 0) if (pin is not None or pout is not None) else None,
             'truncated': body.get('done_reason') == 'length'}      # Ollama says "length" when it stopped at num_predict: the answer is only the start
    note = 'prompt filled the context window' if pin is not None and pin >= NUM_CTX - 32 else None
    return text, usage, note


def _same_model(wanted, installed):
    """'name' matches 'name:latest', so a model typed without a tag is found."""
    if wanted == installed:
        return True
    return ':' not in wanted and installed == wanted + ':latest'


def probe(url, model):
    """Reads what Ollama says about itself; no tokens, no model load. Returns {status, models, gpu_percent}.
    status: ok, model_missing, unreachable, timeout, not_ollama, http_<n>. `models` are the installed names (at most 40). `gpu_percent` is how much
    of the wanted model sits on the graphics card right now (None when it is not loaded, so nothing is claimed)."""
    sess = _session()
    try:
        r = sess.get(url + '/api/tags', timeout=PROBE_TIMEOUT)
    except requests.exceptions.ConnectionError:
        return {'status': 'unreachable', 'models': [], 'gpu_percent': None}
    except requests.exceptions.Timeout:
        return {'status': 'timeout', 'models': [], 'gpu_percent': None}
    except requests.exceptions.RequestException:
        return {'status': 'unreachable', 'models': [], 'gpu_percent': None}
    if not r.ok:
        return {'status': 'http_%d' % r.status_code, 'models': [], 'gpu_percent': None}
    try:
        names = [str(m['name']) for m in r.json()['models']]
    except Exception:
        return {'status': 'not_ollama', 'models': [], 'gpu_percent': None}
    out = {'status': 'ok' if any(_same_model(model, n) for n in names) else 'model_missing', 'models': names[:40], 'gpu_percent': None}
    if out['status'] == 'ok':
        try:
            for m in sess.get(url + '/api/ps', timeout=PROBE_TIMEOUT).json().get('models', []):
                if _same_model(model, str(m.get('name', ''))) and isinstance(m.get('size'), int) and m['size'] > 0:
                    out['gpu_percent'] = round(100 * int(m.get('size_vram') or 0) / m['size'])
        except Exception:
            pass
    return out
