"""Turns the scan report's HTML (templates/scan_report.html, rendered with print_mode) into a PDF with a headless Edge or Chrome.

Why a browser: the old PDF engine (xhtml2pdf) shows Thai as black boxes and ignores flex / grid layout, so it cannot print the report's
design. A browser prints exactly what the report page shows, Thai included. The browser is driven over the DevTools protocol so the
page can be waited for properly: the report sets window.__reportReady once its network diagram is drawn, and the fonts must be loaded.

Nothing here is a web service: the page is written to a temporary folder, opened with file://, printed and thrown away. Each run uses
its own throw-away browser profile, so it never touches (or waits for) the user's own browser. One PDF at a time (a browser is about
100 MB and a few seconds); a second request waits for its turn.

Needs: Edge or Chrome on the machine that runs Clylar (Windows has Edge), the `websocket-client` package, and internet for the CDN
files the report page loads (the diagram library and the Sarabun font), the same as the rest of the app.
Raises ReportPdfError for anything that goes wrong; the caller falls back to the old export."""
import base64
import glob
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

WAIT_JS = 'window.__reportReady === true && document.fonts.status === "loaded"'
_lock = threading.Lock()
WORK_PREFIX = 'clylar_report_'
STALE_SECONDS = 30 * 60        # an export takes at most ~75 s, so a work folder this old belongs to one that died (e.g. the server was restarted in the middle of it)


class ReportPdfError(Exception):
    pass


def _remove_tree(path, tries=8, delay=0.25):
    """shutil.rmtree that survives a browser that has not quite let go of its profile yet (Windows refuses to delete an open file, and rmtree with
    ignore_errors would silently leave the folder behind). True when the folder is gone."""
    for _ in range(tries):
        shutil.rmtree(path, ignore_errors=True)
        if not os.path.exists(path):
            return True
        time.sleep(delay)
    return not os.path.exists(path)


def sweep_stale(older_than=STALE_SECONDS, root=None):
    """Delete leftover work folders (clylar_report_*) older than `older_than` seconds and return their paths. Younger ones are never touched: they may
    belong to an export that is running right now in another process. Never raises."""
    gone = []
    try:
        now = time.time()
        for p in glob.glob(os.path.join(root or tempfile.gettempdir(), WORK_PREFIX + '*')):
            try:
                if os.path.isdir(p) and now - os.path.getmtime(p) > older_than and _remove_tree(p, tries=3, delay=0.1):
                    gone.append(p)
            except OSError:
                pass
    except Exception:
        pass
    return gone


def _kill_tree(proc):
    """Stop OUR browser and the helper processes it started (on Windows `proc.kill()` leaves them running with the profile folder open)."""
    try:
        if os.name == 'nt':
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception:
        pass
    try:
        proc.kill()
        proc.wait(10)
    except Exception:
        pass


def find_browser():
    """Path of an Edge / Chrome / Chromium executable, or None. CLYLAR_BROWSER (a full path) overrides the search."""
    env = os.environ.get('CLYLAR_BROWSER')
    if env and os.path.isfile(env):
        return env
    found = []
    for base in (os.environ.get('ProgramFiles(x86)'), os.environ.get('ProgramFiles'), os.environ.get('LOCALAPPDATA')):
        if base:
            found += [os.path.join(base, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
                      os.path.join(base, 'Google', 'Chrome', 'Application', 'chrome.exe')]
    for name in ('msedge', 'microsoft-edge', 'google-chrome', 'chrome', 'chromium', 'chromium-browser'):
        p = shutil.which(name)
        if p:
            found.append(p)
    found += ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
    return next((p for p in found if p and os.path.isfile(p)), None)


def html_to_pdf(html, timeout=75, scale=2.0):
    """The PDF (bytes) of an HTML string, printed on A4 landscape the way the page's own @page rules ask. `scale` is the device pixel
    ratio the page is drawn at (canvases such as the diagram come out sharper at 2)."""
    browser = find_browser()
    if not browser:
        raise ReportPdfError('no Edge / Chrome found (set CLYLAR_BROWSER to its full path)')
    try:
        import websocket
    except ImportError:
        raise ReportPdfError('the websocket-client package is not installed (pip install -r requirements.txt)')
    if not _lock.acquire(timeout=timeout):
        raise ReportPdfError('another report is still being printed')
    sweep_stale()                                                    # folders of exports that died earlier (the lock is ours, so none of them is ours)
    work = tempfile.mkdtemp(prefix=WORK_PREFIX)
    proc = ws = None
    try:
        page_file = os.path.join(work, 'report.html')
        with open(page_file, 'w', encoding='utf-8') as f:
            f.write(html)
        profile = os.path.join(work, 'profile')
        cmd = [browser, '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync',
               '--hide-scrollbars', '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank']
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        deadline = time.time() + timeout

        port_file = os.path.join(profile, 'DevToolsActivePort')
        while not os.path.isfile(port_file):
            if proc.poll() is not None:
                raise ReportPdfError('the browser exited at start-up (code %s)' % proc.returncode)
            if time.time() > deadline:
                raise ReportPdfError('the browser did not start in time')
            time.sleep(.15)
        time.sleep(.2)
        port = int(open(port_file).read().split()[0])
        target = None
        while target is None:
            try:
                tabs = json.load(urllib.request.urlopen('http://127.0.0.1:%d/json' % port, timeout=5))
                target = next((t for t in tabs if t.get('type') == 'page'), None)
            except Exception:
                pass
            if target is None:
                if time.time() > deadline:
                    raise ReportPdfError('could not reach the browser\'s debugging port')
                time.sleep(.15)

        ws = websocket.create_connection(target['webSocketDebuggerUrl'], timeout=timeout, suppress_origin=True)
        seq = [0]

        def call(method, **params):
            seq[0] += 1
            mid = seq[0]
            ws.send(json.dumps({'id': mid, 'method': method, 'params': params}))
            while True:
                m = json.loads(ws.recv())
                if m.get('id') == mid:
                    if 'error' in m:
                        raise ReportPdfError('%s: %s' % (method, m['error'].get('message', m['error'])))
                    return m.get('result', {})

        call('Page.enable')
        call('Runtime.enable')
        call('Emulation.setDeviceMetricsOverride', width=1123, height=794, deviceScaleFactor=scale, mobile=False)
        call('Page.navigate', url=pathlib.Path(page_file).as_uri())
        while True:
            ready = call('Runtime.evaluate', expression=WAIT_JS, returnByValue=True).get('result', {}).get('value')
            if ready:
                break
            if time.time() > deadline:
                raise ReportPdfError('the report page did not finish drawing in time')
            time.sleep(.25)
        data = call('Page.printToPDF', printBackground=True, preferCSSPageSize=True, displayHeaderFooter=False,
                    marginTop=0, marginBottom=0, marginLeft=0, marginRight=0)['data']
        pdf = base64.b64decode(data)
        if not pdf.startswith(b'%PDF-'):
            raise ReportPdfError('the browser did not return a PDF')
        return pdf
    except ReportPdfError:
        raise
    except Exception as e:                                           # anything else (a closed socket, a timeout...) is the same for the caller
        raise ReportPdfError('%s: %s' % (type(e).__name__, e))
    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:
            pass
        if proc is not None:
            _kill_tree(proc)
        _remove_tree(work)
        _lock.release()
