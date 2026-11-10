"""Runs scans in the background: a queue, a few worker threads, and a way to cancel a scan that is running.

No Flask and no database code lives here. app.py gives it `run_job(job_id)` (what to do with one queued job) through init(), puts job ids on
the queue with enqueue(), and asks for a running scan to stop with cancel(). While a job runs, controlled() makes a scanner.ScanControl
current for that thread, so scanner.ControlledScanner can kill nmap on a cancel and stop it when the scan's time is up.

Why threads inside the web app and not a separate service: a few admins, one machine, one SQLite file. The queue lives in memory, so a restart
loses it; app.py marks every job that was waiting or running at that moment as interrupted (recover_interrupted_jobs).
"""
import os
import queue
import threading
from contextlib import contextmanager

import scanner

MAX_CONCURRENT_SCANS = 2          # how many scans run at once; the others wait as "Queued"

# Seconds a scan may run before it is stopped and marked Failed ("timed out"). One table, by scan type; a type that is not listed gets DEFAULT.
SCAN_TIME_LIMITS = {
    'discovery': 1 * 3600,
    'fast_scan': 2 * 3600,
    'intense': 4 * 3600,
    'vuln_scan': 4 * 3600,
    'custom': 4 * 3600,
}
DEFAULT_TIME_LIMIT = 4 * 3600
TIME_LIMIT_ENV = 'CLYLAR_SCAN_TIME_LIMIT'     # seconds; when set, it replaces the table for every type (for tests and for a quick override)

_lock = threading.Lock()
_queue = queue.Queue()
_workers = []
_controls = {}                    # job id -> the ScanControl of a scan that is running right now
_run_job = None                   # what a worker does with one job id; set by init()


def time_limit_for(scan_type, all_ports=False, gentle=False, udp=False):
    """Seconds the scan type may run, or None for no limit (a limit of 0 in CLYLAR_SCAN_TIME_LIMIT switches the limit off).
    A scan of all 65,535 ports needs longer than a Fast scan's 2 hours: with the option on the limit is at least scanner.ALL_PORTS_TIME_LIMIT (6 h)."""
    raw = os.environ.get(TIME_LIMIT_ENV)
    if raw:
        try:
            value = float(raw)
            return value if value > 0 else None
        except ValueError:
            pass
    limit = SCAN_TIME_LIMITS.get(scan_type, DEFAULT_TIME_LIMIT)
    if all_ports and limit is not None and scan_type in ('fast_scan', 'intense', 'vuln_scan'):
        limit = max(limit, scanner.ALL_PORTS_TIME_LIMIT)
    if udp and limit is not None and scan_type in ('intense', 'vuln_scan'):
        limit = max(limit, scanner.UDP_TIME_LIMIT)       # a second nmap run, and UDP answers are slow
    if gentle and limit is not None and scan_type in ('fast_scan', 'intense', 'vuln_scan'):
        limit = max(limit, scanner.GENTLE_TIME_LIMIT)       # a Gentle scan is 10 to 40 times slower per host
    return limit


def init(run_job):
    """Sets what a worker does with a job id: run_job(job_id). Call once, before the first enqueue()."""
    global _run_job
    _run_job = run_job


def _worker():
    while True:
        job_id = _queue.get()
        try:
            if _run_job is not None:
                _run_job(job_id)
        except Exception:               # a crash in one job must not kill the worker that the next job needs
            import traceback
            traceback.print_exc()
        finally:
            _queue.task_done()


def _ensure_workers():
    """The workers start with the first job, in the process that really serves requests (the dev reloader's parent never gets here)."""
    with _lock:
        while len(_workers) < MAX_CONCURRENT_SCANS:
            t = threading.Thread(target=_worker, name='scan-worker-%d' % (len(_workers) + 1), daemon=True)
            t.start()
            _workers.append(t)


def enqueue(job_id):
    """Puts a job on the queue. The job row must already exist with status 'Queued'."""
    _ensure_workers()
    _queue.put(job_id)


@contextmanager
def controlled(job_id, scan_type, all_ports=False, gentle=False, udp=False):
    """Around one scan, in the worker's thread: makes a ScanControl current (so cancel() reaches nmap and the time limit applies) and
    removes it afterwards, even when the scan raises."""
    ctl = scanner.ScanControl(time_limit=time_limit_for(scan_type, all_ports, gentle, udp))
    with _lock:
        _controls[job_id] = ctl
    scanner.set_control(ctl)
    try:
        yield ctl
    finally:
        scanner.set_control(None)
        with _lock:
            _controls.pop(job_id, None)


def cancel(job_id):
    """Stops the scan of `job_id` if it is running in this process (kills its nmap). Returns True when there was one to stop; a job that is
    only waiting in the queue has no control, and app.py cancels it by changing its row (the worker skips a job that is no longer Queued)."""
    with _lock:
        ctl = _controls.get(job_id)
    if ctl is None:
        return False
    ctl.cancel()
    return True


def running_job_ids():
    with _lock:
        return sorted(_controls)


def progress_for(job_id):
    """What the scan of `job_id` last reported, if it is running in this process: {'fields': {...} or None, 'age': seconds since it was
    reported or None}. None when this process is not running that job (it waits, or it ended, or another process has it)."""
    with _lock:
        ctl = _controls.get(job_id)
    if ctl is None:
        return None
    fields, age = ctl.progress_snapshot()
    return {'fields': fields, 'age': age}


def queue_job_ids():
    """The job ids waiting for a worker, in the order they will start. A job cancelled while it waited stays in here until a worker takes it
    off and skips it, so a caller that shows positions filters this list by what the database says (still 'Queued')."""
    with _queue.mutex:
        return list(_queue.queue)


def queue_size():
    """How many job ids are waiting for a worker (jobs a worker has taken are not counted)."""
    return _queue.qsize()
