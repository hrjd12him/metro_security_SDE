import logging, threading, time
from datetime import datetime, timedelta, timezone
from okta_guard.core.config import (
    OKTA_DOMAIN, OKTA_API_TOKEN, SCAN_SCHEDULE_SECS, INITIAL_SCAN_MINUTES
)
from okta_guard.core.client import OktaClient
from okta_guard.core.store import (
    load_state, save_state, get_last_log_ts, set_last_log_ts, store_alert
)
from okta_guard.core.detectors import detect_from_event

log = logging.getLogger("scanner")
_thread: threading.Thread | None = None
_stop = threading.Event()

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def scan_logs_since_minutes(minutes: int) -> int:
    okta = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    count = 0
    for evt in okta.iter_system_log(since.isoformat()):
        for a in detect_from_event(evt, okta):
            store_alert(a); count += 1
        # update bookmark optimistically
        when = evt.get("published") or evt.get("eventTime")
        if when: set_last_log_ts(when)
    return count

def scan_logs_from_bookmark() -> int:
    load_state()
    last = get_last_log_ts()
    if not last:
        last = (datetime.now(timezone.utc) - timedelta(minutes=INITIAL_SCAN_MINUTES)).isoformat()
    okta = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    count = 0
    for evt in okta.iter_system_log(last):
        for a in detect_from_event(evt, okta):
            store_alert(a); count += 1
        when = evt.get("published") or evt.get("eventTime")
        if when: set_last_log_ts(when)
    return count

def _loop():
    load_state()
    while not _stop.is_set():
        try:
            processed = scan_logs_from_bookmark()
            log.info("Scheduled scan processed=%d", processed)
        except Exception as e:
            log.exception("scan failed: %s", e)
        _stop.wait(SCAN_SCHEDULE_SECS)

def start_scheduler():
    global _thread
    if _thread and _thread.is_alive(): return
    _stop.clear()
    _thread = threading.Thread(target=_loop, name="okta-scan", daemon=True)
    _thread.start()
    log.info("Scheduler started: every %ss", SCAN_SCHEDULE_SECS)

def stop_scheduler():
    _stop.set()
    if _thread: _thread.join(timeout=2)