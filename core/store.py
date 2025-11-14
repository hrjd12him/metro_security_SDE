import os, json, logging
from typing import Optional, List
from datetime import datetime, timezone
from collections import defaultdict, deque

from okta_guard.core.models import Alert
from okta_guard.core.config import ALERTS_JSONL_PATH, STATE_PATH

log = logging.getLogger("store")

_alerts: dict[str, Alert] = {}
_state: dict = {"last_log_ts": None, "user_geo": {}, "user_failures": {}}

def _ensure_dirs():
    os.makedirs(os.path.dirname(ALERTS_JSONL_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)

def load_state():
    _ensure_dirs()
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            _state.update(data)
    except Exception:
        pass

def save_state():
    _ensure_dirs()
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(_state, f)
    except Exception as e:
        log.warning("save_state failed: %s", e)

def set_last_log_ts(iso: str):
    _state["last_log_ts"] = iso
    save_state()

def get_last_log_ts() -> Optional[str]:
    return _state.get("last_log_ts")

def get_user_geo_baseline(email: str) -> set[str]:
    m = _state.setdefault("user_geo", {})
    s = set(m.get(email, []))
    return s

def update_user_geo_baseline(email: str, country: str):
    m = _state.setdefault("user_geo", {})
    s = set(m.get(email, []))
    s.add(country)
    m[email] = sorted(list(s))
    save_state()

def get_user_failures(email: str) -> list[str]:
    m = _state.setdefault("user_failures", {})
    return list(m.get(email, []))

def set_user_failures(email: str, iso_list: list[str]):
    m = _state.setdefault("user_failures", {})
    m[email] = iso_list
    save_state()

def store_alert(a: Alert):
    _alerts[a.id] = a
    _ensure_dirs()
    try:
        with open(ALERTS_JSONL_PATH, "a", encoding="utf-8") as f:
            f.write(a.model_dump_json() + "\n")
    except Exception as e:
        log.warning("alerts append failed: %s", e)

def get_alerts(kind: str | None = None, severity: str | None = None, user: str | None = None) -> List[Alert]:
    vals = list(_alerts.values())
    if kind: vals = [a for a in vals if a.kind == kind]
    if severity: vals = [a for a in vals if a.severity == severity]
    if user: vals = [a for a in vals if (a.user_id == user or a.user_email == user)]
    return sorted(vals, key=lambda x: x.ts, reverse=True)

def get_alert(alert_id: str) -> Optional[Alert]:
    return _alerts.get(alert_id)