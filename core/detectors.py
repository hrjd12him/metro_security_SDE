import logging
from typing import Any, Dict, List
from datetime import datetime, timedelta, timezone
from okta_guard.core.models import Alert
from okta_guard.core.store import (
    get_user_geo_baseline, update_user_geo_baseline,
    get_user_failures, set_user_failures, store_alert
)
from okta_guard.core.config import (
    TZINFO, BUSINESS_HOURS_START, BUSINESS_HOURS_END,
    BRUTE_FAIL_THRESHOLD, BRUTE_WINDOW_MIN, AUTO_SUSPEND_KINDS
)
from okta_guard.core.client import OktaClient

log = logging.getLogger("detectors")

def _parse_ts(evt: Dict[str,Any]) -> datetime:
    s = evt.get("published") or evt.get("eventTime")
    if not s: return datetime.now(timezone.utc)
    return datetime.fromisoformat(s.replace("Z","+00:00"))

def _actor(evt: Dict[str,Any]):
    a = evt.get("actor") or {}
    return a.get("id"), a.get("alternateId") or a.get("displayName")

def _client(evt: Dict[str,Any]):
    c = evt.get("client") or {}
    ip = c.get("ipAddress")
    geo = c.get("geographicalContext") or {}
    country = (geo.get("country") or "").upper()
    city = geo.get("city") or ""
    return ip, country, city

def detect_from_event(evt: Dict[str,Any], okta: OktaClient) -> List[Alert]:
    out: List[Alert] = []
    et = str(evt.get("eventType",""))
    res = ((evt.get("outcome") or {}).get("result") or "").upper()
    ts = _parse_ts(evt)
    user_id, email = _actor(evt)
    ip, country, city = _client(evt)

    # Track failures
    if et.startswith("user.authentication") and res == "FAILURE":
        lst = get_user_failures(email)
        lst.append(ts.isoformat())
        cutoff = ts - timedelta(minutes=BRUTE_WINDOW_MIN)
        lst = [x for x in lst if datetime.fromisoformat(x) >= cutoff]
        set_user_failures(email, lst)

    # Success logins (SSO/MFA/session start)
    if et in ("user.session.start", "user.authentication.sso", "user.authentication.auth_via_mfa") and res == "SUCCESS":
        # Brute-force→success
        lst = get_user_failures(email)
        cutoff = ts - timedelta(minutes=BRUTE_WINDOW_MIN)
        fails_recent = sum(1 for x in lst if datetime.fromisoformat(x) >= cutoff)
        if fails_recent >= BRUTE_FAIL_THRESHOLD:
            a = Alert(
                kind="bruteforce_success", severity="high",
                user_id=user_id, user_email=email, ts=ts.isoformat(),
                evidence={"fails_recent": fails_recent, "window_min": BRUTE_WINDOW_MIN, "ip": ip},
                recommended_action="Auto-suspend and require credential reset."
            )
            if "bruteforce_success" in AUTO_SUSPEND_KINDS and user_id:
                try:
                    okta.suspend_user(user_id)
                    a.remediation_status = "auto_suspended"
                except Exception:
                    pass
            store_alert(a); out.append(a)
            set_user_failures(email, [])  # reset after alert

        # Off-hours
        hour_local = ts.astimezone(TZINFO).hour
        if not (BUSINESS_HOURS_START <= hour_local < BUSINESS_HOURS_END):
            a = Alert(
                kind="off_hours_login", severity="medium",
                user_id=user_id, user_email=email, ts=ts.isoformat(),
                evidence={"hour_local": hour_local, "ip": ip, "country": country, "city": city},
                recommended_action="Step-up verification or verify business need."
            )
            store_alert(a); out.append(a)

        # Unusual geo
        if country:
            seen = get_user_geo_baseline(email)
            if seen and country not in seen:
                a = Alert(
                    kind="unusual_geo", severity="medium",
                    user_id=user_id, user_email=email, ts=ts.isoformat(),
                    evidence={"new_country": country, "known_countries": sorted(list(seen))[:10], "ip": ip},
                    recommended_action="Step-up auth; confirm with user."
                )
                store_alert(a); out.append(a)
            update_user_geo_baseline(email, country)

    return out
