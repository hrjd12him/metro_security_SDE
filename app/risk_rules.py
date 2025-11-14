import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from collections import defaultdict
from typing import List, Dict, Any, Tuple
from .config import settings
from .models import Alert
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def _get_user_key(event: Dict[str, Any]) -> Tuple[str, str]:
    actor = event.get("actor", {}) or {}
    return actor.get("id", "unknown"), actor.get("alternateId", "unknown")


def _is_success(event: Dict[str, Any]) -> bool:
    outcome = event.get("outcome", {}) or {}
    return outcome.get("result") == "SUCCESS"


def _is_failure(event: Dict[str, Any]) -> bool:
    outcome = event.get("outcome", {}) or {}
    return outcome.get("result") == "FAILURE"


def _get_country(event: Dict[str, Any]) -> str:
    client = event.get("client", {}) or {}
    geo = client.get("geographicalContext", {}) or {}
    return geo.get("country", "UNKNOWN")


def _get_ip(event: Dict[str, Any]) -> str:
    client = event.get("client", {}) or {}
    return client.get("ipAddress", "UNKNOWN")


def _get_published_dt(event: Dict[str, Any]) -> datetime:
    # Okta uses 'published' (RFC3339). :contentReference[oaicite:8]{index=8}
    ts = event.get("published")
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def detect_brute_force(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    events_by_user = defaultdict(list)

    for ev in events:
        etype = ev.get("eventType", "")
        # Use authentication-related events; you can refine filter by eventType list. :contentReference[oaicite:9]{index=9}
        if "user.authentication" in etype or "user.session.start" in etype:
            uid, uname = _get_user_key(ev)
            events_by_user[(uid, uname)].append(ev)

    for (uid, uname), evs in events_by_user.items():
        evs.sort(key=_get_published_dt)
        fail_streak = 0
        last_ip = None

        for ev in evs:
            ip = _get_ip(ev)
            if _is_failure(ev):
                if last_ip is None or ip == last_ip:
                    fail_streak += 1
                else:
                    fail_streak = 1
                last_ip = ip
            elif _is_success(ev):
                if fail_streak >= settings.BRUTE_FORCE_FAIL_THRESHOLD and ip == last_ip:
                    alerts.append({
                        "user_id": uid,
                        "username": uname,
                        "risk_type": "BRUTE_FORCE_SUCCESS",
                        "description": f"{fail_streak} failed logins followed by success from IP {ip}",
                        "timestamp": _get_published_dt(ev),
                        "severity": "high"
                    })
                fail_streak = 0
                last_ip = ip

    return alerts


def detect_unusual_geo_and_hours(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts = []
    tz = ZoneInfo(settings.BUSINESS_TZ)

    for ev in events:
        etype = ev.get("eventType", "")
        if not ("user.authentication" in etype or "user.session.start" in etype):
            continue
        if not _is_success(ev):
            continue

        uid, uname = _get_user_key(ev)
        country = _get_country(ev)
        ts_utc = _get_published_dt(ev)
        local_ts = ts_utc.astimezone(tz)
        hour = local_ts.hour

        outside_hours = not (settings.BUSINESS_HOURS_START <= hour < settings.BUSINESS_HOURS_END)
        unusual_geo = country not in settings.ALLOWED_COUNTRIES

        if unusual_geo:
            severity = "medium"
            if outside_hours:
                severity = "high"
            alerts.append({
                "user_id": uid,
                "username": uname,
                "risk_type": "UNUSUAL_GEO",
                "description": f"Login from {country} at {local_ts.isoformat()}",
                "timestamp": ts_utc,
                "severity": severity
            })
        elif outside_hours:
            alerts.append({
                "user_id": uid,
                "username": uname,
                "risk_type": "OFF_HOURS_LOGIN",
                "description": f"Successful login at {local_ts.isoformat()} outside business hours",
                "timestamp": ts_utc,
                "severity": "medium"
            })

    return alerts


def evaluate_mfa_risks(
    db: Session,
    okta_client,
    base_alerts: List[Dict[str, Any]]
) -> List[Alert]:
    """
    Take base alerts (login anomalies), enrich with MFA info,
    escalate severity + auto suspend where needed, and persist to DB.
    """
    alerts_models: List[Alert] = []
    seen_users = {(a["user_id"], a["username"]) for a in base_alerts}

    # For all users in anomalies, fetch MFA factors once
    user_factors_map = {}
    for uid, _ in seen_users:
        user_factors_map[uid] = okta_client.get_user_factors(uid)

    for a in base_alerts:
        uid = a["user_id"]
        factors = user_factors_map.get(uid, [])
        factor_types = {f.get("factorType") for f in factors}

        has_mfa = len(factors) > 0
        only_sms = has_mfa and factor_types == {"sms"}

        severity = a["severity"]
        action_taken = "none"

        if not has_mfa:
            extra_desc = " User has NO MFA enrolled."
            severity = "high" if severity != "high" else "critical"
            a["risk_type"] += "_NO_MFA"
            a["description"] += extra_desc

        elif only_sms:
            extra_desc = " User only has SMS MFA, treated as weak factor."
            if severity == "low":
                severity = "medium"
            elif severity in ("medium", "high"):
                severity = "high"
            a["risk_type"] += "_WEAK_SMS"
            a["description"] += extra_desc

        # Auto-suspend rule: any brute-force or unusual geo + no/weak MFA
        if ("BRUTE_FORCE" in a["risk_type"] or "UNUSUAL_GEO" in a["risk_type"]) and (not has_mfa or only_sms):
            if okta_client.suspend_user(uid):
                action_taken = "auto_suspend"
                severity = "critical"

        alert_obj = Alert(
            user_id=a["user_id"],
            username=a["username"],
            risk_type=a["risk_type"],
            description=a["description"],
            timestamp=a["timestamp"],
            severity=severity,
            action_taken=action_taken
        )
        db.add(alert_obj)
        alerts_models.append(alert_obj)

    db.commit()
    db.flush()
    return alerts_models
