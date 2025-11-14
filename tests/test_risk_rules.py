from datetime import datetime, timezone, timedelta
from app.risk_rules import detect_brute_force

def make_event(result, minutes_ago=1, ip="1.1.1.1"):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    return {
        "published": ts,
        "eventType": "user.authentication.sso",
        "actor": {"id": "user123", "alternateId": "user@example.com"},
        "outcome": {"result": result},
        "client": {"ipAddress": ip, "geographicalContext": {"country": "India"}},
    }

def test_brute_force_detection():
    events = [make_event("FAILURE", minutes_ago=i+5) for i in range(5)]
    events.append(make_event("SUCCESS", minutes_ago=0))
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0]["risk_type"] == "BRUTE_FORCE_SUCCESS"
