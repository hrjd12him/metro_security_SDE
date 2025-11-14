from fastapi import APIRouter, HTTPException, Query
from okta_guard.core.store import get_alerts, get_alert, store_alert
from okta_guard.core.config import OKTA_DOMAIN, OKTA_API_TOKEN
from okta_guard.core.client import OktaClient
from okta_guard.tasks.scanners import scan_logs_since_minutes
from okta_guard.core.mfa_audit import audit_mfa

router = APIRouter()

@router.get("/health")
def health():
    return {"ok": True}

@router.get("/alerts")
def list_alerts(kind: str | None = None, severity: str | None = None, user: str | None = None):
    items = get_alerts(kind=kind, severity=severity, user=user)
    return {"alerts": [a.model_dump() for a in items]}

@router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: str):
    a = get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return a.model_dump()

@router.post("/remediate/{user_id}")
def remediate_suspend(user_id: str):
    okta = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    okta.suspend_user(user_id)
    return {"status": "suspended", "user_id": user_id}

@router.post("/rescan")
def rescan(since_minutes: int = Query(60, ge=1, le=1440)):
    processed = scan_logs_since_minutes(since_minutes)
    return {"processed_alerts": processed, "since_minutes": since_minutes}

@router.post("/scan/mfa")
def run_mfa():
    okta = OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN)
    alerts = audit_mfa(okta)
    for a in alerts:
        store_alert(a)
    return {"alerts_added": len(alerts)}
