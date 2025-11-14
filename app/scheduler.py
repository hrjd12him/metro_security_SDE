import logging
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
from .okta_client import OktaClient
from .risk_rules import detect_brute_force, detect_unusual_geo_and_hours, evaluate_mfa_risks
from .database import SessionLocal
from .config import settings

logger = logging.getLogger(__name__)

okta_client = OktaClient()
scheduler: BackgroundScheduler | None = None


def run_full_scan() -> int:
    """
    Fetch logs, run detection, persist alerts.
    Returns number of alerts created.
    """
    db: Session = SessionLocal()
    try:
        events = okta_client.get_system_logs(minutes_back=settings.POLL_INTERVAL_MINUTES)

        brute = detect_brute_force(events)
        geo_hours = detect_unusual_geo_and_hours(events)
        base_alerts = brute + geo_hours

        alerts = evaluate_mfa_risks(db, okta_client, base_alerts)
        logger.info("Full scan produced %d alerts", len(alerts))
        return len(alerts)
    finally:
        db.close()


def start_scheduler():
    global scheduler
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_full_scan, "interval", minutes=settings.POLL_INTERVAL_MINUTES)
    scheduler.start()
    logger.info("Scheduler started with interval %d minutes", settings.POLL_INTERVAL_MINUTES)


def shutdown_scheduler():
    global scheduler
    if scheduler:
        scheduler.shutdown()
