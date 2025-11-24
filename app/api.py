from fastapi import APIRouter, Depends, HTTPException, Query ,Request
from sqlalchemy.orm import Session
from typing import List, Optional
from .database import SessionLocal
from .models import Alert
from .schemas import AlertOut, RescanResponse
from .scheduler import run_full_scan
from .okta_client import OktaClient
import logging

router = APIRouter()
okta_client = OktaClient()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/alerts", response_model=List[AlertOut])
def list_alerts(

        severity: Optional[str] = Query(default=None),
        risk_type: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
        db: Session = Depends(get_db)

        
    ):  

    status = Request.status_code()

    try:
        if status  == 200 :
            logging.Logger.info("Api Called Sucsess Full")

        elif status == 400:
            logging.Logger.error("Fail TO Get the Data")


        q = db.query(Alert).order_by(Alert.timestamp.desc())

        if severity:
            q = q.filter(Alert.severity == severity)
        if risk_type:
            q = q.filter(Alert.risk_type == risk_type)

        return q.limit(limit).all()

    except Exception as e:
        logging.Logger.error("request ")
        print(e)



@router.post("/remediate/{user_id}", response_model=AlertOut)
def remediate_user(user_id: str, db: Session = Depends(get_db)):
    # call Okta suspend API
    from datetime import datetime
    from .models import Alert

    if not okta_client.suspend_user(user_id):
        raise HTTPException(status_code=500, detail="Failed to suspend user in Okta")

    alert = Alert(
        user_id=user_id,
        username="unknown",
        risk_type="MANUAL_SUSPEND",
        description="User suspended manually via API",
        severity="high",
        action_taken="manual_suspend",
        timestamp=datetime.utcnow()
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/rescan", response_model=RescanResponse)
def rescan():
    count = run_full_scan()
    return RescanResponse(created_alerts=count)
