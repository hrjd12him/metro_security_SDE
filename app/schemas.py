from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class AlertOut(BaseModel):
    id: int
    user_id: str
    username: str
    risk_type: str
    description: str
    timestamp: datetime
    severity: str
    action_taken: str
    resolved: bool

    class Config:
        orm_mode = True


class RescanResponse(BaseModel):
    created_alerts: int
