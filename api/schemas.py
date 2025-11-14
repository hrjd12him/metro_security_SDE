from pydantic import BaseModel
from typing import Any, Dict, Optional, List

class AlertOut(BaseModel):
    id: str
    kind: str
    severity: str
    user_id: Optional[str]
    user_email: Optional[str]
    ts: str
    evidence: Dict[str, Any]
    recommended_action: Optional[str]
    remediation_status: str

class AlertsResponse(BaseModel):
    alerts: List[AlertOut]
