from pydantic import BaseModel, Field
from typing import Any, Dict, Optional
import uuid

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    kind: str
    severity: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    ts: str
    evidence: Dict[str, Any] = {}
    recommended_action: Optional[str] = None
    remediation_status: str = "none"  # none|auto_suspended|manual_suspended|ignored
