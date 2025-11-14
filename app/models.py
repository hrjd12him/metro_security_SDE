from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.sql import func
from .database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    username = Column(String, index=True)
    risk_type = Column(String, index=True)
    description = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    severity = Column(String, index=True)      # e.g. low/medium/high/critical
    action_taken = Column(String)              # e.g. "auto_suspend", "none", "manual_suspend"
    resolved = Column(Boolean, default=False)
