from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["new", "investigating", "closed"]

class SecurityEvent(BaseModel):
    id: str
    timestamp: datetime
    hostname: str
    username: str
    source_ip: str
    destination_ip: str
    event_type: str
    category: str
    severity: Severity
    message: str
    source: str = "simulator"
    is_suspicious: bool = False
    mitre_technique: Optional[str] = None
    # Map location of the *remote* party. For simulator data this is a placeholder
    # (documentation IPs have no real geolocation) and is flagged geo["simulated"] = True.
    geo: Optional[dict] = None
    raw: dict = Field(default_factory=dict)

class SecurityAlert(BaseModel):
    id: str
    event_id: str
    event_type: str = ""
    timestamp: datetime
    title: str
    description: str
    severity: Severity
    hostname: str
    username: str
    source_ip: str
    status: AlertStatus = "new"
    rule_id: str
    mitre_technique: Optional[str] = None
    geo: Optional[dict] = None

class SimulatorConfig(BaseModel):
    events_per_minute: int = Field(default=30, ge=1, le=300)

class AlertUpdate(BaseModel):
    status: AlertStatus