"""FastAPI Schemas."""
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class AlertBase(BaseModel):
    alert_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    username: Optional[str] = None
    hostname: Optional[str] = None
    
    class Config:
        from_attributes = True

class IncidentBase(BaseModel):
    incident_id: str
    title: str
    severity: str
    risk_score: float
    alert_count: int
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    correlation_type: str
    status: str
    
    class Config:
        from_attributes = True

class IncidentDetail(IncidentBase):
    description: Optional[str] = None
    risk_explanation: Optional[List[Dict[str, Any]]] = None
    affected_users: Optional[List[str]] = None
    source_ips: Optional[List[str]] = None
    affected_assets: Optional[List[str]] = None
    event_sequence: Optional[List[str]] = None
    ai_summary: Optional[str] = None
    ai_key_evidence: Optional[List[str]] = None
    ai_possible_explanation: Optional[str] = None
    ai_mitre_explanation: Optional[str] = None
    ai_investigation_steps: Optional[List[str]] = None
    mitre_evidence: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
class TriageRunResponse(BaseModel):
    run_id: str
    status: str
    current_stage: Optional[str] = None
    progress_pct: float
    total_alerts_input: int
    incidents_created: int
    alert_reduction_rate: Optional[float] = None
    
    class Config:
        from_attributes = True

class AnalystReviewCreate(BaseModel):
    decision: str
    notes: Optional[str] = None
    
class MetricsResponse(BaseModel):
    total_alerts: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    mttt_reduction_pct: float
    false_positive_rate: float
    precision: float
    recall: float
    f1_score: float
    alert_reduction: float
