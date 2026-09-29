"""Incident and IncidentAlert database models."""

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean, JSON
from sqlalchemy import ForeignKey
from datetime import datetime, timezone
from app.database.database import Base


class Incident(Base):
    """A correlated security incident composed of multiple alerts."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(20), unique=True, nullable=False, index=True)
    triage_run_id = Column(Integer, ForeignKey("triage_runs.id"), nullable=True)

    # Classification
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_explanation = Column(JSON, nullable=True)  # list of {factor, score, description}

    # MITRE ATT&CK
    mitre_technique_id = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(200), nullable=True)
    mitre_tactic = Column(String(100), nullable=True)
    mitre_evidence = Column(Text, nullable=True)

    # Scope
    alert_count = Column(Integer, default=0)
    affected_users = Column(JSON, nullable=True)  # list of usernames
    source_ips = Column(JSON, nullable=True)  # list of IPs
    affected_assets = Column(JSON, nullable=True)  # list of hostnames
    event_types = Column(JSON, nullable=True)  # list of event types seen
    event_sequence = Column(JSON, nullable=True)  # ordered event sequence

    # Temporal
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # AI summary
    ai_summary = Column(Text, nullable=True)
    ai_key_evidence = Column(JSON, nullable=True)
    ai_possible_explanation = Column(Text, nullable=True)
    ai_mitre_explanation = Column(Text, nullable=True)
    ai_investigation_steps = Column(JSON, nullable=True)
    ai_confidence = Column(String(20), nullable=True)
    ai_limitations = Column(JSON, nullable=True)

    # Status
    status = Column(String(30), default="open")  # open, confirmed, false_positive, investigating, escalated
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Correlation metadata
    correlation_type = Column(String(50), nullable=True)
    correlation_details = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<Incident {self.incident_id} risk={self.risk_score}>"


class IncidentAlert(Base):
    """Association table linking incidents to their constituent alerts."""

    __tablename__ = "incident_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(20), ForeignKey("incidents.incident_id"), nullable=False, index=True)
    alert_id = Column(String(20), ForeignKey("alerts.alert_id"), nullable=False, index=True)
