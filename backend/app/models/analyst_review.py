"""Analyst review model."""

from sqlalchemy import Column, String, Integer, DateTime, Text
from datetime import datetime, timezone
from app.database.database import Base


class AnalystReview(Base):
    """Human analyst decision on an incident."""

    __tablename__ = "analyst_reviews"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(20), nullable=False, index=True)
    analyst_id = Column(String(100), nullable=False, default="analyst-1")
    decision = Column(String(30), nullable=False)  # confirmed, false_positive, investigating, escalated
    notes = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # MTTT measurement
    triage_start_time = Column(DateTime, nullable=True)
    triage_decision_time = Column(DateTime, nullable=True)
    triage_duration_seconds = Column(Integer, nullable=True)

    def __repr__(self):
        return f"<AnalystReview {self.incident_id} {self.decision}>"
