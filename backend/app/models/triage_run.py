"""Triage run model — tracks each execution of the pipeline."""

from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from datetime import datetime, timezone
from app.database.database import Base


class TriageRun(Base):
    """Records a single execution of the triage pipeline."""

    __tablename__ = "triage_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(50), unique=True, nullable=False, index=True)
    status = Column(String(30), default="pending")  # pending, processing, completed, failed
    current_stage = Column(String(50), nullable=True)
    progress_pct = Column(Float, default=0.0)

    # Timing
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    processing_time_seconds = Column(Float, nullable=True)

    # Stage timings (in seconds)
    stage_timings = Column(JSON, nullable=True)

    # Input
    total_alerts_input = Column(Integer, default=0)

    # Deduplication results
    duplicate_alerts_removed = Column(Integer, default=0)
    unique_alerts = Column(Integer, default=0)

    # Correlation results
    correlated_alerts = Column(Integer, default=0)
    incidents_created = Column(Integer, default=0)

    # Incident breakdown
    critical_incidents = Column(Integer, default=0)
    high_incidents = Column(Integer, default=0)
    medium_incidents = Column(Integer, default=0)
    low_incidents = Column(Integer, default=0)

    # Scope
    affected_users_count = Column(Integer, default=0)
    affected_ips_count = Column(Integer, default=0)
    mitre_techniques_count = Column(Integer, default=0)

    # Evaluation metrics (computed against ground truth)
    true_positives = Column(Integer, nullable=True)
    false_positives = Column(Integer, nullable=True)
    false_negatives = Column(Integer, nullable=True)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    alert_reduction_rate = Column(Float, nullable=True)

    # MTTT
    mean_triage_time_seconds = Column(Float, nullable=True)
    median_triage_time_seconds = Column(Float, nullable=True)
    p95_triage_time_seconds = Column(Float, nullable=True)
    baseline_triage_time_seconds = Column(Float, nullable=True)
    mttt_reduction_pct = Column(Float, nullable=True)

    # Error tracking
    error_message = Column(String(500), nullable=True)

    def __repr__(self):
        return f"<TriageRun {self.run_id} {self.status}>"
