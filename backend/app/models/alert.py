"""Alert database model."""

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean
from app.database.database import Base


class Alert(Base):
    """Represents a single raw security alert."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(20), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    username = Column(String(100), nullable=True, index=True)
    hostname = Column(String(200), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    asset_criticality = Column(Integer, nullable=True, default=3)
    protocol = Column(String(20), nullable=True)
    country = Column(String(5), nullable=True)
    device_id = Column(String(100), nullable=True)
    message = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=True)

    # Triage metadata
    is_duplicate = Column(Boolean, default=False)
    duplicate_of = Column(String(20), nullable=True)
    triage_run_id = Column(Integer, nullable=True)

    # Ground truth (not exposed to detection engine)
    scenario_id = Column(String(20), nullable=True)
    scenario_type = Column(String(50), nullable=True)
    is_malicious = Column(Boolean, nullable=True)
    expected_mitre = Column(String(20), nullable=True)

    def __repr__(self):
        return f"<Alert {self.alert_id} {self.event_type}>"
