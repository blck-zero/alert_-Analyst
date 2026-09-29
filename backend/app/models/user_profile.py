"""User behavior profile model."""

from sqlalchemy import Column, String, Integer, Float, DateTime, JSON
from app.database.database import Base


class UserProfile(Base):
    """Persistent behavioral profile for a user entity."""

    __tablename__ = "user_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    triage_run_id = Column(Integer, nullable=True)

    # Login statistics
    total_login_attempts = Column(Integer, default=0)
    failed_login_attempts = Column(Integer, default=0)
    successful_login_attempts = Column(Integer, default=0)
    failure_rate = Column(Float, default=0.0)

    # Entity diversity
    unique_ips = Column(Integer, default=0)
    unique_devices = Column(Integer, default=0)
    unique_countries = Column(Integer, default=0)

    # Temporal
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    usual_login_hours = Column(JSON, nullable=True)  # list of hours e.g. [9,10,11,...,17]

    # Known baselines
    known_ips = Column(JSON, nullable=True)  # list of IPs
    known_devices = Column(JSON, nullable=True)  # list of device IDs

    # Anomaly indicators
    new_ip_count = Column(Integer, default=0)
    new_device_count = Column(Integer, default=0)
    new_ips = Column(JSON, nullable=True)
    new_devices = Column(JSON, nullable=True)

    # Recent activity window
    recent_failed_attempts = Column(Integer, default=0)
    recent_successful_attempts = Column(Integer, default=0)

    # Associated incidents
    incident_count = Column(Integer, default=0)
    risk_level = Column(String(20), default="low")

    # All events
    all_ips = Column(JSON, nullable=True)
    all_devices = Column(JSON, nullable=True)
    all_countries = Column(JSON, nullable=True)
    all_hostnames = Column(JSON, nullable=True)

    # Activity timeline
    activity_timeline = Column(JSON, nullable=True)  # [{timestamp, event_type, ip, ...}]

    def __repr__(self):
        return f"<UserProfile {self.username}>"
