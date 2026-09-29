"""IP behavior profile model."""

from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, JSON
from app.database.database import Base


class IPProfile(Base):
    """Persistent behavioral profile for an IP address."""

    __tablename__ = "ip_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)
    triage_run_id = Column(Integer, nullable=True)

    # Activity statistics
    total_events = Column(Integer, default=0)
    login_attempts = Column(Integer, default=0)
    failed_logins = Column(Integer, default=0)
    successful_logins = Column(Integer, default=0)

    # Entity diversity
    unique_users = Column(Integer, default=0)
    unique_destinations = Column(Integer, default=0)
    unique_ports = Column(Integer, default=0)

    # Temporal
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # Known entities
    known_users = Column(JSON, nullable=True)

    # Network context
    network_type = Column(String(50), nullable=True)  # corporate, public, unknown
    vpn_indicator = Column(Boolean, default=False)
    proxy_indicator = Column(Boolean, default=False)
    tor_indicator = Column(Boolean, default=False)
    shared_ip_signal = Column(Float, default=0.0)  # 0.0 = not shared, 1.0 = highly shared

    # Geolocation
    country = Column(String(5), nullable=True)
    asn = Column(String(100), nullable=True)

    # All associated entities
    all_users = Column(JSON, nullable=True)
    all_destinations = Column(JSON, nullable=True)
    all_ports = Column(JSON, nullable=True)
    all_event_types = Column(JSON, nullable=True)

    # Risk
    risk_level = Column(String(20), default="low")
    incident_count = Column(Integer, default=0)

    # Activity timeline
    activity_timeline = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<IPProfile {self.ip_address}>"
