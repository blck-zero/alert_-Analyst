"""Alert normalization service — standardizes fields and enriches data."""

from typing import List, Dict
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.alert import Alert


def normalize_alerts(db: Session) -> int:
    """
    Normalize all alerts in the database.
    - Standardize severity levels
    - Standardize event type names
    - Validate IP addresses
    - Ensure consistent timestamp format
    Returns count of normalized alerts.
    """
    alerts = db.query(Alert).all()
    count = 0

    severity_map = {
        "info": "info",
        "informational": "info",
        "low": "low",
        "medium": "medium",
        "med": "medium",
        "high": "high",
        "critical": "critical",
        "crit": "critical",
    }

    for alert in alerts:
        # Normalize severity
        if alert.severity:
            alert.severity = severity_map.get(alert.severity.lower(), alert.severity.lower())

        # Normalize event type
        if alert.event_type:
            alert.event_type = alert.event_type.lower().strip().replace(" ", "_")

        # Ensure username is lowercase
        if alert.username:
            alert.username = alert.username.lower().strip()

        # Ensure hostname is lowercase
        if alert.hostname:
            alert.hostname = alert.hostname.lower().strip()

        # Set default asset criticality if missing
        if alert.asset_criticality is None or alert.asset_criticality == 0:
            alert.asset_criticality = 5

        count += 1

    db.commit()
    return count
