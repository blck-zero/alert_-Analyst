"""Deduplication service — identifies and marks near-duplicate alerts."""

from datetime import timedelta
from typing import List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.alert import Alert
from app.config import settings


def deduplicate_alerts(db: Session) -> Tuple[int, int]:
    """
    Identify and mark duplicate/near-duplicate alerts.
    
    Two alerts are considered duplicates if they share:
    - Same event_type
    - Same source_ip
    - Same destination_ip
    - Same username
    - Same hostname
    - Within DEDUP_TIME_WINDOW_SECONDS of each other
    
    Returns (original_count, duplicates_removed).
    """
    window_seconds = settings.DEDUP_TIME_WINDOW_SECONDS

    # Reset all duplicate flags
    db.query(Alert).update({Alert.is_duplicate: False, Alert.duplicate_of: None})
    db.commit()

    # Get all alerts ordered by timestamp
    alerts = db.query(Alert).order_by(Alert.timestamp).all()
    original_count = len(alerts)
    duplicates_found = 0

    # Group by fingerprint (event_type, source_ip, dest_ip, username, hostname)
    seen = {}  # fingerprint -> (alert_id, timestamp)

    for alert in alerts:
        fingerprint = (
            alert.event_type or "",
            alert.source_ip or "",
            alert.destination_ip or "",
            alert.username or "",
            alert.hostname or "",
        )

        if fingerprint in seen:
            prev_id, prev_ts = seen[fingerprint]
            time_diff = abs((alert.timestamp - prev_ts).total_seconds())

            if time_diff <= window_seconds:
                # Mark as duplicate
                alert.is_duplicate = True
                alert.duplicate_of = prev_id
                duplicates_found += 1
                continue

        # Update the seen map with this alert
        seen[fingerprint] = (alert.alert_id, alert.timestamp)

    db.commit()
    return original_count, duplicates_found


def get_unique_alerts(db: Session) -> List[Alert]:
    """Get all non-duplicate alerts."""
    return db.query(Alert).filter(Alert.is_duplicate == False).order_by(Alert.timestamp).all()


def get_duplicate_count(db: Session) -> int:
    """Get count of duplicate alerts."""
    return db.query(Alert).filter(Alert.is_duplicate == True).count()
