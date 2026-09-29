"""Alert ingestion and normalization service."""

import csv
import os
from datetime import datetime
from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.alert import Alert


def load_alerts_from_csv(filepath: str) -> List[Dict]:
    """Load raw alerts from CSV file."""
    alerts = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append(row)
    return alerts


def ingest_alerts(db: Session, filepath: str = None) -> int:
    """Ingest alerts from CSV into database. Returns count of alerts ingested."""
    if filepath is None:
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data", "alerts.csv"
        )

    raw_alerts = load_alerts_from_csv(filepath)

    # Clear existing alerts
    db.query(Alert).delete()
    db.commit()

    count = 0
    for row in raw_alerts:
        alert = Alert(
            alert_id=row["alert_id"],
            timestamp=datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%SZ"),
            source_ip=row["source_ip"],
            destination_ip=row.get("destination_ip", ""),
            source_port=int(row.get("source_port", 0)) if row.get("source_port") else None,
            destination_port=int(row.get("destination_port", 0)) if row.get("destination_port") else None,
            username=row.get("username", ""),
            hostname=row.get("hostname", ""),
            event_type=row["event_type"],
            severity=row.get("severity", "medium"),
            asset_criticality=int(row.get("asset_criticality", 5)),
            protocol=row.get("protocol", ""),
            country=row.get("country", ""),
            device_id=row.get("device_id", ""),
            message=row.get("message", ""),
            raw_log=row.get("raw_log", ""),
            # Ground truth — stored but not used by detection engine
            scenario_id=row.get("scenario_id", ""),
            scenario_type=row.get("scenario_type", ""),
            is_malicious=row.get("is_malicious", "").lower() == "true" if row.get("is_malicious") else None,
            expected_mitre=row.get("expected_mitre", ""),
        )
        db.add(alert)
        count += 1

    db.commit()
    return count


def get_all_alerts(db: Session, skip: int = 0, limit: int = 100) -> List[Alert]:
    """Get paginated alerts."""
    return db.query(Alert).order_by(Alert.timestamp).offset(skip).limit(limit).all()


def get_alert_count(db: Session) -> int:
    """Get total alert count."""
    return db.query(Alert).count()


def get_alert_by_id(db: Session, alert_id: str) -> Alert:
    """Get a single alert by ID."""
    return db.query(Alert).filter(Alert.alert_id == alert_id).first()
