"""User behavior profiling service."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.user_profile import UserProfile


def build_user_profiles(db: Session) -> int:
    """
    Build behavioral profiles for every user observed in the alerts.
    Returns count of profiles created.
    """
    # Clear existing profiles
    db.query(UserProfile).delete()
    db.commit()

    # Get all non-duplicate alerts that have a username
    alerts = (
        db.query(Alert)
        .filter(Alert.is_duplicate == False)
        .filter(Alert.username != "")
        .filter(Alert.username.isnot(None))
        .order_by(Alert.timestamp)
        .all()
    )

    # Group alerts by username
    user_alerts: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        user_alerts[alert.username].append(alert)

    count = 0
    for username, user_alert_list in user_alerts.items():
        profile = _build_single_profile(username, user_alert_list)
        db.add(profile)
        count += 1

    db.commit()
    return count


def _build_single_profile(username: str, alerts: List[Alert]) -> UserProfile:
    """Build a single user profile from their alerts."""
    login_events = {"failed_login", "successful_login", "new_device_login"}

    total_logins = 0
    failed_logins = 0
    successful_logins = 0
    all_ips = set()
    all_devices = set()
    all_countries = set()
    all_hostnames = set()
    login_hours = []
    timestamps = []
    activity_timeline = []

    for alert in alerts:
        timestamps.append(alert.timestamp)

        if alert.source_ip:
            all_ips.add(alert.source_ip)
        if alert.device_id:
            all_devices.add(alert.device_id)
        if alert.country:
            all_countries.add(alert.country)
        if alert.hostname:
            all_hostnames.add(alert.hostname)

        if alert.event_type in login_events:
            total_logins += 1
            login_hours.append(alert.timestamp.hour)

            if alert.event_type == "failed_login":
                failed_logins += 1
            elif alert.event_type in ("successful_login", "new_device_login"):
                successful_logins += 1

        activity_timeline.append({
            "timestamp": alert.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": alert.event_type,
            "source_ip": alert.source_ip,
            "hostname": alert.hostname,
            "severity": alert.severity,
        })

    # Determine usual login hours (hours where >10% of logins occur)
    hour_counts = defaultdict(int)
    for h in login_hours:
        hour_counts[h] += 1
    total_hours = len(login_hours) if login_hours else 1
    usual_hours = [h for h, c in hour_counts.items() if c / total_hours > 0.05]
    usual_hours.sort()

    # Determine "known" IPs and devices (those seen >2 times)
    ip_counts = defaultdict(int)
    device_counts = defaultdict(int)
    for alert in alerts:
        if alert.source_ip:
            ip_counts[alert.source_ip] += 1
        if alert.device_id:
            device_counts[alert.device_id] += 1

    known_ips = [ip for ip, c in ip_counts.items() if c >= 3]
    known_devices = [d for d, c in device_counts.items() if c >= 2]

    # New IPs/devices = those not in the "known" set
    new_ips = [ip for ip in all_ips if ip not in known_ips]
    new_devices = [d for d in all_devices if d not in known_devices]

    # Failure rate
    failure_rate = failed_logins / max(total_logins, 1)

    # Recent activity (last 2 hours of their timeline)
    if timestamps:
        latest = max(timestamps)
        recent_cutoff = latest - timedelta(hours=2)
        recent_alerts = [a for a in alerts if a.timestamp >= recent_cutoff]
        recent_failed = sum(1 for a in recent_alerts if a.event_type == "failed_login")
        recent_successful = sum(1 for a in recent_alerts if a.event_type in ("successful_login", "new_device_login"))
    else:
        recent_failed = 0
        recent_successful = 0

    # Risk level based on failure rate and volume
    risk_level = "low"
    if failure_rate > 0.5 and failed_logins > 20:
        risk_level = "critical"
    elif failure_rate > 0.3 and failed_logins > 10:
        risk_level = "high"
    elif failure_rate > 0.15 or len(new_ips) > 2:
        risk_level = "medium"

    profile = UserProfile(
        username=username,
        total_login_attempts=total_logins,
        failed_login_attempts=failed_logins,
        successful_login_attempts=successful_logins,
        failure_rate=round(failure_rate, 4),
        unique_ips=len(all_ips),
        unique_devices=len(all_devices),
        unique_countries=len(all_countries),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        usual_login_hours=usual_hours,
        known_ips=known_ips,
        known_devices=known_devices,
        new_ip_count=len(new_ips),
        new_device_count=len(new_devices),
        new_ips=new_ips,
        new_devices=new_devices,
        recent_failed_attempts=recent_failed,
        recent_successful_attempts=recent_successful,
        risk_level=risk_level,
        all_ips=list(all_ips),
        all_devices=list(all_devices),
        all_countries=list(all_countries),
        all_hostnames=list(all_hostnames),
        activity_timeline=activity_timeline[-50:],  # Keep last 50 events for display
    )

    return profile


def get_user_profile(db: Session, username: str) -> Optional[UserProfile]:
    """Get a user profile by username."""
    return db.query(UserProfile).filter(UserProfile.username == username).first()


def get_all_user_profiles(db: Session) -> List[UserProfile]:
    """Get all user profiles."""
    return db.query(UserProfile).order_by(UserProfile.risk_level.desc()).all()
