"""IP behavior profiling service."""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from app.models.alert import Alert
from app.models.ip_profile import IPProfile


# Known network context patterns
KNOWN_CORPORATE_SUBNETS = ["10.0.0.", "172.16.", "192.168."]
KNOWN_VPN_IPS = {"198.51.100.10", "198.51.100.11", "198.51.100.12"}
KNOWN_SCANNER_IPS = {"192.0.2.100"}
KNOWN_MONITORING_IPS = {"192.0.2.101"}
KNOWN_NAT_IPS = {"198.51.100.1"}
PUBLIC_WIFI_IPS = {"203.0.113.50", "203.0.113.51"}


def build_ip_profiles(db: Session) -> int:
    """
    Build behavioral profiles for every source IP observed in alerts.
    Returns count of profiles created.
    """
    db.query(IPProfile).delete()
    db.commit()

    alerts = (
        db.query(Alert)
        .filter(Alert.is_duplicate == False)
        .filter(Alert.source_ip != "")
        .filter(Alert.source_ip.isnot(None))
        .order_by(Alert.timestamp)
        .all()
    )

    # Group by source IP
    ip_alerts: Dict[str, List[Alert]] = defaultdict(list)
    for alert in alerts:
        ip_alerts[alert.source_ip].append(alert)

    count = 0
    for ip_address, ip_alert_list in ip_alerts.items():
        profile = _build_single_ip_profile(ip_address, ip_alert_list)
        db.add(profile)
        count += 1

    db.commit()
    return count


def _build_single_ip_profile(ip_address: str, alerts: List[Alert]) -> IPProfile:
    """Build a single IP profile from associated alerts."""
    login_events = {"failed_login", "successful_login", "new_device_login"}

    total_events = len(alerts)
    login_attempts = 0
    failed_logins = 0
    successful_logins = 0
    all_users = set()
    all_destinations = set()
    all_ports = set()
    all_event_types = set()
    timestamps = []
    activity_timeline = []

    for alert in alerts:
        timestamps.append(alert.timestamp)
        all_event_types.add(alert.event_type)

        if alert.username:
            all_users.add(alert.username)
        if alert.destination_ip:
            all_destinations.add(alert.destination_ip)
        if alert.destination_port:
            all_ports.add(alert.destination_port)

        if alert.event_type in login_events:
            login_attempts += 1
            if alert.event_type == "failed_login":
                failed_logins += 1
            else:
                successful_logins += 1

        activity_timeline.append({
            "timestamp": alert.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": alert.event_type,
            "username": alert.username,
            "destination": alert.destination_ip,
            "hostname": alert.hostname,
        })

    # Determine network type
    network_type = _classify_network(ip_address, all_users, alerts)

    # VPN/proxy/tor indicators
    vpn_indicator = ip_address in KNOWN_VPN_IPS
    proxy_indicator = False
    tor_indicator = False

    # Shared IP signal — higher when many unique users share the IP
    # This is NOT a maliciousness score. It's a context signal.
    shared_ip_signal = _compute_shared_ip_signal(ip_address, all_users, network_type)

    # Known users — users seen more than twice from this IP
    user_counts = defaultdict(int)
    for alert in alerts:
        if alert.username:
            user_counts[alert.username] += 1
    known_users = [u for u, c in user_counts.items() if c >= 2]

    # Country (most common)
    country_counts = defaultdict(int)
    for alert in alerts:
        if alert.country:
            country_counts[alert.country] += 1
    country = max(country_counts, key=country_counts.get) if country_counts else None

    # Risk level
    risk_level = _assess_ip_risk(
        ip_address, failed_logins, login_attempts,
        len(all_users), len(all_destinations), len(all_ports),
        network_type, shared_ip_signal
    )

    profile = IPProfile(
        ip_address=ip_address,
        total_events=total_events,
        login_attempts=login_attempts,
        failed_logins=failed_logins,
        successful_logins=successful_logins,
        unique_users=len(all_users),
        unique_destinations=len(all_destinations),
        unique_ports=len(all_ports),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        known_users=known_users,
        network_type=network_type,
        vpn_indicator=vpn_indicator,
        proxy_indicator=proxy_indicator,
        tor_indicator=tor_indicator,
        shared_ip_signal=round(shared_ip_signal, 2),
        country=country,
        all_users=list(all_users),
        all_destinations=list(all_destinations),
        all_ports=[int(p) for p in all_ports],
        all_event_types=list(all_event_types),
        risk_level=risk_level,
        activity_timeline=activity_timeline[-50:],
    )

    return profile


def _classify_network(ip: str, users: set, alerts: List[Alert]) -> str:
    """
    Classify the network type for an IP address.
    Important: many users from one IP does NOT automatically mean malicious.
    """
    # Check if it's an internal/corporate IP
    for subnet in KNOWN_CORPORATE_SUBNETS:
        if ip.startswith(subnet):
            return "corporate_internal"

    if ip in KNOWN_VPN_IPS:
        return "corporate_vpn"

    if ip in KNOWN_SCANNER_IPS:
        return "vulnerability_scanner"

    if ip in KNOWN_MONITORING_IPS:
        return "monitoring_system"

    if ip in KNOWN_NAT_IPS:
        return "corporate_nat"

    if ip in PUBLIC_WIFI_IPS:
        return "public_shared"

    # If many users and mostly successful logins, might be shared infrastructure
    if len(users) > 5:
        fail_count = sum(1 for a in alerts if a.event_type == "failed_login")
        success_count = sum(1 for a in alerts if a.event_type in ("successful_login", "new_device_login"))
        if success_count > fail_count:
            return "possible_shared"

    return "unknown"


def _compute_shared_ip_signal(ip: str, users: set, network_type: str) -> float:
    """
    Compute a shared IP signal (0.0 to 1.0).
    Higher means more likely to be a shared/public IP.
    This is a CONTEXTUAL signal, not a maliciousness indicator.
    """
    if network_type in ("corporate_nat", "public_shared", "corporate_vpn"):
        return min(1.0, len(users) / 10.0)

    if network_type == "corporate_internal":
        return 0.1  # Internal IPs are typically individual workstations

    if len(users) > 10:
        return 0.8
    elif len(users) > 5:
        return 0.5
    elif len(users) > 2:
        return 0.3

    return 0.0


def _assess_ip_risk(
    ip: str, failed_logins: int, login_attempts: int,
    unique_users: int, unique_destinations: int, unique_ports: int,
    network_type: str, shared_ip_signal: float
) -> str:
    """
    Assess IP risk level considering network context.
    A shared IP with many users is NOT automatically high-risk.
    """
    # Known benign network types get lower risk
    if network_type in ("corporate_internal", "corporate_vpn", "vulnerability_scanner",
                        "monitoring_system", "corporate_nat"):
        return "low"

    # Public shared IPs need additional signals to be high risk
    if network_type == "public_shared":
        if failed_logins > 50 and login_attempts > 0:
            failure_rate = failed_logins / login_attempts
            if failure_rate > 0.6:
                return "medium"
        return "low"

    # Unknown external IPs
    risk_score = 0

    if failed_logins > 100:
        risk_score += 3
    elif failed_logins > 30:
        risk_score += 2
    elif failed_logins > 10:
        risk_score += 1

    if unique_users > 10 and shared_ip_signal < 0.5:
        risk_score += 2  # Many users but not from shared infra
    elif unique_users > 5 and shared_ip_signal < 0.3:
        risk_score += 1

    if unique_ports > 20:
        risk_score += 2  # Port scanning behavior

    if unique_destinations > 5:
        risk_score += 1

    if login_attempts > 0:
        failure_rate = failed_logins / login_attempts
        if failure_rate > 0.7:
            risk_score += 2

    if risk_score >= 5:
        return "critical"
    elif risk_score >= 3:
        return "high"
    elif risk_score >= 2:
        return "medium"
    return "low"


def get_ip_profile(db: Session, ip_address: str) -> Optional[IPProfile]:
    """Get an IP profile by address."""
    return db.query(IPProfile).filter(IPProfile.ip_address == ip_address).first()


def get_all_ip_profiles(db: Session) -> List[IPProfile]:
    """Get all IP profiles."""
    return db.query(IPProfile).order_by(IPProfile.risk_level.desc()).all()
