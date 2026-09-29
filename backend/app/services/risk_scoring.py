"""
Risk scoring service — computes explainable risk scores for incidents.

Score range: 0–100

Components (configurable weights):
- 30% Alert severity
- 25% Asset criticality  
- 20% Behavioral anomaly
- 15% Attack-pattern evidence
- 10% Corroborating evidence

Every score includes a detailed explanation of contributing factors.
"""

from typing import List, Dict
from sqlalchemy.orm import Session
from app.models.incident import Incident
from app.models.user_profile import UserProfile
from app.models.ip_profile import IPProfile
from app.config import settings


def score_all_incidents(db: Session) -> int:
    """Calculate risk scores for all incidents. Returns count scored."""
    incidents = db.query(Incident).all()
    count = 0

    for incident in incidents:
        score, explanation = _compute_risk_score(incident, db)
        incident.risk_score = round(score, 1)
        incident.risk_explanation = explanation

        # Update severity based on score
        if score >= 80:
            incident.severity = "critical"
        elif score >= 60:
            incident.severity = "high"
        elif score >= 40:
            incident.severity = "medium"
        else:
            incident.severity = "low"

        count += 1

    db.commit()
    return count


def _compute_risk_score(incident: Incident, db: Session) -> tuple:
    """
    Compute a risk score and generate explanation.
    Returns (score, explanation_list).
    """
    explanation = []

    # ─── Component 1: Alert Severity (30%) ────────────────────
    severity_score = _score_severity(incident)
    weighted_severity = severity_score * settings.RISK_WEIGHT_SEVERITY
    explanation.append({
        "factor": "Alert Severity",
        "raw_score": round(severity_score, 1),
        "weighted_score": round(weighted_severity, 1),
        "description": _describe_severity(incident),
    })

    # ─── Component 2: Asset Criticality (25%) ─────────────────
    criticality_score = _score_asset_criticality(incident)
    weighted_criticality = criticality_score * settings.RISK_WEIGHT_ASSET_CRITICALITY
    explanation.append({
        "factor": "Asset Criticality",
        "raw_score": round(criticality_score, 1),
        "weighted_score": round(weighted_criticality, 1),
        "description": _describe_criticality(incident),
    })

    # ─── Component 3: Behavioral Anomaly (20%) ────────────────
    anomaly_score = _score_behavioral_anomaly(incident, db)
    weighted_anomaly = anomaly_score * settings.RISK_WEIGHT_BEHAVIORAL_ANOMALY
    explanation.append({
        "factor": "Behavioral Anomaly",
        "raw_score": round(anomaly_score, 1),
        "weighted_score": round(weighted_anomaly, 1),
        "description": _describe_anomaly(incident, db),
    })

    # ─── Component 4: Attack Pattern Evidence (15%) ───────────
    pattern_score = _score_attack_pattern(incident)
    weighted_pattern = pattern_score * settings.RISK_WEIGHT_ATTACK_PATTERN
    explanation.append({
        "factor": "Attack Pattern Evidence",
        "raw_score": round(pattern_score, 1),
        "weighted_score": round(weighted_pattern, 1),
        "description": _describe_pattern(incident),
    })

    # ─── Component 5: Corroborating Evidence (10%) ────────────
    corroborating_score = _score_corroborating(incident, db)
    weighted_corroborating = corroborating_score * settings.RISK_WEIGHT_CORROBORATING
    explanation.append({
        "factor": "Corroborating Evidence",
        "raw_score": round(corroborating_score, 1),
        "weighted_score": round(weighted_corroborating, 1),
        "description": _describe_corroborating(incident, db),
    })

    total = weighted_severity + weighted_criticality + weighted_anomaly + weighted_pattern + weighted_corroborating
    total = min(100, max(0, total))

    return total, explanation


def _score_severity(incident: Incident) -> float:
    """Score based on alert severities in the incident."""
    event_types = incident.event_types or []
    severity_map = {
        "malware_detected": 95,
        "privilege_escalation": 90,
        "suspicious_process": 85,
        "large_outbound_transfer": 85,
        "impossible_travel": 80,
        "phishing_detected": 75,
        "account_locked": 70,
        "multiple_failed_mfa": 65,
        "new_device_login": 60,
        "port_scan": 50,
        "suspicious_dns": 55,
        "failed_login": 30,
        "password_reset": 20,
        "successful_login": 10,
    }

    if not event_types:
        return 30

    scores = [severity_map.get(et, 30) for et in event_types]
    return max(scores)


def _describe_severity(incident: Incident) -> str:
    event_types = incident.event_types or []
    critical_events = [et for et in event_types if et in ("malware_detected", "privilege_escalation", "suspicious_process")]
    if critical_events:
        return f"Contains critical event types: {', '.join(critical_events)}"
    return f"Event types observed: {', '.join(event_types[:5])}"


def _score_asset_criticality(incident: Incident) -> float:
    """Score based on the criticality of affected assets."""
    assets = incident.affected_assets or []
    criticality_map = {
        "prod-db-01": 100,
        "finance-db-01": 95,
        "prod-auth-01": 90,
        "dns-server-01": 85,
        "mail-server-01": 80,
        "prod-web-01": 75,
        "prod-app-01": 75,
        "hr-portal-01": 65,
        "staging-app-01": 40,
        "dev-web-01": 30,
    }

    if not assets:
        return 50

    scores = [criticality_map.get(a, 50) for a in assets]
    return max(scores)


def _describe_criticality(incident: Incident) -> str:
    assets = incident.affected_assets or []
    critical = [a for a in assets if a in ("prod-db-01", "finance-db-01", "prod-auth-01")]
    if critical:
        return f"Targets critical production assets: {', '.join(critical)}"
    return f"Affected assets: {', '.join(assets[:5])}"


def _score_behavioral_anomaly(incident: Incident, db: Session) -> float:
    """Score based on user and IP behavioral anomalies."""
    score = 0
    users = incident.affected_users or []
    ips = incident.source_ips or []

    for username in users[:3]:  # Check top 3 users
        profile = db.query(UserProfile).filter(UserProfile.username == username).first()
        if profile:
            if profile.failure_rate > 0.5:
                score = max(score, 80)
            elif profile.failure_rate > 0.3:
                score = max(score, 60)
            if profile.new_ip_count > 0:
                score = max(score, 50)
            if profile.new_device_count > 0:
                score = max(score, 45)

    for ip in ips[:3]:
        ip_profile = db.query(IPProfile).filter(IPProfile.ip_address == ip).first()
        if ip_profile:
            if ip_profile.risk_level == "critical":
                score = max(score, 90)
            elif ip_profile.risk_level == "high":
                score = max(score, 70)
            # If it's a known shared IP, reduce anomaly score
            if ip_profile.shared_ip_signal > 0.5:
                score = max(0, score - 15)

    return min(100, score)


def _describe_anomaly(incident: Incident, db: Session) -> str:
    parts = []
    users = incident.affected_users or []
    for username in users[:2]:
        profile = db.query(UserProfile).filter(UserProfile.username == username).first()
        if profile:
            if profile.new_ip_count > 0:
                parts.append(f"{username}: {profile.new_ip_count} new IP(s)")
            if profile.new_device_count > 0:
                parts.append(f"{username}: {profile.new_device_count} new device(s)")
            if profile.failure_rate > 0.3:
                parts.append(f"{username}: {profile.failure_rate:.0%} failure rate")

    return "; ".join(parts) if parts else "No significant behavioral anomalies detected"


def _score_attack_pattern(incident: Incident) -> float:
    """Score based on recognized attack patterns."""
    correlation_type = incident.correlation_type or ""
    alert_count = incident.alert_count or 0
    event_seq = incident.event_sequence or []

    pattern_scores = {
        "brute_force": 75,
        "password_spraying": 70,
        "account_compromise": 90,
        "port_scanning": 55,
        "malware": 95,
        "data_exfiltration": 90,
        "impossible_travel": 70,
        "phishing": 75,
        "mfa_fatigue": 70,
        "suspicious_dns": 50,
        "lateral_movement": 80,
    }

    base = pattern_scores.get(correlation_type, 30)

    # Volume amplifier
    if alert_count > 100:
        base = min(100, base + 10)
    elif alert_count > 50:
        base = min(100, base + 5)

    # Sequence escalation (failures → success → escalation)
    if "successful_login" in event_seq and "failed_login" in event_seq:
        fail_idx = event_seq.index("failed_login")
        succ_idx = len(event_seq) - 1 - event_seq[::-1].index("successful_login")
        if succ_idx > fail_idx:
            base = min(100, base + 10)

    if "privilege_escalation" in event_seq:
        base = min(100, base + 15)

    return base


def _describe_pattern(incident: Incident) -> str:
    ctype = incident.correlation_type or "unknown"
    count = incident.alert_count or 0
    pattern_names = {
        "brute_force": "Brute-force attack pattern",
        "password_spraying": "Password spraying pattern",
        "account_compromise": "Account compromise sequence",
        "port_scanning": "Network scanning pattern",
        "malware": "Malware activity chain",
        "data_exfiltration": "Data exfiltration pattern",
        "impossible_travel": "Impossible travel anomaly",
        "phishing": "Phishing campaign",
        "mfa_fatigue": "MFA fatigue attack",
        "suspicious_dns": "Suspicious DNS pattern",
        "lateral_movement": "Lateral movement pattern",
    }
    name = pattern_names.get(ctype, "Unknown pattern")
    return f"{name} ({count} alerts)"


def _score_corroborating(incident: Incident, db: Session) -> float:
    """Score based on corroborating evidence from multiple sources."""
    score = 0
    users = incident.affected_users or []
    ips = incident.source_ips or []
    assets = incident.affected_assets or []

    # Multiple affected users increases concern
    if len(users) > 5:
        score += 30
    elif len(users) > 2:
        score += 15

    # Multiple source IPs
    if len(ips) > 3:
        score += 20
    elif len(ips) > 1:
        score += 10

    # Multiple assets
    if len(assets) > 3:
        score += 20
    elif len(assets) > 1:
        score += 10

    # Check if IP is from unknown network
    for ip in ips[:3]:
        ip_profile = db.query(IPProfile).filter(IPProfile.ip_address == ip).first()
        if ip_profile:
            if ip_profile.network_type == "unknown":
                score += 20
            # Reduce if known infrastructure
            if ip_profile.network_type in ("corporate_internal", "corporate_vpn", "vulnerability_scanner"):
                score = max(0, score - 20)

    return min(100, score)


def _describe_corroborating(incident: Incident, db: Session) -> str:
    parts = []
    users = incident.affected_users or []
    ips = incident.source_ips or []
    assets = incident.affected_assets or []

    if len(users) > 1:
        parts.append(f"{len(users)} affected users")
    if len(ips) > 1:
        parts.append(f"{len(ips)} source IPs")
    if len(assets) > 1:
        parts.append(f"{len(assets)} targeted assets")

    for ip in ips[:2]:
        ip_profile = db.query(IPProfile).filter(IPProfile.ip_address == ip).first()
        if ip_profile and ip_profile.network_type == "unknown":
            parts.append(f"IP {ip}: unknown network origin")

    return "; ".join(parts) if parts else "Limited corroborating evidence"
