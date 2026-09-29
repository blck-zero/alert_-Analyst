"""
MITRE ATT&CK mapping service.

Maps incidents to MITRE techniques using deterministic, evidence-based rules.
Does NOT rely solely on LLM for mapping — uses rules first, LLM only explains.
"""

import json
import os
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from app.models.incident import Incident


# Load MITRE mapping data
_MITRE_DATA = None


def _load_mitre_data() -> Dict:
    """Load MITRE mapping from JSON file."""
    global _MITRE_DATA
    if _MITRE_DATA is None:
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "data", "mitre_mapping.json"
        )
        with open(filepath, "r") as f:
            _MITRE_DATA = json.load(f)
    return _MITRE_DATA


def map_all_incidents(db: Session) -> int:
    """Apply MITRE ATT&CK mapping to all incidents. Returns count mapped."""
    incidents = db.query(Incident).all()
    count = 0

    for incident in incidents:
        technique = _map_incident_to_mitre(incident)
        if technique:
            incident.mitre_technique_id = technique["id"]
            incident.mitre_technique_name = technique["name"]
            incident.mitre_tactic = technique["tactic"]
            incident.mitre_evidence = technique["evidence"]
            count += 1

    db.commit()
    return count


def _map_incident_to_mitre(incident: Incident) -> Optional[Dict]:
    """
    Map a single incident to a MITRE ATT&CK technique using rules.
    Returns technique dict or None.
    """
    correlation_type = incident.correlation_type or ""
    event_types = set(incident.event_types or [])
    alert_count = incident.alert_count or 0
    affected_users = incident.affected_users or []
    event_sequence = incident.event_sequence or []

    mitre_data = _load_mitre_data()
    techniques = mitre_data.get("techniques", {})

    # Rule-based mapping
    if correlation_type == "brute_force":
        t = techniques.get("T1110", {})
        return {
            "id": "T1110",
            "name": t.get("name", "Brute Force"),
            "tactic": t.get("tactic", "Credential Access"),
            "evidence": _build_evidence(
                f"{alert_count} failed authentication attempts against "
                f"{', '.join(affected_users[:3])} from {', '.join((incident.source_ips or [])[:3])}. "
                f"High volume of repeated failures consistent with automated credential guessing."
            ),
        }

    if correlation_type == "password_spraying":
        t = techniques.get("T1110.003", {})
        return {
            "id": "T1110.003",
            "name": t.get("name", "Password Spraying"),
            "tactic": t.get("tactic", "Credential Access"),
            "evidence": _build_evidence(
                f"Single source IP attempted authentication against {len(affected_users)} "
                f"unique user accounts. Pattern consistent with password spraying: "
                f"few attempts per account across many targets."
            ),
        }

    if correlation_type == "account_compromise":
        t = techniques.get("T1078", {})
        evidence_parts = []
        if "failed_login" in event_types and "successful_login" in event_types:
            evidence_parts.append("Successful login observed after multiple failures")
        if "new_device_login" in event_types:
            evidence_parts.append("Login from previously unseen device")
        if "privilege_escalation" in event_types:
            evidence_parts.append("Privilege escalation attempt after login")

        return {
            "id": "T1078",
            "name": t.get("name", "Valid Accounts"),
            "tactic": t.get("tactic", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
            "evidence": _build_evidence(". ".join(evidence_parts)),
        }

    if correlation_type == "port_scanning":
        t = techniques.get("T1046", {})
        sources = incident.source_ips or []
        assets = incident.affected_assets or []
        return {
            "id": "T1046",
            "name": t.get("name", "Network Service Scanning"),
            "tactic": t.get("tactic", "Discovery"),
            "evidence": _build_evidence(
                f"Source {', '.join(sources[:3])} scanned {len(assets)} hosts "
                f"across multiple ports. {alert_count} scan events detected."
            ),
        }

    if correlation_type == "malware":
        # Check for specific malware indicators
        if "malware_detected" in event_types:
            t = techniques.get("T1204", {})
            evidence_parts = [f"Malware detected on {', '.join((incident.affected_assets or [])[:3])}"]
            if "suspicious_process" in event_types:
                evidence_parts.append("Suspicious process execution observed")
            if "suspicious_dns" in event_types:
                evidence_parts.append("Suspicious DNS activity suggesting C2 communication")

            return {
                "id": "T1204",
                "name": t.get("name", "User Execution"),
                "tactic": t.get("tactic", "Execution"),
                "evidence": _build_evidence(". ".join(evidence_parts)),
            }

    if correlation_type == "data_exfiltration":
        t = techniques.get("T1041", {})
        return {
            "id": "T1041",
            "name": t.get("name", "Exfiltration Over C2 Channel"),
            "tactic": t.get("tactic", "Exfiltration"),
            "evidence": _build_evidence(
                f"User {', '.join(affected_users[:3])} performed {alert_count} "
                f"large outbound data transfers to external destinations. "
                f"Volume and pattern suggest potential data exfiltration."
            ),
        }

    if correlation_type == "impossible_travel":
        t = techniques.get("T1078.004", {})
        return {
            "id": "T1078.004",
            "name": t.get("name", "Cloud Accounts"),
            "tactic": t.get("tactic", "Defense Evasion, Persistence, Initial Access"),
            "evidence": _build_evidence(
                f"User {', '.join(affected_users[:3])} authenticated from geographically "
                f"distant locations within a short timeframe. Note: This could also be "
                f"explained by VPN usage, cloud infrastructure, or proxy servers."
            ),
        }

    if correlation_type == "phishing":
        t = techniques.get("T1566", {})
        return {
            "id": "T1566",
            "name": t.get("name", "Phishing"),
            "tactic": t.get("tactic", "Initial Access"),
            "evidence": _build_evidence(
                f"Phishing emails detected targeting {len(affected_users)} users. "
                f"{'Post-click activity observed.' if 'suspicious_process' in event_types else 'No post-click activity detected yet.'}"
            ),
        }

    if correlation_type == "mfa_fatigue":
        t = techniques.get("T1556", {})
        return {
            "id": "T1556",
            "name": t.get("name", "Modify Authentication Process"),
            "tactic": t.get("tactic", "Credential Access, Defense Evasion, Persistence"),
            "evidence": _build_evidence(
                f"{alert_count} failed MFA attempts against {', '.join(affected_users[:3])}. "
                f"Pattern consistent with MFA fatigue / push bombing attack."
            ),
        }

    if correlation_type == "suspicious_dns":
        t = techniques.get("T1071", {})
        return {
            "id": "T1071",
            "name": t.get("name", "Application Layer Protocol"),
            "tactic": t.get("tactic", "Command and Control"),
            "evidence": _build_evidence(
                f"{alert_count} suspicious DNS queries detected. "
                f"Pattern may indicate DNS tunneling or C2 communication."
            ),
        }

    if correlation_type == "lateral_movement":
        t = techniques.get("T1078", {})
        assets = incident.affected_assets or []
        return {
            "id": "T1078",
            "name": t.get("name", "Valid Accounts"),
            "tactic": t.get("tactic", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
            "evidence": _build_evidence(
                f"User {', '.join(affected_users[:3])} attempted to access {len(assets)} "
                f"internal systems from {', '.join((incident.source_ips or [])[:3])}. "
                f"Pattern consistent with lateral movement after initial compromise."
            ),
        }

    return None


def _build_evidence(description: str) -> str:
    """Format evidence string."""
    return description


def get_mitre_summary(db: Session) -> Dict:
    """Get a summary of all MITRE techniques detected."""
    incidents = db.query(Incident).filter(Incident.mitre_technique_id.isnot(None)).all()

    techniques = {}
    for inc in incidents:
        tid = inc.mitre_technique_id
        if tid not in techniques:
            techniques[tid] = {
                "id": tid,
                "name": inc.mitre_technique_name,
                "tactic": inc.mitre_tactic,
                "incident_count": 0,
                "incidents": [],
            }
        techniques[tid]["incident_count"] += 1
        techniques[tid]["incidents"].append(inc.incident_id)

    return {
        "total_techniques": len(techniques),
        "techniques": list(techniques.values()),
    }
