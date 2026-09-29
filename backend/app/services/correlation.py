"""
Correlation engine — groups related alerts into incidents.

Uses multiple correlation strategies:
1. Temporal correlation (events close in time)
2. Source correlation (same source IP)
3. User correlation (same username)
4. Asset correlation (same target host)
5. Event sequence correlation (related event patterns)
6. Graph correlation (shared entities)

Does NOT rely on a single rule. Combines multiple signals.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Tuple, Set, Optional
from sqlalchemy.orm import Session
import networkx as nx
from app.models.alert import Alert
from app.models.incident import Incident, IncidentAlert
from app.config import settings


def correlate_alerts(db: Session) -> List[Incident]:
    """
    Main correlation pipeline.
    Groups related alerts into incidents based on multiple signals.
    Returns list of created incidents.
    """
    # Clear existing incidents
    db.query(IncidentAlert).delete()
    db.query(Incident).delete()
    db.commit()

    # Get all non-duplicate alerts
    alerts = (
        db.query(Alert)
        .filter(Alert.is_duplicate == False)
        .order_by(Alert.timestamp)
        .all()
    )

    # Build clusters using multiple strategies
    clusters = []

    # Strategy 1: Brute force detection
    clusters.extend(_detect_brute_force(alerts))

    # Strategy 2: Password spraying detection
    clusters.extend(_detect_password_spraying(alerts))

    # Strategy 3: Account compromise sequences
    clusters.extend(_detect_account_compromise(alerts))

    # Strategy 4: Port scanning detection
    clusters.extend(_detect_port_scanning(alerts))

    # Strategy 5: Malware activity chains
    clusters.extend(_detect_malware_chains(alerts))

    # Strategy 6: Data exfiltration
    clusters.extend(_detect_data_exfiltration(alerts))

    # Strategy 7: Impossible travel
    clusters.extend(_detect_impossible_travel(alerts))

    # Strategy 8: Phishing campaigns
    clusters.extend(_detect_phishing(alerts))

    # Strategy 9: MFA attacks
    clusters.extend(_detect_mfa_attacks(alerts))

    # Strategy 10: Suspicious DNS activity
    clusters.extend(_detect_suspicious_dns(alerts))

    # Strategy 11: Lateral movement
    clusters.extend(_detect_lateral_movement(alerts))

    # Merge overlapping clusters
    merged = _merge_overlapping_clusters(clusters)

    # Create incident objects
    incidents = []
    for idx, cluster in enumerate(merged, 1):
        incident = _create_incident_from_cluster(idx, cluster, db)
        if incident:
            incidents.append(incident)

    # Save to database
    for incident in incidents:
        db.add(incident)
    db.commit()

    # Create incident-alert associations
    for incident in incidents:
        for alert_id in incident._alert_ids:
            assoc = IncidentAlert(
                incident_id=incident.incident_id,
                alert_id=alert_id,
            )
            db.add(assoc)
    db.commit()

    return incidents


def _detect_brute_force(alerts: List[Alert]) -> List[Dict]:
    """Detect brute force attacks: many failed logins from same IP to same user."""
    clusters = []
    window_minutes = settings.CORRELATION_TIME_WINDOW_MINUTES
    threshold = settings.BRUTE_FORCE_THRESHOLD

    # Group by (source_ip, username)
    groups = defaultdict(list)
    for alert in alerts:
        if alert.event_type == "failed_login" and alert.username:
            groups[(alert.source_ip, alert.username)].append(alert)

    for (src_ip, username), group_alerts in groups.items():
        if len(group_alerts) < threshold:
            continue

        # Check temporal clustering
        sorted_alerts = sorted(group_alerts, key=lambda a: a.timestamp)
        # Use sliding window
        window_alerts = _temporal_cluster(sorted_alerts, window_minutes)

        for window in window_alerts:
            if len(window) >= threshold:
                # Also include related events (account_locked, successful_login after failures)
                related = _find_related_events(alerts, src_ip, username, window, window_minutes)
                all_alert_ids = set(a.alert_id for a in window) | set(a.alert_id for a in related)

                clusters.append({
                    "type": "brute_force",
                    "alert_ids": all_alert_ids,
                    "alerts": list(window) + list(related),
                    "source_ip": src_ip,
                    "username": username,
                    "title": f"Potential brute-force activity against {username}",
                })

    return clusters


def _detect_password_spraying(alerts: List[Alert]) -> List[Dict]:
    """Detect password spraying: one IP tries few passwords against many users."""
    clusters = []
    window_minutes = settings.CORRELATION_TIME_WINDOW_MINUTES
    user_threshold = settings.PASSWORD_SPRAY_USER_THRESHOLD

    # Group failed logins by source IP
    ip_groups = defaultdict(list)
    for alert in alerts:
        if alert.event_type == "failed_login" and alert.username:
            ip_groups[alert.source_ip].append(alert)

    for src_ip, group_alerts in ip_groups.items():
        # Count unique usernames
        users = set(a.username for a in group_alerts)
        if len(users) < user_threshold:
            continue

        # Check temporal clustering
        sorted_alerts = sorted(group_alerts, key=lambda a: a.timestamp)
        window_alerts = _temporal_cluster(sorted_alerts, window_minutes)

        for window in window_alerts:
            window_users = set(a.username for a in window)
            if len(window_users) >= user_threshold:
                alert_ids = set(a.alert_id for a in window)

                clusters.append({
                    "type": "password_spraying",
                    "alert_ids": alert_ids,
                    "alerts": list(window),
                    "source_ip": src_ip,
                    "users": list(window_users),
                    "title": f"Potential password spraying from {src_ip} targeting {len(window_users)} users",
                })

    return clusters


def _detect_account_compromise(alerts: List[Alert]) -> List[Dict]:
    """
    Detect potential account compromise:
    failed logins → successful login → new device/privilege change
    """
    clusters = []
    window_minutes = 60  # 1-hour window

    # Group by (source_ip, username)
    groups = defaultdict(list)
    for alert in alerts:
        if alert.username and alert.event_type in (
            "failed_login", "successful_login", "new_device_login",
            "privilege_escalation", "password_reset"
        ):
            groups[(alert.source_ip, alert.username)].append(alert)

    for (src_ip, username), group_alerts in groups.items():
        sorted_alerts = sorted(group_alerts, key=lambda a: a.timestamp)

        # Look for the pattern: failures → success → escalation
        failures = [a for a in sorted_alerts if a.event_type == "failed_login"]
        successes = [a for a in sorted_alerts if a.event_type in ("successful_login", "new_device_login")]
        escalations = [a for a in sorted_alerts if a.event_type in ("privilege_escalation", "new_device_login")]

        if len(failures) < 5 or not successes:
            continue

        # Check if success came after failures
        last_failure = max(a.timestamp for a in failures)
        for success in successes:
            if success.timestamp > last_failure:
                time_diff = (success.timestamp - last_failure).total_seconds() / 60
                if time_diff <= window_minutes:
                    # Found the pattern
                    related_alerts = failures + successes + escalations
                    alert_ids = set(a.alert_id for a in related_alerts)

                    clusters.append({
                        "type": "account_compromise",
                        "alert_ids": alert_ids,
                        "alerts": related_alerts,
                        "source_ip": src_ip,
                        "username": username,
                        "title": f"Suspicious account access pattern for {username}",
                    })
                    break

    return clusters


def _detect_port_scanning(alerts: List[Alert]) -> List[Dict]:
    """Detect port scanning: one IP probes many ports/hosts."""
    clusters = []
    threshold = settings.PORT_SCAN_THRESHOLD

    # Group port_scan events by source IP
    ip_groups = defaultdict(list)
    for alert in alerts:
        if alert.event_type == "port_scan":
            ip_groups[alert.source_ip].append(alert)

    for src_ip, group_alerts in ip_groups.items():
        if len(group_alerts) < threshold:
            continue

        ports = set(a.destination_port for a in group_alerts if a.destination_port)
        destinations = set(a.destination_ip for a in group_alerts if a.destination_ip)
        alert_ids = set(a.alert_id for a in group_alerts)

        clusters.append({
            "type": "port_scanning",
            "alert_ids": alert_ids,
            "alerts": group_alerts,
            "source_ip": src_ip,
            "ports": list(ports),
            "destinations": list(destinations),
            "title": f"Network scanning from {src_ip} — {len(ports)} ports, {len(destinations)} hosts",
        })

    return clusters


def _detect_malware_chains(alerts: List[Alert]) -> List[Dict]:
    """Detect malware activity chains: suspicious_process + malware + C2 comms."""
    clusters = []
    malware_events = {"suspicious_process", "malware_detected"}
    c2_events = {"suspicious_dns", "large_outbound_transfer"}

    # Group by hostname/user
    groups = defaultdict(list)
    for alert in alerts:
        if alert.event_type in malware_events | c2_events:
            key = (alert.hostname, alert.username or "")
            groups[key].append(alert)

    for (hostname, username), group_alerts in groups.items():
        malware = [a for a in group_alerts if a.event_type in malware_events]
        c2 = [a for a in group_alerts if a.event_type in c2_events]

        if malware and c2:
            all_alerts = malware + c2
            alert_ids = set(a.alert_id for a in all_alerts)

            clusters.append({
                "type": "malware",
                "alert_ids": alert_ids,
                "alerts": all_alerts,
                "hostname": hostname,
                "username": username,
                "title": f"Potential malware activity on {hostname}",
            })
        elif len(malware) >= 2:
            alert_ids = set(a.alert_id for a in malware)
            clusters.append({
                "type": "malware",
                "alert_ids": alert_ids,
                "alerts": malware,
                "hostname": hostname,
                "username": username,
                "title": f"Suspicious process activity on {hostname}",
            })

    return clusters


def _detect_data_exfiltration(alerts: List[Alert]) -> List[Dict]:
    """Detect data exfiltration: large outbound transfers to external IPs."""
    clusters = []

    exfil_alerts = [a for a in alerts if a.event_type == "large_outbound_transfer"]

    # Group by user
    user_groups = defaultdict(list)
    for alert in exfil_alerts:
        if alert.username:
            user_groups[alert.username].append(alert)

    for username, group_alerts in user_groups.items():
        if len(group_alerts) >= 2:
            # Also find recent login activity for context
            user_logins = [
                a for a in alerts
                if a.username == username and a.event_type in ("successful_login", "failed_login")
                and any(abs((a.timestamp - ea.timestamp).total_seconds()) < 7200 for ea in group_alerts)
            ]

            all_alerts = group_alerts + user_logins
            alert_ids = set(a.alert_id for a in all_alerts)

            clusters.append({
                "type": "data_exfiltration",
                "alert_ids": alert_ids,
                "alerts": all_alerts,
                "username": username,
                "title": f"Potential data exfiltration by {username}",
            })

    return clusters


def _detect_impossible_travel(alerts: List[Alert]) -> List[Dict]:
    """Detect impossible travel: same user, two distant locations, short time."""
    clusters = []

    # Find impossible_travel event type alerts
    travel_alerts = [a for a in alerts if a.event_type == "impossible_travel"]

    for alert in travel_alerts:
        # Find nearby login events for same user
        related = [
            a for a in alerts
            if a.username == alert.username
            and a.event_type in ("successful_login", "new_device_login", "impossible_travel")
            and abs((a.timestamp - alert.timestamp).total_seconds()) < 3600
        ]

        if related:
            alert_ids = set(a.alert_id for a in related)
            alert_ids.add(alert.alert_id)

            countries = set(a.country for a in related if a.country)

            clusters.append({
                "type": "impossible_travel",
                "alert_ids": alert_ids,
                "alerts": related,
                "username": alert.username,
                "countries": list(countries),
                "title": f"Impossible travel detected for {alert.username}",
            })

    return clusters


def _detect_phishing(alerts: List[Alert]) -> List[Dict]:
    """Detect phishing campaigns: multiple phishing detections + post-click activity."""
    clusters = []

    phishing_alerts = [a for a in alerts if a.event_type == "phishing_detected"]
    if not phishing_alerts:
        return clusters

    # Group by source (attacker) IP
    src_groups = defaultdict(list)
    for alert in phishing_alerts:
        src_groups[alert.source_ip].append(alert)

    for src_ip, group_alerts in src_groups.items():
        # Find post-click activity from targeted users
        targeted_users = set(a.username for a in group_alerts if a.username)
        post_click = [
            a for a in alerts
            if a.username in targeted_users
            and a.event_type in ("suspicious_process", "malware_detected")
            and any(
                0 < (a.timestamp - pa.timestamp).total_seconds() < 3600
                for pa in group_alerts
            )
        ]

        all_alerts = group_alerts + post_click
        alert_ids = set(a.alert_id for a in all_alerts)

        clusters.append({
            "type": "phishing",
            "alert_ids": alert_ids,
            "alerts": all_alerts,
            "source_ip": src_ip,
            "targeted_users": list(targeted_users),
            "title": f"Phishing campaign targeting {len(targeted_users)} users",
        })

    return clusters


def _detect_mfa_attacks(alerts: List[Alert]) -> List[Dict]:
    """Detect MFA fatigue / push bombing attacks."""
    clusters = []

    mfa_alerts = [a for a in alerts if a.event_type == "multiple_failed_mfa"]

    # Group by username
    user_groups = defaultdict(list)
    for alert in mfa_alerts:
        if alert.username:
            user_groups[alert.username].append(alert)

    for username, group_alerts in user_groups.items():
        if len(group_alerts) >= 5:
            # Check if eventually succeeded
            successes = [
                a for a in alerts
                if a.username == username
                and a.event_type == "successful_login"
                and any(
                    0 < (a.timestamp - ma.timestamp).total_seconds() < 3600
                    for ma in group_alerts
                )
            ]

            all_alerts = group_alerts + successes
            alert_ids = set(a.alert_id for a in all_alerts)

            clusters.append({
                "type": "mfa_fatigue",
                "alert_ids": alert_ids,
                "alerts": all_alerts,
                "username": username,
                "title": f"Potential MFA fatigue attack against {username}",
            })

    return clusters


def _detect_suspicious_dns(alerts: List[Alert]) -> List[Dict]:
    """Detect suspicious DNS activity patterns."""
    clusters = []

    dns_alerts = [a for a in alerts if a.event_type == "suspicious_dns"]

    # Group by source host / user
    user_groups = defaultdict(list)
    for alert in dns_alerts:
        key = alert.username or alert.hostname or alert.source_ip
        user_groups[key].append(alert)

    for key, group_alerts in user_groups.items():
        if len(group_alerts) >= 5:
            alert_ids = set(a.alert_id for a in group_alerts)

            clusters.append({
                "type": "suspicious_dns",
                "alert_ids": alert_ids,
                "alerts": group_alerts,
                "source": key,
                "title": f"Suspicious DNS activity from {key}",
            })

    return clusters


def _detect_lateral_movement(alerts: List[Alert]) -> List[Dict]:
    """Detect lateral movement: compromised user trying to access multiple internal systems."""
    clusters = []

    # Look for one user/IP failing to login across multiple hosts
    groups = defaultdict(list)
    for alert in alerts:
        if alert.event_type == "failed_login" and alert.username:
            groups[(alert.source_ip, alert.username)].append(alert)

    for (src_ip, username), group_alerts in groups.items():
        targets = set(a.hostname for a in group_alerts if a.hostname)
        if len(targets) >= 3:  # Targeting 3+ different hosts
            alert_ids = set(a.alert_id for a in group_alerts)
            clusters.append({
                "type": "lateral_movement",
                "alert_ids": alert_ids,
                "alerts": group_alerts,
                "source_ip": src_ip,
                "username": username,
                "targets": list(targets),
                "title": f"Potential lateral movement by {username} from {src_ip}",
            })

    return clusters


def _temporal_cluster(alerts: List[Alert], window_minutes: int) -> List[List[Alert]]:
    """Group alerts into temporal clusters within a sliding window."""
    if not alerts:
        return []

    clusters = []
    current_cluster = [alerts[0]]

    for i in range(1, len(alerts)):
        time_diff = (alerts[i].timestamp - current_cluster[0].timestamp).total_seconds() / 60
        if time_diff <= window_minutes:
            current_cluster.append(alerts[i])
        else:
            if len(current_cluster) >= 2:
                clusters.append(current_cluster)
            current_cluster = [alerts[i]]

    if len(current_cluster) >= 2:
        clusters.append(current_cluster)

    return clusters if clusters else [alerts]


def _find_related_events(
    all_alerts: List[Alert], source_ip: str, username: str,
    cluster_alerts: List[Alert], window_minutes: int
) -> List[Alert]:
    """Find events related to a cluster (e.g., account_locked, successful_login after failures)."""
    if not cluster_alerts:
        return []

    min_ts = min(a.timestamp for a in cluster_alerts)
    max_ts = max(a.timestamp for a in cluster_alerts) + timedelta(minutes=window_minutes)
    cluster_ids = set(a.alert_id for a in cluster_alerts)

    related = []
    for alert in all_alerts:
        if alert.alert_id in cluster_ids:
            continue
        if min_ts <= alert.timestamp <= max_ts:
            if (alert.source_ip == source_ip or alert.username == username):
                if alert.event_type in (
                    "account_locked", "successful_login", "new_device_login",
                    "privilege_escalation", "password_reset"
                ):
                    related.append(alert)

    return related


def _merge_overlapping_clusters(clusters: List[Dict]) -> List[Dict]:
    """Merge clusters that share significant alert overlap."""
    if not clusters:
        return []

    # Build a graph of overlapping clusters
    n = len(clusters)
    merged = [False] * n
    result = []

    for i in range(n):
        if merged[i]:
            continue

        current = clusters[i].copy()
        current_ids = set(current["alert_ids"])

        # Check for overlaps with subsequent clusters
        for j in range(i + 1, n):
            if merged[j]:
                continue

            other_ids = set(clusters[j]["alert_ids"])
            overlap = current_ids & other_ids

            # Merge if >30% overlap
            if overlap and len(overlap) / min(len(current_ids), len(other_ids)) > 0.3:
                current_ids |= other_ids
                current["alert_ids"] = current_ids
                # Merge alerts lists
                existing_alert_ids = set(a.alert_id for a in current.get("alerts", []))
                for alert in clusters[j].get("alerts", []):
                    if alert.alert_id not in existing_alert_ids:
                        current["alerts"].append(alert)
                merged[j] = True

        result.append(current)

    return result


def _create_incident_from_cluster(idx: int, cluster: Dict, db: Session) -> Optional[Incident]:
    """Create an Incident object from a correlated cluster."""
    alert_list = cluster.get("alerts", [])
    if not alert_list:
        return None

    alert_ids = set(cluster.get("alert_ids", set()))

    # Collect scope information
    users = set()
    ips = set()
    assets = set()
    event_types = set()
    event_sequence = []
    timestamps = []

    for alert in sorted(alert_list, key=lambda a: a.timestamp):
        if alert.username:
            users.add(alert.username)
        if alert.source_ip:
            ips.add(alert.source_ip)
        if alert.hostname:
            assets.add(alert.hostname)
        event_types.add(alert.event_type)
        event_sequence.append(alert.event_type)
        timestamps.append(alert.timestamp)

    # Determine severity
    severity = _determine_severity(cluster, alert_list)

    incident = Incident(
        incident_id=f"INC-{idx:04d}",
        title=cluster.get("title", f"Security Incident #{idx}"),
        severity=severity,
        risk_score=0.0,  # Will be calculated by risk scoring service
        alert_count=len(alert_ids),
        affected_users=list(users),
        source_ips=list(ips),
        affected_assets=list(assets),
        event_types=list(event_types),
        event_sequence=event_sequence[:100],  # Cap at 100 events
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        correlation_type=cluster.get("type", "unknown"),
        correlation_details={
            "cluster_type": cluster.get("type"),
            "alert_count": len(alert_ids),
        },
    )

    # Store alert IDs for later association
    incident._alert_ids = list(alert_ids)

    return incident


def _determine_severity(cluster: Dict, alerts: List[Alert]) -> str:
    """Determine incident severity based on cluster type and alert severities."""
    cluster_type = cluster.get("type", "")

    # Base severity by cluster type
    type_severity = {
        "brute_force": "high",
        "password_spraying": "high",
        "account_compromise": "critical",
        "port_scanning": "medium",
        "malware": "critical",
        "data_exfiltration": "critical",
        "impossible_travel": "high",
        "phishing": "high",
        "mfa_fatigue": "high",
        "suspicious_dns": "medium",
        "lateral_movement": "high",
    }

    severity = type_severity.get(cluster_type, "medium")

    # Upgrade if many alerts or critical individual alerts
    critical_alerts = sum(1 for a in alerts if a.severity == "critical")
    if critical_alerts > 0:
        severity = "critical"

    if len(alerts) > 100 and severity == "high":
        severity = "critical"

    return severity


def build_correlation_graph(db: Session) -> Dict:
    """
    Build a NetworkX graph of entity relationships for visualization.
    Returns graph data in a frontend-consumable format.
    """
    alerts = (
        db.query(Alert)
        .filter(Alert.is_duplicate == False)
        .all()
    )

    G = nx.Graph()

    # Add nodes and edges
    for alert in alerts:
        if alert.source_ip:
            G.add_node(alert.source_ip, type="ip")
        if alert.username:
            G.add_node(alert.username, type="user")
            if alert.source_ip:
                if G.has_edge(alert.source_ip, alert.username):
                    G[alert.source_ip][alert.username]["weight"] += 1
                else:
                    G.add_edge(alert.source_ip, alert.username, weight=1, type="LOGIN_FROM")

        if alert.device_id:
            G.add_node(alert.device_id, type="device")
            if alert.username:
                if G.has_edge(alert.username, alert.device_id):
                    G[alert.username][alert.device_id]["weight"] += 1
                else:
                    G.add_edge(alert.username, alert.device_id, weight=1, type="USED_BY")

        if alert.hostname:
            G.add_node(alert.hostname, type="host")
            if alert.source_ip:
                if G.has_edge(alert.source_ip, alert.hostname):
                    G[alert.source_ip][alert.hostname]["weight"] += 1
                else:
                    G.add_edge(alert.source_ip, alert.hostname, weight=1, type="TARGETED")

    # Add incident nodes
    incidents = db.query(Incident).all()
    for incident in incidents:
        G.add_node(incident.incident_id, type="incident")
        for user in (incident.affected_users or []):
            if G.has_node(user):
                G.add_edge(incident.incident_id, user, weight=1, type="AFFECTED")
        for ip in (incident.source_ips or []):
            if G.has_node(ip):
                G.add_edge(incident.incident_id, ip, weight=1, type="CONNECTED_TO")

    # Convert to serializable format — only include high-activity nodes
    nodes = []
    edges = []

    # Filter to nodes with degree > 1 for readability
    significant_nodes = [n for n in G.nodes() if G.degree(n) >= 2 or G.nodes[n].get("type") == "incident"]

    subgraph = G.subgraph(significant_nodes)

    for node in subgraph.nodes():
        nodes.append({
            "id": node,
            "type": subgraph.nodes[node].get("type", "unknown"),
            "degree": subgraph.degree(node),
        })

    for u, v, data in subgraph.edges(data=True):
        edges.append({
            "source": u,
            "target": v,
            "weight": data.get("weight", 1),
            "type": data.get("type", "CONNECTED"),
        })

    return {
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }
