"""
SentinelAI — Synthetic Alert Dataset Generator

Generates ~3,000 realistic security alerts with:
- Benign activity (normal logins, service accounts, public Wi-Fi, etc.)
- Planted attack scenarios (brute force, password spraying, port scanning, etc.)
- Ground truth labels for evaluation

Uses documentation IP ranges (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
"""

import csv
import json
import random
import os
from datetime import datetime, timedelta
from typing import List, Dict, Tuple

# Seed for reproducibility
random.seed(42)

# ─── Constants ────────────────────────────────────────────────────────────────

BASE_DATE = datetime(2026, 9, 29, 6, 0, 0)  # Start at 6 AM

# Documentation IPs (RFC 5737)
CORPORATE_IPS = [f"10.0.0.{i}" for i in range(1, 51)]
CORPORATE_NAT_IP = "198.51.100.1"
PUBLIC_WIFI_IPS = ["203.0.113.50", "203.0.113.51"]
VPN_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
ATTACKER_IPS = [
    "203.0.113.25",  # brute force attacker
    "203.0.113.30",  # password sprayer
    "203.0.113.35",  # port scanner
    "203.0.113.40",  # malware C2
    "203.0.113.45",  # data exfil
]
SCANNER_IP = "192.0.2.100"  # vulnerability scanner
MONITORING_IP = "192.0.2.101"  # monitoring system

# Internal server IPs
SERVERS = {
    "prod-auth-01": "10.0.0.10",
    "prod-web-01": "10.0.0.11",
    "prod-db-01": "10.0.0.12",
    "prod-app-01": "10.0.0.13",
    "dev-web-01": "10.0.0.20",
    "staging-app-01": "10.0.0.30",
    "hr-portal-01": "10.0.0.40",
    "finance-db-01": "10.0.0.41",
    "mail-server-01": "10.0.0.50",
    "dns-server-01": "10.0.0.51",
}

ASSET_CRITICALITY = {
    "prod-auth-01": 9,
    "prod-web-01": 7,
    "prod-db-01": 10,
    "prod-app-01": 7,
    "dev-web-01": 3,
    "staging-app-01": 4,
    "hr-portal-01": 6,
    "finance-db-01": 9,
    "mail-server-01": 7,
    "dns-server-01": 8,
}

NORMAL_USERS = [
    "alice", "bob", "charlie", "david", "eve", "frank",
    "grace", "heidi", "ivan", "judy", "karl", "linda",
    "mike", "nancy", "oscar", "pat", "quinn", "rachel",
    "steve", "tina", "ursula", "victor", "wendy", "xander",
    "yolanda", "zack",
]

SERVICE_ACCOUNTS = ["svc-backup", "svc-monitor", "svc-deploy", "svc-scanner"]

DEVICES = {
    "alice": ["device-alice-mac", "device-alice-iphone"],
    "bob": ["device-bob-win", "device-bob-android"],
    "charlie": ["device-charlie-mac"],
    "david": ["device-david-win", "device-david-ipad"],
    "eve": ["device-eve-linux"],
    "frank": ["device-frank-win"],
    "grace": ["device-grace-mac", "device-grace-iphone"],
    "heidi": ["device-heidi-win"],
    "ivan": ["device-ivan-mac"],
    "judy": ["device-judy-win", "device-judy-android"],
}

# Default devices for users not in DEVICES dict
DEFAULT_DEVICE_PREFIX = "device"

COUNTRIES = {
    "corporate": "US",
    "vpn": "US",
    "public_wifi": "US",
    "attacker_1": "RU",
    "attacker_2": "CN",
    "attacker_3": "BR",
    "travel": "DE",
    "india": "IN",
}

PROTOCOLS = {
    "failed_login": "SSH",
    "successful_login": "SSH",
    "password_reset": "HTTPS",
    "account_locked": "LDAP",
    "port_scan": "TCP",
    "malware_detected": "HTTPS",
    "suspicious_process": "LOCAL",
    "privilege_escalation": "LOCAL",
    "large_outbound_transfer": "HTTPS",
    "new_device_login": "SSH",
    "impossible_travel": "HTTPS",
    "phishing_detected": "SMTP",
    "suspicious_dns": "DNS",
    "multiple_failed_mfa": "HTTPS",
}

SEVERITY_MAP = {
    "failed_login": "low",
    "successful_login": "info",
    "password_reset": "low",
    "account_locked": "medium",
    "port_scan": "medium",
    "malware_detected": "critical",
    "suspicious_process": "high",
    "privilege_escalation": "high",
    "large_outbound_transfer": "high",
    "new_device_login": "medium",
    "impossible_travel": "high",
    "phishing_detected": "high",
    "suspicious_dns": "medium",
    "multiple_failed_mfa": "medium",
}

MESSAGES = {
    "failed_login": "Failed authentication attempt",
    "successful_login": "Successful authentication",
    "password_reset": "Password reset requested",
    "account_locked": "Account locked due to multiple failures",
    "port_scan": "Port scan detected",
    "malware_detected": "Malware signature detected",
    "suspicious_process": "Suspicious process execution detected",
    "privilege_escalation": "Privilege escalation attempt detected",
    "large_outbound_transfer": "Unusually large outbound data transfer",
    "new_device_login": "Login from previously unseen device",
    "impossible_travel": "Login from geographically impossible location",
    "phishing_detected": "Phishing email detected",
    "suspicious_dns": "Suspicious DNS query detected",
    "multiple_failed_mfa": "Multiple failed MFA attempts",
}

# ─── Alert counter ────────────────────────────────────────────────────────────

alert_counter = 0


def next_alert_id() -> str:
    global alert_counter
    alert_counter += 1
    return f"ALT-{alert_counter:06d}"


def make_alert(
    timestamp: datetime,
    source_ip: str,
    destination_ip: str,
    username: str,
    hostname: str,
    event_type: str,
    device_id: str = None,
    country: str = "US",
    source_port: int = None,
    destination_port: int = None,
    severity: str = None,
    asset_criticality: int = None,
    message: str = None,
    scenario_id: str = None,
    scenario_type: str = None,
    is_malicious: bool = None,
    expected_mitre: str = None,
) -> Dict:
    if source_port is None:
        source_port = random.randint(1024, 65535)
    if destination_port is None:
        destination_port = {"SSH": 22, "HTTPS": 443, "SMTP": 25, "DNS": 53,
                            "LDAP": 389, "TCP": random.randint(1, 1024),
                            "LOCAL": 0}.get(PROTOCOLS.get(event_type, "TCP"), 0)
    if severity is None:
        severity = SEVERITY_MAP.get(event_type, "medium")
    if asset_criticality is None:
        asset_criticality = ASSET_CRITICALITY.get(hostname, 5)
    if message is None:
        message = MESSAGES.get(event_type, "Security event detected")
    if device_id is None:
        devices = DEVICES.get(username, [f"{DEFAULT_DEVICE_PREFIX}-{username}-default"])
        device_id = random.choice(devices)

    return {
        "alert_id": next_alert_id(),
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "username": username,
        "hostname": hostname,
        "event_type": event_type,
        "severity": severity,
        "asset_criticality": asset_criticality,
        "protocol": PROTOCOLS.get(event_type, "TCP"),
        "country": country,
        "device_id": device_id,
        "message": message,
        "raw_log": f"<syslog>{timestamp.isoformat()} {source_ip} {event_type} user={username} host={hostname}",
        "scenario_id": scenario_id or "",
        "scenario_type": scenario_type or "",
        "is_malicious": str(is_malicious).lower() if is_malicious is not None else "",
        "expected_mitre": expected_mitre or "",
    }


# ─── Benign Activity Generators ──────────────────────────────────────────────

def generate_normal_logins(alerts: List[Dict], count: int = 800):
    """Normal employee logins throughout the workday."""
    for _ in range(count):
        user = random.choice(NORMAL_USERS)
        # Working hours 8-19 with some noise
        hour = random.gauss(13, 3)
        hour = max(6, min(22, int(hour)))
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=second)

        src_ip = random.choice(CORPORATE_IPS[:20])
        hostname = random.choice(list(SERVERS.keys()))

        event_type = "successful_login"
        # ~5% normal failures (typos, wrong password)
        if random.random() < 0.05:
            event_type = "failed_login"

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type=event_type,
            country="US",
            scenario_id="S_BENIGN_01",
            scenario_type="normal_login",
            is_malicious=False,
        ))


def generate_vpn_logins(alerts: List[Dict], count: int = 200):
    """Remote users connecting via VPN."""
    vpn_users = random.sample(NORMAL_USERS, 8)
    for _ in range(count):
        user = random.choice(vpn_users)
        hour = random.randint(7, 21)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        vpn_ip = random.choice(VPN_IPS)
        hostname = random.choice(list(SERVERS.keys())[:5])

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=vpn_ip,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type="successful_login",
            country="US",
            scenario_id="S_BENIGN_02",
            scenario_type="vpn_login",
            is_malicious=False,
        ))


def generate_public_wifi_logins(alerts: List[Dict], count: int = 150):
    """Multiple users from same public Wi-Fi IP — legitimate shared IP."""
    wifi_users = random.sample(NORMAL_USERS, 12)
    for _ in range(count):
        user = random.choice(wifi_users)
        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        wifi_ip = random.choice(PUBLIC_WIFI_IPS)
        hostname = random.choice(list(SERVERS.keys())[:4])

        event_type = "successful_login"
        # Some normal failures from public wifi
        if random.random() < 0.08:
            event_type = "failed_login"

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=wifi_ip,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type=event_type,
            country="US",
            scenario_id="S_BENIGN_03",
            scenario_type="public_wifi",
            is_malicious=False,
        ))


def generate_corporate_nat_logins(alerts: List[Dict], count: int = 180):
    """Users behind corporate NAT — all show same external IP."""
    nat_users = random.sample(NORMAL_USERS, 15)
    for _ in range(count):
        user = random.choice(nat_users)
        hour = random.randint(8, 18)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        hostname = random.choice(list(SERVERS.keys())[:6])

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=CORPORATE_NAT_IP,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type="successful_login",
            country="US",
            scenario_id="S_BENIGN_04",
            scenario_type="corporate_nat",
            is_malicious=False,
        ))


def generate_service_account_activity(alerts: List[Dict], count: int = 120):
    """Service accounts doing routine work."""
    for _ in range(count):
        user = random.choice(SERVICE_ACCOUNTS)
        # Service accounts run at all hours
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        hostname = random.choice(list(SERVERS.keys()))

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=random.choice(CORPORATE_IPS[40:50]),
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type="successful_login",
            device_id=f"device-{user}",
            country="US",
            scenario_id="S_BENIGN_05",
            scenario_type="service_account",
            is_malicious=False,
        ))


def generate_vulnerability_scanner(alerts: List[Dict], count: int = 100):
    """Scheduled vulnerability scanner activity."""
    # Scanner runs between 2-4 AM
    for _ in range(count):
        hour = random.randint(2, 3)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        hostname = random.choice(list(SERVERS.keys()))
        port = random.randint(1, 1024)

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=SCANNER_IP,
            destination_ip=SERVERS[hostname],
            username="svc-scanner",
            hostname=hostname,
            event_type="port_scan",
            destination_port=port,
            device_id="device-vuln-scanner",
            country="US",
            severity="info",
            scenario_id="S_BENIGN_06",
            scenario_type="vulnerability_scanner",
            is_malicious=False,
        ))


def generate_monitoring_checks(alerts: List[Dict], count: int = 80):
    """Monitoring system health checks."""
    for _ in range(count):
        hour = random.randint(0, 23)
        minute = random.randint(0, 59)
        ts = BASE_DATE.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        hostname = random.choice(list(SERVERS.keys()))

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=MONITORING_IP,
            destination_ip=SERVERS[hostname],
            username="svc-monitor",
            hostname=hostname,
            event_type="successful_login",
            device_id="device-monitoring",
            country="US",
            severity="info",
            scenario_id="S_BENIGN_07",
            scenario_type="monitoring",
            is_malicious=False,
        ))


def generate_password_resets(alerts: List[Dict], count: int = 40):
    """Normal password reset activity."""
    for _ in range(count):
        user = random.choice(NORMAL_USERS)
        hour = random.randint(8, 18)
        ts = BASE_DATE.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=random.choice(CORPORATE_IPS[:20]),
            destination_ip=SERVERS["prod-auth-01"],
            username=user,
            hostname="prod-auth-01",
            event_type="password_reset",
            country="US",
            scenario_id="S_BENIGN_08",
            scenario_type="normal_password_reset",
            is_malicious=False,
        ))


def generate_normal_failed_logins(alerts: List[Dict], count: int = 60):
    """Users with occasional password typos (2-3 failures then success)."""
    for _ in range(count // 3):
        user = random.choice(NORMAL_USERS)
        hour = random.randint(8, 18)
        base_ts = BASE_DATE.replace(hour=hour, minute=random.randint(0, 59))
        src_ip = random.choice(CORPORATE_IPS[:20])
        hostname = random.choice(list(SERVERS.keys())[:4])

        # 1-3 failures
        num_fails = random.randint(1, 3)
        for i in range(num_fails):
            ts = base_ts + timedelta(seconds=i * random.randint(5, 30))
            alerts.append(make_alert(
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=SERVERS[hostname],
                username=user,
                hostname=hostname,
                event_type="failed_login",
                country="US",
                scenario_id="S_BENIGN_09",
                scenario_type="normal_password_failure",
                is_malicious=False,
            ))

        # Then success
        ts = base_ts + timedelta(seconds=num_fails * 30 + random.randint(5, 60))
        alerts.append(make_alert(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type="successful_login",
            country="US",
            scenario_id="S_BENIGN_09",
            scenario_type="normal_password_failure",
            is_malicious=False,
        ))


# ─── Attack Scenario Generators ──────────────────────────────────────────────

def generate_brute_force(alerts: List[Dict]):
    """Scenario 1: Brute force attack against alice from single IP."""
    attacker_ip = "203.0.113.25"
    target_user = "alice"
    hostname = "prod-auth-01"
    base_ts = BASE_DATE.replace(hour=10, minute=0, second=0)

    # 240 failed logins over ~12 minutes
    for i in range(240):
        ts = base_ts + timedelta(seconds=i * 3)  # one every 3 seconds
        alerts.append(make_alert(
            timestamp=ts,
            source_ip=attacker_ip,
            destination_ip=SERVERS[hostname],
            username=target_user,
            hostname=hostname,
            event_type="failed_login",
            device_id="device-unknown-001",
            country="RU",
            severity="medium",
            scenario_id="S_ATTACK_01",
            scenario_type="brute_force",
            is_malicious=True,
            expected_mitre="T1110",
        ))

    # Account locked
    ts = base_ts + timedelta(minutes=12, seconds=10)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=attacker_ip,
        destination_ip=SERVERS[hostname],
        username=target_user,
        hostname=hostname,
        event_type="account_locked",
        device_id="device-unknown-001",
        country="RU",
        severity="high",
        scenario_id="S_ATTACK_01",
        scenario_type="brute_force",
        is_malicious=True,
        expected_mitre="T1110",
    ))


def generate_password_spraying(alerts: List[Dict]):
    """Scenario 2: Password spraying — one IP tries few passwords against many accounts."""
    attacker_ip = "203.0.113.30"
    target_users = ["alice", "bob", "charlie", "david", "eve", "frank",
                    "grace", "heidi", "ivan", "judy", "karl", "linda",
                    "mike", "nancy", "oscar"]
    hostname = "prod-auth-01"
    base_ts = BASE_DATE.replace(hour=11, minute=0, second=0)

    idx = 0
    for round_num in range(3):  # 3 rounds of spraying
        for user in target_users:
            ts = base_ts + timedelta(seconds=idx * 8)
            alerts.append(make_alert(
                timestamp=ts,
                source_ip=attacker_ip,
                destination_ip=SERVERS[hostname],
                username=user,
                hostname=hostname,
                event_type="failed_login",
                device_id="device-unknown-002",
                country="CN",
                severity="low",
                scenario_id="S_ATTACK_02",
                scenario_type="password_spraying",
                is_malicious=True,
                expected_mitre="T1110.003",
            ))
            idx += 1


def generate_suspicious_account_access(alerts: List[Dict]):
    """Scenario 3: Successful login after many failures + new device + privilege change."""
    attacker_ip = "203.0.113.25"
    target_user = "bob"
    hostname = "prod-auth-01"
    base_ts = BASE_DATE.replace(hour=13, minute=0, second=0)

    # 30 failed logins
    for i in range(30):
        ts = base_ts + timedelta(seconds=i * 10)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip=attacker_ip,
            destination_ip=SERVERS[hostname],
            username=target_user,
            hostname=hostname,
            event_type="failed_login",
            device_id="device-unknown-003",
            country="RU",
            scenario_id="S_ATTACK_03",
            scenario_type="account_compromise",
            is_malicious=True,
            expected_mitre="T1078",
        ))

    # Successful login
    ts = base_ts + timedelta(minutes=6)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=attacker_ip,
        destination_ip=SERVERS[hostname],
        username=target_user,
        hostname=hostname,
        event_type="successful_login",
        device_id="device-unknown-003",
        country="RU",
        scenario_id="S_ATTACK_03",
        scenario_type="account_compromise",
        is_malicious=True,
        expected_mitre="T1078",
    ))

    # New device login
    ts = base_ts + timedelta(minutes=7)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=attacker_ip,
        destination_ip=SERVERS[hostname],
        username=target_user,
        hostname=hostname,
        event_type="new_device_login",
        device_id="device-unknown-003",
        country="RU",
        scenario_id="S_ATTACK_03",
        scenario_type="account_compromise",
        is_malicious=True,
        expected_mitre="T1078",
    ))

    # Privilege escalation
    ts = base_ts + timedelta(minutes=10)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=attacker_ip,
        destination_ip=SERVERS[hostname],
        username=target_user,
        hostname=hostname,
        event_type="privilege_escalation",
        device_id="device-unknown-003",
        country="RU",
        scenario_id="S_ATTACK_03",
        scenario_type="account_compromise",
        is_malicious=True,
        expected_mitre="T1078",
    ))


def generate_port_scanning(alerts: List[Dict]):
    """Scenario 4: Port scanning from single source."""
    attacker_ip = "203.0.113.35"
    base_ts = BASE_DATE.replace(hour=14, minute=0, second=0)

    targets = list(SERVERS.items())
    idx = 0
    for hostname, dest_ip in targets:
        for port in random.sample(range(1, 1025), 15):
            ts = base_ts + timedelta(seconds=idx)
            alerts.append(make_alert(
                timestamp=ts,
                source_ip=attacker_ip,
                destination_ip=dest_ip,
                username="",
                hostname=hostname,
                event_type="port_scan",
                destination_port=port,
                device_id="",
                country="BR",
                scenario_id="S_ATTACK_04",
                scenario_type="port_scanning",
                is_malicious=True,
                expected_mitre="T1046",
            ))
            idx += 1


def generate_malware_activity(alerts: List[Dict]):
    """Scenario 5: Malware on an endpoint."""
    infected_user = "charlie"
    hostname = "prod-app-01"
    base_ts = BASE_DATE.replace(hour=15, minute=0, second=0)
    src_ip = "10.0.0.13"

    # Suspicious process
    alerts.append(make_alert(
        timestamp=base_ts,
        source_ip=src_ip,
        destination_ip=SERVERS[hostname],
        username=infected_user,
        hostname=hostname,
        event_type="suspicious_process",
        device_id="device-charlie-mac",
        country="US",
        scenario_id="S_ATTACK_05",
        scenario_type="malware",
        is_malicious=True,
        expected_mitre="T1204",
    ))

    # Malware detected
    ts = base_ts + timedelta(minutes=2)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=src_ip,
        destination_ip=SERVERS[hostname],
        username=infected_user,
        hostname=hostname,
        event_type="malware_detected",
        device_id="device-charlie-mac",
        country="US",
        severity="critical",
        scenario_id="S_ATTACK_05",
        scenario_type="malware",
        is_malicious=True,
        expected_mitre="T1204",
    ))

    # C2 connection
    ts = base_ts + timedelta(minutes=5)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip=src_ip,
        destination_ip="203.0.113.40",
        username=infected_user,
        hostname=hostname,
        event_type="suspicious_dns",
        device_id="device-charlie-mac",
        country="US",
        scenario_id="S_ATTACK_05",
        scenario_type="malware",
        is_malicious=True,
        expected_mitre="T1071",
    ))

    # More suspicious DNS queries
    for i in range(8):
        ts = base_ts + timedelta(minutes=5 + i)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip="203.0.113.40",
            username=infected_user,
            hostname=hostname,
            event_type="suspicious_dns",
            device_id="device-charlie-mac",
            country="US",
            scenario_id="S_ATTACK_05",
            scenario_type="malware",
            is_malicious=True,
            expected_mitre="T1071",
        ))


def generate_data_exfiltration(alerts: List[Dict]):
    """Scenario 6: Data exfiltration — large outbound transfer."""
    user = "david"
    hostname = "finance-db-01"
    base_ts = BASE_DATE.replace(hour=16, minute=0, second=0)

    # Normal activity first
    for i in range(5):
        ts = base_ts + timedelta(minutes=i * 3)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip="10.0.0.41",
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type="successful_login",
            country="US",
            scenario_id="S_ATTACK_06",
            scenario_type="data_exfiltration",
            is_malicious=True,
            expected_mitre="T1041",
        ))

    # Large outbound transfers
    for i in range(6):
        ts = base_ts + timedelta(minutes=20 + i * 5)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip="10.0.0.41",
            destination_ip="203.0.113.45",
            username=user,
            hostname=hostname,
            event_type="large_outbound_transfer",
            country="US",
            severity="high",
            message=f"Large outbound transfer: {random.randint(200, 800)}MB to external IP",
            scenario_id="S_ATTACK_06",
            scenario_type="data_exfiltration",
            is_malicious=True,
            expected_mitre="T1041",
        ))


def generate_impossible_travel(alerts: List[Dict]):
    """Scenario 7: Impossible travel — user logs in from two distant locations."""
    user = "eve"
    hostname = "prod-web-01"
    base_ts = BASE_DATE.replace(hour=10, minute=0, second=0)

    # Login from India
    alerts.append(make_alert(
        timestamp=base_ts,
        source_ip="192.0.2.50",
        destination_ip=SERVERS[hostname],
        username=user,
        hostname=hostname,
        event_type="successful_login",
        device_id="device-eve-linux",
        country="IN",
        scenario_id="S_ATTACK_07",
        scenario_type="impossible_travel",
        is_malicious=True,
        expected_mitre="T1078.004",
    ))

    # Login from Germany 20 minutes later
    ts = base_ts + timedelta(minutes=20)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip="192.0.2.55",
        destination_ip=SERVERS[hostname],
        username=user,
        hostname=hostname,
        event_type="successful_login",
        device_id="device-unknown-travel",
        country="DE",
        scenario_id="S_ATTACK_07",
        scenario_type="impossible_travel",
        is_malicious=True,
        expected_mitre="T1078.004",
    ))

    # Impossible travel alert
    ts = base_ts + timedelta(minutes=21)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip="192.0.2.55",
        destination_ip=SERVERS[hostname],
        username=user,
        hostname=hostname,
        event_type="impossible_travel",
        device_id="device-unknown-travel",
        country="DE",
        scenario_id="S_ATTACK_07",
        scenario_type="impossible_travel",
        is_malicious=True,
        expected_mitre="T1078.004",
    ))


def generate_phishing_campaign(alerts: List[Dict]):
    """Scenario 8: Phishing emails targeting multiple users."""
    targeted_users = ["frank", "grace", "heidi", "ivan", "judy"]
    base_ts = BASE_DATE.replace(hour=9, minute=30, second=0)

    for i, user in enumerate(targeted_users):
        ts = base_ts + timedelta(minutes=i * 2)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip="192.0.2.60",
            destination_ip=SERVERS["mail-server-01"],
            username=user,
            hostname="mail-server-01",
            event_type="phishing_detected",
            country="NG",
            severity="high",
            message=f"Phishing email detected: suspicious attachment from external sender",
            scenario_id="S_ATTACK_08",
            scenario_type="phishing",
            is_malicious=True,
            expected_mitre="T1566",
        ))

    # One user clicked the link
    ts = base_ts + timedelta(minutes=15)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip="10.0.0.13",
        destination_ip="192.0.2.60",
        username="frank",
        hostname="prod-app-01",
        event_type="suspicious_process",
        country="US",
        severity="high",
        message="Process spawned from email attachment",
        scenario_id="S_ATTACK_08",
        scenario_type="phishing",
        is_malicious=True,
        expected_mitre="T1566",
    ))


def generate_mfa_attack(alerts: List[Dict]):
    """Scenario 9: MFA fatigue / push bombing attack."""
    target_user = "grace"
    base_ts = BASE_DATE.replace(hour=12, minute=0, second=0)

    for i in range(20):
        ts = base_ts + timedelta(seconds=i * 30)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip="203.0.113.25",
            destination_ip=SERVERS["prod-auth-01"],
            username=target_user,
            hostname="prod-auth-01",
            event_type="multiple_failed_mfa",
            device_id="device-unknown-mfa",
            country="RU",
            scenario_id="S_ATTACK_09",
            scenario_type="mfa_fatigue",
            is_malicious=True,
            expected_mitre="T1556",
        ))

    # User eventually accepts
    ts = base_ts + timedelta(minutes=12)
    alerts.append(make_alert(
        timestamp=ts,
        source_ip="203.0.113.25",
        destination_ip=SERVERS["prod-auth-01"],
        username=target_user,
        hostname="prod-auth-01",
        event_type="successful_login",
        device_id="device-unknown-mfa",
        country="RU",
        scenario_id="S_ATTACK_09",
        scenario_type="mfa_fatigue",
        is_malicious=True,
        expected_mitre="T1556",
    ))


def generate_internal_recon(alerts: List[Dict]):
    """Scenario 10: After account compromise, internal reconnaissance."""
    user = "bob"  # Same user from scenario 3 (compromised account)
    base_ts = BASE_DATE.replace(hour=13, minute=30, second=0)

    # Scanning internal network
    internal_targets = list(SERVERS.items())[:6]
    idx = 0
    for hostname, dest_ip in internal_targets:
        for port in [22, 80, 443, 3389, 5432]:
            ts = base_ts + timedelta(seconds=idx * 5)
            alerts.append(make_alert(
                timestamp=ts,
                source_ip="203.0.113.25",
                destination_ip=dest_ip,
                username=user,
                hostname=hostname,
                event_type="port_scan",
                destination_port=port,
                device_id="device-unknown-003",
                country="RU",
                scenario_id="S_ATTACK_10",
                scenario_type="internal_recon",
                is_malicious=True,
                expected_mitre="T1046",
            ))
            idx += 1


def generate_lateral_movement_attempt(alerts: List[Dict]):
    """Scenario 11: Lateral movement attempts after initial compromise."""
    base_ts = BASE_DATE.replace(hour=14, minute=30, second=0)
    compromised_ip = "203.0.113.25"

    # Try to login to multiple internal servers
    targets = ["prod-db-01", "finance-db-01", "hr-portal-01"]
    idx = 0
    for hostname in targets:
        for i in range(8):
            ts = base_ts + timedelta(seconds=idx * 15)
            alerts.append(make_alert(
                timestamp=ts,
                source_ip=compromised_ip,
                destination_ip=SERVERS[hostname],
                username="bob",
                hostname=hostname,
                event_type="failed_login",
                device_id="device-unknown-003",
                country="RU",
                scenario_id="S_ATTACK_11",
                scenario_type="lateral_movement",
                is_malicious=True,
                expected_mitre="T1078",
            ))
            idx += 1


def generate_suspicious_dns_exfil(alerts: List[Dict]):
    """Scenario 12: DNS-based data exfiltration."""
    base_ts = BASE_DATE.replace(hour=17, minute=0, second=0)
    user = "heidi"

    for i in range(25):
        ts = base_ts + timedelta(seconds=i * 20)
        alerts.append(make_alert(
            timestamp=ts,
            source_ip="10.0.0.13",
            destination_ip=SERVERS["dns-server-01"],
            username=user,
            hostname="dns-server-01",
            event_type="suspicious_dns",
            destination_port=53,
            country="US",
            message=f"Suspicious DNS query: {random.choice(['aGVsbG8', 'dGVzdA', 'ZGF0YQ'])}.evil-domain.example.com",
            scenario_id="S_ATTACK_12",
            scenario_type="dns_exfiltration",
            is_malicious=True,
            expected_mitre="T1071",
        ))


def generate_duplicate_alerts(alerts: List[Dict], count: int = 300):
    """Generate near-duplicate alerts (same event re-reported by different sensors)."""
    # Pick existing malicious alerts and create near-duplicates
    source_alerts = [a for a in alerts if a.get("is_malicious") == "true"]
    if not source_alerts:
        return

    for _ in range(count):
        original = random.choice(source_alerts)
        ts = datetime.strptime(original["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
        # Add small time jitter (0-30 seconds)
        ts = ts + timedelta(seconds=random.randint(0, 30))

        dup = make_alert(
            timestamp=ts,
            source_ip=original["source_ip"],
            destination_ip=original["destination_ip"],
            username=original["username"],
            hostname=original["hostname"],
            event_type=original["event_type"],
            device_id=original.get("device_id", ""),
            country=original.get("country", "US"),
            severity=original.get("severity", "medium"),
            message=original.get("message", "") + " [duplicate sensor report]",
            scenario_id=original.get("scenario_id", ""),
            scenario_type=original.get("scenario_type", ""),
            is_malicious=original.get("is_malicious") == "true",
            expected_mitre=original.get("expected_mitre", ""),
        )
        alerts.append(dup)


def generate_noise_alerts(alerts: List[Dict], count: int = 200):
    """Random noise alerts to pad to ~3000."""
    event_types = [
        "failed_login", "successful_login", "suspicious_dns",
        "port_scan", "password_reset",
    ]
    for _ in range(count):
        hour = random.randint(0, 23)
        ts = BASE_DATE.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        user = random.choice(NORMAL_USERS + SERVICE_ACCOUNTS)
        hostname = random.choice(list(SERVERS.keys()))
        event = random.choice(event_types)
        src_ip = random.choice(CORPORATE_IPS + VPN_IPS + PUBLIC_WIFI_IPS)

        alerts.append(make_alert(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip=SERVERS[hostname],
            username=user,
            hostname=hostname,
            event_type=event,
            country="US",
            scenario_id="S_BENIGN_10",
            scenario_type="noise",
            is_malicious=False,
        ))


# ─── Main Generator ──────────────────────────────────────────────────────────

def generate_dataset():
    """Generate the complete synthetic dataset."""
    alerts: List[Dict] = []

    print("Generating benign activity...")
    generate_normal_logins(alerts, count=800)
    generate_vpn_logins(alerts, count=200)
    generate_public_wifi_logins(alerts, count=150)
    generate_corporate_nat_logins(alerts, count=180)
    generate_service_account_activity(alerts, count=120)
    generate_vulnerability_scanner(alerts, count=100)
    generate_monitoring_checks(alerts, count=80)
    generate_password_resets(alerts, count=40)
    generate_normal_failed_logins(alerts, count=60)

    print("Generating attack scenarios...")
    generate_brute_force(alerts)           # S_ATTACK_01: ~241 alerts
    generate_password_spraying(alerts)     # S_ATTACK_02: ~45 alerts
    generate_suspicious_account_access(alerts)  # S_ATTACK_03: ~33 alerts
    generate_port_scanning(alerts)         # S_ATTACK_04: ~150 alerts
    generate_malware_activity(alerts)      # S_ATTACK_05: ~11 alerts
    generate_data_exfiltration(alerts)     # S_ATTACK_06: ~11 alerts
    generate_impossible_travel(alerts)     # S_ATTACK_07: ~3 alerts
    generate_phishing_campaign(alerts)     # S_ATTACK_08: ~6 alerts
    generate_mfa_attack(alerts)            # S_ATTACK_09: ~21 alerts
    generate_internal_recon(alerts)        # S_ATTACK_10: ~30 alerts
    generate_lateral_movement_attempt(alerts)  # S_ATTACK_11: ~24 alerts
    generate_suspicious_dns_exfil(alerts)  # S_ATTACK_12: ~25 alerts

    print("Generating near-duplicate alerts...")
    generate_duplicate_alerts(alerts, count=300)

    # Pad with noise to reach ~3000
    current_count = len(alerts)
    target = 3000
    if current_count < target:
        generate_noise_alerts(alerts, count=target - current_count)

    # Sort by timestamp
    alerts.sort(key=lambda a: a["timestamp"])

    # Reassign alert IDs in order
    global alert_counter
    alert_counter = 0
    for alert in alerts:
        alert["alert_id"] = next_alert_id()

    print(f"\nTotal alerts generated: {len(alerts)}")

    # Count by scenario
    scenarios = {}
    for a in alerts:
        st = a.get("scenario_type", "unknown")
        scenarios[st] = scenarios.get(st, 0) + 1

    print("\nBreakdown:")
    for scenario, count in sorted(scenarios.items()):
        print(f"  {scenario}: {count}")

    malicious_count = sum(1 for a in alerts if a.get("is_malicious") == "true")
    benign_count = sum(1 for a in alerts if a.get("is_malicious") == "false")
    print(f"\nMalicious: {malicious_count}")
    print(f"Benign: {benign_count}")

    return alerts


def save_alerts_csv(alerts: List[Dict], filepath: str):
    """Save alerts to CSV."""
    if not alerts:
        return

    fieldnames = [
        "alert_id", "timestamp", "source_ip", "destination_ip",
        "source_port", "destination_port", "username", "hostname",
        "event_type", "severity", "asset_criticality", "protocol",
        "country", "device_id", "message", "raw_log",
        "scenario_id", "scenario_type", "is_malicious", "expected_mitre",
    ]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"\nAlerts saved to {filepath}")


def save_ground_truth(alerts: List[Dict], filepath: str):
    """Save ground truth labels for evaluation."""
    fieldnames = ["alert_id", "scenario_id", "scenario_type", "expected_mitre", "is_malicious"]

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow({
                "alert_id": alert["alert_id"],
                "scenario_id": alert.get("scenario_id", ""),
                "scenario_type": alert.get("scenario_type", ""),
                "expected_mitre": alert.get("expected_mitre", ""),
                "is_malicious": alert.get("is_malicious", ""),
            })

    print(f"Ground truth saved to {filepath}")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(script_dir, "..", "data")
    os.makedirs(data_dir, exist_ok=True)

    alerts = generate_dataset()
    save_alerts_csv(alerts, os.path.join(data_dir, "alerts.csv"))
    save_ground_truth(alerts, os.path.join(data_dir, "ground_truth.csv"))
