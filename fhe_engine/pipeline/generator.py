"""
Synthetic Security Telemetry Generator for Confidential SIEM.
Produces realistic normal baseline traffic and MITRE ATT&CK attack scenarios.
"""

import time
import random
import uuid
from typing import List, Optional

from fhe_engine.pipeline.schema import NormalizedLog


class LogGenerator:
    """Generates synthetic enterprise logs with realistic cyber attack signatures."""

    @staticmethod
    def generate_benign_log(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """Generates regular everyday enterprise telemetry (benign baseline)."""
        category = random.choice(["AUTH", "NETWORK", "PROCESS", "FILE", "DNS"])
        proto = "TCP" if category in ("NETWORK", "AUTH") else ("DNS" if category == "DNS" else "TCP")
        port = 443 if proto == "TCP" else (53 if proto == "DNS" else 80)
        auth = "SUCCESS" if category == "AUTH" else "SUCCESS"
        role = random.choices(["STANDARD", "ADMIN", "SERVICE"], weights=[0.85, 0.10, 0.05])[0]

        return NormalizedLog(
            event_id=f"EVT-{uuid.uuid4().hex[:8].upper()}",
            client_id=client_id,
            timestamp=time.time() - random.uniform(0, 3600),
            event_category=category,
            protocol=proto,
            dest_port=port,
            auth_status=auth,
            user_role=role,
            src_ip_type=random.choices(["INTERNAL", "EXTERNAL_TRUSTED"], weights=[0.9, 0.1])[0],
            is_admin_action=False,
            is_powershell_enc=False,
            has_scheduled_task=False,
            is_suspicious_extension=False,
            is_lsass_access=False,
            is_smb_lateral=False,
            failed_login_count=0.0,
            packet_rate_anomaly=random.gauss(0.0, 0.5),
            bytes_transferred_mb=random.uniform(0.05, 5.0),
            file_entropy=random.uniform(2.5, 4.5),
            beacon_jitter=random.uniform(0.4, 0.95),  # High jitter = normal human activity
            unique_ports_scanned=random.uniform(1.0, 3.0),
            file_mod_rate_per_sec=random.uniform(0.0, 2.0),
            process_ancestry_depth=random.uniform(1.0, 2.0),
        )

    @staticmethod
    def generate_brute_force_attack(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """MITRE ATT&CK T1110: Password Spraying / SSH/RDP Brute Force."""
        port = random.choice([22, 3389])
        proto = "SSH" if port == 22 else "RDP"
        return NormalizedLog(
            event_id=f"ATK-BRUTE-{uuid.uuid4().hex[:6].upper()}",
            client_id=client_id,
            timestamp=time.time(),
            event_category="AUTH",
            protocol=proto,
            dest_port=port,
            auth_status=random.choice(["FAILURE", "LOCKOUT"]),
            user_role="STANDARD",
            src_ip_type=random.choice(["SUSPICIOUS_GEO", "TOR_EXIT"]),
            is_admin_action=False,
            is_powershell_enc=False,
            has_scheduled_task=False,
            is_suspicious_extension=False,
            is_lsass_access=False,
            is_smb_lateral=False,
            failed_login_count=random.uniform(15.0, 48.0),
            packet_rate_anomaly=random.uniform(2.5, 5.0),
            bytes_transferred_mb=random.uniform(1.0, 10.0),
            file_entropy=3.2,
            beacon_jitter=0.8,
            unique_ports_scanned=1.0,
            file_mod_rate_per_sec=0.0,
            process_ancestry_depth=1.0,
        )

    @staticmethod
    def generate_ransomware_attack(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """MITRE ATT&CK T1486: Data Encrypted for Impact (Ransomware Burst)."""
        return NormalizedLog(
            event_id=f"ATK-RANSOM-{uuid.uuid4().hex[:6].upper()}",
            client_id=client_id,
            timestamp=time.time(),
            event_category="FILE",
            protocol="TCP",
            dest_port=445,
            auth_status="SUCCESS",
            user_role="SYSTEM",
            src_ip_type="INTERNAL",
            is_admin_action=True,
            is_powershell_enc=True,
            has_scheduled_task=True,
            is_suspicious_extension=True,
            is_lsass_access=False,
            is_smb_lateral=False,
            failed_login_count=0.0,
            packet_rate_anomaly=random.uniform(3.0, 7.0),
            bytes_transferred_mb=random.uniform(50.0, 300.0),
            file_entropy=random.uniform(7.3, 7.95),  # High entropy = encryption
            beacon_jitter=0.6,
            unique_ports_scanned=2.0,
            file_mod_rate_per_sec=random.uniform(80.0, 220.0),  # Rapid file write
            process_ancestry_depth=random.uniform(4.0, 7.0),
        )

    @staticmethod
    def generate_c2_beaconing_attack(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """MITRE ATT&CK T1071: Command and Control (Periodic Beaconing)."""
        return NormalizedLog(
            event_id=f"ATK-C2-{uuid.uuid4().hex[:6].upper()}",
            client_id=client_id,
            timestamp=time.time(),
            event_category="DNS",
            protocol="DNS",
            dest_port=53,
            auth_status="SUCCESS",
            user_role="STANDARD",
            src_ip_type=random.choice(["SUSPICIOUS_GEO", "TOR_EXIT"]),
            is_admin_action=False,
            is_powershell_enc=True,
            has_scheduled_task=True,
            is_suspicious_extension=False,
            is_lsass_access=False,
            is_smb_lateral=False,
            failed_login_count=0.0,
            packet_rate_anomaly=random.uniform(1.5, 3.5),
            bytes_transferred_mb=random.uniform(0.2, 2.0),
            file_entropy=3.8,
            beacon_jitter=random.uniform(0.01, 0.08),  # Near zero jitter = automated beacon
            unique_ports_scanned=1.0,
            file_mod_rate_per_sec=0.0,
            process_ancestry_depth=random.uniform(3.0, 5.0),
        )

    @staticmethod
    def generate_lateral_movement_attack(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """MITRE ATT&CK T1021: Lateral Movement (SMB / Pass-the-Hash / LSASS dump)."""
        return NormalizedLog(
            event_id=f"ATK-LATERAL-{uuid.uuid4().hex[:6].upper()}",
            client_id=client_id,
            timestamp=time.time(),
            event_category="PROCESS",
            protocol="SMB",
            dest_port=445,
            auth_status="SUCCESS",
            user_role="ADMIN",
            src_ip_type="INTERNAL",
            is_admin_action=True,
            is_powershell_enc=True,
            has_scheduled_task=True,
            is_suspicious_extension=False,
            is_lsass_access=True,
            is_smb_lateral=True,
            failed_login_count=random.uniform(2.0, 8.0),
            packet_rate_anomaly=random.uniform(2.0, 4.5),
            bytes_transferred_mb=random.uniform(20.0, 80.0),
            file_entropy=4.2,
            beacon_jitter=0.5,
            unique_ports_scanned=random.uniform(5.0, 25.0),
            file_mod_rate_per_sec=5.0,
            process_ancestry_depth=random.uniform(4.0, 6.0),
        )

    @staticmethod
    def generate_exfiltration_attack(client_id: str = "CORP-FIN-01") -> NormalizedLog:
        """MITRE ATT&CK T1048: Exfiltration Over Alternative Protocol."""
        return NormalizedLog(
            event_id=f"ATK-EXFIL-{uuid.uuid4().hex[:6].upper()}",
            client_id=client_id,
            timestamp=time.time(),
            event_category="NETWORK",
            protocol="TCP",
            dest_port=443,
            auth_status="SUCCESS",
            user_role="STANDARD",
            src_ip_type="TOR_EXIT",
            is_admin_action=False,
            is_powershell_enc=False,
            has_scheduled_task=False,
            is_suspicious_extension=False,
            is_lsass_access=False,
            is_smb_lateral=False,
            failed_login_count=0.0,
            packet_rate_anomaly=random.uniform(4.0, 7.5),
            bytes_transferred_mb=random.uniform(450.0, 950.0),  # Heavy outbound data
            file_entropy=random.uniform(6.5, 7.8),
            beacon_jitter=0.4,
            unique_ports_scanned=2.0,
            file_mod_rate_per_sec=10.0,
            process_ancestry_depth=2.0,
        )

    @classmethod
    def generate_batch(
        cls,
        count: int = 16,
        attack_type: Optional[str] = None,
        client_id: str = "CORP-FIN-01",
    ) -> List[NormalizedLog]:
        """Generates a batch of logs with optional specific attack injected."""
        logs = []
        generators = {
            "brute_force": cls.generate_brute_force_attack,
            "ransomware": cls.generate_ransomware_attack,
            "c2_beaconing": cls.generate_c2_beaconing_attack,
            "lateral_movement": cls.generate_lateral_movement_attack,
            "data_exfiltration": cls.generate_exfiltration_attack,
        }

        # If attack_type specified, inject attack events
        attack_gen = generators.get(attack_type) if attack_type else None

        for i in range(count):
            if attack_gen and i == 0:
                logs.append(attack_gen(client_id))
            elif attack_gen and random.random() < 0.35:
                logs.append(attack_gen(client_id))
            else:
                logs.append(cls.generate_benign_log(client_id))

        return logs
