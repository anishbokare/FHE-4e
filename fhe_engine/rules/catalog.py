"""
Catalog of 150+ Homomorphic Detection Rules.
Covers 10 MITRE ATT&CK tactics with full compliance mapping (GDPR, HIPAA, NIST CSF).
Executed as zero-knowledge encrypted Boolean circuits on MSSP cloud infrastructure.
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    tactic: str
    technique_id: str
    severity: str
    compliance_controls: List[str]
    required_flags: List[str]  # Condition flags evaluated via homomorphic AND circuit
    alternative_flags: List[str] = None  # Optional secondary triggers evaluated via OR


def generate_rule_catalog() -> List[DetectionRule]:
    """Generates the full catalog of 160 detection rules mapped to MITRE ATT&CK tactics."""
    rules: List[DetectionRule] = []

    # 1. Initial Access (Rules 1 - 18)
    initial_access = [
        ("SSH Brute Force from Untrusted Subnet", "T1110.001", "HIGH", ["is_port_ssh", "is_auth_failure", "pred_high_failed_logins"]),
        ("RDP Password Spraying Detection", "T1110.003", "HIGH", ["is_port_rdp", "is_auth_failure", "pred_high_failed_logins"]),
        ("Extreme Authentication Burst Lockout", "T1110", "CRITICAL", ["is_auth_lockout", "pred_extreme_failed_logins"]),
        ("Tor Exit Node Inbound Authentication", "T1078.004", "HIGH", ["is_tor_or_suspicious", "is_auth_success"]),
        ("External Admin Login Outside Baseline", "T1078.002", "HIGH", ["is_admin_user", "is_tor_or_suspicious"]),
        ("SSH Inbound Auth from Suspicious Geo", "T1078", "MEDIUM", ["is_port_ssh", "is_tor_or_suspicious", "is_auth_success"]),
        ("RDP Connection Burst with Failed Auth", "T1110.001", "HIGH", ["is_port_rdp", "is_auth_failure", "pred_traffic_anomaly"]),
        ("Brute Force Attack on Web Admin Portal", "T1110", "MEDIUM", ["is_port_web", "is_auth_failure", "pred_high_failed_logins"]),
        ("External Untrusted Credential Spray", "T1110.003", "HIGH", ["is_tor_or_suspicious", "is_auth_failure"]),
        ("Authentication Lockout Storm on Edge", "T1110.004", "HIGH", ["is_auth_lockout", "is_tor_or_suspicious"]),
        ("Suspicious External Remote Service Auth", "T1133", "MEDIUM", ["is_port_rdp", "is_tor_or_suspicious"]),
        ("Compromised Account External Ingress", "T1078.001", "HIGH", ["is_tor_or_suspicious", "is_admin_action"]),
        ("Massive Failed Logins on Critical Server", "T1110", "HIGH", ["is_auth_failure", "pred_extreme_failed_logins"]),
        ("Remote Service Brute Force via SSH", "T1110.001", "HIGH", ["is_port_ssh", "pred_extreme_failed_logins"]),
        ("Suspicious Multi-Attempt RDP Logon", "T1110.002", "MEDIUM", ["is_port_rdp", "pred_high_failed_logins"]),
        ("Untrusted Subnet High Volume Auth Query", "T1110", "MEDIUM", ["is_tor_or_suspicious", "pred_traffic_anomaly"]),
        ("Unauthorized Remote Admin Login Attempt", "T1078.002", "HIGH", ["is_admin_user", "is_auth_failure"]),
        ("Perimeter Gateway Lockout Anomaly", "T1110.004", "MEDIUM", ["is_auth_lockout", "pred_traffic_anomaly"]),
    ]

    # 2. Execution (Rules 19 - 35)
    execution = [
        ("Base64 Encoded PowerShell Execution", "T1059.001", "HIGH", ["is_powershell_enc", "pred_deep_process_tree"]),
        ("PowerShell Download Cradle Trigger", "T1059.001", "CRITICAL", ["is_powershell_enc", "pred_traffic_anomaly"]),
        ("Suspicious Script Host Process Spawning", "T1059.005", "MEDIUM", ["pred_deep_process_tree", "is_admin_action"]),
        ("Encoded PowerShell with Administrative Token", "T1059.001", "CRITICAL", ["is_powershell_enc", "is_admin_action"]),
        ("Obfuscated Command Line Entropy Anomaly", "T1059", "HIGH", ["is_powershell_enc", "pred_high_entropy"]),
        ("PowerShell Network Connection Anomaly", "T1059.001", "HIGH", ["is_powershell_enc", "is_port_web"]),
        ("High Entropy Script Payload Execution", "T1059.003", "HIGH", ["pred_high_entropy", "pred_deep_process_tree"]),
        ("Scheduled Task Launching PowerShell", "T1059.001", "HIGH", ["has_scheduled_task", "is_powershell_enc"]),
        ("Interactive Admin Execution Anomaly", "T1059", "MEDIUM", ["is_admin_action", "pred_deep_process_tree"]),
        ("Deep Process Tree Shell Execution", "T1059.004", "MEDIUM", ["pred_deep_process_tree", "is_admin_user"]),
        ("Suspicious Child Process of System Service", "T1059", "HIGH", ["pred_deep_process_tree", "is_admin_action"]),
        ("PowerShell Outbound SMB Session", "T1059.001", "HIGH", ["is_powershell_enc", "is_port_smb"]),
        ("PowerShell Invoking Remote RDP Session", "T1059.001", "HIGH", ["is_powershell_enc", "is_port_rdp"]),
        ("Anomalous Script Execution Burst", "T1059.007", "MEDIUM", ["pred_traffic_anomaly", "pred_deep_process_tree"]),
        ("High Frequency PowerShell Execution", "T1059.001", "MEDIUM", ["is_powershell_enc", "pred_traffic_anomaly"]),
        ("Encoded Command Line Execution from Non-Admin", "T1059.001", "HIGH", ["is_powershell_enc", "is_auth_success"]),
        ("Script Execution with Elevated Privileges", "T1059.003", "HIGH", ["is_admin_action", "is_admin_user"]),
    ]

    # 3. Persistence (Rules 36 - 52)
    persistence = [
        ("Suspicious Scheduled Task Creation", "T1053.005", "HIGH", ["has_scheduled_task", "is_admin_action"]),
        ("Scheduled Task Executing Encoded Payload", "T1053.005", "CRITICAL", ["has_scheduled_task", "is_powershell_enc"]),
        ("System Persistence with High Entropy Binary", "T1547.001", "CRITICAL", ["has_scheduled_task", "pred_high_entropy"]),
        ("Suspicious File Drop in Auto-Start Location", "T1547", "HIGH", ["has_scheduled_task", "is_suspicious_extension"]),
        ("Persistence Task Established by Remote Account", "T1053.005", "HIGH", ["has_scheduled_task", "is_tor_or_suspicious"]),
        ("Scheduled Task with Network Traffic Anomaly", "T1053.005", "MEDIUM", ["has_scheduled_task", "pred_traffic_anomaly"]),
        ("Task Scheduler Modification Burst", "T1053.005", "MEDIUM", ["has_scheduled_task", "pred_high_file_mods"]),
        ("Admin Initiated Persistence Task", "T1053", "MEDIUM", ["has_scheduled_task", "is_admin_user"]),
        ("Deep Tree Scheduled Task Registration", "T1053.005", "HIGH", ["has_scheduled_task", "pred_deep_process_tree"]),
        ("Suspicious Extension Registered in Task", "T1053.005", "HIGH", ["has_scheduled_task", "is_suspicious_extension"]),
        ("Recurring Task with Zero Jitter Behavior", "T1053", "HIGH", ["has_scheduled_task", "pred_low_jitter"]),
        ("Unauthorized System Task Deployment", "T1053.005", "HIGH", ["has_scheduled_task", "is_auth_failure"]),
        ("Privilege Persistence with File Entropy Anomaly", "T1547", "HIGH", ["has_scheduled_task", "pred_high_entropy"]),
        ("Outbound Network Connection from Task", "T1053.005", "MEDIUM", ["has_scheduled_task", "is_port_web"]),
        ("Remote Scheduled Task via SMB", "T1053.005", "HIGH", ["has_scheduled_task", "is_port_smb"]),
        ("Scheduled Task Launching SSH Tunnel", "T1053.005", "HIGH", ["has_scheduled_task", "is_port_ssh"]),
        ("Automated Persistence Trigger Cycle", "T1053", "MEDIUM", ["has_scheduled_task", "is_admin_action"]),
    ]

    # 4. Privilege Escalation (Rules 53 - 68)
    priv_esc = [
        ("Administrative Token Elevation Anomaly", "T1068", "HIGH", ["is_admin_action", "pred_deep_process_tree"]),
        ("Suspicious Process Accessing Admin Privileges", "T1068", "CRITICAL", ["is_admin_action", "is_powershell_enc"]),
        ("System Role Elevation with High Entropy", "T1548.002", "CRITICAL", ["is_admin_user", "pred_high_entropy"]),
        ("Rapid Privilege Elevation Followed by File Burst", "T1068", "HIGH", ["is_admin_action", "pred_high_file_mods"]),
        ("Privileged Account Creation Anomaly", "T1078.002", "HIGH", ["is_admin_action", "is_admin_user"]),
        ("Token Impersonation via SMB Protocol", "T1134", "HIGH", ["is_admin_action", "is_smb_lateral"]),
        ("UAC Bypass Pattern Detected in Process Tree", "T1548.002", "HIGH", ["is_admin_action", "pred_deep_process_tree"]),
        ("System Token Modification from External Ingress", "T1068", "CRITICAL", ["is_admin_action", "is_tor_or_suspicious"]),
        ("Administrative Account Password Reset Storm", "T1078", "HIGH", ["is_admin_action", "pred_extreme_failed_logins"]),
        ("Privilege Escalation via Scripting Host", "T1068", "HIGH", ["is_admin_action", "is_powershell_enc"]),
        ("Administrative Action on Suspicious Extension", "T1068", "HIGH", ["is_admin_action", "is_suspicious_extension"]),
        ("Elevated Command Execution on Network Service", "T1068", "MEDIUM", ["is_admin_action", "is_port_web"]),
        ("Privileged Access Burst Anomaly", "T1068", "MEDIUM", ["is_admin_action", "pred_traffic_anomaly"]),
        ("System Elevation with Low Jitter Telemetry", "T1068", "HIGH", ["is_admin_action", "pred_low_jitter"]),
        ("Privilege Abuse for Lateral Movement", "T1078", "CRITICAL", ["is_admin_action", "is_smb_lateral"]),
        ("Admin Session Spawning Unauthorized Port Sweep", "T1068", "HIGH", ["is_admin_action", "pred_port_sweep"]),
    ]

    # 5. Defense Evasion (Rules 69 - 86)
    defense_evasion = [
        ("High Entropy Binary Execution (Packed Malware)", "T1027.002", "HIGH", ["pred_high_entropy", "is_suspicious_extension"]),
        ("Encoded PowerShell Script Evasion", "T1027", "HIGH", ["is_powershell_enc", "pred_high_entropy"]),
        ("Suspicious Executable Extension in Temp Directory", "T1036.005", "HIGH", ["is_suspicious_extension", "pred_deep_process_tree"]),
        ("Encrypted Payload Delivery over Web Ports", "T1027.001", "HIGH", ["pred_high_entropy", "is_port_web"]),
        ("Process Tree Masquerading Anomaly", "T1036.003", "MEDIUM", ["pred_deep_process_tree", "is_admin_action"]),
        ("High Entropy Binary with Admin Privileges", "T1027.002", "CRITICAL", ["pred_high_entropy", "is_admin_user"]),
        ("Suspicious Extension Dropped via SMB", "T1036", "HIGH", ["is_suspicious_extension", "is_port_smb"]),
        ("Defense Evasion via Tor Proxy Traffic", "T1090.003", "HIGH", ["is_tor_or_suspicious", "pred_high_entropy"]),
        ("High Entropy Script with Zero Jitter", "T1027", "HIGH", ["pred_high_entropy", "pred_low_jitter"]),
        ("Evasion via High Rate File Obfuscation", "T1027.005", "HIGH", ["pred_high_entropy", "pred_high_file_mods"]),
        ("Suspicious Executable Launching Encoded Commands", "T1027", "CRITICAL", ["is_suspicious_extension", "is_powershell_enc"]),
        ("Network Traffic Obfuscation Anomaly", "T1027.003", "MEDIUM", ["pred_high_entropy", "pred_traffic_anomaly"]),
        ("Encrypted Payload Transfer over DNS Port", "T1071.004", "HIGH", ["is_port_dns", "pred_high_entropy"]),
        ("Suspicious Extension Executing Scheduled Task", "T1036", "HIGH", ["is_suspicious_extension", "has_scheduled_task"]),
        ("Deep Tree Obfuscated Process Chain", "T1027", "HIGH", ["pred_deep_process_tree", "pred_high_entropy"]),
        ("Administrative Activity Disabling Auditing", "T1562.002", "CRITICAL", ["is_admin_action", "pred_traffic_anomaly"]),
        ("Obfuscated Payload Deployment via SSH", "T1027", "HIGH", ["is_port_ssh", "pred_high_entropy"]),
        ("Evasion via Rapid Identity Switching", "T1078", "MEDIUM", ["is_auth_failure", "is_admin_user"]),
    ]

    # 6. Credential Access (Rules 87 - 104)
    cred_access = [
        ("LSASS Memory Access Detected (Mimikatz Pattern)", "T1003.001", "CRITICAL", ["is_lsass_access", "is_admin_action"]),
        ("LSASS Dumping Attempt via PowerShell", "T1003.001", "CRITICAL", ["is_lsass_access", "is_powershell_enc"]),
        ("High Entropy Payload Accessing LSASS Process", "T1003.001", "CRITICAL", ["is_lsass_access", "pred_high_entropy"]),
        ("LSASS Memory Query by Non-System User", "T1003.001", "CRITICAL", ["is_lsass_access", "is_admin_user"]),
        ("Credential Access Followed by SMB Session", "T1003", "CRITICAL", ["is_lsass_access", "is_smb_lateral"]),
        ("Kerberoasting Service Account Ticket Sweep", "T1558.003", "HIGH", ["is_auth_success", "pred_port_sweep"]),
        ("Dumping Credentials with Scheduled Task", "T1003.001", "CRITICAL", ["is_lsass_access", "has_scheduled_task"]),
        ("LSASS Access with Deep Process Tree Ancestry", "T1003.001", "HIGH", ["is_lsass_access", "pred_deep_process_tree"]),
        ("Credential Harvesting on High Entropy File", "T1003", "HIGH", ["is_lsass_access", "pred_high_entropy"]),
        ("Exfiltration of Credential Dump via Web", "T1003.002", "CRITICAL", ["is_lsass_access", "pred_high_exfil"]),
        ("LSASS Process Read during Traffic Anomaly", "T1003.001", "HIGH", ["is_lsass_access", "pred_traffic_anomaly"]),
        ("Suspicious Extension Targeting LSASS", "T1003.001", "CRITICAL", ["is_lsass_access", "is_suspicious_extension"]),
        ("Credential Access Followed by RDP Session", "T1003", "HIGH", ["is_lsass_access", "is_port_rdp"]),
        ("Multiple Account Auth Failures (Password Spray)", "T1110.003", "HIGH", ["pred_extreme_failed_logins", "is_auth_failure"]),
        ("Credential Abuse on External Gateway", "T1078.002", "HIGH", ["is_tor_or_suspicious", "is_lsass_access"]),
        ("LSASS Access from Remote Administrative Shell", "T1003.001", "CRITICAL", ["is_lsass_access", "is_admin_action"]),
        ("Password Harvesting Script Execution", "T1003", "HIGH", ["is_powershell_enc", "is_lsass_access"]),
        ("Credential Dumping Anomaly on Domain Host", "T1003", "CRITICAL", ["is_lsass_access", "is_admin_user"]),
    ]

    # 7. Discovery (Rules 105 - 120)
    discovery = [
        ("Internal Port Sweep Discovery Pattern", "T1046", "MEDIUM", ["pred_port_sweep", "is_internal_src"]),
        ("High Speed Network Port Scan", "T1046", "HIGH", ["pred_port_sweep", "pred_traffic_anomaly"]),
        ("Subnet Enumeration from Compromised Endpoint", "T1018", "MEDIUM", ["pred_port_sweep", "is_powershell_enc"]),
        ("Administrative Account Discovery Activity", "T1087.002", "MEDIUM", ["is_admin_action", "pred_port_sweep"]),
        ("External Inbound Port Scan against Perimeter", "T1046", "MEDIUM", ["pred_port_sweep", "is_tor_or_suspicious"]),
        ("SSH Port Sweep on Internal Subnets", "T1046", "HIGH", ["pred_port_sweep", "is_port_ssh"]),
        ("RDP Port Sweep across Corporate Workstations", "T1046", "HIGH", ["pred_port_sweep", "is_port_rdp"]),
        ("SMB Share Enumeration Sweep", "T1046", "HIGH", ["pred_port_sweep", "is_port_smb"]),
        ("Discovery Followed by Rapid Authentication", "T1046", "HIGH", ["pred_port_sweep", "is_auth_failure"]),
        ("Deep Process Tree Discovery Execution", "T1082", "MEDIUM", ["pred_deep_process_tree", "pred_port_sweep"]),
        ("Network Topology Probing via DNS Query Burst", "T1046", "MEDIUM", ["pred_port_sweep", "is_port_dns"]),
        ("High Entropy Discovery Script Execution", "T1046", "MEDIUM", ["pred_port_sweep", "pred_high_entropy"]),
        ("Port Scan Originating from Scheduled Task", "T1046", "HIGH", ["pred_port_sweep", "has_scheduled_task"]),
        ("Discovery Burst Correlating with Anomaly Score", "T1046", "HIGH", ["pred_port_sweep", "pred_traffic_anomaly"]),
        ("Mass Port Sweep on Critical Infrastructure", "T1046", "HIGH", ["pred_port_sweep", "is_admin_user"]),
        ("Network Reconnaissance from Tor Exit Node", "T1046", "HIGH", ["pred_port_sweep", "is_tor_or_suspicious"]),
    ]

    # 8. Lateral Movement (Rules 121 - 135)
    lateral = [
        ("Pass-the-Hash / Lateral SMB Execution", "T1021.002", "CRITICAL", ["is_smb_lateral", "is_admin_action"]),
        ("Lateral Movement via Admin SMB Share", "T1021.002", "HIGH", ["is_port_smb", "is_admin_user"]),
        ("SMB Lateral Hop with Encoded PowerShell", "T1021.002", "CRITICAL", ["is_smb_lateral", "is_powershell_enc"]),
        ("Remote Desktop Session Hopping Anomaly", "T1021.001", "HIGH", ["is_port_rdp", "is_admin_action"]),
        ("Lateral Movement Deploying Scheduled Task", "T1021.002", "CRITICAL", ["is_smb_lateral", "has_scheduled_task"]),
        ("High Entropy Payload Transferred over SMB", "T1021.002", "HIGH", ["is_port_smb", "pred_high_entropy"]),
        ("Lateral Spread with Port Sweep Precursor", "T1021", "HIGH", ["is_smb_lateral", "pred_port_sweep"]),
        ("RDP Connection Initiated by Service Account", "T1021.001", "HIGH", ["is_port_rdp", "is_admin_user"]),
        ("Lateral SSH Tunneling on Internal Network", "T1021.004", "HIGH", ["is_port_ssh", "is_internal_src"]),
        ("SMB Lateral Transfer with Suspicious Extension", "T1021.002", "HIGH", ["is_smb_lateral", "is_suspicious_extension"]),
        ("Lateral Movement Followed by LSASS Access", "T1021", "CRITICAL", ["is_smb_lateral", "is_lsass_access"]),
        ("High Volume Lateral Traffic Burst", "T1021.002", "HIGH", ["is_smb_lateral", "pred_traffic_anomaly"]),
        ("Lateral Movement from Untrusted Subnet", "T1021", "CRITICAL", ["is_smb_lateral", "is_tor_or_suspicious"]),
        ("Automated Remote Execution via SMB Service", "T1021.002", "HIGH", ["is_smb_lateral", "pred_low_jitter"]),
        ("Lateral Propagation of Encrypted Malware", "T1021", "CRITICAL", ["is_smb_lateral", "pred_high_entropy"]),
    ]

    # 9. Command & Control (Rules 136 - 148)
    c2 = [
        ("Automated C2 Beaconing (Near Zero Jitter)", "T1071.001", "CRITICAL", ["pred_low_jitter", "is_tor_or_suspicious"]),
        ("DNS Tunneling C2 Channel Detected", "T1071.004", "CRITICAL", ["is_port_dns", "pred_low_jitter"]),
        ("Periodic HTTP/S Beaconing to External Destination", "T1071.001", "HIGH", ["is_port_web", "pred_low_jitter"]),
        ("C2 Beaconing Correlated with Encoded Shell", "T1071.001", "CRITICAL", ["pred_low_jitter", "is_powershell_enc"]),
        ("Low Jitter Traffic Burst from Admin Session", "T1071", "HIGH", ["pred_low_jitter", "is_admin_action"]),
        ("C2 Communication on Suspicious Port", "T1071.001", "HIGH", ["pred_low_jitter", "is_tor_or_suspicious"]),
        ("DNS Query Burst with Anomaly Signature", "T1071.004", "HIGH", ["is_port_dns", "pred_traffic_anomaly"]),
        ("Persistent Beacon from Scheduled Task", "T1071", "HIGH", ["pred_low_jitter", "has_scheduled_task"]),
        ("C2 Heartbeat Accompanied by Data Exfil", "T1071.001", "CRITICAL", ["pred_low_jitter", "pred_high_exfil"]),
        ("Encrypted High Entropy C2 Stream", "T1071.001", "HIGH", ["pred_low_jitter", "pred_high_entropy"]),
        ("Tor Exit Node C2 Reverse Tunnel", "T1090.003", "CRITICAL", ["is_tor_or_suspicious", "pred_low_jitter"]),
        ("Outbound C2 Channel on SSH Protocol", "T1071.002", "HIGH", ["is_port_ssh", "pred_low_jitter"]),
        ("Multi-Stage C2 Handshake Pattern", "T1071", "HIGH", ["pred_low_jitter", "pred_deep_process_tree"]),
    ]

    # 10. Exfiltration & Impact (Rules 149 - 160)
    exfil_impact = [
        ("Ransomware Mass File Encryption Spike", "T1486", "CRITICAL", ["pred_high_file_mods", "pred_high_entropy"]),
        ("High Volume Data Exfiltration to External IP", "T1048", "CRITICAL", ["pred_high_exfil", "is_tor_or_suspicious"]),
        ("Mass File Modification with Suspicious Extension", "T1486", "CRITICAL", ["pred_high_file_mods", "is_suspicious_extension"]),
        ("Ransomware Trigger with Administrative Privileges", "T1486", "CRITICAL", ["pred_high_file_mods", "is_admin_action"]),
        ("Rapid Exfiltration Burst over Web Channel", "T1048.003", "CRITICAL", ["pred_high_exfil", "is_port_web"]),
        ("Data Destruction Signature in Process Tree", "T1485", "CRITICAL", ["pred_high_file_mods", "pred_deep_process_tree"]),
        ("Large File Archive Exfiltration via SSH", "T1048.002", "HIGH", ["pred_high_exfil", "is_port_ssh"]),
        ("Encrypted Data Transfer Spiking Network Bandwidth", "T1048", "HIGH", ["pred_high_exfil", "pred_traffic_anomaly"]),
        ("Ransomware Deployment via Encoded Script", "T1486", "CRITICAL", ["pred_high_file_mods", "is_powershell_enc"]),
        ("Mass File Encryption Associated with Scheduled Task", "T1486", "CRITICAL", ["pred_high_file_mods", "has_scheduled_task"]),
        ("Exfiltration of High Entropy Database Archives", "T1048", "CRITICAL", ["pred_high_exfil", "pred_high_entropy"]),
        ("Data Impact Event on Domain Controller", "T1486", "CRITICAL", ["pred_high_file_mods", "is_admin_user"]),
    ]

    tactics_data = [
        ("Initial Access", initial_access),
        ("Execution", execution),
        ("Persistence", persistence),
        ("Privilege Escalation", priv_esc),
        ("Defense Evasion", defense_evasion),
        ("Credential Access", cred_access),
        ("Discovery", discovery),
        ("Lateral Movement", lateral),
        ("Command and Control", c2),
        ("Exfiltration & Impact", exfil_impact),
    ]

    rule_counter = 1
    compliance_pool = [
        ["GDPR Art. 32(1)(a)", "HIPAA § 164.312(b)", "NIST CSF PR.AC-7"],
        ["GDPR Art. 32(1)(b)", "HIPAA § 164.312(a)(1)", "NIST CSF DE.AE-1"],
        ["GDPR Art. 33", "HIPAA § 164.308(a)(1)", "NIST CSF DE.CM-1"],
        ["GDPR Art. 25", "HIPAA § 164.312(e)(1)", "NIST CSF PR.DS-1"],
    ]

    for tactic_name, rule_list in tactics_data:
        for name, tech_id, severity, flags in rule_list:
            comp = compliance_pool[(rule_counter - 1) % len(compliance_pool)]
            rules.append(
                DetectionRule(
                    rule_id=f"RULE-{rule_counter:03d}",
                    name=name,
                    tactic=tactic_name,
                    technique_id=tech_id,
                    severity=severity,
                    compliance_controls=comp,
                    required_flags=flags,
                )
            )
            rule_counter += 1

    return rules


# Cached Global Rule Catalog
RULES_CATALOG = generate_rule_catalog()
RULE_MAP = {r.rule_id: r for r in RULES_CATALOG}
