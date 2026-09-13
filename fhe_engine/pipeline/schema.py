"""
Canonical Security Log Schema for Confidential SIEM (OCSF & ECS Aligned).
Defines standard feature representations for hybrid CKKS / TFHE homomorphic evaluation.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import ipaddress


@dataclass
class NormalizedLog:
    """Canonical security event model."""
    event_id: str
    client_id: str
    timestamp: float
    # Discrete categorical attributes (encoded into TFHE bits)
    event_category: str  # "AUTH", "NETWORK", "PROCESS", "FILE", "DNS"
    protocol: str        # "TCP", "UDP", "SMB", "RDP", "SSH", "HTTP", "DNS"
    dest_port: int
    auth_status: str     # "SUCCESS", "FAILURE", "LOCKOUT", "DENIED"
    user_role: str       # "STANDARD", "ADMIN", "SYSTEM", "SERVICE"
    src_ip_type: str     # "INTERNAL", "EXTERNAL_TRUSTED", "SUSPICIOUS_GEO", "TOR_EXIT"
    is_admin_action: bool = False
    is_powershell_enc: bool = False
    has_scheduled_task: bool = False
    is_suspicious_extension: bool = False
    is_lsass_access: bool = False
    is_smb_lateral: bool = False

    # Continuous statistical attributes (packed into SEAL CKKS vector)
    failed_login_count: float = 0.0      # 0 to 50+
    packet_rate_anomaly: float = 0.0     # z-score -3.0 to +8.0
    bytes_transferred_mb: float = 0.0    # 0 to 5000+ MB
    file_entropy: float = 3.5            # 0.0 to 8.0 (8.0 = encrypted/compressed)
    beacon_jitter: float = 1.0           # 0.0 (exact periodic beacon) to 1.0 (random)
    unique_ports_scanned: float = 1.0    # 1 to 1000+
    file_mod_rate_per_sec: float = 0.0   # 0 to 500+ files/sec
    process_ancestry_depth: float = 1.0  # 1 to 10+


# Categorical Encodings for TFHE boolean mapping
CATEGORY_MAP = {"AUTH": 0, "NETWORK": 1, "PROCESS": 2, "FILE": 3, "DNS": 4}
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "SMB": 2, "RDP": 3, "SSH": 4, "HTTP": 5, "DNS": 6}
AUTH_STATUS_MAP = {"SUCCESS": 0, "FAILURE": 1, "LOCKOUT": 2, "DENIED": 3}
USER_ROLE_MAP = {"STANDARD": 0, "ADMIN": 1, "SYSTEM": 2, "SERVICE": 3}
SRC_IP_TYPE_MAP = {"INTERNAL": 0, "EXTERNAL_TRUSTED": 1, "SUSPICIOUS_GEO": 2, "TOR_EXIT": 3}

# Continuous Feature Normalization Bounds: [min, max] -> mapped to [-1, 1]
FEATURE_BOUNDS = {
    "failed_login_count": (0.0, 50.0),
    "packet_rate_anomaly": (-3.0, 8.0),
    "bytes_transferred_mb": (0.0, 1000.0),
    "file_entropy": (0.0, 8.0),
    "beacon_jitter": (0.0, 1.0),
    "unique_ports_scanned": (1.0, 200.0),
    "file_mod_rate_per_sec": (0.0, 250.0),
    "process_ancestry_depth": (1.0, 8.0),
}


def normalize_continuous_feature(value: float, feature_name: str) -> float:
    """Normalizes continuous metric into [-1, 1] range for stable CKKS polynomial evaluation."""
    f_min, f_max = FEATURE_BOUNDS.get(feature_name, (0.0, 100.0))
    clipped = max(f_min, min(float(value), f_max))
    # Map to [-1.0, 1.0]
    return 2.0 * ((clipped - f_min) / (f_max - f_min + 1e-9)) - 1.0
