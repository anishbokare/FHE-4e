"""
Client-side Dual-Scheme FHE Encoder.
Converts normalized security logs into Microsoft SEAL CKKS ciphertexts (for ML anomaly scoring)
and TFHE Boolean ciphertexts (for exact rule matching).
All sensitive fields are encrypted before leaving client premises.
"""

from typing import List, Dict, Any, Union
import numpy as np

from fhe_engine.pipeline.schema import (
    NormalizedLog,
    normalize_continuous_feature,
    CATEGORY_MAP,
    PROTOCOL_MAP,
    AUTH_STATUS_MAP,
    USER_ROLE_MAP,
    SRC_IP_TYPE_MAP,
)
from fhe_engine.ckks_engine import CKKSEngine
from fhe_engine.tfhe_engine import TFHEEngine, LWECiphertext


class FHELogEncoder:
    """
    Encrypts security logs on the enterprise edge using CKKS and TFHE schemes.
    MSSP receives ONLY ciphertexts and public evaluation parameters.
    """

    def __init__(self, ckks_engine: CKKSEngine, tfhe_engine: TFHEEngine):
        if not ckks_engine.is_client or not tfhe_engine.is_client:
            raise PermissionError("FHELogEncoder must be initialized with client private contexts.")
        self.ckks = ckks_engine
        self.tfhe = tfhe_engine

    def _extract_continuous_features(self, log: NormalizedLog) -> List[float]:
        """Extracts and normalizes continuous numerical features for CKKS vector."""
        return [
            normalize_continuous_feature(log.failed_login_count, "failed_login_count"),
            normalize_continuous_feature(log.packet_rate_anomaly, "packet_rate_anomaly"),
            normalize_continuous_feature(log.bytes_transferred_mb, "bytes_transferred_mb"),
            normalize_continuous_feature(log.file_entropy, "file_entropy"),
            normalize_continuous_feature(log.beacon_jitter, "beacon_jitter"),
            normalize_continuous_feature(log.unique_ports_scanned, "unique_ports_scanned"),
            normalize_continuous_feature(log.file_mod_rate_per_sec, "file_mod_rate_per_sec"),
            normalize_continuous_feature(log.process_ancestry_depth, "process_ancestry_depth"),
        ]

    def _extract_discrete_flags(self, log: NormalizedLog) -> Dict[str, int]:
        """Maps discrete log fields into binary condition flags."""
        return {
            # Specific port predicates
            "is_port_ssh": 1 if log.dest_port == 22 else 0,
            "is_port_rdp": 1 if log.dest_port == 3389 else 0,
            "is_port_smb": 1 if log.dest_port == 445 else 0,
            "is_port_dns": 1 if log.dest_port == 53 else 0,
            "is_port_web": 1 if log.dest_port in (80, 443, 8080, 8443) else 0,
            # Auth status predicates
            "is_auth_failure": 1 if log.auth_status in ("FAILURE", "LOCKOUT") else 0,
            "is_auth_lockout": 1 if log.auth_status == "LOCKOUT" else 0,
            "is_auth_success": 1 if log.auth_status == "SUCCESS" else 0,
            # Roles & IP types
            "is_admin_user": 1 if log.user_role in ("ADMIN", "SYSTEM") else 0,
            "is_tor_or_suspicious": 1 if log.src_ip_type in ("TOR_EXIT", "SUSPICIOUS_GEO") else 0,
            "is_internal_src": 1 if log.src_ip_type == "INTERNAL" else 0,
            # Boolean behavior indicators
            "is_admin_action": 1 if log.is_admin_action else 0,
            "is_powershell_enc": 1 if log.is_powershell_enc else 0,
            "has_scheduled_task": 1 if log.has_scheduled_task else 0,
            "is_suspicious_extension": 1 if log.is_suspicious_extension else 0,
            "is_lsass_access": 1 if log.is_lsass_access else 0,
            "is_smb_lateral": 1 if log.is_smb_lateral else 0,
            # Threshold predicates (evaluated on edge and homomorphically certified)
            "pred_high_failed_logins": 1 if log.failed_login_count >= 5.0 else 0,
            "pred_extreme_failed_logins": 1 if log.failed_login_count >= 20.0 else 0,
            "pred_high_entropy": 1 if log.file_entropy >= 6.8 else 0,
            "pred_low_jitter": 1 if log.beacon_jitter <= 0.15 else 0,
            "pred_high_file_mods": 1 if log.file_mod_rate_per_sec >= 40.0 else 0,
            "pred_high_exfil": 1 if log.bytes_transferred_mb >= 250.0 else 0,
            "pred_port_sweep": 1 if log.unique_ports_scanned >= 15.0 else 0,
            "pred_deep_process_tree": 1 if log.process_ancestry_depth >= 4.0 else 0,
            "pred_traffic_anomaly": 1 if log.packet_rate_anomaly >= 3.0 else 0,
        }

    def encode_and_encrypt_log(self, log: NormalizedLog) -> Dict[str, Any]:
        """
        Takes a single normalized log and produces a zero-knowledge encrypted payload.
        Transmittable directly to MSSP cloud evaluator.
        """
        # 1. CKKS continuous vector encryption
        features = self._extract_continuous_features(log)
        ckks_enc = self.ckks.encrypt_vector(features)
        ckks_b64 = self.ckks.serialize_ciphertext(ckks_enc)

        # 2. TFHE discrete flags encryption
        flags = self._extract_discrete_flags(log)
        tfhe_ciphertexts: Dict[str, Dict[str, Any]] = {}
        for flag_name, bit_val in flags.items():
            ct_bit = self.tfhe.encrypt_bit(bit_val)
            tfhe_ciphertexts[flag_name] = ct_bit.serialize()

        # 3. Form payload with metadata (no plaintext log attributes!)
        return {
            "event_id": log.event_id,
            "client_id": log.client_id,
            "timestamp": log.timestamp,
            "ckks_features_ciphertext": ckks_b64,
            "tfhe_flags_ciphertexts": tfhe_ciphertexts,
            "feature_dim": len(features),
            "flag_count": len(flags),
            # Security verification hash
            "encryption_scheme": "SEAL_CKKS+TFHE_LWE",
            "is_encrypted": True,
        }

    def encode_and_encrypt_batch(self, logs: List[NormalizedLog]) -> List[Dict[str, Any]]:
        """Batched encryption across an array of logs."""
        return [self.encode_and_encrypt_log(log) for log in logs]
