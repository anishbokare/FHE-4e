"""
Encrypted Machine Learning Anomaly Detection Model for Confidential SIEM.
Executes polynomial neural inference directly on Microsoft SEAL CKKS encrypted telemetry.
Cloud operates strictly on ciphertexts with zero decryption capability.
"""

import time
import base64
import numpy as np
import tenseal as ts
from typing import Dict, Any, List, Optional, Union

from fhe_engine.ckks_engine import CKKSEngine


class EncryptedAnomalyDetector:
    """
    Evaluates ML anomaly inference on CKKS encrypted vectors.
    Uses polynomial neural activations to compute anomaly scores blind.
    """

    def __init__(self, ckks_engine: CKKSEngine):
        self.ckks = ckks_engine

        # Calibrated anomaly detection weights for 8 canonical security features:
        # [failed_logins, packet_rate, bytes_transferred, file_entropy,
        #  beacon_jitter, ports_scanned, file_mod_rate, ancestry_depth]
        self.weights = np.array([
            3.50,   # High failed logins (brute force)
            1.60,   # Packet rate burst
            1.80,   # High outbound data (exfil)
            2.60,   # High file entropy (ransomware)
            -2.40,  # Negative weight: robotic low jitter -> C2
            1.50,   # Port scan
            2.80,   # Mass file write rate (ransomware)
            2.00,   # Deep process tree
        ], dtype=np.float64)

        # Baseline offset calibrated to map benign traffic to negative z
        self.bias = 4.80

        # Linear-polynomial activation slope: sigma(z) ~ 0.5 + 0.12 * z
        self.poly_slope = 0.12
        self.poly_intercept = 0.50

    def predict_encrypted(self, enc_vector: ts.CKKSVector) -> Dict[str, Any]:
        """
        Runs homomorphic ML anomaly inference over encrypted feature vector.
        Cloud evaluator executes this completely blind without private key.
        """
        t0 = time.perf_counter()

        # 1. Homomorphic Dot Product: W . [x]
        enc_z = self.ckks.homomorphic_dot_product(enc_vector, self.weights.tolist())

        # 2. Homomorphic Bias Addition: (W . [x]) + b
        enc_z = enc_z + float(self.bias)

        # 3. Homomorphic Polynomial Activation: intercept + slope * enc_z
        enc_score = (enc_z * float(self.poly_slope)) + float(self.poly_intercept)

        eval_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "encrypted_score_ciphertext": enc_score,
            "ciphertext_b64": self.ckks.serialize_ciphertext(enc_score),
            "eval_time_ms": round(eval_ms, 3),
            "model_type": "Polynomial_FHE_Neural_Detector",
            "feature_dimension": len(self.weights),
            "scheme": "SEAL_CKKS",
        }

    def client_decrypt_score(self, enc_score_or_b64: Union[ts.CKKSVector, str]) -> float:
        """
        Client decrypts ML anomaly score using private secret key.
        Accepts either CKKSVector or Base64 string from cloud API response.
        Returns probability score in [0.0, 1.0].
        """
        if not self.ckks.is_client:
            raise PermissionError("Client decryption requires secret key.")

        if isinstance(enc_score_or_b64, str):
            enc_vec = self.ckks.deserialize_ciphertext(enc_score_or_b64)
        else:
            raw_bytes = enc_score_or_b64.serialize()
            enc_vec = ts.ckks_vector_from(self.ckks.context, raw_bytes)

        decrypted_vals = enc_vec.decrypt()
        raw_score = float(decrypted_vals[0])
        # Clip to valid probability bounds [0.0, 1.0]
        return round(max(0.0, min(1.0, raw_score)), 4)
