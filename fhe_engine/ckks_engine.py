"""
Microsoft SEAL CKKS Engine for Approximate Arithmetic and ML Anomaly Scoring.
Provides SIMD-packed vector encryption, encrypted dot-products, polynomial activations,
and noise management over encrypted telemetry.
"""

import base64
import time
import numpy as np
import tenseal as ts
from typing import List, Union, Dict, Any, Optional


class CKKSEngine:
    """
    Evaluates linear and polynomial circuits over encrypted continuous log features
    using Microsoft SEAL CKKS homomorphic scheme.
    """

    def __init__(self, context: ts.Context, is_client: bool = False):
        self.context = context
        self.is_client = is_client

    def encrypt_vector(self, values: Union[List[float], np.ndarray]) -> ts.CKKSVector:
        """
        Client-side encryption of continuous telemetry feature vector.
        Values are packed into SIMD slots.
        """
        if not self.is_client:
            raise PermissionError("Encryption requires client private context.")
        val_list = [float(v) for v in values]
        return ts.ckks_vector(self.context, val_list)

    def decrypt_vector(self, encrypted_vector: ts.CKKSVector) -> List[float]:
        """Client-side decryption of evaluated ciphertext vector."""
        if not self.is_client:
            raise PermissionError("Decryption requires client private context with secret key.")
        return encrypted_vector.decrypt()

    def serialize_ciphertext(self, enc_vec: ts.CKKSVector) -> str:
        """Serializes ciphertext to Base64 string for network transport."""
        raw_bytes = enc_vec.serialize()
        return base64.b64encode(raw_bytes).decode("ascii")

    def deserialize_ciphertext(self, b64_str: str) -> ts.CKKSVector:
        """Deserializes Base64 string into a CKKSVector using current context."""
        raw_bytes = base64.b64decode(b64_str.encode("ascii"))
        return ts.ckks_vector_from(self.context, raw_bytes)

    # --- Cloud Evaluation Operations (Blind / Zero-Knowledge) ---

    @staticmethod
    def homomorphic_add(
        vec_a: ts.CKKSVector, vec_b: Union[ts.CKKSVector, List[float], float]
    ) -> ts.CKKSVector:
        """Computes encrypted addition: [a] + [b] or [a] + const."""
        return vec_a + vec_b

    @staticmethod
    def homomorphic_sub(
        vec_a: ts.CKKSVector, vec_b: Union[ts.CKKSVector, List[float], float]
    ) -> ts.CKKSVector:
        """Computes encrypted subtraction: [a] - [b] or [a] - const."""
        return vec_a - vec_b

    @staticmethod
    def homomorphic_mul_plain(vec_a: ts.CKKSVector, plain_weights: Union[List[float], float]) -> ts.CKKSVector:
        """Computes encrypted Hadamard multiplication with plaintext weights: [a] * w."""
        return vec_a * plain_weights

    @staticmethod
    def homomorphic_dot_product(vec_a: ts.CKKSVector, plain_weights: List[float]) -> ts.CKKSVector:
        """
        Computes homomorphic dot product between encrypted vector and plaintext weight vector:
        sum_i([a_i] * w_i).
        """
        return vec_a.dot([float(w) for w in plain_weights])

    @staticmethod
    def homomorphic_poly_eval(
        vec: ts.CKKSVector, coeffs: List[float]
    ) -> ts.CKKSVector:
        """
        Evaluates polynomial approximation on encrypted vector:
        P([x]) = c0 + c1*[x] + c2*[x]^2 + c3*[x]^3 + ...
        Used for encrypted sigmoid / GELU activation functions in neural anomaly detection.
        """
        return vec.polyval(coeffs)

    def evaluate_anomaly_circuit(
        self,
        enc_features: ts.CKKSVector,
        model_weights: np.ndarray,
        model_bias: float,
        chebyshev_coeffs: Optional[List[float]] = None,
    ) -> Dict[str, Any]:
        """
        Executes homomorphic linear projection followed by polynomial activation
        to produce an encrypted anomaly risk score.
        """
        t0 = time.perf_counter()

        # Step 1: Homomorphic dot product (Weights dot encrypted features)
        # Weights shape: (num_features,)
        enc_z = enc_features.dot(model_weights.tolist())

        # Step 2: Homomorphic bias addition
        enc_z = enc_z + model_bias

        # Step 3: Polynomial activation approximating Sigmoid
        # Standard degree-3 Chebyshev approximation: sigma(z) ~ 0.5 + 0.197*z - 0.004*z^3
        coeffs = chebyshev_coeffs or [0.5, 0.197, 0.0, -0.004]
        enc_score = enc_z.polyval(coeffs)

        t_elapsed = (time.perf_counter() - t0) * 1000.0  # ms

        return {
            "encrypted_score": enc_score,
            "ciphertext_size_bytes": len(enc_score.serialize()),
            "eval_time_ms": round(t_elapsed, 3),
            "scheme": "SEAL_CKKS",
            "poly_modulus_degree": self.context.poly_modulus_degree(),
        }
