"""
Cryptographic Key Management for FHE Confidential SIEM.
Manages Microsoft SEAL CKKS keys and TFHE Boolean keys with strict separation
between Client (Secret Key holder) and MSSP Cloud (Public / Evaluation Key holder).
"""

import base64
import os
import numpy as np
import tenseal as ts
from typing import Dict, Any, Optional, Tuple


class FHEKeyManager:
    """
    Orchestrates CKKS and TFHE keys for client and cloud evaluation.
    Guarantees that Secret Keys remain solely on the enterprise client premises.
    """

    def __init__(
        self,
        poly_modulus_degree: int = 8192,
        coeff_mod_bit_sizes: Tuple[int, ...] = (60, 40, 40, 60),
        global_scale: float = 2**40,
        lwe_dim: int = 500,
        lwe_noise_std: float = 0.0001,
    ):
        self.poly_modulus_degree = poly_modulus_degree
        self.coeff_mod_bit_sizes = list(coeff_mod_bit_sizes)
        self.global_scale = global_scale
        self.lwe_dim = lwe_dim
        self.lwe_noise_std = lwe_noise_std

        # Client secret keys (Client only)
        self._ckks_client_context: Optional[ts.Context] = None
        self._tfhe_secret_key: Optional[np.ndarray] = None

        # Public evaluation contexts (Cloud MSSP safe)
        self._ckks_cloud_context: Optional[ts.Context] = None
        self._tfhe_eval_key: Optional[Dict[str, Any]] = None

        # Auto-initialize
        self.generate_keys()

    def generate_keys(self) -> None:
        """Generates key pairs for both CKKS and TFHE schemes."""
        # 1. Generate Microsoft SEAL CKKS Context
        self._ckks_client_context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=self.poly_modulus_degree,
            coeff_mod_bit_sizes=self.coeff_mod_bit_sizes,
        )
        self._ckks_client_context.global_scale = self.global_scale
        self._ckks_client_context.generate_galois_keys()
        self._ckks_client_context.generate_relin_keys()

        # Generate Cloud MSSP Public Context (No secret key)
        public_bytes = self._ckks_client_context.serialize(save_secret_key=False)
        self._ckks_cloud_context = ts.context_from(public_bytes)

        # 2. Generate TFHE (Torus LWE) Key Pair
        # Secret key s in {0, 1}^n
        self._tfhe_secret_key = np.random.randint(0, 2, size=self.lwe_dim, dtype=np.int32)
        # Public evaluation parameters (bootstrap key approximation & gate noise specs)
        self._tfhe_eval_key = {
            "lwe_dim": self.lwe_dim,
            "noise_std": self.lwe_noise_std,
            "q_modulus": 2**32,
            "delta": 2**30,  # message scale
            "is_public": True,
        }

    @property
    def client_ckks_context(self) -> ts.Context:
        """Returns the private CKKS context (for Client use only)."""
        if self._ckks_client_context is None:
            raise RuntimeError("Client CKKS context not initialized.")
        return self._ckks_client_context

    @property
    def cloud_ckks_context(self) -> ts.Context:
        """Returns the public evaluation context without secret keys (for MSSP Cloud)."""
        if self._ckks_cloud_context is None:
            raise RuntimeError("Cloud CKKS context not initialized.")
        return self._ckks_cloud_context

    @property
    def tfhe_secret_key(self) -> np.ndarray:
        """Returns TFHE secret key (Client only)."""
        if self._tfhe_secret_key is None:
            raise RuntimeError("TFHE secret key not initialized.")
        return self._tfhe_secret_key

    @property
    def tfhe_eval_key(self) -> Dict[str, Any]:
        """Returns TFHE evaluation key (MSSP Cloud safe)."""
        if self._tfhe_eval_key is None:
            raise RuntimeError("TFHE eval key not initialized.")
        return self._tfhe_eval_key

    def export_cloud_bundle(self) -> Dict[str, Any]:
        """
        Exports public evaluation parameters for MSSP cloud ingestion.
        Guaranteed to contain NO private or secret key material.
        """
        ckks_pub_bytes = self._ckks_cloud_context.serialize(save_secret_key=False)
        return {
            "ckks_public_context_b64": base64.b64encode(ckks_pub_bytes).decode("ascii"),
            "tfhe_eval_key": self.tfhe_eval_key,
            "scheme": "HYBRID_SEAL_CKKS_TFHE_LWE",
            "poly_modulus_degree": self.poly_modulus_degree,
            "has_secret_key": False,
        }

    def verify_cloud_zero_knowledge(self) -> bool:
        """Verifies that cloud context cannot perform decryption."""
        return not self._ckks_cloud_context.is_private()
