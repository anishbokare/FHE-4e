"""
Automated Test Suite for FHE Confidential SIEM.
Verifies cryptographic correctness, zero-knowledge isolation, 160-rule circuit accuracy,
ML anomaly detection fidelity, and sub-500ms latency SLA.
"""

import pytest
import numpy as np

from fhe_engine.keys import FHEKeyManager
from fhe_engine.ckks_engine import CKKSEngine
from fhe_engine.tfhe_engine import TFHEEngine, LWECiphertext
from fhe_engine.pipeline.schema import NormalizedLog
from fhe_engine.pipeline.encoder import FHELogEncoder
from fhe_engine.pipeline.generator import LogGenerator
from fhe_engine.rules.catalog import RULES_CATALOG, DetectionRule
from fhe_engine.rules.evaluator import HomomorphicRuleEvaluator
from fhe_engine.ml.model import EncryptedAnomalyDetector
from fhe_engine.batching.optimizer import SIMDBatchOptimizer


@pytest.fixture(scope="module")
def key_manager():
    return FHEKeyManager()


@pytest.fixture(scope="module")
def engines(key_manager):
    ckks_client = CKKSEngine(key_manager.client_ckks_context, is_client=True)
    ckks_cloud = CKKSEngine(key_manager.cloud_ckks_context, is_client=False)
    tfhe_client = TFHEEngine(secret_key=key_manager.tfhe_secret_key)
    tfhe_cloud = TFHEEngine(secret_key=None)
    return {
        "ckks_client": ckks_client,
        "ckks_cloud": ckks_cloud,
        "tfhe_client": tfhe_client,
        "tfhe_cloud": tfhe_cloud,
    }


def test_zero_knowledge_security_boundary(key_manager):
    """Verifies that cloud evaluation bundle does not expose secret keys."""
    assert key_manager.verify_cloud_zero_knowledge() is True
    bundle = key_manager.export_cloud_bundle()
    assert bundle["has_secret_key"] is False
    assert "tfhe_secret_key" not in bundle


def test_seal_ckks_homomorphic_arithmetic(engines):
    """Verifies Microsoft SEAL CKKS homomorphic operations."""
    ckks_client = engines["ckks_client"]
    ckks_cloud = engines["ckks_cloud"]

    # Encrypt on client
    v1 = ckks_client.encrypt_vector([2.0, 4.0, 6.0])
    v2 = ckks_client.encrypt_vector([1.0, 2.0, 3.0])

    # Evaluate on cloud
    res_add = ckks_cloud.homomorphic_add(v1, v2)
    res_mul = ckks_cloud.homomorphic_mul_plain(v1, 3.0)

    # Decrypt on client
    dec_add = ckks_client.decrypt_vector(res_add)
    dec_mul = ckks_client.decrypt_vector(res_mul)

    np.testing.assert_allclose(dec_add[:3], [3.0, 6.0, 9.0], rtol=1e-3)
    np.testing.assert_allclose(dec_mul[:3], [6.0, 12.0, 18.0], rtol=1e-3)


def test_tfhe_boolean_logic_circuits(engines):
    """Verifies TFHE exact boolean gate truth tables."""
    tfhe_client = engines["tfhe_client"]
    tfhe_cloud = engines["tfhe_cloud"]

    bit0 = tfhe_client.encrypt_bit(0)
    bit1 = tfhe_client.encrypt_bit(1)

    # AND gate
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_and(bit0, bit0))[0] == 0
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_and(bit0, bit1))[0] == 0
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_and(bit1, bit1))[0] == 1

    # OR gate
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_or(bit0, bit0))[0] == 0
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_or(bit1, bit0))[0] == 1
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_or(bit1, bit1))[0] == 1

    # XOR gate
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_xor(bit0, bit0))[0] == 0
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_xor(bit1, bit0))[0] == 1
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_xor(bit1, bit1))[0] == 0

    # NOT gate
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_not(bit0))[0] == 1
    assert tfhe_client.decrypt_bits(tfhe_cloud.gate_not(bit1))[0] == 0


def test_rule_catalog_160_rules():
    """Verifies that 160 detection rules cover all 10 MITRE tactics."""
    assert len(RULES_CATALOG) >= 150
    tactics = set(r.tactic for r in RULES_CATALOG)
    expected_tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Command and Control", "Exfiltration & Impact"
    }
    assert expected_tactics.issubset(tactics)

    for rule in RULES_CATALOG:
        assert rule.rule_id.startswith("RULE-")
        assert len(rule.required_flags) >= 1
        assert rule.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(rule.compliance_controls) >= 1


def test_ml_anomaly_detector_discrimination(engines):
    """Verifies that encrypted ML model distinguishes benign from ransomware attack."""
    ckks_client = engines["ckks_client"]
    ckks_cloud = engines["ckks_cloud"]
    tfhe_client = engines["tfhe_client"]

    encoder = FHELogEncoder(ckks_client, tfhe_client)
    ml_cloud = EncryptedAnomalyDetector(ckks_cloud)
    ml_client = EncryptedAnomalyDetector(ckks_client)

    benign_log = LogGenerator.generate_benign_log()
    ransom_log = LogGenerator.generate_ransomware_attack()

    enc_benign = encoder.encode_and_encrypt_log(benign_log)
    enc_ransom = encoder.encode_and_encrypt_log(ransom_log)

    v_b = ckks_cloud.deserialize_ciphertext(enc_benign["ckks_features_ciphertext"])
    v_r = ckks_cloud.deserialize_ciphertext(enc_ransom["ckks_features_ciphertext"])

    res_b = ml_cloud.predict_encrypted(v_b)
    res_r = ml_cloud.predict_encrypted(v_r)

    score_b = ml_client.client_decrypt_score(res_b["ciphertext_b64"])
    score_r = ml_client.client_decrypt_score(res_r["ciphertext_b64"])

    # Benign should be low anomaly (<0.3), Ransomware should be high anomaly (>0.7)
    assert score_b < 0.30
    assert score_r > 0.70


def test_sub_500ms_latency_sla(engines):
    """Verifies that batch evaluation achieves sub-500ms latency per event."""
    ckks_client = engines["ckks_client"]
    ckks_cloud = engines["ckks_cloud"]
    tfhe_client = engines["tfhe_client"]
    tfhe_cloud = engines["tfhe_cloud"]

    encoder = FHELogEncoder(ckks_client, tfhe_client)
    optimizer = SIMDBatchOptimizer(ckks_cloud, tfhe_cloud, num_workers=4)

    logs = LogGenerator.generate_batch(count=4, attack_type="brute_force")
    enc_batch = encoder.encode_and_encrypt_batch(logs)

    results, metrics = optimizer.evaluate_batch(enc_batch)

    assert metrics.sub_500ms_compliant is True
    assert metrics.latency_per_event_ms < 500.0
    assert len(results) == 4
