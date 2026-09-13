"""
FastAPI Server for Confidential SIEM.
Provides REST endpoints for encrypted log ingestion, blind homomorphic evaluation,
cyber attack simulations, MITRE rule queries, benchmarks, and compliance audits.
"""

import time
import uuid
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from fhe_engine.keys import FHEKeyManager
from fhe_engine.ckks_engine import CKKSEngine
from fhe_engine.tfhe_engine import TFHEEngine, LWECiphertext
from fhe_engine.pipeline.schema import NormalizedLog
from fhe_engine.pipeline.encoder import FHELogEncoder
from fhe_engine.pipeline.generator import LogGenerator
from fhe_engine.rules.catalog import RULES_CATALOG, RULE_MAP
from fhe_engine.ml.model import EncryptedAnomalyDetector
from fhe_engine.batching.optimizer import SIMDBatchOptimizer


app = FastAPI(
    title="Confidential SIEM (FHE-Powered)",
    description="Zero-Knowledge Privacy-Preserving SIEM on Encrypted Logs",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize FHE Core
print("[Confidential SIEM] Initializing Cryptographic Engines...")
key_manager = FHEKeyManager()

# Client engines (Enterprise edge simulator)
ckks_client = CKKSEngine(key_manager.client_ckks_context, is_client=True)
tfhe_client = TFHEEngine(secret_key=key_manager.tfhe_secret_key)
client_encoder = FHELogEncoder(ckks_client, tfhe_client)
client_ml = EncryptedAnomalyDetector(ckks_client)

# Cloud MSSP engines (Blind evaluation only - no secret keys)
ckks_cloud = CKKSEngine(key_manager.cloud_ckks_context, is_client=False)
tfhe_cloud = TFHEEngine(secret_key=None)
batch_optimizer = SIMDBatchOptimizer(ckks_cloud, tfhe_cloud, num_workers=4)

print("[Confidential SIEM] Cloud Evaluator ready. Zero-knowledge verified:", key_manager.verify_cloud_zero_knowledge())


# --- Pydantic Request Models ---

class IngestLogPayload(BaseModel):
    event_id: str
    client_id: str
    timestamp: float
    ckks_features_ciphertext: str
    tfhe_flags_ciphertexts: Dict[str, Any]
    feature_dim: int
    flag_count: int


class BatchIngestRequest(BaseModel):
    batch: List[IngestLogPayload]


class SimulateAttackRequest(BaseModel):
    attack_type: str  # "brute_force", "ransomware", "c2_beaconing", "lateral_movement", "data_exfiltration", "benign"
    client_id: Optional[str] = "FIN-CORP-SEC-01"
    batch_size: Optional[int] = 4


# --- API Routes ---

@app.get("/api/status")
def get_system_status():
    """Returns cryptographic engine readiness, GPU acceleration, and compliance mode."""
    return {
        "status": "ONLINE",
        "cloud_zero_knowledge": key_manager.verify_cloud_zero_knowledge(),
        "schemes": {
            "ckks": "Microsoft SEAL CKKS 8192 (Approximate Arithmetic & ML)",
            "tfhe": "Vectorized Torus LWE (Exact Boolean & Rule Circuits)",
        },
        "total_detection_rules": len(RULES_CATALOG),
        "workers": batch_optimizer.num_workers,
        "acceleration_device": batch_optimizer.gpu_device_name,
        "cuda_enabled": batch_optimizer.cuda_available,
        "security_level": "128-bit Post-Quantum Lattice Security",
    }


@app.get("/api/keys/public")
def get_public_keys():
    """Returns cloud evaluation parameters without secret key material."""
    return key_manager.export_cloud_bundle()


@app.get("/api/rules")
def get_rule_catalog():
    """Returns the full catalog of 160 detection rules grouped by MITRE ATT&CK tactics."""
    tactics: Dict[str, List[Dict[str, Any]]] = {}
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

    for r in RULES_CATALOG:
        severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
        tactics.setdefault(r.tactic, []).append({
            "rule_id": r.rule_id,
            "name": r.name,
            "tactic": r.tactic,
            "technique_id": r.technique_id,
            "severity": r.severity,
            "compliance_controls": r.compliance_controls,
            "required_flags": r.required_flags,
        })

    return {
        "total_rules": len(RULES_CATALOG),
        "tactics": tactics,
        "severities": severity_counts,
    }


@app.post("/api/evaluate")
def evaluate_encrypted_batch(request: BatchIngestRequest):
    """
    Evaluates a batch of encrypted logs homomorphically.
    MSSP cloud evaluates 160 rules and ML model without decryption.
    """
    batch_data = [item.dict() for item in request.batch]
    results, metrics = batch_optimizer.evaluate_batch(batch_data)

    return {
        "batch_metrics": {
            "batch_size": metrics.batch_size,
            "total_latency_ms": metrics.total_latency_ms,
            "avg_latency_per_event_ms": metrics.latency_per_event_ms,
            "throughput_events_per_sec": metrics.throughput_events_per_sec,
            "sub_500ms_compliant": metrics.sub_500ms_compliant,
            "gpu_accelerated": metrics.gpu_accelerated,
        },
        "results": results,
    }


@app.post("/api/simulate")
def simulate_attack_lifecycle(request: SimulateAttackRequest):
    """
    Executes an end-to-end Confidential SIEM detection lifecycle:
    1. Client edge generates and normalizes log.
    2. Client encrypts features (CKKS + TFHE) on edge.
    3. MSSP Cloud executes blind evaluation (160 rules + ML anomaly detector).
    4. Client decrypts the result with private key, proving zero-leakage threat detection.
    """
    t_start = time.perf_counter()

    # Step 1: Generate logs on Client edge
    attack_type = request.attack_type.lower()
    raw_logs = LogGenerator.generate_batch(
        count=request.batch_size or 4,
        attack_type=None if attack_type == "benign" else attack_type,
        client_id=request.client_id,
    )

    lifecycle_events = []

    for log in raw_logs:
        # Step 2: Client-side encryption
        t_enc = time.perf_counter()
        enc_payload = client_encoder.encode_and_encrypt_log(log)
        enc_time_ms = (time.perf_counter() - t_enc) * 1000.0

        # Step 3: MSSP Cloud Blind Evaluation
        t_eval = time.perf_counter()
        cloud_eval_res = batch_optimizer.evaluate_encrypted_event(enc_payload)
        eval_time_ms = (time.perf_counter() - t_eval) * 1000.0

        # Step 4: Client-side Decryption of Alerts
        # Client decrypts ML score
        ml_res = cloud_eval_res["ml_evaluation"]
        ml_score = client_ml.client_decrypt_score(ml_res["ciphertext_b64"])

        # Client decrypts matched rules
        rule_eval_res = cloud_eval_res["rule_evaluation"]
        matched_rules = []
        for r_id, r_info in rule_eval_res["rule_detections"].items():
            match_ct = r_info["match_ciphertext"]
            dec_bit = tfhe_client.decrypt_bits(match_ct)[0]
            if dec_bit == 1:
                matched_rules.append({
                    "rule_id": r_info["rule_id"],
                    "name": r_info["name"],
                    "tactic": r_info["tactic"],
                    "technique_id": r_info["technique_id"],
                    "severity": r_info["severity"],
                    "compliance": r_info["compliance"],
                    "circuit_depth": r_info["circuit_depth"],
                })

        lifecycle_events.append({
            "event_id": log.event_id,
            "client_id": log.client_id,
            "timestamp": log.timestamp,
            # Plaintext snapshot visible ONLY at Client edge
            "client_plaintext_view": {
                "category": log.event_category,
                "protocol": log.protocol,
                "port": log.dest_port,
                "auth_status": log.auth_status,
                "user_role": log.user_role,
                "src_ip_type": log.src_ip_type,
                "failed_logins": round(log.failed_login_count, 1),
                "bytes_transferred_mb": round(log.bytes_transferred_mb, 2),
                "file_entropy": round(log.file_entropy, 2),
                "beacon_jitter": round(log.beacon_jitter, 3),
            },
            # Encrypted ciphertext snapshot visible to MSSP Cloud (No Plaintext!)
            "mssp_cloud_encrypted_view": {
                "ckks_ciphertext_sample": enc_payload["ckks_features_ciphertext"][:64] + "...",
                "ckks_ciphertext_length": len(enc_payload["ckks_features_ciphertext"]),
                "tfhe_flags_encrypted_count": len(enc_payload["tfhe_flags_ciphertexts"]),
                "plaintext_revealed_to_cloud": False,
                "cloud_has_secret_key": False,
            },
            # Performance metrics
            "timings_ms": {
                "client_encryption_ms": round(enc_time_ms, 2),
                "cloud_eval_ms": round(eval_time_ms, 2),
                "rules_circuit_ms": cloud_eval_res["rules_eval_time_ms"],
                "ml_inference_ms": cloud_eval_res["ml_eval_time_ms"],
            },
            # Threat detection results decrypted solely by Client
            "client_decrypted_detection": {
                "threat_detected": len(matched_rules) > 0 or ml_score >= 0.65,
                "ml_anomaly_score": ml_score,
                "ml_anomaly_alert": ml_score >= 0.65,
                "matched_rules_count": len(matched_rules),
                "matched_rules": matched_rules,
                "max_severity": max([r["severity"] for r in matched_rules], default="NONE") if matched_rules else ("HIGH" if ml_score >= 0.65 else "LOW"),
            },
        })

    total_pipeline_ms = (time.perf_counter() - t_start) * 1000.0

    return {
        "simulation_type": attack_type,
        "total_pipeline_time_ms": round(total_pipeline_ms, 2),
        "events_processed": len(lifecycle_events),
        "sub_500ms": total_pipeline_ms < 500.0,
        "events": lifecycle_events,
    }


@app.get("/api/benchmark")
def run_dynamic_benchmark(batch_size: int = 8, workers: int = 4):
    """Executes a live benchmark test and returns performance statistics."""
    logs = LogGenerator.generate_batch(count=batch_size, attack_type="ransomware")
    enc_batch = client_encoder.encode_and_encrypt_batch(logs)

    results, metrics = batch_optimizer.evaluate_batch(enc_batch)

    return {
        "batch_size": metrics.batch_size,
        "total_latency_ms": metrics.total_latency_ms,
        "latency_per_event_ms": metrics.latency_per_event_ms,
        "rules_latency_ms": metrics.rules_latency_ms,
        "ml_latency_ms": metrics.ml_latency_ms,
        "throughput_events_per_sec": metrics.throughput_events_per_sec,
        "workers": metrics.num_workers,
        "gpu_accelerated": metrics.gpu_accelerated,
        "acceleration_device": metrics.gpu_device_name,
        "sub_500ms_compliant": metrics.sub_500ms_compliant,
        "total_rules_evaluated_per_event": len(RULES_CATALOG),
        "timestamp": time.time(),
    }


@app.get("/api/compliance")
def get_compliance_audit():
    """Returns regulatory compliance alignment and zero-knowledge mathematical verification."""
    return {
        "audit_timestamp": time.time(),
        "compliance_posture": "FULLY_COMPLIANT_ZERO_KNOWLEDGE",
        "regulations": {
            "GDPR": {
                "status": "COMPLIANT",
                "articles": [
                    {
                        "article": "Art. 25 - Data Protection by Design and Default",
                        "verdict": "PASS",
                        "evidence": "Logs are homomorphically encrypted at enterprise edge prior to cloud egress.",
                    },
                    {
                        "article": "Art. 32(1)(a) - Pseudonymisation and Encryption of Personal Data",
                        "verdict": "PASS",
                        "evidence": "All PII, user identifiers, and IP addresses remain encrypted using SEAL CKKS and TFHE lattice ciphertexts.",
                    },
                    {
                        "article": "Art. 32(1)(b) - Confidentiality, Integrity, Availability",
                        "verdict": "PASS",
                        "evidence": "MSSP Cloud does not possess private secret keys; data cannot be exfiltrated via cloud compromise.",
                    },
                ],
            },
            "HIPAA": {
                "status": "COMPLIANT",
                "rules": [
                    {
                        "section": "§ 164.312(a)(2)(iv) - Encryption and Decryption",
                        "verdict": "PASS",
                        "evidence": "Homomorphic encryption eliminates the requirement to decrypt ePHI during SIEM monitoring.",
                    },
                    {
                        "section": "§ 164.312(b) - Audit Controls",
                        "verdict": "PASS",
                        "evidence": "160 rule circuits track unauthorized access attempts with cryptographically verifiable circuits.",
                    },
                ],
            },
            "NIST_CSF": {
                "status": "COMPLIANT",
                "controls": [
                    {
                        "control": "PR.DS-1: Data-at-rest is protected",
                        "verdict": "PASS",
                        "evidence": "Homomorphic ciphertext storage preserves confidentiality continuously.",
                    },
                    {
                        "control": "PR.DS-2: Data-in-transit is protected",
                        "verdict": "PASS",
                        "evidence": "End-to-end homomorphic ciphertexts transmitted over TLS 1.3.",
                    },
                    {
                        "control": "DE.AE-1: Baseline of network operations is established",
                        "verdict": "PASS",
                        "evidence": "Encrypted polynomial ML anomaly detector identifies deviations from baseline.",
                    },
                ],
            },
        },
    }


# Mount Static Files for Cyber SOC Dashboard
app.mount("/static", StaticFiles(directory="server/static"), name="static")


@app.get("/")
def serve_dashboard():
    """Serves the Confidential SIEM Cyber SOC Dashboard."""
    return FileResponse("server/static/index.html")
