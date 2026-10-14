from __future__ import annotations

from pathlib import Path
import time
from typing import Any

import psutil

from adaptive_v2x_security.config import DEFAULT_CONFIG_DIR
from adaptive_v2x_security.domain import (
    DataClass,
    GeoZone,
    Interface,
    LocationContext,
    PQCMode,
    ResourceState,
)
from adaptive_v2x_security.ml import load_model_artifact
from adaptive_v2x_security.policy import RiskEngine
from adaptive_v2x_security.security import (
    OQSPQCProvider,
    SecurityIdentity,
    establish_sessions,
)
from adaptive_v2x_security.simulation import CentralMonitor

from .common import (
    dataset_path,
    json_safe,
    make_adapter,
    normalize_categorical_features,
    percentiles,
    write_json,
)
from .comparison import adaptive_vs_send_all

def _security_trial(
    *,
    iterations: int,
    payload: bytes,
    pqc_mode: PQCMode,
) -> dict[str, Any]:
    left = SecurityIdentity.generate("benchmark-left", pqc_mode)
    right = SecurityIdentity.generate("benchmark-right", pqc_mode)
    establishment: list[float] = []
    for _ in range(max(1, min(iterations, 20))):
        started = time.perf_counter_ns()
        pair = establish_sessions(left, right, pqc_mode=pqc_mode)
        establishment.append((time.perf_counter_ns() - started) / 1_000_000)
    pair = establish_sessions(left, right, pqc_mode=pqc_mode)
    protect: list[float] = []
    open_times: list[float] = []
    sizes: list[int] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        protected = pair.initiator.protect(payload)
        protect.append((time.perf_counter_ns() - started) / 1_000_000)
        sizes.append(len(protected))
        started = time.perf_counter_ns()
        opened = pair.responder.open(protected)
        open_times.append((time.perf_counter_ns() - started) / 1_000_000)
        if opened != payload:
            raise RuntimeError("Security benchmark round trip failed")
    return {
        "mode_requested": pqc_mode.value,
        "mode_status": pair.initiator.pqc_status,
        "key_exchange": (
            "X25519+ML-KEM-768"
            if pair.initiator.pqc_status == "active"
            else "X25519"
        ),
        "signature": (
            "Ed25519+ML-DSA-65"
            if pair.initiator.pqc_status == "active"
            else "Ed25519"
        ),
        "session_establishment_ms": percentiles(establishment),
        "protect_ms": percentiles(protect),
        "open_ms": percentiles(open_times),
        "protected_packet_bytes": percentiles(sizes),
        "plaintext_bytes": len(payload),
    }


def run_benchmark(
    *,
    artifact_dir: str | Path,
    dataset: str | None,
    path: str | Path | None,
    max_records: int,
    iterations: int,
    random_state: int,
    payload_bytes: int,
    output: str | Path,
) -> dict[str, Any]:
    model = load_model_artifact(artifact_dir)
    selected_dataset = dataset or str(model.metadata.get("dataset", "edge-iiot"))
    if selected_dataset not in {"edge-iiot", "veremi"}:
        raise ValueError("Model metadata does not identify a supported dataset")
    source = dataset_path(
        selected_dataset, path or model.metadata.get("dataset_source")
    )
    loaded = normalize_categorical_features(
        make_adapter(
            selected_dataset,
            source,
            task=model.task,
            max_rows=max_records,
            random_state=random_state,
            target_column=model.metadata.get("target_column"),
        ).load()
    )
    records = [json_safe(row.to_dict()) for _, row in loaded.X.iterrows()]
    if not records:
        raise ValueError("No benchmark records were loaded")

    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = process.cpu_times()
    cpu_seconds_before = cpu_before.user + cpu_before.system
    # Exclude one-time pipeline initialization and page faults from steady
    # state inference latency.
    model.assess_one(records[0])
    inference_times: list[float] = []
    assessments = []
    for index in range(iterations):
        record = records[index % len(records)]
        started = time.perf_counter_ns()
        assessment = model.assess_one(record)
        inference_times.append((time.perf_counter_ns() - started) / 1_000_000)
        assessments.append(assessment)

    engine = RiskEngine.from_yaml(DEFAULT_CONFIG_DIR / "security_policy.yaml")
    policy_times: list[float] = []
    decisions = []
    monitor = CentralMonitor(summary_every=10)
    data_classes = (DataClass.PUBLIC, DataClass.INTERNAL, DataClass.SENSITIVE)
    zones = (GeoZone.TRUSTED_INTERNAL, GeoZone.PUBLIC_ROAD, GeoZone.RESTRICTED)
    resources = ResourceState(25.0, 40.0, 2.0, 0.3)
    for index, assessment in enumerate(assessments):
        data_class = data_classes[index % len(data_classes)]
        location = LocationContext(
            zone=zones[index % len(zones)], interface=Interface.V2X
        )
        started = time.perf_counter_ns()
        decision = engine.decide(assessment, data_class, location, resources)
        policy_times.append((time.perf_counter_ns() - started) / 1_000_000)
        decisions.append(decision)
        monitor.observe(
            {
                "message": {"message_id": f"benchmark-{index}"},
                "assessment": {
                    "attack_probability": assessment.attack_probability,
                    "label": assessment.predicted_label,
                },
                "decision": decision.as_dict(),
            },
            decision,
        )

    payload = b"x" * payload_bytes
    classical = _security_trial(
        iterations=iterations,
        payload=payload,
        pqc_mode=PQCMode.CLASSICAL_ONLY,
    )
    availability = OQSPQCProvider.availability()
    pqc_trial: dict[str, Any] | None = None
    if availability.available:
        pqc_trial = _security_trial(
            iterations=iterations,
            payload=payload,
            pqc_mode=PQCMode.PQC_REQUIRED,
        )
    rss_after = process.memory_info().rss
    cpu_after = process.cpu_times()
    cpu_seconds_after = cpu_after.user + cpu_after.system

    result = {
        "command": "benchmark",
        "model_version": model.model_version,
        "dataset": selected_dataset,
        "source": source,
        "iterations": iterations,
        "latency_units": "milliseconds",
        "latency": {
            "inference_ms": percentiles(inference_times),
            "policy_ms": percentiles(policy_times),
            "security_classical": classical,
            "security_pqc": pqc_trial,
        },
        "central_workload": adaptive_vs_send_all(monitor.comparison()),
        "resource_usage": {
            "process_rss_start_bytes": rss_before,
            "process_rss_end_bytes": rss_after,
            "process_rss_delta_bytes": rss_after - rss_before,
            "process_cpu_seconds": cpu_seconds_after - cpu_seconds_before,
        },
        "pqc": {
            "available": availability.available,
            "kem_algorithm": availability.kem_algorithm,
            "signature_algorithm": availability.signature_algorithm,
            "reason": availability.reason,
            "measured": pqc_trial is not None,
            "synthetic_pqc_used": False,
        },
    }
    write_json(output, result)
    return result
