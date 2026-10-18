"""UI-facing adapters for backend services and generated experiment results."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
import json
import math
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping

from adaptive_v2x_security.config import DEFAULT_CONFIG_DIR, PROJECT_ROOT


RESULTS_DIR = PROJECT_ROOT / "results"
MODEL_DIR = RESULTS_DIR / "model"
RESULT_FILES = {
    "train": RESULTS_DIR / "train-metrics.json",
    "demo": RESULTS_DIR / "demo-summary.json",
    "benchmark": RESULTS_DIR / "benchmark.json",
    "ota": RESULTS_DIR / "ota-demo.json",
    "audit": RESULTS_DIR / "audit-data.json",
}
_PRIVATE_KEYS = {
    "artifact_dir",
    "coordinates",
    "dataset_source",
    "directory",
    "envelope",
    "exact_coordinates",
    "key",
    "key_material",
    "model_image_source",
    "path",
    "private_key",
    "raw_envelope",
    "secret",
    "source",
}
_ABSOLUTE_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/]|/(?:home|users|var|tmp)/)\S+")


def safe_json(value: Any) -> Any:
    """Convert backend values into strict, display-safe JSON-compatible values."""
    if is_dataclass(value) and not isinstance(value, type):
        return safe_json(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): safe_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [safe_json(item) for item in value]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, float) and not math.isfinite(value):
        return None
    item = getattr(value, "item", None)
    if callable(item):
        try:
            return safe_json(item())
        except (TypeError, ValueError):
            pass
    return value


def redact_private_fields(value: Any) -> Any:
    """Remove local paths and other location-bearing metadata before rendering."""
    converted = safe_json(value)
    if isinstance(converted, dict):
        return {
            key: (
                "configured locally"
                if key.lower() in _PRIVATE_KEYS
                else redact_private_fields(item)
            )
            for key, item in converted.items()
        }
    if isinstance(converted, list):
        return [redact_private_fields(item) for item in converted]
    if isinstance(converted, str) and _ABSOLUTE_PATH.search(converted):
        return _ABSOLUTE_PATH.sub("<local path>", converted)
    return converted


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object, returning an empty mapping for missing/invalid files."""
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def load_results() -> dict[str, dict[str, Any]]:
    return {name: load_json(path) for name, path in RESULT_FILES.items()}


def discover_artifacts() -> list[dict[str, Any]]:
    """Find model artifact directories without loading untrusted pickle content."""
    artifacts: list[dict[str, Any]] = []
    if not RESULTS_DIR.is_dir():
        return artifacts
    for metadata_path in RESULTS_DIR.glob("**/metadata.json"):
        directory = metadata_path.parent
        manifest = load_json(directory / "manifest.json")
        metadata = load_json(metadata_path)
        if not manifest or not metadata:
            continue
        try:
            modified = metadata_path.stat().st_mtime
        except OSError:
            continue
        artifacts.append(
            {
                "directory": directory,
                "name": directory.name,
                "model_version": metadata.get("model_version", "unknown"),
                "dataset": metadata.get("model_metadata", {}).get("dataset", "unknown"),
                "task": metadata.get("task", "unknown"),
                "modified": modified,
            }
        )
    return sorted(artifacts, key=lambda item: item["modified"], reverse=True)


def latest_model() -> dict[str, Any]:
    artifacts = discover_artifacts()
    return artifacts[0] if artifacts else {}


def pqc_availability() -> dict[str, Any]:
    try:
        from adaptive_v2x_security.security import OQSPQCProvider

        return safe_json(OQSPQCProvider.availability())
    except Exception as exc:  # Optional native provider must not prevent UI startup.
        return {
            "available": False,
            "kem_algorithm": "ML-KEM-768",
            "signature_algorithm": "ML-DSA-65",
            "reason": f"{type(exc).__name__}: provider could not be inspected",
        }


def evaluate_policy(
    *,
    threat_probability: float,
    data_class: str,
    zone: str,
    interface: str,
    assurance: str,
    cpu_percent: float,
    memory_percent: float,
    latency_ms: float,
    traffic_density: float,
) -> dict[str, Any]:
    from adaptive_v2x_security.domain import (
        DataClass,
        GeoZone,
        Interface,
        LocationAssurance,
        LocationContext,
        ResourceState,
        ThreatAssessment,
    )
    from adaptive_v2x_security.policy import RiskEngine

    engine = RiskEngine.from_yaml(DEFAULT_CONFIG_DIR / "security_policy.yaml")
    decision = engine.decide(
        ThreatAssessment(
            attack_probability=float(threat_probability),
            predicted_label="attack" if threat_probability >= 0.5 else "benign",
            model_version="interactive-ui",
        ),
        DataClass(data_class),
        LocationContext(
            zone=GeoZone(zone),
            interface=Interface(interface),
            assurance=LocationAssurance(assurance),
        ),
        ResourceState(
            cpu_percent=float(cpu_percent),
            memory_percent=float(memory_percent),
            latency_ms=float(latency_ms),
            traffic_density=float(traffic_density),
        ),
    )
    return decision.as_dict()


def secure_round_trip(
    *,
    payload: Mapping[str, Any],
    aead: str,
    pqc_mode: str,
    ttl_ms: int,
) -> dict[str, Any]:
    """Protect and open one real in-process session message."""
    from adaptive_v2x_security.domain import PQCMode
    from adaptive_v2x_security.security import SecurityIdentity, establish_sessions
    from adaptive_v2x_security.security.envelope import canonical_cbor

    mode = PQCMode(pqc_mode)
    started = time.perf_counter_ns()
    initiator = SecurityIdentity.generate("vehicle-demo", mode)
    responder = SecurityIdentity.generate("gateway-demo", mode)
    pair = establish_sessions(
        initiator,
        responder,
        pqc_mode=mode,
        aead=aead,
    )
    established_ms = (time.perf_counter_ns() - started) / 1_000_000
    plaintext = canonical_cbor(safe_json(dict(payload)))
    started = time.perf_counter_ns()
    envelope = pair.initiator.protect(plaintext, ttl_ms=int(ttl_ms))
    protect_ms = (time.perf_counter_ns() - started) / 1_000_000
    started = time.perf_counter_ns()
    opened = pair.responder.open(envelope)
    open_ms = (time.perf_counter_ns() - started) / 1_000_000
    return {
        "verified": opened == plaintext,
        "plaintext_bytes": len(plaintext),
        "envelope_bytes": len(envelope),
        "overhead_bytes": len(envelope) - len(plaintext),
        "session_establishment_ms": established_ms,
        "protect_ms": protect_ms,
        "open_ms": open_ms,
        "aead": pair.initiator.aead,
        "pqc_mode": mode.value,
        "pqc_status": pair.initiator.pqc_status,
        "audit": safe_json(pair.audit_log),
    }


def _bounded(value: int, *, minimum: int, maximum: int, name: str) -> int:
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum:,} and {maximum:,}")
    return parsed


def run_experiment(kind: str, **options: Any) -> dict[str, Any]:
    """Run one bounded experiment by calling its Python backend directly."""
    from adaptive_v2x_security.experiments import (
        audit_data,
        run_benchmark,
        run_demo,
        train_experiment,
    )

    dataset = str(options.get("dataset", "edge-iiot"))
    random_state = int(options.get("random_state", 42))
    if kind == "audit":
        return audit_data(
            dataset=dataset,
            path=None,
            task=str(options.get("task", "binary")),
            max_rows=_bounded(options.get("max_rows", 2_000), minimum=100, maximum=10_000, name="Rows"),
            random_state=random_state,
            target_column=None,
            output=RESULT_FILES["audit"],
        )
    if kind == "train":
        return train_experiment(
            dataset=dataset,
            path=None,
            task=str(options.get("task", "binary")),
            max_rows=_bounded(options.get("max_rows", 5_000), minimum=1_000, maximum=25_000, name="Rows"),
            random_state=random_state,
            target_column=None,
            artifact_dir=MODEL_DIR,
            output=RESULT_FILES["train"],
            calibrate=bool(options.get("calibrate", True)),
        )
    if kind == "demo":
        return run_demo(
            artifact_dir=MODEL_DIR,
            dataset=None,
            path=None,
            max_records=_bounded(options.get("max_records", 20), minimum=4, maximum=100, name="Records"),
            random_state=random_state,
            outage_start=None,
            outage_stop=None,
            output=RESULT_FILES["demo"],
        )
    if kind == "benchmark":
        return run_benchmark(
            artifact_dir=MODEL_DIR,
            dataset=None,
            path=None,
            max_records=_bounded(options.get("max_records", 50), minimum=10, maximum=200, name="Records"),
            iterations=_bounded(options.get("iterations", 20), minimum=1, maximum=100, name="Iterations"),
            random_state=random_state,
            payload_bytes=_bounded(options.get("payload_bytes", 256), minimum=16, maximum=4_096, name="Payload bytes"),
            output=RESULT_FILES["benchmark"],
        )
    raise ValueError(f"Unsupported experiment: {kind}")


def run_ota(target: str = "ecu-gateway") -> dict[str, Any]:
    from adaptive_v2x_security.experiments import run_ota_demo

    cleaned_target = target.strip()
    if not cleaned_target or len(cleaned_target) > 64:
        raise ValueError("Target must contain 1–64 characters")
    return run_ota_demo(
        artifact_dir=MODEL_DIR if MODEL_DIR.is_dir() else None,
        target=cleaned_target,
        output=RESULT_FILES["ota"],
    )


def safe_call(operation: Callable[[], Any]) -> tuple[Any | None, str | None]:
    """Execute a UI operation and return a non-traceback error description."""
    try:
        return operation(), None
    except Exception as exc:
        if isinstance(exc, (FileNotFoundError, OSError)):
            detail = "a required configured file or native dependency is unavailable"
        else:
            detail = str(exc)
            detail = detail.replace(str(PROJECT_ROOT), "<project>")
            detail = re.sub(
                r"(?i)\b[a-z]:[\\/][^;\n,]+",
                "<local path>",
                detail,
            )
        return None, f"{type(exc).__name__}: {detail}"
