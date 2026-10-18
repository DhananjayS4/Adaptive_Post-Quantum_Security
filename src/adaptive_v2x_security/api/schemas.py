"""Validated request contracts for monitoring-console operations."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyRequest(StrictModel):
    threat_probability: float = Field(0.65, ge=0, le=1)
    data_class: Literal["public", "internal", "sensitive", "safety_critical"] = "sensitive"
    zone: Literal["trusted_internal", "trusted_external", "public_road", "restricted"] = "public_road"
    interface: Literal["internal_bus", "wifi", "bluetooth", "ota", "v2x", "unknown"] = "v2x"
    assurance: Literal["attested", "simulated_trusted", "self_reported", "unavailable"] = "simulated_trusted"
    cpu_percent: float = Field(42, ge=0, le=100)
    memory_percent: float = Field(48, ge=0, le=100)
    latency_ms: float = Field(12, ge=0, le=10_000)
    traffic_density: float = Field(0.5, ge=0, le=1)


class SecureRoundTripRequest(StrictModel):
    payload: dict[str, Any] = Field(
        default_factory=lambda: {"signal": "brake", "value": True}
    )
    aead: Literal["AES-256-GCM", "ChaCha20-Poly1305"] = "AES-256-GCM"
    pqc_mode: Literal["classical_only", "pqc_preferred", "pqc_required"] = "classical_only"
    ttl_ms: int = Field(5_000, ge=100, le=60_000)


class JobRequest(StrictModel):
    kind: Literal["audit", "train", "demo", "benchmark", "ota"]
    options: dict[str, Any] = Field(default_factory=dict)
