from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    SAFETY_CRITICAL = "safety_critical"


class Interface(StrEnum):
    INTERNAL_BUS = "internal_bus"
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    OTA = "ota"
    V2X = "v2x"
    UNKNOWN = "unknown"


class GeoZone(StrEnum):
    TRUSTED_INTERNAL = "trusted_internal"
    TRUSTED_EXTERNAL = "trusted_external"
    PUBLIC_ROAD = "public_road"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class LocationAssurance(StrEnum):
    ATTESTED = "attested"
    SIMULATED_TRUSTED = "simulated_trusted"
    SELF_REPORTED = "self_reported"
    UNAVAILABLE = "unavailable"


class EdgeAction(StrEnum):
    LOCAL_ONLY = "local_only"
    PROTECT_AND_FORWARD = "protect_and_forward"
    ALERT_CENTRAL = "alert_central"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class PQCMode(StrEnum):
    CLASSICAL_ONLY = "classical_only"
    PQC_PREFERRED = "pqc_preferred"
    PQC_REQUIRED = "pqc_required"


@dataclass(frozen=True, slots=True)
class ResourceState:
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    latency_ms: float = 0.0
    traffic_density: float = 0.0


@dataclass(frozen=True, slots=True)
class LocationContext:
    zone: GeoZone = GeoZone.UNKNOWN
    interface: Interface = Interface.UNKNOWN
    assurance: LocationAssurance = LocationAssurance.UNAVAILABLE
    x: float | None = None
    y: float | None = None


@dataclass(frozen=True, slots=True)
class ThreatAssessment:
    attack_probability: float
    predicted_label: str
    model_version: str
    inference_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class ProtectionDecision:
    risk_score: float
    profile_id: str
    action: EdgeAction
    pqc_mode: PQCMode
    reasons: tuple[str, ...]
    policy_version: str
    security_floor: int

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["action"] = self.action.value
        result["pqc_mode"] = self.pqc_mode.value
        result["reasons"] = list(self.reasons)
        return result


@dataclass(slots=True)
class VehicleMessage:
    message_id: str
    sender_id: str
    recipient_id: str
    signal_type: str
    data_class: DataClass
    payload: dict[str, Any]
    location: LocationContext
    resource_state: ResourceState = field(default_factory=ResourceState)
    observed_features: dict[str, Any] = field(default_factory=dict)
    created_at_ms: int = 0
