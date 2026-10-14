from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

import yaml

from adaptive_v2x_security.domain import (
    DataClass,
    EdgeAction,
    GeoZone,
    Interface,
    LocationContext,
    PQCMode,
    ProtectionDecision,
    ResourceState,
    ThreatAssessment,
    VehicleMessage,
)


class PolicyConfigurationError(ValueError):
    """Raised when a policy cannot be interpreted safely."""


class ReasonCode(StrEnum):
    RISK_BASELINE = "risk.baseline"
    RISK_ELEVATED = "risk.elevated"
    RISK_HIGH = "risk.high"
    RISK_CRITICAL = "risk.critical"
    UNKNOWN_THREAT = "unknown.threat"
    UNKNOWN_DATA_CLASS = "unknown.data_class"
    UNKNOWN_LOCATION = "unknown.location"
    UNKNOWN_INTERFACE = "unknown.interface"
    UNKNOWN_RESOURCES = "unknown.resources"
    UNKNOWN_LATENCY = "unknown.latency"
    UNKNOWN_DENSITY = "unknown.density"
    DATA_FLOOR = "floor.data"
    INTERFACE_FLOOR = "floor.interface"
    HYSTERESIS_HELD = "hysteresis.held"
    CENTRAL_ALERT = "action.alert_central"
    QUARANTINE = "action.quarantine"


@dataclass(frozen=True, slots=True)
class _Profile:
    id: str
    level: int
    pqc_mode: PQCMode


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyConfigurationError(f"{name} must be a mapping")
    return value


def _finite(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _bounded(value: Any, *, scale: float = 1.0) -> tuple[float, bool]:
    number = _finite(value)
    if number is None or number < 0:
        return 1.0, True
    return min(number / scale, 1.0), False


class RiskEngine:
    """Configurable, conservative policy evaluator with profile hysteresis."""

    def __init__(self, config: Mapping[str, Any]) -> None:
        self._config = dict(config)
        self.version = str(config.get("version", "unknown"))

        weights = _mapping(config.get("risk_weights"), "risk_weights")
        required_weights = (
            "threat",
            "data",
            "location",
            "interface",
            "resources",
            "latency",
            "density",
        )
        parsed_weights: dict[str, float] = {}
        for key in required_weights:
            weight = _finite(weights.get(key))
            if weight is None or weight < 0:
                raise PolicyConfigurationError(f"Invalid risk weight: {key}")
            parsed_weights[key] = weight
        weight_total = sum(parsed_weights.values())
        if weight_total <= 0:
            raise PolicyConfigurationError("Risk weights must have a positive sum")
        self._weights = {key: value / weight_total for key, value in parsed_weights.items()}

        thresholds = _mapping(config.get("thresholds"), "thresholds")
        self._thresholds = {
            name: self._probability(thresholds.get(name), f"thresholds.{name}")
            for name in ("elevated", "high", "critical", "quarantine_attack_probability")
        }
        if not (
            0 <= self._thresholds["elevated"]
            <= self._thresholds["high"]
            <= self._thresholds["critical"]
            <= 1
        ):
            raise PolicyConfigurationError("Risk thresholds must be ordered")

        self._data_scores = self._scores(config.get("data_scores"), "data_scores")
        self._location_scores = self._scores(config.get("location_scores"), "location_scores")
        self._interface_scores = self._scores(config.get("interface_scores"), "interface_scores")

        floors = _mapping(config.get("security_floors"), "security_floors")
        self._data_floors = self._floors(floors.get("data"), "security_floors.data")
        self._interface_floors = self._floors(
            floors.get("interface"), "security_floors.interface"
        )

        raw_profiles = config.get("profiles")
        if not isinstance(raw_profiles, list) or not raw_profiles:
            raise PolicyConfigurationError("profiles must be a non-empty list")
        profiles: list[_Profile] = []
        for item in raw_profiles:
            profile = _mapping(item, "profile")
            try:
                profiles.append(
                    _Profile(
                        id=str(profile["id"]),
                        level=int(profile["level"]),
                        pqc_mode=PQCMode(str(profile["pqc_mode"])),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyConfigurationError("Invalid profile") from exc
        self._profiles = tuple(sorted(profiles, key=lambda item: item.level))
        if len({profile.level for profile in self._profiles}) != len(self._profiles):
            raise PolicyConfigurationError("Profile levels must be unique")

        margin = _finite(config.get("hysteresis_margin", 0.0))
        if margin is None or not 0 <= margin < 1:
            raise PolicyConfigurationError("hysteresis_margin must be in [0, 1)")
        self._hysteresis_margin = margin

        normalization = config.get("normalization", {})
        if normalization is None:
            normalization = {}
        normalization = _mapping(normalization, "normalization")
        self._latency_max_ms = _finite(normalization.get("latency_max_ms", 200.0))
        if self._latency_max_ms is None or self._latency_max_ms <= 0:
            raise PolicyConfigurationError("normalization.latency_max_ms must be positive")

    @classmethod
    def from_yaml(cls, path: str | Path) -> RiskEngine:
        with Path(path).open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle)
        if not isinstance(config, Mapping):
            raise PolicyConfigurationError("Policy YAML must contain a mapping")
        return cls(config)

    @staticmethod
    def _probability(value: Any, name: str) -> float:
        number = _finite(value)
        if number is None or not 0 <= number <= 1:
            raise PolicyConfigurationError(f"{name} must be in [0, 1]")
        return number

    @classmethod
    def _scores(cls, value: Any, name: str) -> dict[str, float]:
        source = _mapping(value, name)
        return {str(key): cls._probability(score, f"{name}.{key}") for key, score in source.items()}

    @staticmethod
    def _floors(value: Any, name: str) -> dict[str, int]:
        source = _mapping(value, name)
        try:
            floors = {str(key): int(level) for key, level in source.items()}
        except (TypeError, ValueError) as exc:
            raise PolicyConfigurationError(f"{name} contains a non-integer floor") from exc
        if any(level < 0 for level in floors.values()):
            raise PolicyConfigurationError(f"{name} contains a negative floor")
        return floors

    @staticmethod
    def _value(value: Any) -> str:
        return str(getattr(value, "value", value)).lower()

    @staticmethod
    def _lookup(
        table: Mapping[str, float], value: Any, unknown_key: str = "unknown"
    ) -> tuple[float, bool]:
        key = RiskEngine._value(value)
        if key in table:
            return table[key], key == unknown_key
        return table.get(unknown_key, 1.0), True

    def _candidate_level(self, risk: float) -> int:
        if risk >= self._thresholds["critical"]:
            return 3
        if risk >= self._thresholds["high"]:
            return 2
        if risk >= self._thresholds["elevated"]:
            return 1
        return 0

    def _profile_for_level(self, level: int) -> _Profile:
        for profile in self._profiles:
            if profile.level >= level:
                return profile
        return self._profiles[-1]

    def _apply_hysteresis(
        self, risk: float, candidate: int, previous: ProtectionDecision | None
    ) -> tuple[int, bool]:
        if previous is None:
            return candidate, False
        prior = next(
            (item.level for item in self._profiles if item.id == previous.profile_id),
            previous.security_floor,
        )
        prior = max(self._profiles[0].level, min(prior, self._profiles[-1].level))
        boundaries = {
            1: self._thresholds["elevated"],
            2: self._thresholds["high"],
            3: self._thresholds["critical"],
        }
        if candidate > prior:
            boundary = boundaries.get(candidate, 1.0)
            if risk < boundary + self._hysteresis_margin:
                return prior, True
        elif candidate < prior:
            boundary = boundaries.get(prior, 0.0)
            if risk >= boundary - self._hysteresis_margin:
                return prior, True
        return candidate, False

    def decide(
        self,
        threat: ThreatAssessment | float | None,
        data_class: DataClass | str,
        location: LocationContext | GeoZone | str,
        resources: ResourceState | None = None,
        *,
        interface: Interface | str | None = None,
        previous_decision: ProtectionDecision | None = None,
    ) -> ProtectionDecision:
        reasons: list[str] = []

        threat_value = threat.attack_probability if isinstance(threat, ThreatAssessment) else threat
        threat_score, unknown = _bounded(threat_value)
        if unknown:
            reasons.append(ReasonCode.UNKNOWN_THREAT.value)

        data_score, unknown = self._lookup(self._data_scores, data_class)
        data_key = self._value(data_class)
        if unknown:
            reasons.append(ReasonCode.UNKNOWN_DATA_CLASS.value)

        if isinstance(location, LocationContext):
            zone = location.zone
            selected_interface = location.interface if interface is None else interface
        else:
            zone = location
            selected_interface = Interface.UNKNOWN if interface is None else interface
        location_score, unknown = self._lookup(self._location_scores, zone)
        if unknown:
            reasons.append(ReasonCode.UNKNOWN_LOCATION.value)
        interface_score, unknown = self._lookup(self._interface_scores, selected_interface)
        interface_key = self._value(selected_interface)
        if unknown:
            reasons.append(ReasonCode.UNKNOWN_INTERFACE.value)

        if resources is None:
            resource_score = latency_score = density_score = 1.0
            reasons.extend(
                (
                    ReasonCode.UNKNOWN_RESOURCES.value,
                    ReasonCode.UNKNOWN_LATENCY.value,
                    ReasonCode.UNKNOWN_DENSITY.value,
                )
            )
        else:
            cpu, bad_cpu = _bounded(resources.cpu_percent, scale=100.0)
            memory, bad_memory = _bounded(resources.memory_percent, scale=100.0)
            resource_score = max(cpu, memory)
            if bad_cpu or bad_memory:
                reasons.append(ReasonCode.UNKNOWN_RESOURCES.value)
            latency_score, bad_latency = _bounded(
                resources.latency_ms, scale=self._latency_max_ms
            )
            if bad_latency:
                reasons.append(ReasonCode.UNKNOWN_LATENCY.value)
            density_score, bad_density = _bounded(resources.traffic_density)
            if bad_density:
                reasons.append(ReasonCode.UNKNOWN_DENSITY.value)

        components = {
            "threat": threat_score,
            "data": data_score,
            "location": location_score,
            "interface": interface_score,
            "resources": resource_score,
            "latency": latency_score,
            "density": density_score,
        }
        risk = min(1.0, sum(self._weights[key] * value for key, value in components.items()))
        level, held = self._apply_hysteresis(
            risk, self._candidate_level(risk), previous_decision
        )
        if held:
            reasons.append(ReasonCode.HYSTERESIS_HELD.value)

        data_floor = self._data_floors.get(
            data_key, max(self._data_floors.values(), default=self._profiles[-1].level)
        )
        interface_floor = self._interface_floors.get(
            interface_key,
            self._interface_floors.get("unknown", self._profiles[-1].level),
        )
        floor = max(data_floor, interface_floor)
        if level < data_floor:
            reasons.append(ReasonCode.DATA_FLOOR.value)
        if max(level, data_floor) < interface_floor:
            reasons.append(ReasonCode.INTERFACE_FLOOR.value)
        level = max(level, floor)
        profile = self._profile_for_level(level)

        if threat_score >= self._thresholds["quarantine_attack_probability"]:
            action = EdgeAction.QUARANTINE
            reasons.append(ReasonCode.QUARANTINE.value)
        elif risk >= self._thresholds["critical"] or profile.level >= 3:
            action = EdgeAction.ALERT_CENTRAL
            reasons.append(ReasonCode.CENTRAL_ALERT.value)
        else:
            action = EdgeAction.PROTECT_AND_FORWARD

        risk_reason = (
            ReasonCode.RISK_CRITICAL
            if risk >= self._thresholds["critical"]
            else ReasonCode.RISK_HIGH
            if risk >= self._thresholds["high"]
            else ReasonCode.RISK_ELEVATED
            if risk >= self._thresholds["elevated"]
            else ReasonCode.RISK_BASELINE
        )
        reasons.insert(0, risk_reason.value)
        return ProtectionDecision(
            risk_score=round(risk, 6),
            profile_id=profile.id,
            action=action,
            pqc_mode=profile.pqc_mode,
            reasons=tuple(dict.fromkeys(reasons)),
            policy_version=self.version,
            security_floor=floor,
        )

    def evaluate(
        self,
        message: VehicleMessage,
        threat: ThreatAssessment | float | None,
        previous_decision: ProtectionDecision | None = None,
    ) -> ProtectionDecision:
        return self.decide(
            threat,
            message.data_class,
            message.location,
            message.resource_state,
            previous_decision=previous_decision,
        )


PolicyEngine = RiskEngine
