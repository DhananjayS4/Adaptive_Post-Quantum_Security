"""Central-workload accounting for adaptive V2X experiments."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from adaptive_v2x_security.domain import EdgeAction, ProtectionDecision
from adaptive_v2x_security.security import canonical_cbor


@dataclass(frozen=True, slots=True)
class WorkloadComparison:
    baseline_messages: int
    baseline_bytes: int
    adaptive_messages: int
    adaptive_bytes: int
    alert_messages: int
    summary_messages: int
    unavailable_messages: int

    @property
    def message_reduction(self) -> float:
        if not self.baseline_messages:
            return 0.0
        return 1.0 - self.adaptive_messages / self.baseline_messages

    @property
    def byte_reduction(self) -> float:
        if not self.baseline_bytes:
            return 0.0
        return 1.0 - self.adaptive_bytes / self.baseline_bytes

    def as_dict(self) -> dict[str, int | float]:
        result = asdict(self)
        result["message_reduction"] = self.message_reduction
        result["byte_reduction"] = self.byte_reduction
        return result


class CentralMonitor:
    """Compares send-all workload with adaptive alerts and summaries."""

    def __init__(self, *, summary_every: int = 10, available: bool = True) -> None:
        if summary_every <= 0:
            raise ValueError("summary_every must be positive")
        self.summary_every = summary_every
        self.available = available
        self.baseline_messages = 0
        self.baseline_bytes = 0
        self.adaptive_messages = 0
        self.adaptive_bytes = 0
        self.alert_messages = 0
        self.summary_messages = 0
        self.unavailable_messages = 0
        self.records: list[dict[str, Any]] = []
        self._since_summary = 0

    def set_available(self, available: bool) -> None:
        self.available = bool(available)

    def observe(
        self,
        canonical_object: Any,
        decision: ProtectionDecision,
    ) -> dict[str, Any] | None:
        encoded = canonical_cbor(canonical_object)
        self.baseline_messages += 1
        self.baseline_bytes += len(encoded)
        self._since_summary += 1

        is_alert = decision.action in {
            EdgeAction.ALERT_CENTRAL,
            EdgeAction.QUARANTINE,
            EdgeAction.REJECT,
        }
        event: dict[str, Any] | None = None
        if is_alert:
            event = {
                "kind": "alert",
                "message_id": canonical_object.get("message", {}).get("message_id")
                if isinstance(canonical_object, dict)
                else None,
                "decision": decision.as_dict(),
            }
            self.alert_messages += 1
        elif self._since_summary >= self.summary_every:
            event = {
                "kind": "summary",
                "events": self._since_summary,
                "last_risk_score": decision.risk_score,
                "policy_version": decision.policy_version,
            }
            self.summary_messages += 1

        if event is not None:
            self._since_summary = 0
            if self.available:
                self.records.append(event)
                self.adaptive_messages += 1
                self.adaptive_bytes += len(canonical_cbor(event))
            else:
                self.unavailable_messages += 1
        return event

    def comparison(self) -> WorkloadComparison:
        return WorkloadComparison(
            baseline_messages=self.baseline_messages,
            baseline_bytes=self.baseline_bytes,
            adaptive_messages=self.adaptive_messages,
            adaptive_bytes=self.adaptive_bytes,
            alert_messages=self.alert_messages,
            summary_messages=self.summary_messages,
            unavailable_messages=self.unavailable_messages,
        )

    report = comparison
