"""Small scenario runner; intended for synthetic records, not full datasets."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from adaptive_v2x_security.domain import DataClass, LocationContext, ResourceState

from .channel import SimulatedV2XChannel
from .ecu import SendOutcome, SimulatedECU
from .monitor import CentralMonitor, WorkloadComparison


@dataclass(frozen=True, slots=True)
class ScenarioEvent:
    signal_type: str
    payload: Mapping[str, Any]
    observed_features: Mapping[str, Any] = field(default_factory=dict)
    data_class: DataClass | None = None
    location: LocationContext | None = None
    resource_state: ResourceState | None = None
    central_available: bool | None = None


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    outcomes: tuple[SendOutcome, ...]
    workload: WorkloadComparison | None

    @property
    def accepted(self) -> int:
        return sum(
            1
            for outcome in self.outcomes
            for delivery in outcome.deliveries
            if getattr(delivery.receiver_result, "accepted", False)
        )


class ScenarioRunner:
    def __init__(
        self,
        sender: SimulatedECU,
        receiver: SimulatedECU,
        channel: SimulatedV2XChannel,
        *,
        central_monitor: CentralMonitor | None = None,
    ) -> None:
        self.sender = sender
        self.receiver = receiver
        self.channel = channel
        self.central_monitor = central_monitor or sender.central_monitor
        if sender.central_monitor is None and self.central_monitor is not None:
            sender.central_monitor = self.central_monitor

    def run(
        self,
        events: Iterable[ScenarioEvent],
        *,
        central_outage: range | set[int] | tuple[int, int] | None = None,
    ) -> ScenarioResult:
        """Run a bounded synthetic event iterable.

        ``central_outage`` can be an index collection/range or a half-open
        ``(start, stop)`` tuple. Peer-to-peer processing continues during it.
        """

        if isinstance(central_outage, tuple):
            outage_indices: set[int] | range = range(*central_outage)
        else:
            outage_indices = central_outage or set()
        outcomes: list[SendOutcome] = []
        for index, event in enumerate(events):
            if self.central_monitor is not None:
                available = (
                    event.central_available
                    if event.central_available is not None
                    else index not in outage_indices
                )
                self.central_monitor.set_available(available)
            message = self.sender.make_message(
                self.receiver.ecu_id,
                event.signal_type,
                event.payload,
                data_class=event.data_class,
                location=event.location,
                observed_features=event.observed_features,
                resource_state=event.resource_state,
            )
            outcomes.append(self.sender.send(self.receiver, message, self.channel))
        return ScenarioResult(
            tuple(outcomes),
            self.central_monitor.comparison() if self.central_monitor else None,
        )


SimulationRunner = ScenarioRunner
