"""Resource sampling adapters for lightweight simulations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

import psutil

from adaptive_v2x_security.domain import ResourceState


class MetricsProvider(Protocol):
    def __call__(self) -> Mapping[str, float] | ResourceState: ...


@dataclass(slots=True)
class ResourceMonitor:
    """Samples psutil, or an injected deterministic metrics provider."""

    metrics_provider: MetricsProvider | None = None
    latency_provider: Callable[[], float] | None = None
    traffic_density_provider: Callable[[], float] | None = None

    def sample(self) -> ResourceState:
        if self.metrics_provider is None:
            values: Mapping[str, float] | ResourceState = {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
            }
        else:
            values = self.metrics_provider()
        if isinstance(values, ResourceState):
            return values
        return ResourceState(
            cpu_percent=float(values.get("cpu_percent", 0.0)),
            memory_percent=float(values.get("memory_percent", 0.0)),
            latency_ms=float(
                values.get(
                    "latency_ms",
                    self.latency_provider() if self.latency_provider else 0.0,
                )
            ),
            traffic_density=float(
                values.get(
                    "traffic_density",
                    self.traffic_density_provider()
                    if self.traffic_density_provider
                    else 0.0,
                )
            ),
        )

    snapshot = sample


PsutilResourceMonitor = ResourceMonitor
