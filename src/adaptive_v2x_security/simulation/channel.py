"""Deterministic, in-process V2X transport simulation.

This module models channel behaviour only.  It does not claim to model a
physical radio, RF interference, or hardware-backed tamper resistance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random
import time
from typing import Callable, Protocol


class PacketHook(Protocol):
    def __call__(self, payload: bytes, rng: random.Random) -> bytes | None: ...


class InjectionHook(Protocol):
    def __call__(self, payload: bytes, rng: random.Random) -> list[bytes]: ...


@dataclass(frozen=True, slots=True)
class ChannelConfig:
    latency_ms: float = 0.0
    jitter_ms: float = 0.0
    loss_rate: float = 0.0
    tamper_rate: float = 0.0
    replay_rate: float = 0.0
    seed: int = 0
    sleep_for_latency: bool = False

    def __post_init__(self) -> None:
        if self.latency_ms < 0 or self.jitter_ms < 0:
            raise ValueError("latency_ms and jitter_ms must be non-negative")
        for name in ("loss_rate", "tamper_rate", "replay_rate"):
            value = getattr(self, name)
            if not 0 <= value <= 1:
                raise ValueError(f"{name} must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class ChannelDelivery:
    payload: bytes
    latency_ms: float
    kind: str = "primary"
    delivered: bool = True
    receiver_result: object | None = None


@dataclass(slots=True)
class SimulatedV2XChannel:
    """A seeded channel with loss, mutation, replay, and injection hooks."""

    config: ChannelConfig = field(default_factory=ChannelConfig)
    tamper_hook: PacketHook | None = None
    injection_hooks: tuple[InjectionHook, ...] = ()
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.config.seed)

    def reset(self, seed: int | None = None) -> None:
        """Reset the deterministic random stream."""

        self._rng.seed(self.config.seed if seed is None else seed)

    def _latency(self) -> float:
        jitter = self._rng.uniform(-self.config.jitter_ms, self.config.jitter_ms)
        return max(0.0, self.config.latency_ms + jitter)

    @staticmethod
    def _default_tamper(payload: bytes, rng: random.Random) -> bytes:
        if not payload:
            return payload
        changed = bytearray(payload)
        index = rng.randrange(len(changed))
        changed[index] ^= 1 << rng.randrange(8)
        return bytes(changed)

    def transmit(
        self,
        payload: bytes,
        receiver: Callable[[bytes], object],
    ) -> list[ChannelDelivery]:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if self._rng.random() < self.config.loss_rate:
            return [ChannelDelivery(payload, self._latency(), delivered=False)]

        packets: list[tuple[str, bytes]] = [("primary", payload)]
        if self._rng.random() < self.config.tamper_rate:
            hook = self.tamper_hook or self._default_tamper
            changed = hook(payload, self._rng)
            if changed is not None:
                packets[0] = ("tampered", changed)
        if self._rng.random() < self.config.replay_rate:
            packets.append(("replay", packets[0][1]))
        for hook in self.injection_hooks:
            packets.extend(("injected", item) for item in hook(payload, self._rng))

        deliveries: list[ChannelDelivery] = []
        for kind, packet in packets:
            latency = self._latency()
            if self.config.sleep_for_latency and latency:
                time.sleep(latency / 1_000)
            try:
                result = receiver(packet)
            except Exception as exc:  # Receiver failures are channel outcomes.
                result = exc
            deliveries.append(
                ChannelDelivery(packet, latency, kind, True, result)
            )
        return deliveries

    send = transmit
