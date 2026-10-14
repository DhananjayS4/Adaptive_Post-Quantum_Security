"""Testable in-process ECU sender and receiver simulation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import time
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from adaptive_v2x_security.domain import (
    DataClass,
    EdgeAction,
    Interface,
    LocationContext,
    PQCMode,
    ResourceState,
    ThreatAssessment,
    VehicleMessage,
)
from adaptive_v2x_security.policy.engine import RiskEngine
from adaptive_v2x_security.security import (
    SecureEnvelope,
    SecureSession,
    SecurityError,
    SecurityIdentity,
    establish_sessions,
)

from .channel import ChannelDelivery, SimulatedV2XChannel
from .monitor import CentralMonitor
from .resources import ResourceMonitor


class ThreatScorer(Protocol):
    """The small subset implemented by ``ThreatPredictor``."""

    def predict(self, record: Mapping[str, Any] | VehicleMessage) -> ThreatAssessment: ...


@dataclass(frozen=True, slots=True)
class ReceiveOutcome:
    accepted: bool
    sender_id: str | None
    message_id: str | None
    value: Any = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SendOutcome:
    message: VehicleMessage
    assessment: ThreatAssessment
    decision: Any
    canonical_object: Mapping[str, Any]
    protected_payload: bytes | None
    deliveries: tuple[ChannelDelivery, ...]
    session_reused: bool
    error: str | None = None

    @property
    def sent(self) -> bool:
        return self.protected_payload is not None


def classify_signal(signal_type: str) -> DataClass:
    """Classify common ECU signals using conservative defaults."""

    normalized = signal_type.strip().lower().replace("-", "_")
    if any(token in normalized for token in ("brake", "steer", "alert")):
        return DataClass.SAFETY_CRITICAL
    if "sensor" in normalized:
        return DataClass.SENSITIVE
    if "telemetry" in normalized:
        return DataClass.INTERNAL
    return DataClass.INTERNAL


class SimulatedECU:
    """An ECU simulation integrating predictor, policy, and secure sessions.

    Identity, channel, and secure-boot behaviour are software simulations; no
    hardware-rooted identity or hardware isolation is implied.
    """

    def __init__(
        self,
        ecu_id: str,
        risk_engine: RiskEngine,
        scorer: ThreatScorer | Callable[[VehicleMessage], ThreatAssessment],
        *,
        identity: SecurityIdentity | None = None,
        resource_monitor: ResourceMonitor | None = None,
        central_monitor: CentralMonitor | None = None,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if not ecu_id:
            raise ValueError("ecu_id must not be empty")
        self.ecu_id = ecu_id
        self.risk_engine = risk_engine
        self.scorer = scorer
        self.identity = identity or SecurityIdentity.generate(
            ecu_id, PQCMode.PQC_PREFERRED
        )
        self.resource_monitor = resource_monitor or ResourceMonitor()
        self.central_monitor = central_monitor
        self.clock_ms = clock_ms or (lambda: int(time.time() * 1_000))
        self.received: list[ReceiveOutcome] = []
        self._send_sessions: dict[tuple[str, str, str, str], SecureSession] = {}
        self._receive_sessions: dict[bytes, SecureSession] = {}
        self._previous_decisions: dict[str, Any] = {}

    @staticmethod
    def classify(signal_type: str) -> DataClass:
        return classify_signal(signal_type)

    def make_message(
        self,
        recipient_id: str,
        signal_type: str,
        payload: Mapping[str, Any],
        *,
        message_id: str | None = None,
        data_class: DataClass | None = None,
        location: LocationContext | None = None,
        observed_features: Mapping[str, Any] | None = None,
        resource_state: ResourceState | None = None,
    ) -> VehicleMessage:
        return VehicleMessage(
            message_id=message_id or uuid4().hex,
            sender_id=self.ecu_id,
            recipient_id=recipient_id,
            signal_type=signal_type,
            data_class=data_class or classify_signal(signal_type),
            payload=dict(payload),
            location=location
            or LocationContext(interface=Interface.V2X),
            resource_state=resource_state or self.resource_monitor.sample(),
            observed_features=dict(observed_features or payload),
            created_at_ms=self.clock_ms(),
        )

    def _score(self, message: VehicleMessage) -> ThreatAssessment:
        predictor = getattr(self.scorer, "predict", None)
        result = predictor(message) if predictor is not None else self.scorer(message)
        if not isinstance(result, ThreatAssessment):
            raise TypeError("scorer must return ThreatAssessment")
        if not 0 <= result.attack_probability <= 1:
            raise ValueError("assessment attack_probability must be in [0, 1]")
        return result

    @staticmethod
    def _canonical_object(
        message: VehicleMessage,
        assessment: ThreatAssessment,
        decision: Any,
    ) -> dict[str, Any]:
        return {
            "schema": "adaptive-v2x-message-v1",
            "message": {
                "message_id": message.message_id,
                "sender_id": message.sender_id,
                "recipient_id": message.recipient_id,
                "signal_type": message.signal_type,
                "data_class": message.data_class.value,
                "payload": dict(message.payload),
                "location": {
                    "zone": message.location.zone.value,
                    "interface": message.location.interface.value,
                    "assurance": message.location.assurance.value,
                    "x": message.location.x,
                    "y": message.location.y,
                },
                "resource_state": asdict(message.resource_state),
                "observed_features": dict(message.observed_features),
                "created_at_ms": message.created_at_ms,
            },
            "assessment": asdict(assessment),
            "decision": decision.as_dict(),
        }

    def _session_for(
        self, recipient: SimulatedECU, decision: Any
    ) -> tuple[SecureSession, bool]:
        key = (
            recipient.ecu_id,
            decision.policy_version,
            decision.profile_id,
            decision.pqc_mode.value,
        )
        existing = self._send_sessions.get(key)
        if existing is not None:
            return existing, True
        pair = establish_sessions(self.identity, recipient.identity, decision=decision)
        self._send_sessions[key] = pair.initiator
        recipient._receive_sessions[pair.responder.session_id] = pair.responder
        return pair.initiator, False

    def send(
        self,
        recipient: SimulatedECU,
        message: VehicleMessage,
        channel: SimulatedV2XChannel,
        *,
        ttl_ms: int = 5_000,
    ) -> SendOutcome:
        if message.sender_id != self.ecu_id:
            raise ValueError("message sender_id does not match this ECU")
        if message.recipient_id != recipient.ecu_id:
            raise ValueError("message recipient_id does not match recipient ECU")
        assessment = self._score(message)
        previous = self._previous_decisions.get(recipient.ecu_id)
        decision = self.risk_engine.evaluate(message, assessment, previous)
        self._previous_decisions[recipient.ecu_id] = decision
        value = self._canonical_object(message, assessment, decision)
        if self.central_monitor is not None:
            self.central_monitor.observe(value, decision)

        if decision.action in {
            EdgeAction.LOCAL_ONLY,
            EdgeAction.QUARANTINE,
            EdgeAction.REJECT,
        }:
            return SendOutcome(
                message, assessment, decision, value, None, (), False
            )

        try:
            session, reused = self._session_for(recipient, decision)
        except SecurityError as exc:
            # A required suite that cannot be established is an intentional
            # fail-closed outcome, not a reason to terminate the ECU loop.
            return SendOutcome(
                message,
                assessment,
                decision,
                value,
                None,
                (),
                False,
                f"{type(exc).__name__}: {exc}",
            )
        protected = session.protect_object(
            value, ttl_ms=ttl_ms, timestamp_ms=self.clock_ms()
        )
        deliveries = channel.transmit(protected, recipient.receive)
        return SendOutcome(
            message,
            assessment,
            decision,
            value,
            protected,
            tuple(deliveries),
            reused,
        )

    def receive(self, protected_payload: bytes) -> ReceiveOutcome:
        sender_id: str | None = None
        message_id: str | None = None
        try:
            envelope = SecureEnvelope.decode(protected_payload)
            session_id = envelope.headers.get("session_id")
            sender = envelope.headers.get("sender_id")
            sender_id = sender if isinstance(sender, str) else None
            if not isinstance(session_id, bytes):
                raise ValueError("missing session identifier")
            session = self._receive_sessions.get(session_id)
            if session is None:
                raise ValueError("unknown security session")
            value = session.open_object(protected_payload, now_ms=self.clock_ms())
            if not isinstance(value, dict) or value.get("schema") != "adaptive-v2x-message-v1":
                raise ValueError("unexpected canonical object schema")
            message = value.get("message")
            if not isinstance(message, dict):
                raise ValueError("canonical object has no message")
            if message.get("recipient_id") != self.ecu_id:
                raise ValueError("canonical object has wrong recipient")
            message_id = (
                message.get("message_id")
                if isinstance(message.get("message_id"), str)
                else None
            )
            outcome = ReceiveOutcome(True, sender_id, message_id, value)
        except Exception as exc:
            outcome = ReceiveOutcome(
                False, sender_id, message_id, error=f"{type(exc).__name__}: {exc}"
            )
        self.received.append(outcome)
        return outcome


ECU = SimulatedECU
