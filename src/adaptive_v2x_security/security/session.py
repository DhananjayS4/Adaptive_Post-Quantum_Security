from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from adaptive_v2x_security.domain import PQCMode, ProtectionDecision

from .envelope import ENVELOPE_VERSION, SecureEnvelope, canonical_cbor
from .errors import EnvelopeError, NegotiationError, PQCUnavailableError, ReplayError
from .providers import (
    ClassicalIdentity,
    ClassicalProvider,
    OQSPQCProvider,
    PQCIdentity,
)


AES_256_GCM = "AES-256-GCM"
CHACHA20_POLY1305 = "ChaCha20-Poly1305"
_HEADER_FIELDS = frozenset(
    (
        "version",
        "session_id",
        "sender_id",
        "recipient_id",
        "sequence",
        "timestamp_ms",
        "expires_ms",
        "nonce",
        "aead",
        "key_exchange",
        "signature",
        "pqc_mode",
        "pqc_status",
        "policy_version",
        "profile_id",
    )
)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class SecurityIdentity:
    peer_id: str
    classical: ClassicalIdentity
    pqc: PQCIdentity | None = None

    @classmethod
    def generate(
        cls,
        peer_id: str,
        pqc_mode: PQCMode | str = PQCMode.CLASSICAL_ONLY,
    ) -> SecurityIdentity:
        if not peer_id:
            raise ValueError("peer_id must not be empty")
        mode = PQCMode(pqc_mode)
        pqc: PQCIdentity | None = None
        if mode is not PQCMode.CLASSICAL_ONLY:
            if OQSPQCProvider.is_available():
                pqc = OQSPQCProvider.generate_identity()
            elif mode is PQCMode.PQC_REQUIRED:
                OQSPQCProvider.require_available()
        return cls(peer_id, ClassicalProvider.generate_identity(), pqc)


def _aead_name(value: str) -> str:
    normalized = value.upper().replace("_", "-")
    if normalized in ("AES-256-GCM", "AES256-GCM", "AESGCM"):
        return AES_256_GCM
    if normalized in (
        "CHACHA20-POLY1305",
        "CHACHA20POLY1305",
        "CHACHA20-POLY-1305",
    ):
        return CHACHA20_POLY1305
    raise NegotiationError(f"Unsupported AEAD: {value}")


def _cipher(name: str, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if len(key) != 32:
        raise ValueError("AEAD key must be 256 bits")
    return AESGCM(key) if name == AES_256_GCM else ChaCha20Poly1305(key)


class SecureSession:
    """One endpoint of an authenticated, replay-protected two-party session."""

    def __init__(
        self,
        *,
        local: SecurityIdentity,
        peer: SecurityIdentity,
        send_key: bytes,
        receive_key: bytes,
        session_id: bytes,
        aead: str,
        pqc_mode: PQCMode,
        pqc_status: str,
        key_exchange: str,
        signature_algorithm: str,
        policy_version: str,
        profile_id: str,
        audit_log: tuple[AuditEvent, ...],
        max_ttl_ms: int = 60_000,
        clock_skew_ms: int = 30_000,
    ) -> None:
        self.local_id = local.peer_id
        self.peer_id = peer.peer_id
        self.session_id = session_id
        self.aead = aead
        self.pqc_mode = pqc_mode
        self.pqc_status = pqc_status
        self.audit_log = audit_log
        self._local = local
        self._peer = peer
        self._send_cipher = _cipher(aead, send_key)
        self._receive_cipher = _cipher(aead, receive_key)
        self._key_exchange = key_exchange
        self._signature_algorithm = signature_algorithm
        self._policy_version = policy_version
        self._profile_id = profile_id
        self._max_ttl_ms = max_ttl_ms
        self._clock_skew_ms = clock_skew_ms
        self._send_sequence = 0
        self._received_sequence = 0
        self._lock = threading.Lock()

    def _headers(
        self, sequence: int, timestamp_ms: int, expires_ms: int, nonce: bytes
    ) -> dict[str, Any]:
        return {
            "version": ENVELOPE_VERSION,
            "session_id": self.session_id,
            "sender_id": self.local_id,
            "recipient_id": self.peer_id,
            "sequence": sequence,
            "timestamp_ms": timestamp_ms,
            "expires_ms": expires_ms,
            "nonce": nonce,
            "aead": self.aead,
            "key_exchange": self._key_exchange,
            "signature": self._signature_algorithm,
            "pqc_mode": self.pqc_mode.value,
            "pqc_status": self.pqc_status,
            "policy_version": self._policy_version,
            "profile_id": self._profile_id,
        }

    def protect(
        self,
        plaintext: bytes,
        *,
        ttl_ms: int = 5_000,
        timestamp_ms: int | None = None,
    ) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not 0 < ttl_ms <= self._max_ttl_ms:
            raise ValueError(f"ttl_ms must be in [1, {self._max_ttl_ms}]")
        now = int(time.time() * 1000) if timestamp_ms is None else int(timestamp_ms)
        with self._lock:
            self._send_sequence += 1
            sequence = self._send_sequence
        if sequence >= 2**64:
            raise NegotiationError("Session sequence exhausted; rekey is required")
        # Unique per directional key: a random session prefix plus a monotonic
        # counter avoids depending on random nonce collision probability.
        nonce = self.session_id[:4] + sequence.to_bytes(8, "big")
        headers = self._headers(sequence, now, now + ttl_ms, nonce)
        ciphertext = self._send_cipher.encrypt(nonce, plaintext, canonical_cbor(headers))
        unsigned = SecureEnvelope(headers, ciphertext, {})
        signed_bytes = unsigned.signing_bytes()
        signatures = {
            "Ed25519": ClassicalProvider.sign(self._local.classical, signed_bytes)
        }
        if self.pqc_status == "active":
            if self._local.pqc is None:
                raise PQCUnavailableError("Active PQC session has no local PQC identity")
            signatures["ML-DSA-65"] = OQSPQCProvider.sign(
                self._local.pqc.signature_secret, signed_bytes
            )
        return SecureEnvelope(headers, ciphertext, signatures).encode()

    seal = protect

    def protect_object(
        self,
        value: Any,
        *,
        ttl_ms: int = 5_000,
        timestamp_ms: int | None = None,
    ) -> bytes:
        return self.protect(
            canonical_cbor(value), ttl_ms=ttl_ms, timestamp_ms=timestamp_ms
        )

    def _validate_headers(self, headers: dict[str, Any], now_ms: int) -> tuple[int, bytes]:
        if set(headers) != _HEADER_FIELDS:
            raise EnvelopeError("Envelope header set is invalid")
        expected = {
            "version": ENVELOPE_VERSION,
            "session_id": self.session_id,
            "sender_id": self.peer_id,
            "recipient_id": self.local_id,
            "aead": self.aead,
            "key_exchange": self._key_exchange,
            "signature": self._signature_algorithm,
            "pqc_mode": self.pqc_mode.value,
            "pqc_status": self.pqc_status,
            "policy_version": self._policy_version,
            "profile_id": self._profile_id,
        }
        if any(headers.get(key) != value for key, value in expected.items()):
            raise EnvelopeError("Envelope context mismatch or downgrade attempt")

        sequence = headers.get("sequence")
        timestamp = headers.get("timestamp_ms")
        expires = headers.get("expires_ms")
        nonce = headers.get("nonce")
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence <= 0
            or isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or isinstance(expires, bool)
            or not isinstance(expires, int)
            or not isinstance(nonce, bytes)
            or len(nonce) != 12
        ):
            raise EnvelopeError("Envelope sequence, time, or nonce is invalid")
        if expires <= timestamp or expires - timestamp > self._max_ttl_ms:
            raise ReplayError("Envelope lifetime is invalid")
        if now_ms > expires:
            raise ReplayError("Envelope has expired")
        if timestamp > now_ms + self._clock_skew_ms:
            raise ReplayError("Envelope timestamp is in the future")
        if timestamp < now_ms - self._max_ttl_ms - self._clock_skew_ms:
            raise ReplayError("Envelope timestamp is stale")
        with self._lock:
            if sequence <= self._received_sequence:
                raise ReplayError("Envelope sequence was already received")
        return sequence, nonce

    def open(self, encoded: bytes, *, now_ms: int | None = None) -> bytes:
        envelope = SecureEnvelope.decode(encoded)
        headers = dict(envelope.headers)
        current_time = int(time.time() * 1000) if now_ms is None else int(now_ms)
        sequence, nonce = self._validate_headers(headers, current_time)

        expected_signatures = (
            frozenset(("Ed25519", "ML-DSA-65"))
            if self.pqc_status == "active"
            else frozenset(("Ed25519",))
        )
        if set(envelope.signatures) != expected_signatures:
            raise EnvelopeError("Signature set mismatch or downgrade attempt")
        signed_bytes = envelope.signing_bytes()
        if not ClassicalProvider.verify(
            self._peer.classical.public.signing_key,
            signed_bytes,
            envelope.signatures["Ed25519"],
        ):
            raise EnvelopeError("Ed25519 signature verification failed")
        if self.pqc_status == "active":
            if self._peer.pqc is None or not OQSPQCProvider.verify(
                self._peer.pqc.public.signing_key,
                signed_bytes,
                envelope.signatures["ML-DSA-65"],
            ):
                raise EnvelopeError("ML-DSA-65 signature verification failed")

        try:
            plaintext = self._receive_cipher.decrypt(
                nonce, envelope.ciphertext, canonical_cbor(headers)
            )
        except InvalidTag as exc:
            raise EnvelopeError("AEAD authentication failed") from exc
        with self._lock:
            if sequence <= self._received_sequence:
                raise ReplayError("Envelope sequence was concurrently replayed")
            self._received_sequence = sequence
        return plaintext

    unseal = open

    def open_object(self, encoded: bytes, *, now_ms: int | None = None) -> Any:
        import cbor2

        plaintext = self.open(encoded, now_ms=now_ms)
        try:
            value = cbor2.loads(plaintext)
        except (ValueError, EOFError, cbor2.CBORDecodeError) as exc:
            raise EnvelopeError("Decrypted payload is not CBOR") from exc
        if canonical_cbor(value) != plaintext:
            raise EnvelopeError("Decrypted payload is not canonical CBOR")
        return value


@dataclass(frozen=True, slots=True)
class SessionPair:
    initiator: SecureSession
    responder: SecureSession
    audit_log: tuple[AuditEvent, ...]

    def __iter__(self) -> Iterator[SecureSession]:
        yield self.initiator
        yield self.responder


def establish_sessions(
    initiator: SecurityIdentity,
    responder: SecurityIdentity,
    *,
    decision: ProtectionDecision | None = None,
    pqc_mode: PQCMode | str | None = None,
    aead: str = AES_256_GCM,
    max_ttl_ms: int = 60_000,
    clock_skew_ms: int = 30_000,
) -> SessionPair:
    """Establish an in-process pair suitable for V2X simulation."""

    if initiator.peer_id == responder.peer_id:
        raise NegotiationError("Session peers must have distinct IDs")
    if max_ttl_ms <= 0 or clock_skew_ms < 0:
        raise ValueError("Invalid replay-protection timing")
    selected_aead = _aead_name(aead)
    if decision is not None and pqc_mode is not None:
        if decision.pqc_mode != PQCMode(pqc_mode):
            raise NegotiationError("Decision and explicit PQC modes conflict")
    mode = (
        decision.pqc_mode
        if decision is not None
        else PQCMode.CLASSICAL_ONLY
        if pqc_mode is None
        else PQCMode(pqc_mode)
    )
    audit: list[AuditEvent] = []
    pqc_active = False
    pqc_secret = b""
    kem_ciphertext = b""

    status = OQSPQCProvider.availability()
    identities_have_pqc = initiator.pqc is not None and responder.pqc is not None
    if mode is PQCMode.PQC_REQUIRED:
        if not status.available:
            raise PQCUnavailableError(status.reason or "PQC provider unavailable")
        if not identities_have_pqc:
            raise NegotiationError("PQC-required session needs PQC identities for both peers")
        pqc_active = True
    elif mode is PQCMode.PQC_PREFERRED:
        if status.available and identities_have_pqc:
            pqc_active = True
        else:
            reason = status.reason if not status.available else "one or both peers lack PQC keys"
            audit.append(
                AuditEvent(
                    "pqc.preferred_fallback",
                    f"Fell back to X25519+Ed25519: {reason}",
                )
            )

    classical_secret = ClassicalProvider.exchange(
        initiator.classical, responder.classical.public.exchange_key
    )
    responder_secret = ClassicalProvider.exchange(
        responder.classical, initiator.classical.public.exchange_key
    )
    if classical_secret != responder_secret:
        raise NegotiationError("X25519 key agreement failed")

    if pqc_active:
        assert responder.pqc is not None
        kem_ciphertext, pqc_secret = OQSPQCProvider.encapsulate(
            responder.pqc.public.kem_key
        )
        decapsulated = OQSPQCProvider.decapsulate(
            responder.pqc.kem_secret, kem_ciphertext
        )
        if not hmac.compare_digest(pqc_secret, decapsulated):
            raise NegotiationError("ML-KEM-768 key agreement failed")

    session_id = os.urandom(16)
    pqc_status = (
        "active"
        if pqc_active
        else "fallback"
        if mode is PQCMode.PQC_PREFERRED
        else "disabled"
    )
    key_exchange = (
        "X25519+ML-KEM-768" if pqc_active else ClassicalProvider.exchange_algorithm
    )
    signature_algorithm = (
        "Ed25519+ML-DSA-65" if pqc_active else ClassicalProvider.signature_algorithm
    )
    policy_version = decision.policy_version if decision is not None else ""
    profile_id = decision.profile_id if decision is not None else ""
    context = {
        "protocol": "adaptive-v2x-session-v1",
        "session_id": session_id,
        "initiator_id": initiator.peer_id,
        "responder_id": responder.peer_id,
        "initiator_exchange_key": initiator.classical.public.exchange_key,
        "responder_exchange_key": responder.classical.public.exchange_key,
        "initiator_signing_key": initiator.classical.public.signing_key,
        "responder_signing_key": responder.classical.public.signing_key,
        "aead": selected_aead,
        "key_exchange": key_exchange,
        "signature": signature_algorithm,
        "pqc_mode": mode.value,
        "pqc_status": pqc_status,
        "kem_ciphertext": kem_ciphertext,
        "initiator_pqc_kem_key": (
            initiator.pqc.public.kem_key if pqc_active and initiator.pqc else b""
        ),
        "responder_pqc_kem_key": (
            responder.pqc.public.kem_key if pqc_active and responder.pqc else b""
        ),
        "initiator_pqc_signing_key": (
            initiator.pqc.public.signing_key if pqc_active and initiator.pqc else b""
        ),
        "responder_pqc_signing_key": (
            responder.pqc.public.signing_key if pqc_active and responder.pqc else b""
        ),
        "policy_version": policy_version,
        "profile_id": profile_id,
    }
    encoded_context = canonical_cbor(context)
    input_key_material = canonical_cbor([classical_secret, pqc_secret])
    keys = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(encoded_context).digest(),
        info=b"adaptive-v2x directional keys\x00" + encoded_context,
    ).derive(input_key_material)
    initiator_to_responder, responder_to_initiator = keys[:32], keys[32:]
    common = {
        "session_id": session_id,
        "aead": selected_aead,
        "pqc_mode": mode,
        "pqc_status": pqc_status,
        "key_exchange": key_exchange,
        "signature_algorithm": signature_algorithm,
        "policy_version": policy_version,
        "profile_id": profile_id,
        "audit_log": tuple(audit),
        "max_ttl_ms": max_ttl_ms,
        "clock_skew_ms": clock_skew_ms,
    }
    left = SecureSession(
        local=initiator,
        peer=responder,
        send_key=initiator_to_responder,
        receive_key=responder_to_initiator,
        **common,
    )
    right = SecureSession(
        local=responder,
        peer=initiator,
        send_key=responder_to_initiator,
        receive_key=initiator_to_responder,
        **common,
    )
    return SessionPair(left, right, tuple(audit))


create_session_pair = establish_sessions
