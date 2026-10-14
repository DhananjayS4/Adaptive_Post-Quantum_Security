"""Authenticated encryption and hybrid session support."""

from .envelope import ENVELOPE_VERSION, SecureEnvelope, canonical_cbor, decode_envelope
from .errors import (
    EnvelopeError,
    NegotiationError,
    PQCUnavailableError,
    ReplayError,
    SecurityError,
)
from .providers import (
    ML_DSA_ALGORITHM,
    ML_KEM_ALGORITHM,
    ClassicalIdentity,
    ClassicalProvider,
    ClassicalPublicIdentity,
    OQSPQCProvider,
    PQCIdentity,
    PQCPublicIdentity,
    ProviderAvailability,
)
from .session import (
    AES_256_GCM,
    CHACHA20_POLY1305,
    AuditEvent,
    SecurityIdentity,
    SecureSession,
    SessionPair,
    create_session_pair,
    establish_sessions,
)

__all__ = [
    "AES_256_GCM",
    "CHACHA20_POLY1305",
    "ENVELOPE_VERSION",
    "ML_DSA_ALGORITHM",
    "ML_KEM_ALGORITHM",
    "AuditEvent",
    "ClassicalIdentity",
    "ClassicalProvider",
    "ClassicalPublicIdentity",
    "EnvelopeError",
    "NegotiationError",
    "OQSPQCProvider",
    "PQCIdentity",
    "PQCPublicIdentity",
    "PQCUnavailableError",
    "ProviderAvailability",
    "ReplayError",
    "SecureEnvelope",
    "SecureSession",
    "SecurityError",
    "SecurityIdentity",
    "SessionPair",
    "canonical_cbor",
    "create_session_pair",
    "decode_envelope",
    "establish_sessions",
]
