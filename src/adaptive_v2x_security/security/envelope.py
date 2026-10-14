from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import cbor2

from .errors import EnvelopeError


ENVELOPE_VERSION = 1
_TOP_LEVEL_FIELDS = frozenset(("headers", "ciphertext", "signatures"))


def canonical_cbor(value: Any) -> bytes:
    try:
        return cbor2.dumps(value, canonical=True)
    except (TypeError, ValueError, cbor2.CBOREncodeError) as exc:
        raise EnvelopeError("Value cannot be canonically encoded") from exc


@dataclass(frozen=True, slots=True)
class SecureEnvelope:
    headers: Mapping[str, Any]
    ciphertext: bytes
    signatures: Mapping[str, bytes]

    def signing_bytes(self) -> bytes:
        return canonical_cbor(
            {"headers": dict(self.headers), "ciphertext": self.ciphertext}
        )

    def encode(self) -> bytes:
        return canonical_cbor(
            {
                "headers": dict(self.headers),
                "ciphertext": self.ciphertext,
                "signatures": dict(self.signatures),
            }
        )

    @classmethod
    def decode(cls, encoded: bytes) -> SecureEnvelope:
        if not isinstance(encoded, bytes):
            raise EnvelopeError("Envelope must be bytes")
        try:
            value = cbor2.loads(encoded)
        except (ValueError, EOFError, cbor2.CBORDecodeError) as exc:
            raise EnvelopeError("Malformed CBOR envelope") from exc
        if not isinstance(value, dict) or set(value) != _TOP_LEVEL_FIELDS:
            raise EnvelopeError("Envelope has unexpected fields")
        if canonical_cbor(value) != encoded:
            raise EnvelopeError("Envelope is not canonical CBOR")

        headers = value["headers"]
        ciphertext = value["ciphertext"]
        signatures = value["signatures"]
        if not isinstance(headers, dict) or not all(
            isinstance(key, str) for key in headers
        ):
            raise EnvelopeError("Invalid envelope headers")
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise EnvelopeError("Invalid envelope ciphertext")
        if not isinstance(signatures, dict) or not signatures:
            raise EnvelopeError("Envelope has no signatures")
        if not all(
            isinstance(key, str) and isinstance(signature, bytes)
            for key, signature in signatures.items()
        ):
            raise EnvelopeError("Invalid envelope signatures")
        return cls(headers=dict(headers), ciphertext=ciphertext, signatures=dict(signatures))


def decode_envelope(encoded: bytes) -> SecureEnvelope:
    return SecureEnvelope.decode(encoded)
