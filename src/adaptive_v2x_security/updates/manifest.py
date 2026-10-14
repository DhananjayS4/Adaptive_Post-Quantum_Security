"""Signed update manifests using real Ed25519 and optional ML-DSA."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from adaptive_v2x_security.security import OQSPQCProvider, PQCIdentity, canonical_cbor


class ManifestError(ValueError):
    pass


class SignatureVerificationError(ManifestError):
    pass


class ArtifactVerificationError(ManifestError):
    pass


class RollbackProtectionError(ManifestError):
    pass


def _utc(value: datetime | str | int | float) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        # Large values are interpreted as Unix milliseconds.
        result = datetime.fromtimestamp(
            value / 1_000 if value > 10_000_000_000 else value, tz=UTC
        )
    elif isinstance(value, str):
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ManifestError("expires_at must be an ISO timestamp or Unix time")
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def compare_versions(left: str, right: str) -> int:
    """Compare common dotted versions without adding a packaging dependency."""

    def parts(value: str) -> tuple[tuple[int, int | str], ...]:
        if not value or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", value):
            raise ManifestError(f"invalid version: {value!r}")
        tokens = re.findall(r"\d+|[A-Za-z]+", value)
        return tuple(
            (1, int(token)) if token.isdigit() else (0, token.lower())
            for token in tokens
        )

    left_parts, right_parts = parts(left), parts(right)
    width = max(len(left_parts), len(right_parts))
    zero = (1, 0)
    padded_left = left_parts + (zero,) * (width - len(left_parts))
    padded_right = right_parts + (zero,) * (width - len(right_parts))
    return (padded_left > padded_right) - (padded_left < padded_right)


@dataclass(frozen=True, slots=True)
class UpdateManifest:
    target: str
    version: str
    sha256: str
    expires_at: datetime | str | int | float
    size: int
    artifact_type: str = "firmware"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.target:
            raise ManifestError("target must not be empty")
        compare_versions(self.version, self.version)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256):
            raise ManifestError("sha256 must be 64 hexadecimal characters")
        if self.size < 0:
            raise ManifestError("size must be non-negative")
        _utc(self.expires_at)

    @classmethod
    def for_artifact(
        cls,
        artifact: bytes,
        *,
        target: str,
        version: str,
        expires_at: datetime | str | int | float,
        artifact_type: str = "firmware",
        metadata: Mapping[str, Any] | None = None,
    ) -> UpdateManifest:
        return cls(
            target=target,
            version=version,
            sha256=hashlib.sha256(artifact).hexdigest(),
            expires_at=expires_at,
            size=len(artifact),
            artifact_type=artifact_type,
            metadata=dict(metadata or {}),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "adaptive-v2x-update-manifest-v1",
            "target": self.target,
            "version": self.version,
            "sha256": self.sha256.lower(),
            "size": self.size,
            "expires_at": _utc(self.expires_at).isoformat().replace("+00:00", "Z"),
            "artifact_type": self.artifact_type,
            "metadata": dict(self.metadata),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_cbor(self.as_dict())

    def is_expired(self, now: datetime | None = None) -> bool:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        return current >= _utc(self.expires_at)

    def verify_artifact(self, artifact: bytes) -> None:
        if not isinstance(artifact, bytes):
            raise TypeError("artifact must be bytes")
        if len(artifact) != self.size:
            raise ArtifactVerificationError("artifact size mismatch")
        actual = hashlib.sha256(artifact).hexdigest()
        if actual != self.sha256.lower():
            raise ArtifactVerificationError("artifact SHA-256 mismatch")


@dataclass(frozen=True, slots=True)
class SignedManifest:
    manifest: UpdateManifest
    signatures: Mapping[str, bytes]


@dataclass(frozen=True, slots=True)
class ManifestSigningIdentity:
    ed25519_private: Ed25519PrivateKey
    pqc: PQCIdentity | None = None

    @classmethod
    def generate(cls, *, enable_pqc: bool = False) -> ManifestSigningIdentity:
        pqc = OQSPQCProvider.generate_identity() if enable_pqc else None
        return cls(Ed25519PrivateKey.generate(), pqc)

    @property
    def ed25519_public_bytes(self) -> bytes:
        return self.ed25519_private.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def pqc_public_bytes(self) -> bytes | None:
        return self.pqc.public.signing_key if self.pqc else None

    def sign(self, manifest: UpdateManifest) -> SignedManifest:
        content = manifest.canonical_bytes()
        signatures = {"Ed25519": self.ed25519_private.sign(content)}
        if self.pqc is not None:
            signatures["ML-DSA-65"] = OQSPQCProvider.sign(
                self.pqc.signature_secret, content
            )
        return SignedManifest(manifest, signatures)


def verify_signed_manifest(
    signed: SignedManifest,
    ed25519_public_key: bytes | Ed25519PublicKey,
    *,
    pqc_public_key: bytes | None = None,
    require_pqc: bool = False,
) -> None:
    expected = {"Ed25519", *(["ML-DSA-65"] if require_pqc else [])}
    if not expected.issubset(signed.signatures):
        raise SignatureVerificationError("required manifest signature is missing")
    public_key = (
        Ed25519PublicKey.from_public_bytes(ed25519_public_key)
        if isinstance(ed25519_public_key, bytes)
        else ed25519_public_key
    )
    try:
        public_key.verify(
            signed.signatures["Ed25519"], signed.manifest.canonical_bytes()
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise SignatureVerificationError("Ed25519 verification failed") from exc
    if "ML-DSA-65" in signed.signatures:
        if pqc_public_key is None:
            if require_pqc:
                raise SignatureVerificationError("ML-DSA public key is missing")
        elif not OQSPQCProvider.verify(
            pqc_public_key,
            signed.manifest.canonical_bytes(),
            signed.signatures["ML-DSA-65"],
        ):
            raise SignatureVerificationError("ML-DSA-65 verification failed")


ArtifactManifest = UpdateManifest
SigningIdentity = ManifestSigningIdentity
