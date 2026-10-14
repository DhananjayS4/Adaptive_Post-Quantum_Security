from __future__ import annotations

import ctypes.util
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import PQCUnavailableError


def _native_oqs_present() -> bool:
    if ctypes.util.find_library("oqs"):
        return True
    roots = [
        Path(os.environ.get("OQS_INSTALL_PATH", Path.home() / "_oqs")),
        *(Path(item) for item in os.environ.get("PATH", "").split(os.pathsep) if item),
    ]
    library_names = ("oqs.dll", "liboqs.dll", "liboqs.so", "liboqs.dylib")
    return any(
        (root / directory / name).is_file()
        for root in roots
        for directory in ("", "bin", "lib", "lib64")
        for name in library_names
    )


if not _native_oqs_present():
    _oqs = None
    _OQS_IMPORT_ERROR = "liboqs native library was not found"
else:
    try:
        import oqs as _oqs
    except (ImportError, OSError, RuntimeError, SystemExit) as _oqs_error:
        _oqs = None
        _OQS_IMPORT_ERROR = str(_oqs_error)
    else:
        _OQS_IMPORT_ERROR = None


ML_KEM_ALGORITHM = "ML-KEM-768"
ML_DSA_ALGORITHM = "ML-DSA-65"


@dataclass(frozen=True, slots=True)
class ProviderAvailability:
    available: bool
    kem_algorithm: str
    signature_algorithm: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ClassicalPublicIdentity:
    exchange_key: bytes
    signing_key: bytes


@dataclass(frozen=True, slots=True)
class ClassicalIdentity:
    exchange_private: X25519PrivateKey
    signing_private: Ed25519PrivateKey

    @property
    def public(self) -> ClassicalPublicIdentity:
        return ClassicalPublicIdentity(
            exchange_key=self.exchange_private.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
            signing_key=self.signing_private.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
        )


@dataclass(frozen=True, slots=True)
class PQCPublicIdentity:
    kem_key: bytes
    signing_key: bytes


@dataclass(frozen=True, slots=True)
class PQCIdentity:
    kem_secret: bytes
    signature_secret: bytes
    public: PQCPublicIdentity


class ClassicalProvider:
    """X25519 key agreement and Ed25519 signatures."""

    exchange_algorithm = "X25519"
    signature_algorithm = "Ed25519"

    @staticmethod
    def generate_identity() -> ClassicalIdentity:
        return ClassicalIdentity(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @staticmethod
    def exchange(identity: ClassicalIdentity, peer_exchange_key: bytes) -> bytes:
        if len(peer_exchange_key) != 32:
            raise ValueError("Invalid X25519 public key")
        return identity.exchange_private.exchange(
            X25519PublicKey.from_public_bytes(peer_exchange_key)
        )

    @staticmethod
    def sign(identity: ClassicalIdentity, message: bytes) -> bytes:
        return identity.signing_private.sign(message)

    @staticmethod
    def verify(signing_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(signing_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


def _enabled(kind: str) -> set[str]:
    if _oqs is None:
        return set()
    getter = getattr(_oqs, f"get_enabled_{kind}_mechanisms", None)
    if getter is None:
        return set()
    try:
        return set(getter())
    except Exception:
        return set()


def _dispose(instance: Any) -> None:
    close = getattr(instance, "free", None) or getattr(instance, "close", None)
    if close is not None:
        close()


class OQSPQCProvider:
    """Optional real liboqs provider; it never substitutes synthetic primitives."""

    kem_algorithm = ML_KEM_ALGORITHM
    signature_algorithm = ML_DSA_ALGORITHM

    @classmethod
    def availability(cls) -> ProviderAvailability:
        if _oqs is None:
            return ProviderAvailability(
                False, cls.kem_algorithm, cls.signature_algorithm, _OQS_IMPORT_ERROR
            )
        kems = _enabled("kem")
        signatures = _enabled("sig")
        missing = [
            algorithm
            for algorithm, enabled in (
                (cls.kem_algorithm, kems),
                (cls.signature_algorithm, signatures),
            )
            if algorithm not in enabled
        ]
        if missing:
            return ProviderAvailability(
                False,
                cls.kem_algorithm,
                cls.signature_algorithm,
                f"liboqs does not enable: {', '.join(missing)}",
            )
        return ProviderAvailability(True, cls.kem_algorithm, cls.signature_algorithm)

    @classmethod
    def is_available(cls) -> bool:
        return cls.availability().available

    @classmethod
    def require_available(cls) -> None:
        status = cls.availability()
        if not status.available:
            raise PQCUnavailableError(status.reason or "PQC provider unavailable")

    @classmethod
    def generate_identity(cls) -> PQCIdentity:
        cls.require_available()
        kem = _oqs.KeyEncapsulation(cls.kem_algorithm)
        signature = _oqs.Signature(cls.signature_algorithm)
        try:
            kem_public = bytes(kem.generate_keypair())
            kem_secret = bytes(kem.export_secret_key())
            signature_public = bytes(signature.generate_keypair())
            signature_secret = bytes(signature.export_secret_key())
        finally:
            _dispose(kem)
            _dispose(signature)
        return PQCIdentity(
            kem_secret=kem_secret,
            signature_secret=signature_secret,
            public=PQCPublicIdentity(kem_public, signature_public),
        )

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        cls.require_available()
        kem = _oqs.KeyEncapsulation(cls.kem_algorithm)
        try:
            ciphertext, secret = kem.encap_secret(public_key)
            return bytes(ciphertext), bytes(secret)
        finally:
            _dispose(kem)

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        cls.require_available()
        kem = _oqs.KeyEncapsulation(cls.kem_algorithm, secret_key=secret_key)
        try:
            return bytes(kem.decap_secret(ciphertext))
        finally:
            _dispose(kem)

    @classmethod
    def sign(cls, secret_key: bytes, message: bytes) -> bytes:
        cls.require_available()
        signature = _oqs.Signature(cls.signature_algorithm, secret_key=secret_key)
        try:
            return bytes(signature.sign(message))
        finally:
            _dispose(signature)

    @classmethod
    def verify(
        cls, public_key: bytes, message: bytes, signature_value: bytes
    ) -> bool:
        cls.require_available()
        signature = _oqs.Signature(cls.signature_algorithm)
        try:
            return bool(signature.verify(message, signature_value, public_key))
        except Exception:
            return False
        finally:
            _dispose(signature)
