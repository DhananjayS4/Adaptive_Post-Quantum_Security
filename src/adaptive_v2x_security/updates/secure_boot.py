"""Software-only secure-boot verification simulation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Iterable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .manifest import (
    ManifestError,
    RollbackProtectionError,
    SignedManifest,
    compare_versions,
    verify_signed_manifest,
)


SECURE_BOOT_SIMULATION_NOTICE = (
    "SIMULATED: manifest verification models a secure-boot decision, but keys "
    "and measurements are not anchored in TPM, HSM, ROM, or other hardware."
)


@dataclass(frozen=True, slots=True)
class BootComponent:
    signed_manifest: SignedManifest
    artifact: bytes


@dataclass(frozen=True, slots=True)
class BootVerification:
    allowed: bool
    verified_components: tuple[str, ...]
    errors: tuple[str, ...]
    simulation_notice: str = SECURE_BOOT_SIMULATION_NOTICE


class SecureBootSimulator:
    """Verify signed firmware/model manifests before a simulated boot."""

    def __init__(
        self,
        *,
        target: str,
        ed25519_public_key: bytes | Ed25519PublicKey,
        pqc_public_key: bytes | None = None,
        require_pqc: bool = False,
        minimum_versions: Mapping[str, str] | None = None,
        required_types: Iterable[str] = ("firmware", "model"),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.target = target
        self.ed25519_public_key = ed25519_public_key
        self.pqc_public_key = pqc_public_key
        self.require_pqc = require_pqc
        self.minimum_versions = dict(minimum_versions or {})
        self.required_types = frozenset(required_types)
        self.now = now or (lambda: datetime.now(UTC))

    def verify(self, components: Iterable[BootComponent]) -> BootVerification:
        verified: list[str] = []
        errors: list[str] = []
        seen: set[str] = set()
        for component in components:
            manifest = component.signed_manifest.manifest
            label = manifest.artifact_type
            try:
                if label in seen:
                    raise ManifestError(f"duplicate {label} manifest")
                seen.add(label)
                verify_signed_manifest(
                    component.signed_manifest,
                    self.ed25519_public_key,
                    pqc_public_key=self.pqc_public_key,
                    require_pqc=self.require_pqc,
                )
                if manifest.target != self.target:
                    raise ManifestError("target mismatch")
                if manifest.is_expired(self.now()):
                    raise ManifestError("manifest expired")
                manifest.verify_artifact(component.artifact)
                minimum = self.minimum_versions.get(label)
                if minimum is not None and compare_versions(
                    manifest.version, minimum
                ) < 0:
                    raise RollbackProtectionError(
                        f"{label} {manifest.version} is older than {minimum}"
                    )
                verified.append(label)
            except Exception as exc:
                errors.append(f"{label}: {type(exc).__name__}: {exc}")
        missing = sorted(self.required_types - seen)
        errors.extend(f"{label}: required manifest missing" for label in missing)
        return BootVerification(not errors, tuple(verified), tuple(errors))

    verify_boot = verify


SimulatedSecureBoot = SecureBootSimulator
