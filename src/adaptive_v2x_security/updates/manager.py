"""A/B update staging and activation simulation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import inspect
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .manifest import (
    ManifestError,
    RollbackProtectionError,
    SignedManifest,
    UpdateManifest,
    compare_versions,
    verify_signed_manifest,
)


SIMULATION_NOTICE = (
    "SIMULATED: A/B slots, activation, rollback, and boot state are software "
    "models and provide no hardware security guarantee."
)


@dataclass(frozen=True, slots=True)
class SlotImage:
    slot: str
    manifest: UpdateManifest
    artifact: bytes


@dataclass(frozen=True, slots=True)
class ActivationResult:
    activated: bool
    rolled_back: bool
    active_slot: str
    version: str | None
    reason: str | None = None
    simulation_notice: str = SIMULATION_NOTICE


class ABUpdateManager:
    """Verifies, stages, and activates artifacts in simulated A/B slots."""

    def __init__(
        self,
        *,
        target: str,
        ed25519_public_key: bytes | Ed25519PublicKey,
        pqc_public_key: bytes | None = None,
        require_pqc: bool = False,
        active_slot: str = "A",
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if active_slot not in {"A", "B"}:
            raise ValueError("active_slot must be A or B")
        self.target = target
        self.ed25519_public_key = ed25519_public_key
        self.pqc_public_key = pqc_public_key
        self.require_pqc = require_pqc
        self.active_slot = active_slot
        self.now = now or (lambda: datetime.now(UTC))
        self.slots: dict[str, SlotImage | None] = {"A": None, "B": None}
        self.accepted_versions: dict[str, str] = {}
        self.audit_log: list[str] = [SIMULATION_NOTICE]

    @property
    def inactive_slot(self) -> str:
        return "B" if self.active_slot == "A" else "A"

    @property
    def active_image(self) -> SlotImage | None:
        return self.slots[self.active_slot]

    def seed_active(
        self, manifest: UpdateManifest, artifact: bytes, *, slot: str | None = None
    ) -> None:
        """Seed a simulated factory image after local hash verification."""

        selected = slot or self.active_slot
        if selected not in self.slots:
            raise ValueError("slot must be A or B")
        if manifest.target != self.target:
            raise ManifestError("factory image target mismatch")
        manifest.verify_artifact(artifact)
        self.slots[selected] = SlotImage(selected, manifest, artifact)
        self.active_slot = selected
        self.accepted_versions[manifest.artifact_type] = manifest.version

    def validate(
        self,
        signed: SignedManifest,
        artifact: bytes,
        *,
        allow_same_version: bool = False,
    ) -> None:
        verify_signed_manifest(
            signed,
            self.ed25519_public_key,
            pqc_public_key=self.pqc_public_key,
            require_pqc=self.require_pqc,
        )
        manifest = signed.manifest
        if manifest.target != self.target:
            raise ManifestError(
                f"manifest target {manifest.target!r} does not match {self.target!r}"
            )
        if manifest.is_expired(self.now()):
            raise ManifestError("manifest has expired")
        manifest.verify_artifact(artifact)
        current = self.accepted_versions.get(manifest.artifact_type)
        if current is not None:
            comparison = compare_versions(manifest.version, current)
            if comparison < 0 or (comparison == 0 and not allow_same_version):
                raise RollbackProtectionError(
                    f"version {manifest.version} is not newer than {current}"
                )

    def stage(self, signed: SignedManifest, artifact: bytes) -> SlotImage:
        self.validate(signed, artifact)
        slot = self.inactive_slot
        image = SlotImage(slot, signed.manifest, bytes(artifact))
        self.slots[slot] = image
        self.audit_log.append(
            f"staged {image.manifest.artifact_type} {image.manifest.version} in {slot}"
        )
        return image

    def activate(
        self,
        health_check: Callable[..., bool] | None = None,
    ) -> ActivationResult:
        candidate_slot = self.inactive_slot
        candidate = self.slots[candidate_slot]
        if candidate is None:
            raise ManifestError("inactive slot has no staged image")
        previous_slot = self.active_slot
        self.active_slot = candidate_slot
        healthy = True
        reason: str | None = None
        if health_check is not None:
            try:
                parameters = inspect.signature(health_check).parameters
                healthy = bool(
                    health_check()
                    if not parameters
                    else health_check(candidate.manifest, candidate.artifact)
                )
            except Exception as exc:
                healthy = False
                reason = f"health check raised {type(exc).__name__}: {exc}"
        if not healthy:
            self.active_slot = previous_slot
            reason = reason or "post-activation health check failed"
            self.audit_log.append(
                f"rolled back {candidate.manifest.version}: {reason}"
            )
            active = self.active_image
            return ActivationResult(
                False,
                True,
                self.active_slot,
                active.manifest.version if active else None,
                reason,
            )

        self.accepted_versions[
            candidate.manifest.artifact_type
        ] = candidate.manifest.version
        self.audit_log.append(
            f"activated {candidate.manifest.artifact_type} "
            f"{candidate.manifest.version} from {candidate_slot}"
        )
        return ActivationResult(
            True, False, self.active_slot, candidate.manifest.version
        )

    def install(
        self,
        signed: SignedManifest,
        artifact: bytes,
        *,
        health_check: Callable[..., bool] | None = None,
    ) -> ActivationResult:
        self.stage(signed, artifact)
        return self.activate(health_check)


UpdateManager = ABUpdateManager
