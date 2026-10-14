"""Signed OTA update and software-only secure-boot simulations."""

from .manager import (
    SIMULATION_NOTICE,
    ABUpdateManager,
    ActivationResult,
    SlotImage,
    UpdateManager,
)
from .manifest import (
    ArtifactManifest,
    ArtifactVerificationError,
    ManifestError,
    ManifestSigningIdentity,
    RollbackProtectionError,
    SignatureVerificationError,
    SignedManifest,
    SigningIdentity,
    UpdateManifest,
    compare_versions,
    verify_signed_manifest,
)
from .secure_boot import (
    SECURE_BOOT_SIMULATION_NOTICE,
    BootComponent,
    BootVerification,
    SecureBootSimulator,
    SimulatedSecureBoot,
)

__all__ = [
    "ABUpdateManager",
    "ActivationResult",
    "ArtifactManifest",
    "ArtifactVerificationError",
    "BootComponent",
    "BootVerification",
    "ManifestError",
    "ManifestSigningIdentity",
    "RollbackProtectionError",
    "SECURE_BOOT_SIMULATION_NOTICE",
    "SIMULATION_NOTICE",
    "SecureBootSimulator",
    "SignatureVerificationError",
    "SignedManifest",
    "SigningIdentity",
    "SimulatedSecureBoot",
    "SlotImage",
    "UpdateManager",
    "UpdateManifest",
    "compare_versions",
    "verify_signed_manifest",
]
