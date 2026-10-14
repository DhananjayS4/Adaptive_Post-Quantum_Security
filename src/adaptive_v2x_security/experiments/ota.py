from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from io import BytesIO
from pathlib import Path
from typing import Any
import zipfile

from adaptive_v2x_security.security import OQSPQCProvider
from adaptive_v2x_security.updates import (
    ABUpdateManager,
    BootComponent,
    ManifestSigningIdentity,
    SecureBootSimulator,
    UpdateManifest,
)

from .common import write_json


def _model_image(artifact_dir: str | Path | None) -> tuple[bytes, str]:
    if artifact_dir is None:
        return b"SIMULATED-MODEL-IMAGE-v2", "generated_demo_image"
    directory = Path(artifact_dir)
    if not directory.is_dir():
        return b"SIMULATED-MODEL-IMAGE-v2", "generated_demo_image"
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted(path for path in directory.rglob("*") if path.is_file()):
            info = zipfile.ZipInfo(source.relative_to(directory).as_posix())
            info.date_time = (1980, 1, 1, 0, 0, 0)
            archive.writestr(info, source.read_bytes())
    return buffer.getvalue(), str(directory.resolve())


def _manifest_summary(signed: Any) -> dict[str, Any]:
    return {
        "manifest": signed.manifest.as_dict(),
        "signature_algorithms": sorted(signed.signatures),
        "signature_sha256": {
            algorithm: hashlib.sha256(value).hexdigest()
            for algorithm, value in signed.signatures.items()
        },
    }


def run_ota_demo(
    *,
    artifact_dir: str | Path | None,
    target: str,
    output: str | Path,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    expires = now + timedelta(days=1)
    pqc = OQSPQCProvider.availability()
    signer = ManifestSigningIdentity.generate(enable_pqc=pqc.available)
    firmware_v1 = b"SIMULATED-FIRMWARE-IMAGE-v1"
    firmware_v2 = b"SIMULATED-FIRMWARE-IMAGE-v2"
    firmware_v3 = b"SIMULATED-FIRMWARE-IMAGE-v3-unhealthy"
    model_v2, model_source = _model_image(artifact_dir)

    factory_manifest = UpdateManifest.for_artifact(
        firmware_v1,
        target=target,
        version="1.0.0",
        expires_at=expires,
        artifact_type="firmware",
    )
    firmware_manifest = UpdateManifest.for_artifact(
        firmware_v2,
        target=target,
        version="2.0.0",
        expires_at=expires,
        artifact_type="firmware",
        metadata={"slot_strategy": "A/B", "simulation": True},
    )
    rollback_manifest = UpdateManifest.for_artifact(
        firmware_v3,
        target=target,
        version="3.0.0",
        expires_at=expires,
        artifact_type="firmware",
        metadata={"expected_health": "fail", "simulation": True},
    )
    model_manifest = UpdateManifest.for_artifact(
        model_v2,
        target=target,
        version="2.0.0",
        expires_at=expires,
        artifact_type="model",
        metadata={"source": model_source},
    )
    signed_firmware = signer.sign(firmware_manifest)
    signed_rollback = signer.sign(rollback_manifest)
    signed_model = signer.sign(model_manifest)

    secure_boot = SecureBootSimulator(
        target=target,
        ed25519_public_key=signer.ed25519_public_bytes,
        pqc_public_key=signer.pqc_public_bytes,
        require_pqc=pqc.available,
        minimum_versions={"firmware": "2.0.0", "model": "2.0.0"},
        now=lambda: now,
    ).verify(
        (
            BootComponent(signed_firmware, firmware_v2),
            BootComponent(signed_model, model_v2),
        )
    )

    manager = ABUpdateManager(
        target=target,
        ed25519_public_key=signer.ed25519_public_bytes,
        pqc_public_key=signer.pqc_public_bytes,
        require_pqc=pqc.available,
        now=lambda: now,
    )
    manager.seed_active(factory_manifest, firmware_v1)
    successful_update = manager.install(
        signed_firmware, firmware_v2, health_check=lambda *_: True
    )
    manager.stage(signed_rollback, firmware_v3)
    rollback = manager.activate(health_check=lambda *_: False)

    result = {
        "command": "ota-demo",
        "target": target,
        "manifests": {
            "firmware": _manifest_summary(signed_firmware),
            "model": _manifest_summary(signed_model),
            "rollback_candidate": _manifest_summary(signed_rollback),
        },
        "secure_boot": secure_boot,
        "ab_update": {
            "successful_update": successful_update,
            "rollback_scenario": rollback,
            "active_slot_after_scenarios": manager.active_slot,
            "audit_log": manager.audit_log,
        },
        "pqc": {
            "available": pqc.available,
            "kem_algorithm": pqc.kem_algorithm,
            "signature_algorithm": pqc.signature_algorithm,
            "reason": pqc.reason,
            "manifest_pqc_signatures_used": pqc.available,
            "synthetic_pqc_used": False,
        },
        "simulation_scope": {
            "firmware_images": "generated demo bytes",
            "model_image_source": model_source,
            "hardware_root_of_trust": False,
        },
    }
    write_json(output, result)
    return result
