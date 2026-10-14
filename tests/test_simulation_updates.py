from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from adaptive_v2x_security.domain import (
    DataClass,
    GeoZone,
    Interface,
    LocationContext,
    ResourceState,
    ThreatAssessment,
)
from adaptive_v2x_security.policy import RiskEngine
from adaptive_v2x_security.simulation import (
    CentralMonitor,
    ChannelConfig,
    ScenarioEvent,
    ScenarioRunner,
    SimulatedECU,
    SimulatedV2XChannel,
)
from adaptive_v2x_security.updates import (
    ABUpdateManager,
    ArtifactVerificationError,
    BootComponent,
    ManifestError,
    ManifestSigningIdentity,
    RollbackProtectionError,
    SecureBootSimulator,
    SignatureVerificationError,
    SignedManifest,
    UpdateManifest,
    verify_signed_manifest,
)


class StaticScorer:
    def __init__(self, probability=0.1):
        self.probability = probability

    def predict(self, _record):
        return ThreatAssessment(self.probability, "0", "static")


@pytest.fixture
def ecus(policy_path):
    engine = RiskEngine.from_yaml(policy_path)
    monitor = CentralMonitor(summary_every=2)
    clock = lambda: 10_000
    return (
        SimulatedECU("sender", engine, StaticScorer(), central_monitor=monitor, clock_ms=clock),
        SimulatedECU("receiver", engine, StaticScorer(), clock_ms=clock),
        monitor,
    )


def _message(sender, receiver):
    return sender.make_message(
        receiver.ecu_id,
        "status",
        {"speed": 20},
        data_class=DataClass.PUBLIC,
        location=LocationContext(
            zone=GeoZone.TRUSTED_INTERNAL, interface=Interface.INTERNAL_BUS
        ),
        resource_state=ResourceState(),
    )


def test_simulation_accepts_valid_and_rejects_tamper_and_replay(ecus):
    sender, receiver, _ = ecus
    valid = sender.send(receiver, _message(sender, receiver), SimulatedV2XChannel())
    assert valid.sent and valid.deliveries[0].receiver_result.accepted

    tampered = sender.send(
        receiver,
        _message(sender, receiver),
        SimulatedV2XChannel(ChannelConfig(tamper_rate=1, seed=2)),
    )
    assert not tampered.deliveries[0].receiver_result.accepted

    replayed = sender.send(
        receiver,
        _message(sender, receiver),
        SimulatedV2XChannel(ChannelConfig(replay_rate=1, seed=2)),
    )
    assert replayed.deliveries[0].receiver_result.accepted
    assert not replayed.deliveries[1].receiver_result.accepted
    assert "ReplayError" in replayed.deliveries[1].receiver_result.error


def test_runner_continues_during_central_outage_and_reduces_workload(ecus):
    sender, receiver, monitor = ecus
    events = [
        ScenarioEvent(
            "status",
            {"n": i},
            data_class=DataClass.PUBLIC,
            location=LocationContext(
                zone=GeoZone.TRUSTED_INTERNAL, interface=Interface.INTERNAL_BUS
            ),
            resource_state=ResourceState(),
        )
        for i in range(6)
    ]
    result = ScenarioRunner(
        sender, receiver, SimulatedV2XChannel(), central_monitor=monitor
    ).run(events, central_outage=(1, 4))
    assert result.accepted == 6
    assert result.workload.baseline_messages == 6
    assert result.workload.unavailable_messages >= 1
    assert result.workload.adaptive_messages < result.workload.baseline_messages
    assert result.workload.message_reduction > 0


@pytest.fixture
def signing():
    return ManifestSigningIdentity.generate()


def _manifest(signing, artifact=b"firmware-v2", *, version="2.0", target="ecu", kind="firmware", expires=None):
    manifest = UpdateManifest.for_artifact(
        artifact,
        target=target,
        version=version,
        artifact_type=kind,
        expires_at=expires or datetime.now(UTC) + timedelta(hours=1),
    )
    return manifest, signing.sign(manifest), artifact


def test_manifest_signature_hash_target_expiry_and_rollback(signing):
    manifest, signed, artifact = _manifest(signing)
    verify_signed_manifest(signed, signing.ed25519_public_bytes)

    bad_sig = SignedManifest(manifest, {"Ed25519": b"\0" * 64})
    with pytest.raises(SignatureVerificationError):
        verify_signed_manifest(bad_sig, signing.ed25519_public_bytes)
    with pytest.raises(ArtifactVerificationError):
        manifest.verify_artifact(artifact + b"x")

    manager = ABUpdateManager(target="ecu", ed25519_public_key=signing.ed25519_public_bytes)
    wrong, wrong_signed, wrong_artifact = _manifest(signing, target="other")
    with pytest.raises(ManifestError, match="target"):
        manager.stage(wrong_signed, wrong_artifact)
    old, old_signed, old_artifact = _manifest(
        signing, version="3", expires=datetime.now(UTC) - timedelta(seconds=1)
    )
    with pytest.raises(ManifestError, match="expired"):
        manager.stage(old_signed, old_artifact)

    manager.seed_active(*_manifest(signing, b"v2", version="2")[:1], artifact=b"v2")
    lower, lower_signed, lower_artifact = _manifest(signing, b"v1", version="1")
    with pytest.raises(RollbackProtectionError):
        manager.stage(lower_signed, lower_artifact)


def test_ab_activation_success_and_health_rollback(signing):
    base, _, base_artifact = _manifest(signing, b"v1", version="1")
    manager = ABUpdateManager(target="ecu", ed25519_public_key=signing.ed25519_public_bytes)
    manager.seed_active(base, base_artifact)
    _, signed2, artifact2 = _manifest(signing, b"v2", version="2")
    success = manager.install(signed2, artifact2, health_check=lambda *_: True)
    assert success.activated and success.version == "2"

    _, signed3, artifact3 = _manifest(signing, b"v3", version="3")
    rolled_back = manager.install(signed3, artifact3, health_check=lambda *_: False)
    assert rolled_back.rolled_back and manager.active_image.manifest.version == "2"


def test_secure_boot_requires_all_components_and_validates_them(signing):
    firmware, fw_signed, fw = _manifest(signing, b"fw", version="2", kind="firmware")
    model, model_signed, model_bytes = _manifest(signing, b"model", version="4", kind="model")
    boot = SecureBootSimulator(
        target="ecu",
        ed25519_public_key=signing.ed25519_public_bytes,
        minimum_versions={"firmware": "2", "model": "3"},
    )
    missing = boot.verify([BootComponent(fw_signed, fw)])
    assert not missing.allowed and any("model: required" in error for error in missing.errors)
    valid = boot.verify(
        [BootComponent(fw_signed, fw), BootComponent(model_signed, model_bytes)]
    )
    assert valid.allowed
    assert set(valid.verified_components) == {"firmware", "model"}

    stale, stale_signed, stale_bytes = _manifest(signing, b"old", version="1", kind="model")
    rejected = boot.verify(
        [BootComponent(fw_signed, fw), BootComponent(stale_signed, stale_bytes)]
    )
    assert not rejected.allowed
    assert any("RollbackProtectionError" in error for error in rejected.errors)
