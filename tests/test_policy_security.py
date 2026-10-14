from __future__ import annotations

import pytest

from adaptive_v2x_security.domain import (
    DataClass,
    EdgeAction,
    GeoZone,
    Interface,
    LocationContext,
    PQCMode,
    ResourceState,
)
from adaptive_v2x_security.policy import RiskEngine
from adaptive_v2x_security.security import (
    EnvelopeError,
    OQSPQCProvider,
    PQCUnavailableError,
    ReplayError,
    SecureEnvelope,
    SecurityIdentity,
    canonical_cbor,
    establish_sessions,
)


@pytest.fixture
def engine(policy_path):
    return RiskEngine.from_yaml(policy_path)


def test_policy_data_and_interface_floors(engine):
    resources = ResourceState()
    data_floor = engine.decide(
        0, DataClass.SAFETY_CRITICAL, GeoZone.TRUSTED_INTERNAL, resources,
        interface=Interface.INTERNAL_BUS,
    )
    interface_floor = engine.decide(
        0, DataClass.PUBLIC, GeoZone.TRUSTED_INTERNAL, resources,
        interface=Interface.OTA,
    )
    assert data_floor.security_floor == 3
    assert data_floor.profile_id == "restricted"
    assert "floor.data" in data_floor.reasons
    assert interface_floor.security_floor == 3
    assert "floor.interface" in interface_floor.reasons


def test_unknowns_are_conservative_and_location_changes_risk(engine):
    unknown = engine.decide(None, "mystery", "nowhere", None)
    trusted = engine.decide(
        0.1, DataClass.PUBLIC, GeoZone.TRUSTED_INTERNAL, ResourceState(),
        interface=Interface.INTERNAL_BUS,
    )
    restricted = engine.decide(
        0.1, DataClass.PUBLIC, GeoZone.RESTRICTED, ResourceState(),
        interface=Interface.INTERNAL_BUS,
    )
    assert unknown.risk_score > trusted.risk_score
    assert {"unknown.threat", "unknown.data_class", "unknown.location", "unknown.resources"} <= set(unknown.reasons)
    assert restricted.risk_score > trusted.risk_score


def test_high_threat_is_quarantined(engine):
    decision = engine.decide(
        0.99, DataClass.PUBLIC,
        LocationContext(zone=GeoZone.PUBLIC_ROAD, interface=Interface.V2X),
        ResourceState(),
    )
    assert decision.action is EdgeAction.QUARANTINE
    assert "action.quarantine" in decision.reasons


@pytest.fixture
def classical_pair():
    alice = SecurityIdentity.generate("alice")
    bob = SecurityIdentity.generate("bob")
    return establish_sessions(alice, bob, max_ttl_ms=1_000, clock_skew_ms=0)


def _mutate_envelope(encoded: bytes, *, header=None, ciphertext=False, signatures=False):
    env = SecureEnvelope.decode(encoded)
    headers = dict(env.headers)
    if header:
        key, value = header
        headers[key] = value
    body = env.ciphertext
    if ciphertext:
        body = bytes([body[0] ^ 1]) + body[1:]
    sigs = dict(env.signatures)
    if signatures:
        sigs["Ed25519"] = bytes([sigs["Ed25519"][0] ^ 1]) + sigs["Ed25519"][1:]
    return canonical_cbor({"headers": headers, "ciphertext": body, "signatures": sigs})


def test_classical_round_trip_tamper_replay_and_expiry(classical_pair):
    sent = classical_pair.initiator.protect(b"hello", timestamp_ms=1_000, ttl_ms=100)
    assert classical_pair.responder.open(sent, now_ms=1_050) == b"hello"
    with pytest.raises(ReplayError):
        classical_pair.responder.open(sent, now_ms=1_050)

    tampered = classical_pair.initiator.protect(b"secret", timestamp_ms=2_000, ttl_ms=100)
    with pytest.raises(EnvelopeError):
        classical_pair.responder.open(_mutate_envelope(tampered, ciphertext=True), now_ms=2_050)
    expired = classical_pair.initiator.protect(b"late", timestamp_ms=3_000, ttl_ms=10)
    with pytest.raises(ReplayError, match="expired"):
        classical_pair.responder.open(expired, now_ms=3_011)


@pytest.mark.parametrize(
    "header",
    [
        ("pqc_mode", PQCMode.PQC_PREFERRED.value),
        ("aead", "ChaCha20-Poly1305"),
        ("profile_id", "weaker"),
    ],
)
def test_header_and_downgrade_mutations_are_rejected(classical_pair, header):
    sent = classical_pair.initiator.protect(b"x", timestamp_ms=5_000, ttl_ms=100)
    with pytest.raises(EnvelopeError, match="downgrade|context"):
        classical_pair.responder.open(_mutate_envelope(sent, header=header), now_ms=5_001)


def test_signature_tamper_is_rejected(classical_pair):
    sent = classical_pair.initiator.protect(b"x", timestamp_ms=5_000, ttl_ms=100)
    with pytest.raises(EnvelopeError, match="signature"):
        classical_pair.responder.open(_mutate_envelope(sent, signatures=True), now_ms=5_001)


def test_pqc_preferred_is_active_or_audited_fallback():
    alice = SecurityIdentity.generate("alice", PQCMode.PQC_PREFERRED)
    bob = SecurityIdentity.generate("bob", PQCMode.PQC_PREFERRED)
    pair = establish_sessions(alice, bob, pqc_mode=PQCMode.PQC_PREFERRED)
    if OQSPQCProvider.is_available():
        assert pair.initiator.pqc_status == "active"
    else:
        assert pair.initiator.pqc_status == "fallback"
        assert [event.code for event in pair.audit_log] == ["pqc.preferred_fallback"]


def test_pqc_required_fails_closed_when_unavailable():
    if OQSPQCProvider.is_available():
        pytest.skip("Real PQC is available; fail-closed unavailable path is not applicable")
    with pytest.raises(PQCUnavailableError):
        SecurityIdentity.generate("required", PQCMode.PQC_REQUIRED)
    alice = SecurityIdentity.generate("alice")
    bob = SecurityIdentity.generate("bob")
    with pytest.raises(PQCUnavailableError):
        establish_sessions(alice, bob, pqc_mode=PQCMode.PQC_REQUIRED)
