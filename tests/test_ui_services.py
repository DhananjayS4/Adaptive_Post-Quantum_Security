from __future__ import annotations

from adaptive_v2x_security.security import AES_256_GCM
from adaptive_v2x_security.ui import services


def test_policy_lab_uses_real_policy_engine() -> None:
    decision = services.evaluate_policy(
        threat_probability=0.8,
        data_class="safety_critical",
        zone="restricted",
        interface="v2x",
        assurance="simulated_trusted",
        cpu_percent=40,
        memory_percent=50,
        latency_ms=10,
        traffic_density=0.4,
    )

    assert decision["profile_id"] == "restricted"
    assert decision["security_floor"] == 3
    assert decision["pqc_mode"] == "pqc_required"


def test_secure_ui_round_trip_uses_authenticated_session() -> None:
    result = services.secure_round_trip(
        payload={"signal": "brake", "value": True},
        aead=AES_256_GCM,
        pqc_mode="classical_only",
        ttl_ms=5_000,
    )

    assert result["verified"] is True
    assert result["envelope_bytes"] > result["plaintext_bytes"]
    assert result["pqc_status"] == "disabled"


def test_missing_or_invalid_results_are_safe(tmp_path) -> None:
    assert services.load_json(tmp_path / "missing.json") == {}
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json", encoding="utf-8")
    assert services.load_json(invalid) == {}


def test_ui_errors_redact_local_paths() -> None:
    _, error = services.safe_call(
        lambda: (_ for _ in ()).throw(
            ValueError(r"failed at D:\Freelancing\adaptive_v2x_security\secret")
        )
    )

    assert error is not None
    assert "D:\\Freelancing" not in error
    assert "<project>" in error or "<local path>" in error
