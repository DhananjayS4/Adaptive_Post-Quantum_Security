from __future__ import annotations

import time

from fastapi.testclient import TestClient

from adaptive_v2x_security.api.app import create_app
from adaptive_v2x_security.api import jobs as jobs_module


def test_health_status_and_results_are_available(tmp_path) -> None:
    with TestClient(create_app(job_directory=tmp_path)) as client:
        assert client.get("/api/v1/health").status_code == 200
        status = client.get("/api/v1/status")
        assert status.status_code == 200
        assert "assurance" in status.json()

        results = client.get("/api/v1/results")
        assert results.status_code == 200
        serialized = results.text
        assert "D:\\\\Freelancing" not in serialized


def test_policy_and_secure_round_trip_contracts(tmp_path) -> None:
    with TestClient(create_app(job_directory=tmp_path)) as client:
        policy = client.post(
            "/api/v1/policy/evaluate",
            json={
                "threat_probability": 0.8,
                "data_class": "safety_critical",
                "zone": "restricted",
                "interface": "v2x",
                "assurance": "simulated_trusted",
                "cpu_percent": 40,
                "memory_percent": 50,
                "latency_ms": 10,
                "traffic_density": 0.4,
            },
        )
        assert policy.status_code == 200
        assert policy.json()["security_floor"] == 3

        secure = client.post(
            "/api/v1/security/round-trip",
            json={
                "payload": {"signal": "brake", "value": True},
                "aead": "AES-256-GCM",
                "pqc_mode": "classical_only",
                "ttl_ms": 5000,
            },
        )
        assert secure.status_code == 200
        assert secure.json()["verified"] is True
        assert "envelope" not in secure.json()


def test_jobs_are_single_flight_and_persist_results(tmp_path, monkeypatch) -> None:
    def bounded_job(kind: str, **options: object) -> dict[str, object]:
        time.sleep(0.05)
        return {"kind": kind, "options": options, "source": r"D:\private\data.csv"}

    monkeypatch.setattr(jobs_module, "run_experiment", bounded_job)
    with TestClient(create_app(job_directory=tmp_path)) as client:
        first = client.post("/api/v1/jobs", json={"kind": "demo", "options": {}})
        assert first.status_code == 202
        second = client.post("/api/v1/jobs", json={"kind": "demo", "options": {}})
        assert second.status_code == 409

        job_id = first.json()["id"]
        for _ in range(50):
            record = client.get(f"/api/v1/jobs/{job_id}").json()
            if record["status"] == "succeeded":
                break
            time.sleep(0.01)
        assert record["status"] == "succeeded"
        result = client.get(f"/api/v1/jobs/{job_id}/result").json()
        assert result["result"]["source"] == "configured locally"
