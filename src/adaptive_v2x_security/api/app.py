"""FastAPI application for the adaptive V2X monitoring console."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from adaptive_v2x_security import __version__
from adaptive_v2x_security.api.jobs import JobConflictError, JobManager
from adaptive_v2x_security.api.schemas import (
    JobRequest,
    PolicyRequest,
    SecureRoundTripRequest,
)
from adaptive_v2x_security.config import PROJECT_ROOT
from adaptive_v2x_security.ui import services


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe(operation: Any) -> Any:
    value, error = services.safe_call(operation)
    if error is not None:
        raise HTTPException(status_code=422, detail=error)
    return services.redact_private_fields(value)


def _system_status() -> dict[str, Any]:
    results = services.load_results()
    train = results["train"]
    demo = results["demo"]
    benchmark = results["benchmark"]
    ota = results["ota"]
    return services.redact_private_fields(
        {
            "generated_at": _utc_now(),
            "model": {
                "available": bool(train),
                "version": train.get("model_version"),
                "dataset": train.get("dataset"),
                "task": train.get("task"),
                "calibrated": train.get("calibrated"),
            },
            "edge": {
                "records_replayed": demo.get("records_replayed", 0),
                "accepted_deliveries": demo.get("accepted_deliveries", 0),
                "fail_closed": demo.get("fail_closed", {}).get("count", 0),
                "central_workload": benchmark.get("central_workload")
                or demo.get("adaptive_vs_send_all"),
            },
            "assurance": {
                "secure_boot_allowed": ota.get("secure_boot", {}).get("allowed"),
                "active_slot": ota.get("ab_update", {}).get(
                    "active_slot_after_scenarios"
                ),
                "pqc": services.pqc_availability(),
            },
            "result_availability": {
                name: bool(payload) for name, payload in results.items()
            },
        }
    )


def create_app(*, job_directory: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="Adaptive V2X Security API",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.jobs = JobManager(job_directory)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/api/v1/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "timestamp": _utc_now()}

    @app.get("/api/v1/status")
    def system_status() -> dict[str, Any]:
        return _system_status()

    @app.get("/api/v1/results")
    def results() -> dict[str, Any]:
        return services.redact_private_fields(services.load_results())

    @app.get("/api/v1/results/{name}")
    def result(name: str) -> dict[str, Any]:
        all_results = services.load_results()
        if name not in all_results:
            raise HTTPException(status_code=404, detail="Result not found")
        return services.redact_private_fields(all_results[name])

    @app.get("/api/v1/artifacts")
    def artifacts() -> list[dict[str, Any]]:
        return services.redact_private_fields(services.discover_artifacts())

    @app.post("/api/v1/policy/evaluate")
    def policy_evaluate(request: PolicyRequest) -> dict[str, Any]:
        return _safe(lambda: services.evaluate_policy(**request.model_dump()))

    @app.post("/api/v1/security/round-trip")
    def security_round_trip(
        request: SecureRoundTripRequest,
    ) -> dict[str, Any]:
        return _safe(lambda: services.secure_round_trip(**request.model_dump()))

    @app.post("/api/v1/jobs", status_code=status.HTTP_202_ACCEPTED)
    def submit_job(request: JobRequest) -> dict[str, Any]:
        try:
            return app.state.jobs.submit(request.kind, request.options)
        except JobConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/v1/jobs")
    def jobs() -> list[dict[str, Any]]:
        return app.state.jobs.list()

    @app.get("/api/v1/jobs/{job_id}")
    def job(job_id: str) -> dict[str, Any]:
        record = app.state.jobs.get(job_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return app.state.jobs._summary(record)

    @app.get("/api/v1/jobs/{job_id}/result")
    def job_result(job_id: str) -> dict[str, Any]:
        result_payload = app.state.jobs.result(job_id)
        if result_payload is None:
            raise HTTPException(status_code=404, detail="Job not found")
        return result_payload

    dist = PROJECT_ROOT / "frontend" / "dist"
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{spa_path:path}", include_in_schema=False)
    def spa(spa_path: str, request: Request) -> Any:
        del request
        if spa_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API route not found")
        candidate = (dist / spa_path).resolve()
        if dist.is_dir() and candidate.is_relative_to(dist.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        index = dist / "index.html"
        if index.is_file():
            return FileResponse(index)
        return {
            "service": "Adaptive V2X Security API",
            "console": "Frontend build not found. Run npm run build in frontend.",
            "docs": "/api/docs",
        }

    return app


app = create_app()
