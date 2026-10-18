"""Single-flight background execution with durable, redacted job records."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from adaptive_v2x_security.config import PROJECT_ROOT
from adaptive_v2x_security.ui.services import (
    redact_private_fields,
    run_experiment,
    run_ota,
    safe_call,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class JobConflictError(RuntimeError):
    """Raised when a long-running operation is already active."""


class JobManager:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or PROJECT_ROOT / "results" / "jobs"
        self.directory.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._active_job_id: str | None = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="v2x-job")
        self._recover_interrupted_jobs()

    def _path(self, job_id: str) -> Path:
        return self.directory / f"{job_id}.json"

    def _write(self, record: dict[str, Any]) -> None:
        path = self._path(record["id"])
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(redact_private_fields(record), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(path)

    def _read(self, path: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _recover_interrupted_jobs(self) -> None:
        for path in self.directory.glob("*.json"):
            record = self._read(path)
            if record and record.get("status") in {"queued", "running"}:
                record.update(
                    status="failed",
                    completed_at=_now(),
                    error="ProcessInterrupted: operation did not complete",
                )
                self._write(record)

    def submit(self, kind: str, options: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self._active_job_id is not None:
                raise JobConflictError(
                    f"job {self._active_job_id} is already running"
                )
            job_id = uuid4().hex
            record = {
                "id": job_id,
                "kind": kind,
                "status": "queued",
                "submitted_at": _now(),
                "started_at": None,
                "completed_at": None,
                "options": options,
                "result": None,
                "error": None,
            }
            self._active_job_id = job_id
            self._write(record)
            self._executor.submit(self._run, job_id, kind, dict(options))
            return self._summary(record)

    def _run(self, job_id: str, kind: str, options: dict[str, Any]) -> None:
        record = self.get(job_id)
        if record is None:
            return
        record.update(status="running", started_at=_now())
        self._write(record)
        operation = (
            (lambda: run_ota(target=str(options.get("target", "ecu-gateway"))))
            if kind == "ota"
            else (lambda: run_experiment(kind, **options))
        )
        result, error = safe_call(operation)
        record.update(
            status="succeeded" if error is None else "failed",
            result=redact_private_fields(result) if error is None else None,
            error=error,
            completed_at=_now(),
        )
        self._write(record)
        with self._lock:
            if self._active_job_id == job_id:
                self._active_job_id = None

    @staticmethod
    def _summary(record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if key != "result"}

    def get(self, job_id: str) -> dict[str, Any] | None:
        if not job_id.isalnum():
            return None
        return self._read(self._path(job_id))

    def list(self) -> list[dict[str, Any]]:
        records = [
            record
            for path in self.directory.glob("*.json")
            if (record := self._read(path)) is not None
        ]
        records.sort(key=lambda item: str(item.get("submitted_at", "")), reverse=True)
        return [self._summary(record) for record in records]

    def result(self, job_id: str) -> dict[str, Any] | None:
        record = self.get(job_id)
        if record is None:
            return None
        return {
            "id": job_id,
            "status": record.get("status"),
            "result": record.get("result"),
            "error": record.get("error"),
        }
