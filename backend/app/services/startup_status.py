from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StartupStatus:
    def __init__(self) -> None:
        self._lock = Lock()
        self._started_at = _now()
        self._platform_message = "API process started."
        self._jobs: dict[str, dict[str, Any]] = {
            "reference_ingestion": {
                "status": "pending",
                "phase": "waiting",
                "message": "ATT&CK/ATLAS reference ingestion has not started yet.",
                "started_at": None,
                "completed_at": None,
                "error": None,
            }
        }

    def set_platform_message(self, message: str) -> None:
        with self._lock:
            self._platform_message = message

    def mark_job_running(self, name: str, *, phase: str, message: str) -> None:
        with self._lock:
            job = self._jobs.setdefault(name, {})
            job.update(
                {
                    "status": "running",
                    "phase": phase,
                    "message": message,
                    "started_at": job.get("started_at") or _now(),
                    "completed_at": None,
                    "error": None,
                }
            )

    def mark_job_complete(self, name: str, *, phase: str, message: str) -> None:
        with self._lock:
            job = self._jobs.setdefault(name, {})
            job.update(
                {
                    "status": "complete",
                    "phase": phase,
                    "message": message,
                    "completed_at": _now(),
                    "error": None,
                }
            )

    def mark_job_failed(self, name: str, *, phase: str, message: str, error: Exception) -> None:
        with self._lock:
            job = self._jobs.setdefault(name, {})
            job.update(
                {
                    "status": "failed",
                    "phase": phase,
                    "message": message,
                    "completed_at": _now(),
                    "error": f"{type(error).__name__}: {error}",
                }
            )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            jobs = {name: dict(value) for name, value in self._jobs.items()}
            statuses = {str(job.get("status")) for job in jobs.values()}
            if "failed" in statuses:
                status = "degraded"
                ready = True
            elif statuses & {"pending", "running"}:
                status = "starting"
                ready = False
            else:
                status = "ready"
                ready = True
            return {
                "status": status,
                "ready": ready,
                "started_at": self._started_at,
                "message": self._platform_message,
                "reference_ingestion": jobs["reference_ingestion"],
                "jobs": jobs,
            }


startup_status = StartupStatus()
