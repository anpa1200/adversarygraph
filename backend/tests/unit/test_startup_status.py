from app.services.startup_status import StartupStatus


def test_startup_status_tracks_reference_ingestion_lifecycle():
    status = StartupStatus()

    pending = status.snapshot()
    assert pending["status"] == "starting"
    assert pending["reference_ingestion"]["status"] == "pending"

    status.mark_job_running(
        "reference_ingestion",
        phase="attck_ingestion",
        message="running",
    )
    running = status.snapshot()
    assert running["status"] == "starting"
    assert running["ready"] is False
    assert running["reference_ingestion"]["status"] == "running"
    assert running["reference_ingestion"]["started_at"]

    status.mark_job_complete(
        "reference_ingestion",
        phase="complete",
        message="done",
    )
    complete = status.snapshot()
    assert complete["status"] == "ready"
    assert complete["ready"] is True
    assert complete["reference_ingestion"]["status"] == "complete"
    assert complete["reference_ingestion"]["completed_at"]


def test_startup_status_failed_job_is_degraded_but_api_ready():
    status = StartupStatus()
    status.mark_job_failed(
        "reference_ingestion",
        phase="failed",
        message="failed",
        error=RuntimeError("boom"),
    )

    snapshot = status.snapshot()
    assert snapshot["status"] == "degraded"
    assert snapshot["ready"] is True
    assert snapshot["reference_ingestion"]["status"] == "failed"
    assert "RuntimeError: boom" == snapshot["reference_ingestion"]["error"]
