from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Literal
from uuid import uuid4
import re
import shutil

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ENGINE_VERSION = "1.13.0"
ENGINE_REF = os.getenv("EVIDENCEFORGE_REF", "unknown")
DATA_DIR = Path(os.getenv("EVIDENCEFORGE_DATA_DIR", "/data/runs")).resolve()
MAX_SCENARIO_BYTES = int(os.getenv("EVIDENCEFORGE_MAX_SCENARIO_BYTES", "262144"))
TIMEOUT_SECONDS = int(os.getenv("EVIDENCEFORGE_TIMEOUT_SECONDS", "180"))

app = FastAPI(title="AdversaryGraph Synthetic Evidence Service", version="1.0.0")


class ScenarioPayload(BaseModel):
    scenario_yaml: str = Field(min_length=1, max_length=MAX_SCENARIO_BYTES)


class GeneratePayload(ScenarioPayload):
    target: Literal["default", "sof-elk", "splunk"] = "default"
    formats: list[str] = Field(default_factory=list, max_length=32)


def _run(args: list[str], timeout: int = TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp"},
    )


def _write_scenario(run_dir: Path, content: str) -> tuple[Path, str]:
    encoded = content.encode()
    if len(encoded) > MAX_SCENARIO_BYTES:
        raise HTTPException(413, "Scenario exceeds the configured size limit")
    path = run_dir / "scenario.yaml"
    path.write_bytes(encoded)
    return path, hashlib.sha256(encoded).hexdigest()


def _artifacts(root: Path) -> list[dict]:
    result = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        resolved = path.resolve()
        if root not in resolved.parents:
            continue
        content = path.read_bytes()
        result.append(
            {
                "path": str(path.relative_to(root)),
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return result


@app.get("/health")
def health() -> dict:
    probe = _run(["eforge", "--help"], timeout=10)
    return {
        "ok": probe.returncode == 0,
        "engine": "EvidenceForge",
        "engine_version": ENGINE_VERSION,
        "engine_ref": ENGINE_REF,
        "synthetic_only": True,
    }


@app.get("/templates")
def templates() -> list[dict]:
    source = Path("/opt/evidenceforge/scenarios/branch-office-example/scenario.yaml")
    return [
        {
            "id": "branch-office",
            "name": "Branch office baseline and storyline",
            "description": "Official EvidenceForge scenario; review and edit before generation.",
            "scenario_yaml": source.read_text(encoding="utf-8"),
            "source": "Cisco-Talos/EvidenceForge",
            "synthetic_only": True,
        }
    ]


@app.post("/validate")
def validate(payload: ScenarioPayload) -> dict:
    run_dir = DATA_DIR / f"validate-{uuid4()}"
    run_dir.mkdir(parents=True)
    scenario, digest = _write_scenario(run_dir, payload.scenario_yaml)
    try:
        output = _run(["eforge", "validate", str(scenario)])
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "EvidenceForge validation timed out") from exc
    return {
        "valid": output.returncode == 0,
        "exit_code": output.returncode,
        "scenario_sha256": digest,
        "output": (output.stdout + "\n" + output.stderr)[-16000:],
        "engine_version": ENGINE_VERSION,
        "engine_ref": ENGINE_REF,
        "synthetic_only": True,
    }


@app.post("/generate")
def generate(payload: GeneratePayload) -> dict:
    run_id = f"synthetic-{uuid4()}"
    run_dir = DATA_DIR / run_id
    output_dir = run_dir / "data"
    run_dir.mkdir(parents=True)
    scenario, digest = _write_scenario(run_dir, payload.scenario_yaml)
    checked = _run(["eforge", "validate", str(scenario)])
    if checked.returncode:
        raise HTTPException(
            422,
            {"message": "Scenario validation failed", "output": (checked.stdout + checked.stderr)[-16000:]},
        )
    command = [
        "eforge", "generate", str(scenario), "--output", str(output_dir),
        "--target", payload.target, "--force",
    ]
    normalized = [item.strip() for item in payload.formats if item.strip()]
    if any(not item.replace("_", "").replace("-", "").isalnum() for item in normalized):
        raise HTTPException(422, "Invalid format name")
    if normalized:
        command.extend(["--formats", ",".join(normalized)])
    started = time.monotonic()
    try:
        generated = _run(command)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(504, "EvidenceForge generation timed out") from exc
    if generated.returncode:
        raise HTTPException(
            502,
            {"message": "EvidenceForge generation failed", "output": (generated.stdout + generated.stderr)[-16000:]},
        )
    evaluated = _run(["eforge", "eval", str(output_dir), "--scenario", str(scenario), "--format", "json"])
    quality: dict = {"available": False, "passed": False}
    if evaluated.returncode == 0:
        try:
            quality = json.loads(evaluated.stdout)
            quality["available"] = True
        except json.JSONDecodeError:
            quality["error"] = "Invalid evaluation JSON"
    artifacts = _artifacts(output_dir)
    manifest = {
        "run_id": run_id,
        "synthetic_only": True,
        "engine": "EvidenceForge",
        "engine_version": ENGINE_VERSION,
        "engine_ref": ENGINE_REF,
        "scenario_sha256": digest,
        "target": payload.target,
        "formats": normalized,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "quality": quality,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    shutil.make_archive(str(run_dir / "synthetic-evidence"), "zip", output_dir)
    return manifest


@app.get("/runs/{run_id}/bundle")
def bundle(run_id: str) -> FileResponse:
    if not re.fullmatch(r"synthetic-[0-9a-f-]{36}", run_id):
        raise HTTPException(404, "Synthetic run not found")
    path = (DATA_DIR / run_id / "synthetic-evidence.zip").resolve()
    if DATA_DIR not in path.parents or not path.is_file():
        raise HTTPException(404, "Synthetic run bundle not found")
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"{run_id}.zip",
    )
