"""
Walk the unpack chain from analysis.json, copy each layer's file to
saved-outputs/ with the user-defined naming convention:

  Original:       <original_name>.<ext>
  Unpack layer 1: <original_stem>_<found_name_1>_layer1.<ext>
  Unpack layer 2: <original_stem>_<found_name_1>_layer1_<found_name_2>_layer2.<ext>
  Deobfuscated:   <stem_of_target>_deobfuscated.<lang_ext>

where <found_name_N> is the stem of the actual file extracted at that tier,
and deobfuscation files are named after the stem of the entity they were applied to.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from dataclasses import dataclass
from hashlib import sha256 as sha256_digest
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

STORAGE_ROOT = Path(settings.malwaregraph_storage_dir)
ARTIFACTS_DIR = STORAGE_ROOT / "artifacts"
OUTPUT_DIR = STORAGE_ROOT / "saved-outputs"

_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
_MAX_UNPACK_LAYERS = 100
_MAX_DEOBFUSCATED_LINES = 50_000
_HASH_CHUNK_SIZE = 1024 * 1024

_DEOB_EXT: dict[str, str] = {
    "csharp": ".cs",
    "java": ".java",
    "python": ".py",
    "javascript": ".js",
    "c": ".c",
    "cpp": ".cpp",
}


@dataclass
class SavedLayer:
    layer: int        # 0 = original, 1+ = unpack tiers, "deob" tiers follow
    method: str       # "original" | "deobfuscation" | packer method
    filename: str
    source_path: str  # path in storage (empty for synthesised text files)
    saved_path: str
    size_bytes: int
    sha256: str


def _clean(name: str) -> str:
    cleaned = re.sub(r'[^\w.\-]', '_', str(name))[:120]
    return cleaned or "artifact"


def _bounded_stem(value: str, max_length: int = 180) -> str:
    if len(value) <= max_length:
        return value
    digest = sha256_digest(value.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{value[:max_length - 13]}_{digest}"


def _stem_ext(filename: str) -> tuple[str, str]:
    p = Path(str(filename))
    extension = p.suffix
    if not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", extension):
        extension = ".bin"
    return _clean(p.stem), extension


def _contained_path(root: Path, relative_name: str) -> Path | None:
    """Resolve an untrusted artifact name and keep it below ``root``."""
    if not relative_name or Path(relative_name).is_absolute():
        return None
    resolved_root = root.resolve()
    candidate = (resolved_root / relative_name).resolve()
    return candidate if candidate.is_relative_to(resolved_root) else None


def _file_integrity(path: Path) -> tuple[int, str]:
    """Return metadata calculated from the persisted artifact itself."""
    digest = sha256_digest()
    size_bytes = 0
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK_SIZE):
            size_bytes += len(chunk)
            digest.update(chunk)
    return size_bytes, digest.hexdigest()


def save_unpacked_layers(job_id: str) -> list[SavedLayer]:
    if job_id in {".", ".."} or not _JOB_ID_RE.fullmatch(job_id):
        raise ValueError("Invalid analysis job ID")

    artifacts_root = ARTIFACTS_DIR.resolve()
    job_dir = (artifacts_root / job_id).resolve()
    if not job_dir.is_relative_to(artifacts_root):
        raise ValueError("Invalid analysis job path")
    analysis_path = job_dir / "analysis.json"
    extracted_dir = job_dir / "extracted"

    if not analysis_path.exists():
        raise FileNotFoundError(f"analysis.json not found for job {job_id}")

    with analysis_path.open() as fh:
        raw_analysis = json.load(fh)
    if not isinstance(raw_analysis, dict):
        raise ValueError("MalwareGraph analysis metadata must be a JSON object")
    analysis: dict[str, Any] = raw_analysis

    raw_artifacts = analysis.get("artifacts", [])
    artifacts: list[dict[str, Any]] = (
        [item for item in raw_artifacts if isinstance(item, dict)]
        if isinstance(raw_artifacts, list)
        else []
    )

    # ── Unpack chain ─────────────────────────────────────────────────────────
    unpack_results = [
        artifact
        for artifact in artifacts
        if artifact.get("type") == "unpack-result"
        and isinstance(artifact.get("output"), dict)
        and isinstance(artifact.get("sample_ref"), str)
        and artifact.get("sample_ref")
    ]
    by_input: dict[str, dict[str, Any]] = {str(record["sample_ref"]): record for record in unpack_results}

    output_entity_ids = {
        value
        for record in unpack_results
        if isinstance(
            (value := record.get("output_entity_id") or record["output"].get("target_entity_id", "")),
            str,
        )
        and value
    }
    root_entities = [r for r in unpack_results if r["sample_ref"] not in output_entity_ids]
    if not root_entities:
        root_entities = unpack_results[:1]

    # ── Original filename ─────────────────────────────────────────────────────
    original_filename = analysis.get("archive_name") if isinstance(analysis.get("archive_name"), str) else ""
    if not original_filename and root_entities:
        target_name = root_entities[0].get("target_name", "")
        original_filename = target_name if isinstance(target_name, str) else ""
    if not original_filename:
        original_filename = f"sample_{job_id[:8]}.bin"
    orig_stem, orig_ext = _stem_ext(original_filename)

    output_root = OUTPUT_DIR.resolve()
    out_dir = (output_root / job_id).resolve()
    if not out_dir.is_relative_to(output_root):
        raise ValueError("Invalid saved-output job path")
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[SavedLayer] = []
    # Maps entity_id → the accumulated stem for that entity so deobfuscation
    # artifacts can derive their filename from the same chain.
    entity_to_stem: dict[str, str] = {}
    visited_entities: set[str] = set()

    # ── Walk unpack chain ─────────────────────────────────────────────────────
    def walk(entity_id: str, layer: int, stem_so_far: str) -> None:
        if entity_id in visited_entities:
            logger.warning("unpack_export: cyclic or duplicate entity reference ignored: %s", entity_id)
            return
        if layer > _MAX_UNPACK_LAYERS:
            logger.warning("unpack_export: unpack chain exceeded %d layers", _MAX_UNPACK_LAYERS)
            return
        visited_entities.add(entity_id)
        entity_to_stem[entity_id] = stem_so_far
        record = by_input.get(entity_id)
        if not record:
            return

        output = record["output"]
        method = _clean(record.get("unpack_method") or record.get("packer") or "unknown")
        out_name = output.get("name", "") if isinstance(output.get("name"), str) else ""
        out_stem, layer_ext = _stem_ext(out_name)
        if not layer_ext or layer_ext == ".bin":
            layer_ext = orig_ext
        out_label = _clean(out_stem) if out_stem else method

        new_stem = _bounded_stem(f"{stem_so_far}_{out_label}_layer{layer}")
        new_filename = f"{new_stem}{layer_ext}"

        src = _contained_path(extracted_dir, str(out_name))
        dst = out_dir / new_filename

        raw_next_entity = record.get("output_entity_id") or output.get("target_entity_id", "")
        next_entity = raw_next_entity if isinstance(raw_next_entity, str) else ""
        if next_entity:
            entity_to_stem[next_entity] = new_stem

        if src is None or not src.is_file():
            logger.warning("unpack_export: source file missing or outside artifact root: %s", out_name)
        else:
            if not dst.exists():
                shutil.copy2(src, dst)
                logger.info("unpack_export: saved %s → %s", src.name, new_filename)
            actual_size, actual_sha256 = _file_integrity(dst)
            results.append(SavedLayer(
                layer=layer,
                method=method,
                filename=new_filename,
                source_path=str(src),
                saved_path=str(dst),
                size_bytes=actual_size,
                sha256=actual_sha256,
            ))

        if next_entity:
            walk(next_entity, layer + 1, new_stem)

    for root in root_entities:
        walk(root["sample_ref"], 1, _clean(orig_stem))

    # ── Original file (layer 0) ───────────────────────────────────────────────
    if extracted_dir.exists():
        extracted_root = extracted_dir.resolve()
        orig_candidates = [
            item
            for item in extracted_dir.iterdir()
            if item.is_file()
            and item.resolve().is_relative_to(extracted_root)
            and "unpacked" not in item.name
        ]
        if orig_candidates:
            orig_src = orig_candidates[0]
            _, original_extension = _stem_ext(orig_src.name)
            orig_dst = out_dir / (_bounded_stem(_clean(orig_stem)) + original_extension)
            if not orig_dst.exists():
                shutil.copy2(orig_src, orig_dst)
            original_size, original_sha256 = _file_integrity(orig_dst)
            results.insert(0, SavedLayer(
                layer=0,
                method="original",
                filename=orig_dst.name,
                source_path=str(orig_src),
                saved_path=str(orig_dst),
                size_bytes=original_size,
                sha256=original_sha256,
            ))

    # ── Deobfuscation artifacts ───────────────────────────────────────────────
    # Each decompilation artifact carries the deobfuscated text in pseudocode[]
    # or source_preview[].  Name the file after the stem of the entity it was
    # applied to, appending _deobfuscated.<lang_ext>.
    deob_artifacts = [a for a in artifacts if a.get("type") == "decompilation"]
    for artifact in deob_artifacts:
        raw_content_lines = (
            artifact.get("source_preview")
            or artifact.get("pseudocode")
            or []
        )
        content_lines = (
            [str(line) for line in raw_content_lines[:_MAX_DEOBFUSCATED_LINES]]
            if isinstance(raw_content_lines, list)
            else []
        )
        if not content_lines:
            continue

        raw_target_entity = artifact.get("target_entity_id", "")
        target_entity = raw_target_entity if isinstance(raw_target_entity, str) else ""
        raw_language = artifact.get("language")
        language = raw_language.lower() if isinstance(raw_language, str) else ""
        deob_ext = _DEOB_EXT.get(language, ".txt")

        base_stem = entity_to_stem.get(target_entity, _clean(orig_stem))
        deob_filename = f"{_bounded_stem(base_stem + '_deobfuscated')}{deob_ext}"
        deob_dst = out_dir / deob_filename

        if not deob_dst.exists():
            deob_dst.write_text("\n".join(content_lines), encoding="utf-8")
            logger.info("unpack_export: saved deobfuscated → %s", deob_filename)

        deob_size, deob_sha256 = _file_integrity(deob_dst)

        results.append(SavedLayer(
            layer=len(results),
            method="deobfuscation",
            filename=deob_filename,
            source_path="",
            saved_path=str(deob_dst),
            size_bytes=deob_size,
            sha256=deob_sha256,
        ))

    return results
