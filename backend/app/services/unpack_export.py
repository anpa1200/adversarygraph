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
from pathlib import Path
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

STORAGE_ROOT = Path(settings.malwaregraph_storage_dir)
ARTIFACTS_DIR = STORAGE_ROOT / "artifacts"
OUTPUT_DIR = STORAGE_ROOT / "saved-outputs"

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
    return re.sub(r'[^\w.\-]', '_', name)


def _stem_ext(filename: str) -> tuple[str, str]:
    p = Path(filename)
    return p.stem, p.suffix or ".bin"


def save_unpacked_layers(job_id: str) -> list[SavedLayer]:
    job_dir = ARTIFACTS_DIR / job_id
    analysis_path = job_dir / "analysis.json"
    extracted_dir = job_dir / "extracted"

    if not analysis_path.exists():
        raise FileNotFoundError(f"analysis.json not found for job {job_id}")

    with analysis_path.open() as fh:
        analysis: dict[str, Any] = json.load(fh)

    artifacts: list[dict[str, Any]] = analysis.get("artifacts", [])

    # ── Unpack chain ─────────────────────────────────────────────────────────
    unpack_results = [a for a in artifacts if a.get("type") == "unpack-result" and a.get("output")]
    by_input: dict[str, dict[str, Any]] = {r["sample_ref"]: r for r in unpack_results}

    output_entity_ids = {
        r.get("output_entity_id") or r["output"].get("target_entity_id", "")
        for r in unpack_results
    }
    root_entities = [r for r in unpack_results if r["sample_ref"] not in output_entity_ids]
    if not root_entities:
        root_entities = unpack_results[:1]

    # ── Original filename ─────────────────────────────────────────────────────
    original_filename = analysis.get("archive_name") or ""
    if not original_filename and root_entities:
        original_filename = root_entities[0].get("target_name", "")
    if not original_filename:
        original_filename = f"sample_{job_id[:8]}.bin"
    orig_stem, orig_ext = _stem_ext(original_filename)

    out_dir = OUTPUT_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[SavedLayer] = []
    # Maps entity_id → the accumulated stem for that entity so deobfuscation
    # artifacts can derive their filename from the same chain.
    entity_to_stem: dict[str, str] = {}

    # ── Walk unpack chain ─────────────────────────────────────────────────────
    def walk(entity_id: str, layer: int, stem_so_far: str) -> None:
        entity_to_stem[entity_id] = stem_so_far
        record = by_input.get(entity_id)
        if not record:
            return

        output = record["output"]
        method = _clean(record.get("unpack_method") or record.get("packer") or "unknown")
        out_name = output.get("name", "")
        out_stem, layer_ext = _stem_ext(out_name)
        if not layer_ext or layer_ext == ".bin":
            layer_ext = orig_ext
        out_label = _clean(out_stem) if out_stem else method

        new_stem = f"{stem_so_far}_{out_label}_layer{layer}"
        new_filename = f"{new_stem}{layer_ext}"

        src = extracted_dir / out_name
        dst = out_dir / new_filename

        next_entity = record.get("output_entity_id") or output.get("target_entity_id", "")
        if next_entity:
            entity_to_stem[next_entity] = new_stem

        if not src.exists():
            logger.warning("unpack_export: source file missing: %s", src)
        else:
            if not dst.exists():
                shutil.copy2(src, dst)
                logger.info("unpack_export: saved %s → %s", src.name, new_filename)
            sha256 = output.get("hashes", {}).get("sha256", "")
            results.append(SavedLayer(
                layer=layer,
                method=method,
                filename=new_filename,
                source_path=str(src),
                saved_path=str(dst),
                size_bytes=output.get("size_bytes", dst.stat().st_size if dst.exists() else 0),
                sha256=sha256,
            ))

        if next_entity:
            walk(next_entity, layer + 1, new_stem)

    for root in root_entities:
        walk(root["sample_ref"], 1, _clean(orig_stem))

    # ── Original file (layer 0) ───────────────────────────────────────────────
    if extracted_dir.exists():
        orig_candidates = [f for f in extracted_dir.iterdir()
                           if f.is_file() and "unpacked" not in f.name]
        if orig_candidates:
            orig_src = orig_candidates[0]
            orig_dst = out_dir / (_clean(orig_stem) + orig_src.suffix)
            if not orig_dst.exists():
                shutil.copy2(orig_src, orig_dst)
            results.insert(0, SavedLayer(
                layer=0,
                method="original",
                filename=orig_dst.name,
                source_path=str(orig_src),
                saved_path=str(orig_dst),
                size_bytes=orig_dst.stat().st_size,
                sha256="",
            ))

    # ── Deobfuscation artifacts ───────────────────────────────────────────────
    # Each decompilation artifact carries the deobfuscated text in pseudocode[]
    # or source_preview[].  Name the file after the stem of the entity it was
    # applied to, appending _deobfuscated.<lang_ext>.
    deob_artifacts = [a for a in artifacts if a.get("type") == "decompilation"]
    for artifact in deob_artifacts:
        content_lines: list[str] = (
            artifact.get("source_preview")
            or artifact.get("pseudocode")
            or []
        )
        if not content_lines:
            continue

        target_entity = artifact.get("target_entity_id", "")
        language = (artifact.get("language") or "").lower()
        deob_ext = _DEOB_EXT.get(language, ".txt")

        base_stem = entity_to_stem.get(target_entity, _clean(orig_stem))
        deob_filename = f"{base_stem}_deobfuscated{deob_ext}"
        deob_dst = out_dir / deob_filename

        if not deob_dst.exists():
            deob_dst.write_text("\n".join(content_lines), encoding="utf-8")
            logger.info("unpack_export: saved deobfuscated → %s", deob_filename)

        results.append(SavedLayer(
            layer=len(results),
            method="deobfuscation",
            filename=deob_filename,
            source_path="",
            saved_path=str(deob_dst),
            size_bytes=deob_dst.stat().st_size,
            sha256=artifact.get("hashes", {}).get("sha256", ""),
        ))

    return results
