"""
Walk the unpack chain from analysis.json, copy each layer's file to
saved-outputs/ with the user-defined naming convention:

  Original:  <original_name>.<ext>
  Layer 1:   <original_stem>_<method1>_layer1.<ext>
  Layer 2:   <original_stem>_<method1>_layer1_<method2>_layer2.<ext>
  ...
"""
from __future__ import annotations

import json
import logging
import os
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


@dataclass
class SavedLayer:
    layer: int               # 0 = original, 1 = first unpack, etc.
    method: str              # packer/unpack method
    filename: str            # new filename with convention
    source_path: str         # absolute path in storage (read-only)
    saved_path: str          # absolute path in saved-outputs
    size_bytes: int
    sha256: str


def _clean(name: str) -> str:
    """Strip unsafe characters from a filename component."""
    return re.sub(r'[^\w.\-]', '_', name)


def _stem_ext(filename: str) -> tuple[str, str]:
    p = Path(filename)
    return p.stem, p.suffix or ".bin"


def save_unpacked_layers(job_id: str) -> list[SavedLayer]:
    """
    Read analysis.json for job_id, walk the unpack chain, copy files to
    saved-outputs/{job_id}/ with the naming convention and return metadata.
    """
    job_dir = ARTIFACTS_DIR / job_id
    analysis_path = job_dir / "analysis.json"
    extracted_dir = job_dir / "extracted"

    if not analysis_path.exists():
        raise FileNotFoundError(f"analysis.json not found for job {job_id}")

    with analysis_path.open() as fh:
        analysis: dict[str, Any] = json.load(fh)

    # ── Build unpack chain ────────────────────────────────────────────────────
    # unpack-result artifacts: each has sample_ref (input entity) and
    # output_entity_id (output entity). Chain: original → layer1 → layer2…

    unpack_results: list[dict[str, Any]] = [
        a for a in analysis.get("artifacts", [])
        if a.get("type") == "unpack-result" and a.get("output")
    ]

    # Index by input entity ID so we can walk the chain
    by_input: dict[str, dict[str, Any]] = {
        r["sample_ref"]: r for r in unpack_results
    }

    # Find the root entity (not an output of any earlier layer)
    output_entity_ids = {r.get("output_entity_id") or r["output"]["target_entity_id"]
                         for r in unpack_results}
    root_entities = [r for r in unpack_results if r["sample_ref"] not in output_entity_ids]

    if not root_entities:
        # Fallback: just take all in arbitrary order
        root_entities = unpack_results[:1]

    # ── Determine original filename ───────────────────────────────────────────
    # Prefer the archive_name from the job, then the target_name of the root.
    original_filename = analysis.get("archive_name") or ""
    if not original_filename and root_entities:
        original_filename = root_entities[0].get("target_name", "")
    if not original_filename:
        original_filename = f"sample_{job_id[:8]}.bin"

    # Strip password-protected zip prefix patterns like "upx--<sha256>.zip" → use inner name
    # or just use the name as-is with the right extension
    orig_stem, orig_ext = _stem_ext(original_filename)

    # ── Output directory ──────────────────────────────────────────────────────
    out_dir = OUTPUT_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[SavedLayer] = []

    # ── Walk the chain from root ──────────────────────────────────────────────
    def walk(entity_id: str, layer: int, stem_so_far: str):
        record = by_input.get(entity_id)
        if not record:
            return

        output = record["output"]
        method = _clean(record.get("unpack_method") or record.get("packer") or "unknown")
        out_name = output.get("name", "")
        _, layer_ext = _stem_ext(out_name)
        if not layer_ext or layer_ext == ".bin":
            layer_ext = orig_ext

        new_stem = f"{stem_so_far}_{method}_layer{layer}"
        new_filename = f"{new_stem}{layer_ext}"

        src = extracted_dir / out_name
        dst = out_dir / new_filename

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

        next_entity = record.get("output_entity_id") or output.get("target_entity_id", "")
        if next_entity:
            walk(next_entity, layer + 1, new_stem)

    for root in root_entities:
        walk(root["sample_ref"], 1, _clean(orig_stem))

    # ── Also copy the original file (layer 0) ─────────────────────────────────
    # Find the original sample file in extracted/
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

    return results
