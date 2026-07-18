import json
from hashlib import sha256

import pytest

from app.services import unpack_export


@pytest.fixture
def storage(tmp_path, monkeypatch):
    artifacts = tmp_path / "artifacts"
    outputs = tmp_path / "saved-outputs"
    monkeypatch.setattr(unpack_export, "ARTIFACTS_DIR", artifacts)
    monkeypatch.setattr(unpack_export, "OUTPUT_DIR", outputs)
    return artifacts, outputs


def _analysis(storage, job_id: str, payload: object):
    artifacts, _ = storage
    job = artifacts / job_id
    (job / "extracted").mkdir(parents=True)
    (job / "analysis.json").write_text(json.dumps(payload), encoding="utf-8")
    return job


def test_rejects_traversal_job_id(storage):
    with pytest.raises(ValueError, match="Invalid analysis job ID"):
        unpack_export.save_unpacked_layers("../outside")


def test_rejects_non_object_analysis_metadata(storage):
    _analysis(storage, "job-1", ["not", "an", "object"])

    with pytest.raises(ValueError, match="JSON object"):
        unpack_export.save_unpacked_layers("job-1")


def test_does_not_copy_artifact_outside_extracted_directory(storage, tmp_path):
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    _analysis(
        storage,
        "job-2",
        {
            "archive_name": "sample.bin",
            "artifacts": [
                {
                    "type": "unpack-result",
                    "sample_ref": "root",
                    "output": {"name": "../../outside.bin"},
                }
            ],
        },
    )

    results = unpack_export.save_unpacked_layers("job-2")

    assert not any(item.method == "unknown" for item in results)
    assert outside.read_bytes() == b"secret"


def test_cyclic_unpack_chain_is_bounded(storage):
    job = _analysis(
        storage,
        "job-3",
        {
            "archive_name": "sample.bin",
            "artifacts": [
                {
                    "type": "unpack-result",
                    "sample_ref": "entity-a",
                    "output_entity_id": "entity-b",
                    "unpack_method": "zip",
                    "output": {"name": "a.bin"},
                },
                {
                    "type": "unpack-result",
                    "sample_ref": "entity-b",
                    "output_entity_id": "entity-a",
                    "unpack_method": "upx",
                    "output": {"name": "b.bin"},
                },
            ],
        },
    )
    (job / "extracted" / "a.bin").write_bytes(b"a")
    (job / "extracted" / "b.bin").write_bytes(b"b")

    results = unpack_export.save_unpacked_layers("job-3")

    unpacked = [item for item in results if item.method in {"zip", "upx"}]
    assert len(unpacked) == 2
    assert all(len(item.filename) <= 255 for item in results)


def test_saved_metadata_is_calculated_from_files_not_untrusted_analysis(storage):
    job = _analysis(
        storage,
        "job-integrity",
        {
            "archive_name": "sample.bin",
            "artifacts": [
                {
                    "type": "unpack-result",
                    "sample_ref": "root",
                    "unpack_method": "zip",
                    "output": {
                        "name": "unpacked-layer.bin",
                        "size_bytes": 999_999,
                        "hashes": {"sha256": "0" * 64},
                    },
                },
                {
                    "type": "decompilation",
                    "target_entity_id": "root",
                    "language": "python",
                    "source_preview": ["print('verified')"],
                    "hashes": {"sha256": "f" * 64},
                },
            ],
        },
    )
    original_content = b"original"
    unpacked_content = b"actual unpacked bytes"
    (job / "extracted" / "original.bin").write_bytes(original_content)
    (job / "extracted" / "unpacked-layer.bin").write_bytes(unpacked_content)

    results = unpack_export.save_unpacked_layers("job-integrity")

    original = next(item for item in results if item.method == "original")
    unpacked = next(item for item in results if item.method == "zip")
    deobfuscated = next(item for item in results if item.method == "deobfuscation")
    assert (original.size_bytes, original.sha256) == (
        len(original_content),
        sha256(original_content).hexdigest(),
    )
    assert (unpacked.size_bytes, unpacked.sha256) == (
        len(unpacked_content),
        sha256(unpacked_content).hexdigest(),
    )
    deobfuscated_content = b"print('verified')"
    assert (deobfuscated.size_bytes, deobfuscated.sha256) == (
        len(deobfuscated_content),
        sha256(deobfuscated_content).hexdigest(),
    )
