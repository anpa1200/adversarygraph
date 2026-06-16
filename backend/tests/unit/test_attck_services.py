"""Unit tests for ATT&CK bundle download and version maintenance helpers."""

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.attck import downloader, version_checker


class _Response:
    def __init__(self, payload=None, chunks=None):
        self._payload = payload
        self._chunks = chunks or []

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload

    def iter_content(self, chunk_size):
        assert chunk_size == 65536
        return iter(self._chunks)


def test_get_latest_version_ignores_non_bundle_files(monkeypatch):
    def fake_get(url, headers, timeout):
        assert url.endswith("/enterprise-attack")
        assert headers["Accept"] == "application/vnd.github.v3+json"
        assert timeout == 30
        return _Response(payload=[
            {"name": "README.md"},
            {"name": "enterprise-attack-14.1.json"},
            {"name": "enterprise-attack-15.0.json"},
            {"name": "enterprise-attack-next.json"},
        ])

    monkeypatch.setattr(downloader.requests, "get", fake_get)

    assert downloader.get_latest_version("enterprise-attack") == "15.0"


def test_get_latest_version_raises_when_no_json_bundles(monkeypatch):
    monkeypatch.setattr(
        downloader.requests,
        "get",
        lambda *args, **kwargs: _Response(payload=[{"name": "README.md"}]),
    )

    with pytest.raises(RuntimeError, match="No STIX bundles"):
        downloader.get_latest_version("mobile-attack")


def test_download_bundle_uses_cached_file(tmp_path):
    cached = tmp_path / "ics-attack-16.0.json"
    cached.write_text("{}", encoding="utf-8")

    assert downloader.download_bundle("ics-attack", "16.0", str(tmp_path)) == cached


def test_download_bundle_streams_to_temp_file_then_renames(monkeypatch, tmp_path):
    requests_seen = []

    def fake_get(url, stream, timeout):
        requests_seen.append((url, stream, timeout))
        return _Response(chunks=[b'{"type":', b'"bundle"}'])

    monkeypatch.setattr(downloader.requests, "get", fake_get)

    path = downloader.download_bundle("enterprise-attack", "15.1", str(tmp_path))

    assert path == tmp_path / "enterprise-attack-15.1.json"
    assert path.read_bytes() == b'{"type":"bundle"}'
    assert not path.with_suffix(".tmp").exists()
    assert requests_seen == [(
        downloader.RAW_BUNDLE_URL.format(domain="enterprise-attack", version="15.1"),
        True,
        120,
    )]


def test_download_bundle_removes_temp_file_on_stream_error(monkeypatch, tmp_path):
    class BrokenResponse(_Response):
        def iter_content(self, chunk_size):
            yield b"partial"
            raise OSError("connection dropped")

    monkeypatch.setattr(
        downloader.requests,
        "get",
        lambda *args, **kwargs: BrokenResponse(),
    )

    with pytest.raises(OSError, match="connection dropped"):
        downloader.download_bundle("enterprise-attack", "15.1", str(tmp_path))

    assert not (tmp_path / "enterprise-attack-15.1.tmp").exists()
    assert not (tmp_path / "enterprise-attack-15.1.json").exists()


def test_ensure_bundle_returns_downloaded_path_and_version(monkeypatch, tmp_path):
    expected_path = tmp_path / "mobile-attack-16.0.json"
    monkeypatch.setattr(downloader, "get_latest_version", lambda domain: "16.0")
    monkeypatch.setattr(
        downloader,
        "download_bundle",
        lambda domain, version, data_dir: expected_path,
    )

    assert downloader.ensure_bundle("mobile-attack", str(tmp_path)) == (expected_path, "16.0")


def test_ensure_bundle_falls_back_to_cached_version(monkeypatch, tmp_path):
    cached = tmp_path / "enterprise-attack-19.1.json"
    cached.write_text("{}")
    monkeypatch.setattr(downloader, "get_latest_version", lambda domain: (_ for _ in ()).throw(RuntimeError("rate limited")))
    monkeypatch.setattr(
        downloader,
        "download_bundle",
        lambda domain, version, data_dir: tmp_path / f"{domain}-{version}.json",
    )

    assert downloader.ensure_bundle("enterprise-attack", str(tmp_path)) == (cached, "19.1")


def test_sync_outdated_domains_updates_only_domains_that_need_it(monkeypatch, tmp_path):
    actions_seen = []
    bundle_path = tmp_path / "enterprise-attack-15.1.json"

    monkeypatch.setattr(
        version_checker,
        "get_status",
        lambda: [
            version_checker.DomainStatus("enterprise-attack", "15.0", "15.1", True, None),
            version_checker.DomainStatus("mobile-attack", "16.0", "16.0", False, None),
        ],
    )
    monkeypatch.setattr(version_checker.settings, "attck_data_dir", str(tmp_path))
    monkeypatch.setattr(
        "app.services.attck.downloader.download_bundle",
        lambda domain, version, data_dir: bundle_path,
    )
    monkeypatch.setattr(
        "app.services.attck.ingestor.ingest_domain",
        lambda domain, path, version: actions_seen.append((domain, path, version)),
    )

    assert version_checker.sync_outdated_domains() == {
        "enterprise-attack": "updated to 15.1",
        "mobile-attack": "up-to-date",
    }
    assert actions_seen == [("enterprise-attack", bundle_path, "15.1")]


def test_sync_outdated_domains_can_force_selected_domain(monkeypatch, tmp_path):
    actions_seen = []
    bundle_path = tmp_path / "mobile-attack-16.0.json"

    monkeypatch.setattr(
        version_checker,
        "get_status",
        lambda: [
            version_checker.DomainStatus("enterprise-attack", "15.1", "15.1", False, None),
            version_checker.DomainStatus("mobile-attack", "16.0", "16.0", False, None),
        ],
    )
    monkeypatch.setattr(version_checker.settings, "attck_data_dir", str(tmp_path))
    monkeypatch.setattr(
        "app.services.attck.downloader.download_bundle",
        lambda domain, version, data_dir: bundle_path,
    )
    monkeypatch.setattr(
        "app.services.attck.ingestor.ingest_domain",
        lambda domain, path, version: actions_seen.append((domain, path, version)),
    )

    assert version_checker.sync_outdated_domains(domains=["mobile-attack"], force=True) == {
        "mobile-attack": "refreshed 16.0",
    }
    assert actions_seen == [("mobile-attack", bundle_path, "16.0")]


def test_get_status_reports_current_latest_and_failures(monkeypatch):
    class Row:
        version = "15.0"
        ingested_at = datetime(2026, 6, 15, 10, 30)

    class Result:
        def __init__(self, row):
            self.row = row

        def scalar_one_or_none(self):
            return self.row

    class SessionStub:
        def __init__(self, engine):
            self.calls = 0

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, statement):
            self.calls += 1
            return Result(Row() if self.calls == 1 else None)

    def fake_latest(domain):
        if domain == "mobile-attack":
            raise RuntimeError("network unavailable")
        return "15.1"

    monkeypatch.setattr(version_checker, "_get_engine", lambda: object())
    monkeypatch.setattr(version_checker, "Session", SessionStub)
    monkeypatch.setattr(
        version_checker,
        "settings",
        SimpleNamespace(attck_domain_list=["enterprise-attack", "mobile-attack"], attck_data_dir="/tmp"),
    )
    monkeypatch.setattr(version_checker, "get_latest_version", fake_latest)
    monkeypatch.setattr(version_checker, "get_latest_cached_version", lambda domain, data_dir: "16.0")

    statuses = version_checker.get_status()

    assert statuses == [
        version_checker.DomainStatus(
            "enterprise-attack",
            "15.0",
            "15.1",
            True,
            "2026-06-15T10:30:00",
        ),
        version_checker.DomainStatus("mobile-attack", None, "16.0", True, None),
    ]
