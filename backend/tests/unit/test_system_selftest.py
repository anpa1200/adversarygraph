from app.api.routes.system import (
    _asset_scanner_readiness_check,
    _cpu_percent_from_totals,
    _data_integrity_check,
    _format_bytes,
    _memory_usage_details,
    _auth_readiness_check,
    _check_status,
    _overall_selftest_status,
    _storage_writable_check,
    _taxonomy_normalization_check,
)


def test_format_bytes_uses_binary_units():
    assert _format_bytes(0) == "0 B"
    assert _format_bytes(1024) == "1.0 KiB"
    assert _format_bytes(5 * 1024 * 1024) == "5.0 MiB"


def test_cpu_percent_from_totals_calculates_busy_time():
    first = (100, 200)
    second = (130, 300)

    assert _cpu_percent_from_totals(first, second) == 70.0


def test_memory_usage_details_reads_proc_and_cgroup(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text(
        "\n".join(
            [
                "MemTotal:       1000 kB",
                "MemFree:         200 kB",
                "MemAvailable:    400 kB",
            ]
        ),
        encoding="utf-8",
    )
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nVmRSS:\t250 kB\n", encoding="utf-8")
    cgroup = tmp_path / "cgroup"
    cgroup.mkdir()
    (cgroup / "memory.current").write_text("512\n", encoding="utf-8")
    (cgroup / "memory.max").write_text("1024\n", encoding="utf-8")

    details = _memory_usage_details(
        meminfo_path=str(meminfo),
        self_status_path=str(status),
        cgroup_root=str(cgroup),
    )

    assert details["host"]["total_bytes"] == 1000 * 1024
    assert details["host"]["available_bytes"] == 400 * 1024
    assert details["host"]["used_percent"] == 60.0
    assert details["process"]["rss_bytes"] == 250 * 1024
    assert details["cgroup"]["current_bytes"] == 512
    assert details["cgroup"]["limit_bytes"] == 1024
    assert details["cgroup"]["used_percent"] == 50.0


def test_overall_selftest_status_distinguishes_degraded_from_error():
    assert _overall_selftest_status([_check_status("database", "ok", "ok")]) == "ok"
    assert _overall_selftest_status(
        [
            _check_status("database", "ok", "ok"),
            _check_status("ioc_sync", "degraded", "feed degraded"),
        ]
    ) == "degraded"
    assert _overall_selftest_status(
        [
            _check_status("database", "ok", "ok"),
            _check_status("redis", "error", "redis failed"),
            _check_status("ioc_sync", "degraded", "feed degraded"),
        ]
    ) == "error"


def test_data_integrity_check_passes_with_cross_source_overlap_only():
    check = _data_integrity_check(
        {
            "status": "ok",
            "duplicate_groups": {
                "normalized_ioc_value_type_source": 0,
                "normalized_cve_id": 0,
                "cross_source_ioc_overlap": 3,
            },
            "samples": {},
            "policy": {},
        }
    )

    assert check.name == "ioc_cve_dedup_integrity"
    assert check.status == "ok"
    assert "cross-source IOC overlap" in check.message


def test_data_integrity_check_fails_on_ioc_or_cve_duplicates():
    check = _data_integrity_check(
        {
            "status": "error",
            "duplicate_groups": {
                "normalized_ioc_value_type_source": 2,
                "normalized_cve_id": 1,
                "cross_source_ioc_overlap": 0,
            },
            "samples": {},
            "policy": {},
        }
    )

    assert check.status == "error"
    assert "2 normalized IOC duplicate" in check.message
    assert "1 CVE duplicate" in check.message


def test_data_integrity_check_reports_background_scan_without_blocking():
    check = _data_integrity_check(
        {
            "status": "running",
            "checked_at": None,
            "duplicate_groups": {},
            "samples": {},
            "policy": {},
        }
    )

    assert check.status == "warning"
    assert "running in the background" in check.message


def test_auth_readiness_passes_with_local_auth_disabled_warning(monkeypatch):
    monkeypatch.setattr("app.api.routes.system.settings.auth_enabled", False)

    check = _auth_readiness_check(total_users=0, enabled_users=0)

    assert check.name == "auth_readiness"
    assert check.status == "ok"
    assert check.details["auth_enabled"] is False
    assert "production_recommendation" in check.details


def test_auth_readiness_fails_when_enabled_without_users_or_bootstrap(monkeypatch):
    monkeypatch.setattr("app.api.routes.system.settings.auth_enabled", True)
    monkeypatch.setattr("app.api.routes.system.settings.auth_bootstrap_admin_password", "")

    check = _auth_readiness_check(total_users=0, enabled_users=0)

    assert check.status == "error"
    assert "no enabled user" in check.message


def test_auth_readiness_passes_with_enabled_user(monkeypatch):
    monkeypatch.setattr("app.api.routes.system.settings.auth_enabled", True)
    monkeypatch.setattr("app.api.routes.system.settings.auth_bootstrap_admin_password", "")

    check = _auth_readiness_check(total_users=2, enabled_users=1)

    assert check.status == "ok"
    assert check.details["enabled_users"] == 1


def test_storage_writable_check_creates_and_removes_probe(tmp_path):
    check = _storage_writable_check(tmp_path, "tmp_storage")

    assert check.status == "ok"
    assert check.details["writable"] is True
    assert not (tmp_path / ".adversarygraph-selftest").exists()


def test_asset_scanner_readiness_requires_configured_nmap_binary(monkeypatch, tmp_path):
    monkeypatch.setattr("app.api.routes.system.settings.asset_scanner_enabled", True)
    monkeypatch.setattr("app.api.routes.system.settings.asset_scanner_nmap_enabled", True)
    monkeypatch.setattr(
        "app.api.routes.system.settings.asset_scanner_nmap_binary",
        str(tmp_path / "missing-nmap"),
    )
    missing = _asset_scanner_readiness_check()
    assert missing.status == "error"
    assert missing.details["profile"] == "safe-service-discovery"

    monkeypatch.setattr("app.api.routes.system.settings.asset_scanner_nmap_enabled", False)
    passive_only = _asset_scanner_readiness_check()
    assert passive_only.status == "ok"
    assert passive_only.details["nmap_enabled"] is False


def test_taxonomy_normalization_check_warns_on_raw_tags():
    check = _taxonomy_normalization_check(
        {
            "checked_rows": 3,
            "normalized": False,
            "raw_tag_examples": {"ioc_indicators": ["phishing"]},
            "convention": "namespace:value",
        }
    )

    assert check.name == "taxonomy_normalized"
    assert check.status == "warning"
    assert "raw unnamespaced tags" in check.message


def test_taxonomy_normalization_check_passes_when_clean():
    check = _taxonomy_normalization_check(
        {
            "checked_rows": 3,
            "normalized": True,
            "raw_tag_examples": {},
            "convention": "namespace:value",
        }
    )

    assert check.status == "ok"
