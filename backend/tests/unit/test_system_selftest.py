from app.api.routes.system import (
    _cpu_percent_from_totals,
    _format_bytes,
    _memory_usage_details,
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
