from app.services.cve_intel import _normalize_osv_ecosystem, _parse_ghsa_advisory, _parse_osv_vuln


def test_parse_github_advisory_imports_cve_and_package_tags():
    item = {
        "ghsa_id": "GHSA-test-1234",
        "cve_id": "CVE-2026-12345",
        "summary": "Package vulnerability",
        "description": "Affected package can be exploited remotely.",
        "severity": "critical",
        "published_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
        "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cwes": [{"cwe_id": "CWE-22"}],
        "references": ["https://github.com/advisories/GHSA-test-1234"],
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "demo-package"}}],
    }

    parsed = _parse_ghsa_advisory(item)

    assert parsed is not None
    assert parsed.cve_id == "CVE-2026-12345"
    assert parsed.source_id == "github-advisory-database"
    assert parsed.cvss_severity == "CRITICAL"
    assert "ecosystem-npm" in parsed.tags
    assert "dependency:demo-package" in parsed.tags
    assert "product-security" in parsed.tags


def test_parse_osv_vulnerability_imports_cve_alias_and_query_package():
    vuln = {
        "id": "GHSA-test-5678",
        "aliases": ["CVE-2026-5555"],
        "summary": "OSV package issue",
        "details": "Dependency is vulnerable.",
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-03T00:00:00Z",
        "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/GHSA-test-5678"}],
    }

    parsed = _parse_osv_vuln(vuln, {"name": "urllib3", "ecosystem": "PyPI", "version": "1.26.18"})

    assert len(parsed) == 1
    assert parsed[0].cve_id == "CVE-2026-5555"
    assert parsed[0].source_id == "osv-dev"
    assert "ecosystem-PyPI" in parsed[0].tags
    assert "dependency:urllib3" in parsed[0].tags
    assert parsed[0].raw["queried_package"]["version"] == "1.26.18"


def test_normalize_osv_ecosystem_aliases():
    assert _normalize_osv_ecosystem("python") == "PyPI"
    assert _normalize_osv_ecosystem("go-module") == "Go"
    assert _normalize_osv_ecosystem("composer") == "Packagist"
