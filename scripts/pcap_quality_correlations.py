"""Read-only verification of stored local correlation edges, not attribution."""
import argparse
import ipaddress
import json
from pathlib import Path

import httpx


def key(kind, value):
    if kind in {"ipv4", "ipv6"}:
        return kind, str(ipaddress.ip_address(value))
    return kind, value.lower().rstrip(".") if kind == "domain" else value.lower()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cache = {}
    total = 0
    with httpx.Client(base_url="http://127.0.0.1:3000", timeout=60, trust_env=False) as client:
        for path in sorted(args.output.glob("????-??-??/enriched.json")):
            data = json.loads(path.read_text())
            own = {key(o["type"], o["value"]) for o in data["result"]["observables"] if o["type"] in {"ipv4", "ipv6", "domain", "sha256"}}
            checks = []
            for edge in data.get("context", {}).get("cross_case_correlations", []):
                target = edge["analysis_id"]
                if target not in cache:
                    response = client.get(f"/api/pcap/analyses/{target}")
                    response.raise_for_status()
                    other = response.json()
                    cache[target] = {"source_sha256": other["source_sha256"],
                                     "keys": {key(o["type"], o["value"]) for o in other["result"]["observables"] if o["type"] in {"ipv4", "ipv6", "domain", "sha256"}}}
                other = cache[target]
                shared = {key(o["type"], o["value"]) for o in edge["shared_observables"]}
                low_specificity = []
                for kind, value in shared:
                    if kind in {"ipv4", "ipv6"}:
                        address = ipaddress.ip_address(value)
                        if not address.is_global or address.is_multicast:
                            low_specificity.append({"type": kind, "value": value})
                checks.append({"analysis_id": target, "source_hash_matches_edge": other["source_sha256"] == edge["source_sha256"],
                               "different_capture": other["source_sha256"] != data["source_sha256"],
                               "shared_values_verified_in_both": shared <= own and shared <= other["keys"],
                               "shared_rows": len(shared), "reported_shared_count": edge["shared_count"],
                               "scope": edge["status"], "non_specific_address_overlaps": low_specificity})
            result = {"scope": "Local overlap checks only. No same actor, campaign or maliciousness conclusion.", "checks": checks,
                      "all_edges_valid": all(c["source_hash_matches_edge"] and c["different_capture"] and c["shared_values_verified_in_both"] for c in checks)}
            (path.parent / "correlation-validation.json").write_text(json.dumps(result, indent=2) + "\n")
            assert result["all_edges_valid"]
            total += len(checks)
            print(json.dumps({"case": path.parent.name, "edges_verified": len(checks), "low_specificity_edges": sum(bool(c["non_specific_address_overlaps"]) for c in checks)}), flush=True)
    print(json.dumps({"total_edges_verified": total, "distinct_related_records_read": len(cache)}))


if __name__ == "__main__":
    main()
