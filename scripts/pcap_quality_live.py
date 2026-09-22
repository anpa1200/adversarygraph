"""Real local-platform regression. No answer keys or direct provider calls.

Public training marking is explicit; nothing is executed or submitted to file
scanners. Old benchmark records are read-only. Use a new output directory.
"""
import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["analyze", "enrich", "refresh", "recover", "story"])
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-training-confirmed", action="store_true")
    parser.add_argument("--case", action="append")
    parser.add_argument("--max-targets", type=int, default=30)
    parser.add_argument("--story-min-interval", type=float, default=65)
    parser.add_argument("--provider", default="openai", choices=["openai", "claude", "gemini"])
    args = parser.parse_args()
    if not args.public_training_confirmed:
        parser.error("Explicit public-training confirmation is required for source marking and external enrichment")
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    cases = json.loads((args.source / "cases.json").read_text())
    last_story_request = 0.0
    with httpx.Client(base_url="http://127.0.0.1:3000", timeout=300, trust_env=False) as client:
        for case in cases:
            if args.case and case["date"] not in args.case:
                continue
            folder = args.output / case["date"]; folder.mkdir(exist_ok=True, mode=0o700)

            def request(label, method, url, **kwargs):
                start = time.monotonic()
                response = client.request(method, url, **kwargs)
                try:
                    data = response.json()
                except ValueError:
                    data = {"detail": "Non-JSON platform response", "http_status": response.status_code,
                            "content_type": response.headers.get("content-type")}
                save(folder / (label + ".json"), data)
                save(folder / (label + "-http.json"), {"status": response.status_code, "seconds": round(time.monotonic()-start, 3),
                    "method": method, "url": url, "utc": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(response.content).hexdigest()})
                response.raise_for_status()
                return data

            if args.action == "analyze":
                if (folder / "native.json").exists():
                    continue
                with (args.source / case["date"] / case["filename"]).open("rb") as capture:
                    data = request("native", "POST", "/api/pcap/analyze", files={"file": (case["filename"], capture, "application/vnd.tcpdump.pcap")})
                assert data["source_sha256"] == case["source_sha256"]
                assert data["analyzer_manifest"]["profile_id"] == "tshark-evidence-v6"
                request("source-public", "PATCH", f"/api/analyze/sessions/{data['session_id']}/linked-report", json={"tlp": "TLP:CLEAR"})
                print(json.dumps({"case": case["date"], "analysis_id": data["analysis_id"], "objects": len(data["result"]["artifacts"])}), flush=True)
            elif args.action == "enrich":
                if (folder / "enriched.json").exists():
                    continue
                data = json.loads((folder / "native.json").read_text())
                data = request("before-enrichment", "GET", f"/api/pcap/analyses/{data['analysis_id']}")
                plan = data["assessment"]["enrichment_plan"]["items"]
                # Fixed small budget, ranking owned by platform, never answers.
                selected = [r for r in plan if r.get("queue_ready", not r["direct_checked"]) and r["priority"] >= 45][:min(60, max(1, args.max_targets))]
                save(folder / "enrichment-plan.json", {"selected_by": "platform-" + data["assessment"]["enrichment_plan"]["policy"], "max_targets": args.max_targets, "minimum_priority": 45, "items": selected})
                for i in range(0, len(selected), 10):
                    batch = selected[i:i+10]
                    providers = ["virustotal", "threatfox"]
                    if any(r["type"] in {"sha256", "sha1", "md5"} for r in batch):
                        providers.append("malwarebazaar")
                    data = request(f"enrich-{i//10+1}", "POST", f"/api/pcap/analyses/{data['analysis_id']}/enrich",
                                   json={"observable_ids": [r["observable_id"] for r in batch], "providers": providers, "consent": True})
                    print(json.dumps({"case": case["date"], "batch": i//10+1, "lookups": data["enrichment"]["coverage"]["provider_lookups_started"], "cache_hits": data["enrichment"]["coverage"]["cache_hits"]}), flush=True)
                save(folder / "enriched.json", data)
                (folder / "NATIVE-PCAP-REPORT.md").write_text(data["report"])
            elif args.action == "refresh":
                data = json.loads((folder / "enriched.json").read_text())
                if not (folder / "enriched-before-final-policy.json").exists():
                    save(folder / "enriched-before-final-policy.json", data)
                data = request("enriched", "GET", f"/api/pcap/analyses/{data['analysis_id']}")
                (folder / "NATIVE-PCAP-REPORT.md").write_text(data["report"])
                print(json.dumps({"case": case["date"], "refreshed_candidates": data["assessment"]["ioc_candidate_count"]}), flush=True)
            elif args.action == "recover":
                data = json.loads((folder / "enriched.json").read_text())
                artifacts = [a for a in data["result"]["artifacts"] if a.get("static_features", {}).get("content_kind") in {"pe", "ole-document"} or a["extraction_method"] != "tshark-http-export-objects"]
                checks = []
                for artifact in artifacts[:12]:
                    response = client.get(f"/api/pcap/analyses/{data['analysis_id']}/artifacts/{artifact['artifact_id']}/download")
                    response.raise_for_status()
                    content = response.content
                    checks.append({"artifact_id": artifact["artifact_id"], "sha256": hashlib.sha256(content).hexdigest(), "size_bytes": len(content),
                                   "match": hashlib.sha256(content).hexdigest() == artifact["sha256"] and len(content) == artifact["size_bytes"],
                                   "extraction_method": artifact["extraction_method"], "disposition": response.headers.get("content-disposition"), "executed": False})
                    assert checks[-1]["match"]
                save(folder / "recovery-validation.json", checks)
                print(json.dumps({"case": case["date"], "recovered_and_verified": len(checks)}), flush=True)
            else:
                workspace = json.loads((folder / "workspace-native-full.json").read_text())
                report = [n for n in workspace["evidence_nodes"] if n["type"] == "investigation-report"][-1]
                if (folder / "story.json").exists():
                    previous = json.loads((folder / "story.json").read_text())
                    if previous.get("type") == "investigation-summary" and previous.get("report_id") == report["id"]:
                        continue
                    save(folder / f"story-attempt-{time.time_ns()}.json", previous)
                request("workspace-marking", "PATCH", f"/api/operations/investigations/{workspace['id']}/marking", json={"tlp": "TLP:CLEAR", "reason": "Public malware-traffic-analysis.net training capture and public reputation only; no private enterprise evidence."})
                try:
                    preflight = request("story-preflight", "GET", f"/api/operations/investigations/{workspace['id']}/summary/preflight", params={"report_id": report["id"]})
                except httpx.HTTPStatusError as exc:
                    save(folder / "story.json", {"detail": "Preflight failed; no inference was attempted", "http_status": exc.response.status_code})
                    print(json.dumps({"case": case["date"], "preflight_http_error": exc.response.status_code}), flush=True)
                    continue
                provider = next(p for p in preflight["providers"] if p["id"] == args.provider)
                if not provider["available"] or preflight["effective_tlp"] != "TLP:CLEAR":
                    save(folder / "story.json", {"detail": "Provider blocked by governed disclosure policy; no inference attempted", "effective_tlp": preflight["effective_tlp"]})
                    print(json.dumps({"case": case["date"], "policy_blocked": True}), flush=True)
                    continue
                print(json.dumps({"case": case["date"], "model": provider["model"], "evidence_chars": preflight["coverage"]["source_characters"]}), flush=True)
                while last_story_request and time.monotonic() - last_story_request < args.story_min_interval:
                    time.sleep(min(55, args.story_min_interval - (time.monotonic() - last_story_request)))
                try:
                    last_story_request = time.monotonic()
                    result = request("story", "POST", f"/api/operations/investigations/{workspace['id']}/summary", json={"report_id": report["id"], "provider": args.provider, "cloud_processing_acknowledged": True})
                    (folder / "STORY.md").write_text(result["content"])
                    print(json.dumps({"case": case["date"], "story_status": result["status"], "model": result["model"]}), flush=True)
                except httpx.HTTPStatusError as exc:
                    print(json.dumps({"case": case["date"], "story_http_error": exc.response.status_code}), flush=True)
                finally:
                    # A native repair may have made a second request late in
                    # the call. Pace the next case from completion, not start.
                    last_story_request = time.monotonic()


if __name__ == "__main__":
    main()
