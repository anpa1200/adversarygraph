# AdversaryGraph Demo Dataset

This dataset gives reviewers deterministic input for evaluating report mapping,
IOC extraction, asset-surface analysis, Evidence-to-Detection Graph reasoning,
and SIEM telemetry handling without using private data.

## Files

| File | Purpose |
|---|---|
| `sample-report.md` | Public-style CTI report excerpt with ATT&CK behaviors and IOCs |
| `firewall.log` | Firewall/proxy-like egress and scan events |
| `edr.jsonl` | Endpoint process, file, and credential-access telemetry |
| `iocs.csv` | IOC import sample |
| `asset-inventory.csv` | Asset Surface inventory sample |
| `expected-techniques.json` | Expected ATT&CK technique candidates |
| `expected-iocs.json` | Expected IOC extraction output |
| `expected-navigator-layer.json` | Expected Navigator-style layer |
| `expected-report.md` | Expected analyst summary shape |
| `evidence-graph/` | Safe synthetic evidence-to-detection graph demo with report, logs, IOCs, assets, expected graph, expected gaps, and expected report |

## Review Flow

1. Upload or paste `sample-report.md` into AI Analysis.
2. Import `iocs.csv` into IOC workflows or paste values into IOC Investigation.
3. Upload `asset-inventory.csv` into Asset Surface.
4. Forward or ingest `firewall.log` and `edr.jsonl` into a test SIEM/parser.
5. Open Evidence Graph and create/import a draft reasoning path using
   `evidence-graph/sample-report.md`, `evidence-graph/sample-logs.jsonl`,
   `evidence-graph/sample-iocs.csv`, and `evidence-graph/sample-assets.csv`.
6. Compare the result to the expected JSON files.

Expected outputs are not ground truth for every model response. They are a stable baseline for checking that the platform extracts the obvious behaviors, keeps evidence visible, and avoids treating AI output as final attribution.

The Evidence Graph demo uses only fictional activity, `example.com`, and
RFC5737 documentation IP ranges. It does not include real malware, private
customer data, secrets, or operational attack instructions.
