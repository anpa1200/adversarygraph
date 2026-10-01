# Review guide: CTI-to-detection workbench

Andrey Pautov owns the CTI workflow, backend, frontend and documentation (see [MAINTAINERS.md](MAINTAINERS.md)). His contribution is the analyst workflow and evidence model around report ingestion, ATT&CK/ATLAS mapping, graph reasoning and detection review. MITRE data, external reports and integrated tools remain third-party work.

## Architecture and contribution

React workspace → FastAPI services → PostgreSQL/evidence records → reviewed mappings and detection candidates. AI adapters provide proposals that require analyst review.

Role relevance: CTI platform engineering, detection workflow design, full-stack security delivery.

## Safe reproducible quickstart

Run from the repository root. Python 3; no extra packages or service credentials required.

```bash
python3 demo/check_portfolio_fixture.py
```

Expected result:

```text
PASS: 7 technique expectations, 6 IOC expectations, 9 graph edges
```

These commands use committed or generated benign/synthetic input. They do not execute malware, invoke a hosted provider, scan a target or require credentials.

## Evidence to inspect

[Synthetic evidence graph](demo/evidence-graph/expected-graph.json) · [Architecture](docs/evidence-to-detection-graph.md)

![Historical v4 workspace screenshot](docs/assets/adversarygraph-v4-platform/04-ai-analysis.png)

Committed historical v4 screenshot; not a new capture or proof of current beta behavior.

## Validation and limitations

This verifies relationships among committed synthetic expectations; it does not run the backend, a model, containers or a SIEM. The graph’s staged/pass fields are illustrative fixture values, not measurements from this run.

See [validation.md](validation.md) for checks performed on the exact source snapshot, verified results and capabilities not run. Existing release/CI claims remain historical repository statements, not fresh certification.

Preserve the full [README](README.md) and original technical documentation for installation, deployment and capability details.
