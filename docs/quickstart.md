# Quickstart

This guide starts a local ThreatMapper Docker deployment for evaluation.

## Prerequisites

- Docker Engine and Docker Compose v2.
- 8 GB RAM available to Docker.
- At least one LLM provider key for AI report extraction.

The public browser workspace at <https://1200km.com/threat-matrix/> does not require Docker, but it also does not process private reports or store backend analyses.

## 1. Clone

```bash
git clone https://github.com/anpa1200/threatmapper.git
cd threatmapper
```

## 2. Configure

```bash
cp .env.example .env
```

Edit `.env` and set at least one provider key:

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
```

For private analysis, use an operator-controlled LLM gateway and review the provider's data-retention terms.

## 3. Start

```bash
docker compose up --build
```

First startup ingests MITRE ATT&CK STIX data into PostgreSQL. This can take several minutes.

## 4. Open

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API docs | http://localhost:8000/docs |
| Health | http://localhost:8000/api/health |
| Anomaly Detection Atlas | http://localhost:3001/anomaly-detection-atlas/ |

## 5. Smoke Test

```bash
curl http://localhost:8000/api/health
curl "http://localhost:8000/api/attack/versions"
```

Expected health response:

```json
{"status":"ok","version":"0.9.0"}
```

## 6. Demo Workflow

1. Open the frontend.
2. Select Enterprise ATT&CK.
3. Paste a public CTI excerpt from `docs/demo-dataset/public-report-excerpt.md`.
4. Run analysis with the configured provider.
5. Review the extracted techniques.
6. Compare against known groups and campaigns.
7. Export a Navigator layer, JSON report, or PDF report.

Do not use confidential reports in public or third-party environments.
