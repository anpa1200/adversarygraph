# Security Threat Model

AdversaryGraph is a self-hosted analyst workbench for controlled environments. This document describes expected trust boundaries and the security assumptions reviewers should use when evaluating the project.

## Assets

| Asset | Why it matters |
|---|---|
| Uploaded reports and extracted text | May contain customer, incident, or victim-sensitive details |
| Stored investigations and analyst notes | May contain private conclusions and operational context |
| IOC feeds and enrichment results | May include restricted source data or private indicators |
| Malware-analysis artifacts | Potentially hostile files, strings, unpacked outputs, and debugger notes |
| Attack Simulation SIEM targets | May identify internal collectors or validation systems |
| API keys and provider tokens | Enable external LLM, CTI, IOC, and enrichment calls |

## Trust Boundaries

| Boundary | Expected control |
|---|---|
| Browser to frontend | Operator-controlled network or authenticated reverse proxy |
| Frontend to API | Same deployment boundary; no direct public API exposure by default |
| API to PostgreSQL/Redis | Internal Compose network only |
| API to LLM providers | Operator-selected provider; operator accepts provider data handling terms |
| API to feed URLs | SSRF-safe fetch logic blocks localhost, private, link-local, reserved, and metadata ranges |
| API to SIEM collector | Explicit operator-provided HTTP(S) destination for telemetry forwarding |
| AdversaryGraph to MalwareGraph | Isolated service boundary; analysis artifacts are imported back, not raw runtime control |
| Attack Simulation to lab fixtures | Approved local lab targets only; no arbitrary internet target execution |

## Main Threats

| Threat | Mitigation |
|---|---|
| Public demo data leakage | Public demo warning in docs and UI guidance; private work should use self-hosted deployment |
| Secret leakage in repository | `.env.example` contains placeholders only; CI includes gitleaks secret scan |
| SSRF through feed import or SIEM forwarding | Safe URL validation rejects unsafe schemes and metadata/link-local/private ranges for fetches; SIEM forwarding is explicit and logs destination use |
| LLM hallucination or overconfident mapping | Review states, validation docs, limitation notices, and evidence-based mapping workflow |
| Untrusted file parsing | Controlled deployment guidance and bounded parser usage; malware workflows stay behind MalwareGraph boundary |
| Malware execution in app containers | Not allowed by default; runtime debugging requires isolated disposable MalwareGraph profiles |
| Internet-exposed default stack | Default Compose binds UI/docs/PostgreSQL to localhost and leaves API/Redis/internal services unexposed |
| Overclaiming synthetic telemetry | Docs separate real lab telemetry from synthetic AI-generated telemetry |

## Required Operator Hardening

Before exposing AdversaryGraph beyond a trusted local network:

- Put the frontend/API behind TLS.
- Enable native authentication with `AUTH_ENABLED=true`; use trusted-header authentication with a strong `PROXY_SECRET` only behind an identity-aware reverse proxy.
- Set `CORS_ALLOWED_ORIGINS` to the exact production origin.
- Rotate `DB_PASS`, `REDIS_PASSWORD`, LLM keys, and CTI provider tokens.
- Restrict PostgreSQL, Redis, MalwareGraph, and lab fixtures to internal networks.
- Configure backups, retention policy, monitoring, and audit log retention.
- Decide which data may be sent to cloud LLM and enrichment providers.

## Residual Risk

AdversaryGraph remains an analyst-assistance tool. AI-generated mappings, generated detections, malware-analysis summaries, synthetic attack telemetry, and similarity scores can be wrong. Treat them as review material, not authoritative output.
