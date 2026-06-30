# Deployment Sizing Guide

This guide gives starting points for controlled self-hosted deployments. Actual
requirements depend on feed volume, number of analysts, LLM provider latency,
uploaded report size, malware-analysis workload, and Attack Simulation usage.

## Profiles

| Profile | Analysts | CPU | RAM | Disk | Recommended Use |
|---|---:|---:|---:|---:|---|
| Small | 1-3 | 4 vCPU | 8-12 GiB | 80-150 GiB SSD | Lab, evaluation, private analyst workstation |
| Medium | 3-10 | 8 vCPU | 24-32 GiB | 250-500 GiB SSD | Internal CTI/detection team with scheduled feeds |
| Large | 10-30 | 16 vCPU | 48-64 GiB | 1 TiB+ SSD | Shared team deployment, broad IOC/CVE/feed sync, heavier malware triage |

## Per-Service Starting Points

| Service | Small | Medium | Large |
|---|---:|---:|---:|
| PostgreSQL | 1 vCPU / 2 GiB | 2 vCPU / 4-8 GiB | 4 vCPU / 16 GiB |
| API | 1-2 vCPU / 2 GiB | 2 vCPU / 4 GiB | 4 vCPU / 8 GiB |
| Worker | 1-2 vCPU / 2-3 GiB | 2-4 vCPU / 6-8 GiB | 6-8 vCPU / 16 GiB |
| Redis | 0.5 vCPU / 512 MiB | 1 vCPU / 1 GiB | 2 vCPU / 2 GiB |
| MalwareGraph | 1-2 vCPU / 2 GiB | 2-4 vCPU / 4-8 GiB | 4-8 vCPU / 16 GiB |
| Frontend | 0.5 vCPU / 256 MiB | 0.5 vCPU / 512 MiB | 1 vCPU / 1 GiB |

## Disk Planning

Plan storage for:

- PostgreSQL database: ATT&CK/ATLAS, APTs, IOCs, CVEs, reports, cases, users.
- `adversarygraph_logs`: API logs, Attack Simulation logs, observability log tail.
- `malwaregraph_storage`: uploaded samples, extracted artifacts, static-analysis output.
- `attck_data`: cached ATT&CK/ATLAS bundles.
- Backups: at least 7-30 logical dumps, depending on retention.

Suggested baseline:

- Small: 80 GiB SSD plus 80 GiB backup target.
- Medium: 250 GiB SSD plus 500 GiB backup target.
- Large: 1 TiB SSD plus 2 TiB backup target.

## Operational Notes

- Keep PostgreSQL data on persistent SSD-backed storage.
- Keep backups outside the primary data directory.
- Disable `AUTO_IOC_FULL_SYNC_ON_STARTUP` in production and run feed sync on a
  planned schedule.
- Enable auth before exposing the UI beyond localhost.
- Use an external reverse proxy or ingress for TLS.
- Monitor `/api/health`, `/api/observability/summary`, and service logs.
