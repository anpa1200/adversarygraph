# Security Model

ThreatMapper is a self-hosted analyst workbench, not a managed SaaS.

## Trust Boundaries

| Boundary | Trust Assumption |
|---|---|
| Browser to frontend | User has access to the workspace |
| Frontend to API | API is reachable from the operator-controlled network |
| API to PostgreSQL | Database is private to the deployment |
| API/worker to LLM provider | Operator controls provider choice and accepts provider data terms |
| API to MITRE/GitHub | Public ATT&CK STIX bundles are downloaded for sync |
| API to IOC feeds | Operator controls ThreatFox, OTX, and custom feed credentials/URLs |

## Sensitive Data

Potentially sensitive data includes:

- Uploaded reports.
- Extracted text from reports.
- LLM raw responses.
- Analyst notes.
- Campaign or customer names.
- IOC feed contents and actor-linked indicators.
- Custom feed URLs.
- Exported PDF/JSON reports.
- API keys.

## Public Workspace

The public web workspace is for exploration. It should not receive:

- Customer reports.
- Internal incident data.
- Classified or restricted data.
- Credentials.
- Private victim details.

## Self-Hosted Workspace

For private analysis:

- Deploy locally or inside a trusted network.
- Use non-default database credentials.
- Use private LLM infrastructure if provider transmission is not acceptable.
- Restrict access through a reverse proxy.
- Back up and purge data according to local policy.

## LLM Output

LLM output is treated as untrusted:

- Mappings require analyst review.
- Similarity scores are investigation leads.
- Generated detection logic is draft material.
- Exports should include limitations when used in a report.

## File Parsing

ThreatMapper supports text, PDF, and DOCX extraction. Operators should treat uploaded documents as untrusted and run the platform in a controlled environment.

## IOC Feeds

IOC feeds are operational data, not stable reference data. Operators should:

- keep ThreatFox/OTX keys out of commits and screenshots;
- review custom feed provenance before import;
- avoid importing customer-private feeds into public demos;
- define retention and export rules for actor IOC CSVs;
- treat extracted IOCs from uploaded reports as untrusted until reviewed.
