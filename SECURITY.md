# Security Policy

## Supported Versions

AdversaryGraph **v5.6.0** is the current feature milestone release.
The project is a self-hosted/internal analyst workbench, not a hardened multi-tenant SaaS.
Security fixes are applied to the latest `main` branch and the latest tagged release.

| Version | Supported |
|---|---|
| latest `main` | Yes |
| latest tagged release (`v5.6.0`) | Yes |
| older tags (`v4.x` and below) | Best effort |

## Reporting a Vulnerability

Do not open a public issue for vulnerabilities involving data exposure, authentication bypass, secret handling, arbitrary file access, or unsafe report parsing.

Report privately by email:

```text
1200km@gmail.com
```

Include:

- Affected component: frontend, API, parser, export, Docker deployment, or docs.
- Impact and attack preconditions.
- Reproduction steps.
- Whether the issue affects self-hosted deployments, the public web workspace, or both.
- Suggested mitigation if known.

## Data Handling Model

- AdversaryGraph Docker stores report analysis data in the operator-controlled PostgreSQL database.
- Uploaded report text is sent only to the LLM provider configured by the operator.
- The public web workspace is for exploration and should not receive confidential, customer-sensitive, classified, or internal reports.
- Operators who need private processing should use a local or private LLM gateway and isolate the deployment behind an authenticated reverse proxy.

## Deployment Boundary

The default Docker Compose profile is for local or controlled self-hosted use. Internet-facing deployments require:

- TLS termination.
- Native authentication enabled or identity-aware reverse-proxy authentication.
- Network restrictions for PostgreSQL, Redis, API, and worker services.
- Secret rotation and non-default database credentials.
- Backups, retention policy, and restore testing.
- Review of LLM provider data-retention terms.

## Known Security Limitations

- The default deployment is not a hardened multi-tenant SaaS.
- LLM outputs are untrusted and require analyst review.
- File parsing is bounded but should still be run in a controlled environment for untrusted documents.
- Generated detection logic is a draft and must not be deployed without local review and testing.
- Starlette/FastAPI transitive dependencies are audited in CI with `pip-audit`. Operators who route public traffic through AdversaryGraph should still ensure a trusted reverse proxy normalizes the `Host` header before it reaches the backend.
