# AdversaryGraph v6.0.0 Release Summary

AdversaryGraph v6.0.0 turns the accumulated v5 feature set into a more
reviewable operational release. The emphasis is evidence: one command for the
release gate, current reproducible screenshots, deterministic local case
studies, corrected historical records, explicit production acceptance
criteria, and a documented rollback path.

## Release Outcome

- A reviewer can trace the complete evolution from v5.0 Attack Simulation to
  v5.9.1 network-fingerprint investigation in one overview.
- An operator can run the same metadata, build, browser, backend, Compose, and
  security checks used to judge the release.
- A security team can evaluate workflows with fictional repository data rather
  than customer reports, credentials, malware, or private telemetry.
- A deployment owner gets an explicit go/no-go checklist instead of a generic
  “production ready” claim.
- Visual evidence is generated from the current production frontend build with
  deterministic fixtures and recorded limitations.

## Production Claim

v6.0.0 is suitable for controlled self-hosted production when the operator
passes the release-readiness checklist and supplies TLS, authentication,
network isolation, secrets management, backups, monitoring, retention policy,
and an approved data-handling process.

It is not a managed SaaS, a multi-tenant isolation boundary, or safe for direct
internet exposure with default settings.

## Evidence

- [Release readiness guide](release-readiness-v6.md)
- [v6 case studies](case-studies-v6.md)
- [v6 screenshot manifest](assets/adversarygraph-v6/manifest.md)
- [Complete v5 overview](v5-overview.md)
- [Validation and limitations](validation-and-limitations.md)
- [Security threat model](security-threat-model.md)
- [Production readiness](production-readiness.md)
