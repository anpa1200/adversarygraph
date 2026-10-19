# AdversaryGraph 8.1 release acceptance

The 8.1 stable source promotes the reviewed ATT&CK v20 and evidence/workflow
changes. The historical [8.0 beta matrix](release-readiness-v8.md) remains a
record of that earlier candidate, not a claim that optional integrations have
all been configured or manually accepted.

## Required publication gates

- Consistent 8.1.0 metadata and versioned release notes.
- Full current-head CI: backend tests and coverage, PostgreSQL schema/migration
  authority and transactional regressions, frontend browser/build/audit,
  scanner tests, docs build/audit, Helm/Compose validation, secret and image scans.
- Protected immutable tag policy; exact tag-to-source identity throughout publication.
- Nine scanned image identities, public immutable digests and attached manifest.

The release workflow is the authoritative publication gate. Source tests passed
on the reconciled candidate before promotion; the final stable commit must pass
its own CI and tag workflow. No missing check is represented as passed.

## Deployment acceptance

Retain backup and rollback configuration, run schema gates before serving,
verify API health/version, all three ATT&CK domains, historical snapshots,
existing evidence and read-only export round trips. Preserve the Review Gate.

Provider/TLP authorization, semantic embedding endpoints, SIEM forwarding,
external assessment targets, optional MCP sessions and multi-operator workflows
remain deployment-specific. They are not universally certified by a source
release. Do not infer semantic readiness from exact/FTS fallback, and do not
promote or export unreviewed evidence to satisfy a smoke test.
