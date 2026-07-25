# AdversaryGraph v6.5.0 Release Summary

AdversaryGraph v6.5.0 consolidates the complete development line after v6.0.0
into one governed self-hosted threat-operations release. It connects threat
intelligence, hunting, query engineering, asset exposure assessment, detection
validation, and SOC access control while keeping analyst decisions and source
evidence explicit.

## What Changes for Analysts

- Threat hunters can move from a stored report or hypothesis to bounded scope,
  ATT&CK mappings, telemetry requirements, a versioned query, reviewed
  findings, and a documented outcome.
- Query engineers can search reviewed and community-backed Sigma/YARA-L
  material, generate typed queries from IOCs, and hand a draft into a hunt
  without representing it as executed or validated.
- CTI analysts can search a normalized IOC/CVE/TTP/actor/report corpus with
  exact, full-text, optional vector, and bounded relationship retrieval.
- Navigator users can request a cited answer or temporary TTP proposal and
  explicitly confirm verified technique IDs.
- Asset and vulnerability teams can open a saved company asset, review
  evidence-labelled CVE/TTP/IOC context, run an authorized bounded assessment,
  and selectively merge newly observed inventory facts.
- SOC teams can use named accounts and least-privilege groups whose module and
  action policy is enforced in both the interface and API.

## Product Scope

The release contains 31 governed workspaces across intelligence, analysis,
hunting, operations, platform administration, and support. The generated
contract reference covers 28 API groups and 322 operations. The
[Module Reference and Casebook](module-reference.md) provides an end-to-end
workflow, worked example, case study, and limitation statement for every
workspace.

## Trust Boundary

AdversaryGraph is advisory and evidence-preserving:

- it does not autonomously attribute an actor;
- it does not execute hunt queries against an external telemetry system;
- it does not treat provider results or detected services as confirmed
  vulnerabilities;
- it does not confirm Navigator proposals or save layers without analyst action;
- it does not allow MCP to bypass the application API or mutate operational
  state; and
- it does not make synthetic attack telemetry equivalent to real lab evidence.

## Release State

The source metadata is v6.5.0. The earlier v6.1.0 source milestone was never
published as a stable release and is superseded. Until the protected v6.5.0 tag
workflow completes, v6.0.0 remains the latest published immutable release and
its evidence must not be presented as v6.5 evidence.

The complete local release gate is:

```bash
./scripts/release-readiness.sh --full
```

Candidate validation on 2026-07-25 completed the canonical full readiness
wrapper in one fail-closed run. Its strict stage rebuilt and scanned all seven
custom image families plus the pinned Redis, BusyBox, and Nginx dependencies
with no fixable high- or critical-severity findings under the release policy.
See the release notes for the complete test counts and documented moderate
frontend advisories.

Immutable release acceptance additionally requires successful merge CI and the
tag workflow's image, scan, registry-readability, digest, metadata, and tag
protection checks.

See the [complete release notes](release-notes/v6.5.0.md),
[version matrix](version-matrix.md),
[release-readiness guide](release-readiness-v6.md), and
[production-readiness boundary](production-readiness.md).
