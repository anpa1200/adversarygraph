# ATT&CK v20 rollout: security gate follow-up

The ATT&CK update is PR #36. Deployment remains subject to the existing CI security thresholds; none are disabled or relaxed. Findings below were observed on 19 October 2026.

## Compatible fixes included

- Backend urllib3 2.7.0 → 2.8.0 resolves PYSEC-2026-4175, PYSEC-2026-4176 and PYSEC-2026-4177.
- Backend and scanner MCP 1.28.1 → 1.30.0 resolves CVE-2026-59951 while retaining the v1 API.
- Frontend brace-expansion 5.0.12 and DOMPurify 3.4.16 plus compatible lockfile refresh reduce the npm audit findings from 14 to 7.
- The pinned stable-alpine nginx digest is refreshed consistently in Compose, CI, release scanning and validation scripts. The inspected image contains nginx 1.30.6-r1 and OpenSSL libraries 3.5.9-r0. The unchanged site configuration passes nginx -t in an isolated container.

Validation: backend 1,486 passed / 180 skipped (71.79% coverage); scanner 8 passed; frontend build and 19 browser tests passed. Backend and scanner requirement audits report zero advisories. The final documentation clean install, production build and image-size boundary test pass. The TLS test stub supports urllib3's tuple result while retaining hostname and certificate verification assertions.

## Remaining release decisions

- Frontend audit still reports 5 high and 2 moderate findings. The braces advisory GHSA-vfj7-8cjw-p6xm affects every published braces version. The vulnerable chain includes Tailwind 3, chokidar, fast-glob and micromatch. npm recommends Tailwind 4.3.3 as a semver-major migration. This needs a deliberate CSS migration and visual regression review, not an audit bypass.
- The separately bundled malwaregraph UI fails its Compose build at its own npm audit. Its source is pinned to upstream commit 79f604c6b59522cc993c82d32e081e8357bba98a and has a related Tailwind 3 dependency chain. Update and validate that integration independently.
- The anomaly documentation application has a separate vulnerable dependency tree. The initial hosted audit reported 66 findings (17 critical, 28 high, 21 moderate); npm's complete remediation proposes a breaking Docusaurus change. Compatible-only fixes reduce this to 47 (15 critical, 19 high, 13 moderate), including a Docusaurus patch update from 3.10.1 to 3.10.2 and ip-address 10.7.4; do not force a framework migration without build and content regression validation.
- The available Redis 7-alpine/7.4.11-alpine digest 858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499 still contains OpenSSL 3.3.7-r1; the reported fixed package revision for CVE-2026-84782 is r2. Therefore this change does not claim that the currently published replacement resolves all Redis image findings. The existing Redis pin is retained pending a fixed compatible image.

## Existing deployment baseline

The running local deployment reports 8.1.0-beta.1 and uses investigation image builds and Compose overlays outside this clean checkout. It already has official ATT&CK 20.0 current in all three domains (Enterprise 706, Mobile 125, ICS 104), with historical snapshots preserved. The PR's main-branch baseline is 8.0.0-beta.1. Reconcile this newer deployment's source and overlays before applying this PR to that runtime; replacing it directly would overwrite unrelated work. No production reingestion or database mutation is necessary for the version update.
