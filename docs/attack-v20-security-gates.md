# ATT&CK v20 and preserved local beta validation

The 8.1.0-beta.2 source candidate reconciles the reviewed ATT&CK changes with the running 8.1 investigation source. It is an unpublished local beta, not a public release. Existing audit severity thresholds, secret scans, database safety rules, authentication and disclosure settings remain enforced.

## Dependency fixes

- Backend/scanner urllib3 2.8.0 and MCP 1.30.0 retain their supported compatible API lines.
- Frontend uses Tailwind 4.3.3 with its PostCSS adapter and retained theme configuration; compatible axios patches clear the audit.
- The pinned malwaregraph UI migration uses Tailwind 4 and React Router 7.18.4. Its backend source was compared with the running integration before changes.
- Docusaurus stays on supported 3.10.2; TinyPool 2.2.0 and selector-parser 7.1.6 resolve their advisories. The complete clean build and dependency audit pass.
- Upstream braces 3.0.3 has no fixed release for CVE-2026-93687. The clearly named local @adversarygraph/braces-guard package retains the upstream MIT source and guards every public recursive entry point. Tests reject excessive nesting, long strings, excessive/cyclic ASTs and preserve ordinary glob behavior. This is a repository-maintained mitigation, not an upstream fix. See vendor/braces-guard/SECURITY.md for limits and residual risk; do not expose build glob APIs to network-supplied patterns. No advisory is ignored.
- Patched Redis/nginx Dockerfiles start from immutable official image digests and install exact supported Alpine security package revisions. CI builds and scans those derived images with the unchanged high/critical failure threshold. Production registry overrides must still be immutable digests; local builds use local tags.
- Nuclei remains on its pinned official source, with Go 1.26.9 and fixed transitive modules; the runtime Debian security refresh has an explicit cache epoch. Module/version assertions and image scans fail closed.

## Validation

Full reconciled backend: 1639 passed, 180 skipped, 72.51% coverage. The investigation fixtures now follow the running image's timeout and passage-citation protocol; provider caches are isolated between tests. Runtime security controls and production image-immutability requirements remain enforced. Frontend full browser run: 70 passed and four conditional skips; the one ambiguous locator was corrected to assert the actual Navigator link, and its affected test file passes. Source module/version checks pass. Final image scan and hosted CI receipts accompany deployment evidence.

No production ATT&CK reimport is needed: all three runtime domains already contain official v20 snapshots, with history retained. The update preserves existing volumes and uses recoverable image/config/database backups.
