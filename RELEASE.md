# Release Process

Use this checklist for reviewer-friendly AdversaryGraph releases.

## Pre-Release

- Update `VERSION`.
- Update `frontend/package.json` and `frontend/package-lock.json`.
- Update backend API version in `backend/app/core/version.py`.
- Update Helm chart/app versions and default application image tags.
- Move `CHANGELOG.md` entries from unreleased work into a dated version.
- Add `docs/release-notes/vX.Y.Z.md`.
- Add `docs/release-summary-vX.Y.Z.md` and update
  `docs/version-matrix.md`, `ROADMAP.md`, `SECURITY.md`, and current guides.
- Regenerate `docs/api-reference.md` with
  `./scripts/check-api-contracts.py --write-docs`.
- Run `python3 scripts/check-module-docs.py` so every governed backend module
  has exactly one detailed reference entry.
- Confirm sample outputs and demo dataset still match the documented workflow.
- Confirm no secrets, private reports, credentials, or customer data are added.
- Confirm an active GitHub tag ruleset blocks updates and deletion of existing
  `v*` tags without bypass actors. The workflow verifies this policy and
  repeatedly checks the remote tag target; publication stops when either gate
  is absent.
- If unified RAG schema or embedding settings changed, document the database
  migration, pgvector prerequisite, reindex plan, derived-data retention, and
  rollback behavior. Never change `RAG_EMBEDDING_DIMENSIONS` on an existing
  corpus without a reviewed schema migration and full reindex.
- Keep the MCP surface stdio-only unless an independently reviewed remote
  authorization design is implemented. Do not add proposal confirmation,
  reindexing, layer mutation, feed administration, or response actions to its
  tool allowlist as part of a routine release.
- For an Atlas update, set the reviewed full `ATLAS_REPOSITORY_REF` in
  `.env.example`, run
  `ATLAS_REPOSITORY_REF=<sha> make sync-atlas-release`, review the synchronized
  source and dependency-lock diff, and confirm `.atlas-source-ref` matches.

## Verification

```bash
./scripts/release-readiness.sh --full
```

- Review `docs/release-readiness-v6.md` and record every deployment go/no-go
  decision.
- Regenerate release screenshots with
  `npm --prefix frontend run screenshots:v6`, inspect them, and refresh their
  checksum file.
- Verify the pre-release backup and rollback path for the target deployment.

### Unified RAG and MCP acceptance

The automated gate validates the pgvector image, application tests, and static
configuration. It does not substitute for a deployment-specific inference and
retrieval smoke test. In a staging environment that matches production:

1. Confirm the bundled PostgreSQL image exposes the expected pgvector extension,
   or preinstall pgvector in the external PostgreSQL 16 service.
2. Start with `RAG_EMBEDDING_ENABLED=false`, queue reconciliation, and verify
   `/api/rag/status` reports a non-empty sanitized corpus and `exact+fts`
   retrieval.
3. If semantic search is approved, configure the private embedding endpoint,
   enable embeddings, reconcile the full corpus, and review pending/failed
   chunk counts. Do not call the feature semantic-ready while it remains in
   lexical-only fallback.
4. Test a representative business profile query. Verify citations, canonical
   routes, TLP/legal markings, freshness, retrieval mode, and warnings against
   the authoritative source records.
5. Generate a Navigator proposal, preview it, and verify that Add/Replace needs
   explicit server confirmation and does not automatically save a named layer.
6. Run the stdio MCP process with a dedicated least-privilege analyst session.
   Verify its four fixed tools, then confirm it cannot reindex, confirm a
   proposal, save a layer, fetch arbitrary URLs, execute SQL, or perform an
   operational action.
7. Confirm daily reconciliation and retention schedules are active. RAG workers
   must connect directly to PostgreSQL or through PgBouncer session pooling;
   transaction or statement pooling is not compatible with the session
   advisory lock.
8. Record the embedding/chat provider, models, dimensions, corpus index time,
   retrieval mode, ATT&CK version/domain, retention settings, and evidence from
   this smoke test in the release decision.

## Tag And Publish

1. Commit the release changes.
2. Create tag `vX.Y.Z`.
3. Push `main` and the tag.
4. Wait for the tag workflow to build and scan the image family, publish the
   semantic-version tags, and record their immutable digests. Do not create the
   GitHub release manually: the workflow creates it from
   `docs/release-notes/vX.Y.Z.md`. The workflow never modifies a published
   release. It resumes an existing draft only when its title, notes, and sole
   manifest asset exactly match the regenerated release; otherwise it stops for
   explicit review and draft cleanup.
5. Confirm all seven GHCR packages are public. The workflow uses a clean,
   unauthenticated Docker configuration to bind every public version manifest
   to the scanned local image before it creates the public GitHub release. A
   first publication can stop here if GitHub created a new package as private;
   change that package's visibility to public, then rerun the same tag workflow.
   A previously pushed version image is accepted on retry only when its image ID
   exactly matches the new source build; review and remove a mismatched partial
   registry version before retrying.
   Do not create or replace the release manually. Shared `latest` tags are not
   advanced because a seven-image family cannot be updated atomically; deploy
   only from `adversarygraph-images.env`. Current artifacts target Linux/AMD64.
6. Verify the workflow-generated GitHub release contains
   `adversarygraph-images.env`, and independently compare every recorded digest
   with the registry before deployment.
7. Confirm the public hub and docs links still resolve.

## Post-Release

- Check GitHub Actions.
- Check the live workspace and docs site.
- Confirm the production RAG index is current after any source migration, that
  scheduled reconciliation/retention jobs are healthy, and that no assistance
  or proposal record crossed the configured provider/TLP boundary.
- Update external discovery material only after the tag exists.
