# Release Process

Use this checklist for reviewer-friendly AdversaryGraph releases.

## Pre-Release

- Update `VERSION`.
- Update `frontend/package.json` and `frontend/package-lock.json`.
- Update backend API version in `backend/app/core/version.py`.
- Move `CHANGELOG.md` entries from unreleased work into a dated version.
- Add `docs/release-notes/vX.Y.Z.md`.
- Confirm sample outputs and demo dataset still match the documented workflow.
- Confirm no secrets, private reports, credentials, or customer data are added.
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

## Tag And Publish

1. Commit the release changes.
2. Create tag `vX.Y.Z`.
3. Push `main` and the tag.
4. Wait for the tag workflow to build, scan, and publish the immutable image
   family. Do not create the GitHub release manually: the workflow creates it
   from `docs/release-notes/vX.Y.Z.md`. Every published release is immutable,
   regardless of its attached assets. Only a release that is still a draft may
   be resumed by the workflow's same-commit recovery checks.
5. Verify the workflow-generated GitHub release contains
   `adversarygraph-images.env`, and independently compare every recorded digest
   with the registry before deployment.
6. Confirm the public hub and docs links still resolve.

## Post-Release

- Check GitHub Actions.
- Check the live workspace and docs site.
- Update external discovery material only after the tag exists.
