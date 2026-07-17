# Release Process

Use this checklist for reviewer-friendly AdversaryGraph releases.

## Pre-Release

- Update `VERSION`.
- Update `frontend/package.json` and `frontend/package-lock.json`.
- Update backend API version in `backend/main.py`.
- Move `CHANGELOG.md` entries from unreleased work into a dated version.
- Add `docs/release-notes/vX.Y.Z.md`.
- Confirm sample outputs and demo dataset still match the documented workflow.
- Confirm no secrets, private reports, credentials, or customer data are added.

## Verification

```bash
./scripts/release-readiness.sh --full
```

- Review `docs/release-readiness-v6.md` and record every deployment go/no-go
  decision.
- Regenerate release screenshots with `npm run screenshots:v6`, inspect them,
  and refresh their checksum file.
- Verify the pre-release backup and rollback path for the target deployment.

## Tag And Publish

1. Commit the release changes.
2. Create tag `vX.Y.Z`.
3. Push `main` and the tag.
4. Create a GitHub release using `docs/release-notes/vX.Y.Z.md`.
5. Confirm the public hub and docs links still resolve.

## Post-Release

- Check GitHub Actions.
- Check the live workspace and docs site.
- Update external discovery material only after the tag exists.
