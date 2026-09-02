# SEO and AI-searchability fixes

Status at preparation time (2026-08-14): validated locally and awaiting publication. Search-engine submission remains a post-deployment human action.

## Issue 4 — Docusaurus metadata

- `anomaly_detection/docs-site/docusaurus.config.js` centralizes the browser-title suffix on `1200km`, declares the exact portfolio `og:site_name`, retains the existing 1200×630 project social card, and enables the metadata build plugin.
- `anomaly_detection/docs-site/src/pages/index.js` keeps the project title and supplies an authored root value statement.
- `anomaly_detection/docs-site/seo/descriptions.json` is the source of truth for seven unique indexable-route descriptions, each 140–160 characters.
- `anomaly_detection/docs-site/src/theme/DocItem/Metadata/index.js` applies those values and Twitter parity during server rendering, hydration, and client navigation.
- `anomaly_detection/docs-site/seo-metadata-plugin.cjs` enforces title, description, canonical, social-parity, image, uniqueness, and branded-404 rules during every production build.

## Issue 7 — HexStrike destinations

- The Docusaurus source and generated seven-route site were audited; neither contains a HexStrike GitHub destination, so no label change was applicable.

## Issue 8 — accurate sitemap dates

- `anomaly_detection/docs-site/seo/dates.json` is a source-controlled manifest for all seven routes. Each record binds a last-source-change calendar date to the exact route source and its SHA-256 digest.
- `anomaly_detection/docs-site/scripts/generate-seo-date-manifest.mjs` refreshes the manifest from full Git history and refuses shallow history. Clean sources use `git log -1 --format=%cs`; a source being edited uses the local calendar date, or the explicit `SEO_DATE_MANIFEST_DIRTY_DATE`, so the manifest can accompany the content commit.
- `anomaly_detection/docs-site/seo/date-manifest.cjs` rejects missing or extra routes, impossible dates, unexpected source mappings, malformed digests, missing source files, and manifests whose source digest is stale.
- `anomaly_detection/docs-site/docusaurus.config.js` loads the validated manifest before building and assigns its date to every sitemap route. The same data is therefore used with full Git history and in the Git-less release image; Git metadata is not copied into the image.
- `anomaly_detection/docs-site/Dockerfile` runs the fail-closed manifest tests before its Git-less production build.
- `anomaly_detection/docker/sync-and-build.sh` restores the reviewed SEO config, manifest, root source, and hydrated metadata component from the immutable image seed after a runtime Atlas sync, then tests the manifest before every rebuild. Changed synchronized route content cannot inherit a stale date because its source digest fails validation; the process keeps serving the last successful output instead of publishing that candidate.
- `.github/workflows/ci.yml` checks out full Git history, checks that the manifest is current, runs its fail-closed tests, and then builds the anomaly documentation.
- `.github/workflows/release.yml` performs the same manifest check and test in the full-history, non-skippable release-validation job before building the Git-less release image.

## Issue 9 — structured data

- `anomaly_detection/docs-site/src/pages/index.js` emits an absolute-URL root `BreadcrumbList`.
- `anomaly_detection/docs-site/seo-metadata-plugin.cjs` preserves framework breadcrumbs, supplies a valid fallback when absent, and emits manifest-backed document update times as `article:modified_time`.
- `anomaly_detection/docs-site/src/theme/DocItem/Metadata/index.js` uses the same manifest-backed modified time and social metadata in the hydrated application head, including when Docusaurus cannot query Git.

## Exact touched-file manifest

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `SEO-FIXES.md`
- `anomaly_detection/docker/sync-and-build.sh`
- `anomaly_detection/docs-site/Dockerfile`
- `anomaly_detection/docs-site/docusaurus.config.js`
- `anomaly_detection/docs-site/package.json`
- `anomaly_detection/docs-site/scripts/generate-seo-date-manifest.mjs`
- `anomaly_detection/docs-site/scripts/seo-date-manifest.test.cjs`
- `anomaly_detection/docs-site/seo-metadata-plugin.cjs`
- `anomaly_detection/docs-site/seo/date-manifest.cjs`
- `anomaly_detection/docs-site/seo/dates.json`
- `anomaly_detection/docs-site/seo/descriptions.json`
- `anomaly_detection/docs-site/src/pages/index.js`
- `anomaly_detection/docs-site/src/theme/DocItem/Metadata/index.js`

## Validation

- `npm run check:seo-dates`, `npm run test:seo-dates`, and `npm run build` passed from `anomaly_detection/docs-site` in a full-history worktree.
- A second production build passed from a standalone copy with no `.git` directory, matching the release-image build boundary.
- Audited seven indexable routes: seven exact branded titles, seven unique compliant descriptions, seven canonical URLs, seven Open Graph/Twitter parity matches, seven social-card matches, and seven valid `BreadcrumbList` blocks.
- Both builds expose six manifest-backed `article:modified_time` values and seven manifest-backed sitemap dates; the custom root is dated in the sitemap but is not mislabeled as an article.
- Fail-closed tests cover missing routes, invalid calendar dates, stale source digests, and deterministic Open Graph timestamp conversion.

## Deploy and human follow-ups

1. Publish this source repository and verify the deployment workflow completes successfully.
2. Rebuild the 1200km.com aggregate sitemap after the sub-site is live.
3. Resubmit the aggregate sitemap in Google Search Console and Bing Webmaster Tools, then inspect the atlas root and representative catalog routes.
