# AdversaryGraph v2.5.4 Release Summary

AdversaryGraph v2.5.4 improves IOC data quality and makes IOC-to-TTP mapping
more defensible.

The release fixes fragmented hash IOC counts caused by provider-specific labels
such as `sha256_hash`, `filehash-sha256`, `sha1_hash`, and `md5_hash`. These are
now normalized into `sha256`, `sha1`, and `md5`, with duplicate rows merged
without losing actor links or enrichment metadata.

IOC-to-TTP mapping now follows an explicit priority model:

1. strict source/report evidence
2. enrichment-platform metadata
3. optional AI fallback

AI fallback is opt-in from the UI or API. Deterministic evidence always runs
first.

## Operator Value

- Hash IOC counts and filters now reflect real hash observables instead of
  provider naming variants.
- IOC-to-TTP links are easier to explain because each mapping stores its
  evidence priority.
- Local IOC databases can be reprocessed with one action from IOC Library,
  Feeds Management, or `/api/ioc/enrich/ttps`.
- Feed sync can ask whether to use AI fallback for new unmapped IOCs instead of
  silently inferring mappings.

## Verification

- Frontend production build passed.
- Backend syntax check passed.
- IOC unit tests passed.
- IOC route integration tests passed.
- Local deterministic enrichment normalized or merged 941 legacy IOC types.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.5.4
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Published v2.5 article: https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e
- 1200km article mirror: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.5.4.md`
