# AdversaryGraph v2.5.8 Release Summary

AdversaryGraph v2.5.8 adds a full IOC enrichment drill-down workflow.

Analysts can now open any IOC from the IOC Library or actor/group IOC tab and
inspect the complete stored context for that indicator: source metadata,
enrichment values, actor links, ATT&CK TTP mappings, source report links, and raw
JSON.

## Operator Value

- IOC Library rows now open a dedicated enrichment detail page.
- Actor/group IOC tabs expose the same detail page through clickable IOC values
  and an `Open detail` action.
- Mapped TTPs are shown with names, tactics, ATT&CK links, and evidence.
- Actor links are clickable and return the analyst to the relevant actor page.
- Enrichment values are clickable, allowing fast pivots to external URLs,
  Navigator technique views, actor pages, and IOC Library search.
- Raw JSON remains available for audit and troubleshooting.

## Verification

- Docker Compose config validation passed.
- Backend source compile check passed.
- Focused backend unit tests passed.
- Frontend production build passed.
- Frontend lint passed.
- Live API probes passed for IOC Library, IOC detail, and actor IOC endpoints.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.5.8
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Published v2.5 article: https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e
- 1200km article mirror: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.5.8.md`
