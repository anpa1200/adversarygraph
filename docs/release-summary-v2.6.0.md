# AdversaryGraph v2.6.0 Release Summary

AdversaryGraph v2.6.0 expands the analyst workflow around telemetry triage,
ATT&CK layer comparison, and use-case documentation.

The release adds AI-assisted log/PCAP analysis, richer Navigator layer handling,
more direct Discover actions, and a refreshed use-case documentation set with
animated walkthrough GIFs from the published Medium use-case article.

## Operator Value

- Analysts can paste logs or upload log/PCAP-like files, extract observables,
  identify suspicious activity patterns, map possible TTPs, and generate a
  triage report.
- Extracted TTPs can be injected into Navigator or used as comparison layers
  instead of being treated as isolated analysis output.
- Navigator can load and compare multiple layers with distinct colors and
  overlap markers, making report-vs-actor, report-vs-report, and coverage
  review easier.
- Discover now gives direct entry points into common platform workflows:
  self-test, report analysis, IOC lookup, actor review, feed management, and
  ATT&CK matrix work.
- The use-case documentation is no longer marked as draft and includes local
  animated GIF walkthroughs for the Medium-published workflows that included
  GIF assets.

## Verification

- Backend source compile check passed.
- Focused log/PCAP helper smoke test passed.
- Frontend production build passed.
- Frontend lint passed.
- Use-case GIF assets were verified as animated GIF files.
- Local Markdown image links for the use-case documents were checked.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.6.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Published use-case article: https://medium.com/@1200km/adversarygraph-usecases-820d03c3a7ab
- Published v2.5 article: https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.6.0.md`
