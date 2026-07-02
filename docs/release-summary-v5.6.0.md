# AdversaryGraph v5.6.0 Release Summary

AdversaryGraph v5.6.0 focuses on statistics and tag-based validation. The
Statistics module now exposes cross-dataset tags for IOC, CVE, TTP,
actor/group, report, sector, and global entity analysis.

The release adds widgets for risk, confidence, region, sector, type, source,
telemetry source, TLP, attack vector, malware family, freeform IOC tags, and
relationship confidence. This gives detection engineers a faster way to see
where CTI, vulnerability, IOC, and ATT&CK data are concentrated and where
coverage is thin.

## Validation

- Backend statistics integration tests passed.
- Frontend lint and production build passed.
- Local Docker validation confirmed populated tag widgets from the live
  database.
