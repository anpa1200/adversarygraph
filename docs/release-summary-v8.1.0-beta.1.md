# AdversaryGraph v8.1.0-beta.1 Release Summary

Source candidate: 2026-09-22. This is a minor beta increment for deterministic
PCAP investigation, bounded file recovery, evidence-qualified IOC triage,
provider-aware enrichment and investigation reporting. It is not a stable
promotion, immutable image publication or running-instance upgrade.

## What Improves

- Packet evidence, identities, exported-byte hashes and recovery limits remain
  distinct and traceable through the investigation and report workflow.
- Passive reputation checks preserve direct verdicts, reuse dated results and
  keep partial provider coverage visible for reviewed retries.
- Native full reports preserve file candidates even with no selected ATT&CK
  techniques. PDF exports have corrected byte offsets.
- Second-layer story output selects server-issued evidence passages, with
  original quotes attached and validated locally. Source governance and consent
  remain mandatory; stories remain analyst-review drafts.

## What Is Not Solved

The ten known-case regression recovered 12/12 comparable published file hashes
and saved 10/10 full reports. However, network-indicator shortlist recall was
20/54 versus the prior 22/54, and recorded native story attempts saved 0/10.
The latest citation change is locally tested but awaits authorized cloud retesting.
Large evidence packs, incomplete provider coverage and historical reputation
remain practical limitations. No 100% accuracy, confirmed actor attribution or
complete campaign correlation is claimed.

The existing v8 Review Gate, migration, authenticated deployment and manual
acceptance boundaries still apply. v7.0.0 remains the latest stable release.

See [full release notes](release-notes/v8.1.0-beta.1.md),
[implementation evidence](pcap-quality-remediation-20260922.md),
[version matrix](version-matrix.md), and
[v8 acceptance checklist](release-readiness-v8.md).
