# AdversaryGraph v3.2.0 Release Summary

AdversaryGraph v3.2.0 documents the new integrated Malware Analysis module and
marks the platform version for the MalwareGraph integration milestone.

## Release Focus

- MalwareGraph can operate as a standalone Docker Compose workbench or as an
  integrated AdversaryGraph module.
- The AdversaryGraph dashboard keeps malware findings clickable and linked to
  existing IOC, ATT&CK TTP, evidence, comparison, and detection workflows.
- The first-analysis flow covers sample type, magic bytes, hashes, entropy,
  packed/obfuscated hints, PE headers, strings, smart extraction, and optional
  AI analysis.
- Runtime debugging is documented as policy-gated and appropriate only for a
  disposable, network-isolated analysis profile.
- The new module is explicitly labeled under construction in the repository and
  documentation.

## Links

- Malware Analysis module: `docs/malware-analysis-module.md`
- Malware Analysis architecture: `docs/malware-analysis-architecture.md`
- Detailed notes: `docs/release-notes/v3.2.0.md`
