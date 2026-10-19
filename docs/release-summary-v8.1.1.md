# AdversaryGraph 8.1.1 release summary

ATT&CK v20 support across Enterprise, Mobile and ICS, version-correct Navigator
exports and historical catalog preservation accompany deterministic packet
evidence, CTI investigation workflows and durable governed report processing.
Database safety fixes make migration chains atomic and protect populated
investigation metadata from destructive downgrade.

See [release notes](release-notes/v8.1.1.md),
[acceptance record](release-readiness-v8.1.md) and
[security policy](../SECURITY.md). Use the published digest manifest for all
nine images; optional provider and integration readiness remains deployment-specific.

Adds bounded transient registry-upload retries without replacing the earlier
protected tag or relaxing the scanned-image identity checks.
