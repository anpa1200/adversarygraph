# Local beta source reconciliation

The original checkout at b39aadcebb74b632209fece31f32af79cd0cf8eb was not reset. Its 29 local changes were copied to an isolated checkout and committed as c782a5f. Reviewed ATT&CK fixes were merged on top. The actual running API investigation-v11 image contained 17 differences from that checkout: 16 source files were recovered; the remaining ingestor difference consists of the reviewed ATT&CK fixes and is retained. Running scanner and malwaregraph Python sources were compared before replacement.

Four recorded Compose overlays no longer existed at their labeled paths. Effective configuration was recovered from Docker inspection into private update and rollback plans, preserving literal environment values, mount identities, networks, users, capabilities, resource limits, commands, health checks and port bindings. Secrets are excluded from this repository. The plans validate without printing configuration.

Before replacement, backups include a full Git bundle, tracked/untracked source archives, running-source snapshots, rollback image tags, PostgreSQL custom-format dump, and private archives of ATT&CK/PCAP/malwaregraph/logs/Redis volumes. Original data volumes are reused, not recreated. A disposable no-network database is used to validate dump restoration.

Only the selected seven application/cache services are replaced; unrelated PCAP analyzer, evidenceforge, observability and PostgreSQL containers remain in place. Rollback uses the private plan with original image IDs and original configuration. No new persistent credentials or security settings are introduced.
