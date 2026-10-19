# ATT&CK v20 validation — 2026-10-19

MITRE released ATT&CK 20.0 on October 13, 2026: https://attack.mitre.org/resources/updates/updates-october-2026/ .

Release fixtures use the official immutable commit `20664a889568dce884a1dac0ec7b12ae3a199f51` (peeled `v20.0` tag) from `mitre-attack/attack-stix-data`. Bundle paths are `{domain}/{domain}-20.0.json` for Enterprise, Mobile and ICS. Counts exclude revoked/deprecated objects: Enterprise 15 tactics, 227 parents and 479 sub-techniques; Mobile 12 tactics and 125 entries; ICS 12 tactics and 104 entries. ATLAS remains independently versioned.

The existing daily 03:00 UTC Celery `sync.check_and_sync` task discovers versions separately for configured domains. No production synchronization was invoked. Raw objects and relationships remain versioned. Active usage, campaign attribution and detection-source projections exclude stale relationships. Reingestion now reselects an existing snapshot as current for its domain within the ingest transaction.

## Isolated database regression

`backend/scripts/validate_attack_release.py` refuses nonempty databases and any database/user name other than `attack_test`. It imports all three actual v20 bundles, selects the actual prior ICS 19.2 release, then reselects existing 20.0 and asserts unique current versions and preserved historical data. Run only in a newly created disposable PostgreSQL instance with `DB_NAME=attack_test`, `DB_USER=attack_test`, explicit connection settings and `ATTACK_TEST_BUNDLE_DIR` pointing to pinned fixtures. Never point it at an application database. The local validation used a container with no network, no production volumes and temporary in-memory database storage.

## Exports and historical fixtures

Navigator exports derive ATT&CK's major version from the selected catalog, independently of Navigator version and layer format 4.5. Import/re-export within the same view preserves tactic-specific annotations, scores, comments, disabled records and top-level metadata. ATLAS exports omit ATT&CK release metadata. Internal saved TTP layers are identifier selections, not full annotated Navigator documents. Historical demo files recording 19.1 retain their original baseline; `sample-outputs/navigator-layer-v20.json` is a separate current example.

Validation includes actual official bundle parsing and database imports, upgrade/rollback regression, focused and broader backend suites, browser import/download round trips, TypeScript/Vite build and custom STIX reopening. See the task validation report for exact outcomes and baseline failures. No production upgrade, real scheduler execution or production-database migration is claimed.
