# ThreatMapper Functionality Parity

## Product rule

The Docker platform is the superset product: ThreatMapper Web analyst workflow plus
private/server capabilities and AI functions.

## Shared workflow

Both products provide ATT&CK matrix exploration, actor profiles, actor overlays, TTP
similarity, group comparison, correlated CTI/IR reports, ecosystem research links,
detection guidance, mitigation guidance, threat-hunting hypotheses, hunt-plan export,
coverage import and backlog export, evidence/maturity assessments, investigation
workspaces, shareable entity links, and investigation reports.

## Docker-only capabilities

- AI-assisted PDF/DOCX/text report analysis
- LLM technique assistant
- Private stored report sessions
- MITRE campaign ingestion and comparison
- PostgreSQL-backed saved layers
- Server-side PDF exports and APIs
- Automated ATT&CK synchronization
- Self-hosted/private deployment

## Remaining architecture gap

ThreatMapper Web includes a static MITRE ATLAS matrix. Docker currently embeds and
cross-links the Anomaly Detection Atlas reference book but does not ingest MITRE ATLAS
objects into PostgreSQL. Adding native ATLAS requires a dedicated ingestion adapter
because ATLAS is not represented by the current Enterprise/Mobile/ICS ATT&CK STIX
domain pipeline.
