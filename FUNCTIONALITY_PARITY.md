# AdversaryGraph Functionality Parity

## Product rule

The Docker platform is the superset product: AdversaryGraph Web analyst workflow plus
private/server capabilities and AI functions.

## Shared workflow

Both products provide ATT&CK matrix exploration, actor profiles, actor overlays, TTP
similarity, group comparison, correlated CTI/IR reports, ecosystem research links,
detection guidance, mitigation guidance, threat-hunting hypotheses, hunt-plan export,
coverage import and backlog export, evidence/maturity assessments, investigation
workspaces, shareable entity links, and investigation reports.

## Docker-only capabilities

- Persistent operational intelligence workbench
- Campaign/investigation evidence graphs and timelines
- Analyst-reviewed report intake
- Tracked-actor behavior change logs
- Detection engineering lifecycle management
- AI-assisted PDF/DOCX/text report analysis
- LLM technique assistant
- Unified normalized corpus over IOC, CVE, ATT&CK/ATLAS, actors, campaigns,
  reports, knowledge, Threat Radar, Threat Hunting, Evidence Graph, and
  sanitized asset records
- Exact-ID and PostgreSQL full-text retrieval with optional private pgvector
  embeddings, reciprocal-rank fusion, and bounded relationship expansion
- Saved business profiles for private region/sector/technology/crown-jewel
  reranking and governed answer context
- Citation-bound Navigator intelligence assistant with source routes,
  TLP/legal markings, freshness warnings, verified ATT&CK IDs, proposal preview,
  and explicit Add/Replace confirmation
- Local stdio MCP tools for bounded search, grounded questions, indexed-entity
  retrieval, and advisory Navigator proposals
- Scheduled corpus reconciliation, status/history, retry handling, tombstones,
  and bounded derived-data retention
- Private stored report sessions
- MITRE campaign ingestion and comparison
- PostgreSQL-backed saved layers
- Server-side PDF exports and APIs
- Automated ATT&CK and ATLAS synchronization
- Self-hosted/private deployment

## Current architecture note

AdversaryGraph Docker now ingests MITRE ATLAS as a first-class `atlas` domain in
PostgreSQL beside Enterprise, Mobile, and ICS ATT&CK. ATLAS currently contributes
matrix, tactic, technique, and sub-technique objects; APT groups and campaigns remain
ATT&CK datasets because the upstream ATLAS bundle does not publish intrusion-set or
campaign profiles.

The Docker RAG and MCP surfaces are not part of the public browser workspace.
The base Docker deployment provides exact-ID and full-text retrieval without an
embedding model. Semantic vector retrieval becomes available only after an
operator configures the approved private embedding endpoint, enables embeddings,
and reconciles the corpus. The MCP process is stdio-only and calls fixed REST
routes; it never connects directly to PostgreSQL or confirms/applies a Navigator
proposal.

AdversaryGraph remains a single-workspace platform rather than a tenant
isolation boundary. Saved business profiles affect request-time retrieval and
generation but are not globally indexed corpus documents.
