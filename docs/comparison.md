# Comparison With Related Tools

AdversaryGraph is not intended to replace an enterprise CTI platform, SIEM,
EDR, case-management system, general vector database, or unrestricted agent
framework. It focuses on the governed workflow between intelligence research,
business-context retrieval, ATT&CK mapping, evidence review, threat hunting,
detection-gap planning, and safe validation.

| Tool | Primary Strength | AdversaryGraph Difference |
|---|---|---|
| MITRE ATT&CK Navigator | ATT&CK layer visualization and comparison | Adds cross-source report/IOC/CVE/actor/hunt/asset retrieval, cited AI synthesis, and an expiring human-confirmed technique proposal; saving remains separate |
| OpenCTI | Full CTI knowledge graph and operational CTI workflows | A lighter self-hosted analyst workbench focused on ATT&CK mapping, business-context ranking, source-backed IOC/CVE relationships, hunting, and detection handoff; it is not a replacement for broad CTI object lifecycle and collaboration |
| MISP | Indicator/event sharing, correlation, and enrichment | Uses locally stored source-backed IOC and actor evidence but remains a TTP-first analysis workbench, not a high-volume event-sharing community or distribution platform |
| VECTR | Purple-team emulation and control validation | Starts from intelligence evidence and ATT&CK mapping; its Attack Lab is an allowlisted validation surface rather than a general adversary-emulation platform |
| Maltego | Flexible link analysis and visual graph investigation | Uses bounded, allowlisted relationships and citations rather than arbitrary transforms; focuses on ATT&CK, actor/campaign overlap, Evidence Graph, and analyst handoff |
| Sigma tooling | Detection rule authoring and conversion | Provides intelligence, hunt, telemetry-gap, and review context around detection candidates; generated or translated rules still require local schema review and testing |
| General vector databases | Large-scale embedding storage and similarity primitives | Uses pgvector beside provenance, TLP, legal flags, full-text search, exact IDs, relationships, retention, and authorization; it is an application corpus, not a general vector service |
| General AI/RAG frameworks | Flexible connectors, agents, prompts, and model orchestration | Exposes twelve fixed sanitized collectors, strict citation/schema checks, stale-source rejection, provider-egress policy, and no automatic operational action; arbitrary connectors and tool execution are intentionally absent |
| MCP clients and hosts | Connecting models to local or remote tools | AdversaryGraph supplies a four-tool stdio-only advisory MCP server; the client remains a separate trust boundary and receives no proposal-confirmation, reindex, simulation, SIEM, or response capability |

## Unified RAG scope

The unified corpus currently indexes allowlisted fields from ATT&CK/ATLAS
techniques, groups, campaigns, actor sector/region/technology observations,
IOCs, CVEs, completed analysis reports, Knowledge articles, Threat Radar
signals, canonical threat hunts, Evidence Graph nodes, and sanitized Asset
Surface records. It combines exact identifier lookup, PostgreSQL full-text
search, optional private pgvector similarity, reciprocal-rank fusion,
deterministic business-profile reranking, and one bounded relationship pass.

It does not index every database table. Raw provider/feed JSON, secrets, feed
configuration, authentication/audit data, raw model exchanges, arbitrary files,
and unsupported workflow child records remain outside the corpus. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md#indexed-source-coverage)
for the field-level contract.

## When To Use AdversaryGraph

- You have a threat report and need a reviewed ATT&CK mapping.
- You want to compare selected TTPs against groups or campaigns.
- You need to identify detection and telemetry gaps.
- You need to rank actors by client sector, geography, environment, and recent context.
- You need lightweight actor IOC enrichment without operating a full MISP/OpenCTI deployment.
- You need a concise export for analyst handoff.
- You want a self-hosted workflow that can be adapted to private reports.
- You want one cited search surface across supported IOC, CVE, TTP, actor,
  report, hunt, evidence, and sanitized asset records.
- You want to rank intelligence against a saved region, sector, technology, and
  crown-jewel profile while keeping that profile out of the global corpus.
- You want an AI-assisted Navigator proposal that remains a temporary preview
  until an analyst reviews citations and explicitly confirms Add or Replace.
- You want a local MCP integration whose tools search or advise but cannot
  confirm, save, execute, forward, block, or respond.

## When Not To Use AdversaryGraph

- You need a full CTI knowledge graph with collaboration workflows.
- You need high-volume IOC distribution, sharing communities, correlation rules, or event lifecycle management.
- You need production detection validation out of the box.
- You need automated attribution.
- You cannot send reports to any configured LLM provider and have not deployed a private provider.
- You require every database table, arbitrary file share, SaaS application, or
  telemetry backend to be searched without building a reviewed collector.
- You need real-time streaming indexing or a corpus size that requires a
  distributed vector/search platform; reconciliation currently materializes a
  selected collector and existing corpus rows in worker memory.
- You need hard multi-customer isolation inside one instance; the current
  product is a single-workspace boundary, so mutually untrusted customers need
  separate deployments.
- You need a remotely exposed MCP server, autonomous Navigator mutation,
  automated blocking, exploitation, containment, or production rule
  publication.
- You need semantic vector search but cannot operate an approved private
  embedding endpoint. Exact and full-text retrieval still work, but the system
  does not substitute fake embeddings or silently send corpus text to cloud
  embeddings.
