# Comparison With Related Tools

ThreatMapper is not intended to replace existing CTI platforms. It focuses on the CTI-to-detection workflow between report reading, ATT&CK mapping, similarity review, and detection-gap planning.

| Tool | Primary Strength | ThreatMapper Difference |
|---|---|---|
| MITRE ATT&CK Navigator | Manual ATT&CK layer visualization | Adds report extraction, group/campaign comparison, report library, and detection-gap workflow |
| OpenCTI | Full CTI knowledge graph and operational CTI platform | Lighter self-hosted analyst workbench focused on ATT&CK mapping, sector relevance, source-backed IOC enrichment, and detection handoff |
| MISP | Indicator/event sharing and operational enrichment | Uses local source-backed IOC and sector evidence, but remains a TTP-first analysis workbench rather than a full event-sharing platform |
| VECTR | Purple-team emulation and control validation | Starts from reports and ATT&CK mapping; validation planning is downstream |
| Maltego | Link analysis and visual graph investigation | Focuses on ATT&CK techniques, actor/campaign overlap, and analyst exports |
| Sigma tooling | Detection rule creation and conversion | Produces reviewed detection backlog context; generated rules require local engineering review |

## When To Use ThreatMapper

- You have a threat report and need a reviewed ATT&CK mapping.
- You want to compare selected TTPs against groups or campaigns.
- You need to identify detection and telemetry gaps.
- You need to rank actors by client sector, geography, environment, and recent context.
- You need lightweight actor IOC enrichment without operating a full MISP/OpenCTI deployment.
- You need a concise export for analyst handoff.
- You want a self-hosted workflow that can be adapted to private reports.

## When Not To Use ThreatMapper

- You need a full CTI knowledge graph with collaboration workflows.
- You need high-volume IOC distribution, sharing communities, correlation rules, or event lifecycle management.
- You need production detection validation out of the box.
- You need automated attribution.
- You cannot send reports to any configured LLM provider and have not deployed a private provider.
