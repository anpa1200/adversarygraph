# Public Demo Privacy

The public AdversaryGraph pages are for exploration and portfolio demonstration. They are not a private analysis environment.

Do not upload or paste:

- Customer reports.
- Internal incident response notes.
- Classified, restricted, or regulated data.
- Credentials, tokens, API keys, or passwords.
- Private victim names, hostnames, IP ranges, or identities.
- Malware samples or proprietary binaries.

Use the self-hosted Docker deployment for private analysis. For sensitive work,
configure a local or private OpenAI-compatible LLM gateway, restrict network
access, enable native authentication, and use TLS or an authenticated reverse
proxy for exposed deployments.

The unified RAG corpus, saved business profiles, vector embeddings, generated
answers/citations, and local MCP integration are self-hosted Docker capabilities
and are not a privacy boundary for a public demo. Do not index customer assets,
internal hunts, incident evidence, restricted reports, or private IOC feeds in
a shared instance. Treat MCP clients and any model connected to them as another
authorized data processor because tool results can contain the same sensitive
derived context as the source records.

Public demo outputs are examples only. Treat AI mappings, RAG rankings and
relationship expansion, citations, Navigator proposals, similarity scores, IOC
enrichment, generated detections, malware-analysis output, and Attack
Simulation telemetry as analyst-assistance data that requires independent
validation.
