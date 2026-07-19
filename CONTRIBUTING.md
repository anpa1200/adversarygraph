# Contributing

AdversaryGraph welcomes focused contributions that improve CTI analyst workflows, documentation, validation, and operational reliability.

## Good First Contributions

- Fix broken documentation or unclear setup steps.
- Add safe public demo reports.
- Improve sample outputs.
- Add tests for parsing, ATT&CK mapping, exports, or API validation.
- Add reviewed RAG relevance fixtures, source collectors, deep-link checks, or
  MCP boundary tests that do not include private intelligence.
- Report incorrect ATT&CK mappings with evidence.
- Improve deployment hardening guidance.

## Before Opening a Pull Request

1. Keep the change scoped.
2. Add or update tests when behavior changes.
3. Update documentation for user-facing changes.
4. Do not commit secrets, private reports, customer data, malware samples, or credentials.
5. For RAG changes, preserve provenance, sanitization, TLP/legal controls,
   citation binding, bounded inputs/outputs, and lexical-only behavior when the
   embedding service is unavailable. A new source collector must use an
   explicit field allowlist; never embed raw provider JSON or arbitrary model
   output.
6. For MCP changes, keep transport stdio-only and API routes/tool behavior
   explicitly allowlisted. Do not add arbitrary SQL, URL fetching, proposal
   confirmation, reindexing, Navigator mutation, or response actions.
7. Run the relevant checks:

```bash
cd backend
PYTHONPATH=. pytest tests/unit -v

cd ../frontend
npm ci
npm run build
```

For unified RAG, assistant, retention, or MCP work, also run:

```bash
cd backend
PYTHONPATH=. pytest \
  tests/unit/test_rag_service.py \
  tests/unit/test_rag_ai.py \
  tests/unit/test_rag_tasks.py \
  tests/unit/test_rag_retention.py \
  tests/unit/test_mcp_server.py \
  tests/integration/test_rag_routes.py --no-cov -v
```

Tests must not require a public model endpoint. Mock provider protocol behavior
in automated tests, then record a separate staging smoke test when a change
affects real embedding dimensions, endpoint compatibility, retrieval quality,
or governed generation.

## Mapping Corrections

For ATT&CK mapping issues, include:

- Source report URL or public citation.
- Exact text that supports the technique.
- Current mapped technique.
- Proposed corrected technique.
- Reasoning and confidence.

## Pull Request Style

- Use neutral language.
- Prefer evidence over claims.
- Avoid broad rewrites unless the change is explicitly documentation-only.
- Keep generated build artifacts out of the PR unless the repo section already tracks them.
- Record the top-level RAG mode (`fts` plus optional `exact`, `vector`, and
  `relationship`) and each item's `retrieval_signals`. The top-level mode shows
  which paths were available for the request; per-item signals show which paths
  contributed to that item. Do not describe lexical-only fallback as
  semantic/vector validation.
