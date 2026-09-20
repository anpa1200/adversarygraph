# Investigation summary: Tell the story

The second layer reads a saved full investigation report and linked stored evidence. It writes a separate, short analyst-review draft. It does not replace the full report, rerun the investigation, query enrichment providers, or promote intelligence.

## Analyst workflow

1. Complete the investigation and add relevant PCAP/log results, IOC enrichments, and analyst notes to its workspace.
2. In **Investigation Report**, generate and save the full report.
3. Select that saved report, select **Local LLM**, and click **Tell the story**.
4. Review the narrative and exact supporting quotes. The new summary appears separately in Saved reports and can be reopened or downloaded as Markdown, TXT, or PDF.
5. Recheck the source-snapshot banner before sharing. If the report or linked evidence changed, regenerate the summary.

No ATT&CK selection is required to summarize an existing report. Section checkboxes govern full-report creation, not which saved evidence the second layer reads. A previous AI summary is never accepted as a full-report input.

## Output

- **What happened:** chronological narrative, target 150–220 words, hard limit 240 words.
- **Identities:** hosts/accounts/IPs, preserving their source associations.
- **TTPs:** source-present ATT&CK IDs, with behavior candidates separated from report claims and intelligence leads.
- **Priority IOCs / observables:** source-present values and their relevance; observation alone does not prove maliciousness.
- **Unknowns and limitations:** missing initial access, execution, exfiltration, attribution, conflicting evidence, and coverage limits as applicable.
- **Recommended next checks:** proposed actions, not fabricated completed actions.
- **Evidence references and generation record:** exact quotes, source references, snapshot checksum, model, prompt version, duration, and explicit unavailable token usage.

The body has a 600-word limit; evidence and generation appendices are additional. The schema allows up to six identities, six TTPs, and eight priority indicators. This is an executive selection, not the complete inventory.

## Evidence contract

`POST /api/operations/investigations/{id}/summary` accepts `report_id`, `provider`, optional server-configured `model`, and `cloud_processing_acknowledged`. Both `run_analysis` and `manage_intel` permissions are required when authentication is enabled.

The server, not the model, resolves sources. It reads the full saved report, authoritative completed PCAP reports/identities/findings/candidates, stored local CTI snapshots, and primary stored IOC provider summaries. It never follows arbitrary evidence URLs. UI handoff previews attached to an authoritative PCAP are replaced by that source; analyst annotations remain separate. Duplicate native report text already embedded in the saved report is not resent.

All packet identities and findings are included in the supplement. Frame lists use three representative references plus the original count and hash. Large raw provider responses, expansion graphs, and full ATT&CK catalog descriptions are excluded and explicitly labeled as outside the supplement's scope. This layer does not claim to reread every packet or every raw provider response. Full reports are never silently prefix-truncated: oversize input returns 413.

Limits are 320,000 source characters and 450,000 serialized evidence-pack characters. These are application safety ceilings, **not tokenizer counts or a guarantee of model context capacity**. Before inference, the local adapter conservatively reserves one token per UTF-8 prompt byte, 1,024 tokens for chat-template overhead, and 8,192 output tokens. This bound deliberately rejects some inputs that a tokenizer-aware check could fit; it is not a usage estimate. For Ollama, the adapter reads the model's advertised context capacity and explicitly sets `num_ctx`; unknown or insufficient capacity fails before report generation. For other private OpenAI-compatible servers, an operator must set `LOCAL_LLM_CONTEXT_TOKENS` only after verifying actual non-truncating capacity. Large cases need a larger-context private model or multiple smaller full reports. Live model acceptance, latency, and narrative correctness still require evaluation.

The LLM gets no tools. The prompt treats report text, hostnames, and provider data as untrusted. Pydantic rejects unexpected fields, oversized sections, and malformed output. Each citation must match one exact, unambiguous quote in its identified input record. The server checks that IOC values, identity values, and ATT&CK IDs appear in the cited quotes and forbids promoting provider/report evidence into observed behavior. Selected literal IDs/IPs/hashes in prose are also checked.

**Quote binding is not semantic entailment.** An irrelevant but real quote can still accompany an incorrect interpretation. Prompt-injection resistance and hallucination-free narratives are not proven by schema validation. A dedicated regression test documents this boundary. Human review remains necessary; no accuracy percentage is claimed.

## Storage, privacy, and failure behavior

The summary is an `investigation-summary` evidence node, not an authoritative finding. Structured claims, bound quotations, hashes, source manifest, scope, duration, and provenance are persisted. No database migration is needed. The original report, actor/technique selections, Review Gate state, and intelligence objects remain unchanged.

Generation uses the existing configured provider adapter with its bounded timeout. Workspaces currently lack governed TLP metadata, so effective classification defaults conservatively to `TLP:AMBER+STRICT` (or `TLP:RED` if a linked source is RED). Cloud processing is rejected even if a client acknowledges it. Arbitrary node metadata cannot downgrade classification. A later cloud release needs a governed classification/consent path; this version does not add one.

Schema/quote failures, unavailable models, and provider timeouts do not save a summary. Provider errors are sanitized. The source snapshot is checked again after generation and before a locked append; concurrent evidence changes return 409. `GET /api/operations/investigations/{id}/summaries/{summary_id}` reports whether the historical snapshot still matches its sources.

When the local provider returns token counts, input/output usage is saved from its response; otherwise `token_usage` is null, never estimated. Model identity and wall-clock generation seconds are recorded. No model alias is substituted. The conservative context reservation is explicitly not reported as actual token usage.

## Verification

```bash
cd backend
python -m pytest tests/unit/test_investigation_story.py tests/integration/test_investigation_story_routes.py --no-cov -q
PYTHONPATH=. python ../scripts/check-investigation-story-fixtures.py /path/to/adversarygraph-ten-additional-cases
cd ../frontend
npm run build
npx playwright test tests/e2e/investigation-story.spec.ts tests/e2e/pcap-investigation-contract.spec.ts tests/e2e/ioc-investigation-contract.spec.ts
```

The fixture replay loads the ten retained full dossiers, PCAP JSON, workspace link records, and saved enrichment results. It checks complete report inclusion, identity preservation, source resolution, and input bounds. It does **not** call an LLM, evaluate narrative accuracy, or rerun a local production instance. API tests use the repository's mocked database fixture. Browser tests use mocked APIs. These scopes must not be represented as live end-to-end validation.

The structured-output design follows the distinction between schema conformance and application validation in the [official OpenAI documentation](https://developers.openai.com/api/docs/guides/structured-outputs). This implementation remains provider-agnostic and locally validates JSON through the existing adapter; it does not claim API-enforced JSON Schema support for every local model.

For Ollama, JSON mode and usage fields follow its [chat API](https://docs.ollama.com/api/chat); explicit capacity reservation avoids relying on a potentially short [default context length](https://docs.ollama.com/context-length). The application validates the full schema locally. It deliberately avoids passing the nested schema to older Ollama schema-to-grammar implementations after a live 0.13.5 compatibility failure.
