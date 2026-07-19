# Demo Dataset

This directory contains a deterministic demo dataset for evaluating
AdversaryGraph without private or confidential data. The broader repository demo
folder also contains an Evidence-to-Detection Graph scenario in
[`demo/evidence-graph/`](../../demo/evidence-graph/).

## Files

| File | Description |
|---|---|
| `public-report-excerpt.md` | Excerpt from a synthetic public threat report — safe to run through the ATT&CK extraction pipeline |
| `expected-mappings.json` | Expected ATT&CK technique mappings for the report excerpt — use to verify extraction accuracy |

## How to use

1. Start AdversaryGraph with `docker compose up`
2. Upload `public-report-excerpt.md` through the web UI or API
3. Run AI analysis to extract ATT&CK mappings
4. Compare extracted techniques against `expected-mappings.json`
5. For evidence-to-detection review, open
   [`demo/evidence-graph/`](../../demo/evidence-graph/) and compare the
   synthetic report/log/IOC/asset inputs to `expected-graph.json`,
   `expected-gaps.json`, and `expected-report.md`.
6. Reconcile the unified RAG corpus and search for the report's ATT&CK IDs.
   Confirm the indexed analysis report and technique citations open their
   canonical platform routes. If embeddings are disabled, expect exact/full-text
   mode rather than claiming semantic validation.
7. Generate a temporary Navigator proposal from the cited demo report, review
   the Add/Replace diff, and confirm it remains an in-memory selection until a
   named layer is saved separately.

The demo dataset is designed so that reasonable AI extraction produces at least 70% overlap with the expected mappings. Exact match rates vary by LLM provider and model.

## Notes

- This dataset contains no real threat intelligence, no real IOCs, and no real victim or adversary names
- The report text is synthetic and safe for sharing publicly
- Do not use this dataset to evaluate production detection coverage
- Evidence Graph demo outputs are reasoning examples, not proof of real
  detection coverage.
- RAG rankings, vector matches, relationship expansion, and generated answers
  are retrieval/assistance examples, not evidence of targeting or compromise.
