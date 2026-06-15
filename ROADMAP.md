# Roadmap

This roadmap tracks the work needed to move ThreatMapper from an early CTI workbench into a mature product suitable for external curation.

## v0.9 - Maturity Evidence

- Publish quickstart, user guide, admin guide, security model, limitations, comparison, validation, and sample outputs.
- Add GitHub Actions for backend tests and frontend build.
- Add issue templates for bugs, feature requests, mapping corrections, and documentation issues.
- Publish a deterministic demo dataset that can be reviewed without private data.
- Add sample exports for JSON, Navigator layer, detection-gap CSV, and Markdown report.

## v0.10 - Analyst Review Workflow

- Add review states for AI-extracted techniques: `suggested`, `accepted`, `rejected`, `needs-evidence`. **Implemented for stored analysis records and API updates.**
- Store analyst notes and source evidence per technique. **Implemented for JSONB analysis records; deeper UI review controls remain pending.**
- Add report-level quality summary: number accepted, rejected, unresolved, and low-confidence.
- Add UI filters for review status and confidence.
- Raise enforced backend coverage gate from 47% to at least 60% with targeted tests for exports, LLM provider selection, report generation, and scheduled jobs.

## v0.11 - Evidence Binding

- Store source paragraph/span references for every extracted technique. **Implemented as best-effort character offsets when quoted evidence is found in source text.**
- Display evidence snippets beside ATT&CK mappings. **Implemented in AI analysis results.**
- Export evidence-backed mappings to Markdown and JSON.
- Add validation warnings when techniques lack evidence.

## v0.12 - Detection Engineering Workflow

- Add detection coverage states per technique: `none`, `hunt`, `candidate`, `validated`, `production`.
- Track required telemetry by source type.
- Export a detection backlog with Sigma/KQL/SPL/EQL skeletons and analyst-review placeholders.
- Add coverage summaries by tactic and platform.

## v1.0 - Stable Release Criteria

- Clean install works from a fresh clone with documented prerequisites.
- CI is green for backend tests, frontend build, and lint.
- Demo dataset and sample outputs are current.
- Security model and limitations are explicit.
- Tagged release contains changelog, migration notes, and known limitations.
- At least one external user has successfully run the Docker quickstart and filed feedback.

## Backlog

- Optional local LLM gateway profile.
- Authentication hardening guide for reverse-proxy deployments.
- STIX/TAXII export mode.
- Case timeline view.
- ATT&CK version-diff view for mappings across releases.
- Mapping evaluation harness for public CTI reports.
