# PCAP investigation summaries

The PCAP flow has three distinct stages: deterministic packet evidence, approved
passive IOC enrichment, and **Summarise & write the investigation report**.

The final stage writes a concise analyst-review draft. It does not replace the
packet report, execute recovered files, promote IOCs, or attribute an actor.
The focused `/pcap/:analysisId/report` view is intended for readable screenshots
and review. It displays the capture filename/hash and the actual returned model
ID; citations and coverage stay in a separately expandable evidence view.

## Report contract

- Chronological account first, targeting 180–260 claim-text words, maximum 320.
- At most three identity entries, five justified indicators, two technique
  candidates, two uncertainties, and one next check. Empty IOC/TTP lists are valid.
- Exact source quotations are rebound on the server. IP/hash/technique literals
  must appear in their cited passages. A citation check is **not semantic proof**.
- The server may downgrade a model's evidence-level label, never upgrade it.
  Unsupported optional identity/IOC/TTP/next-step entries are omitted and listed
  in `validation_adjustments`. A bad narrative or material uncertainty still
  rejects the draft. No claim text or source quotation is rewritten to make it pass.
- OpenAI strict output schemas constrain references to server-issued citation
  IDs and IOC values to the assessment shortlist. Local validation remains final.
- PE/document/archive transfers take precedence over routine script inventory.
  Actual static content type is included, not inferred from an extension.
- A hash-bound PE served under an image/CSS/HTML URL is a suspicious file-review
  candidate, not proof of malware execution or a malicious hosting-IP verdict.
- Transfer-bound qualified file evidence cannot be omitted from the narrative.
  T1105 entries additionally require a file-transfer citation; outbound POSTs
  alone do not establish ingress transfer, C2, or exfiltration.

## Governance and evidence

`GET /api/pcap/analyses/{id}/summary/preflight` is read-only: it returns provider
configuration, evidence coverage, classification and the current saved summary.
No model request is made until the analyst explicitly starts report writing.
Cloud writing requires `run_analysis`, `export_data`, an available configured
provider, permissible TLP, and explicit cloud-processing acknowledgement.
`TLP:RED` and `TLP:AMBER+STRICT` are prohibited from cloud summarisation.

`POST /api/pcap/analyses/{id}/summary` accepts a provider and optional expected
source fingerprint. Unconfigured model overrides are rejected. The evidence
projection is capped at 18,000 characters and reports omitted records. It uses
a disclosed compact selection capped at 10,000 characters when the normal
projection exceeds 14,000 characters; repeated zero-output provider length
responses motivated this guard. The report records which projection was used.
It does not send recovered payload bytes, arbitrary HTTP bodies, or prior-case contents.
Packet metadata can still include identities or sensitive URL query parameters:
review classification and cloud disclosure before processing real incident data.

The source is checked again under a write lock after generation. Concurrent
evidence/TLP changes prevent saving. Later changes mark a summary stale. Up to
five replaced summaries are retained. Provider errors and invalid drafts are
audited, not substituted with fabricated results. One bounded repair is allowed.

Markdown is a short report; the structured JSON export retains exact citations,
source digests, coverage, prompt version, requested and returned model names,
generation time and provider-reported token usage. Unknown token counts remain
unknown. The database packet report remains authoritative.

## Review before release

For each report, verify chronology, correct host/account ownership, transfer
direction, actual file format, provider dates, IOC reasons, and technique meaning.
Reputation unavailable/not-found is not benign. A download is not execution.
Current reputation cannot establish capture-time maliciousness of reused IPs.

For each screenshot, match the analysis and summary IDs, capture hash and model
against the API record; check every claim is visible, no text is clipped, and the
font is readable. Open and visually inspect the image as well as checking the DOM.
Screenshots are presentation evidence, not independent packet or threat evidence.
