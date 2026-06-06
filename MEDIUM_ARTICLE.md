# ThreatMapper: I Built a Self-Hosted AI Threat Intelligence Platform — Here's How to Use It

*Map adversary behaviour to MITRE ATT&CK in seconds, compare against 160+ APT groups, and generate PDF reports — all running locally with your own LLM keys.*

---

## Table of Contents

- [The Problem](#the-problem)
- [What ThreatMapper Does](#what-threatmapper-does)
- [Architecture in Brief](#architecture-in-brief)
- [Setting Up (10 Minutes)](#setting-up-10-minutes)
- [Core Workflow: Analysing a Threat Report](#core-workflow-analysing-a-threat-report)
- [The Navigator: Your ATT&CK Workspace](#the-navigator-your-attck-workspace)
- [APT Attribution Deep-Dive: The Compare View](#apt-attribution-deep-dive-the-compare-view)
- [Two Databases: Actor Profiles and Your Report Library](#two-databases-actor-profiles-and-your-report-library)
- [Generating Reports](#generating-reports)
- [Using the AI Chat Assistant](#using-the-ai-chat-assistant)
- [Working with All Three ATT&CK Domains](#working-with-all-three-attck-domains)
- [API Usage (Headless / CI Integration)](#api-usage-headless--ci-integration)
- [Keeping ATT&CK Data Fresh](#keeping-attck-data-fresh)
- [Tips for Analysts](#tips-for-analysts)
- [Security Considerations](#security-considerations)
- [What's Coming Next](#whats-coming-next)
- [Final Thoughts](#final-thoughts)

---

## The Problem

Every threat intelligence analyst knows the workflow: you receive a malware report, an IR summary, or a threat feed entry, and you need to translate it into ATT&CK technique IDs so you can slot it into a detection backlog or a purple-team plan.

Doing this manually is slow. You read the report, recognise a behaviour ("the implant used scheduled tasks for persistence"), pull up the ATT&CK website, search for the technique, copy the ID. Repeat 20 times for a single report. Then someone asks: *"Does this look like APT29?"* — and you start manually cross-referencing technique lists.

There are commercial platforms that do this — but they are expensive, require data to leave your environment, and often treat ATT&CK as a secondary feature behind proprietary kill-chains.

**ThreatMapper** is my attempt to solve this for analysts who want a self-hosted, privacy-first, open-source option that uses the LLM API keys they already have.

---

## What ThreatMapper Does

In one sentence: **you give it a threat report, it gives you ATT&CK technique IDs, APT group matches, confidence scores, and a PDF.**

Concretely:

- **AI Analysis** — upload a PDF, DOCX, or TXT file (or paste text), pick Claude, GPT-4o, or Gemini, and get a streamed extraction of every ATT&CK technique the LLM identifies with evidence snippets and confidence scores
- **ATT&CK Navigator** — an interactive heatmap of the full ATT&CK matrix (Enterprise, Mobile, ICS) where you build and explore your TTP layer
- **APT Attribution** — automatic Jaccard similarity ranking of every extraction against 174+ named ATT&CK threat groups and 56+ named campaigns (e.g. "Operation Ghost", "SolarWinds Compromise")
- **Compare** — deep side-by-side comparison of your TTP set against groups, MITRE named campaigns, or your own stored report library; with visual matrix diff, tactic breakdown chart, and gap analysis
- **Export** — ATT&CK Navigator-compatible JSON layers and multi-page PDF reports suitable for executive briefings

Everything runs locally in Docker. Your threat reports never leave your machine.

---

## Architecture in Brief

ThreatMapper is four containers:

```
React / Vite frontend  ←→  FastAPI backend  ←→  PostgreSQL
                                  ↕
                           Redis + Celery
                        (background jobs, daily ATT&CK sync)
```

The backend ingests ATT&CK STIX 2.1 bundles directly from MITRE's GitHub repository using pure Python — no third-party ATT&CK library, fully compatible with Python 3.12. All three ATT&CK domains (Enterprise, Mobile, ICS) are parsed and stored in PostgreSQL with JSONB arrays for the STIX arrays.

LLM calls go directly from the FastAPI backend to Anthropic / OpenAI / Google using their official SDKs. Your API keys never touch a third-party service beyond the LLM provider itself.

---

## Setting Up (10 Minutes)

### Prerequisites

- Docker + Docker Compose
- An API key for at least one of: Anthropic (Claude), OpenAI, Google Gemini

### Step 1: Clone and configure

```bash
git clone https://github.com/anpa1200/threatmapper.git
cd threatmapper
cp .env.example .env
```

**Important:** you must create `.env` before running `docker compose up`. Without it the container starts with empty API keys and AI Analysis returns 500.

Open `.env` and add your keys. You only need one:

```env
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GEMINI_API_KEY=AIza...

DB_PASS=choose_a_strong_password
```

If you want a faster first start and only need Enterprise ATT&CK, set:

```env
ATTCK_DOMAINS=enterprise-attack
```

This downloads ~35 MB instead of ~105 MB.

### Step 2: Start

```bash
docker compose up
```

The first start downloads and ingests ATT&CK data automatically. Watch progress:

```bash
docker compose logs -f api
```

You'll see something like:

```
Parsing enterprise-attack-19.1.json ...
  Parsed: 15 tactics, 760 techniques, 174 groups, 56 campaigns, 9100+ usages
Finished ingesting enterprise-attack v19.1
INFO:     Application startup complete.
```

This takes 5–15 minutes depending on your network speed. Subsequent startups are instant (data is cached in the PostgreSQL volume).

### Step 3: Open

- Frontend: http://localhost:3000
- API docs (Swagger UI): http://localhost:8000/docs

---

## Core Workflow: Analysing a Threat Report

This is the killer feature and what most analysts will use day-to-day.

### Upload your report

Navigate to **Analyze** in the sidebar. You'll see:

1. A provider dropdown (Claude / GPT-4o / Gemini)
2. An optional model override (defaults to `claude-opus-4-8`, `gpt-4o`, `gemini-2.0-flash`)
3. A domain selector (`enterprise-attack` for most corporate IR work)
4. A text area or file upload

For a PDF analysis report:

1. Select **Claude** (or your preferred provider)
2. Leave the domain as `enterprise-attack`
3. Click **Choose file** and upload your PDF
4. Click **Analyse with AI**

You'll immediately see the LLM's response streaming in the output box — token by token, just like ChatGPT. This is not a spinner that makes you wait: you can read the thinking as it happens.

### Reading the results

When the stream completes, three tabs appear:

**Techniques tab** — the core output. Each row shows:

| Field | Example |
|---|---|
| ATT&CK ID | T1059.001 |
| Name | PowerShell |
| Tactic | Execution |
| Confidence | 92% |
| Evidence | *"executed a base64-encoded PowerShell payload"* |

The evidence field is a direct quote or paraphrase from your source document — you can use it to trace every mapping back to its origin in the text. High confidence (≥ 80%) means the text explicitly described the behaviour; lower scores mean it was inferred.

**APT Matches tab** — the attribution layer. Computed locally using Jaccard similarity between your extracted techniques and every named ATT&CK group's known TTP set. The top 10 are shown with:

- Similarity score (0–100%)
- Shared technique count
- List of the overlapping technique IDs

A match above 25–30% is worth investigating. Don't treat this as definitive attribution — use it as a lead for further research.

**Raw Response** — the LLM's full JSON output. Useful for debugging when the model outputs something unexpected.

### Inject into Navigator

Click **→ Inject into Navigator** to push all extracted techniques into your live Navigator layer. You can then:

- See the techniques highlighted on the full ATT&CK matrix
- Overlay an APT group to visualise the behavioural overlap
- Export as an ATT&CK Navigator JSON layer

---

## The Navigator: Your ATT&CK Workspace

The Navigator is the central hub. It renders the full ATT&CK matrix as an interactive heatmap with D3.js zoom/pan.

### Building a layer

Click any technique cell to add it to your layer (it turns red). Click again to deselect. For sub-techniques, click the small ▶ arrow to expand the parent cell and see the sub-technique rows.

**Practical tip:** use the search box to find techniques by name or ID without manually scanning the matrix. Type `T1059` to jump to all Command and Scripting Interpreter techniques, or type `phish` to find all phishing-related techniques.

### Overlaying an APT group

1. Go to **APT Library** and find your group of interest
2. Click **Overlay on Navigator**
3. Return to **Navigator**

The matrix now uses three colours:
- **Red** — in your layer only
- **Blue** — in the APT group's profile only
- **Amber** — in both (the overlap)

This visual immediately answers: *"Which of this group's known techniques am I not already detecting?"*

### Importing an existing layer

If you already have ATT&CK Navigator layers from previous work, click **↑ Import layer** and upload the JSON. ThreatMapper will load it as your active layer, which you can then enrich with AI analysis or compare against APT groups.

---

## APT Attribution Deep-Dive: The Compare View

The Compare view has three modes selectable from a switcher at the top of the page.

### Mode 1 — Groups (DB 1)

With techniques selected in Navigator (or injected from an AI analysis), navigate to **Compare**, make sure **Groups (DB 1)** is selected, and click **Compare vs APT Groups**. This ranks all 174+ threat groups by Jaccard similarity.

Click any group to open the four-tab detail view:

**Overview** — similarity score, shared technique chips (amber), techniques only in your layer (red). Answers: *"How much of our observed behaviour matches this group's known playbook?"*

**Tactic Breakdown** — stacked bar per kill-chain phase: shared / user-only / APT-only. Reveals *where* in the kill chain the overlap is concentrated.

**Visual Diff** — compact colour-strip matrix. Best for presentations.

**Gap Analysis** — every technique in the group's known profile not in your layer. This is your detection backlog.

### Mode 2 — Campaigns (DB 1)

Switch to **Campaigns (DB 1)** and click **Compare vs Campaigns**. This ranks all 56+ named MITRE operations by Jaccard similarity.

**Why this is more precise than group comparison:** A group's aggregate profile spans years. A campaign profile is one specific attack. Matching your TTPs against C0024 (SolarWinds Compromise) at 40% is a sharper lead than matching against G0016 (APT29) at 15%.

### Mode 3 — Reports (DB 2)

Switch to **Reports (DB 2)**. The left panel lists every AI analysis you have ever run. Click any report to re-run Jaccard comparison against all ATT&CK groups — without re-calling the LLM.

Use this for retrospective attribution after ATT&CK releases new group data, or to cluster multiple incidents under a common actor.

### Practical attribution workflow

1. Run AI analysis on your incident data (give it a descriptive name)
2. Inject extracted techniques into Navigator
3. Compare → Groups mode: look for similarity > 25%
4. Compare → Campaigns mode: check if the top group has a campaign that fits the timeline
5. Gap Analysis tab: use the technique gap as a structured hunt checklist
6. Download the PDF report for your findings

---

## Two Databases: Actor Profiles and Your Report Library

When you dig into attribution you quickly realise there are two different things you want to compare against:

1. **What MITRE says groups have done** — the curated ATT&CK dataset of group TTP profiles, including named campaigns (specific operations like "Operation Ghost")
2. **What you have actually observed** — your own library of analysed reports, each with its own extracted TTP mapping

ThreatMapper v0.3 builds both into a single comparison workflow via three modes in the **Compare** view.

### DB 1: MITRE Actor Profiles and Named Campaigns

The ATT&CK STIX 2.1 bundle contains more than just group TTP profiles. It also includes:

- **`campaign` objects** — named operations with their own ATT&CK IDs (e.g. C0023 = "Operation Ghost", C0025 = "2016 Ukraine Electric Power Attack")
- **`attributed-to` relationships** — which group conducted which campaign
- **`uses` relationships at the campaign level** — the specific techniques observed in each named operation (often different from the group's aggregate profile)

ThreatMapper parses all of this during ATT&CK ingestion. The result is two searchable, comparable datasets that both live in DB 1:

| Dataset | What it contains | ID format |
|---|---|---|
| APT Groups | Aggregate TTP profile of each named threat group | G0001 – G0174+ |
| Campaigns | TTP profile of each named operation/campaign | C0001 – C0063+ |

**Why campaigns matter:** A group's aggregate profile is the union of everything ever attributed to them across all operations and years. A campaign profile is specific to one attack. Comparing your incident TTPs against campaigns is often more discriminating than comparing against the full group — an incident that matches C0023 (Operation Ghost) at 45% similarity is a more specific lead than a match against G0016 (APT29) at 15%.

### Viewing campaigns in the APT Library

The APT Library now has two tabs per group:

- **Techniques** — the full aggregate TTP list (existing behaviour)
- **Campaigns (DB 1)** — all named operations attributed to this group

Each campaign card shows the date range, technique count, and ATT&CK ID. Click to expand and see the full technique list with the use description from STIX.

The **"Add to my TTPs"** button on each campaign card pushes all of that campaign's techniques into your Navigator layer — useful for building a "this specific operation's TTP fingerprint" layer to compare against your detection coverage.

### DB 2: Your Report Library

Every time you run an AI analysis in ThreatMapper, the result is stored: the extracted techniques, the summary, the APT matches, and the provider/model used. DB 2 is this library of past analyses.

Access it via **Compare → Reports (DB 2)**.

The left panel lists every completed report session with:
- Name (the filename or label you gave it when you uploaded)
- Technique count
- Domain
- Provider and model used
- Date

Click any report to run a fresh Jaccard comparison of that report's extracted techniques against all ATT&CK groups. This answers: *"If I come back to this report from three months ago — which groups match its TTP profile?"*

This is useful in a few scenarios:

**Retrospective attribution:** You analysed a report before you had a strong hypothesis about the actor. A new ATT&CK version was released that added new groups or techniques. Rerun the comparison against the updated ATT&CK data without re-running the expensive LLM analysis.

**Cross-incident correlation:** If two reports from different incidents both have high similarity to the same APT group, that's a data point for clustering the incidents under the same actor.

**Building a baseline:** Accumulate 20 reports over a quarter. In the Reports library you can see at a glance which groups are recurring themes across your incident set — a form of environmental threat profiling.

### The three Compare modes

| Mode | What you compare | Against |
|---|---|---|
| **Groups (DB 1)** | Your selected TTPs (from Navigator) | All 160+ ATT&CK groups |
| **Campaigns (DB 1)** | Your selected TTPs (from Navigator) | All named MITRE campaigns |
| **Reports (DB 2)** | A stored report's extracted TTPs | All 160+ ATT&CK groups |

Use the mode switcher at the top of the Compare page to move between them.

### API for both databases

Compare against campaigns:

```bash
curl -X POST "http://localhost:8000/api/apt/campaigns/compare?domain=enterprise-attack&top_n=10" \
  -H "Content-Type: application/json" \
  -d '{"technique_ids": ["T1566.001", "T1059.001", "T1078", "T1021.001"]}'
```

List your stored report sessions:

```bash
curl "http://localhost:8000/api/analyze/sessions?limit=20" | python -m json.tool
```

Re-compare a stored report:

```bash
SESSION_ID="550e8400-e29b-41d4-a716-446655440000"
curl -X POST "http://localhost:8000/api/analyze/sessions/$SESSION_ID/compare?top_n=10"
```

List campaigns for a specific group:

```bash
curl "http://localhost:8000/api/apt/campaigns?domain=enterprise-attack&group_id=G0016"
```

---

## Generating Reports

ThreatMapper generates two types of PDF reports.

### Analysis report

From the **Analyze** page, after a completed analysis, click **Download PDF**. The report is formatted for sharing with management or a client and includes:

- Cover page with provider, model, domain, session ID, and timestamp
- Executive summary (the AI-generated TL;DR)
- Extracted techniques table sorted by confidence descending
- APT attribution section with the top 10 Jaccard matches
- Tactic coverage breakdown showing how the techniques distribute across the kill chain

### Navigator layer report

From the **Navigator**, click **↓ PDF** in the toolbar. This generates a lighter report listing all techniques in your current layer with their ATT&CK IDs, tactics, and platforms — useful as a rapid deliverable for a purple-team session or a detection engineering sprint.

---

## Using the AI Chat Assistant

Every technique in the detail panel has an embedded AI chat. This is not a generic chatbot — it is a threat intelligence assistant with the full ATT&CK description of the selected technique already in context.

**Practical prompts that work well:**

For detection engineering:
> *"Write a SIGMA rule for detecting this technique on Windows via Sysmon events"*

For understanding evasion:
> *"How do attackers modify this technique to avoid common detections?"*

For hunting:
> *"What should I look for in Windows Security event logs to hunt for this technique? Give me specific event IDs and field values."*

For red teaming context:
> *"Which tools in the open-source red team ecosystem implement this technique?"*

For correlation:
> *"Which techniques are commonly chained with this one in post-exploitation workflows?"*

The **context** field at the bottom of the chat lets you paste additional information — for example, a log snippet or a list of technique IDs from your current investigation. This gives the assistant grounding in your specific situation. The context field accepts up to 8,000 characters.

---

## Working with All Three ATT&CK Domains

ThreatMapper supports Enterprise, Mobile, and ICS ATT&CK out of the box.

Switch domains using the **Domain** dropdown in the Navigator toolbar or the Analyze page.

**Enterprise ATT&CK** — 641 techniques, 163 groups. Use for traditional IT infrastructure incidents: Windows/Linux/macOS endpoints, cloud workloads, Active Directory environments.

**Mobile ATT&CK** — covers Android and iOS threat behaviours. Useful for incidents involving mobile device management (MDM) bypass, spyware, or mobile-targeting APT campaigns.

**ICS ATT&CK** — covers operational technology and industrial control systems. Use for incidents involving SCADA, PLCs, HMIs, or critical infrastructure.

Each domain has its own set of tactics, techniques, and APT groups. When you run an AI analysis, select the appropriate domain so the Jaccard comparison runs against groups known for activity in that domain.

---

## API Usage (Headless / CI Integration)

ThreatMapper exposes a full REST API. You can drive the entire workflow programmatically.

### Analyse a report via API

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "provider=claude" \
  -F "domain=enterprise-attack" \
  -F "file=@incident_report.pdf" \
  | python -m json.tool
```

Response:

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider": "claude",
  "model": "claude-opus-4-8",
  "summary": "The report describes a spearphishing campaign ...",
  "techniques": [
    {
      "attack_id": "T1566.001",
      "name": "Spearphishing Attachment",
      "tactic": "initial-access",
      "confidence": 0.95,
      "evidence": "the email contained a malicious Excel attachment"
    }
  ],
  "apt_matches": [
    {
      "group_attack_id": "G0016",
      "group_name": "APT29",
      "similarity": 0.34,
      "shared_count": 8,
      "shared_techniques": ["T1566.001", "T1059.001", ...]
    }
  ]
}
```

### Compare a known technique set via API

```bash
curl -X POST "http://localhost:8000/api/apt/compare?domain=enterprise-attack&top_n=5" \
  -H "Content-Type: application/json" \
  -d '{"technique_ids": ["T1566.001", "T1059.001", "T1078", "T1021.001", "T1003.001"]}' \
  | python -m json.tool
```

### Stream an analysis (Python example)

```python
import httpx, json

with httpx.stream(
    "POST",
    "http://localhost:8000/api/analyze/stream",
    data={"provider": "claude", "domain": "enterprise-attack"},
    files={"file": open("report.pdf", "rb")},
    timeout=300,
) as r:
    for line in r.iter_lines():
        if line.startswith("data: "):
            event = json.loads(line[6:])
            if event["type"] == "token":
                print(event["content"], end="", flush=True)
            elif event["type"] == "result":
                print("\n\nFinal techniques:")
                for t in event["data"]["techniques"]:
                    print(f"  {t['attack_id']} ({t['confidence']*100:.0f}%) — {t['name']}")
            elif event["type"] == "error":
                print(f"\nError: {event['message']}")
```

---

## Keeping ATT&CK Data Fresh

ATT&CK releases new versions periodically (approximately twice a year). ThreatMapper checks for new versions daily at 03:00 UTC via a Celery Beat job.

The sidebar footer shows a pulsing amber indicator when a new version is available. Trigger an update:

```bash
# Quick API call
curl -X POST http://localhost:8000/api/sync/trigger

# Check what version you have vs what's available
curl http://localhost:8000/api/sync/status
```

The sync downloads only the new bundle version and ingests it alongside the existing data without deleting anything. Both versions remain queryable — endpoints accept an optional `?version=19.1` parameter to target a specific release.

---

## Tips for Analysts

**Calibrate your confidence threshold.** I recommend treating < 50% confidence as noise until you validate it manually. The LLM is trying hard to find ATT&CK mappings, which means it will sometimes stretch an inference. Use the evidence snippet to sanity-check every mapping.

**Use the Gap Analysis as a hunt checklist.** When you match against an APT group in Compare, the Gap Analysis tab shows every technique in their known profile that you haven't covered. This is an excellent input for a structured hunt — you're essentially asking *"what would we need to observe to confirm this attribution?"*

**Chain features for maximum value.** The best workflow is: AI Analysis → inject into Navigator → Compare against APT groups → Gap Analysis → export PDF. Each step builds on the last.

**Chat is good for detection rules.** The AI assistant is particularly strong at generating SIGMA rules, KQL queries, and Splunk SPL from ATT&CK technique IDs. Give it the full ATT&CK technique description plus any specific context from your environment (OS, logging stack) and you'll get useful starting points rather than generic templates.

**Import your existing layers.** If your team already maintains ATT&CK Navigator layers for your environment (e.g. a "what we detect" layer and a "what we've seen" layer), import them via the ↑ Import button. ThreatMapper will let you compare them against APT profiles and run AI chat against the techniques in the layer.

**Use text paste for quick triage.** You don't need a formatted document. Paste raw Slack thread text, a SIEM alert body, or a vendor advisory into the text box. The AI is good at extracting signal from noisy, informal text.

---

## Security Considerations

ThreatMapper is designed for internal/intranet use. It has no built-in authentication — anyone who can reach the Docker network can use it.

**For a team deployment:**

1. Set a strong `DB_PASS` in `.env`
2. Put ThreatMapper behind nginx / Caddy with TLS and HTTP Basic Auth (or integrate with your identity provider via OAuth)
3. Run the Docker containers on an internal network that is not directly internet-accessible
4. The `.env` file containing your LLM API keys should have `chmod 600` and never be committed to git

Your threat intelligence reports are stored in PostgreSQL inside the Docker volume. If you need to comply with data handling policies, deploy ThreatMapper on infrastructure that meets those policies — since it's self-hosted, you retain full control.

---

## What's Coming Next

The tool is functional but there is plenty of room to grow. Things I'm actively thinking about:

- **TAXII/STIX import** — accept threat intelligence directly from TAXII feeds (MISP, OpenCTI, commercial CTI platforms)
- **Team collaboration** — shared TTP layers with user namespacing
- **Detection coverage overlay** — import your existing SIGMA rule library and visualise which ATT&CK techniques you have coverage for vs which are blind spots
- **Automatic APT tracking** — when ATT&CK releases a new version that adds techniques to a group you're tracking, send a notification

---

## Final Thoughts

The core idea behind ThreatMapper is that the heavy lifting of ATT&CK mapping — reading a report, recognising a technique, looking it up, comparing it — is exactly the kind of repetitive, pattern-matching work that LLMs are well-suited for.

The analyst's judgement is still essential: deciding which mappings to trust, what the attribution implications are, what to do about the gap analysis. But the mechanical translation layer — text to ATT&CK IDs — should not take most of your time.

ThreatMapper tries to handle that translation layer so you can spend your time on the interesting parts.

The project is open source under the MIT licence. If you find it useful, have feature requests, or find bugs, open an issue on GitHub.

---

**GitHub:** https://github.com/anpa1200/threatmapper  
**API Docs:** http://localhost:8000/docs (after starting with `docker compose up`)

---

*ThreatMapper uses the MITRE ATT&CK® framework. ATT&CK is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
