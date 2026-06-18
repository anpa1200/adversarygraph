# AdversaryGraph AI: A Self-Hosted CTI-to-Detection Workbench — Here's How to Use It

*Map adversary behaviour to MITRE ATT&CK in seconds, compare against the currently ingested ATT&CK group and campaign profiles, and generate analyst-ready outputs — self-hosted, with report content sent only to the LLM provider you configure.*

> **Editor's note:** AdversaryGraph now uses “Group & Campaign Similarity” terminology instead of “APT attribution.” TTP overlap and Jaccard similarity are analytical leads for hypothesis generation and prioritization, not attribution proof. In Docker mode, report content is sent only to the LLM provider configured by the operator unless a local/private LLM gateway is used. The public Web workspace does not perform LLM report extraction or backend private report storage.

> **v2.5 update:** The current release adds the IOC Library, searchable multi-select group filtering, VirusTotal IOC enrichment, STIX/TAXII import/export, MISP JSON export ingestion, custom IOC feeds, Sigma/YARA rule-feed sync, sandbox behavior enrichment, and a personal/private-use license model.

---

## Table of Contents

- [The Problem](#the-problem)
- [What AdversaryGraph Does](#what-adversarygraph-does)
- [Architecture in Brief](#architecture-in-brief)
- [Setting Up (10 Minutes)](#setting-up-10-minutes)
- [Core Workflow: Analysing a Threat Report](#core-workflow-analysing-a-threat-report)
- [The Navigator: Your ATT&CK Workspace](#the-navigator-your-attck-workspace)
- [Saving and Loading Named Layers](#saving-and-loading-named-layers)
- [Group & Campaign Similarity Deep-Dive: Three Compare Modes](#group--campaign-similarity-deep-dive-three-compare-modes)
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

There are commercial platforms that do this, but analysts may also need a self-hosted control plane with explicit storage, networking, and provider choices.

**AdversaryGraph** is my attempt to provide that analyst-assisted workflow using operator-configured LLM providers.

---

## What AdversaryGraph Does

In one sentence: **you give it a threat report, it returns ATT&CK mapping candidates, group-similarity leads, extraction-confidence scores, and a PDF for analyst review.**

Concretely:

- **AI Analysis** — upload a PDF, DOCX, or TXT file (or paste text), pick Claude, OpenAI, Gemini, or Local, and get a streamed extraction of every ATT&CK technique the LLM identifies with evidence snippets and confidence scores
- **ATT&CK Navigator** — an interactive heatmap of the full ATT&CK matrix (Enterprise, Mobile, ICS) where you build, save, and reload named TTP layers
- **Group & Campaign Similarity** — Jaccard TTP-overlap ranking against currently ingested ATT&CK group and campaign profiles
- **Compare** — deep side-by-side comparison of your TTP set against groups, MITRE named campaigns, or your own stored report library; with visual matrix diff, tactic breakdown chart, and gap analysis
- **Export** — ATT&CK Navigator-compatible JSON layers and multi-page PDF reports suitable for executive briefings

AdversaryGraph is self-hosted. In Docker mode, report content is sent only to the LLM provider configured by the operator. For fully private analysis, deploy with a local or private LLM gateway. The public Web workspace does not perform LLM report extraction or backend private report storage.

---

## Architecture in Brief

AdversaryGraph is four containers:

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
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
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
  Parsed: current tactics, techniques, groups, campaigns, and relationships
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

1. A provider dropdown (Claude / OpenAI / Gemini / Local)
2. An optional model override (defaults to `claude-opus-4-8`, `gpt-4.1`, `gemini-2.0-flash`)
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

**Group Similarity Leads tab** — the overlap-analysis layer. The Docker backend computes Jaccard similarity between your extracted techniques and every named ATT&CK group's known TTP set. The top 10 are shown with:

- Similarity score (0–100%)
- Shared technique count
- List of the overlapping technique IDs

A similarity score above 25–30% may be worth investigating, but the threshold is contextual. Treat it as a lead for further research, not attribution proof.

**Raw Response** — the LLM's full JSON output. Useful for debugging when the model outputs something unexpected.

### Inject into Navigator

Click **→ Inject into Navigator** to push all extracted techniques into your live Navigator layer. You can then:

- See the techniques highlighted on the full ATT&CK matrix
- Overlay a group profile to visualise the behavioural overlap
- Export as an ATT&CK Navigator JSON layer

---

## The Navigator: Your ATT&CK Workspace

The Navigator is the central hub. It renders the full ATT&CK matrix as an interactive heatmap with D3.js zoom/pan.

### Building a layer

Click any technique cell to add it to your layer (it turns red). Click again to deselect. For sub-techniques, click the small ▶ arrow to expand the parent cell and see the sub-technique rows.

**Practical tip:** use the search box to find techniques by name or ID without manually scanning the matrix. Type `T1059` to jump to all Command and Scripting Interpreter techniques, or type `phish` to find all phishing-related techniques.

### Overlaying a Group Profile

1. Go to **ATT&CK Group Library** and find your group of interest
2. Click **Overlay on Navigator**
3. Return to **Navigator**

The matrix now uses three colours:
- **Red** — in your layer only
- **Blue** — in the group profile only
- **Amber** — in both (the overlap)

This visual immediately answers: *"Which of this group's known techniques am I not already detecting?"*

### Importing an existing layer

If you already have ATT&CK Navigator layers from previous work, click **↑ Import layer** and upload the JSON. AdversaryGraph will load it as your active layer, which you can then enrich with AI analysis or compare against ATT&CK group profiles.

---

## Saving and Loading Named Layers

Once you have built a TTP layer — whether through AI analysis, manual selection, or a group/campaign overlay — you can save it to the database with a name and reload it in any future session.

### Why this matters

Without persistence, every session starts blank. You would have to re-inject or re-select all your techniques each time you come back to a piece of work. Named layers let you:

- **Bookmark a specific investigation.** Save "Lazarus Q1 2025 incident" at 47 techniques and return to it a week later exactly where you left off.
- **Build a fingerprint library.** Save a layer for each major campaign you track — "Operation Ghost TTPs", "SolarWinds Compromise TTPs" — and reload any of them for comparison without re-running AI analysis.
- **Maintain a baseline.** Keep a "What we detect" layer with your detection coverage and a "What we've seen" layer of your observed incidents. Load each into a fresh session to compare.
- **Share work across team members.** Layers are stored in the shared PostgreSQL database, so a layer saved by one analyst is visible to all.

### Saving a layer

1. Select your techniques in Navigator (they turn red)
2. Click **↓ Save layer** in the toolbar — this button appears only when at least one technique is selected
3. Enter a descriptive name (e.g. *"MuddyWater CTI analysis — April 2025"*)
4. Press Enter or click **Save**

The layer is immediately written to the database. The technique IDs are stored in sorted, deduplicated form together with the domain.

### Loading a layer

1. Click **📂 Load layer** in the toolbar (always visible)
2. A list of all saved layers appears, each showing the name, technique count, domain, and last-modified date
3. Click **Load** — the saved layer replaces your current selection entirely

To delete a layer you no longer need, click the **✕** button next to it in the Load dialog and confirm.

---

## Group & Campaign Similarity Deep-Dive: Three Compare Modes

The Compare view has three modes — **Groups**, **Campaigns**, and **Reports** — selectable from a switcher at the top of the page. Each answers a different similarity or overlap question.

> TTP overlap is not attribution evidence by itself. AdversaryGraph uses overlap as an analytical lead for triage, prioritization, and investigation. Attribution requires additional evidence such as malware, infrastructure, victimology, timing, procedure detail, and external intelligence.

### Mode 1 — Groups (DB 1)

With techniques selected in Navigator (or injected from an AI analysis), navigate to **Compare**, make sure **Groups (DB 1)** is selected, and click **Compare vs Groups**. This ranks the currently ingested group profiles by Jaccard similarity.

Click any group to open the four-tab detail view:

**Overview** — similarity score, shared technique chips (amber), techniques only in your layer (red). Answers: *"How much of our observed behaviour matches this group's known playbook?"*

**Tactic Breakdown** — stacked bar per kill-chain phase: shared / user-only / group-only. Reveals *where* in the kill chain the overlap is concentrated.

**Visual Diff** — compact colour-strip matrix. Best for presentations.

**Gap Analysis** — every technique in the group's known profile not in your layer. This is your detection backlog.

### Mode 2 — Campaigns (DB 1)

Switch to **Campaigns (DB 1)** and click **Compare vs Campaigns**. This ranks named operations from the currently ingested ATT&CK release by Jaccard similarity.

**Why this is more precise than group comparison:** A group's aggregate profile spans years. A campaign profile is one specific attack. Matching your TTPs against C0024 (SolarWinds Compromise) at 40% is a sharper lead than matching against G0016 (APT29) at 15%.

### Mode 3 — Reports (DB 2)

Switch to **Reports (DB 2)**. The left panel lists stored AI analyses. Click a report body to re-run Jaccard comparison against the currently ingested group profiles without re-calling the LLM.

Each report entry also has two action buttons directly below the session info:

- **↓ PDF** — download the full multi-page analysis report (cover, summary, techniques table, TTP-overlap analysis, tactic coverage) directly from the browser without re-running analysis
- **✕ Remove** — permanently delete the session from DB 2; a browser confirmation prompt guards against accidents, and the list refreshes automatically; if the deleted session was selected, the comparison results are cleared

Use this for retrospective TTP-overlap review after ATT&CK releases new group data, or to cluster multiple incidents under a common actor.

### Practical similarity-review workflow

1. Run AI analysis on your incident data (give it a descriptive name)
2. Inject extracted techniques into Navigator
3. Compare → Groups mode: look for similarity > 25%
4. Compare → Campaigns mode: check if the top group has a campaign that fits the timeline
5. Gap Analysis tab: use the technique gap as a structured hunt checklist
6. Download the PDF report for your findings

---

## Two Databases: Actor Profiles and Your Report Library

When you investigate similarity leads, there are two different things you may want to compare against:

1. **What MITRE says groups have done** — the curated ATT&CK dataset of group TTP profiles, including named campaigns (specific operations like "Operation Ghost")
2. **What you have actually observed** — your own library of analysed reports, each with its own extracted TTP mapping

AdversaryGraph v0.3 builds both into a single comparison workflow via three modes in the **Compare** view.

### DB 1: MITRE Actor Profiles and Named Campaigns

The ATT&CK STIX 2.1 bundle contains more than just group TTP profiles. It also includes:

- **`campaign` objects** — named operations with their own ATT&CK IDs (e.g. C0023 = "Operation Ghost", C0025 = "2016 Ukraine Electric Power Attack")
- **`attributed-to` relationships** — which group conducted which campaign
- **`uses` relationships at the campaign level** — the specific techniques observed in each named operation (often different from the group's aggregate profile)

AdversaryGraph parses all of this during ATT&CK ingestion. The result is two searchable, comparable datasets that both live in DB 1:

| Dataset | What it contains | ID format |
|---|---|---|
| Threat Groups | Aggregate TTP profile of each named threat group | Current ingested ATT&CK release |
| Campaigns | TTP profile of each named operation/campaign | Current ingested ATT&CK release |

**Why campaigns matter:** A group's aggregate profile is the union of everything ever attributed to them across all operations and years. A campaign profile is specific to one attack. Comparing your incident TTPs against campaigns is often more discriminating than comparing against the full group — an incident that matches C0023 (Operation Ghost) at 45% similarity is a more specific lead than a match against G0016 (APT29) at 15%.

### Viewing campaigns in the ATT&CK Group Library

The ATT&CK Group Library now has two tabs per group:

- **Techniques** — the full aggregate TTP list (existing behaviour)
- **Campaigns (DB 1)** — all named operations attributed to this group

Each campaign card shows the date range, technique count, and ATT&CK ID. Click to expand and see the full technique list with the use description from STIX.

The **"Add to my TTPs"** button on each campaign card pushes all of that campaign's techniques into your Navigator layer — useful for building a "this specific operation's TTP fingerprint" layer to compare against your detection coverage.

### DB 2: Your Report Library

Every time you run an AI analysis in AdversaryGraph, the result is stored: the extracted techniques, the summary, the group similarity leads, and the provider/model used. DB 2 is this library of past analyses.

Access it via **Compare → Reports (DB 2)**.

The left panel lists every completed report session with:
- Name (the filename or label you gave it when you uploaded)
- Technique count
- Domain
- Provider and model used
- Date

Click any report body to run a fresh Jaccard comparison of that report's extracted techniques against the currently ingested ATT&CK group profiles. This answers: *"If I return to this report later, which group profiles share the most documented behavior?"*

Each row also exposes two action buttons:

- **↓ PDF** — downloads the full analysis PDF for that session (identical to the PDF you can generate immediately after an analysis, but retrievable at any time from the library)
- **✕ Remove** — deletes the session from DB 2; a browser confirmation prevents accidental deletion; the session list updates immediately and any displayed comparison results for that session are cleared

This is useful in a few scenarios:

**Retrospective TTP-overlap review:** You analysed a report before you had a strong hypothesis about the actor. A new ATT&CK version was released that added new groups or techniques. Rerun the comparison against the updated ATT&CK data without re-running the expensive LLM analysis.

**Cross-incident correlation:** If two reports from different incidents both have high similarity to the same group profile, that is a lead for further clustering analysis, not attribution proof.

**Building a baseline:** Accumulate 20 reports over a quarter. In the Reports library you can see at a glance which groups are recurring themes across your incident set — a form of environmental threat profiling.

### The three Compare modes

| Mode | What you compare | Against |
|---|---|---|
| **Groups (DB 1)** | Your selected TTPs (from Navigator) | Currently ingested ATT&CK group profiles |
| **Campaigns (DB 1)** | Your selected TTPs (from Navigator) | Named campaigns from the ingested release |
| **Reports (DB 2)** | A stored report's extracted TTPs | Currently ingested ATT&CK group profiles |

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

AdversaryGraph generates two types of PDF reports.

### Analysis report

From the **Analyze** page, after a completed analysis, click **Download PDF**. The report is formatted for sharing with management or a client and includes:

- Cover page with provider, model, domain, session ID, and timestamp
- Executive summary (the AI-generated TL;DR)
- Extracted techniques table sorted by confidence descending
- TTP-overlap analysis section with the top Jaccard-overlap leads
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

AdversaryGraph supports Enterprise, Mobile, and ICS ATT&CK out of the box.

Switch domains using the **Domain** dropdown in the Navigator toolbar or the Analyze page.

**Enterprise ATT&CK** — use the currently ingested ATT&CK dataset for traditional IT infrastructure incidents: Windows/Linux/macOS endpoints, cloud workloads, Active Directory environments. Counts depend on the selected ATT&CK domain and release.

**Mobile ATT&CK** — covers Android and iOS threat behaviours. Useful for incidents involving mobile device management (MDM) bypass, spyware, or mobile-targeting campaigns.

**ICS ATT&CK** — covers operational technology and industrial control systems. Use for incidents involving SCADA, PLCs, HMIs, or critical infrastructure.

Each domain has its own set of tactics, techniques, and group profiles. When you run an AI analysis, select the appropriate domain so the Jaccard comparison runs against groups known for activity in that domain.

---

## API Usage (Headless / CI Integration)

AdversaryGraph exposes a full REST API. You can drive the entire workflow programmatically.

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

### Manage saved layers via API

```bash
# List all saved layers (optionally filter by domain)
curl "http://localhost:8000/api/layers?domain=enterprise-attack" | python -m json.tool

# Save a layer
curl -X POST http://localhost:8000/api/layers \
  -H "Content-Type: application/json" \
  -d '{"name": "MuddyWater Q1 indicators", "domain": "enterprise-attack",
       "technique_ids": ["T1566.001", "T1059.001", "T1078", "T1021.001"]}'

# Load a specific layer (returns technique_ids)
LAYER_ID="550e8400-e29b-41d4-a716-446655440000"
curl "http://localhost:8000/api/layers/$LAYER_ID" | python -m json.tool

# Delete a layer
curl -X DELETE "http://localhost:8000/api/layers/$LAYER_ID"
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

ATT&CK releases new versions periodically (approximately twice a year). AdversaryGraph checks for new versions daily at 03:00 UTC via a Celery Beat job.

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

**Use the Gap Analysis as a hunt checklist.** When you compare against a group profile, the Gap Analysis tab shows every technique in its known profile that you have not covered. This is useful input for a structured hunt: ask what additional observations would support or challenge the current hypothesis.

**Chain features for maximum value.** The best workflow is: AI Analysis → inject into Navigator → compare against group and campaign profiles → Gap Analysis → export PDF. Each step builds on the last.

**Chat is good for detection rules.** The AI assistant is particularly strong at generating SIGMA rules, KQL queries, and Splunk SPL from ATT&CK technique IDs. Give it the full ATT&CK technique description plus any specific context from your environment (OS, logging stack) and you'll get useful starting points rather than generic templates.

**Import your existing layers.** If your team already maintains ATT&CK Navigator layers for your environment (e.g. a "what we detect" layer and a "what we've seen" layer), import them via the ↑ Import button. AdversaryGraph will let you compare them against group profiles and run AI chat against the techniques in the layer.

**Save named layers as investigation checkpoints.** After any significant piece of work — a completed AI analysis, a finished group-comparison session, a purple-team prep layer — click **↓ Save layer** and give it a meaningful name. This takes 10 seconds and means you never lose work between sessions. You can reload any saved layer instantly from **📂 Load layer** without re-running analysis.

**Use text paste for quick triage.** You don't need a formatted document. Paste raw Slack thread text, a SIEM alert body, or a vendor advisory into the text box. The AI is good at extracting signal from noisy, informal text.

---

## Security Considerations

AdversaryGraph is designed for internal/intranet use. It has no built-in authentication — anyone who can reach the Docker network can use it.

**For a team deployment:**

1. Set a strong `DB_PASS` in `.env`
2. Put AdversaryGraph behind nginx / Caddy with TLS and HTTP Basic Auth (or integrate with your identity provider via OAuth)
3. Run the Docker containers on an internal network that is not directly internet-accessible
4. The `.env` file containing your LLM API keys should have `chmod 600` and never be committed to git

Your threat intelligence reports are stored in PostgreSQL inside the Docker volume. If you need to comply with data handling policies, deploy AdversaryGraph on infrastructure that meets those policies — since it's self-hosted, you retain full control.

---

## What's Coming Next

The tool is functional but there is plenty of room to grow. Things I'm actively thinking about:

- **TAXII/STIX import** — accept threat intelligence directly from TAXII feeds (MISP, OpenCTI, commercial CTI platforms)
- **Team collaboration** — shared TTP layers with user namespacing
- **Detection coverage overlay** — import your existing SIGMA rule library and visualise which ATT&CK techniques you have coverage for vs which are blind spots
- **Automatic group-profile tracking** — when ATT&CK releases a new version that adds techniques to a group you are tracking, send a notification

---

## Final Thoughts

The core idea behind AdversaryGraph is that the heavy lifting of ATT&CK mapping — reading a report, recognising a technique, looking it up, comparing it — is exactly the kind of repetitive, pattern-matching work that LLMs are well-suited for.

The analyst's judgement is still essential: deciding which mappings to trust, what the attribution implications are, what to do about the gap analysis. But the mechanical translation layer — text to ATT&CK IDs — should not take most of your time.

AdversaryGraph tries to handle that translation layer so you can spend your time on the interesting parts.

The project is source-available under the AdversaryGraph Personal Use License. Personal/private use is free; business, commercial, organizational, client-delivery, production, or government use requires prior written approval from Andrey Pautov. If you find it useful, have feature requests, or find bugs, open an issue on GitHub.

---

**GitHub:** https://github.com/anpa1200/adversarygraph
**API Docs:** http://localhost:8000/docs (after starting with `docker compose up`)

---

*AdversaryGraph uses the MITRE ATT&CK® framework. ATT&CK is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
