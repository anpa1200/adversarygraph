# Show HN Draft: AdversaryGraph

Use this for a Hacker News Show HN submission.

Primary rules checked:

- Show HN rules: https://news.ycombinator.com/showhn.html
- HN guidelines: https://news.ycombinator.com/newsguidelines.html

## Submit URL

```text
https://github.com/anpa1200/adversarygraph
```

Use the repository, not the Medium article. Show HN posts should point to
something people can try.

## Title

Recommended:

```text
Show HN: AdversaryGraph – self-hosted CTI-to-detection workbench
```

Alternatives:

```text
Show HN: AdversaryGraph – map threat reports to ATT&CK and detection rules
Show HN: AdversaryGraph – local CTI workbench for ATT&CK mapping
```

Avoid:

- "AI-powered ultimate cyber platform"
- "revolutionary"
- "best"
- "complete"
- excessive uppercase or exclamation marks

## Text / First Comment

HN sometimes does not show the optional submission text prominently. If that
happens, post this as the first comment.

```text
Hi HN,

I built AdversaryGraph as a self-hosted CTI-to-detection workbench. The problem I was trying to solve was the gap between reading threat reports and turning them into something useful for ATT&CK review, actor comparison, IOC context, and detection engineering.

The tool runs with Docker Compose and includes:

- ATT&CK / ATLAS matrix navigation
- threat actor and campaign comparison by TTP overlap
- AI-assisted report mapping through local, Claude, OpenAI, Gemini, or MiniMax providers
- source-backed IOC library with ThreatFox, OTX, VirusTotal lookup, MISP/STIX/TAXII/custom feed workflows
- sector relevance scoring for actors
- Sigma, YARA, YARA-L, KQL, SPL, and EQL detection skeletons, plus optional AI-assisted rule generation
- export paths for Navigator layers, CSV, JSON, PDF, and STIX

It is not meant to be an attribution engine. Similarity scores are investigation leads, and AI output is explicitly marked as analyst-review material.

The repo has a Docker quickstart:

git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
cp .env.example .env
docker compose up -d --build

I would appreciate technical feedback on the architecture, the CTI-to-detection workflow, and which integrations would make it more useful for analysts or detection engineers.
```

## Short Version For Comment Replies

Use if someone asks "what does it do?":

```text
It is a self-hosted workbench for turning CTI/report text into ATT&CK mappings, actor/campaign comparisons, IOC context, and detection-rule handoff. The main goal is analyst workflow support, not automated attribution.
```

Use if someone asks "is this just an LLM wrapper?":

```text
No. The LLM path is optional. The platform also syncs ATT&CK/ATLAS, actor profiles, campaigns, IOC sources, sector metadata, Sigma/YARA feeds, and keeps local PostgreSQL-backed workspaces. AI output is treated as suggested analyst-review material.
```

Use if someone asks about privacy:

```text
The Docker deployment is self-hosted. Report text goes only to the LLM provider the operator configures. For private environments, use the local/OpenAI-compatible provider path. The public web workspace should not be used for confidential reports.
```

Use if someone asks about license:

```text
The current license allows personal/private use. Business use requires approval from the author. I know that is narrower than permissive OSS; I am still deciding what model makes sense for the project.
```

## Pre-Submission Checklist

- [ ] Submit the GitHub repo URL, not the Medium article.
- [ ] Use a plain `Show HN:` title.
- [ ] Do not ask anyone to upvote or comment.
- [ ] Be available for comments for a few hours after posting.
- [ ] Answer technically and briefly; avoid marketing language.
- [ ] If there is criticism, acknowledge real issues and describe tradeoffs.
- [ ] Do not repost if it does not get traction.

## Posting Steps

1. Open https://news.ycombinator.com/submit
2. URL: `https://github.com/anpa1200/adversarygraph`
3. Title: `Show HN: AdversaryGraph – self-hosted CTI-to-detection workbench`
4. Submit.
5. If no text appears at the top of the thread, add the prepared text as the
   first comment.

