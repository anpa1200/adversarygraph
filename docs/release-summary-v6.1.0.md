# AdversaryGraph v6.1.0 Unpublished Source-Milestone Summary

> **Superseded:** v6.1.0 was not published as an immutable stable tag or GitHub
> release. The supported release narrative is
> [v6.5.0](release-notes/v6.5.0.md).

This historical milestone turned the post-v6 development line into a governed
self-hosted threat-operations release. Its central additions are inventory-bound
asset assessment, persistent SOC access groups, module-level authorization,
Threat Hunting query engineering, and unified RAG/MCP assistance.

## Operational Outcome

- Platform Administrators can manage the complete platform.
- SOC Managers can supervise operational workflows without changing platform
  configuration or identity policy.
- SOC Tier 1 receives a focused IOC-investigation, reporting, evidence-intake,
  and escalation workspace; Tier 2 and Tier 3 progressively add correlation,
  advanced analysis, hunting, validation, and response engineering.
- Specialist CTI, hunting, detection, IR, vulnerability, feed, and audit groups
  receive role-appropriate modules and actions.
- Administrators can create named accounts with visible password-policy
  guidance, autofill-safe submission, least-privilege group assignment, and
  explicit validation feedback instead of an unexplained disabled action.
- Analysts can open a saved company asset, review evidence-labelled
  CVE/TTP/IOC context, and run an explicitly authorized assessment against an
  inventory-approved target.
- Detection teams can move from a hypothesis or IOC to a reviewed query, ATT&CK
  mapping, validation scenario, and recorded outcome.
- Evaluators and operators have a module-by-module casebook covering every
  governed workspace, including access context, prerequisites, repeatable
  workflows, outputs, examples, case studies, acceptance evidence, and limits.

## Trust Boundary

Authorization is enforced in both the interface and backend API; hiding a menu
item is never the security boundary. The release prevents loss of the final
user manager and prevents custom groups from impersonating the built-in
Platform Administrators profile.

Asset and AI results remain analyst-review material. Passive provider records,
open ports, product-family CVE candidates, RAG retrieval, and LLM output do not
prove compromise or vulnerability applicability.

## Release Evidence

The source change set passed 720 backend tests, the 60% coverage gate at 67.5%,
frontend lint and production build, ten RBAC and administration Playwright
tests, Ruff, patch hygiene, and local Compose health checks. Immutable
container and digest evidence is produced only by the successful v6.1.0 tag
workflow.

See the [complete release notes](release-notes/v6.1.0.md),
[authentication guide](authentication-and-users.md),
[Threat Radar guide](threat-radar.md), and
[production-readiness boundary](production-readiness.md).
