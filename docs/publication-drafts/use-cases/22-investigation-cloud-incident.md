# AdvarsaryGraph Usecases.

## Draft

## Usecase number "22"

### Investigation: Cloud And Kubernetes Incident: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Investigate a cloud/Kubernetes incident using sector, TTP, IOC, and detection context.

## Why This Use Case Matters

Investigate a cloud/Kubernetes incident using sector, TTP, IOC, and detection context. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A Kubernetes workload starts beaconing externally after unusual service account behavior. Cloud logs show API calls, container execution, and suspicious network egress.

**Trigger:** Traditional endpoint-centric triage does not explain the full cloud control-plane activity.

**Analyst objective:** The analyst needs to combine cloud/Kubernetes context, ATT&CK behavior, IOC enrichment, and telemetry requirements into one investigation flow.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Create workspace and select cloud/Kubernetes technology context.**
2. **Import incident notes, audit logs summary, or report text.**
3. **Run AI extraction and manually validate cloud-relevant TTPs.**
4. **Use Sector Intel filters for cloud/Kubernetes-related actor relevance.**
5. **Extract service accounts, domains, IPs, tools, and hashes as IOCs/artifacts.**
6. **Enrich observables and identify malware/tool families where possible.**
7. **Compare TTPs to actor and campaign profiles.**
8. **Review ATT&CK matrix for cloud-adjacent execution, persistence, discovery, credential access, and exfiltration.**
9. **Map each accepted TTP to available telemetry such as Kubernetes audit, cloud control plane, EDR, or proxy logs.**
10. **Export a PDF and a detection backlog for the cloud/SOC team.**


## Expected Output

Cloud incident CTI package with prioritized telemetry-backed detection work.

## Analyst Review Standard

- Keep source evidence and source labels attached.
- Mark uncertain findings as `needs-evidence` instead of forcing a conclusion.
- Do not treat TTP similarity as attribution by itself.
- Use enrichment as context, not as an automatic decision.
- Export only reviewed findings.

## Where This Fits

This use case can support CTI production, SOC triage, threat hunting, detection engineering, customer reporting, or platform validation depending on the workflow level.

**Project:** https://github.com/anpa1200/adversarygraph  
**Docs:** https://1200km.com/adversarygraph-docs/  
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
