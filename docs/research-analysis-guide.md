# Research Analysis Guide

AdversaryGraph workflow for turning a strategic cyber research report into
reviewed CTI, CVE context, ATT&CK mappings, detection requirements, and
validation tasks.

Worked source:
`/home/andrey/git-projects/nvidia/researches/Research_Fable_FINAL.md`

Source theme:
embedded systems, hardware vendors, firmware, edge appliances, BMC, UEFI,
GPU/AI accelerators, SOHO/IoT, OT/IoT, and appliance persistence.

## Analyst Outcome

After processing the research in AdversaryGraph, the analyst should have:

- A saved analyzed report with clickable inline links to TTPs, IOCs, CVEs,
  threat actors, sectors, infrastructure classes, and source evidence.
- A reviewed entity set for CVEs, campaigns, vendors, asset classes, and
  infrastructure categories.
- Candidate ATT&CK mappings separated from confirmed source facts.
- A CVE-to-asset and CVE-to-TTP review backlog.
- Telemetry Readiness Score per accepted TTP.
- Detection engineering gaps for edge, firmware, BMC, UEFI, GPU, and OT/IoT
  monitoring.
- A report-ready summary with confidence and validation notes.

## Important Source Handling Rule

The source report contains many campaign names, CVEs, vendors, asset classes,
and defensive recommendations, but it does not embed explicit ATT&CK technique
IDs. In AdversaryGraph, treat ATT&CK mappings as analyst-reviewed candidates.
Do not mark a TTP as confirmed only because an actor, product, or vulnerability
is mentioned.

Use this separation:

| Item type | Source-backed immediately | Needs analyst mapping |
|---|---|---|
| CVE IDs | Yes, when explicitly listed in the report | Link to products, assets, KEV state, CVSS, and likely exploitation behavior |
| Threat actors and campaigns | Yes, when named in the report | Link to ATT&CK group/campaign profiles and compare behavior |
| Vendors and asset classes | Yes, when named in scope or risk matrix | Link to asset inventory and exposure data |
| ATT&CK techniques | No explicit IDs in the source | Validate from behavior evidence, not actor reputation |
| Detection requirements | Yes, when described as telemetry needs | Translate to required data components and readiness gaps |

## Source-Backed Entity Seed

Use these as the first deterministic tags in the Reports / Research collection.

### Campaigns and Actors

- Volt Typhoon / KV Botnet
- UAT-4356 / Storm-1849 / ArcaneDoor / FIRESTARTER
- UNC3886 / RedPenguin
- UNC5221
- UNC4841
- Sandworm / Cyclops Blink / AcidRain
- Mirai-derived IoT botnets

### CVEs

- CVE-2022-21894
- CVE-2022-40982
- CVE-2023-20198
- CVE-2023-20273
- CVE-2023-2868
- CVE-2023-46805
- CVE-2023-4969
- CVE-2024-21887
- CVE-2024-3400
- CVE-2024-36347
- CVE-2024-54085
- CVE-2024-56161
- CVE-2025-20333
- CVE-2025-20362
- CVE-2025-22457
- CVE-2025-54510
- CVE-2025-68686

### Asset and Infrastructure Tags

- internet-facing edge appliance
- VPN gateway
- firewall
- router
- mail security gateway
- load balancer
- MDM appliance
- BMC / IPMI / Redfish
- UEFI / BIOS / Secure Boot
- GPU / AI accelerator
- CPU microcode
- confidential computing
- SOHO router
- IoT / NVR / camera
- OT / IoT router
- BMS / BAS
- PLC-adjacent infrastructure
- satellite / telecom modem

### Sector Tags

- critical infrastructure
- communications
- energy
- transportation
- water
- government
- cloud and AI infrastructure
- OT / industrial
- telecom

## End-to-End Workflow

### 1. Ingest The Research

Module: **AI Analysis**

1. Open `AI Analysis`.
2. Paste the Markdown report or upload the converted PDF/DOCX/TXT.
3. Set domain to CTI / infrastructure risk.
4. Choose the configured LLM provider.
5. Run extraction.
6. Save the analysis session.
7. Open the linked report view.

Expected result:

- Summary of strategic findings.
- Extracted CVEs.
- Extracted actors, campaigns, vendors, sectors, and infrastructure tags.
- Candidate TTPs only where the model can cite behavior text.

Validation:

- Reject mappings that rely only on actor reputation.
- Require source text for every accepted TTP.
- Keep low-confidence mappings as backlog items.

### 2. Open The Linked Report

Module: **Linked Report Review**

Use the linked report page to inspect the original research with inline
platform links.

Required links:

- CVE links to CVE Library.
- Actor links to ATT&CK Group Library when the actor exists locally.
- Candidate TTP links to Navigator.
- IOC links to IOC Library only if an actual observable is present.
- Sector and infrastructure tags to Reports / Research filters.

Analyst checks:

- Does each highlighted phrase preserve the original meaning?
- Does a CVE mention include product context?
- Does a campaign mention include observed tradecraft?
- Is the infrastructure tag specific enough for asset-surface review?

### 3. Build A Research Collection Entry

Module: **Reports / Research**

The report should appear as a tagged intelligence object.

Minimum tags:

- `embedded-systems`
- `hardware-vendors`
- `firmware`
- `edge-appliances`
- `bmc`
- `uefi`
- `gpu-ai`
- `soho-iot`
- `ot-iot`
- `appliance-persistence`

Use the collection page to answer:

- Which reports mention the same CVE?
- Which reports mention the same actor?
- Which reports discuss the same infrastructure class?
- Which reports produce the same detection telemetry requirements?

### 4. Enrich CVEs

Module: **CVE Library**

For each CVE listed above:

1. Open the CVE record.
2. Confirm CVSS score, severity, vector, CWE, NVD description, and modified
   date.
3. Confirm CISA KEV state when available.
4. Link affected vendor/product context.
5. Add relationship notes to likely TTP review candidates.

Use this table for the working review.

| CVE | Product context from research | Analyst action |
|---|---|---|
| CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect / Captive Portal | Review edge exploitation and internet-facing exposure |
| CVE-2023-46805 + CVE-2024-21887 | Ivanti Connect Secure / Policy Secure chains | Review VPN appliance exploitation chain |
| CVE-2025-22457 | Ivanti Connect Secure | Review appliance malware and integrity-check guidance |
| CVE-2023-20198 + CVE-2023-20273 | Cisco IOS XE | Review exposed management and privilege path |
| CVE-2025-20333 + CVE-2025-20362 | Cisco ASA/FTD FIRESTARTER context | Review persistence and reimage requirements |
| CVE-2023-2868 | Barracuda ESG | Review replacement guidance and mail-gateway position |
| CVE-2024-54085 | AMI MegaRAC BMC | Review Redfish/IPMI exposure and BMC isolation |
| CVE-2022-21894 | Secure Boot / BlackLotus | Review boot-chain trust and revocation state |
| CVE-2023-4969 | GPU local memory leakage | Review AI/GPU workload isolation |

### 5. Map Candidate ATT&CK Techniques

Module: **Navigator**

Because the source does not provide explicit TTP IDs, start with candidate
techniques and validate each one from behavior text.

Candidate review areas:

| Research behavior | Candidate ATT&CK area | Evidence requirement |
|---|---|---|
| Exploiting internet-facing VPN, firewall, router, mail gateway, or MDM appliance | Initial access via public-facing service or external remote service | Product, exposure, exploit path, and observed access behavior |
| Appliance-native malware, startup scripts, symlinks, LINA hooks, router backdoors | Persistence and defense evasion | File/process/config evidence showing durable foothold |
| Credential, VPN secret, certificate, SSH key, admin hash, API token theft | Credential access | Source text showing credential material access or theft |
| SOHO router and appliance relay infrastructure | Proxy / command-and-control infrastructure | Evidence of relay, proxying, or C2 routing |
| Logging disablement or off-device log requirement | Defense evasion and telemetry gap | Evidence of log tampering or missing local telemetry |
| Pivot from appliance into AD, cloud, virtualization, or OT | Lateral movement | Evidence of post-edge movement path |
| Modem wiping, firewall reload, logging disablement, destructive activity | Impact | Evidence of destruction, disruption, or wipe activity |

Do not accept a mapping until the linked report shows source text that supports
the behavior.

### 6. Score Telemetry Readiness

Module: **Navigator technique panel**

For every accepted TTP, fill the Telemetry Coverage Matrix.

Example for edge appliance exploitation:

| Technique | Required Data Components | Available Logs | Missing Telemetry | Detection Feasibility |
|---|---|---|---|---|
| Candidate edge exploitation TTP | Edge appliance HTTP/API logs, VPN auth logs, config-change logs, crash/core evidence, firmware version, external exposure state | Firewall/VPN syslog, reverse proxy, EDR only after pivot, CISA KEV context | Full appliance process telemetry, volatile memory, filesystem integrity, off-device logs | Medium |

Example for BMC compromise:

| Technique | Required Data Components | Available Logs | Missing Telemetry | Detection Feasibility |
|---|---|---|---|---|
| Candidate BMC access/control TTP | Redfish/IPMI auth logs, management network flow, BMC firmware version, power-control events, virtual-media events | Network flow, BMC audit logs if enabled, CMDB/BMC inventory | EDR visibility, host OS logs, complete Redfish method audit | Medium-low |

Example for UEFI / boot trust:

| Technique | Required Data Components | Available Logs | Missing Telemetry | Detection Feasibility |
|---|---|---|---|---|
| Candidate boot-chain manipulation TTP | Secure Boot state, db/dbx/KEK versions, bootloader hashes, firmware update events, attestation | Endpoint attestation, firmware inventory, vendor update history | Runtime preboot telemetry, historical dbx state, firmware filesystem diff | Low to medium |

### 7. Map Assets To Risk

Module: **Asset Surface**

Create or upload an inventory that includes:

- Vendor and model.
- Hardware revision and serial.
- Firmware, BMC, BIOS/UEFI, bootloader, microcode, GPU driver, and OS version.
- Enabled services such as SSL-VPN, GlobalProtect, Web UI, Redfish, IPMI, SSH,
  SNMP, PXE, captive portal, SD-WAN management, and remote console.
- External exposure and management-plane exposure.
- End-of-life / end-of-support state.
- Inherited components such as AMI MegaRAC, EDK II, OpenSSL, mbedTLS, libssh2,
  BusyBox, and Linux kernel version.
- Secure Boot status and certificate state.

AdversaryGraph output should include:

- Exposed Tier-0 edge devices.
- Unsupported edge devices.
- CVE hits by product/version.
- Firmware lifecycle gaps.
- Missing telemetry per asset class.
- Suggested TTP review candidates.
- Priority actions for replacement, isolation, patching, reimage, or
  credential rotation.

### 8. Correlate Actor, Campaign, And Behavior

Modules: **ATT&CK Group Library**, **Compare**, **Evidence Graph**

Use named actors and campaigns as pivots:

- Volt Typhoon / KV Botnet for SOHO relay and critical infrastructure context.
- UAT-4356 / ArcaneDoor / FIRESTARTER for Cisco ASA/FTD appliance persistence.
- UNC3886 / RedPenguin for Juniper router backdoors and logging disablement.
- UNC5221 for Ivanti Connect Secure appliance exploitation.
- UNC4841 for Barracuda ESG exploitation and appliance compromise.
- Sandworm / Cyclops Blink / AcidRain for network-device malware and
  destructive modem/router activity.

Rules:

- Similarity is an investigation lead, not attribution proof.
- Actor overlap does not prove the actor is present in the environment.
- A campaign should be linked to a finding only when the report itself gives
  source-backed context.

### 9. Create Evidence-To-Detection Graph

Module: **Evidence Graph**

Create one graph per major research claim:

```text
Source evidence
  -> claim
  -> observed or inferred behavior
  -> candidate ATT&CK technique
  -> required telemetry
  -> detection candidate
  -> validation scenario
  -> analyst decision
```

Recommended graph claims:

- Internet-facing edge devices are Tier-0 exposure.
- Appliance persistence can survive patch-only remediation.
- BMC compromise bypasses host OS controls.
- Secure Boot depends on certificate, dbx, bootloader, and firmware lifecycle.
- Shared GPU/AI infrastructure needs tenant-isolation validation.
- SOHO/IoT infrastructure can be used as strategic relay infrastructure.
- OT/IoT risk is driven by lifecycle, exposure, and weak asset intelligence.

### 10. Validate With Attack Simulation Only Where Safe

Module: **Attack Simulation**

Use attack simulation for SIEM and detection validation, not for proving the
source report. Only run authorized lab-safe simulations.

Suitable validation examples:

- Web or VPN-style brute-force telemetry.
- Suspicious edge admin login pattern.
- Configuration-change style event.
- Syslog forwarding and SIEM parsing validation.
- Windows/Sysmon process or credential-access telemetry when the candidate TTP
  requires endpoint evidence.

Do not simulate firmware implant, BMC compromise, bootkit installation, or
destructive modem/router activity on real infrastructure. For those, validate
coverage with vendor logs, asset inventory, tabletop evidence, and controlled
atomic telemetry fixtures.

### 11. Build Statistics Views

Module: **Statistics**

Recommended widgets for this research:

- CVE severity distribution across edge, BMC, UEFI, GPU, and OT/IoT classes.
- CISA KEV count by vendor.
- Unsupported asset count by vendor/model.
- Top affected infrastructure classes.
- TTP candidate frequency by asset class.
- Telemetry readiness by technique.
- Missing telemetry by platform.
- Actor/campaign mentions by sector.
- CVE-to-TTP relationship density.
- Sector exposure by asset class.

### 12. Produce Analyst Output

Module: **Investigation Report**

The final output should include:

- Executive judgment.
- Source-backed entities.
- CVE table with CVSS, KEV, CWE, product, and exposure notes.
- Candidate TTP table with evidence and confidence.
- Telemetry Readiness Score by TTP.
- Asset inventory gaps.
- Detection backlog.
- Incident-response actions.
- Validation gaps.
- Next collection requirements.

## Quality Gate Checklist

Before publishing the analysis:

- Every accepted TTP has source evidence.
- Every CVE links to product or asset context.
- Every actor/campaign mention is marked as source-backed, inferred, or only
  contextual.
- Every IOC is source-backed and fresh enough for the use case.
- Every detection recommendation has required telemetry listed.
- Every missing telemetry item has an owner or next step.
- Every high-risk edge or BMC finding includes exposure and lifecycle state.
- Every firmware/UEFI/GPU finding distinguishes remote exploitation from
  local/privileged trust-boundary risk.
- Every remediation note distinguishes patch, reimage, replacement, credential
  rotation, and validation.

## Suggested Report Tags

Use consistent tags so Statistics and Reports / Research filters work.

| Tag field | Suggested values |
|---|---|
| Risk | critical, high, medium, lifecycle-risk, telemetry-gap, trust-boundary-risk |
| Confidence | confirmed, high-confidence, assessed |
| Region | global, critical-infrastructure, sector-specific |
| Sector | government, communications, energy, transportation, water, cloud-ai, industrial |
| Infrastructure | vpn, firewall, router, bmc, uefi, gpu, soho, iot, ot, mail-gateway, mdm |
| Telemetry | syslog, vpn-auth, appliance-config, bmc-redfish, ipmi, netflow, edr, firmware-inventory, secure-boot-state |
| Lifecycle | supported, end-of-support, unknown-firmware, missing-oem-patch, replacement-required |
| Action | patch, isolate, replace, reimage, rotate-secrets, enable-off-device-logs, validate-compromise |

## AdversaryGraph Module Map

| Research task | Primary module | Supporting module |
|---|---|---|
| Import and summarize research | AI Analysis | Reports / Research |
| Review source text with links | Linked Report Review | Knowledge Library |
| Normalize CVEs | CVE Library | Statistics |
| Normalize assets | Asset Surface | CVE Library |
| Review actor/campaign context | ATT&CK Group Library | Compare |
| Validate TTP candidates | Navigator | Evidence Graph |
| Plan telemetry | Navigator technique panel | Evidence Graph |
| Test SIEM ingestion | Attack Simulation | Observability |
| Compare sector risk | Sector Intel | Statistics |
| Write handoff report | Investigation Report | Exports |

## Minimal Practical Runbook

1. Import `Research_Fable_FINAL.md` into AI Analysis.
2. Save the session.
3. Open the linked report page.
4. Confirm CVEs and actors from the source text.
5. Open CVE Library and enrich the CVE list.
6. Create an Asset Surface inventory for edge, BMC, UEFI, GPU, SOHO/IoT, and
   OT/IoT assets.
7. Review candidate ATT&CK mappings in Navigator.
8. Fill Telemetry Coverage Matrix for accepted TTPs.
9. Build Evidence Graphs for the seven major research claims.
10. Use Attack Simulation only for safe telemetry validation.
11. Build Statistics views for CVE severity, KEV, asset class, and telemetry
    readiness.
12. Export an investigation report with validation gaps and next collection
    requirements.

## Unified Intelligence Search

In v6.5, stored analysis reports can enter the
Unified RAG corpus after reconciliation. The derived document retains the
report's stored TLP, source reference, version, timestamps, legal-sensitivity,
and verification context. Use grounded search to reconnect a new question to
existing reports, IOCs, CVEs, actors, techniques, and evidence nodes, then open
the cited source before accepting a claim. Retrieval does not promote a report
or turn an AI extraction into confirmed evidence. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md).
