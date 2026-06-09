# Anomaly Detection Mapped to MITRE ATT&CK

## Scope and key findings

This report covers **Enterprise ATT&CK** and uses **MITRE ATT&CK v19.1** as the latest version visible in MITRE’s version history and live Enterprise matrix at the time of research. The access date for this report is **8 June 2026**. The Enterprise matrix currently spans Windows, macOS, Linux, PRE, Office Suite, Identity Provider, SaaS, IaaS, Network Devices, Containers, and ESXi, which is the right breadth for a cross-environment anomaly-detection study. citeturn0search7turn45search4

The highest-confidence conclusion is that anomaly detection adds the most value where an adversary’s behaviour creates a **contextual change in relationships, sequences, or baselines**, not merely a suspicious artefact. MITRE’s newer ATT&CK detection-strategy pages explicitly describe anomaly-friendly patterns for DCSync, Kerberoasting, PowerShell abuse, scheduled tasks, Registry autoruns, email forwarding rules, Group Policy modification, network service discovery, container deployment, and container escape. In other words, MITRE itself is now articulating many detections in behavioural and correlation-centric terms rather than as single-event signatures. citeturn35view0turn36view0turn37view0turn38view0turn39view0turn40view0turn41view0turn42view0turn43view0turn44view0

The strongest anomaly-detection opportunities fall into five clusters. First, **identity misuse**: valid account abuse, Kerberos anomalies, privilege or credential additions, and mailbox-rule tampering all create deviations against an account’s own history, its peer group, or its relationship graph. Second, **execution and persistence**: PowerShell, scheduled tasks, startup persistence, and service or policy changes are often rare for the affected user, host, or process lineage. Third, **discovery and lateral movement**: scanning and unexpected remote-administration paths are naturally graph and sequence problems. Fourth, **cloud and container administration**: data-access spikes, new privileged container launches, and first-seen admin actions are classic peer-group and novelty anomalies. Fifth, **impact and exfiltration side effects**: ransomware-style file bursts and abnormal upload/download fan-out are often easier to detect as volume and drift anomalies than the initial intrusion itself. citeturn45search9turn36view0turn35view0turn42view0turn37view0turn38view0turn39view0turn40view0turn43view0turn44view0turn25view0

The weakest areas for anomaly detection are techniques whose useful signal is primarily **content-specific**, **tool-specific**, or **policy-deterministic**. If the best detection is “this hash,” “this exploit string,” “this user-agent,” or “this change should never happen,” then anomaly methods are usually secondary to signatures, content inspection, or preventive controls. Windows and Sysmon telemetry pages also reinforce the point that raw events are *evidence, not alerts*; meaning emerges through correlation, context, and behavioural patterns over time. citeturn34view0

This report deliberately does **not** force a full-technique mapping across the entire Enterprise matrix in one pass. Instead, it follows the staged research sequence implied by the prompt: define the anomaly taxonomy, catalogue the log sources, then concentrate on the techniques with the clearest evidence and the highest operational value. That produces a more defensible result than pretending every ATT&CK technique is a good anomaly candidate.

## Where anomaly detection fits and where it does not

A practical anomaly taxonomy for ATT&CK work needs to be operational rather than academic. The useful categories are: **self-baseline anomalies** for “this entity is behaving unlike itself”; **peer-group anomalies** for “this entity is unlike comparable entities”; **temporal anomalies** for unusual time, burst, cadence, or seasonality; **rarity or novelty anomalies** for first-seen processes, destinations, commands, credentials, or admin actions; **sequence anomalies** for surprising orderings of otherwise legitimate events; **graph anomalies** for new edges between users, hosts, mailboxes, services, identities, buckets, or containers; and **cross-source anomalies** where nothing is suspicious until two or more sources are fused. Those are precisely the kinds of patterns ATT&CK’s recent detection strategies are leaning on for DCSync, Kerberoasting, PowerShell, email forwarding, service discovery, and container behaviour. citeturn35view0turn36view0turn39view0turn40view0turn42view0turn43view0turn44view0

The simplest useful models are usually not “AI” in the grand sense. MITRE’s own guidance for many techniques can be implemented with rarity scores, entity-specific baselines, correlation windows, expected-admin lists, image allow-lists, or known-good service-account baselines. These are interpretable, cheaper to maintain, and more resilient in SOC operations than opaque models. For example, MITRE’s Kerberoasting strategy recommends unusual TGS request counts, anomalous service-account targeting, and correlation to LSASS/process-access behaviour; its DCSync strategy relies on non-DC replication requesters plus DRSUAPI-related traffic; its Deploy Container strategy relies on non-admin users, unknown images, and risky runtime attributes within a short causal window. citeturn36view0turn35view0turn43view0

The main design rule is simple: **do not call something anomaly-based unless the suspicion arises from a contextual comparison**. A universal threshold, a vendor IOC, or a single “bad-looking” event is not an anomaly detector. MITRE’s Windows telemetry guidance is especially useful here: Sysmon is observational, composable, and neutral; no single event denotes maliciousness on its own. That is exactly why anomaly logic should be expressed as baseline-plus-context rather than as isolated event matches. citeturn34view0

Cold-start handling matters more than most detection content admits. Endpoint and identity behaviours with sufficient volume can reasonably start from local baselines after several weeks of data, but low-frequency administrative actions, cloud-control-plane actions, and service-account behaviour usually need longer windows and peer-group fallback. When the entity has too little history, the safer default is to score against a peer cohort and require either a second signal or an analyst-visible explanation of novelty. This is an operational inference from the sparsity and optionality visible in Entra, CloudTrail, GCP, Kubernetes, and mailbox-audit telemetry rather than a vendor-prescribed fixed number. citeturn27view0turn28view0turn29view0turn25view0turn23view4turn21view0

## Log-source and field catalogue

The table below is a normalised catalogue of the most useful log sources for anomaly-backed ATT&CK coverage. The “essential fields” are deliberately limited to the fields that repeatedly matter for baselining, graphing, and causal correlation.

| Source | Behaviours revealed | Essential fields | Common quality problems | Retention and baseline note | Evidence |
|---|---|---|---|---|---|
| **Windows Security Event Log** | Logons, account creation, scheduled tasks, AD object changes, Kerberos service-ticket requests, security-log clearing | `EventID`, `TimeCreated`, `Subject*`, `Target*`, `LogonType`, `IpAddress`, `TaskName`, `ObjectDN`, `ServiceName`, `TicketEncryptionType` | High-volume DC noise; `4662` only appears with the right SACL; some fields vary by OS version | Core identity baselines need long windows; DC-admin actions should be baselined separately from user endpoints | citeturn12search0turn12search1turn12search2turn12search3turn19search0turn19search1turn19search6turn33search3 |
| **Sysmon** | Process creation, process access, DLL/image load, network connect, DNS query, registry persistence, file creation/deletion | `EventID`, `ProcessGuid`, `Image`, `CommandLine`, `ParentImage`, `ParentProcessGuid`, `User`, `Hashes`, `TargetImage`, `DestinationIp`, `DestinationPort`, `QueryName`, `TargetObject` | Event 3/7/10 are high-volume; selective enablement is required; poor config destroys signal quality | Best suited to host, process-tree, first-seen, and sequence baselines | citeturn11search6turn34view0turn19search3turn32search3turn33search4 |
| **PowerShell operational logs** | Script-block execution, module usage, runspace/session metadata, indirect PowerShell abuse | `EventID`, `HostApplication`, `ScriptBlockText`, `ModuleName`, `RunspaceId`, `PipelineId` | Script-block and module logging may not be enabled; transcription is environment-specific | Excellent for rarity and sequence models; best when joined to Sysmon process trees | citeturn13search15turn13search0turn13search1turn42view0 |
| **Linux auditd** | Process execution, syscall activity, file changes, authentication-relevant actions | `type`, `timestamp`, `exe`, `auid`, `uid`, `pid`, `ppid`, `cwd`, `argv`, `key` | Events are verbose and interleaved; poor rule design causes both blind spots and floods | Strong for peer-group and sequence baselines on servers and containers | citeturn14search0turn14search1turn14search12turn40view0turn44view0 |
| **macOS Endpoint Security and Unified Logging** | Process execution, file access, security-relevant system events, Apple Mail rule changes depending on sensor coverage | Sensor-specific process, path, parent, user, signing, file-event fields | Exact field names depend on the collector; native coverage is broader with an ES-based sensor than with generic logs alone | Best treated through EDR-normalised schemas rather than raw platform assumptions | citeturn14search3turn39view0 |
| **Network NSM and flow telemetry** | Port scans, service discovery, unusual east-west edges, exfil volume, process-to-destination rarity | Source/destination IP and port, protocol, bytes, packets, duration, action; where available, process or container attribution | No application context in plain flow logs; NAT and middleboxes distort identity; packet content often unavailable | Flow/NSM is essential for graph and volume anomalies, but rarely sufficient by itself | citeturn11search0turn11search5turn30view0turn40view0 |
| **Active Directory and Entra ID** | Interactive and non-interactive sign-ins, service-principal sign-ins, role and credential changes, Conditional Access and policy changes | `UserPrincipalName`, `UserId`, `AppDisplayName`, `AppId`, `IPAddress`, `Location`, `AutonomousSystemNumber`, `DeviceDetail`, `UserAgent`, `ResultType`, `ActivityDisplayName`, `InitiatedBy`, `TargetResources` | Entra can be rich but requires export for good querying; admin noise is sparse and heavily peer-group dependent | Identity baselines should distinguish human users, service principals, managed identities, and break-glass/admin accounts | citeturn8search0turn8search1turn27view0turn28view0turn16view1turn16view2 |
| **AWS CloudTrail and VPC Flow Logs** | IAM changes, STS usage, S3 object access, network activity, unusual role assumptions | `eventTime`, `userIdentity`, `eventSource`, `eventName`, `requestParameters`, `resources`, `recipientAccountId`; for flow logs `srcaddr`, `dstaddr`, `srcport`, `dstport`, `bytes`, `packets`, `action` | **Data events are not logged by default**; object-level visibility for S3 requires explicit enablement; flow logs lack process identity | Baselines should separate humans, automation, roles, and cross-account activity | citeturn29view0turn8search10turn17search2turn17search3turn17search7turn17search15turn30view0 |
| **Azure Activity, AuditLogs, and SigninLogs** | Resource-manager writes/deletes/actions, tenant audit activity, sign-ins, Azure RBAC elevation and Entra admin changes | `OperationName`, `ResourceId`, `resourceProviderName`, `caller/clientIpAddress` where available; `ActivityDisplayName`, `InitiatedBy`, `TargetResources`; `UserPrincipalName`, `IPAddress`, `Location`, `ASN`, `DeviceDetail`, `UserAgent`, `AppDisplayName`, `ResultType` | Different schemas by ingestion route; activity logs cover control plane, not all data plane | Strong for control-plane and identity anomalies; join with Entra and resource-specific logs | citeturn31view0turn18search6turn28view0turn27view0 |
| **GCP Cloud Audit Logs** | Admin activity, data access, policy-denied events, cloud-storage access and IAM-sensitive operations | `protoPayload.serviceName`, `protoPayload.methodName`, `authenticationInfo.principalEmail`, `resource`, `timestamp`, `logName` | **Data Access logs are disabled by default except BigQuery**; some identity and resource details may be redacted | Excellent for principal-to-resource graph baselines and data-access drift | citeturn25view0turn24view0 |
| **Kubernetes audit and runtime telemetry** | API-driven cluster actions, pod specs, verbs, object targets, privileged workload creation, hostPath use, container start and follow-on activity | Requesting user, timestamp, resource, verb, request URI, stage; runtime attributes such as `privileged`, `hostPID`, `hostNetwork`, host mounts | If `--audit-policy-file` is omitted, no audit events are logged; runtime and audit streams are often siloed | High-value for sequence and graph anomalies, especially create→start→activity chains | citeturn22view0turn23view4turn43view0turn44view0 |
| **Mailbox and SaaS audit logs** | Inbox-rule creation, forwarding abuse, mailbox changes, Google Workspace login and OAuth activity | Operation name, actor, target mailbox/resource, destination forwarding address, `principalEmail`, `callerIp`, `methodName`, timestamp | Retention and licensing differ; mailbox and transport-rule data are not identical | Strong for first-seen admin/user actions, new forwarding destinations, and cross-source identity-to-mailbox anomalies | citeturn21view0turn20view0turn10search1turn26view0 |

The most important telemetry caveats are not subtle. CloudTrail **data events** are off by default; GCP **Data Access** is off by default except BigQuery; Kubernetes audit logging is absent unless configured; Sysmon networking, process-access, and image-load visibility depends on deliberate enablement and tuning; Windows AD object access events require the right SACLs; and Entra/Microsoft 365 security use cases become materially better when logs are exported into a queryable analytics layer rather than left only in the admin plane. citeturn8search6turn25view0turn23view4turn34view0turn12search1turn18search4

## Evidence-backed ATT&CK coverage matrix

The matrix below is intentionally selective. It lists techniques and sub-techniques where there is good evidence that anomaly detection is useful, interpretable, and implementable. “Fit” reflects how naturally the technique lends itself to baseline-relative detection rather than to pure signatures or pure preventive policy.

| ATT&CK | Fit | Best anomaly types | Core telemetry | Feasibility | Operational value | Confidence | Evidence |
|---|---|---|---|---|---|---|---|
| **T1078 Valid Accounts** | Strong | Self-baseline, peer-group, temporal, graph, cross-source | Entra `SigninLogs`, Windows `4624/4625`, SSH/VPN/IdP logs | Medium | High | Supported | citeturn45search9turn27view0turn19search0turn19search1 |
| **T1003.006 DCSync** | Strong | Peer-group, graph, cross-source, rarity | `4662`, `4929`, DRSUAPI/RPC traffic | Medium | High | Confirmed | citeturn35view0turn12search1 |
| **T1558.003 Kerberoasting** | Strong | Self-baseline, volume, rarity, cross-source | `4769`, `4624/4648`, `4672`, Sysmon `10` | Medium | High | Confirmed | citeturn36view0turn12search0turn32search3 |
| **T1059.001 PowerShell** | Strong | Rarity, sequence, parent-child, cross-source | Sysmon `1/7`, PowerShell `400/403/4103-4106` | High | High | Confirmed | citeturn42view0turn13search15turn34view0 |
| **T1053.005 Scheduled Task** | Strong | Rarity, sequence, temporal, user-context | `4698/4702`, Sysmon `1/11`, registry updates | High | High | Confirmed | citeturn37view0turn12search2turn34view0 |
| **T1547.001 Registry Run Keys / Startup Folder** | Strong | Novelty, sequence, path rarity | Sysmon `13/14`, process create, startup-folder file events | High | High | Confirmed | citeturn38view0turn34view0 |
| **T1114.003 Email Forwarding Rule** | Strong | Novelty, graph, cross-source, temporal | Exchange/M365 audit, mailbox rules, mail-flow metadata | Medium | High | Confirmed | citeturn39view0turn21view0turn20view0 |
| **T1484.001 Group Policy Modification** | Strong | Peer-group, rarity, sequence, cross-source | `5136`, `4663/4670/4656`, Sysmon `1/11` | Medium | High | Confirmed | citeturn41view0turn19search6 |
| **T1046 Network Service Discovery** | Strong | Volume, graph, sequence, population | Sysmon `3`, auditd `execve`, Zeek/flows | Medium | High | Confirmed | citeturn40view0turn34view0turn11search0turn30view0 |
| **T1530 Data from Cloud Storage** | Strong | Graph, volume, drift, peer-group | CloudTrail S3 data events, GCP Data Access, SaaS storage audit | Medium | High | Supported | citeturn7search2turn17search3turn17search15turn25view0turn24view0 |
| **T1610 Deploy Container** | Strong | Novelty, sequence, peer-group, cross-source | Kubernetes audit, Docker/containerd events, runtime activity | Medium | High | Confirmed | citeturn43view0turn22view0 |
| **T1611 Escape to Host** | Moderate to strong | Sequence, graph, cross-source, rarity | Kubernetes audit, runtime spec changes, host follow-on process activity | Medium | High | Confirmed | citeturn44view0turn22view0 |
| **T1055 Process Injection** | Moderate | Rarity, cross-source, sequence | Sysmon `8/10`, image load, ETW/EDR | Medium | High | Supported | citeturn7search6turn32search3turn34view0 |
| **T1567 Exfiltration Over Web Service** | Moderate | Volume, graph, drift, cross-source | Proxy, NSM, cloud audit, endpoint network telemetry | Medium | High | Supported | citeturn5search11turn11search0turn30view0turn25view0 |
| **T1486 Data Encrypted for Impact** | Moderate | Volume, drift, sequence | File create/modify/delete, process lineage | Medium | Very high | Supported | citeturn45search0turn34view0 |
| **T1190 Exploit Public-Facing Application** | Weak to moderate | Sequence and volume only, usually hybrid | WAF, app logs, reverse proxy, API gateway | Medium | High | Supported | citeturn31view0turn11search0 |
| **T1027 Obfuscated Files or Information** | Weak | Rarely anomaly-first; usually content- or behaviour-assisted | Content inspection plus execution context | Variable | Medium | Supported | citeturn42view0turn34view0 |
| **T1071 Application Layer Protocol** | Moderate | Process-to-destination rarity, drift, cross-source | Network telemetry + endpoint process attribution | Medium | High | Supported | citeturn19search3turn11search0turn30view0 |

The broad pattern is consistent: techniques with **entity-to-entity relationships** and **short causal chains** are the best anomaly candidates. Techniques whose only obvious signal is a payload string, a known-bad tool, or a “this should never happen” policy violation are better handled with deterministic content, access control, or prevention.

## Detailed detection-hypothesis catalogue

**ANOM-T1078-001** — **attack_id:** T1078, **attack_name:** Valid Accounts, **tactics:** Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement. **Adversary behaviour:** an otherwise legitimate account signs in from a new geography, ASN, application, device state, or work pattern. **Anomaly type:** self-baseline, peer-group, temporal, graph, cross-source. **Anomalous entity:** user, service principal, or managed identity. **Baseline subject:** the identity’s usual locations, ASNs, applications, client types, device patterns, sign-in hours, and target resources; peer group is role-equivalent users or workload identities. **Expected normal behaviour:** repeated access to a stable set of apps/resources from a bounded set of devices/locations at roughly business-consistent times. **Anomalous behaviour:** first-seen location/ASN, new app/resource edge, strange non-interactive sign-in, or successful access following unusual failures. **Minimum required context:** identity type, peer-group tags, admin/service-account labels, maintenance windows. **Required log sources and fields:** Entra `SigninLogs` (`UserPrincipalName`, `IPAddress`, `Location`, `AutonomousSystemNumber`, `DeviceDetail`, `UserAgent`, `AppDisplayName`, `ResultType`), Windows `4624/4625` on endpoints or servers. **Level 1 logic:** first-seen or rarity score per user. **Level 2 logic:** graph score for new user→app/resource edge, plus temporal deviation, plus preceding failed-auth pattern. **Level 3 logic:** only if needed, a user-sequence model over sign-in feature vectors; explainability must expose the top unusual dimensions. **False positives:** travel, VPN changes, VDI shifts, mergers, new app rollouts, admin break-glass use. **Tuning and suppression:** maintain explicit labels for break-glass/admin/service accounts and corporate egress ranges; suppress after ticket-backed change windows rather than through static permanent exceptions. **Validation:** replay historical sign-ins, purple-team sign-ins from test ASNs/devices, and login-simulation for new-resource edges. **Estimated data quality:** medium to high. **Implementation effort:** medium. **Operational value:** high. **Confidence:** supported. **Evidence summary:** ATT&CK now explicitly describes valid-account abuse in terms of anomalous logon patterns and inconsistent geographic/time-based activity; Entra sign-in telemetry exposes the right baseline fields. citeturn45search9turn27view0turn19search0turn19search1

**ANOM-T1003.006-001** — **attack_id:** T1003.006, **attack_name:** DCSync, **tactic:** Credential Access. **Adversary behaviour:** a non-DC host or non-approved account invokes directory-replication behaviour to pull credential material. **Anomaly type:** peer-group, graph, rarity, cross-source. **Anomalous entity:** source host plus requesting account. **Baseline subject:** hosts and accounts that legitimately perform replication; peer group is domain controllers and approved identity-sync products. **Expected normal behaviour:** replication originates from DCs or known sync infrastructure. **Anomalous behaviour:** first-seen replication requester, non-DC requester, or unusual account generating replication-related object access plus DRSUAPI traffic. **Minimum required context:** current DC inventory, sync-service list, domain-admin exceptions. **Required log sources and fields:** `4662` object access on DCs, optional `4929`, and network content/metadata for RPC DRSUAPI; correlation keys are source IP/host and requester identity. **Level 1 logic:** first-seen requester or requester outside the approved replication peer set. **Level 2 logic:** correlate `4662/4929` with DRSUAPI traffic within a short time window. **Level 3 logic:** graph model over expected replication edges, alerting on new source→DC replication arcs. **Example pseudocode:** `if source_host not in dc_or_sync_baseline and has_4662_replication_access and drsuapi_seen_within_5m then score=high`. **False positives:** backup tools, directory sync, security products querying AD unusually. **Tuning:** hold a change-controlled list of legitimate replication-capable services and map them to specific hosts. **Evasion/blind spots:** incomplete SACLs, lack of NSM/RPC visibility, adversary execution from a compromised sync server. **Validation:** perform authorised DCSync emulation from a non-DC lab host and verify both host and network joins. **Estimated data quality:** high. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn35view0turn12search1

**ANOM-T1558.003-001** — **attack_id:** T1558.003, **attack_name:** Kerberoasting, **tactic:** Credential Access. **Adversary behaviour:** an account requests service tickets for SPNs outside its normal workload, often in bursts. **Anomaly type:** self-baseline, volume, rarity, cross-source. **Anomalous entity:** requesting user or host. **Baseline subject:** per-account service-ticket request volume, targeted SPNs, encryption type mix, and privilege context; peers are role-similar admins, scanners, or application accounts. **Expected normal behaviour:** users request a relatively stable set of service tickets tied to business applications. **Anomalous behaviour:** unusual number of TGS requests, first-time access to many service accounts, or RC4-heavy requests where modern usage should be uncommon. **Minimum required context:** account role labels, service-account inventory, encryption-policy understanding. **Required log sources and fields:** Event `4769`, logon context (`4624`, `4648`, `4672`), optional Sysmon `10` for suspicious LSASS/process access. **Level 1 logic:** user-specific burst or first-seen SPN score. **Level 2 logic:** join unusual `4769` patterns to suspicious process-access or privileged logon context. **Level 3 logic:** cluster TGS-request sequences per user/host and score deviations from historic SPN mix. **False positives:** application testing, SharePoint or legacy service behaviour, legitimate admin troubleshooting. **Tuning:** suppress on known service accounts and carefully document expected RC4 exceptions. **Validation:** run controlled Kerberoast emulation and compare against baseline business-service use. **Estimated data quality:** high. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn36view0turn12search0turn32search3

**ANOM-T1059.001-001** — **attack_id:** T1059.001, **attack_name:** PowerShell, **tactics:** Execution, Persistence, Privilege Escalation, Defense Evasion. **Adversary behaviour:** PowerShell is launched directly or indirectly for arbitrary execution. **Anomaly type:** rarity, sequence, graph, cross-source. **Anomalous entity:** host, user, parent process, script block, or module. **Baseline subject:** parent→PowerShell relationships, script-block families, module use, network follow-on, and time-of-day patterns by admin tier. **Expected normal behaviour:** PowerShell usage constrained to admin cohorts, software distribution, and predictable automation windows. **Anomalous behaviour:** Office/LOLBin parent, first-seen script block or module, unusual encoded/hidden invocation, or PowerShell followed by network activity or child-process spawning. **Required logs and fields:** Sysmon `1/7`, PowerShell `400/403/4103-4106`; especially `Image`, `ParentImage`, `CommandLine`, `ScriptBlockText`, `ModuleName`, `RunspaceId`. **Level 1 logic:** rarity score on `{user, host, parent, command-line family}` and script-block novelty. **Level 2 logic:** sequence model for `parent → PowerShell → network/child process`. **Level 3 logic:** only where justified, embed script-block token patterns plus parent/process context, but retain analyst-facing top features. **False positives:** admin frameworks, configuration management, Intune/SCCM, internal tooling. **Tuning:** separate admin endpoints, jump hosts, and software-deployment servers into their own peer groups. **Validation:** Atomic-style PowerShell emulation plus replay of real admin jobs. **Estimated data quality:** high if logging is enabled. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn42view0turn13search15turn13search0turn13search1turn34view0

**ANOM-T1053.005-001** — **attack_id:** T1053.005, **attack_name:** Scheduled Task, **tactics:** Execution, Persistence, Privilege Escalation. **Adversary behaviour:** a task is created or modified to run code under a useful context. **Anomaly type:** novelty, temporal, sequence, peer-group. **Anomalous entity:** task author, task target host, task name, and launched process. **Baseline subject:** normal task creators on a host, expected naming patterns, typical run-as principals, and common maintenance windows. **Expected normal behaviour:** scheduled tasks are created by a small set of admin or deployment identities and follow stable naming and timing conventions. **Anomalous behaviour:** first-seen task creator on a host, hidden or random-looking task names, unusual SYSTEM-context task, or task creation followed by execution of a rare binary. **Required logs and fields:** `4698/4702`, Sysmon `1/11`, registry updates if relevant; fields include `TaskName`, subject identity, created command, child process, and file path. **Level 1 logic:** first-seen task name or creator on host. **Level 2 logic:** creation/modification → execution correlation within a short window. **Level 3 logic:** peer-group model over task names, user contexts, and maintenance windows. **False positives:** software installation, patching, OEM task churn. **Tuning:** maintain software-distribution and patch peer groups; weight task *novelty* higher than raw task creation count. **Validation:** authorised `schtasks`, WMI, and PowerShell task creation tests. **Estimated data quality:** medium to high. **Implementation effort:** low to medium. **Operational value:** high. **Confidence:** confirmed. citeturn37view0turn12search2turn34view0

**ANOM-T1114.003-001** — **attack_id:** T1114.003, **attack_name:** Email Forwarding Rule, **tactics:** Collection, Exfiltration, Persistence. **Adversary behaviour:** a mailbox or transport rule is created or updated so mail is silently redirected. **Anomaly type:** novelty, graph, temporal, cross-source. **Anomalous entity:** mailbox, actor, and forwarding destination. **Baseline subject:** whether the mailbox has ever used rules before, whether the actor typically administers mailbox rules, and whether the destination domain is organisation-approved. **Expected normal behaviour:** most user mailboxes rarely change forwarding rules, and when they do, destinations are internal or previously approved. **Anomalous behaviour:** first forwarding rule for a mailbox, first external destination, first actor→mailbox admin edge, or rule creation followed by auto-forwarded messages. **Required logs and fields:** Exchange/M365 operations `New-InboxRule`, `Set-InboxRule`, `Remove-InboxRule`, plus message-trace or mail-flow metadata; `principalEmail`, target mailbox, operation, destination address, timestamps. **Level 1 logic:** first-seen forwarding destination or mailbox-rule activity. **Level 2 logic:** audit event joined to subsequent auto-forwarded mail-flow. **Level 3 logic:** graph model over actor→mailbox and mailbox→destination edges. **False positives:** executive assistants, shared mailboxes, approved journalling, legitimate forwarding during leave. **Tuning:** maintain approved external-routing domains and delegation relationships. **Validation:** create benign test rules, including internal and approved external destinations, and verify differential scoring. **Estimated data quality:** medium. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn39view0turn21view0turn20view0turn10search1

**ANOM-T1530-001** — **attack_id:** T1530, **attack_name:** Data from Cloud Storage, **tactics:** Collection, Exfiltration. **Adversary behaviour:** a user, role, or service principal accesses cloud-stored objects or documents outside its usual business pattern. **Anomaly type:** graph, volume, drift, peer-group, cross-source. **Anomalous entity:** principal plus bucket/container/site/document store. **Baseline subject:** usual principal→storage-resource edges, object-read volume, prefixes or paths, read/write mix, and time-of-day. **Expected normal behaviour:** storage access is repetitive and role-constrained. **Anomalous behaviour:** first principal→bucket edge, spike in `GetObject` or analogous reads, unusual cross-project or cross-tenant access, or SaaS document access from an identity that has never touched that resource family. **Required logs and fields:** AWS S3 object-level CloudTrail data events, GCP Data Access logs, SharePoint/Drive/Workspace audit logs where available. **Level 1 logic:** first-seen edge or per-principal z-score on object reads. **Level 2 logic:** graph anomaly plus sign-in/context anomaly plus egress/upload follow-on. **Level 3 logic:** seasonal decomposition for high-volume data consumers only. **False positives:** migrations, backups, analytics jobs, new project onboarding. **Tuning:** separate machines and service roles from human identities, and require approved change windows for large transfers. **Blind spots:** missing data events, public-object access, service-side copying that does not traverse the expected logs. **Validation:** synthetic bucket-read bursts, first-seen access from a test role, and audit of known migration windows. **Estimated data quality:** high if data access logging is enabled. **Implementation effort:** medium. **Operational value:** high. **Confidence:** supported. citeturn7search2turn17search3turn17search15turn25view0turn24view0turn26view0

**ANOM-T1610-001** — **attack_id:** T1610, **attack_name:** Deploy Container, **tactic:** Execution. **Adversary behaviour:** a container is created and started through Docker or Kubernetes using an unusual image, principal, or runtime privilege set. **Anomaly type:** novelty, sequence, peer-group, cross-source. **Anomalous entity:** principal, image, workload spec, and namespace/cluster target. **Baseline subject:** approved images by digest, normal deployer identities, permitted namespace-to-image relationships, and expected runtime flags. **Expected normal behaviour:** CI/CD and platform admins deploy known images with constrained security contexts. **Anomalous behaviour:** non-admin principal deploys an unapproved image, image tagged `latest`, privileged runtime flags, host namespaces, or sensitive host mounts, followed by immediate network/process activity. **Required logs and fields:** Kubernetes audit metadata, Docker/containerd create/start events, runtime process/network telemetry. **Level 1 logic:** first-seen image or deployer outside approved cohort. **Level 2 logic:** create → start → first network/process chain with risk-attribute scoring. **Level 3 logic:** graph model linking principal, image, namespace, and capability set. **False positives:** emergency incident response containers, ad hoc SRE debugging, image rollout transitions. **Tuning:** maintain approved image-digest and deployer inventories; treat `latest` as a risk amplifier, not a standalone alert. **Validation:** cluster-test deployments with safe but intentionally unusual specs. **Estimated data quality:** medium to high. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn43view0turn22view0

**ANOM-T1611-001** — **attack_id:** T1611, **attack_name:** Escape to Host, **tactics:** Privilege Escalation, Defense Evasion. **Adversary behaviour:** a container workload uses privileged configuration or suspicious syscalls to reach the host. **Anomaly type:** sequence, graph, rarity, cross-source. **Anomalous entity:** pod/container plus host resource. **Baseline subject:** expected hostPath mounts, privileged workloads, admin namespaces, and syscall behaviour for each workload class. **Expected normal behaviour:** most workloads never use `hostPath`, host namespaces, `docker.sock`, or host-level syscalls such as `unshare`, `mount`, `setns`, and `keyctl`. **Anomalous behaviour:** unexpected privileged container creation, out-of-policy host mount, or container-sourced syscall followed by host process activity. **Required logs and fields:** Kubernetes audit, container creation metadata, auditd syscall telemetry where available, host process creation. **Level 1 logic:** first-seen privileged host-touching spec by workload or namespace. **Level 2 logic:** correlate spec anomaly with host-follow-on process execution. **Level 3 logic:** model namespace/workload-specific syscall baselines only where runtime telemetry quality is high. **False positives:** platform agents, CSI/observability components, deliberate host maintenance. **Tuning:** isolate cluster-system namespaces and node agents as separate peers. **Validation:** safe lab pod specs with hostPath and privileged flags, followed by test host interaction. **Estimated data quality:** high for spec-level signals, medium for syscall-to-host correlation. **Implementation effort:** medium. **Operational value:** high. **Confidence:** confirmed. citeturn44view0turn22view0

## MVP roadmap, research gaps, and machine-readable output

An initial MVP should bias toward detections that are interpretable, produce analyst-friendly explanations, and use telemetry most organisations already have or can enable quickly. The top twenty priorities are below.

| MVP priority | Detection | Main telemetry dependency | Effort | Why it belongs in the first wave |
|---|---|---|---|---|
| 1 | Valid-account misuse by new sign-in edge | Entra `SigninLogs`, Windows auth | Medium | High coverage across initial access, persistence, and lateral movement |
| 2 | Password spraying / distributed brute-force patterns | IdP, `4625`, VPN, mail auth | Medium | Strong attacker ROI, good temporal and population signal |
| 3 | DCSync from non-DC or first-seen requester | DC `4662` + RPC/NSM | Medium | High-confidence AD crown-jewel detector |
| 4 | Kerberoasting service-ticket burst or new SPN fan-out | `4769` + context logs | Medium | Strong credential-access coverage |
| 5 | Rare remote admin path | RDP/SMB/SSH/WinRM + identity | Medium | Excellent graph anomaly for lateral movement |
| 6 | Rare PowerShell parent/script-block pattern | Sysmon + PowerShell logs | Medium | Strong Windows execution coverage |
| 7 | Rare Unix shell command line by host role | auditd / EDR process logs | Medium | Strong Linux coverage with interpretable rarity |
| 8 | Scheduled-task novelty and creation→execution chain | `4698/4702` + Sysmon | Low | High persistence value |
| 9 | Registry autorun first-seen path | Sysmon registry/process | Low | High persistence value |
| 10 | Mailbox forwarding-rule novelty | M365/Exchange audit | Medium | High BEC and mailbox-exfil value |
| 11 | Group Policy modification by unusual actor | `5136` + SYSVOL file events | Medium | High-value AD persistence/privilege path |
| 12 | Service-principal credential addition by unusual actor | Entra `AuditLogs` | Medium | Cloud persistence with strong novelty signal |
| 13 | AWS access-key or policy attachment anomaly | CloudTrail | Medium | Persistence and privilege-change coverage |
| 14 | Azure control-plane admin anomaly | Azure Activity + Entra audit | Medium | Resource and identity misuse coverage |
| 15 | GCP Data Access first-seen principal→resource edge | Cloud Audit Logs | Medium | Strong cloud collection/exfil signal |
| 16 | Network-service-discovery fan-out anomaly | NSM/flow + process telemetry | Medium | Good discovery and pre-lateral-movement signal |
| 17 | Web-service exfil volume and destination drift | Proxy/NSM + endpoint/cloud | Medium | Broad exfil coverage |
| 18 | Cloud-storage download spike | S3/GCS/Drive/SharePoint audit | Medium | High-value collection/exfil signal |
| 19 | Deploy-container create→start→activity anomaly | Kubernetes audit + runtime | Medium | Strong container execution coverage |
| 20 | Container escape precursor + host follow-on | Kubernetes + runtime + host | Medium | High-impact container privilege-escalation control |

The major research gaps are clear. A complete pass over **all** Enterprise ATT&CK techniques still needs tactic-by-tactic review, because some newer ATT&CK content reorganises techniques and sub-techniques, and several cloud-control-plane mappings are many-to-many rather than neat one-to-one relationships. The weakest-supported areas are techniques where only a post-condition is observable, where telemetry is optional or expensive, or where legitimate and malicious behaviour are nearly indistinguishable without business metadata. The biggest blind spots are still missing **data access logs**, missing **runtime telemetry**, poor **entity resolution**, and absent **peer-group labels**. citeturn25view0turn23view4turn34view0

Open questions and limitations remain. This report is a **high-confidence cross-tactic synthesis**, not a literal one-row-for-every-technique dump of the full Enterprise matrix. It also does not attempt to invent vendor-normalised fields where the platform documentation is intentionally collector-agnostic, particularly on macOS and some SaaS surfaces. Finally, the recommended lookback windows and scoring defaults are operational defaults derived from the telemetry characteristics above, not vendor-mandated constants.

Below is a **valid JSON subset** matching the requested top-level shape. It only includes techniques and hypotheses explicitly detailed in this report, uses `null` where values would otherwise be invented, and preserves direct source URLs inside the JSON for machine-readability.

```json
{
  "metadata": {
    "research_date": "2026-06-08",
    "attack_domain": "enterprise-attack",
    "attack_version": "v19.1",
    "scope_notes": "Evidence-backed cross-tactic subset prioritising anomaly-friendly ATT&CK techniques across Windows, identity, cloud, containers, and SaaS. This is not an exhaustive one-row-for-every-technique matrix."
  },
  "anomaly_types": [
    "self-baseline anomaly",
    "peer-group anomaly",
    "temporal anomaly",
    "volume anomaly",
    "rarity or novelty anomaly",
    "sequence anomaly",
    "graph or relationship anomaly",
    "cross-source anomaly"
  ],
  "log_sources": [
    {
      "source_name": "Windows Security Event Log",
      "category": "endpoint and identity",
      "producing_systems": ["Windows Server", "Windows clients", "Domain Controllers"],
      "security_behaviors": ["logon", "kerberos service tickets", "scheduled task creation", "AD object access/modification"],
      "essential_fields": ["EventID", "TimeCreated", "SubjectUserName", "TargetUserName", "LogonType", "IpAddress", "TaskName", "ObjectDN", "ServiceName"],
      "useful_optional_fields": ["TicketEncryptionType", "LogonId", "ProcessName"],
      "entity_identifiers": ["hostname", "user SID", "user name", "source IP"],
      "common_data_quality_problems": ["4662 requires appropriate SACLs", "domain controller volume can be high", "field layouts vary by OS version"],
      "retention_and_baseline_recommendations": "Retain at least several weeks locally and longer centrally; baseline DC/admin activity separately from user endpoints.",
      "relevant_attack_data_components": ["DC0071", "DC0084", "DC0067", "DC0066", "DC0001"],
      "example_anomaly_use_cases": ["DCSync from non-DC", "Kerberoasting burst", "scheduled task novelty"]
    },
    {
      "source_name": "Microsoft Entra SigninLogs and AuditLogs",
      "category": "identity and SaaS",
      "producing_systems": ["Microsoft Entra ID", "Azure Monitor"],
      "security_behaviors": ["interactive and non-interactive sign-ins", "service principal sign-ins", "tenant audit activity"],
      "essential_fields": ["UserPrincipalName", "IPAddress", "Location", "AutonomousSystemNumber", "DeviceDetail", "UserAgent", "AppDisplayName", "ResultType", "ActivityDisplayName", "InitiatedBy", "TargetResources"],
      "useful_optional_fields": ["ConditionalAccessPolicies", "AuthenticationMethodsUsed", "ResourceDisplayName"],
      "entity_identifiers": ["user id", "service principal id", "tenant id", "IP address"],
      "common_data_quality_problems": ["admin actions are sparse", "some workflows require export to Log Analytics for practical querying"],
      "retention_and_baseline_recommendations": "Baseline humans, service principals, and managed identities separately; maintain peer cohorts for administrators and break-glass identities.",
      "relevant_attack_data_components": ["DC0026", "DC0010", "DC0038"],
      "example_anomaly_use_cases": ["valid-account misuse", "new service principal credential addition"]
    },
    {
      "source_name": "AWS CloudTrail",
      "category": "cloud control plane and data plane",
      "producing_systems": ["AWS services", "S3", "IAM", "STS"],
      "security_behaviors": ["API calls", "IAM changes", "object access"],
      "essential_fields": ["eventTime", "userIdentity", "eventSource", "eventName", "requestParameters", "resources", "eventCategory", "readOnly"],
      "useful_optional_fields": ["recipientAccountId", "vpcEndpointId", "tlsDetails", "eventContext"],
      "entity_identifiers": ["principal ARN", "account id", "resource ARN"],
      "common_data_quality_problems": ["S3 and other data events are not logged by default", "cross-account actions need careful identity resolution"],
      "retention_and_baseline_recommendations": "Enable relevant data events before relying on collection/exfiltration anomalies.",
      "relevant_attack_data_components": ["DC0038", "DC0025", "DC0078"],
      "example_anomaly_use_cases": ["cloud-storage read spike", "new access-key creation pattern", "unexpected role assumption"]
    }
  ],
  "techniques": [
    {
      "attack_id": "T1003.006",
      "attack_name": "DCSync",
      "tactics": ["Credential Access"],
      "platforms": ["Windows", "Active Directory"],
      "anomaly_detection_fit": "strong",
      "gap_reason": null,
      "hypotheses": [
        {
          "hypothesis_id": "ANOM-T1003.006-001",
          "attack_id": "T1003.006",
          "attack_name": "DCSync",
          "tactic": ["Credential Access"],
          "platforms": ["Windows", "Active Directory"],
          "adversary_behavior": "Replication API abuse from a non-DC or otherwise unusual replication requester.",
          "anomaly_hypothesis": "A host-account pair that has never legitimately requested replication, or that is not in the approved DC/sync peer set, will stand out when 4662 object-access activity aligns with DRSUAPI traffic.",
          "anomaly_type": ["peer-group anomaly", "graph or relationship anomaly", "cross-source anomaly", "rarity or novelty anomaly"],
          "anomalous_entity": "source host plus requester account",
          "baseline_subject": "known replication requesters by host and account",
          "peer_group": "domain controllers and approved directory sync services",
          "expected_normal_behavior": "Replication originates from DCs or specific sync infrastructure.",
          "anomalous_behavior": "First-seen or non-DC replication requester with matching directory object access and replication traffic.",
          "minimum_required_context": "Current DC inventory and approved sync-service inventory.",
          "required_log_sources": ["Windows Security Event Log", "network security monitoring on RPC/DRSUAPI"],
          "required_data_components": ["DC0071", "DC0068", "DC0085"],
          "required_fields": ["EventID", "SubjectUserName", "SubjectLogonId", "ObjectDN", "source IP", "destination IP", "RPC service/protocol metadata"],
          "correlation_keys": ["source host", "source IP", "requester identity", "time window"],
          "lookback_window": "30-90 days recommended",
          "scoring_window": "5-15 minutes",
          "baseline_update_strategy": "Daily update of approved replication peer set with change-controlled source inventory.",
          "cold_start_strategy": "Use peer-group baseline only; require two signals before alerting.",
          "detection_logic_level_1": "Flag first-seen requester outside approved replication hosts.",
          "detection_logic_level_2": "Correlate replication-related 4662/4929 events with DRSUAPI traffic in a short causal window.",
          "detection_logic_level_3": "Graph anomaly over expected requester-to-DC replication edges.",
          "example_pseudocode": "if requester_host not in approved_replication_hosts and winsec_4662_replication and drsuapi_rpc_within_5m then score = high",
          "explanation_features_for_analyst": ["requester not in DC inventory", "first-seen requester-account pair", "matched DRSUAPI traffic", "time of day"],
          "false_positives": ["directory sync products", "backup or identity-governance tools"],
          "tuning_and_suppression": "Suppress only for explicitly approved replication-capable systems and documented maintenance windows.",
          "evasion_and_blind_spots": ["missing SACLs", "lack of RPC visibility", "compromised approved sync server"],
          "validation_plan": "Authorised DCSync emulation from a non-DC host in a lab or purple-team scope.",
          "estimated_data_quality_required": "high",
          "estimated_implementation_effort": "medium",
          "estimated_operational_value": "high",
          "confidence": "confirmed",
          "evidence_summary": "MITRE DET0594 directly describes unauthorised DCSync as unusual replication operations from non-DC endpoints and lists 4662, 4929, and DRSUAPI traffic as sources.",
          "sources": [
            {
              "title": "MITRE ATT&CK DET0594",
              "url": "https://attack.mitre.org/detectionstrategies/DET0594/"
            },
            {
              "title": "Microsoft Event 4662",
              "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662"
            }
          ]
        }
      ]
    },
    {
      "attack_id": "T1558.003",
      "attack_name": "Kerberoasting",
      "tactics": ["Credential Access"],
      "platforms": ["Windows", "Active Directory"],
      "anomaly_detection_fit": "strong",
      "gap_reason": null,
      "hypotheses": [
        {
          "hypothesis_id": "ANOM-T1558.003-001",
          "attack_id": "T1558.003",
          "attack_name": "Kerberoasting",
          "tactic": ["Credential Access"],
          "platforms": ["Windows", "Active Directory"],
          "adversary_behavior": "An account requests service tickets for SPNs outside its normal pattern, often in a burst.",
          "anomaly_hypothesis": "A requesting principal will deviate from its own history and peer group when it suddenly requests many service tickets, targets unusual SPNs, or uses RC4 where that is abnormal for the environment.",
          "anomaly_type": ["self-baseline anomaly", "volume anomaly", "rarity or novelty anomaly", "cross-source anomaly"],
          "anomalous_entity": "requesting user or host",
          "baseline_subject": "Per-account service-ticket volume and historic SPN targets.",
          "peer_group": "Role-similar users, admins, and service accounts.",
          "expected_normal_behavior": "Stable service-ticket use tied to a narrow set of applications.",
          "anomalous_behavior": "Burst of TGS requests, first-time SPN fan-out, or suspicious encryption use.",
          "minimum_required_context": "Service-account inventory and known legacy-encryption exceptions.",
          "required_log_sources": ["Windows Security Event Log", "Sysmon", "logon events"],
          "required_data_components": ["DC0084", "DC0035", "DC0067", "DC0088"],
          "required_fields": ["EventID", "ServiceName", "TicketEncryptionType", "SubjectUserName", "TargetLogonId", "TargetImage"],
          "correlation_keys": ["user", "host", "time window"],
          "lookback_window": "30-60 days recommended",
          "scoring_window": "5-30 minutes",
          "baseline_update_strategy": "Daily incremental refresh with slower updates for service-account peer groups.",
          "cold_start_strategy": "Use peer-group volume and SPN-target norms until enough per-user history exists.",
          "detection_logic_level_1": "Detect unusual TGS-request volume and first-seen SPN targets.",
          "detection_logic_level_2": "Correlate unusual 4769 activity with suspicious process-access or privileged logon context.",
          "detection_logic_level_3": "Sequence model over SPN-target vectors per user/host.",
          "example_pseudocode": "score = rarity(user, service_spn) + burst(user, 4769, 15m) + rc4_weight + join(sysmon10, same_host, 15m)",
          "explanation_features_for_analyst": ["new SPN targets", "request volume above user baseline", "legacy encryption observed", "suspicious host context"],
          "false_positives": ["application testing", "legacy services", "admin troubleshooting"],
          "tuning_and_suppression": "Track and suppress documented legacy-encryption workflows and known service-account behaviours.",
          "evasion_and_blind_spots": ["stealthy low-and-slow requests", "incomplete process telemetry"],
          "validation_plan": "Controlled Kerberoast emulation against lab service accounts with and without legacy-encryption exceptions.",
          "estimated_data_quality_required": "high",
          "estimated_implementation_effort": "medium",
          "estimated_operational_value": "high",
          "confidence": "confirmed",
          "evidence_summary": "MITRE DET0157 directly frames Kerberoasting around anomalous 4769 patterns, unusual service-account targeting, and optional process-access correlation.",
          "sources": [
            {
              "title": "MITRE ATT&CK DET0157",
              "url": "https://attack.mitre.org/detectionstrategies/DET0157/"
            },
            {
              "title": "Microsoft Event 4769",
              "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769"
            },
            {
              "title": "Sysmon Event 10",
              "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
            }
          ]
        }
      ]
    },
    {
      "attack_id": "T1610",
      "attack_name": "Deploy Container",
      "tactics": ["Execution"],
      "platforms": ["Containers", "IaaS"],
      "anomaly_detection_fit": "strong",
      "gap_reason": null,
      "hypotheses": [
        {
          "hypothesis_id": "ANOM-T1610-001",
          "attack_id": "T1610",
          "attack_name": "Deploy Container",
          "tactic": ["Execution"],
          "platforms": ["Containers", "IaaS"],
          "adversary_behavior": "A container is remotely created and started with an unusual image, principal, or risky runtime attributes.",
          "anomaly_hypothesis": "A deployment will be abnormal when it combines a first-seen image or deployer with privileged flags, host namespaces, or sensitive host-path mounts, especially if followed quickly by first network or process activity.",
          "anomaly_type": ["rarity or novelty anomaly", "sequence anomaly", "peer-group anomaly", "cross-source anomaly"],
          "anomalous_entity": "deployer principal plus image plus runtime spec",
          "baseline_subject": "approved image digests, normal deployer identities, and expected namespace-to-image relationships",
          "peer_group": "CI/CD identities, platform administrators, workload owners by namespace",
          "expected_normal_behavior": "Known images deployed by approved automation or admins with constrained security context.",
          "anomalous_behavior": "Unknown image or non-admin principal deploys privileged or host-touching container and it becomes active quickly.",
          "minimum_required_context": "Approved image inventory, namespace ownership, admin/deployer inventory.",
          "required_log_sources": ["Kubernetes audit", "Docker or containerd events", "runtime process/network telemetry"],
          "required_data_components": ["DC0038", "DC0077", "DC0032", "DC0085"],
          "required_fields": ["user", "verb", "resource", "image", "privileged", "hostPID", "hostNetwork", "volume mounts", "start timestamp"],
          "correlation_keys": ["container id", "pod uid", "image digest", "principal", "time window"],
          "lookback_window": "30-90 days recommended",
          "scoring_window": "5 minutes",
          "baseline_update_strategy": "Daily image and principal inventory update from deployment systems.",
          "cold_start_strategy": "Use allow-listed image digests and approved deployer peer groups before entity history exists.",
          "detection_logic_level_1": "Flag first-seen image or deployer outside approved cohort.",
          "detection_logic_level_2": "Correlate create -> start -> first process/network activity and add risk weights for privileged attributes.",
          "detection_logic_level_3": "Graph anomaly across principal-to-namespace-to-image relationships.",
          "example_pseudocode": "score = new_image + non_admin_deployer + privileged_flag + sensitive_mount + first_activity_within_5m",
          "explanation_features_for_analyst": ["image not previously observed", "deployer outside CI/CD cohort", "privileged or hostPath flags", "rapid post-start activity"],
          "false_positives": ["incident response containers", "manual SRE debugging", "new service rollout"],
          "tuning_and_suppression": "Separate platform/system namespaces and emergency operations from normal tenant workloads.",
          "evasion_and_blind_spots": ["compromised CI/CD identity", "runtime telemetry not joined to control-plane events"],
          "validation_plan": "Deploy safe test containers with unusual but non-malicious flags in a lab namespace and verify create/start/activity chaining.",
          "estimated_data_quality_required": "medium",
          "estimated_implementation_effort": "medium",
          "estimated_operational_value": "high",
          "confidence": "confirmed",
          "evidence_summary": "MITRE DET0249 explicitly describes create-start-activity behaviour chains around unapproved images, non-admin deployers, and risky runtime attributes.",
          "sources": [
            {
              "title": "MITRE ATT&CK DET0249",
              "url": "https://attack.mitre.org/detectionstrategies/DET0249/"
            },
            {
              "title": "Kubernetes auditing",
              "url": "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/"
            }
          ]
        }
      ]
    }
  ],
  "mvp_priorities": [
    "T1078 Valid Accounts anomaly model",
    "T1003.006 DCSync requester anomaly model",
    "T1558.003 Kerberoasting request-pattern model",
    "T1059.001 PowerShell parent/script-block rarity model",
    "T1114.003 Mailbox forwarding-rule novelty model"
  ],
  "research_gaps": [
    "A full tactic-by-tactic pass is still needed for lower-fit techniques and recently reorganised ATT&CK areas.",
    "Cloud and SaaS data-access anomalies remain telemetry-dependent because object-level logs are optional or expensive in several platforms.",
    "Collector-normalised field mapping for macOS and some SaaS surfaces should be validated per vendor before production implementation."
  ],
  "sources": [
    {
      "title": "MITRE ATT&CK version history",
      "url": "https://attack.mitre.org/resources/versions/"
    },
    {
      "title": "MITRE ATT&CK Enterprise matrix",
      "url": "https://attack.mitre.org/matrices/enterprise/"
    },
    {
      "title": "Microsoft Entra SigninLogs schema",
      "url": "https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs"
    },
    {
      "title": "AWS CloudTrail record contents",
      "url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html"
    },
    {
      "title": "Google Cloud Audit Logs overview",
      "url": "https://docs.cloud.google.com/logging/docs/audit"
    }
  ]
}
```