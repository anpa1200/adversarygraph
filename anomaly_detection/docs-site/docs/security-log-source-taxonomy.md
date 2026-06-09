# Vendor-Neutral Security Log Source Taxonomy

This document catalogs security-relevant log and telemetry source types without mapping them to vendors, detection rules, anomalies, or threat frameworks. Each entry describes what the source records and the kinds of activity it can report.

A log source may be a primary producer of events, such as an operating system or application, or an aggregation layer, such as EDR, NDR, SIEM, or XDR. Aggregation layers commonly enrich, correlate, or summarize events produced by multiple underlying sources.

The taxonomy is grounded in established log-management guidance, protocol standards, security-control catalogs, and peer-reviewed literature listed in the references section [1-22].

## Endpoint Detection and Host Monitoring

### 1. Endpoint Detection and Response Telemetry

Endpoint Detection and Response (EDR) telemetry records detailed activity from monitored workstations, servers, and other supported endpoints. It commonly combines process, file, registry, module, network, user-session, and sensor-health observations into a time-correlated endpoint activity stream.

It can report process execution and ancestry, command-line activity, file creation and modification, executable and library loading, persistence-related changes, local user activity, endpoint-originated connections, suspicious process behavior, isolation actions, and endpoint sensor status.

### 2. Extended Detection and Response Telemetry

Extended Detection and Response (XDR) telemetry combines events from multiple security domains, commonly endpoint, identity, email, network, cloud, and application sources. It is an aggregation and correlation layer rather than a single raw log source.

It can report cross-domain activity chains, related alerts, entity timelines, correlated user and device activity, incident groupings, response actions, and enriched risk or behavior summaries.

### 3. Host-Based Intrusion Detection Logs

Host-Based Intrusion Detection System (HIDS) logs record security observations produced by software monitoring an individual host. Depending on configuration, the system may inspect files, processes, logs, system calls, configuration changes, and local network activity.

It can report file-integrity changes, suspicious local activity, policy violations, changes to protected system resources, local attack indicators, and health or availability of the monitoring agent.

### 4. Host-Based Intrusion Prevention Logs

Host-Based Intrusion Prevention System (HIPS) logs record activity evaluated or blocked by host-level prevention controls. These controls may enforce process, memory, application, exploit, device, or network policies.

They can report blocked or allowed execution attempts, exploit-prevention actions, memory-protection violations, application-control decisions, local network restrictions, and policy enforcement outcomes.

### 5. Endpoint Sensor Health Logs

Endpoint sensor health logs record whether endpoint monitoring and protection agents are installed, active, updated, connected, and functioning correctly.

They can report agent startup and shutdown, heartbeat status, policy synchronization, version changes, update failures, telemetry gaps, disabled protections, communication errors, and degraded monitoring coverage.

### 6. Process Execution Logs

Process execution logs record the creation, termination, and identity of operating-system processes. Rich implementations include executable path, process identifier, parent process, user, command line, working directory, integrity level, hashes, and timestamps.

They can report application launches, script and command execution, process ancestry, unusual parent-child relationships, process lifetimes, execution under different users, and use of system utilities.

### 7. Command-Line and Shell History Logs

Command-line and shell history logs record commands entered or executed through interactive shells, command interpreters, remote sessions, scripts, or administrative consoles.

They can report administrative actions, file and directory operations, software execution, environment changes, network commands, account management, scripted activity, and sequences of interactive commands.

### 8. Script-Execution Logs

Script-execution logs record activity from scripting engines and automation runtimes. Depending on the engine, they may include script content, parsed commands, modules, execution context, session identifiers, and output.

They can report script launches, dynamically executed code, imported modules, automation tasks, remote commands, interpreter activity, and script-level errors.

### 9. System-Call Telemetry

System-call telemetry records requests made by processes to the operating-system kernel. It may capture process, file, memory, identity, network, device, and privilege-related operations at a low level.

It can report process creation, file access, permission changes, inter-process activity, network socket operations, privilege changes, kernel interactions, and attempts to access protected resources.

### 10. Kernel and Driver Logs

Kernel and driver logs record activity and errors generated by the operating-system kernel and loaded device or software drivers.

They can report driver loading and unloading, kernel faults, device interactions, low-level access failures, memory or resource issues, kernel security events, and system stability problems.

### 11. Module, Library, and Image-Load Logs

Module and library load logs record executable images, shared libraries, dynamic-link libraries, kernel modules, and similar code components loaded into processes or the operating system.

They can report code-loading behavior, library search paths, unsigned or untrusted modules, unusual module-process combinations, injected libraries, and dependency loading.

### 12. Memory-Protection and Exploit-Mitigation Logs

Memory-protection logs record events produced by exploit mitigations, runtime protections, or memory-integrity controls.

They can report blocked memory operations, control-flow violations, stack or heap protection events, code-injection attempts, executable-memory creation, protected-process access, and mitigation failures.

### 13. File-System Activity Logs

File-system activity logs record access to files and directories. Depending on the source, they may capture creation, opening, reading, writing, renaming, moving, deletion, permission changes, and ownership changes.

They can report document access, executable creation, configuration modification, bulk file operations, access to protected paths, file deletion, and changes to shared or sensitive data.

### 14. File-Integrity Monitoring Logs

File-Integrity Monitoring (FIM) logs record changes to a defined set of monitored files, directories, and sometimes configuration objects.

They can report creation, modification, deletion, ownership changes, permission changes, hash changes, unexpected content changes, and drift from an approved baseline.

### 15. Registry and Configuration-Store Logs

Registry and configuration-store logs record reads and changes to structured operating-system or application configuration repositories.

They can report creation, modification, and deletion of configuration values; changes to startup behavior; service configuration; security settings; application settings; and system policy changes.

### 16. Service and Daemon Management Logs

Service and daemon logs record installation, configuration, startup, shutdown, failure, and removal of background services.

They can report new service creation, service-account changes, executable-path changes, altered startup modes, repeated failures, manual starts and stops, and service lifecycle activity.

### 17. Scheduled Task and Job Logs

Scheduled task and job logs record creation, modification, execution, completion, and deletion of operating-system or application scheduling entries.

They can report recurring and one-time tasks, scheduled command execution, task owners, execution results, failed jobs, changed schedules, and automated maintenance activity.

### 18. Package and Software Installation Logs

Package and software installation logs record the installation, upgrade, repair, and removal of software packages, applications, libraries, and updates.

They can report newly installed software, package-source activity, dependency changes, failed installations, update history, software removal, and installer execution.

### 19. Application-Control Logs

Application-control logs record decisions made by allowlisting, denylisting, code-signing, reputation, or execution-policy controls.

They can report allowed, blocked, or audited application launches; script and library policy decisions; publisher and signature information; policy exceptions; and execution attempts from restricted locations.

### 20. Removable-Media and Peripheral Device Logs

Peripheral and removable-media logs record connections, disconnections, access, and policy decisions involving external devices.

They can report USB storage insertion, device identifiers, mounted volumes, data-access activity where available, blocked devices, printing, camera use, Bluetooth connections, and other peripheral activity.

### 21. Local Firewall Logs

Local firewall logs record network traffic and policy decisions made by a firewall running on an individual endpoint.

They can report allowed and blocked inbound or outbound connections, listening services, source and destination addresses, ports, protocols, rule matches, profile changes, and local firewall configuration changes.

### 22. Endpoint DNS Logs

Endpoint DNS logs record name-resolution requests and responses generated or observed on an individual host.

They can report queried names, query types, response codes, returned addresses, requesting processes where supported, resolver selection, and failed or repeated resolution activity.

## Operating-System Logs

### 23. Windows Security Event Logs

Windows Security event logs record security-auditing events generated by Windows when relevant audit policies are enabled.

They can report successful and failed logons, account creation and changes, group membership changes, privilege use, object access, process creation where configured, policy changes, directory-service activity, scheduled tasks, service installation, and audit-log clearing.

### 24. Windows System Event Logs

Windows System event logs record events generated by the operating system, drivers, and system services.

They can report service startup and failure, driver loading, shutdowns and restarts, hardware and storage problems, network-stack events, update activity, and operating-system component errors.

### 25. Windows Application Event Logs

Windows Application event logs record events generated by applications and application frameworks running on Windows.

They can report application starts and failures, authentication events exposed by applications, database or service errors, application-specific operations, crashes, and configuration problems.

### 26. Windows PowerShell Logs

PowerShell logs record PowerShell engine, provider, module, script-block, transcription, and operational activity when the relevant logging features are enabled.

They can report PowerShell startup, commands and scripts, imported modules, remoting activity, script content, execution errors, pipeline behavior, and session details.

### 27. Windows Remote Management Logs

Windows remote-management logs record remote administration activity performed through supported Windows management protocols and services.

They can report remote session creation, remote command execution, authentication, connection endpoints, management operations, session errors, and remote resource access.

### 28. Windows Task Scheduler Logs

Windows Task Scheduler logs record task registration, updates, triggers, execution, completion, and failure.

They can report task definitions, task owners, executed programs, scheduled times, manual task execution, changed schedules, and task results.

### 29. Windows Defender and Native Security-Control Logs

Native Windows security-control logs record activity from built-in malware protection, exploit protection, firewall, application control, and related security components.

They can report scans, detections, quarantines, exclusions, configuration changes, blocked behavior, protection status, update failures, and remediation actions.

### 30. Linux System Logs

Linux system logs record messages from the kernel, system services, daemons, and applications through the operating system's logging facilities.

They can report service lifecycle activity, kernel messages, authentication activity, scheduled jobs, networking events, application errors, hardware issues, and system startup or shutdown.

### 31. Linux Audit Logs

Linux audit logs record security-relevant events produced by the kernel auditing subsystem according to configured audit rules.

They can report system calls, file access, permission and ownership changes, process execution, account changes, authentication activity, privilege use, security-policy changes, and access to monitored resources.

### 32. Linux Authentication Logs

Linux authentication logs record authentication and authorization activity from local and remote access services.

They can report successful and failed logins, remote-shell access, privilege elevation, session creation and closure, account lockouts, authentication methods, and source addresses.

### 33. Linux Shell History

Linux shell history records commands entered through supported interactive shells when history collection is enabled and not bypassed.

It can report user-entered commands, administrative activity, file and process operations, networking commands, and sequences of interactive actions.

### 34. Linux Service-Manager Logs

Linux service-manager logs record the lifecycle and status of managed services and scheduled units.

They can report service starts, stops, restarts, failures, configuration reloads, timer execution, dependency failures, and service resource consumption.

### 35. macOS Unified Logs

macOS Unified Logs collect structured and unstructured messages from the operating system, applications, and services.

They can report process and application activity, authentication, system services, privacy-control decisions, network behavior, errors, hardware activity, and security-relevant operating-system events.

### 36. macOS Endpoint Security Telemetry

macOS Endpoint Security telemetry records security-relevant operating-system events exposed through the Endpoint Security framework.

It can report process execution, file operations, authentication, code-signing information, inter-process activity, system extension events, and authorization decisions.

### 37. Unix Accounting Logs

Unix accounting logs record summaries of process execution, user sessions, and resource use when accounting is enabled.

They can report executed commands, session start and end times, CPU usage, elapsed time, users, terminals, and aggregate resource consumption.

### 38. Operating-System Crash and Diagnostic Logs

Crash and diagnostic logs record application crashes, kernel failures, dumps, exception details, and diagnostic reports.

They can report failing processes, faulting modules, exception types, stack traces, repeated crashes, resource exhaustion, and operating-system instability.

## Identity, Authentication, and Authorization Logs

### 39. Identity Provider Sign-In Logs

Identity provider sign-in logs record authentication attempts to centralized identity services.

They can report successful and failed sign-ins, user and service identities, source addresses, applications, authentication methods, device context, session properties, conditional access outcomes, and failure reasons.

### 40. Identity Provider Audit Logs

Identity provider audit logs record administrative and configuration changes within an identity platform.

They can report account creation and deletion, credential changes, application registration, role assignment, policy changes, group changes, federation changes, and administrative actions.

### 41. Directory-Service Authentication Logs

Directory-service authentication logs record authentication activity involving centralized directories and domain services.

They can report ticket requests, credential validation, directory logons, failed authentication, account lockouts, protocol use, source systems, and service authentication.

### 42. Directory-Service Audit Logs

Directory-service audit logs record changes and access to directory objects when auditing is enabled.

They can report creation, modification, deletion, permission changes, group membership updates, replication activity, policy-object changes, and access to protected directory objects.

### 43. Privileged Access Management Logs

Privileged Access Management (PAM) logs record requests, approvals, grants, sessions, and use of privileged credentials or accounts.

They can report privilege elevation, credential checkout, approval workflows, administrative session activity, password rotation, command recording where supported, and privileged-session termination.

### 44. Multi-Factor Authentication Logs

Multi-Factor Authentication (MFA) logs record challenges, responses, enrollment, device registration, and authentication-factor changes.

They can report approved and denied challenges, failed verification, repeated prompts, factor enrollment and removal, recovery actions, device changes, and authentication methods.

### 45. Single Sign-On Logs

Single Sign-On (SSO) logs record authentication and token-based access across connected applications.

They can report application access, session creation, token issuance, federation activity, authentication failures, logout, and application-specific access through the SSO service.

### 46. Federation-Service Logs

Federation-service logs record trust relationships and authentication exchanges between identity domains.

They can report assertion or token issuance, relying-party access, federation errors, certificate changes, trust configuration changes, and external identity use.

### 47. Certificate-Authority and Public-Key Infrastructure Logs

Certificate Authority (CA) and Public-Key Infrastructure (PKI) logs record certificate requests, issuance, renewal, revocation, validation, and administrative activity.

They can report certificate enrollment, requester identity, certificate templates or profiles, approval activity, failed validation, revocation, key-management events, and CA configuration changes.

### 48. Remote Access and VPN Authentication Logs

Remote-access and Virtual Private Network (VPN) logs record authentication and session activity for users and devices connecting remotely.

They can report successful and failed connections, source addresses, assigned addresses, user and device identity, session duration, transferred volume, authentication method, and disconnect reasons.

### 49. Network Access Control Logs

Network Access Control (NAC) logs record authentication, posture assessment, authorization, and connection decisions for devices joining a network.

They can report device identity, user identity, network location, authentication protocol, posture results, assigned access policy, quarantine, and connection failures.

### 50. RADIUS and TACACS-Type Authentication Logs

Centralized network authentication logs record authentication, authorization, and accounting activity for network and remote-access devices.

They can report login attempts, administrative commands where supported (a capability of TACACS+ implementations specifically), session duration, network-device access, authorization outcomes, and accounting records.

### 51. Password-Management and Credential-Vault Logs

Credential-vault logs record storage, retrieval, rotation, sharing, and administrative management of protected credentials.

They can report credential access, secret retrieval, password rotation, policy changes, vault administration, access failures, and use by applications or automation.

## Network Infrastructure and Traffic Logs

### 52. Network Firewall Logs

Network firewall logs record traffic decisions and policy enforcement at network boundaries or segmentation points.

They can report allowed, denied, rejected, and dropped connections; source and destination addresses; ports; protocols; rule matches; translated addresses; connection states; transferred bytes; and policy changes.

### 53. Next-Generation Firewall Logs

Next-Generation Firewall logs extend basic firewall records with application identification, user context, content inspection, threat classification, and other enriched traffic details.

They can report application use, users associated with traffic, inspected content categories, policy decisions, encrypted-session metadata, blocked files or threats, and traffic behavior.

### 54. Router Logs

Router logs record routing, interface, protocol, access-control, and system activity from network routers.

They can report route changes, neighbor relationships, interface status, access-control decisions, configuration changes, administrative logins, dropped traffic, and device health.

### 55. Switch Logs

Switch logs record switching, interface, virtual-LAN, access-control, and device-management activity.

They can report port up and down events, device connections, address-table changes, virtual-LAN changes, spanning-tree events, port-security violations, configuration changes, and administrative access.

### 56. Wireless Controller and Access-Point Logs

Wireless infrastructure logs record client association, authentication, roaming, radio, and management activity.

They can report wireless client connections, failed authentication, access-point changes, signal conditions, rogue access points, network selection, disconnections, and administrative configuration changes.

### 57. Network Flow Logs

Network flow logs summarize network conversations without necessarily recording packet contents. Common fields include source and destination addresses, ports, protocol, byte counts, packet counts, direction, and duration.

They can report communication relationships, connection volume, traffic direction, service use, scanning-like patterns, internal and external communication, and large or long-lived flows.

### 58. Packet-Capture Data

Packet-capture data records complete or partial network packets observed at a collection point.

It can report protocol exchanges, payload contents when not encrypted, session behavior, malformed packets, file transfers, authentication exchanges, application commands, retransmissions, and detailed connection timing.

### 59. Network Metadata Logs

Network metadata logs extract structured information from observed traffic without retaining full packet payloads.

They can report sessions, protocols, application-layer fields, files, certificates, names, headers, request and response properties, and communication timing.

### 60. Network Detection and Response Telemetry

Network Detection and Response (NDR) telemetry aggregates and analyzes packet, flow, protocol, and network metadata.

It can report network communication patterns, discovered assets, protocol activity, unusual relationships, detected behaviors, encrypted-traffic metadata, network alerts, and response actions.

### 61. Network Intrusion Detection Logs

Network Intrusion Detection System (NIDS) logs record network activity that matches configured signatures, protocol rules, heuristics, or behavior models.

They can report suspicious payloads, protocol violations, exploit patterns, scanning behavior, known malicious indicators, policy violations, and observed attack-like traffic.

### 62. Network Intrusion Prevention Logs

Network Intrusion Prevention System (NIPS) logs record network activity evaluated or blocked by inline prevention controls.

They can report blocked or allowed threats, rule matches, exploit attempts, protocol violations, reset connections, dropped packets, and prevention-policy outcomes.

### 63. DNS Resolver Logs

DNS resolver logs record name-resolution queries and responses handled by recursive or forwarding resolvers.

They can report queried domains, query types, requesting clients, response codes, returned records, response times, recursion activity, and failed lookups.

### 64. Authoritative DNS Logs

Authoritative DNS logs record queries and administrative changes involving authoritative domain-name servers.

They can report requests for hosted domains, record types requested, source addresses, response outcomes, zone transfers, dynamic updates, and zone configuration changes.

### 65. DHCP Logs

Dynamic Host Configuration Protocol (DHCP) logs record address leases and related network configuration assignments.

They can report device identifiers, assigned addresses, lease times, hostnames, relay information, lease renewal, release, conflicts, and address-assignment failures.

### 66. Proxy and Secure Web Gateway Logs

Proxy and Secure Web Gateway logs record web requests and policy decisions for traffic passing through web-access controls.

They can report requested URLs, domains, methods, users, source devices, response codes, content categories, transferred bytes, user agents, downloads, uploads, and blocked requests.

### 67. Web Application Firewall Logs

Web Application Firewall (WAF) logs record inspected web requests, responses, and policy decisions for protected web applications.

They can report request methods, paths, parameters, source addresses, rule matches, blocked requests, protocol violations, malformed input, rate controls, and application-layer attack indicators.

### 68. Load Balancer Logs

Load balancer logs record connections and requests distributed across backend services.

They can report client connections, requested hosts and paths, selected backend targets, response codes, connection duration, bytes transferred, TLS details, backend health, and routing decisions.

### 69. Reverse Proxy Logs

Reverse proxy logs record inbound requests forwarded to internal applications or services.

They can report client addresses, hosts, paths, request methods, headers, response codes, upstream targets, latency, authentication outcomes, and transferred data.

### 70. Content Delivery Network Logs

Content Delivery Network (CDN) logs record requests served or forwarded by distributed edge infrastructure.

They can report client geography, requested resources, cache hits and misses, response codes, bytes transferred, edge locations, origin fetches, rate-limiting actions, and blocked requests.

### 71. TLS and Certificate Metadata Logs

TLS metadata logs record properties of encrypted sessions without necessarily decrypting their contents.

They can report protocol versions, cipher suites, server names, certificates, issuers, fingerprints, handshake outcomes, session reuse, and client or server TLS characteristics.

### 72. Email Gateway Logs

Email gateway logs record messages processed by inbound, outbound, or internal mail gateways.

They can report senders, recipients, message identifiers, subjects or metadata, delivery status, attachments, URLs, authentication results, filtering actions, spam or malware classifications, and message routing.

### 73. Voice and Unified Communications Logs

Voice, video, and unified-communications logs record call signaling, session establishment, messaging, conferencing, and related service activity.

They can report callers and recipients, call duration, source and destination addresses, signaling outcomes, media-session properties, failed calls, conference participation, and administrative changes.

## Network Device Management and Control-Plane Logs

### 74. Network Device Administrative Audit Logs

Network-device administrative logs record access and changes made through management interfaces.

They can report administrator logins, commands, configuration changes, firmware updates, user changes, failed access, session duration, and management-source addresses.

### 75. Network Configuration Change Logs

Network configuration logs record current configuration, committed changes, rollback activity, and configuration differences.

They can report changed routing, firewall, switching, wireless, access-control, monitoring, and management settings, along with the actor and time of change.

### 76. Routing Protocol Logs

Routing protocol logs record route advertisements, withdrawals, peer relationships, and protocol state changes.

They can report neighbor establishment and loss, route changes, rejected advertisements, path changes, convergence events, and routing-policy decisions.

### 77. Network Time Protocol Logs

Network Time Protocol (NTP) logs record time synchronization requests, peers, offsets, and synchronization state.

They can report clock drift, synchronization sources, peer changes, failed synchronization, large time adjustments, and time-service health.

### 78. Software-Defined Networking Control-Plane Logs

Software-Defined Networking (SDN) logs record centralized network-policy, topology, flow-programming, and controller activity.

They can report policy changes, virtual-network creation, programmed flows, controller access, topology changes, workload attachment, and control-plane errors.

## Application and Service Logs

### 79. Web Server Access Logs

Web server access logs record requests received and responses returned by a web server.

They can report client addresses, request methods, paths, query parameters where configured, response codes, transferred bytes, user agents, referrers, authentication identities, and request timing.

### 80. Web Server Error Logs

Web server error logs record request-processing failures, configuration issues, runtime errors, and service problems.

They can report failed requests, missing resources, application exceptions, permission failures, startup problems, module errors, and upstream connection failures.

### 81. Application Audit Logs

Application audit logs record security-relevant and business-relevant actions performed within an application.

They can report user logins, data access, record creation and modification, exports, permission changes, administrative actions, workflow changes, and application configuration changes.

### 82. Application Runtime Logs

Application runtime logs record operational messages generated while an application executes.

They can report starts and stops, requests, background jobs, errors, warnings, dependencies, performance conditions, internal state changes, and application-specific activity.

### 83. Application Authentication Logs

Application authentication logs record authentication and session activity handled directly by an application.

They can report successful and failed logins, password resets, account lockouts, session creation, logout, authentication methods, source addresses, and session expiration.

### 84. API Gateway Logs

API gateway logs record API requests and policy decisions at a centralized gateway.

They can report callers, tokens or identities, methods, paths, request and response sizes, status codes, rate limits, schema validation, backend destinations, latency, and blocked requests.

### 85. API Application Logs

API application logs record requests and operations handled by an API service itself.

They can report called endpoints, request parameters where permitted, caller identity, object access, result codes, application errors, data changes, and service-to-service activity.

### 86. Database Audit Logs

Database audit logs record authentication, queries, object access, data changes, privilege use, and administrative activity within a database system.

They can report logins, failed authentication, executed statements, table and object access, schema changes, account changes, privilege grants, exports, and administrative operations.

### 87. Database Transaction Logs

Database transaction logs record low-level changes used for recovery, replication, and consistency.

They can report inserted, updated, and deleted data; transaction boundaries; rollback and commit activity; replication changes; and recovery operations, depending on database capabilities and access.

### 88. Database Performance and Diagnostic Logs

Database performance logs record query performance, resource use, errors, locks, and operational health.

They can report slow queries, failed statements, deadlocks, connection activity, resource exhaustion, replication lag, and database-service failures.

### 89. Message Queue and Event Broker Logs

Message queue and event broker logs record producer, consumer, topic, queue, delivery, and administrative activity.

They can report message publication and consumption, failed delivery, queue depth, subscriber changes, topic creation, authentication, permission changes, and broker health.

### 90. File Transfer Service Logs

File transfer service logs record uploads, downloads, authentication, and session activity for managed file-transfer protocols and services.

They can report users, transferred files, source and destination addresses, transfer sizes, paths, success or failure, session duration, and permission errors.

### 91. Collaboration Platform Audit Logs

Collaboration platform audit logs record activity involving messages, meetings, channels, shared files, and administration.

They can report user access, message and channel activity, file sharing, external invitations, meeting participation, application integrations, permission changes, and administrative actions.

### 92. Source-Code Management Audit Logs

Source-code management logs record repository, branch, commit, access, integration, and administrative activity.

They can report repository access, code pushes, branch changes, pull or merge requests, permission changes, token use, webhook changes, repository creation or deletion, and administrative actions.

### 93. Continuous Integration and Continuous Delivery/Deployment (CI/CD) Logs

Continuous Integration and Continuous Delivery/Deployment (CI/CD) logs record pipeline definitions, builds, jobs, deployments, artifacts, and automation activity.

They can report pipeline execution, actor identity, source revisions, build commands, test results, deployment targets, secret use where audited, artifact creation, and configuration changes.

### 94. Artifact Repository Logs

Artifact repository logs record storage, retrieval, publication, deletion, and administration of software packages and build artifacts.

They can report uploaded and downloaded artifacts, package versions, users or automation identities, source addresses, repository changes, metadata changes, and access failures.

### 95. Secrets-Management Logs

Secrets-management logs record creation, retrieval, rotation, deletion, and administration of secrets, keys, and credentials.

They can report secret access, requesting identities, authentication, policy decisions, secret versions, rotation activity, access failures, and configuration changes.

### 96. Enterprise Resource Planning and Business-System Audit Logs

Business-system audit logs record user, workflow, financial, operational, and administrative actions in enterprise applications.

They can report record access, approvals, transactions, master-data changes, exports, role changes, configuration updates, and business-process activity.

## Email, Messaging, and Content Logs

### 97. Mailbox Audit Logs

Mailbox audit logs record actions performed within user and shared mailboxes.

They can report message access, movement, deletion, sending, forwarding, delegate activity, mailbox-rule changes, permission changes, and administrative mailbox access.

### 98. Mail Transport Logs

Mail transport logs record message movement through mail servers and routing infrastructure.

They can report sender and recipient addresses, message identifiers, delivery hops, routing decisions, delivery status, rejections, delays, and message-size information.

### 99. Email Authentication Logs

Email authentication logs record validation of sending domains and messages through email-authentication mechanisms.

They can report authentication outcomes, sending domains, source addresses, alignment results, policy decisions, and rejected or quarantined messages.

### 100. Data Loss Prevention Logs

Data Loss Prevention (DLP) logs record content inspection and policy decisions involving sensitive information.

They can report detected data classifications, users, source and destination channels, file or message actions, blocked or allowed transfers, policy matches, overrides, and administrative changes.

### 101. Content Inspection and Malware Scanning Logs

Content inspection logs record the analysis of files, messages, web content, and other objects by scanning or sandboxing controls.

They can report inspected objects, hashes, file types, scan outcomes, detected content, behavioral observations, quarantines, blocked delivery, and analysis errors.

### 102. Digital Rights Management and Information Protection Logs

Information-protection logs record labeling, encryption, access, sharing, and policy enforcement for protected content.

They can report label application and removal, document access, sharing, decryption, policy violations, access denial, and administrative policy changes.

## Cloud Infrastructure Logs

### 103. Cloud Control-Plane Audit Logs

Cloud control-plane audit logs record administrative API calls and configuration changes made to cloud resources.

They can report resource creation, modification, and deletion; identity and access changes; network changes; storage configuration; service enablement; policy changes; and the identity responsible for each action.

### 104. Cloud Data-Plane Access Logs

Cloud data-plane logs record access to the contents or operational interfaces of cloud-hosted resources.

They can report object reads and writes, database access, function invocation, message access, secret retrieval, file operations, and requests to hosted services.

### 105. Cloud Identity and Access Management Logs

Cloud Identity and Access Management (IAM) logs record changes and use involving cloud users, roles, service identities, permissions, and credentials.

They can report role assumptions, permission grants and revocations, key creation, policy changes, service-account activity, authentication, and access-denied events.

### 106. Cloud Network Flow Logs

Cloud network flow logs summarize network traffic involving cloud virtual networks and interfaces.

They can report source and destination addresses, ports, protocols, byte and packet counts, accepted or rejected traffic, interface identifiers, and communication between cloud resources.

### 107. Cloud Firewall and Security-Group Logs

Cloud firewall logs record traffic decisions and configuration changes involving cloud-native network controls.

They can report allowed and denied traffic, matched rules, source and destination resources, rule creation and modification, exposure changes, and policy enforcement.

### 108. Cloud Object-Storage Access Logs

Object-storage logs record requests involving buckets, containers, objects, and related policies.

They can report object reads, writes, deletion, listing, copies, sharing, public-access changes, lifecycle operations, caller identity, and source addresses.

### 109. Cloud Compute Instance Logs

Cloud compute logs record lifecycle and platform activity involving virtual machines and similar compute resources.

They can report instance creation and deletion, startup and shutdown, metadata changes, attached storage, image changes, console access, health events, and administrative actions.

### 110. Cloud Function and Serverless Logs

Serverless logs record function invocation, execution, errors, dependencies, and configuration activity.

They can report invocation identity, trigger sources, execution duration, runtime output, failures, environment changes, permissions, and network activity where available.

### 111. Cloud Database Service Logs

Managed cloud database logs record database access, control-plane activity, queries where auditing is enabled, and service health.

They can report authentication, queries, data access, configuration changes, backups, replication, scaling, maintenance, and database failures.

### 112. Cloud Key-Management Logs

Cloud key-management logs record creation, use, rotation, disabling, and deletion of cryptographic keys.

They can report encryption and decryption operations, callers, key-policy changes, grants, rotations, access failures, and administrative actions.

### 113. Cloud Secrets-Manager Logs

Cloud secrets-manager logs record access and administration of managed secrets.

They can report secret retrieval, creation, updates, rotation, deletion, requesting identities, access failures, and policy changes.

### 114. Cloud Resource-Configuration Inventory

Cloud resource inventories record current and historical resource configuration and relationships.

They can report resource types, ownership, tags, network placement, access settings, dependencies, configuration drift, exposure, and changes over time.

### 115. Cloud Security-Posture Management Logs

Cloud Security Posture Management (CSPM) logs record assessments of cloud configuration against security and compliance policies.

They can report misconfigurations, exposed resources, excessive permissions, policy violations, remediation status, asset inventory, and posture changes.

### 116. Cloud Workload Protection Logs

Cloud workload protection logs record security observations from virtual machines, containers, serverless functions, and cloud workloads.

They can report workload process and file activity, runtime behavior, network connections, vulnerabilities, policy violations, detected threats, and response actions.

### 117. Cloud Billing and Usage Logs

Cloud billing and usage logs record resource consumption, service usage, and cost allocation.

They can report consumed services, resource quantities, account and project usage, regional activity, cost changes, resource growth, and unusual consumption patterns.

## Container and Orchestration Logs

### 118. Container Runtime Logs

Container runtime logs record container creation, startup, execution, termination, image use, and runtime errors.

They can report container lifecycle, images, commands, runtime users, mounts, namespaces, failures, and runtime operations.

### 119. Container Standard Output and Error Logs

Container output logs collect messages written by applications and processes running inside containers.

They can report application requests, errors, operational state, internal activity, dependency failures, and application-specific events.

### 120. Container Image Registry Logs

Container registry logs record image publication, retrieval, deletion, scanning, and administration.

They can report image pushes and pulls, tags, digests, users or service identities, source addresses, repository changes, scanning outcomes, and access failures.

### 121. Orchestrator Audit Logs

Container-orchestrator audit logs record requests to the orchestration control plane.

They can report requesting identities, API operations, resources, namespaces, object creation and modification, permission decisions, workload deployment, secret access, and administrative actions.

### 122. Orchestrator Control-Plane Component Logs

Control-plane component logs record operational activity from schedulers, controllers, API services, and orchestration databases.

They can report scheduling decisions, controller actions, leader election, reconciliation failures, state changes, cluster errors, and component health.

### 123. Orchestrator Node-Agent Logs

Node-agent logs record workload lifecycle and node-management activity on individual cluster nodes.

They can report pod or workload startup, image pulling, volume mounting, health probes, resource pressure, node status, runtime errors, and workload termination.

### 124. Container Network Logs

Container network logs record communication and policy enforcement involving containers, pods, services, and cluster networks.

They can report workload-to-workload connections, ingress and egress, network-policy decisions, service communication, names, addresses, ports, and denied traffic.

### 125. Container Admission-Control Logs

Admission-control logs record validation and mutation decisions made before workloads or resources are accepted by an orchestrator.

They can report allowed and rejected deployments, policy violations, mutated settings, image restrictions, privilege settings, and admission errors.

### 126. Container Runtime Security Logs

Container runtime security logs record behavior and policy decisions observed while containers execute.

They can report process execution, file access, system calls, privilege changes, network activity, container escapes or violations, policy matches, and response actions.

### 127. Service Mesh Logs

Service mesh logs record service-to-service communication managed through mesh proxies and control-plane components.

They can report service identities, requests, destinations, response codes, latency, mutual-authentication outcomes, policy decisions, certificates, and service relationships.

## Virtualization and Infrastructure Logs

### 128. Hypervisor Logs

Hypervisor logs record virtual machine lifecycle, host activity, virtual networking, storage, and administrative operations.

They can report virtual machine creation, startup, shutdown, snapshots, migration, console access, virtual-device changes, host errors, and administrative actions.

### 129. Virtualization Management Logs

Virtualization management logs record centralized administration of hypervisors, clusters, and virtual machines.

They can report user logins, role changes, virtual machine operations, cluster configuration, resource allocation, template use, network changes, and storage changes.

### 130. Virtual Desktop Infrastructure Logs

Virtual Desktop Infrastructure (VDI) logs record virtual desktop assignment, connection, session, image, and administration activity.

They can report user sessions, source devices, desktop pools, connection failures, session duration, image changes, administrative actions, and remote-display activity.

### 131. Storage-System Audit Logs

Storage-system logs record access and administration of network-attached, block, file, and object storage systems.

They can report file or volume access, shares, snapshots, replication, permission changes, storage administration, deletions, capacity conditions, and hardware failures.

### 132. Backup and Recovery Logs

Backup and recovery logs record backup jobs, protected resources, restore operations, retention, and backup-system administration.

They can report successful and failed backups, restores, deleted backups, changed retention policies, repository access, protected-system coverage, and administrative changes.

### 133. Infrastructure Management Interface Logs

Infrastructure management logs record access and activity through out-of-band hardware management interfaces.

They can report administrative logins, remote console use, power operations, firmware changes, hardware configuration, virtual-media mounting, and management-network activity.

### 134. Hardware and Environmental Monitoring Logs

Hardware monitoring logs record physical device health and environmental conditions.

They can report component failures, temperature, power, fan state, storage errors, memory errors, chassis access, sensor alerts, and hardware replacement.

## Security Control and Assessment Logs

### 135. Antivirus and Antimalware Logs

Antivirus and antimalware logs record scanning, detection, prevention, quarantine, and remediation activity.

They can report detected files or behavior, scan results, quarantines, cleanup actions, exclusions, signature or engine updates, protection status, and failures.

### 136. Vulnerability Scanner Logs

Vulnerability scanner logs record discovered assets, scan activity, identified weaknesses, and scan outcomes.

They can report open services, software versions, missing updates, configuration weaknesses, scan credentials, scan coverage, failed checks, and remediation status.

### 137. Configuration and Compliance Scanner Logs

Configuration and compliance logs record assessments against defined configuration, security, and regulatory baselines.

They can report failed controls, configuration drift, missing settings, insecure permissions, compliance status, exceptions, and remediation activity.

### 138. Attack-Surface Management Logs

Attack-Surface Management logs record discovered internet-facing and externally observable assets.

They can report domains, addresses, certificates, exposed services, cloud resources, ownership relationships, newly discovered assets, and changes in external exposure.

### 139. Breach and Attack Simulation Logs

Breach and Attack Simulation logs record controlled security tests and their observed outcomes.

They can report executed test actions, affected controls, blocked and allowed simulations, telemetry visibility, detection outcomes, and control coverage.

### 140. Deception-System Logs

Deception systems record interactions with decoy accounts, systems, files, credentials, services, or data.

They can report access to decoys, connection attempts, authentication, commands, file operations, source entities, session behavior, and triggered deception artifacts.

### 141. Sandbox Analysis Logs

Sandbox logs record static and dynamic analysis of submitted files, URLs, scripts, or other content.

They can report file properties, process behavior, network activity, dropped files, registry or configuration changes, memory behavior, observed indicators, and analysis verdicts.

### 142. Security Orchestration and Automated Response Logs

Security Orchestration, Automation, and Response (SOAR) logs record playbook execution, automated actions, approvals, and integrations.

They can report triggered workflows, enrichment queries, containment actions, analyst approvals, failed automation, case updates, and changes to response playbooks.

### 143. Security Information and Event Management Logs

Security Information and Event Management (SIEM) systems record ingestion, normalization, correlation, querying, alerting, and administrative activity across collected sources.

They can report source ingestion status, parsing outcomes, correlation alerts, search activity, rule changes, user access, data retention, collector failures, and case-related activity.

### 144. User and Entity Behavior Analytics Logs

User and Entity Behavior Analytics (UEBA) logs record behavioral profiles, anomaly scores, entity relationships, and behavior-based alerts derived from other telemetry.

They can report deviations from entity or peer behavior, risk-score changes, observed behavioral features, contributing events, entity timelines, and model or baseline status.

### 145. Threat-Intelligence Platform Logs

Threat-intelligence platform logs record ingestion, enrichment, sharing, matching, and administration of threat-intelligence data.

They can report indicator creation and updates, source feeds, enrichment activity, matches against observed data, confidence or scoring changes, sharing activity, and administrative changes.

### 146. Case-Management and Incident-Response Logs

Case-management logs record investigations, analyst actions, evidence handling, decisions, and response workflows.

They can report case creation, assignment, status changes, analyst notes, evidence access, containment decisions, escalations, and closure activity.

## Data Platform and Observability Logs

### 147. Central Log Collector Logs

Central log collector logs record receipt, forwarding, parsing, buffering, and failure of log data from source systems.

They can report source connectivity, event volume, parsing failures, dropped messages, queue backlogs, forwarding destinations, collector health, and configuration changes.

### 148. Data Pipeline and Stream-Processing Logs

Data pipeline logs record ingestion, transformation, routing, processing, and delivery of data between systems.

They can report job execution, source and destination activity, schema changes, transformation failures, processing delays, dropped records, retries, and pipeline configuration changes.

### 149. Data Warehouse Audit Logs

Data warehouse audit logs record authentication, queries, data access, data modification, exports, and administration of analytical data platforms.

They can report user and service access, queried datasets, executed statements, data exports, permission changes, schema operations, workload activity, and administrative actions.

### 150. Data Lake Access Logs

Data lake logs record access and administration involving large-scale file, object, or table-based analytical storage.

They can report reads, writes, deletion, listing, sharing, table operations, query activity, identities, data locations, and permission changes.

### 151. Extract, Transform, and Load Logs

Extract, Transform, and Load (ETL) logs record scheduled or triggered movement and transformation of data.

They can report source extraction, transformation steps, destination loading, data volumes, failures, retries, schema mismatches, and job configuration changes.

### 152. Metrics and Monitoring-System Logs

Metrics systems record numerical measurements about application, system, network, and service behavior over time.

They can report resource utilization, request rates, error rates, latency, queue depth, availability, capacity, health indicators, and changes in measured operational state.

### 153. Distributed Tracing Logs

Distributed tracing records the path and timing of requests across services and components.

It can report service dependencies, request flow, called operations, latency, errors, parent-child spans, service identities, and failures within distributed transactions.

### 154. Application Performance Monitoring Logs

Application Performance Monitoring (APM) logs combine metrics, traces, errors, and application runtime details.

They can report transaction performance, slow operations, errors, dependency calls, code-level behavior where supported, service health, and resource consumption.

### 155. Change-Management Logs

Change-management logs record requested, approved, implemented, and reviewed changes to systems and services.

They can report change owners, approval status, implementation windows, affected assets, rollback activity, emergency changes, and documented reasons for changes.

### 156. Asset Inventory and Discovery Logs

Asset inventory logs record discovered hardware, software, services, identities, and ownership information.

They can report newly discovered assets, software installations, device attributes, owners, network locations, lifecycle state, missing assets, and inventory changes.

### 157. Configuration Management Database Logs

Configuration Management Database (CMDB) logs record configuration items, ownership, relationships, and changes.

They can report asset relationships, service dependencies, ownership changes, lifecycle status, configuration updates, and changes to documented infrastructure.

## Physical Security and Operational Technology Logs

### 158. Physical Access-Control Logs

Physical access-control logs record badge, biometric, key, gate, and door-access activity.

They can report successful and denied entry, identity, location, time, door state, forced entry, tailgating alerts where supported, and access-policy changes.

### 159. Video Surveillance System Logs

Video surveillance logs record camera, recorder, user-access, motion, and administrative activity.

They can report camera availability, motion events, video access, exports, camera configuration changes, storage failures, and administrative logins.

### 160. Building Management System Logs

Building management logs record environmental controls, alarms, access, and operational state for managed facilities.

They can report temperature, power, lighting, ventilation, alarms, equipment state, configuration changes, and operator activity.

### 161. Industrial Control System Logs

Industrial Control System (ICS) logs record process-control, operator, controller, alarm, and engineering activity.

They can report process values, control commands, alarm state, operator actions, controller changes, engineering access, device communication, and operational state changes.

### 162. Supervisory Control and Data Acquisition Logs

Supervisory Control and Data Acquisition (SCADA) logs record telemetry, commands, alarms, and operator activity across distributed industrial systems.

They can report remote-terminal data, set-point changes, control commands, communication failures, alarms, operator sessions, and field-device state.

### 163. Programmable Logic Controller Logs

Programmable Logic Controller (PLC) logs record controller status, program changes, faults, and process interactions where supported.

They can report logic uploads and downloads, mode changes, faults, input and output state, communications, firmware changes, and engineering access.

### 164. Operational Technology Network Logs

Operational Technology (OT) network logs record communication among industrial devices, controllers, operator stations, and management systems.

They can report industrial protocol use, device relationships, commands, process values where decoded, network connections, communication failures, and unexpected device activity.

### 165. Internet of Things Device Logs

Internet of Things (IoT) logs record device activity, connectivity, sensor readings, commands, firmware, and management activity.

They can report device registration, telemetry, cloud communication, command execution, firmware updates, authentication, configuration changes, and device health.

## Mobile and Remote-Device Logs

### 166. Mobile Device Management Logs

Mobile Device Management (MDM) logs record enrollment, compliance, configuration, application, and administrative activity for managed mobile devices.

They can report device enrollment, policy application, compliance status, application installation, remote wipe or lock, configuration changes, and device ownership.

### 167. Mobile Endpoint Security Logs

Mobile endpoint security logs record security-relevant activity and posture from supported mobile devices.

They can report malicious application detections, unsafe network connections, device compromise indicators, application behavior, policy violations, and remediation actions.

### 168. Mobile Operating-System Logs

Mobile operating-system logs record application, system, network, crash, and diagnostic activity available from the device platform.

They can report application execution, permission use, system errors, network behavior, device state, crashes, and operating-system service activity.

### 169. Remote Desktop and Remote Support Logs

Remote desktop and remote-support logs record interactive remote-control sessions.

They can report users, source and destination devices, session start and end, authentication, file transfer, clipboard use where audited, session recording, and administrative actions.

## Development, Administrative, and Governance Logs

### 170. Administrative Console Audit Logs

Administrative console logs record actions performed through management portals and consoles.

They can report administrator login, configuration changes, user and role management, resource changes, policy decisions, exports, and administrative-session activity.

### 171. Infrastructure-as-Code Logs

Infrastructure-as-Code logs record planned and applied changes generated from declarative infrastructure definitions.

They can report changed resources, execution plans, applying identities, state changes, failed deployments, configuration revisions, and drift from managed definitions.

### 172. Automation and Orchestration Platform Logs

Automation-platform logs record jobs, playbooks, runbooks, scripts, and administrative changes executed across systems.

They can report actor identity, targeted assets, executed tasks, commands, results, failures, credentials or service identities used, schedules, and automation configuration changes.

### 173. IT Service Management Logs

IT Service Management (ITSM) logs record incidents, requests, changes, problems, approvals, and operational workflows.

They can report requested access, approved changes, incident handling, assigned personnel, service impact, maintenance activity, and documented operational context.

### 174. Governance, Risk, and Compliance Logs

Governance, Risk, and Compliance (GRC) logs record assessments, control status, exceptions, approvals, and risk-management activity.

They can report control failures, accepted risks, policy exceptions, assessment results, evidence access, remediation plans, and changes in compliance status.

### 175. Privacy and Data-Governance Logs

Privacy and data-governance logs record classification, lineage, access, retention, and handling of governed data.

They can report data discovery, classification changes, data-owner actions, access requests, retention changes, lineage updates, policy violations, and data-subject request activity.

## General Interpretation Principles

1. **A platform is not always a raw source.** EDR, XDR, NDR, SIEM, UEBA, and similar systems usually aggregate or derive information from multiple underlying telemetry sources.
2. **Availability depends on configuration.** Many sources report only the activity explicitly enabled by audit policy, collection rules, licensing, or retention settings.
3. **A log records an observation, not complete reality.** Missing events may reflect collection gaps, unsupported activity, filtering, or disabled auditing.
4. **Descriptions are capability-oriented.** A source may technically report an activity without capturing every field needed to interpret it.
5. **Source overlap is expected.** The same activity may be reported by several sources at different layers and with different levels of detail.
6. **Administrative logs are security-relevant.** Configuration, policy, audit, and health logs often provide essential context about why behavior changed.
7. **Data quality matters.** Accurate timestamps, entity identifiers, source identity, parsing, normalization, and retention determine whether telemetry can be reliably used.

## References

1. Kent, K., and Souppaya, M. (2006). *Guide to Computer Security Log Management*. NIST Special Publication 800-92. https://doi.org/10.6028/NIST.SP.800-92
2. Scarfone, K., and Souppaya, M. (2023). *Cybersecurity Log Management Planning Guide*. NIST Special Publication 800-92 Revision 1, Initial Public Draft. https://doi.org/10.6028/NIST.SP.800-92r1.ipd
3. National Institute of Standards and Technology. (2020). *Security and Privacy Controls for Information Systems and Organizations*. NIST Special Publication 800-53 Revision 5. https://doi.org/10.6028/NIST.SP.800-53r5
4. National Institute of Standards and Technology. (2011). *Information Security Continuous Monitoring for Federal Information Systems and Organizations*. NIST Special Publication 800-137. https://doi.org/10.6028/NIST.SP.800-137
5. Scarfone, K., and Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems*. NIST Special Publication 800-94. https://doi.org/10.6028/NIST.SP.800-94
6. Gerhards, R. (2009). *The Syslog Protocol*. RFC 5424. Internet Engineering Task Force. https://doi.org/10.17487/RFC5424
7. Rigney, C., Willens, S., Rubens, A., and Simpson, W. (2000). *Remote Authentication Dial In User Service (RADIUS)*. RFC 2865. Internet Engineering Task Force. https://doi.org/10.17487/RFC2865
8. Rigney, C. (2000). *RADIUS Accounting*. RFC 2866. Internet Engineering Task Force. https://doi.org/10.17487/RFC2866
9. Dahm, T., Ota, A., Medway Gash, D. C., Carrel, D., and Grant, L. (2020). *The Terminal Access Controller Access-Control System Plus (TACACS+) Protocol*. RFC 8907. Internet Engineering Task Force. https://doi.org/10.17487/RFC8907
10. Mockapetris, P. (1987). *Domain Names - Implementation and Specification*. RFC 1035. Internet Engineering Task Force. https://doi.org/10.17487/RFC1035
11. Droms, R. (1997). *Dynamic Host Configuration Protocol*. RFC 2131. Internet Engineering Task Force. https://doi.org/10.17487/RFC2131
12. Claise, B., Trammell, B., and Aitken, P. (2013). *Specification of the IP Flow Information Export (IPFIX) Protocol for the Exchange of Flow Information*. RFC 7011. Internet Engineering Task Force. https://doi.org/10.17487/RFC7011
13. Rekhter, Y., Li, T., and Hares, S., eds. (2006). *A Border Gateway Protocol 4 (BGP-4)*. RFC 4271. Internet Engineering Task Force. https://doi.org/10.17487/RFC4271
14. Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3*. RFC 8446. Internet Engineering Task Force. https://doi.org/10.17487/RFC8446
15. Stouffer, K., Pease, M., Tang, C., Zimmerman, T., Pillitteri, V., Lightman, S., Hahn, A., Saravia, S., Sherule, A., and Thompson, M. (2023). *Guide to Operational Technology Security*. NIST Special Publication 800-82 Revision 3. https://doi.org/10.6028/NIST.SP.800-82r3
16. Souppaya, M., Morello, J., and Scarfone, K. (2017). *Application Container Security Guide*. NIST Special Publication 800-190. https://doi.org/10.6028/NIST.SP.800-190
17. Scarfone, K., Souppaya, M., and Hoffman, P. (2011). *Guide to Security for Full Virtualization Technologies*. NIST Special Publication 800-125. https://doi.org/10.6028/NIST.SP.800-125
18. Rose, S., Borchert, O., Mitchell, S., and Connelly, S. (2020). *Zero Trust Architecture*. NIST Special Publication 800-207. https://doi.org/10.6028/NIST.SP.800-207
19. OpenTelemetry Authors. (2025). *OpenTelemetry Specification: Logs, Metrics, and Traces*. Cloud Native Computing Foundation. https://opentelemetry.io/docs/specs/otel/
20. Shahin, M., Babar, M. A., and Zhu, L. (2017). Continuous integration, delivery and deployment: A systematic review on approaches, tools, challenges and practices. *IEEE Access*, 5, 3909-3943. https://doi.org/10.1109/ACCESS.2017.2685629
21. Oliner, A., Ganapathi, A., and Xu, W. (2012). Advances and challenges in log analysis. *Communications of the ACM*, 55(2), 55-61. https://doi.org/10.1145/2076450.2076466
22. He, S., Zhu, J., He, P., and Lyu, M. R. (2016). Experience report: System log analysis for anomaly detection. In *2016 IEEE 27th International Symposium on Software Reliability Engineering*, 207-218. https://doi.org/10.1109/ISSRE.2016.21
