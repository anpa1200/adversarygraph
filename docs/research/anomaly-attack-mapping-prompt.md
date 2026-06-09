# Deep Research Prompt: Anomaly Detection Mapped to MITRE ATT&CK

Use this prompt with an LLM that supports deep research and source citations. Replace the values in the **Research scope** section before running it.

```text
You are a senior detection engineer, threat researcher, data scientist, and MITRE ATT&CK specialist.

Your task is to conduct a rigorous, evidence-backed study of how behavioral anomalies can detect adversary activity and how those anomalies map to MITRE ATT&CK techniques and sub-techniques.

The goal is NOT to produce another list of signatures, static indicators, or simple fixed-threshold alerts. The goal is to identify behavior that becomes suspicious because it deviates from an entity's own history, an appropriate peer group, an expected sequence, a normal relationship graph, or an established environmental pattern.

RESEARCH SCOPE

- ATT&CK domain: Enterprise ATT&CK
- ATT&CK version: latest available version; state the exact version and access date
- Priority environments: Windows, Linux, macOS, Active Directory, Entra ID, AWS, Azure, GCP, Kubernetes, SaaS, email, network, and identity
- Priority tactics: all Enterprise ATT&CK tactics
- Output depth: technique and sub-technique level where evidence permits
- Audience: detection engineers, SOC analysts, threat hunters, security data scientists, and detection-content developers

CORE RESEARCH QUESTION

For each relevant ATT&CK technique or sub-technique, what observable activity could be detected as an anomaly, what baseline or behavioral model would make it anomalous, which telemetry and fields are required, and how could a defender implement and validate the detection?

DEFINITION OF AN ANOMALY DETECTION

Treat a detection as anomaly-based only when it compares observed behavior against one or more learned or derived expectations, including:

1. Self-baseline anomaly: deviation from the historical behavior of the same user, host, service, workload, process, application, account, or network entity.
2. Peer-group anomaly: deviation from entities with comparable roles, functions, privileges, workloads, or business context.
3. Temporal anomaly: unusual time, frequency, duration, periodicity, burst pattern, or seasonality.
4. Volume anomaly: unusual count, rate, size, fan-out, fan-in, or data transfer volume relative to a contextual baseline.
5. Rarity or novelty anomaly: a first-seen or rarely seen process, command, parent-child relationship, destination, resource, permission, user-agent, protocol, or action.
6. Sequence anomaly: an unusual ordering or transition between otherwise legitimate events.
7. Graph or relationship anomaly: a new or unusual relationship between users, hosts, processes, resources, services, accounts, or destinations.
8. Population anomaly: behavior that is statistically unusual across the environment.
9. Distribution or drift anomaly: a material change in the distribution of behavior over time.
10. Cross-source anomaly: behavior that becomes anomalous only when telemetry from multiple sources is correlated.

Do not classify these as anomaly detections unless they include a contextual baseline:

- A fixed count or fixed time-window threshold used for every entity
- A known-bad hash, IP address, domain, filename, command, tool, or user-agent
- A static allowlist or denylist match
- A direct signature or exact pattern match
- A single suspicious event with no comparison to expected behavior

RESEARCH METHOD

1. Build the ATT&CK technique inventory from official MITRE ATT&CK sources.
2. Review official ATT&CK data sources, data components, detection strategies, analytics, procedure examples, and mitigations.
3. Supplement MITRE material with primary and high-quality sources:
   - official vendor documentation and detection research
   - peer-reviewed papers and reputable conference publications
   - open-source detection projects and public detection content
   - documented incident reports with sufficient behavioral detail
4. Prefer primary sources. Clearly label inferences and unsupported hypotheses.
5. Cite every substantive technique mapping and implementation claim with direct URLs.
6. Record the publication date and access date for sources where available.
7. Separate evidence-backed mappings from plausible research hypotheses.
8. Do not force an anomaly mapping for every ATT&CK technique. State when a technique:
   - has no reliable anomaly-detection opportunity
   - is better detected using signatures or deterministic policy controls
   - lacks sufficient telemetry
   - is indistinguishable from legitimate behavior without additional context

ANALYSIS PROCESS FOR EACH TECHNIQUE

For every technique or sub-technique in scope:

1. Describe the adversary behavior in implementation-neutral terms.
2. Identify the smallest observable units:
   - entities
   - actions
   - resources
   - relationships
   - sequences
   - time and volume characteristics
3. Identify one or more anomaly hypotheses.
4. Explain why each hypothesis represents a contextual anomaly rather than a signature or fixed threshold.
5. Define the appropriate baseline:
   - baseline subject
   - peer-group definition
   - training/lookback period
   - seasonality and business-calendar handling
   - minimum data volume
   - update/retraining cadence
   - cold-start strategy
6. Identify required telemetry, log sources, data components, and exact fields.
7. Describe normalization and entity-resolution requirements.
8. Propose detection logic at three maturity levels:
   - Level 1: interpretable statistical or rarity-based method
   - Level 2: sequence, graph, peer-group, or multi-source method
   - Level 3: advanced model only where justified by the data and expected benefit
9. Explain likely false positives and the environmental context needed to suppress them safely.
10. Define validation methods using adversary emulation, historical incidents, labeled data, synthetic data, or controlled experiments.
11. Assign confidence and feasibility scores.

REQUIRED DETECTION-HYPOTHESIS FIELDS

For each anomaly hypothesis, provide:

- hypothesis_id: stable identifier such as ANOM-T1059.001-001
- attack_id
- attack_name
- tactic
- platforms
- adversary_behavior
- anomaly_hypothesis
- anomaly_type: one or more types from the anomaly definition
- anomalous_entity
- baseline_subject
- peer_group
- expected_normal_behavior
- anomalous_behavior
- minimum_required_context
- required_log_sources
- required_data_components
- required_fields
- correlation_keys
- lookback_window
- scoring_window
- baseline_update_strategy
- cold_start_strategy
- detection_logic_level_1
- detection_logic_level_2
- detection_logic_level_3
- example_pseudocode
- explanation_features_for_analyst
- false_positives
- tuning_and_suppression
- evasion_and_blind_spots
- validation_plan
- estimated_data_quality_required: low, medium, or high
- estimated_implementation_effort: low, medium, or high
- estimated_operational_value: low, medium, or high
- confidence: confirmed, supported, plausible, or speculative
- evidence_summary
- sources

LOG-SOURCE CATALOG

Create a normalized catalog of useful log sources. For each source include:

- source name and category
- producing systems or products
- security behaviors it can reveal
- essential fields
- useful optional fields
- entity identifiers
- common data-quality problems
- retention and baseline recommendations
- relevant ATT&CK data sources and data components
- example anomaly use cases

At minimum, assess:

- endpoint process, file, module, registry, service, driver, and authentication telemetry
- Windows Event Logs, Sysmon, PowerShell, and ETW-derived telemetry
- Linux audit, process, authentication, shell, service, and package telemetry
- macOS endpoint and unified logs
- DNS, DHCP, proxy, firewall, VPN, NetFlow/IPFIX, packet-derived metadata, and TLS metadata
- Active Directory and Entra ID identity, authentication, authorization, and audit logs
- AWS CloudTrail and supporting AWS service logs
- Azure activity, resource, identity, and platform logs
- GCP audit and platform logs
- Kubernetes audit, workload, identity, and network telemetry
- SaaS audit logs, especially email, collaboration, source control, and administrative activity
- email gateway and mailbox audit telemetry
- application, API gateway, database, and data-access telemetry

QUALITY CONTROLS

- Never invent log fields, ATT&CK mappings, product capabilities, or citations.
- Distinguish raw telemetry fields from fields created by normalization or enrichment.
- Do not claim that machine learning is required when statistics, rarity, or graph rules are sufficient.
- Avoid vague statements such as "use ML to detect unusual behavior."
- Every proposed model must state its entity, features, baseline, window, output score, and analyst explanation.
- Prefer interpretable and operationally maintainable detections.
- Identify data leakage, concept drift, poisoning, sparse-data, and class-imbalance risks where relevant.
- Address privileged users, service accounts, scanners, automation, ephemeral cloud resources, remote workers, and maintenance windows.
- Treat ATT&CK mappings as many-to-many. One anomaly may indicate multiple techniques, and one technique may produce multiple anomaly patterns.
- Distinguish detection of the technique itself from detection of its prerequisites, side effects, or downstream consequences.

DELIVERABLES

Produce the following artifacts:

1. Executive summary
   - key findings
   - where anomaly detection adds the most value
   - where anomaly detection is weak or inappropriate
   - major telemetry and operational prerequisites

2. Anomaly taxonomy
   - precise definitions
   - cybersecurity examples
   - suitable modeling approaches
   - strengths, weaknesses, and evasion considerations

3. ATT&CK coverage matrix
   - one row per technique/sub-technique
   - number of supported anomaly hypotheses
   - best anomaly types
   - required log-source categories
   - feasibility, operational value, and confidence
   - explicit gap reason where no mapping is recommended

4. Detailed detection-hypothesis catalog
   - use all required detection-hypothesis fields
   - group by tactic and technique
   - provide evidence-backed citations

5. Log-source and field catalog

6. Prioritized implementation roadmap
   - top 20 anomaly detections for an initial MVP
   - selection criteria
   - telemetry dependencies
   - expected engineering effort
   - proposed validation approach

7. Research gaps
   - weakly supported mappings
   - missing telemetry
   - experiments needed
   - techniques unsuitable for anomaly detection

8. Machine-readable output
   - provide valid JSON matching the schema below
   - use null rather than invented values
   - place citations in each relevant record

MACHINE-READABLE JSON SHAPE

{
  "metadata": {
    "research_date": "YYYY-MM-DD",
    "attack_domain": "enterprise-attack",
    "attack_version": "string",
    "scope_notes": "string"
  },
  "anomaly_types": [],
  "log_sources": [],
  "techniques": [
    {
      "attack_id": "T0000.000",
      "attack_name": "string",
      "tactics": [],
      "platforms": [],
      "anomaly_detection_fit": "strong | moderate | weak | unsuitable | unknown",
      "gap_reason": null,
      "hypotheses": []
    }
  ],
  "mvp_priorities": [],
  "research_gaps": [],
  "sources": []
}

FINAL REVIEW BEFORE SUBMISSION

Before returning the research:

1. Check that every anomaly hypothesis uses a real contextual baseline.
2. Remove detections that are only signatures, static indicators, or universal fixed thresholds.
3. Verify ATT&CK IDs and names against the stated ATT&CK version.
4. Verify that every cited URL supports the associated claim.
5. Mark inference and uncertainty explicitly.
6. Confirm that machine-readable output is valid JSON.
7. Identify any coverage statistics that could be misleading because of weak or speculative mappings.
```

## Recommended Research Sequence

Do not ask the model to research the entire Enterprise ATT&CK matrix in one pass. Use the master prompt in stages:

1. Produce the anomaly taxonomy and normalized log-source catalog.
2. Research one ATT&CK tactic at a time.
3. Review and reject weak mappings before continuing.
4. Merge accepted mappings into the coverage matrix.
5. Select the MVP detections only after telemetry requirements and validation plans are known.

For each tactic-specific run, append:

```text
For this run, research only the following ATT&CK tactic: <TACTIC NAME>.
Return no more than 25 high-quality detection hypotheses. Favor evidence and operational usefulness over coverage.
```
