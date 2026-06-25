"""
NVIDIA-focused Sector Intel content packs.
All intelligence is based on public information, generic assessments,
and analytic tradecraft. No proprietary NVIDIA data or fabricated incidents.
Confidence levels: High / Medium / Low / Unknown.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.models.sector_packs import SectorPack

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Seed data — 15 NVIDIA-relevant sectors
# ---------------------------------------------------------------------------

NVIDIA_SECTOR_PACKS: list[dict[str, Any]] = [
    # ── 1. AI Data Centers ───────────────────────────────────────────────────
    {
        "sector_id": "nvidia_ai_data_centers",
        "sector_name": "AI Data Centers",
        "sector_summary": (
            "Large-scale compute facilities deploying GPU clusters (H100, A100, GB200) "
            "for AI training and inference workloads. Operate as critical infrastructure "
            "for hyperscalers, cloud providers, and national AI programs."
        ),
        "relevance_to_nvidia": (
            "NVIDIA GPU sales to AI data center operators represent the largest and "
            "fastest-growing revenue segment. Adversary targeting of this sector directly "
            "impacts NVIDIA's most strategic customers and the perceived security posture "
            "of NVIDIA hardware and software (CUDA, NIM, NeMo)."
        ),
        "relevant_nvidia_products": [
            "H100/H200 SXM/PCIe GPUs", "GB200 NVL72 rack system",
            "NVLink Switch System", "CUDA Toolkit", "NVIDIA AI Enterprise",
            "NVIDIA NIM microservices", "NVIDIA NeMo", "Magnum IO"
        ],
        "crown_jewel_assets": [
            "GPU firmware and driver signing keys",
            "AI model weights and training checkpoints",
            "Proprietary training datasets",
            "Orchestration platform credentials (Kubernetes, Slurm)",
            "Hypervisor and BMC access credentials",
            "Network fabric configuration (InfiniBand, NVLink)",
            "Cooling and power management SCADA systems"
        ],
        "likely_threat_actors": [
            "Nation-state APTs (assessed: CN, RU, IR, KP) — IP theft and AI capability acquisition",
            "Ransomware groups — high-value targets with low downtime tolerance",
            "Insider threats — privileged access to sensitive compute and data",
            "Industrial espionage actors — competitor intelligence on AI R&D"
        ],
        "adversary_motivations": [
            "AI model and dataset theft for national AI programs",
            "Disruption of AI training pipelines (economic sabotage)",
            "Intelligence collection on AI capabilities and roadmaps",
            "Ransom / extortion leveraging operational dependency",
            "Long-term persistent access for future exploitation"
        ],
        "common_attack_surfaces": [
            "BMC/IPMI interfaces exposed on management network",
            "Kubernetes API server misconfigurations",
            "Publicly exposed model-serving endpoints",
            "Supply-chain compromise of AI software frameworks",
            "Privileged contractor and vendor remote access",
            "Misconfigured object storage (training data/checkpoints)"
        ],
        "likely_attack_paths": [
            "Spearphish data-center ops team → lateral to orchestration → exfil model weights",
            "Exploit exposed BMC → persistent firmware implant → long-term access",
            "Compromise CI/CD pipeline → inject malicious CUDA kernel → data poisoning",
            "Abuse cloud IAM misconfiguration → access GPU node pools → crypto-mining or data theft"
        ],
        "intelligence_requirements": [
            "IR-1: Threat actor TTPs targeting GPU cluster management interfaces",
            "IR-2: Known exploits against BMC/IPMI firmware in NVIDIA-adjacent hardware",
            "IR-3: Ransomware group interest in AI data center operators",
            "IR-4: Nation-state AI acquisition campaigns targeting NVIDIA customers",
            "IR-5: Insider threat indicators in high-clearance AI facilities"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Which threat actors are actively targeting NVIDIA GPU cluster environments? (Confidence: High)",
            "PIR-2: Are there active campaigns targeting CUDA or AI framework supply chains? (Confidence: Medium)",
            "PIR-3: What TTPs are used to exfiltrate large AI model weights at scale? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Anomalous outbound data transfers from GPU nodes during off-hours",
            "Unexpected BMC firmware version changes or failed integrity checks",
            "Reconnaissance against NVLink/InfiniBand management interfaces",
            "Credential stuffing activity on data center VPN or SSO portals",
            "Underground forum discussions about AI model theft techniques"
        ],
        "relevant_ioc_types": [
            "C2 IPs/domains associated with APT tooling",
            "File hashes of known BMC implants",
            "Malicious container images in public registries",
            "Anomalous DNS queries from orchestration nodes",
            "Indicators from AI framework supply-chain compromises"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Phishing, Valid Accounts, Exploit Public-Facing Application",
            "Execution: Command and Scripting Interpreter, Container Administration Command",
            "Persistence: Firmware Modification, Implant Container Image",
            "Exfiltration: Exfiltration Over Alternative Protocol, Transfer Data to Cloud Account",
            "Impact: Data Encrypted for Impact, Resource Hijacking"
        ],
        "mitre_attack_focus": [
            "T1190 Exploit Public-Facing Application",
            "T1078 Valid Accounts",
            "T1542 Pre-OS Boot (Firmware)",
            "T1613 Container and Resource Discovery",
            "T1537 Transfer Data to Cloud Account",
            "T1486 Data Encrypted for Impact"
        ],
        "vulnerability_intelligence_focus": [
            "BMC/IPMI firmware vulnerabilities in GPU server vendors",
            "CUDA runtime and driver privilege escalation",
            "Kubernetes container escape vulnerabilities",
            "AI framework deserialization issues (PyTorch, TensorFlow)",
            "NVFlash and GPU firmware update mechanisms"
        ],
        "supply_chain_risk_focus": [
            "Compromised AI framework packages (PyPI, conda)",
            "Malicious pre-trained model weights in public repositories",
            "Third-party data center hardware with counterfeit components",
            "Vendor remote-access tooling used during GPU deployments",
            "GPU driver distribution channels"
        ],
        "product_security_relevance": (
            "NVIDIA PSIRT should monitor for vulnerabilities in GPU firmware, driver signing "
            "infrastructure, and CUDA runtime that could be exploited in AI data center contexts. "
            "Secure boot chain integrity for H100/GB200 is a critical control."
        ),
        "telemetry_requirements": [
            "BMC/IPMI audit logs with integrity checks",
            "GPU driver telemetry (unexpected mode changes, errors)",
            "Kubernetes audit logs from orchestration layer",
            "Network flow data on management VLANs",
            "Object storage access logs (model checkpoints)",
            "EDR telemetry from orchestration control nodes"
        ],
        "hunting_opportunities": [
            "Hunt for unexpected processes on GPU orchestration nodes querying BMC interfaces",
            "Hunt for containers with excessive privileges or host namespace access",
            "Hunt for large scheduled data transfers outside normal training windows",
            "Hunt for Kubernetes service account token exfiltration patterns",
            "Hunt for AI framework imports from non-standard package indexes"
        ],
        "detection_engineering_opportunities": [
            "Alert on BMC firmware version change events",
            "Detect container images pulled from unregistered or external registries",
            "Alert on anomalous GPU utilization combined with outbound traffic spikes (crypto-mining)",
            "Detect Kubernetes ClusterRole/ClusterRoleBinding creation by non-admin accounts",
            "Alert on mass file reads from model checkpoint directories"
        ],
        "mitigation_recommendations": [
            "Isolate BMC/IPMI interfaces on dedicated management VLAN with strict ACLs",
            "Enable NVIDIA Secure Boot for GPU firmware",
            "Enforce Kubernetes RBAC with least privilege and audit all API calls",
            "Implement model registry with cryptographic signing for all artifacts",
            "Require MFA and just-in-time access for all privileged operator accounts"
        ],
        "engineering_follow_up_actions": [
            "Evaluate NVIDIA GPU attestation APIs for continuous integrity verification",
            "Integrate GPU telemetry into SIEM for anomaly detection baselines",
            "Review and harden container image build pipelines",
            "Conduct red team exercise focused on GPU cluster lateral movement"
        ],
        "psirt_relevance": (
            "High. Vulnerabilities in GPU firmware, driver update mechanisms, or CUDA runtime "
            "components that affect AI data center deployments should be prioritized by PSIRT "
            "for rapid patching and coordinated disclosure with major data center operators."
        ),
        "customer_risk_considerations": [
            "Customers running AI training workloads have low tolerance for downtime — prioritize availability",
            "Model IP loss has direct business impact; encryption at rest and in transit is essential",
            "Compliance requirements (SOC2, ISO27001) apply to many AI data center operators",
            "Multi-tenant GPU environments require strong workload isolation guarantees"
        ],
        "executive_summary_points": [
            "AI data centers are high-value targets for nation-state actors seeking AI capability parity",
            "GPU firmware and orchestration layer represent critical, under-monitored attack surfaces",
            "Model weight exfiltration is a novel, high-impact threat requiring dedicated detection",
            "NVIDIA's market position makes it a focal point for adversary reconnaissance"
        ],
        "analyst_notes": (
            "Assessment based on public threat reporting, ATT&CK framework analysis, and analogy "
            "to prior campaigns against HPC and cloud environments. No confirmed incidents attributed "
            "to specific actors in NVIDIA AI data center environments as of this writing. "
            "Source requirements should be validated against current threat reporting."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "CISA advisories on critical infrastructure threats",
            "Vendor security bulletins (NVIDIA PSIRT, IPMI vendors)",
            "Threat intelligence from ISAC sharing (IT-ISAC, SEMI ISAC)",
            "Public APT reporting from major threat intelligence vendors",
            "CVE database: GPU firmware, BMC, Kubernetes components"
        ],
        "pack_source": "nvidia",
    },
    # ── 2. Accelerated Computing ─────────────────────────────────────────────
    {
        "sector_id": "nvidia_accelerated_computing",
        "sector_name": "Accelerated Computing (GPU/CUDA Ecosystem)",
        "sector_summary": (
            "The broad ecosystem of GPU-accelerated compute workloads including deep learning, "
            "scientific simulation, data analytics, and rendering. Encompasses NVIDIA CUDA, "
            "libraries (cuDNN, cuBLAS, RAPIDS), and developer toolchain."
        ),
        "relevance_to_nvidia": (
            "CUDA is NVIDIA's core competitive moat. Threats to the CUDA ecosystem, developer "
            "toolchain, or GPU driver integrity directly threaten NVIDIA's platform dominance "
            "and the security of all downstream applications."
        ),
        "relevant_nvidia_products": [
            "CUDA Toolkit", "cuDNN", "cuBLAS", "RAPIDS", "Nsight profilers",
            "GPU drivers (Windows/Linux)", "TensorRT", "NCCL"
        ],
        "crown_jewel_assets": [
            "CUDA compiler source code and IP",
            "GPU microarchitecture documentation",
            "Driver signing certificates",
            "Developer ecosystem telemetry and usage data",
            "Library source code (cuDNN, TensorRT)"
        ],
        "likely_threat_actors": [
            "Nation-state actors seeking GPU microarchitecture IP",
            "Competitors conducting industrial espionage on CUDA optimization techniques",
            "Cybercriminals targeting driver signing infrastructure for malware distribution",
            "Researchers discovering CUDA privilege escalation vulnerabilities"
        ],
        "adversary_motivations": [
            "Acquisition of GPU microarchitecture and CUDA compiler IP",
            "Driver signing certificate theft for malware signing",
            "Discovery of exploitable vulnerabilities in driver layer",
            "Competitive intelligence on CUDA roadmap"
        ],
        "common_attack_surfaces": [
            "NVIDIA developer portal and SDK download infrastructure",
            "GPU driver update mechanism (Windows Update, official installers)",
            "Open-source CUDA ecosystem repositories (GitHub)",
            "Developer workstations with GPU driver access",
            "CI/CD pipelines building CUDA-accelerated software"
        ],
        "likely_attack_paths": [
            "Compromise driver signing infrastructure → distribute malicious driver updates",
            "Exploit CUDA driver privilege escalation → kernel-level access on developer machines",
            "Backdoor RAPIDS or cuDF package in conda/PyPI → persistent access to data science workloads",
            "Social engineer NVIDIA developer → exfil internal CUDA documentation"
        ],
        "intelligence_requirements": [
            "IR-1: Known CUDA driver privilege escalation vulnerabilities",
            "IR-2: Threat actors targeting GPU driver signing infrastructure",
            "IR-3: Malicious packages mimicking CUDA ecosystem libraries",
            "IR-4: Underground market for GPU microarchitecture documentation"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active campaigns targeting NVIDIA driver update infrastructure? (Confidence: Medium)",
            "PIR-2: Are CUDA-ecosystem packages (PyPI/conda) being targeted for typosquatting? (Confidence: High)"
        ],
        "early_warning_indicators": [
            "Typosquatted packages in PyPI/conda mimicking CUDA libraries",
            "Reported CUDA driver privilege escalation PoCs in public forums",
            "Anomalous downloads from NVIDIA developer portal",
            "Unusual CUDA driver signing certificate usage"
        ],
        "relevant_ioc_types": [
            "Hashes of malicious GPU driver installers",
            "Typosquatted package names in PyPI/conda",
            "Domains mimicking NVIDIA developer resources",
            "Code signing certificates not matching NVIDIA's known cert chain"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Supply Chain Compromise",
            "Privilege Escalation: Exploitation for Privilege Escalation (driver layer)",
            "Defense Evasion: Signed Binary Proxy Execution",
            "Collection: Data from Local System (GPU-resident data)"
        ],
        "mitre_attack_focus": [
            "T1195 Supply Chain Compromise",
            "T1068 Exploitation for Privilege Escalation",
            "T1553 Subvert Trust Controls",
            "T1588 Obtain Capabilities"
        ],
        "vulnerability_intelligence_focus": [
            "CUDA driver kernel-mode vulnerabilities (privilege escalation)",
            "GPU memory isolation bypass techniques",
            "CUDA JIT compiler exploits",
            "Installer package integrity verification gaps"
        ],
        "supply_chain_risk_focus": [
            "CUDA library distribution via PyPI and conda channels",
            "Third-party CUDA-accelerated ML framework dependencies",
            "GPU driver bundled with OEM system software",
            "CUDA samples and tutorials from unofficial sources"
        ],
        "product_security_relevance": (
            "NVIDIA PSIRT is directly responsible for CUDA driver CVEs. Privilege escalation "
            "vulnerabilities in GPU drivers are high-severity and widely exploited. "
            "Rapid patch development and coordinated disclosure processes are essential."
        ),
        "telemetry_requirements": [
            "GPU driver installation event logs",
            "Package installation telemetry from developer environments",
            "Code signing validation logs",
            "NVIDIA developer portal access logs"
        ],
        "hunting_opportunities": [
            "Hunt for unsigned or anomalously signed GPU driver modules loaded in kernel",
            "Hunt for CUDA processes making unexpected syscalls or kernel memory accesses",
            "Hunt for packages installed from non-official NVIDIA channels on critical systems"
        ],
        "detection_engineering_opportunities": [
            "Alert on GPU driver version downgrades (potential rollback attack)",
            "Detect kernel modules loaded that are not in the NVIDIA-signed allowlist",
            "Alert on CUDA-related processes with anomalous child process spawning"
        ],
        "mitigation_recommendations": [
            "Enforce driver installation only from official NVIDIA sources with hash verification",
            "Implement application allowlisting for CUDA-enabled environments",
            "Monitor PyPI/conda environments for unexpected CUDA-related package updates",
            "Enable Secure Boot to prevent unsigned driver loading"
        ],
        "engineering_follow_up_actions": [
            "Audit all CUDA library dependencies in internal toolchains",
            "Evaluate Software Bill of Materials (SBOM) for CUDA-accelerated products",
            "Establish vulnerability intelligence feed for CUDA CVEs"
        ],
        "psirt_relevance": (
            "Core PSIRT domain. All GPU driver CVEs fall under NVIDIA PSIRT scope. "
            "Priority: privilege escalation in kernel-mode drivers has highest blast radius."
        ),
        "customer_risk_considerations": [
            "Enterprise customers deploying CUDA in regulated environments need rapid patch SLAs",
            "Academic and research institutions often run outdated drivers — outreach needed",
            "Consumer gaming GPU users are a large attack surface for driver-level malware"
        ],
        "executive_summary_points": [
            "CUDA driver vulnerabilities represent a high-severity, broadly-exploitable attack class",
            "Supply chain risks in the CUDA software ecosystem are growing with AI adoption",
            "Driver signing infrastructure is a high-value target for malware distribution campaigns"
        ],
        "analyst_notes": (
            "NVIDIA regularly publishes PSIRT advisories for GPU driver CVEs. "
            "Historical precedent includes multiple privilege escalation CVEs patched in production drivers. "
            "Confidence levels are based on public vulnerability history and general supply-chain threat trends."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "NVIDIA PSIRT advisories (nvd.nist.gov filter: vendor=NVIDIA)",
            "CVE database: CUDA driver, display driver",
            "Package repository security monitoring (PyPI, conda-forge)",
            "Public PoC repositories (GitHub, ExploitDB)"
        ],
        "pack_source": "nvidia",
    },
    # ── 3. HPC / Supercomputing ───────────────────────────────────────────────
    {
        "sector_id": "nvidia_hpc_supercomputing",
        "sector_name": "HPC & Supercomputing",
        "sector_summary": (
            "High-performance computing environments at national labs, universities, and research "
            "institutions deploying NVIDIA GPUs (A100, H100) for scientific simulation, climate "
            "modeling, genomics, and defense-related workloads."
        ),
        "relevance_to_nvidia": (
            "NVIDIA dominates the HPC accelerator market. Nation-state adversaries target HPC "
            "clusters that use NVIDIA GPUs for both IP theft and to understand the operational "
            "limits of NVIDIA hardware in classified and sensitive programs."
        ),
        "relevant_nvidia_products": [
            "A100/H100 HPC GPUs", "NVLink", "InfiniBand (Mellanox/NVIDIA)",
            "NCCL", "CUDA Toolkit", "HPC SDK", "Magnum IO"
        ],
        "crown_jewel_assets": [
            "Classified and sensitive research data on HPC nodes",
            "Simulation code and algorithms",
            "Export-controlled computational research",
            "HPC cluster job scheduler configurations",
            "InfiniBand fabric management credentials"
        ],
        "likely_threat_actors": [
            "Nation-state APTs targeting defense and dual-use research (assessed: CN, RU)",
            "Academic espionage actors targeting research IP",
            "Ransomware groups targeting high-uptime environments for extortion"
        ],
        "adversary_motivations": [
            "Theft of defense-relevant scientific research",
            "Acquisition of export-controlled HPC algorithms",
            "Long-term persistent access to ongoing research programs",
            "Disruption of national lab compute capacity"
        ],
        "common_attack_surfaces": [
            "HPC cluster login nodes exposed to academic networks",
            "SSH key management for researcher accounts",
            "Shared file systems (Lustre, GPFS) with broad access",
            "Job scheduler APIs (Slurm, PBS)",
            "InfiniBand management software"
        ],
        "likely_attack_paths": [
            "Compromise researcher account via phishing → pivot to HPC login node → access shared datasets",
            "Exploit Slurm job scheduler vulnerability → execute arbitrary jobs → access GPU nodes",
            "Compromise InfiniBand subnet manager → traffic intercept on high-speed fabric"
        ],
        "intelligence_requirements": [
            "IR-1: Active APT campaigns targeting HPC environments using NVIDIA GPUs",
            "IR-2: Slurm and PBS scheduler vulnerabilities being exploited in the wild",
            "IR-3: Ransomware groups specifically targeting HPC/national lab infrastructure"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active nation-state campaigns against NVIDIA GPU-equipped HPC clusters? (Confidence: Medium)",
            "PIR-2: What are the current TTPs for initial access into HPC login nodes? (Confidence: High)"
        ],
        "early_warning_indicators": [
            "Anomalous job submissions to HPC scheduler from compromised accounts",
            "Unusual outbound data transfers from shared file systems",
            "SSH brute-force activity against HPC login nodes",
            "Underground forum interest in HPC cluster access credentials"
        ],
        "relevant_ioc_types": [
            "Malicious SSH keys installed on HPC nodes",
            "Known APT C2 domains resolving from HPC cluster egress IPs",
            "Malicious batch job scripts",
            "Anomalous Slurm API calls"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Valid Accounts, Phishing",
            "Lateral Movement: Remote Services (SSH)",
            "Collection: Data from Shared Drive",
            "Exfiltration: Exfiltration Over Alternative Protocol"
        ],
        "mitre_attack_focus": [
            "T1078 Valid Accounts",
            "T1021 Remote Services",
            "T1039 Data from Network Shared Drive",
            "T1048 Exfiltration Over Alternative Protocol"
        ],
        "vulnerability_intelligence_focus": [
            "Slurm and PBS job scheduler CVEs",
            "OpenMPI and MPI library vulnerabilities",
            "InfiniBand subnet manager security issues",
            "CUDA multi-process service (MPS) isolation gaps"
        ],
        "supply_chain_risk_focus": [
            "Scientific software supply chain (Spack, EasyBuild packages)",
            "Research software with unverified provenance",
            "Third-party HPC management software"
        ],
        "product_security_relevance": (
            "NVIDIA InfiniBand (Mellanox) and GPU driver CVEs are relevant to HPC environments. "
            "PSIRT should coordinate with major HPC centers on vulnerability disclosure timelines "
            "given their patching constraints."
        ),
        "telemetry_requirements": [
            "Slurm/PBS job submission logs",
            "SSH authentication logs on login nodes",
            "Network flow data on HPC fabric management interfaces",
            "File access audit logs on shared storage"
        ],
        "hunting_opportunities": [
            "Hunt for GPU jobs submitting unusual data exfiltration patterns post-compute",
            "Hunt for SSH keys installed outside normal provisioning workflows",
            "Hunt for Slurm jobs with unusual resource requests or external data staging"
        ],
        "detection_engineering_opportunities": [
            "Alert on Slurm job submissions from newly compromised or inactive accounts",
            "Detect data transfers to external IPs from HPC compute nodes",
            "Alert on InfiniBand subnet manager configuration changes"
        ],
        "mitigation_recommendations": [
            "Enforce MFA for HPC cluster login nodes",
            "Implement strict egress filtering on compute nodes",
            "Audit Slurm job scheduler permissions regularly",
            "Segment InfiniBand management traffic from user-accessible networks"
        ],
        "engineering_follow_up_actions": [
            "Engage NVIDIA channel managers at key national labs on security posture",
            "Develop InfiniBand management security guidance documentation"
        ],
        "psirt_relevance": (
            "Medium. HPC operators are large InfiniBand (Mellanox) and GPU driver consumers. "
            "CVEs in HPC-specific NVIDIA software (NCCL, HPC SDK) warrant coordinated disclosure "
            "with major HPC center security teams."
        ),
        "customer_risk_considerations": [
            "HPC operators have strict maintenance windows — coordinate vulnerability disclosure accordingly",
            "Export-controlled research on GPU clusters creates legal and compliance risk if exfiltrated",
            "Many HPC facilities are government-funded and subject to national security breach reporting"
        ],
        "executive_summary_points": [
            "HPC environments using NVIDIA GPUs are persistent targets for nation-state IP theft",
            "Slurm/PBS scheduler vulnerabilities represent an under-monitored attack vector",
            "NVIDIA InfiniBand fabric is integral to HPC — its security posture matters"
        ],
        "analyst_notes": (
            "Public reporting confirms nation-state targeting of HPC facilities (e.g., 2020 European HPC incident). "
            "NVIDIA GPU-specific exploitation techniques in HPC context are not widely documented publicly."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "CISA/FBI advisories on academic and research targeting",
            "HPC security community publications (SC conference proceedings)",
            "CVE database: Slurm, OpenMPI, InfiniBand management software",
            "NVIDIA PSIRT advisories for HPC-relevant components"
        ],
        "pack_source": "nvidia",
    },
    # ── 4. AI Networking Fabric ───────────────────────────────────────────────
    {
        "sector_id": "nvidia_ai_networking_fabric",
        "sector_name": "AI Networking Fabric (InfiniBand / NVLink / Spectrum-X)",
        "sector_summary": (
            "High-speed interconnect infrastructure connecting GPU nodes within AI data centers. "
            "Includes NVIDIA InfiniBand (HDR/NDR), NVLink Switch, and Spectrum-X Ethernet solutions "
            "for AI-optimized networking."
        ),
        "relevance_to_nvidia": (
            "NVIDIA's networking portfolio (Mellanox acquisition) is critical to AI data center "
            "performance. Network fabric vulnerabilities can compromise entire GPU cluster security "
            "and are a single point of failure for major AI training runs."
        ),
        "relevant_nvidia_products": [
            "InfiniBand HDR/NDR switches", "ConnectX-7/8 NICs",
            "NVLink Switch System", "Spectrum-X Ethernet switch",
            "UFM (Unified Fabric Manager)", "MLNX_OFED drivers"
        ],
        "crown_jewel_assets": [
            "UFM admin credentials",
            "InfiniBand subnet manager private keys",
            "NVLink topology and routing tables",
            "Network fabric configuration databases",
            "RDMA traffic traversing fabric (unencrypted model data)"
        ],
        "likely_threat_actors": [
            "Nation-state APTs targeting AI training fabric for traffic interception",
            "Advanced persistent actors with hardware implant capabilities",
            "Insiders with network management access"
        ],
        "adversary_motivations": [
            "Passive interception of RDMA traffic carrying model weights",
            "Disruption of AI training via fabric partition attacks",
            "Long-term persistent access via firmware implant in switch ASICs",
            "Intelligence collection on cluster topology for future operations"
        ],
        "common_attack_surfaces": [
            "UFM web interface and API (exposed on management network)",
            "InfiniBand subnet manager (OpenSM) configuration interface",
            "MLNX_OFED driver installation and update mechanism",
            "Out-of-band management (IPMI) on InfiniBand switch nodes",
            "RDMA traffic without encryption (high bandwidth, often unencrypted)"
        ],
        "likely_attack_paths": [
            "Exploit UFM API vulnerability → reconfigure fabric partitions → isolate GPU nodes",
            "Compromise subnet manager host → inject malicious routing tables → MITM RDMA traffic",
            "Firmware implant in ConnectX NIC → persistent access and traffic visibility",
            "Abuse MLNX_OFED update channel → deploy malicious NIC firmware"
        ],
        "intelligence_requirements": [
            "IR-1: Known CVEs in UFM, OpenSM, or MLNX_OFED",
            "IR-2: Threat actor capabilities for RDMA traffic interception at scale",
            "IR-3: Firmware implant techniques applicable to ConnectX or InfiniBand switches",
            "IR-4: Reports of AI training fabric disruption incidents"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active exploits for UFM or InfiniBand management interfaces? (Confidence: Medium)",
            "PIR-2: Is RDMA traffic encryption adoption rate sufficient to mitigate interception? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Unexpected UFM configuration changes outside change-window",
            "Unusual subnet manager re-election events",
            "MLNX_OFED driver updates from non-official sources",
            "Anomalous RDMA traffic patterns on fabric monitoring"
        ],
        "relevant_ioc_types": [
            "UFM API authentication anomalies",
            "Malicious MLNX_OFED package hashes",
            "Unexpected InfiniBand partition configuration changes",
            "Out-of-band management access from unusual IPs"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Exploit Public-Facing Application (UFM)",
            "Persistence: Firmware Modification (NIC/switch firmware)",
            "Collection: Network Sniffing (RDMA)",
            "Impact: Network Denial of Service, Service Stop"
        ],
        "mitre_attack_focus": [
            "T1190 Exploit Public-Facing Application",
            "T1542 Pre-OS Boot (Firmware)",
            "T1040 Network Sniffing",
            "T1498 Network Denial of Service"
        ],
        "vulnerability_intelligence_focus": [
            "UFM API authentication and authorization vulnerabilities",
            "InfiniBand subnet manager OpenSM security issues",
            "ConnectX NIC firmware update verification gaps",
            "MLNX_OFED driver kernel-mode vulnerabilities"
        ],
        "supply_chain_risk_focus": [
            "MLNX_OFED distribution integrity",
            "Third-party InfiniBand management software",
            "NIC firmware signing and verification chain"
        ],
        "product_security_relevance": (
            "NVIDIA PSIRT covers vulnerabilities in UFM, MLNX_OFED, and ConnectX firmware. "
            "InfiniBand management plane security is critical for all AI data center deployments. "
            "RDMA encryption guidance should be proactively published."
        ),
        "telemetry_requirements": [
            "UFM audit and access logs",
            "InfiniBand fabric event logs (partition changes, SM events)",
            "ConnectX NIC firmware version inventory",
            "Out-of-band management authentication logs"
        ],
        "hunting_opportunities": [
            "Hunt for UFM API calls outside normal operational hours",
            "Hunt for unauthorized subnet manager instances on the fabric",
            "Hunt for NIC firmware versions not matching approved baseline"
        ],
        "detection_engineering_opportunities": [
            "Alert on UFM configuration exports or API key creation",
            "Detect subnet manager re-election not correlated with maintenance events",
            "Alert on MLNX_OFED driver installs from non-official package mirrors"
        ],
        "mitigation_recommendations": [
            "Restrict UFM API access to dedicated management jump hosts with MFA",
            "Enable RoCE (RDMA over Converged Ethernet) with encryption where supported",
            "Implement firmware inventory and integrity monitoring for all ConnectX NICs",
            "Use InfiniBand partitioning to isolate different workload tiers"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA security hardening guide for UFM deployments",
            "Evaluate InfiniBand fabric encryption roadmap for AI workloads",
            "Conduct security audit of OpenSM integration with UFM"
        ],
        "psirt_relevance": (
            "High. UFM, MLNX_OFED, and ConnectX firmware are all NVIDIA PSIRT scope. "
            "Management plane vulnerabilities in fabric infrastructure warrant critical priority."
        ),
        "customer_risk_considerations": [
            "Large AI training operators are highly sensitive to fabric disruption — even brief outages cost millions",
            "Many customers do not encrypt RDMA traffic due to performance overhead — education needed",
            "Fabric misconfiguration incidents may not be detected without dedicated monitoring"
        ],
        "executive_summary_points": [
            "AI networking fabric is a single point of failure for GPU cluster security",
            "RDMA traffic is typically unencrypted, creating data interception risk at scale",
            "UFM and subnet manager represent concentrated management plane attack surface"
        ],
        "analyst_notes": (
            "No publicly confirmed exploitation of UFM or InfiniBand management plane in AI data center context. "
            "Threat model is based on analogous attacks against network management infrastructure and "
            "the unique value of RDMA traffic in AI training environments."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "NVIDIA PSIRT advisories: UFM, MLNX_OFED, ConnectX",
            "InfiniBand Trade Association security publications",
            "Network management plane attack research (academic and vendor)",
            "CVE database: OpenSM, MLNX_OFED"
        ],
        "pack_source": "nvidia",
    },
    # ── 5. DPU / SmartNIC ─────────────────────────────────────────────────────
    {
        "sector_id": "nvidia_dpu_smartnic",
        "sector_name": "DPU & SmartNIC (BlueField)",
        "sector_summary": (
            "NVIDIA BlueField DPUs (Data Processing Units) deployed in cloud and enterprise data centers "
            "for network offload, security enforcement, and infrastructure isolation. "
            "BlueField-3 is used for zero-trust infrastructure and secure multi-tenancy."
        ),
        "relevance_to_nvidia": (
            "BlueField DPUs represent a strategic security product line. Vulnerabilities or "
            "exploitation of DPUs would undermine zero-trust infrastructure claims and damage "
            "NVIDIA's credibility in security-conscious cloud and enterprise markets."
        ),
        "relevant_nvidia_products": [
            "BlueField-2/3 DPU", "DOCA SDK", "DOCA Security Services",
            "ConnectX-7 SmartNIC", "NVIDIA Base Command Platform (DPU integration)"
        ],
        "crown_jewel_assets": [
            "DPU firmware and signing keys",
            "DOCA application code running in DPU ARM cores",
            "TLS termination keys handled by DPU",
            "Security policy enforcement tables in DPU",
            "Attestation keys for zero-trust identity"
        ],
        "likely_threat_actors": [
            "Nation-state actors with hardware implant capabilities",
            "Advanced persistent actors targeting cloud provider infrastructure",
            "Security researchers finding DPU firmware vulnerabilities"
        ],
        "adversary_motivations": [
            "Persistent firmware implant below hypervisor visibility",
            "Bypass of host-based security controls via DPU offload path",
            "Access to TLS keys or encrypted traffic processed by DPU",
            "Disable security enforcement functions (firewall, IDS offload)"
        ],
        "common_attack_surfaces": [
            "DPU management interface (rshim, BMC integration)",
            "DOCA application update and deployment mechanism",
            "BlueField firmware update (BFB) file distribution",
            "Host-to-DPU communication channel (virtio, PCIe BAR)",
            "DOCA SDK libraries used in customer applications"
        ],
        "likely_attack_paths": [
            "Malicious BFB firmware image → persistent implant in DPU ARM cores below host OS",
            "Exploit host-to-DPU communication vulnerability → escape from tenant to DPU security plane",
            "Compromise DOCA application → disable or subvert security enforcement on DPU",
            "Supply chain attack on BFB distribution → compromise at scale across cloud deployments"
        ],
        "intelligence_requirements": [
            "IR-1: Known vulnerabilities in BlueField firmware or DOCA SDK",
            "IR-2: Research into DPU-level persistent implant techniques",
            "IR-3: Cloud provider deployments using BlueField for security enforcement",
            "IR-4: Supply chain risks in BFB firmware distribution"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there public PoCs for BlueField firmware vulnerabilities? (Confidence: Low)",
            "PIR-2: Is BlueField being considered for classified infrastructure deployments? (Confidence: Unknown)"
        ],
        "early_warning_indicators": [
            "BlueField firmware version mismatches across fleet",
            "Unexpected DOCA application deployments",
            "BFB files with hashes not matching official NVIDIA releases",
            "Security research publications targeting DPU architecture"
        ],
        "relevant_ioc_types": [
            "BFB firmware file hashes (malicious versions)",
            "DOCA application binaries with unexpected signatures",
            "Anomalous host-to-DPU PCIe traffic patterns"
        ],
        "relevant_ttp_categories": [
            "Persistence: Firmware Modification",
            "Defense Evasion: Rootkit (below hypervisor)",
            "Initial Access: Supply Chain Compromise",
            "Impact: Inhibit System Recovery"
        ],
        "mitre_attack_focus": [
            "T1542 Pre-OS Boot (Firmware)",
            "T1014 Rootkit",
            "T1195 Supply Chain Compromise",
            "T1490 Inhibit System Recovery"
        ],
        "vulnerability_intelligence_focus": [
            "BlueField ARM core firmware vulnerabilities",
            "DOCA SDK memory safety issues",
            "PCIe DMA attack vectors through BlueField",
            "BFB secure boot bypass techniques"
        ],
        "supply_chain_risk_focus": [
            "BFB firmware image distribution and integrity verification",
            "DOCA SDK open-source dependencies",
            "Third-party DOCA applications in marketplace"
        ],
        "product_security_relevance": (
            "Critical for NVIDIA PSIRT. BlueField is marketed as a security product. "
            "Any firmware vulnerability has cascading trust implications for all deployments "
            "using BlueField for zero-trust enforcement or security offload."
        ),
        "telemetry_requirements": [
            "BlueField firmware inventory and version monitoring across fleet",
            "DOCA application deployment audit logs",
            "BFB update event logs",
            "Host-to-DPU communication anomaly detection"
        ],
        "hunting_opportunities": [
            "Hunt for BlueField units with firmware versions not matching the deployment baseline",
            "Hunt for DOCA applications not in the approved catalog",
            "Hunt for anomalous BFB file transfers in data center networks"
        ],
        "detection_engineering_opportunities": [
            "Alert on BlueField firmware updates outside approved maintenance windows",
            "Detect DOCA application crash loops that could indicate exploitation attempts",
            "Alert on BFB files with hashes not matching NVIDIA-published checksums"
        ],
        "mitigation_recommendations": [
            "Enforce BFB firmware integrity verification using NVIDIA Secure Boot",
            "Restrict DOCA application deployment to signed, approved images",
            "Monitor BlueField management interfaces for unauthorized access",
            "Implement attestation for DPU identity in zero-trust deployments"
        ],
        "engineering_follow_up_actions": [
            "Publish BlueField security hardening guide for cloud and enterprise deployments",
            "Evaluate DOCA application signing and attestation framework",
            "Establish BFB firmware integrity verification service for large deployments"
        ],
        "psirt_relevance": (
            "Critical. BlueField/DPU is a security-positioned product. Vulnerabilities here "
            "have high reputational impact beyond technical severity. Proactive security research "
            "engagement and rapid PSIRT response are essential."
        ),
        "customer_risk_considerations": [
            "Cloud providers using BlueField for tenant isolation face cascading risk if DPU is compromised",
            "Zero-trust deployments relying on DPU enforcement lose security guarantees if implanted",
            "Financial and healthcare customers may have compliance implications from DPU compromise"
        ],
        "executive_summary_points": [
            "BlueField DPU compromise can bypass all host-based security controls",
            "DPU firmware is a high-value target due to persistence below hypervisor visibility",
            "Supply chain integrity of BFB firmware is a critical security control"
        ],
        "analyst_notes": (
            "DPU-level persistent implants are a theoretically significant threat; no confirmed "
            "public incidents in production BlueField deployments are known at this writing. "
            "Threat model is based on analogous UEFI/BMC firmware implant research."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "NVIDIA PSIRT advisories: BlueField, DOCA",
            "Security research on PCIe DMA attacks and DPU architecture",
            "CVE database: DOCA SDK, BlueField firmware",
            "Cloud provider security bulletins mentioning SmartNIC/DPU"
        ],
        "pack_source": "nvidia",
    },
    # ── 6. Cloud / Hyperscale ─────────────────────────────────────────────────
    {
        "sector_id": "nvidia_cloud_hyperscale",
        "sector_name": "Cloud & Hyperscale Providers",
        "sector_summary": (
            "Major cloud and hyperscale operators (public cloud providers, CDN operators, "
            "co-location providers) deploying NVIDIA GPU instances at massive scale for IaaS "
            "GPU compute, AI inference APIs, and managed AI services."
        ),
        "relevance_to_nvidia": (
            "Hyperscalers are among NVIDIA's largest customers. Their security practices "
            "define baseline security standards for GPU deployments. Incidents involving "
            "NVIDIA hardware at hyperscalers have outsized reputational impact."
        ),
        "relevant_nvidia_products": [
            "H100/H200/A100 PCIe/SXM GPUs", "GB200 NVL72",
            "ConnectX NICs", "BlueField DPUs",
            "NVIDIA AI Enterprise", "NIM microservices",
            "CUDA, TensorRT, Triton Inference Server"
        ],
        "crown_jewel_assets": [
            "Multi-tenant GPU workload isolation mechanisms",
            "Cloud provider IAM systems governing GPU access",
            "Hyperscaler AI training infrastructure",
            "GPU hardware allocation and scheduling systems",
            "Customer AI workload data on shared GPU nodes"
        ],
        "likely_threat_actors": [
            "Nation-state APTs targeting cloud infrastructure for mass intelligence collection",
            "Ransomware groups targeting cloud management planes",
            "Cryptomining operators abusing cloud GPU provisioning",
            "Insider threats at hyperscaler organizations"
        ],
        "adversary_motivations": [
            "Multi-tenant data exfiltration via GPU memory side-channel",
            "Free GPU compute via credential theft or misconfiguration abuse",
            "Disruption of cloud AI services for economic impact",
            "Intelligence collection on cloud customer AI workloads"
        ],
        "common_attack_surfaces": [
            "GPU instance provisioning APIs (IAM misconfigurations)",
            "Shared GPU node multi-tenant isolation (GPU memory, PCIe)",
            "Cloud management plane APIs",
            "NVIDIA drivers in virtualized environments",
            "Triton Inference Server and model serving endpoints"
        ],
        "likely_attack_paths": [
            "Exploit cloud IAM misconfiguration → provision GPU instances for crypto-mining",
            "GPU memory side-channel attack → leak neighboring tenant model weights",
            "Compromise Triton Inference Server → manipulate inference outputs or exfil models",
            "Exploit vGPU driver → escape guest VM to host GPU context"
        ],
        "intelligence_requirements": [
            "IR-1: GPU memory isolation vulnerabilities in virtualized/multi-tenant environments",
            "IR-2: Cryptomining campaigns targeting cloud GPU provisioning APIs",
            "IR-3: vGPU driver vulnerabilities enabling hypervisor escapes",
            "IR-4: Triton Inference Server known attack patterns"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active GPU memory side-channel attacks in cloud environments? (Confidence: Medium)",
            "PIR-2: Are cloud GPU APIs being systematically abused for cryptomining? (Confidence: High)"
        ],
        "early_warning_indicators": [
            "Mass GPU instance provisioning from new or low-reputation cloud accounts",
            "Academic publications on GPU memory isolation bypass",
            "Cloud provider security bulletins mentioning GPU isolation",
            "Cryptomining pool traffic from cloud GPU IP ranges"
        ],
        "relevant_ioc_types": [
            "Cryptomining pool connection indicators from GPU instances",
            "Malicious cloud IAM credentials used for GPU provisioning",
            "Model-serving endpoint abuse patterns"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Valid Accounts (cloud IAM)",
            "Execution: Resource Hijacking (GPU crypto-mining)",
            "Collection: Data from Cloud Storage, Side-Channel",
            "Privilege Escalation: Exploitation for Privilege Escalation (vGPU)"
        ],
        "mitre_attack_focus": [
            "T1078 Valid Accounts",
            "T1496 Resource Hijacking",
            "T1530 Data from Cloud Storage Object",
            "T1068 Exploitation for Privilege Escalation"
        ],
        "vulnerability_intelligence_focus": [
            "vGPU driver isolation vulnerabilities",
            "NVIDIA GPU memory scrubbing between tenant workloads",
            "Triton Inference Server vulnerabilities",
            "Cloud GPU instance metadata service abuse"
        ],
        "supply_chain_risk_focus": [
            "Pre-built GPU VM images in cloud marketplaces",
            "Third-party AI inference APIs using NVIDIA hardware",
            "Cloud-native AI service dependencies"
        ],
        "product_security_relevance": (
            "NVIDIA PSIRT must monitor vGPU and CUDA virtualization vulnerabilities closely. "
            "GPU memory isolation between cloud tenants is a core security property of vGPU. "
            "Triton Inference Server is open-source and PSIRT-adjacent."
        ),
        "telemetry_requirements": [
            "Cloud IAM audit logs for GPU resource provisioning",
            "GPU utilization telemetry (detect cryptomining patterns)",
            "vGPU driver error logs indicating isolation failures",
            "Triton Inference Server access and error logs"
        ],
        "hunting_opportunities": [
            "Hunt for GPU instances with unexpected outbound connections to mining pools",
            "Hunt for vGPU driver versions with known isolation CVEs in production",
            "Hunt for overprivileged cloud service accounts with GPU provisioning access"
        ],
        "detection_engineering_opportunities": [
            "Alert on GPU instance creation velocity exceeding baseline (mass provisioning)",
            "Detect cryptomining network signatures from GPU compute instances",
            "Alert on Triton model repository changes not correlated with deployment events"
        ],
        "mitigation_recommendations": [
            "Enforce GPU memory scrubbing between tenant workloads (verify NVIDIA driver settings)",
            "Implement cloud IAM guardrails on GPU instance provisioning quotas",
            "Keep vGPU drivers patched on a regular cadence",
            "Restrict Triton Inference Server to internal networks with authentication"
        ],
        "engineering_follow_up_actions": [
            "Publish GPU multi-tenancy security guidance for cloud operators",
            "Engage major cloud providers on vGPU security partnership",
            "Evaluate NVIDIA Confidential Computing for sensitive cloud AI workloads"
        ],
        "psirt_relevance": (
            "Medium-High. vGPU driver CVEs are PSIRT scope. Cloud GPU abuse (cryptomining) "
            "is a business risk but not directly PSIRT. Triton Inference Server vulnerabilities "
            "should be tracked by PSIRT."
        ),
        "customer_risk_considerations": [
            "Multi-tenant isolation is a contractual guarantee for cloud providers — GPU isolation failures create liability",
            "Cloud GPU credential theft leads to significant financial exposure",
            "Model IP leakage via side-channel could affect AI startup customers"
        ],
        "executive_summary_points": [
            "Cloud GPU environments face cryptomining and tenant-isolation threats at scale",
            "vGPU driver vulnerabilities can break multi-tenant isolation guarantees",
            "AI model serving endpoints are increasingly targeted as AI adoption grows"
        ],
        "analyst_notes": (
            "Cryptomining abuse of cloud GPU APIs is a confirmed, active threat. "
            "GPU memory side-channel research is published but no confirmed exploitation in production reported. "
            "vGPU driver CVEs have been issued by NVIDIA PSIRT previously."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "Cloud provider security bulletins (AWS, Azure, GCP security advisories)",
            "NVIDIA PSIRT advisories: vGPU drivers, Triton",
            "Academic research on GPU memory side-channels",
            "Cryptomining threat intelligence feeds"
        ],
        "pack_source": "nvidia",
    },
    # ── 7. Semiconductor Supply Chain ─────────────────────────────────────────
    {
        "sector_id": "nvidia_semiconductor_supply_chain",
        "sector_name": "Semiconductor & Hardware Supply Chain",
        "sector_summary": (
            "The global supply chain for GPU hardware manufacturing: foundry partners (TSMC), "
            "OSAT (outsourced assembly and test), PCB and memory suppliers, "
            "and logistics/distribution networks for NVIDIA GPUs."
        ),
        "relevance_to_nvidia": (
            "NVIDIA is fabless — all GPU manufacturing depends on trusted third-party suppliers. "
            "Supply chain compromise could introduce counterfeit components, hardware trojans, "
            "or enable IP theft at critical manufacturing steps."
        ),
        "relevant_nvidia_products": [
            "H100/H200/GB200 GPUs (manufactured at TSMC)",
            "NVIDIA GPU packaging (CoWoS, SXM)",
            "HBM memory (supplied by SK Hynix, Micron, Samsung)",
            "PCB and carrier boards for GPU systems"
        ],
        "crown_jewel_assets": [
            "GPU chip design files (GDSII/RTL)",
            "TSMC process node allocation agreements",
            "Supply chain partner NDA and contractual data",
            "Component authentication and anti-counterfeiting systems",
            "Logistics and inventory data"
        ],
        "likely_threat_actors": [
            "Nation-state actors targeting semiconductor IP (assessed: CN)",
            "Industrial espionage actors targeting chip design data",
            "Counterfeit component networks supplying gray-market GPU products",
            "Insiders at foundry or OSAT partners"
        ],
        "adversary_motivations": [
            "Acquisition of GPU chip design and microarchitecture IP",
            "Counterfeit GPU production for financial gain",
            "Hardware trojan insertion for long-term intelligence access",
            "Disruption of GPU supply for geopolitical leverage"
        ],
        "common_attack_surfaces": [
            "Foundry and OSAT partner IT systems (TSMC, CoWoS facilities)",
            "EDA tool licensing and collaboration platforms",
            "Secure design file transfer mechanisms (PDK, GDSII)",
            "Logistics and shipping tracking systems",
            "Component authentication portals"
        ],
        "likely_attack_paths": [
            "Compromise TSMC partner network → access GPU GDSII design files",
            "Insider at OSAT facility → photograph or export design documentation",
            "Counterfeit GPU cards through gray-market channels with modified firmware",
            "Compromise supply chain management software → manipulate logistics data"
        ],
        "intelligence_requirements": [
            "IR-1: Active campaigns targeting semiconductor IP at foundry partners",
            "IR-2: Counterfeit GPU market activity and detection methods",
            "IR-3: Hardware trojan insertion techniques applicable to GPU packaging",
            "IR-4: Supply chain disruption risks from geopolitical tensions"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are TSMC or OSAT partners actively targeted for NVIDIA GPU design IP? (Confidence: Medium)",
            "PIR-2: Is there active trade in counterfeit or remarked NVIDIA GPU products? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Dark web listings offering NVIDIA GPU chip design data",
            "Reports of counterfeit GPU cards in distribution channels",
            "Cybersecurity incidents at major semiconductor foundry partners",
            "Export control enforcement actions related to NVIDIA GPUs"
        ],
        "relevant_ioc_types": [
            "Dark web forum posts offering NVIDIA design files",
            "Counterfeit GPU identification signatures",
            "Malware targeting EDA (Electronic Design Automation) toolsets"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Supply Chain Compromise, Spearphishing",
            "Collection: Data from Information Repositories",
            "Exfiltration: Exfiltration to Cloud, Physical Media",
            "Impact: Supply Chain Disruption"
        ],
        "mitre_attack_focus": [
            "T1195 Supply Chain Compromise",
            "T1213 Data from Information Repositories",
            "T1052 Exfiltration Over Physical Medium",
            "T1072 Software Deployment Tools"
        ],
        "vulnerability_intelligence_focus": [
            "EDA tool vulnerabilities (Cadence, Synopsys environments)",
            "Secure file transfer platform vulnerabilities used in IP sharing",
            "Component authentication protocol weaknesses"
        ],
        "supply_chain_risk_focus": [
            "Foundry (TSMC, Samsung) cybersecurity posture",
            "CoWoS and advanced packaging supply chain",
            "HBM memory supplier security",
            "PCB fabrication and assembly partner security"
        ],
        "product_security_relevance": (
            "Indirectly relevant to NVIDIA PSIRT. Hardware trojan insertion or component "
            "authentication bypass could affect all NVIDIA GPU products. "
            "PSIRT should maintain visibility on supply chain security incidents."
        ),
        "telemetry_requirements": [
            "Design file access logs (IP management systems)",
            "Partner network access audit logs",
            "Component authentication system logs",
            "Supply chain management platform audit trails"
        ],
        "hunting_opportunities": [
            "Hunt for anomalous access to GPU design files in IP management systems",
            "Hunt for EDA tool network connections to unusual external destinations",
            "Hunt for unauthorized data exports from design collaboration platforms"
        ],
        "detection_engineering_opportunities": [
            "Alert on bulk download of GDSII or RTL files from internal design repositories",
            "Detect EDA license server access from unauthorized hosts",
            "Alert on supply chain management system configuration changes outside change windows"
        ],
        "mitigation_recommendations": [
            "Implement strict data classification and access controls for GPU design files",
            "Conduct supply chain security assessments of top-tier partners annually",
            "Deploy component authentication for GPU cards in distribution",
            "Encrypt all GPU design IP in transit and at rest"
        ],
        "engineering_follow_up_actions": [
            "Develop NVIDIA GPU component authentication program for distribution channel",
            "Establish supply chain threat intelligence sharing with foundry partners",
            "Review EDA tool network segmentation for design environments"
        ],
        "psirt_relevance": (
            "Low-Medium for PSIRT directly. Supply chain hardware security issues are "
            "primarily an IP protection and product integrity concern. "
            "PSIRT engagement relevant if hardware trojans are confirmed in shipped products."
        ),
        "customer_risk_considerations": [
            "Data center operators receiving counterfeit GPUs face performance and reliability risk",
            "Hardware trojans in shipped GPUs would be a critical trust issue for all customers",
            "Export control compliance is a customer risk when acquiring NVIDIA GPUs in restricted markets"
        ],
        "executive_summary_points": [
            "NVIDIA's fabless model creates inherent supply chain exposure at foundry and packaging partners",
            "GPU chip design IP is a primary target for nation-state semiconductor espionage",
            "Counterfeit GPU products in the gray market represent an ongoing distribution risk"
        ],
        "analyst_notes": (
            "Supply chain targeting of semiconductor companies is well-documented in public threat reporting. "
            "NVIDIA-specific supply chain incidents are not extensively documented publicly. "
            "Risk assessment based on general semiconductor threat landscape and NVIDIA's market position."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "CISA/FBI advisories on semiconductor IP theft",
            "Industry reports on counterfeit electronics",
            "Semiconductor ISAC threat intelligence",
            "Export control enforcement actions (BIS, DoJ) related to GPU smuggling"
        ],
        "pack_source": "nvidia",
    },
    # ── 8. Firmware & Drivers ─────────────────────────────────────────────────
    {
        "sector_id": "nvidia_firmware_drivers",
        "sector_name": "GPU Firmware & Drivers",
        "sector_summary": (
            "The software stack between NVIDIA GPU hardware and operating systems: "
            "GPU firmware (VBIOS, GSP firmware), kernel-mode display/compute drivers, "
            "and user-mode runtime libraries across Windows and Linux."
        ),
        "relevance_to_nvidia": (
            "GPU drivers and firmware are the most direct attack surface for NVIDIA-specific "
            "exploitation. Driver vulnerabilities affect hundreds of millions of endpoints. "
            "Firmware compromise provides the deepest persistence level available on GPU hardware."
        ),
        "relevant_nvidia_products": [
            "NVIDIA Display Driver (Windows/Linux)",
            "NVIDIA GPU firmware (VBIOS, GSP firmware)",
            "CUDA driver",
            "OpenGL/Vulkan/DirectX runtime",
            "NvFlash and firmware update utilities",
            "NVIDIA VGPU Manager"
        ],
        "crown_jewel_assets": [
            "GPU driver signing certificates",
            "VBIOS signing keys",
            "GSP firmware source code",
            "Driver code signing infrastructure",
            "Internal driver vulnerability database"
        ],
        "likely_threat_actors": [
            "Cybercriminal groups deploying rootkits via driver exploitation",
            "Nation-state actors targeting driver layer for persistent implants",
            "Security researchers discovering kernel-mode driver vulnerabilities",
            "Malware campaigns abusing BYOVD (Bring Your Own Vulnerable Driver)"
        ],
        "adversary_motivations": [
            "Kernel-level code execution via driver vulnerability",
            "BYOVD: use vulnerable NVIDIA driver to disable security tools",
            "GPU firmware implant for ultra-persistent malware",
            "Code signing certificate theft for malware distribution",
            "Anti-cheat bypass in gaming context"
        ],
        "common_attack_surfaces": [
            "Windows IOCTL interface of GPU kernel driver",
            "Linux kernel DRM/KMS driver interface",
            "VBIOS flashing utilities (NvFlash)",
            "GPU driver update mechanism (Windows Update, official installers)",
            "vGPU driver exposed to guest VMs"
        ],
        "likely_attack_paths": [
            "Exploit IOCTL vulnerability in Windows GPU driver → privilege escalation to kernel",
            "BYOVD: load old vulnerable NVIDIA driver → kill EDR via kernel access",
            "Abuse NvFlash tool → write malicious VBIOS → persistent firmware implant",
            "Compromise driver signing cert → distribute malicious driver as signed update"
        ],
        "intelligence_requirements": [
            "IR-1: Active exploitation of NVIDIA driver CVEs (in-the-wild)",
            "IR-2: BYOVD campaigns using NVIDIA driver versions",
            "IR-3: VBIOS and GSP firmware attack research",
            "IR-4: Driver signing certificate exposure or theft incidents"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Which NVIDIA driver CVEs are being actively exploited in the wild? (Confidence: High)",
            "PIR-2: Are there active BYOVD campaigns using NVIDIA drivers? (Confidence: Medium)",
            "PIR-3: Is there a public PoC for current unpatched GPU firmware vulnerabilities? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Security researcher publications on NVIDIA driver kernel vulnerabilities",
            "BYOVD campaign reports mentioning NVIDIA driver versions",
            "NvFlash misuse reports in security incident data",
            "NVIDIA driver CVEs with public PoC before patch availability",
            "Malware samples signed with NVIDIA code signing certificates"
        ],
        "relevant_ioc_types": [
            "Vulnerable NVIDIA driver version numbers (BYOVD indicators)",
            "Hashes of trojanized NVIDIA driver installers",
            "NVIDIA certificate serial numbers (for signing abuse detection)",
            "Known malicious VBIOS file hashes"
        ],
        "relevant_ttp_categories": [
            "Privilege Escalation: Exploitation for Privilege Escalation",
            "Defense Evasion: Bring Your Own Vulnerable Driver",
            "Persistence: Firmware Modification (VBIOS)",
            "Defense Evasion: Code Signing (driver cert abuse)"
        ],
        "mitre_attack_focus": [
            "T1068 Exploitation for Privilege Escalation",
            "T1211 Exploitation for Defense Evasion",
            "T1542 Pre-OS Boot (VBIOS)",
            "T1553.002 Code Signing"
        ],
        "vulnerability_intelligence_focus": [
            "All active NVIDIA GPU driver CVEs (kernel-mode)",
            "VBIOS and GSP firmware security architecture",
            "NvFlash authentication bypass research",
            "Windows IOCTL surface of NVIDIA display driver"
        ],
        "supply_chain_risk_focus": [
            "Driver distribution via Windows Update integrity",
            "Third-party driver packaging and distribution",
            "OEM-bundled driver software modifications"
        ],
        "product_security_relevance": (
            "Core PSIRT responsibility. Every GPU driver CVE is a PSIRT deliverable. "
            "VBIOS/firmware vulnerabilities require hardware-level remediation planning. "
            "BYOVD threat intelligence should feed into PSIRT vulnerability prioritization."
        ),
        "telemetry_requirements": [
            "NVIDIA driver version inventory across enterprise endpoints",
            "EDR telemetry: NVIDIA driver IOCTL call anomalies",
            "Windows Event Log: driver load events for vulnerable NVIDIA driver versions",
            "Code signing certificate usage monitoring"
        ],
        "hunting_opportunities": [
            "Hunt for NVIDIA driver versions known to be used in BYOVD campaigns",
            "Hunt for NvFlash execution outside normal IT maintenance workflows",
            "Hunt for unsigned processes making IOCTL calls to NVIDIA driver",
            "Hunt for GPU VBIOS version mismatches vs fleet baseline"
        ],
        "detection_engineering_opportunities": [
            "Alert on NVIDIA driver version below minimum secure version (per BYOVD IOC lists)",
            "Detect NvFlash.exe execution from non-standard parent processes",
            "Alert on VBIOS version changes on production GPU systems",
            "Detect loading of old/revoked NVIDIA driver certificates"
        ],
        "mitigation_recommendations": [
            "Maintain current NVIDIA driver versions per PSIRT security advisories",
            "Block NvFlash on endpoints where VBIOS update is not required",
            "Add vulnerable NVIDIA driver hashes to endpoint blocklists",
            "Enable Windows HVCI (Hypervisor-Protected Code Integrity) to mitigate BYOVD",
            "Monitor GPU driver update channel for tampering"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA driver security baseline guide with minimum supported versions",
            "Accelerate VBIOS secure boot enforcement roadmap",
            "Establish driver vulnerability-to-BYOVD pipeline for proactive detection"
        ],
        "psirt_relevance": (
            "Critical. Primary PSIRT domain. GPU driver and firmware CVEs are NVIDIA PSIRT's "
            "core workload. BYOVD threat intelligence should directly inform advisory urgency "
            "and coordinated disclosure timelines."
        ),
        "customer_risk_considerations": [
            "Enterprise customers need clear minimum driver version guidance per PSIRT advisory",
            "Consumer GPU users (gaming) rarely patch drivers promptly — large BYOVD exposure",
            "Data center operators need zero-downtime patching guidance for driver updates"
        ],
        "executive_summary_points": [
            "GPU driver vulnerabilities represent the largest NVIDIA attack surface by endpoint count",
            "BYOVD is an active, confirmed threat using NVIDIA driver versions as malware enablers",
            "VBIOS firmware compromise provides persistent implant capability below OS visibility"
        ],
        "analyst_notes": (
            "NVIDIA GPU driver CVEs are regularly issued. BYOVD campaigns using NVIDIA drivers "
            "are confirmed in public threat reporting. VBIOS-level compromise remains largely "
            "theoretical but is a credible advanced threat scenario."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "NVIDIA PSIRT advisories (all driver CVEs)",
            "BYOVD tracker databases (e.g., LOLDrivers.io)",
            "Malware analysis reports mentioning NVIDIA driver abuse",
            "Security research publications on GPU firmware"
        ],
        "pack_source": "nvidia",
    },
    # ── 9. Autonomous Vehicles ────────────────────────────────────────────────
    {
        "sector_id": "nvidia_autonomous_vehicles",
        "sector_name": "Autonomous Vehicles & ADAS",
        "sector_summary": (
            "Automotive sector deploying NVIDIA DRIVE platform (DRIVE AGX, DRIVE Thor) "
            "for autonomous driving (L2-L4), ADAS, and in-vehicle infotainment. "
            "Includes OEM automotive manufacturers and tier-1 suppliers."
        ),
        "relevance_to_nvidia": (
            "NVIDIA DRIVE is a strategic automotive platform competing with Mobileye, Qualcomm, "
            "and Renesas. Security vulnerabilities in DRIVE could cause safety incidents and "
            "damage NVIDIA's automotive credibility in a safety-critical market."
        ),
        "relevant_nvidia_products": [
            "NVIDIA DRIVE AGX Orin", "NVIDIA DRIVE Thor",
            "DriveWorks SDK", "DRIVE OS", "DRIVE AV software stack",
            "NVIDIA Omniverse for AV simulation"
        ],
        "crown_jewel_assets": [
            "DRIVE platform firmware and BSP",
            "AV perception model weights (deployed in vehicles)",
            "DriveWorks algorithm implementations",
            "OTA update signing keys for vehicle software",
            "Vehicle sensor fusion and path planning algorithms"
        ],
        "likely_threat_actors": [
            "Nation-state actors targeting AV technology IP (assessed: CN)",
            "Safety researchers discovering exploitable ADAS vulnerabilities",
            "Criminal actors targeting OTA update infrastructure for ransomware",
            "Competitor intelligence actors"
        ],
        "adversary_motivations": [
            "Theft of AV perception and path-planning algorithms",
            "OTA update system compromise for persistent vehicle access",
            "Physical safety impact via sensor spoofing combined with software exploit",
            "Competitive intelligence on NVIDIA DRIVE roadmap"
        ],
        "common_attack_surfaces": [
            "OTA update server and signing infrastructure",
            "V2X (vehicle-to-everything) communication interfaces",
            "Vehicle diagnostic port (OBD-II / UDS interface)",
            "Bluetooth and WiFi interfaces in IVI systems",
            "DRIVE OS Linux kernel attack surface"
        ],
        "likely_attack_paths": [
            "Compromise OTA update infrastructure → push malicious vehicle software update",
            "Exploit DRIVE OS vulnerability via V2X attack → persistent vehicle access",
            "Physical access via OBD-II → extract AV model weights from DRIVE platform",
            "Spearphish OEM automotive cybersecurity team → access DRIVE development environment"
        ],
        "intelligence_requirements": [
            "IR-1: Known CVEs in DRIVE OS or DriveWorks SDK",
            "IR-2: AV OTA update system attack patterns",
            "IR-3: Automotive cybersecurity regulations affecting NVIDIA DRIVE (UN-R155/156)",
            "IR-4: Sensor spoofing combined with software attack techniques"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active campaigns targeting NVIDIA DRIVE or DriveWorks IP? (Confidence: Low)",
            "PIR-2: What are the known attack surfaces of OTA update systems in DRIVE deployments? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Security research publications targeting DRIVE OS or DriveWorks",
            "Automotive CVEs mentioning NVIDIA DRIVE components",
            "Regulatory actions on AV cybersecurity affecting DRIVE-equipped vehicles",
            "Dark web interest in AV model weights or DRIVE firmware"
        ],
        "relevant_ioc_types": [
            "Malicious OTA update package signatures",
            "Known exploit payloads for DRIVE OS",
            "Suspicious V2X message patterns"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Supply Chain Compromise (OTA), Exploit Public-Facing Application",
            "Persistence: Firmware Modification (vehicle BSP)",
            "Impact: Inhibit System Recovery (vehicle OTA bricked)"
        ],
        "mitre_attack_focus": [
            "T1195 Supply Chain Compromise",
            "T1542 Pre-OS Boot (Vehicle BSP Firmware)",
            "T1490 Inhibit System Recovery"
        ],
        "vulnerability_intelligence_focus": [
            "DRIVE OS Linux kernel CVEs",
            "DriveWorks SDK memory safety issues",
            "OTA update verification bypass techniques",
            "V2X protocol security vulnerabilities"
        ],
        "supply_chain_risk_focus": [
            "Tier-1 automotive supplier software integrated with DRIVE platform",
            "Open-source components in DRIVE OS (Linux, ROS2)",
            "OTA update server infrastructure operated by OEM partners"
        ],
        "product_security_relevance": (
            "PSIRT relevance for DRIVE OS and DriveWorks SDK. "
            "Automotive cybersecurity regulations (ISO/SAE 21434, UN-R155) require "
            "NVIDIA PSIRT to maintain vehicle-specific vulnerability management processes."
        ),
        "telemetry_requirements": [
            "DRIVE platform telemetry from field-deployed vehicles (via OEM)",
            "OTA update server access and authentication logs",
            "DriveWorks SDK crash/error telemetry from development platforms",
            "V2X communication anomaly detection (prototype)"
        ],
        "hunting_opportunities": [
            "Hunt for DRIVE development system access by non-automotive-team personnel",
            "Hunt for unusual OTA update package submissions outside release windows",
            "Hunt for DriveWorks algorithm extraction attempts from development platforms"
        ],
        "detection_engineering_opportunities": [
            "Alert on OTA update signing key usage outside authorized workflows",
            "Detect anomalous DRIVE OS process behavior in simulation environments",
            "Alert on unauthorized access to DRIVE platform BSP repositories"
        ],
        "mitigation_recommendations": [
            "Implement multi-party authorization for OTA update signing",
            "Enforce secure boot for DRIVE platform BSP",
            "Conduct regular security audits of DriveWorks SDK against MISRA/CERT-C",
            "Ensure UN-R155/ISO 21434 compliance processes are maintained"
        ],
        "engineering_follow_up_actions": [
            "Establish NVIDIA DRIVE vulnerability disclosure channel for automotive safety researchers",
            "Publish AV cybersecurity hardening guide for OEM DRIVE integrators",
            "Engage with automotive ISAC (Auto-ISAC) on AV threat intelligence sharing"
        ],
        "psirt_relevance": (
            "Medium-High. DRIVE OS and DriveWorks fall under PSIRT scope. "
            "Safety-critical context requires coordinated disclosure with automotive OEMs "
            "and compliance with ISO/SAE 21434 vulnerability management requirements."
        ),
        "customer_risk_considerations": [
            "Automotive OEMs have strict vehicle recall and safety reporting obligations",
            "OTA update failures can strand vehicles — availability is a safety requirement",
            "UN-R155 compliance requires OEM partners to have documented incident response for NVIDIA DRIVE"
        ],
        "executive_summary_points": [
            "NVIDIA DRIVE is in safety-critical vehicles — exploits have physical safety implications",
            "OTA update infrastructure is the primary software attack vector for AV platforms",
            "Automotive cybersecurity regulations require NVIDIA to maintain vehicle-specific PSIRT processes"
        ],
        "analyst_notes": (
            "No confirmed public exploitation of NVIDIA DRIVE in production vehicles. "
            "AV cybersecurity research is active and growing. "
            "Threat model reflects the broader automotive cybersecurity landscape and NVIDIA's growing market share."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "Auto-ISAC threat intelligence advisories",
            "NVIDIA PSIRT advisories: DRIVE OS, DriveWorks",
            "UN-R155/R156 regulatory publications",
            "Academic AV cybersecurity research (IEEE S&P, USENIX)"
        ],
        "pack_source": "nvidia",
    },
    # ── 10. Robotics ──────────────────────────────────────────────────────────
    {
        "sector_id": "nvidia_robotics",
        "sector_name": "Robotics & Embodied AI",
        "sector_summary": (
            "Industrial and service robotics deployments using NVIDIA Jetson and Isaac platforms "
            "for AI-powered robot perception, manipulation, and autonomy. "
            "Covers manufacturing robots, logistics robots, and humanoid robot development."
        ),
        "relevance_to_nvidia": (
            "NVIDIA Isaac and Jetson are key platforms for the emerging robotics AI market. "
            "Vulnerabilities in embedded AI systems could cause physical harm, IP theft, "
            "or disruption of manufacturing operations."
        ),
        "relevant_nvidia_products": [
            "NVIDIA Jetson Orin", "NVIDIA Isaac ROS",
            "NVIDIA Isaac Sim", "NVIDIA Isaac Manipulator",
            "NVIDIA DRIVE for Robotics", "Jetson Linux BSP"
        ],
        "crown_jewel_assets": [
            "Robot AI model weights (perception, manipulation)",
            "Jetson firmware and BSP",
            "Isaac ROS algorithm implementations",
            "Robot fleet management credentials",
            "Simulation environment (digital twin data)"
        ],
        "likely_threat_actors": [
            "Nation-state actors targeting industrial automation IP",
            "Safety researchers discovering embedded AI vulnerabilities",
            "Criminal actors targeting robot fleet management for ransomware",
            "Competitor intelligence actors targeting Isaac algorithm IP"
        ],
        "adversary_motivations": [
            "Theft of robot AI algorithm and model IP",
            "Disruption of manufacturing automation for economic impact",
            "Physical safety sabotage via robot manipulation",
            "Persistent access to industrial network via compromised Jetson"
        ],
        "common_attack_surfaces": [
            "Jetson device management interfaces (network-connected robots)",
            "ROS2 (Robot Operating System) inter-node communication",
            "Robot fleet management software",
            "OTA update mechanism for Isaac and Jetson BSP",
            "Simulation environment connectivity to production"
        ],
        "likely_attack_paths": [
            "Exploit ROS2 DDS communication vulnerability → manipulate robot behavior",
            "Compromise robot fleet management → push malicious firmware to Jetson fleet",
            "Network pivot via compromised Jetson → lateral movement to industrial OT network",
            "Physical access to Jetson device → extract model weights from eMMC"
        ],
        "intelligence_requirements": [
            "IR-1: ROS2 DDS security vulnerabilities being exploited",
            "IR-2: Jetson firmware vulnerabilities enabling persistent access",
            "IR-3: Industrial robot ransomware campaigns",
            "IR-4: Physical security of Jetson modules in deployed robots"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are ROS2 vulnerabilities actively exploited in production robotics? (Confidence: Low)",
            "PIR-2: Are Jetson devices being targeted in industrial OT network attacks? (Confidence: Low)"
        ],
        "early_warning_indicators": [
            "ROS2 vulnerability disclosures by security researchers",
            "Reports of ransomware targeting logistics robot fleets",
            "Jetson firmware CVE publications",
            "Academic research on robot manipulation via software attack"
        ],
        "relevant_ioc_types": [
            "Malicious ROS2 packages",
            "Jetson firmware with unexpected versions",
            "Known C2 indicators from industrial malware hitting Jetson IPs"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Exploit Public-Facing Application, Supply Chain Compromise",
            "Lateral Movement: Remote Services",
            "Impact: Inhibit System Recovery, Physical Damage (indirect)"
        ],
        "mitre_attack_focus": [
            "T1190 Exploit Public-Facing Application",
            "T1195 Supply Chain Compromise",
            "T1021 Remote Services",
            "T1490 Inhibit System Recovery"
        ],
        "vulnerability_intelligence_focus": [
            "ROS2 DDS middleware vulnerabilities",
            "Jetson Linux BSP kernel CVEs",
            "Isaac ROS package dependency vulnerabilities",
            "Robot fleet management software security"
        ],
        "supply_chain_risk_focus": [
            "ROS2 package ecosystem (rosdep, colcon packages)",
            "Third-party AI models integrated into Isaac",
            "Industrial robot OEM software integrated with Jetson"
        ],
        "product_security_relevance": (
            "PSIRT scope includes Jetson BSP CVEs. "
            "ROS2 is open-source but NVIDIA Isaac ROS is NVIDIA's distribution. "
            "Physical safety implications require conservative CVE severity ratings."
        ),
        "telemetry_requirements": [
            "Jetson device inventory and firmware version monitoring",
            "Robot fleet management access logs",
            "ROS2 node communication anomaly detection",
            "OTA update event logs for Jetson fleet"
        ],
        "hunting_opportunities": [
            "Hunt for Jetson devices with unexpected network connections outside robot subnet",
            "Hunt for ROS2 packages not in approved allowlist running on production robots",
            "Hunt for robot fleet management configuration changes outside maintenance windows"
        ],
        "detection_engineering_opportunities": [
            "Alert on Jetson devices communicating outside defined operational subnets",
            "Detect unexpected ROS2 node registrations on production robot networks",
            "Alert on Jetson firmware version changes outside OTA maintenance windows"
        ],
        "mitigation_recommendations": [
            "Isolate robot networks from corporate IT networks with strict firewall rules",
            "Implement ROS2 DDS security (SROS2) with authentication and encryption",
            "Enforce Jetson secure boot and firmware integrity verification",
            "Restrict robot fleet management access to authorized personnel with MFA"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA Jetson security hardening guide for industrial deployments",
            "Engage ROS2 security working group on DDS vulnerability response",
            "Evaluate Isaac ROS SBOM for dependency vulnerability tracking"
        ],
        "psirt_relevance": (
            "Medium. Jetson CVEs are PSIRT scope. Physical safety implications in robotics "
            "warrant escalated response timelines. Isaac ROS vulnerabilities are PSIRT-adjacent."
        ),
        "customer_risk_considerations": [
            "Manufacturing operators face production downtime risk from robot firmware attacks",
            "Humanoid robot deployments in public spaces create safety and liability concerns",
            "Industrial customers may not have IT security resources for robot network monitoring"
        ],
        "executive_summary_points": [
            "NVIDIA Jetson/Isaac is entering safety-critical industrial environments with growing attack surface",
            "ROS2 DDS communication is largely unauthenticated in default deployments",
            "Robot fleet management systems are single points of control for entire automation lines"
        ],
        "analyst_notes": (
            "Robotics cybersecurity is an emerging field. Limited confirmed incidents involving NVIDIA "
            "robotics platforms are publicly documented. Risk assessment based on general ICS/OT threat "
            "landscape and ROS2 security research."
        ),
        "confidence_level": "Low",
        "source_requirements": [
            "ROS2 security working group publications",
            "ICS-CERT advisories on industrial robot vulnerabilities",
            "NVIDIA PSIRT advisories: Jetson BSP",
            "Academic robotics cybersecurity research"
        ],
        "pack_source": "nvidia",
    },
    # ── 11. Healthcare AI ─────────────────────────────────────────────────────
    {
        "sector_id": "nvidia_healthcare_ai",
        "sector_name": "Healthcare & Medical AI",
        "sector_summary": (
            "Healthcare institutions and medical AI companies deploying NVIDIA Clara platform, "
            "Holoscan, and GPU-accelerated workloads for medical imaging, genomics, "
            "drug discovery, and clinical AI applications."
        ),
        "relevance_to_nvidia": (
            "NVIDIA Clara and Holoscan are strategic healthcare AI platforms. "
            "Security incidents in healthcare AI deployments create regulatory, liability, "
            "and patient safety risks that reflect on NVIDIA's platform."
        ),
        "relevant_nvidia_products": [
            "NVIDIA Clara (Imaging, Parabricks, Clara AGX)",
            "NVIDIA Holoscan SDK",
            "NVIDIA IGX Orin (medical edge)",
            "BioNeMo (drug discovery)",
            "CUDA-accelerated genomics tools"
        ],
        "crown_jewel_assets": [
            "Patient health information (PHI) processed by Clara/Holoscan",
            "Medical AI model weights (diagnostic classifiers)",
            "Clinical trial data in CUDA-accelerated analytics",
            "Medical device firmware (IGX Orin)",
            "Drug discovery research data in BioNeMo"
        ],
        "likely_threat_actors": [
            "Ransomware groups targeting hospitals (high payment pressure)",
            "Nation-state actors targeting drug discovery IP (assessed: CN, IR)",
            "Insiders at pharmaceutical companies with GPU access",
            "Medical device security researchers"
        ],
        "adversary_motivations": [
            "Ransomware extortion leveraging patient care dependency",
            "Drug discovery and clinical trial IP theft",
            "PHI theft for identity fraud or targeted attacks",
            "Medical device manipulation for patient harm (advanced threat)"
        ],
        "common_attack_surfaces": [
            "Hospital network connectivity of Clara/Holoscan workstations",
            "DICOM server integrations with Clara Imaging",
            "Cloud-connected medical AI platforms",
            "IGX Orin device management interfaces in medical devices",
            "Genomics data pipelines with external data inputs"
        ],
        "likely_attack_paths": [
            "Ransomware via phishing → encrypt hospital GPU workstations running Clara",
            "Exploit DICOM protocol vulnerability → access patient imaging data on Clara",
            "Compromise pharmaceutical GPU cluster → exfiltrate drug discovery data",
            "Attack medical device management → compromise IGX Orin in deployed device"
        ],
        "intelligence_requirements": [
            "IR-1: Ransomware groups actively targeting hospital AI infrastructure",
            "IR-2: Nation-state campaigns targeting pharmaceutical AI/genomics IP",
            "IR-3: Medical device vulnerabilities involving NVIDIA hardware (IGX)",
            "IR-4: DICOM and HL7 protocol vulnerabilities affecting Clara deployments"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are NVIDIA Clara or Holoscan deployments targeted in active ransomware campaigns? (Confidence: Medium)",
            "PIR-2: Is pharmaceutical AI data (BioNeMo) targeted by nation-state actors? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Hospital network ransomware indicators in healthcare ISAC feeds",
            "DICOM server vulnerability disclosures",
            "Medical device security research targeting AI accelerators",
            "Dark web listings of pharmaceutical research data"
        ],
        "relevant_ioc_types": [
            "Healthcare-specific ransomware IOCs (e.g., known health-sector ransomware families)",
            "DICOM server exploit payloads",
            "Malicious packages targeting bioinformatics/genomics pipelines"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Phishing, Exploit Public-Facing Application (DICOM)",
            "Impact: Data Encrypted for Impact (ransomware), Data Manipulation",
            "Collection: Data from Local System (PHI, model weights)"
        ],
        "mitre_attack_focus": [
            "T1566 Phishing",
            "T1190 Exploit Public-Facing Application",
            "T1486 Data Encrypted for Impact",
            "T1565 Data Manipulation"
        ],
        "vulnerability_intelligence_focus": [
            "Clara and Holoscan SDK vulnerabilities",
            "DICOM protocol implementation vulnerabilities",
            "IGX Orin firmware and Linux BSP CVEs",
            "Genomics pipeline software (GATK, Parabricks) vulnerabilities"
        ],
        "supply_chain_risk_focus": [
            "Bioinformatics software dependencies (conda packages for genomics)",
            "Pre-trained medical AI models from public repositories",
            "Third-party DICOM integrations with Clara"
        ],
        "product_security_relevance": (
            "PSIRT scope: Clara SDK, Holoscan SDK, IGX Orin BSP. "
            "Medical device context (IGX) requires FDA cybersecurity guidance compliance. "
            "PHI processing creates HIPAA obligations for NVIDIA and its customers."
        ),
        "telemetry_requirements": [
            "Clara/Holoscan deployment audit logs",
            "Medical AI platform access logs",
            "IGX device firmware inventory",
            "DICOM server access and error logs"
        ],
        "hunting_opportunities": [
            "Hunt for Clara workstations with unexpected internet connectivity",
            "Hunt for anomalous data access patterns on medical AI model repositories",
            "Hunt for bioinformatics pipeline package installs from non-standard sources"
        ],
        "detection_engineering_opportunities": [
            "Alert on Clara/Holoscan systems communicating with healthcare-sector ransomware IOCs",
            "Detect DICOM server queries with anomalous patient data export patterns",
            "Alert on IGX firmware version changes outside approved maintenance"
        ],
        "mitigation_recommendations": [
            "Network-segment Clara/Holoscan workstations from general hospital IT networks",
            "Implement data-at-rest encryption for all PHI processed by NVIDIA platforms",
            "Keep IGX Orin firmware current with NVIDIA PSIRT advisories",
            "Validate pre-trained medical AI models against known provenance before deployment"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA healthcare AI security hardening guide",
            "Engage H-ISAC on Clara/Holoscan threat intelligence sharing",
            "Evaluate FDA medical device cybersecurity requirements for IGX deployments"
        ],
        "psirt_relevance": (
            "Medium-High. Clara, Holoscan, and IGX BSP are PSIRT scope. "
            "Medical device context (FDA) requires accelerated patch timelines and coordinated "
            "disclosure with medical device manufacturers using NVIDIA silicon."
        ),
        "customer_risk_considerations": [
            "HIPAA breach notification obligations apply if PHI on Clara systems is compromised",
            "Hospital customers have critical uptime requirements — patching coordination needed",
            "FDA cybersecurity requirements impose device vulnerability management obligations on IGX users"
        ],
        "executive_summary_points": [
            "Healthcare AI deployments face acute ransomware risk with direct patient care implications",
            "PHI processed by NVIDIA Clara creates compliance and breach notification obligations",
            "Medical device AI (IGX) is subject to FDA cybersecurity requirements"
        ],
        "analyst_notes": (
            "Healthcare ransomware is a confirmed, active threat to hospitals. "
            "NVIDIA Clara-specific targeting has not been confirmed in public reporting; "
            "threat model extrapolated from general healthcare IT threat landscape."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "H-ISAC healthcare cybersecurity advisories",
            "CISA healthcare sector advisories",
            "FDA medical device cybersecurity guidance",
            "NVIDIA PSIRT advisories: Clara, Holoscan, IGX"
        ],
        "pack_source": "nvidia",
    },
    # ── 12. Telecom / 5G / Edge ───────────────────────────────────────────────
    {
        "sector_id": "nvidia_telecom_5g_edge",
        "sector_name": "Telecom, 5G & Edge Computing",
        "sector_summary": (
            "Telecommunications operators and 5G network equipment vendors deploying NVIDIA "
            "GPUs and BlueField DPUs for AI-RAN, vRAN (virtualized RAN), Multi-access Edge "
            "Computing (MEC), and network AI workloads."
        ),
        "relevance_to_nvidia": (
            "NVIDIA Aerial SDK and BlueField DPUs are strategic products for the 5G/AI-RAN market. "
            "Telecom infrastructure is critical national infrastructure — compromise has broad impact."
        ),
        "relevant_nvidia_products": [
            "NVIDIA Aerial SDK (AI-RAN)", "BlueField-3 DPU",
            "NVIDIA GPU for vRAN acceleration", "CUDA for edge inferencing",
            "NVIDIA AI Enterprise for telecom"
        ],
        "crown_jewel_assets": [
            "Aerial SDK source and 5G IP",
            "vRAN software and ML models",
            "Telecom operator subscriber data on edge",
            "5G network slice configuration",
            "BlueField DPU configuration for RAN workloads"
        ],
        "likely_threat_actors": [
            "Nation-state APTs targeting telecom infrastructure (assessed: CN, RU)",
            "Criminal actors targeting telecom for SIM swapping and fraud",
            "State-sponsored actors seeking persistent telecom access for surveillance"
        ],
        "adversary_motivations": [
            "Persistent access to 5G infrastructure for surveillance",
            "Theft of NVIDIA Aerial SDK and 5G algorithm IP",
            "Disruption of telecom services (denial of service)",
            "Subscriber data theft via edge compute access"
        ],
        "common_attack_surfaces": [
            "vRAN containerized deployment infrastructure (Kubernetes)",
            "BlueField DPU management interfaces in RAN deployments",
            "MEC application platforms exposed to network",
            "Aerial SDK build and development environments",
            "O-RAN interfaces (O1, A1, E2) in disaggregated RAN"
        ],
        "likely_attack_paths": [
            "Exploit O-RAN interface vulnerability → access RAN controller",
            "Compromise vRAN Kubernetes cluster → lateral movement to subscriber data",
            "BlueField firmware implant in DPU running RAN acceleration → persistent telecom access",
            "Supply chain attack on Aerial SDK → compromised 5G software in operator deployments"
        ],
        "intelligence_requirements": [
            "IR-1: APT campaigns targeting 5G infrastructure using NVIDIA components",
            "IR-2: O-RAN interface vulnerabilities relevant to Aerial deployments",
            "IR-3: Telecom sector ransomware targeting vRAN infrastructure",
            "IR-4: NVIDIA BlueField exploitation in telecom context"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are there active campaigns targeting AI-RAN or vRAN deployments? (Confidence: Low)",
            "PIR-2: Are O-RAN security vulnerabilities relevant to NVIDIA Aerial SDK deployments? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "CISA/NCSC advisories on telecom infrastructure targeting",
            "O-RAN Alliance security working group vulnerability publications",
            "Reports of vRAN container infrastructure attacks",
            "NVIDIA Aerial SDK vulnerability disclosures"
        ],
        "relevant_ioc_types": [
            "Known APT C2 indicators in telecom network IP ranges",
            "Malicious O-RAN protocol messages",
            "vRAN container image anomalies"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Exploit Public-Facing Application (O-RAN), Supply Chain Compromise",
            "Persistence: Firmware Modification (BlueField in RAN)",
            "Collection: Network Sniffing (subscriber data)",
            "Impact: Network Denial of Service"
        ],
        "mitre_attack_focus": [
            "T1190 Exploit Public-Facing Application",
            "T1195 Supply Chain Compromise",
            "T1040 Network Sniffing",
            "T1498 Network Denial of Service"
        ],
        "vulnerability_intelligence_focus": [
            "NVIDIA Aerial SDK vulnerabilities",
            "O-RAN protocol implementation security",
            "vRAN Kubernetes cluster vulnerabilities",
            "BlueField DPU in telecom deployment security"
        ],
        "supply_chain_risk_focus": [
            "Aerial SDK third-party dependencies",
            "vRAN software distribution to telecom operators",
            "BlueField firmware in RAN hardware deployments"
        ],
        "product_security_relevance": (
            "PSIRT scope: Aerial SDK, BlueField DPU (telecom profile). "
            "5G network criticality requires coordinated disclosure with telecom operators "
            "and national cybersecurity agencies."
        ),
        "telemetry_requirements": [
            "Aerial SDK deployment event logs",
            "vRAN Kubernetes audit logs",
            "BlueField DPU firmware inventory in telecom deployments",
            "O-RAN interface access and anomaly logs"
        ],
        "hunting_opportunities": [
            "Hunt for anomalous Aerial SDK process behavior in vRAN nodes",
            "Hunt for BlueField units with unauthorized firmware in telecom deployments",
            "Hunt for unexpected O-RAN interface connections from non-operator IPs"
        ],
        "detection_engineering_opportunities": [
            "Alert on Aerial SDK binary execution anomalies",
            "Detect O-RAN E2 interface messages with unexpected content patterns",
            "Alert on vRAN Kubernetes pods with unexpected network egress"
        ],
        "mitigation_recommendations": [
            "Enforce mutual TLS on all O-RAN interfaces",
            "Isolate vRAN Kubernetes clusters from corporate IT networks",
            "Implement BlueField firmware integrity monitoring in telecom deployments",
            "Conduct O-RAN security hardening per GSMA FS.40 guidelines"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA Aerial SDK and vRAN security hardening guide",
            "Engage GSMA and O-RAN Alliance on security standards alignment",
            "Establish BlueField firmware attestation service for telecom operators"
        ],
        "psirt_relevance": (
            "Medium. Aerial SDK and BlueField in telecom deployments are PSIRT scope. "
            "National critical infrastructure context requires engagement with national "
            "telecom security authorities on disclosure."
        ),
        "customer_risk_considerations": [
            "Telecom operators face regulatory obligations for network security incidents",
            "5G subscriber data breach has direct consumer privacy impact",
            "vRAN availability is critical — any patching requires strict maintenance windows"
        ],
        "executive_summary_points": [
            "5G/vRAN infrastructure using NVIDIA components is critical national infrastructure",
            "O-RAN disaggregation introduces new attack surfaces relevant to Aerial SDK",
            "BlueField DPU in RAN deployments extends DPU security concerns to telecom"
        ],
        "analyst_notes": (
            "Telecom infrastructure APT targeting is well-documented. NVIDIA-specific Aerial SDK "
            "targeting is not confirmed in public reporting. Risk model based on telecom threat "
            "landscape and NVIDIA's growing market presence in 5G."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "CISA/NCSC telecom infrastructure advisories",
            "GSMA FS.40 network security guidelines",
            "O-RAN Alliance security working group publications",
            "NVIDIA PSIRT advisories: Aerial SDK"
        ],
        "pack_source": "nvidia",
    },
    # ── 13. Enterprise AI ─────────────────────────────────────────────────────
    {
        "sector_id": "nvidia_enterprise_ai",
        "sector_name": "Enterprise AI & On-Premises Deployment",
        "sector_summary": (
            "Enterprise organizations deploying NVIDIA AI Enterprise software suite, "
            "NVIDIA DGX systems, and NVIDIA NIM microservices on-premises for "
            "private AI, RAG (retrieval-augmented generation), and AI application development."
        ),
        "relevance_to_nvidia": (
            "NVIDIA AI Enterprise is a major software revenue driver. Enterprise deployments "
            "of DGX and NIM are high-value targets. Security issues in this stack affect "
            "NVIDIA's ability to penetrate regulated enterprise verticals."
        ),
        "relevant_nvidia_products": [
            "NVIDIA AI Enterprise (NVAIE)", "NVIDIA DGX systems",
            "NVIDIA NIM microservices", "NVIDIA NeMo Retriever",
            "NVIDIA Base Command Manager", "NVIDIA NGC catalog"
        ],
        "crown_jewel_assets": [
            "NVAIE license management infrastructure",
            "Enterprise AI model deployments (NIM)",
            "Proprietary enterprise data in RAG pipelines",
            "DGX system management credentials",
            "NGC private registry contents"
        ],
        "likely_threat_actors": [
            "Ransomware groups targeting enterprise AI infrastructure",
            "Nation-state APTs targeting enterprise IP through AI platforms",
            "Insider threats with DGX and NIM administrative access",
            "Supply chain attackers targeting NGC container images"
        ],
        "adversary_motivations": [
            "Ransomware of high-value DGX infrastructure",
            "Exfiltration of enterprise proprietary data via RAG pipeline access",
            "AI model theft from enterprise NIM deployments",
            "Persistent access to enterprise AI infrastructure"
        ],
        "common_attack_surfaces": [
            "NIM microservice REST API endpoints",
            "Base Command Manager web UI and API",
            "NGC private registry access credentials",
            "DGX BMC management interface",
            "Enterprise VPN and SSO for AI platform access"
        ],
        "likely_attack_paths": [
            "Phish enterprise AI admin → access DGX management → ransomware DGX cluster",
            "Exploit NIM API vulnerability → access RAG knowledge base with sensitive enterprise data",
            "Compromise NGC private registry → inject malicious container image into enterprise pipeline",
            "Abuse NVAIE license server vulnerability → DoS enterprise AI workloads"
        ],
        "intelligence_requirements": [
            "IR-1: Ransomware campaigns targeting DGX and enterprise AI infrastructure",
            "IR-2: NIM microservice vulnerabilities being exploited",
            "IR-3: NGC container image supply chain attacks",
            "IR-4: Base Command Manager security vulnerabilities"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are NIM microservices targeted by API exploitation campaigns? (Confidence: Medium)",
            "PIR-2: Are NGC container images targeted for supply chain attacks? (Confidence: Medium)"
        ],
        "early_warning_indicators": [
            "Ransomware activity in enterprise AI verticals (finance, healthcare)",
            "Security research on NIM API security",
            "NGC container image tampering reports",
            "DGX BMC vulnerability disclosures"
        ],
        "relevant_ioc_types": [
            "Ransomware IOCs from groups targeting enterprise AI",
            "Malicious NGC container image hashes",
            "NIM API abuse patterns",
            "DGX BMC unauthorized access indicators"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Phishing, Valid Accounts",
            "Execution: Container Administration Command",
            "Impact: Data Encrypted for Impact",
            "Collection: Data from Information Repositories (RAG)"
        ],
        "mitre_attack_focus": [
            "T1566 Phishing",
            "T1078 Valid Accounts",
            "T1613 Container and Resource Discovery",
            "T1486 Data Encrypted for Impact"
        ],
        "vulnerability_intelligence_focus": [
            "NIM microservice API vulnerabilities",
            "Base Command Manager CVEs",
            "NVAIE license server vulnerabilities",
            "DGX BMC firmware issues"
        ],
        "supply_chain_risk_focus": [
            "NGC container image integrity and provenance",
            "NVAIE software update mechanism",
            "Third-party AI plugins for NVIDIA AI Enterprise"
        ],
        "product_security_relevance": (
            "PSIRT scope: NIM, NVAIE, Base Command Manager, DGX BMC. "
            "Enterprise AI platforms handle sensitive customer data — "
            "vulnerability severity assessments must account for data exposure impact."
        ),
        "telemetry_requirements": [
            "NIM microservice API access logs",
            "Base Command Manager audit logs",
            "NGC registry pull and push audit logs",
            "DGX BMC access and authentication logs"
        ],
        "hunting_opportunities": [
            "Hunt for NIM API calls accessing unusual knowledge base content",
            "Hunt for NGC container pulls from non-standard geographic locations",
            "Hunt for DGX BMC access from non-management network IPs"
        ],
        "detection_engineering_opportunities": [
            "Alert on NIM microservice crash loops or unusual API error rates",
            "Detect NGC private registry image pushes from non-CI/CD service accounts",
            "Alert on Base Command Manager admin actions outside business hours"
        ],
        "mitigation_recommendations": [
            "Restrict NIM API endpoints to internal networks with API key authentication",
            "Verify NGC container image signatures before deployment",
            "Isolate DGX BMC on dedicated management VLAN with strict ACLs",
            "Implement MFA for all NVAIE and Base Command Manager administrative access"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA enterprise AI security hardening guide (DGX, NIM, NVAIE)",
            "Implement NGC container signing and verification as default",
            "Establish security review process for new NGC catalog entries"
        ],
        "psirt_relevance": (
            "High. NIM, NVAIE, and DGX are all PSIRT scope. "
            "Enterprise AI deployments hold sensitive customer data — "
            "prioritize API security and supply chain integrity."
        ),
        "customer_risk_considerations": [
            "Enterprise customers in regulated industries (finance, healthcare) face compliance risk",
            "RAG pipeline data exposure could leak confidential internal documents",
            "DGX ransomware can halt critical AI development operations"
        ],
        "executive_summary_points": [
            "Enterprise AI infrastructure (DGX, NIM) is a growing ransomware target",
            "RAG pipeline data is a novel, high-value exfiltration target",
            "NGC container supply chain integrity is critical for enterprise AI security"
        ],
        "analyst_notes": (
            "Enterprise AI platform targeting is an emerging threat that extrapolates from general "
            "enterprise ransomware and API exploitation trends. NIM and NVAIE-specific exploitation "
            "is not confirmed in public reporting at this writing."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "NVIDIA PSIRT advisories: NIM, NVAIE, Base Command Manager",
            "Enterprise security vendor threat intelligence on AI platform targeting",
            "CVE database: NIM, DGX management software",
            "NGC security and integrity publications from NVIDIA"
        ],
        "pack_source": "nvidia",
    },
    # ── 14. Gaming / RTX ─────────────────────────────────────────────────────
    {
        "sector_id": "nvidia_gaming_rtx",
        "sector_name": "Gaming & RTX Consumer Platform",
        "sector_summary": (
            "Consumer gaming market deploying NVIDIA GeForce RTX GPUs with Game Ready Drivers, "
            "DLSS, ray tracing, and NVIDIA App/GeForce Experience. "
            "Largest installed base of NVIDIA GPU endpoints globally."
        ),
        "relevance_to_nvidia": (
            "GeForce/RTX represents the largest consumer endpoint count for NVIDIA software. "
            "Driver vulnerabilities here affect the broadest user population and are the most "
            "frequently exploited via BYOVD. GeForce is a primary driver of NVIDIA brand trust."
        ),
        "relevant_nvidia_products": [
            "GeForce RTX 40/50 series GPUs", "Game Ready Drivers",
            "NVIDIA App (successor to GeForce Experience)", "NVIDIA DLSS",
            "NVIDIA Broadcast", "NVIDIA ShadowPlay"
        ],
        "crown_jewel_assets": [
            "GeForce driver signing infrastructure",
            "NVIDIA App user account database",
            "Game Ready Driver distribution channel",
            "DLSS model weights and algorithm IP",
            "Anti-cheat ecosystem integrations"
        ],
        "likely_threat_actors": [
            "Cybercriminal groups using BYOVD with GeForce drivers",
            "Anti-cheat bypass actors in competitive gaming",
            "Malware distributors targeting NVIDIA App auto-update",
            "Hacktivists targeting NVIDIA brand (historical: Lapsus$ 2022)"
        ],
        "adversary_motivations": [
            "BYOVD: exploit vulnerable GeForce driver to kill EDR/AV",
            "Account credential theft from NVIDIA App users",
            "Malicious driver distribution via compromised update channel",
            "Anti-cheat bypass for competitive game cheating",
            "DLSS algorithm and model IP theft"
        ],
        "common_attack_surfaces": [
            "GeForce driver Windows IOCTL surface",
            "NVIDIA App auto-update mechanism",
            "GeForce driver update channel (Windows Update)",
            "NVIDIA App user authentication and account system",
            "Anti-cheat kernel module interface"
        ],
        "likely_attack_paths": [
            "BYOVD campaign: bundle vulnerable GeForce driver in malware dropper → kill EDR",
            "Compromise NVIDIA App update server → distribute trojanized driver update to millions",
            "Exploit NVIDIA App client authentication → mass account credential theft",
            "Kernel exploit via driver IOCTL → full system compromise on gaming endpoints"
        ],
        "intelligence_requirements": [
            "IR-1: BYOVD campaigns actively using GeForce driver versions (confirmed or suspected)",
            "IR-2: Malware campaigns targeting NVIDIA App users",
            "IR-3: Anti-cheat bypass techniques targeting NVIDIA kernel modules",
            "IR-4: GeForce driver distribution channel integrity threats"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Which GeForce driver versions are actively used in BYOVD campaigns? (Confidence: High)",
            "PIR-2: Are there active campaigns targeting NVIDIA App account credentials? (Confidence: Medium)",
            "PIR-3: Are there unpatched GeForce driver privilege escalation vulnerabilities with public PoC? (Confidence: High)"
        ],
        "early_warning_indicators": [
            "LOLDrivers.io listings of GeForce driver versions",
            "BYOVD campaign reports mentioning NVIDIA driver version numbers",
            "Security researcher PoC publications for GeForce driver vulnerabilities",
            "Malware sample analysis showing NVIDIA App impersonation",
            "Darkweb listings of NVIDIA App account credential databases"
        ],
        "relevant_ioc_types": [
            "GeForce driver versions listed in BYOVD campaigns (specific version strings)",
            "File hashes of known malicious NVIDIA driver installers",
            "NVIDIA App impersonation domains",
            "Credential stuffing IOCs targeting NVIDIA App accounts"
        ],
        "relevant_ttp_categories": [
            "Defense Evasion: Bring Your Own Vulnerable Driver (T1211 equivalent)",
            "Privilege Escalation: Exploitation for Privilege Escalation",
            "Persistence: Boot or Logon Autostart (driver)",
            "Initial Access: Drive-by Compromise (via gaming sites)"
        ],
        "mitre_attack_focus": [
            "T1068 Exploitation for Privilege Escalation",
            "T1211 Exploitation for Defense Evasion (BYOVD)",
            "T1553 Subvert Trust Controls",
            "T1189 Drive-by Compromise"
        ],
        "vulnerability_intelligence_focus": [
            "All GeForce driver IOCTL privilege escalation CVEs",
            "NVIDIA App authentication and client security",
            "Anti-cheat kernel module security",
            "GeForce driver installer package integrity"
        ],
        "supply_chain_risk_focus": [
            "GeForce driver distribution via Windows Update integrity",
            "NVIDIA App update server and CDN integrity",
            "Third-party gaming hardware that bundles GeForce drivers"
        ],
        "product_security_relevance": (
            "Core PSIRT responsibility. GeForce driver CVEs are high-volume and high-impact "
            "due to the consumer endpoint count. BYOVD threat intelligence must feed directly "
            "into PSIRT prioritization and expedited patching decisions."
        ),
        "telemetry_requirements": [
            "GeForce driver CVE patch adoption rate (via NVIDIA telemetry)",
            "NVIDIA App authentication anomaly logs",
            "Windows Update delivery anomalies for GeForce drivers",
            "Anti-cheat module integrity monitoring data"
        ],
        "hunting_opportunities": [
            "Hunt for vulnerable GeForce driver versions in enterprise endpoint inventories",
            "Hunt for NVIDIA driver load events not correlated with legitimate installer processes",
            "Hunt for NVIDIA App credential stuffing patterns in authentication logs"
        ],
        "detection_engineering_opportunities": [
            "Alert on GeForce driver versions below minimum secure version (per PSIRT advisory)",
            "Detect Windows kernel driver loads from non-standard NVIDIA installer paths",
            "Alert on NVIDIA App update requests to non-official CDN endpoints",
            "Detect suspicious processes loading NVIDIA driver via known BYOVD technique"
        ],
        "mitigation_recommendations": [
            "Maintain current GeForce driver versions per PSIRT advisory minimum",
            "Add known vulnerable GeForce driver versions to Windows Driver Block List",
            "Enable Windows HVCI to mitigate kernel driver exploitation",
            "Implement MFA for NVIDIA App accounts",
            "Monitor NVIDIA App update infrastructure for tampering"
        ],
        "engineering_follow_up_actions": [
            "Accelerate submission of vulnerable GeForce driver versions to Microsoft HVCI block list",
            "Publish GeForce BYOVD threat awareness guide for enterprise security teams",
            "Implement automatic vulnerability notification for NVIDIA App users with outdated drivers"
        ],
        "psirt_relevance": (
            "Critical. Highest PSIRT workload by volume. GeForce driver BYOVD exploitation "
            "is confirmed in the wild. Rapid patching cadence and HVCI block list coordination "
            "with Microsoft are essential operational tasks."
        ),
        "customer_risk_considerations": [
            "Consumer gamers rarely update drivers promptly — large vulnerable endpoint base",
            "Enterprise environments with gaming GPUs may have outdated GeForce drivers",
            "NVIDIA App account holders face credential theft risk requiring identity protection"
        ],
        "executive_summary_points": [
            "GeForce driver BYOVD exploitation is a confirmed, active threat to enterprise security",
            "Hundreds of millions of gaming endpoints run potentially outdated NVIDIA drivers",
            "NVIDIA App distribution infrastructure is a high-value supply chain target"
        ],
        "analyst_notes": (
            "BYOVD with NVIDIA drivers is confirmed in multiple public malware analysis reports. "
            "GeForce driver CVEs are regularly published by NVIDIA PSIRT. "
            "Lapsus$ breach of NVIDIA in 2022 exposed driver signing certificates — "
            "historical precedent for code signing infrastructure risk."
        ),
        "confidence_level": "High",
        "source_requirements": [
            "NVIDIA PSIRT advisories: GeForce drivers (all)",
            "LOLDrivers.io database for NVIDIA driver BYOVD listings",
            "Threat intelligence reports on BYOVD campaigns",
            "Microsoft HVCI driver block list updates",
            "CVE database: GeForce display and compute drivers"
        ],
        "pack_source": "nvidia",
    },
    # ── 15. Manufacturing / Industrial Supply Chain ────────────────────────────
    {
        "sector_id": "nvidia_manufacturing_supply_chain",
        "sector_name": "Manufacturing & Industrial Supply Chain",
        "sector_summary": (
            "Industrial manufacturers deploying NVIDIA GPUs and AI platforms for smart factory, "
            "predictive maintenance, quality inspection, and industrial automation. "
            "Includes NVIDIA Omniverse for digital twin and manufacturing simulation."
        ),
        "relevance_to_nvidia": (
            "NVIDIA Omniverse and Jetson are strategic platforms for industrial AI. "
            "Manufacturing sector attacks can disrupt production lines and potentially "
            "affect NVIDIA's own supply chain if OEM partners are targeted."
        ),
        "relevant_nvidia_products": [
            "NVIDIA Omniverse Enterprise", "NVIDIA Jetson for industrial edge",
            "NVIDIA Isaac for robotics", "NVIDIA Metropolis (visual AI)",
            "CUDA for industrial analytics", "NVIDIA AI Enterprise (industrial)"
        ],
        "crown_jewel_assets": [
            "Digital twin models (Omniverse) containing production IP",
            "Predictive maintenance AI models",
            "Industrial control system integrations via AI edge",
            "Manufacturing process optimization algorithms",
            "Supplier network and logistics data"
        ],
        "likely_threat_actors": [
            "Ransomware groups targeting manufacturing (Cl0p, LockBit historical targeting)",
            "Nation-state actors targeting critical manufacturing for economic disruption",
            "Industrial espionage actors targeting manufacturing AI IP",
            "Insiders with Omniverse or Jetson access"
        ],
        "adversary_motivations": [
            "Ransomware of manufacturing OT/IT convergence environment",
            "Digital twin IP theft (manufacturing processes, designs)",
            "Disruption of AI-driven production lines",
            "Persistent access to OT networks via Jetson edge devices"
        ],
        "common_attack_surfaces": [
            "Omniverse Enterprise server and collaboration platform",
            "Jetson edge devices connected to OT networks",
            "Industrial AI inference servers (Metropolis)",
            "IT/OT network boundary where AI edge devices reside",
            "Remote access for AI platform administration"
        ],
        "likely_attack_paths": [
            "Phish manufacturing IT → ransomware → encrypt Omniverse digital twin servers",
            "Compromise Jetson edge device → pivot to OT network → access PLC/SCADA",
            "Exfiltrate Omniverse digital twin data → steal manufacturing process IP",
            "Compromise Metropolis camera AI → blind quality inspection → product sabotage"
        ],
        "intelligence_requirements": [
            "IR-1: Ransomware campaigns targeting manufacturers using NVIDIA AI platforms",
            "IR-2: Omniverse vulnerabilities enabling digital twin data exfiltration",
            "IR-3: OT network pivot techniques via AI edge devices",
            "IR-4: Nation-state targeting of manufacturing AI for industrial espionage"
        ],
        "priority_intelligence_requirements": [
            "PIR-1: Are Omniverse Enterprise deployments targeted in ransomware campaigns? (Confidence: Medium)",
            "PIR-2: Are Jetson edge devices used as pivot points in IT/OT boundary attacks? (Confidence: Low)"
        ],
        "early_warning_indicators": [
            "Manufacturing sector ransomware activity with confirmed IT/OT impact",
            "Omniverse vulnerability research publications",
            "Jetson CVEs applicable to OT-connected deployments",
            "Reports of digital twin IP theft in industrial sectors"
        ],
        "relevant_ioc_types": [
            "Ransomware IOCs from groups targeting manufacturing",
            "Malware lateral movement indicators from IT/OT boundary",
            "Omniverse server anomalous access patterns"
        ],
        "relevant_ttp_categories": [
            "Initial Access: Phishing, Valid Accounts",
            "Lateral Movement: Exploitation of Remote Services (IT/OT pivot)",
            "Impact: Data Encrypted for Impact, Inhibit System Recovery",
            "Collection: Data from Information Repositories (digital twins)"
        ],
        "mitre_attack_focus": [
            "T1566 Phishing",
            "T1210 Exploitation of Remote Services",
            "T1486 Data Encrypted for Impact",
            "T1213 Data from Information Repositories"
        ],
        "vulnerability_intelligence_focus": [
            "Omniverse Enterprise server-side vulnerabilities",
            "Jetson Linux BSP CVEs relevant to OT environments",
            "Industrial AI inference platform security",
            "IT/OT boundary protocol vulnerabilities"
        ],
        "supply_chain_risk_focus": [
            "NVIDIA Omniverse extension marketplace (third-party extensions)",
            "Industrial AI model repositories used with Metropolis",
            "Third-party OT integrations with Jetson edge"
        ],
        "product_security_relevance": (
            "PSIRT scope: Omniverse Enterprise, Jetson BSP. "
            "Industrial/OT context requires conservative patch urgency and coordination "
            "with ICS security teams. Omniverse server vulnerabilities could leak "
            "critical manufacturing IP."
        ),
        "telemetry_requirements": [
            "Omniverse server access and collaboration audit logs",
            "Jetson device network connection monitoring",
            "Industrial AI inference platform anomaly detection",
            "IT/OT boundary firewall and IDS logs"
        ],
        "hunting_opportunities": [
            "Hunt for Omniverse servers with unexpected external connectivity",
            "Hunt for Jetson devices communicating with OT network segments outside approved paths",
            "Hunt for Omniverse large file exports outside normal collaboration workflows"
        ],
        "detection_engineering_opportunities": [
            "Alert on Omniverse server large asset exports",
            "Detect Jetson devices initiating connections to OT VLAN segments",
            "Alert on Metropolis camera AI platform configuration changes"
        ],
        "mitigation_recommendations": [
            "Segment Omniverse servers from general corporate networks",
            "Implement strict IT/OT boundary controls for Jetson edge devices",
            "Keep Omniverse and Jetson software current with NVIDIA PSIRT advisories",
            "Restrict Omniverse collaboration features to authenticated internal users"
        ],
        "engineering_follow_up_actions": [
            "Publish NVIDIA Omniverse Enterprise security hardening guide",
            "Develop IT/OT boundary deployment guidance for Jetson in manufacturing",
            "Engage Manufacturing ISAC on NVIDIA platform threat intelligence sharing"
        ],
        "psirt_relevance": (
            "Medium. Omniverse Enterprise and Jetson BSP are PSIRT scope. "
            "Industrial context requires coordination with ICS security community "
            "on vulnerability disclosure and patch deployment timelines."
        ),
        "customer_risk_considerations": [
            "Manufacturing customers have strict OT uptime requirements — patch coordination critical",
            "Digital twin IP is high-value competitive intelligence — data classification matters",
            "IT/OT convergence creates regulatory compliance implications in critical infrastructure"
        ],
        "executive_summary_points": [
            "Manufacturing AI deployments face acute ransomware risk at the IT/OT boundary",
            "Omniverse digital twin data represents valuable industrial IP for exfiltration",
            "Jetson edge devices in OT environments create persistent IT/OT pivot risk"
        ],
        "analyst_notes": (
            "Manufacturing ransomware is confirmed and growing. NVIDIA-specific targeting in "
            "manufacturing is not confirmed in public reporting. Risk model extrapolated from "
            "ICS/OT threat landscape and NVIDIA's platform presence in smart factory deployments."
        ),
        "confidence_level": "Medium",
        "source_requirements": [
            "Manufacturing ISAC (MFG-ISAC) advisories",
            "ICS-CERT advisories on OT network attacks",
            "NVIDIA PSIRT advisories: Omniverse, Jetson",
            "Industrial cybersecurity research (Dragos, Claroty public reports)"
        ],
        "pack_source": "nvidia",
    },
]


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

async def ensure_sector_packs(db: AsyncSession) -> int:
    """Seed the sector_packs table with NVIDIA packs if not already present. Returns count inserted."""
    inserted = 0
    for pack_data in NVIDIA_SECTOR_PACKS:
        result = await db.execute(
            select(SectorPack).where(SectorPack.sector_id == pack_data["sector_id"])
        )
        existing = result.scalar_one_or_none()
        if existing is None:
            pack = SectorPack(**pack_data)
            db.add(pack)
            inserted += 1
    if inserted:
        await db.commit()
    return inserted


async def list_sector_packs(
    db: AsyncSession,
    pack_source: str | None = None,
    confidence_level: str | None = None,
) -> list[SectorPack]:
    """Return all sector packs, optionally filtered."""
    query = select(SectorPack)
    if pack_source:
        query = query.where(SectorPack.pack_source == pack_source)
    if confidence_level:
        query = query.where(SectorPack.confidence_level == confidence_level)
    query = query.order_by(SectorPack.sector_name)
    result = await db.execute(query)
    return list(result.scalars().all())


async def get_sector_pack(db: AsyncSession, sector_id: str) -> SectorPack | None:
    """Return a single sector pack by sector_id."""
    result = await db.execute(
        select(SectorPack).where(SectorPack.sector_id == sector_id)
    )
    return result.scalar_one_or_none()
