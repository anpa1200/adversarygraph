"""
Keyword-based tagger: maps signal text to NVIDIA sector_ids and tech categories.
All matching is case-insensitive substring search against title + body.
"""
from __future__ import annotations

import re

# ── Sector keyword map ────────────────────────────────────────────────────────
# Keys must match sector_id values in sector_packs table.

SECTOR_KEYWORDS: dict[str, list[str]] = {
    "nvidia_firmware_drivers": [
        "nvidia driver", "nvidia display driver", "cuda driver",
        "nvflash", "vbios", "geforce driver", "nvlddmkm", "nvkflt",
        "nvidia gpu driver", "driver privilege escalation", "nvidia kernel module",
        "byovd", "bring your own vulnerable driver",
    ],
    "nvidia_accelerated_computing": [
        "cuda", "cublas", "cudnn", "cufft", "cusparse", "curand",
        "tensorrt", "nccl", "cuda toolkit", "nvcc", "cuda runtime",
        "opencl nvidia", "nvidia compute", "gpu compute",
    ],
    "nvidia_ai_data_centers": [
        "h100", "h200", "a100", "gb200", "nvl72",
        "nvidia hgx", "nvidia dgx", "sxm gpu", "hopper gpu",
        "blackwell gpu", "nvidia ai data center", "gpu cluster",
        "nvidia tensor core",
    ],
    "nvidia_ai_networking_fabric": [
        "infiniband", "mellanox", "connectx", "ufm",
        "mlnx_ofed", "rdma", "nvlink switch",
        "spectrum-x", "hdr infiniband", "ndr infiniband",
        "nvidia networking", "unified fabric manager",
    ],
    "nvidia_dpu_smartnic": [
        "bluefield", "doca", "smartnic", "data processing unit",
        "bluefield-2", "bluefield-3", "nvidia dpu", "nvidia bf2", "nvidia bf3",
    ],
    "nvidia_gaming_rtx": [
        "geforce rtx", "geforce gtx", "game ready driver",
        "nvidia shadowplay", "dlss", "geforce experience",
        "nvidia app", "rtx 4090", "rtx 5090", "rtx 3090",
        "rtx 4080", "rtx 4070", "rtx 5080",
    ],
    "nvidia_autonomous_vehicles": [
        "drive agx", "driveworks", "drive os", "drive thor",
        "drive xavier", "nvidia drive", "nvidia automotive",
    ],
    "nvidia_healthcare_ai": [
        "nvidia clara", "clara imaging", "holoscan",
        "igx orin", "bionemo", "parabricks", "nvidia healthcare",
    ],
    "nvidia_cloud_hyperscale": [
        "vgpu", "nvidia grid", "triton inference server",
        "nim microservices", "gpu virtualization",
        "triton server", "nvidia vgpu",
    ],
    "nvidia_enterprise_ai": [
        "nvidia ai enterprise", "base command manager",
        "nvaie", "ngc catalog", "nvidia nim",
        "nvidia nemo", "nvidia riva",
    ],
    "nvidia_hpc_supercomputing": [
        "nvidia hpc sdk", "nvhpc", "magnum io",
        "openacc nvidia", "nvidia supercomputer",
    ],
    "nvidia_telecom_5g_edge": [
        "nvidia aerial", "aerial sdk", "vran nvidia",
        "o-ran nvidia", "ai-ran", "5g gpu acceleration",
    ],
    "nvidia_robotics": [
        "jetson", "isaac ros", "isaac sim",
        "jetson orin", "jetson nano", "nvidia isaac",
        "jetson xavier", "jetson agx",
    ],
    "nvidia_semiconductor_supply_chain": [
        "nvidia supply chain", "counterfeit nvidia",
        "nvidia hardware trojan", "nvidia foundry",
    ],
    "nvidia_manufacturing_supply_chain": [
        "nvidia omniverse", "omniverse enterprise",
        "nvidia metropolis", "digital twin nvidia",
    ],
}

# General NVIDIA signals — tag to all relevant sectors based on further matching
NVIDIA_GENERAL: list[str] = ["nvidia", "nvda", "nvml", "nvapi"]

# ── Tech category keyword map ─────────────────────────────────────────────────

TECH_KEYWORDS: dict[str, list[str]] = {
    "privilege_escalation": [
        "privilege escalation", "local privilege", "lpe", "elevation of privilege",
        "eop", "nt authority", "ring0", "kernel privilege",
    ],
    "remote_code_execution": [
        "remote code execution", "rce", "arbitrary code execution",
        "code injection", "command injection",
    ],
    "memory_corruption": [
        "buffer overflow", "use-after-free", "heap overflow",
        "memory corruption", "uaf", "stack overflow", "out-of-bounds write",
        "heap spray", "type confusion",
    ],
    "byovd": [
        "byovd", "bring your own vulnerable driver",
        "vulnerable driver", "driver blocklist",
    ],
    "firmware": [
        "firmware vulnerability", "uefi", "bios exploit", "bmc vulnerability",
        "ipmi", "baseboard management", "secure boot bypass", "vbios",
    ],
    "supply_chain": [
        "supply chain attack", "dependency confusion", "typosquatting",
        "malicious package", "pypi malware", "npm malware", "conda malware",
        "compromised package", "backdoored package",
    ],
    "side_channel": [
        "side channel", "spectre", "meltdown", "rowhammer",
        "cache timing", "transient execution", "speculative execution",
        "gpu side channel",
    ],
    "container_escape": [
        "container escape", "docker escape", "namespace escape",
        "cgroup escape", "kubernetes escape", "pod escape",
    ],
    "ransomware": [
        "ransomware", "data encrypted for impact",
        "lockbit", "blackcat", "cl0p", "akira", "alphv",
    ],
    "crypto_mining": [
        "cryptomining", "crypto mining", "coinminer",
        "xmrig", "monero mining", "illicit mining",
    ],
    "authentication_bypass": [
        "authentication bypass", "auth bypass",
        "unauthenticated access", "default credentials",
        "weak authentication", "token forgery",
    ],
    "ai_model_security": [
        "model poisoning", "adversarial attack", "model theft",
        "prompt injection", "llm jailbreak", "training data poisoning",
        "model inversion", "membership inference",
    ],
    "ot_ics": [
        "scada", "plc", "industrial control", "operational technology",
        "ics vulnerability", "modbus", "dnp3", "profinet",
    ],
}

# ── CVE extraction regex ──────────────────────────────────────────────────────

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    return list({m.upper() for m in _CVE_RE.findall(text)})


def tag_signal(title: str, body: str) -> dict[str, list[str]]:
    """Return sector_tags, tech_tags extracted from title + body."""
    haystack = (title + " " + body).lower()

    sector_tags: list[str] = []
    for sector_id, keywords in SECTOR_KEYWORDS.items():
        if any(kw.lower() in haystack for kw in keywords):
            sector_tags.append(sector_id)

    # If "nvidia" appears but no specific sector matched, tag all High-confidence sectors
    if not sector_tags and any(kw in haystack for kw in NVIDIA_GENERAL):
        sector_tags = ["nvidia_firmware_drivers", "nvidia_accelerated_computing"]

    tech_tags: list[str] = []
    for tech_id, keywords in TECH_KEYWORDS.items():
        if any(kw.lower() in haystack for kw in keywords):
            tech_tags.append(tech_id)

    return {"sector_tags": sector_tags, "tech_tags": tech_tags}
