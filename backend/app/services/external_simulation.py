from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass(frozen=True)
class Simulation:
    id: str
    technique_id: str
    name: str
    category: str
    risk_level: int
    target_types: list[str]
    description: str
    expected_telemetry: list[str]
    safety_controls: list[str]
    steps: list[str]
    destructive: bool = False
    emits_network_traffic: bool = False


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    address: str
    target_type: str
    environment: str
    owner: str
    authorization: str
    allowed_categories: list[str]
    allowed_simulations: list[str] = field(default_factory=list)
    rate_limit: str = "dry-run only"
    allowed_hours: str = "lab approval required"


SIMULATIONS: list[Simulation] = [
    Simulation(
        id="sim-t1595-http-fingerprint",
        technique_id="T1595",
        name="HTTP/TLS service fingerprint plan",
        category="reconnaissance",
        risk_level=0,
        target_types=["http", "https", "web"],
        description="Prepare a safe external-service fingerprint validation for approved web targets.",
        expected_telemetry=["web access log", "WAF log", "firewall allow/deny", "source IP"],
        safety_controls=["target allowlist", "dry-run first", "no payloads", "rate limit", "analyst review"],
        steps=[
            "Confirm target authorization and maintenance window.",
            "Prepare one HTTP HEAD/GET root request and one TLS metadata observation.",
            "Verify web/WAF/firewall telemetry ingestion.",
            "Record whether the detection fired or the telemetry was only observed.",
        ],
    ),
    Simulation(
        id="sim-t1190-web-exposure",
        technique_id="T1190",
        name="Public web exposure validation plan",
        category="initial-access-surface",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Validate visibility for benign public-facing web exposure checks without exploit payloads.",
        expected_telemetry=["web access log", "WAF log", "application access log"],
        safety_controls=["no exploit payload", "no fuzzing", "target allowlist", "single request set"],
        steps=[
            "Review target technology and allowed URL paths.",
            "Prepare benign requests for /, /robots.txt, /.well-known/security.txt.",
            "Do not submit forms or payloads.",
            "Capture expected log fields: path, status, user-agent, source IP.",
        ],
    ),
    Simulation(
        id="sim-t1133-remote-service-reachability",
        technique_id="T1133",
        name="External remote service reachability plan",
        category="remote-access",
        risk_level=1,
        target_types=["vpn", "ssh", "rdp", "remote-service"],
        description="Validate telemetry for approved remote-service reachability checks.",
        expected_telemetry=["firewall deny/allow", "VPN gateway log", "remote access service log"],
        safety_controls=["no authentication attempts", "no brute force", "target allowlist", "single connection intent"],
        steps=[
            "Confirm service and port are approved for reachability validation.",
            "Prepare one low-rate connection attempt without credentials.",
            "Validate firewall and remote-access telemetry.",
            "Record whether alerting exists for unexpected external reachability.",
        ],
    ),
    Simulation(
        id="sim-t1071-controlled-beacon",
        technique_id="T1071",
        name="Controlled HTTP/DNS beacon validation plan",
        category="c2-emulation",
        risk_level=2,
        target_types=["lab-agent", "egress"],
        description="Plan a controlled beacon from a lab agent to a controlled endpoint.",
        expected_telemetry=["DNS resolver log", "proxy log", "NDR metadata", "EDR network event"],
        safety_controls=["lab agent only", "controlled endpoint only", "no malware", "fixed interval cap"],
        steps=[
            "Confirm the target is a lab agent, not a production host.",
            "Prepare a fixed benign HTTP or DNS callback to a controlled domain.",
            "Validate proxy/DNS/NDR/EDR telemetry.",
            "Document periodicity, source process, and destination context.",
        ],
    ),
    Simulation(
        id="sim-t1110-lab-login-sequence",
        technique_id="T1110",
        name="Lab-only failed-login sequence plan",
        category="credential-access",
        risk_level=2,
        target_types=["identity-lab", "sso-lab"],
        description="Plan low-rate failed logins against a lab-only identity target and test account.",
        expected_telemetry=["IdP sign-in log", "MFA log", "VPN/SSO log", "SIEM identity alert"],
        safety_controls=["lab-only target", "test account only", "low rate", "no real users", "explicit approval"],
        steps=[
            "Confirm the identity target is lab-only and uses a test account.",
            "Prepare a low-rate failed-login sequence.",
            "Do not target real users or production identity providers.",
            "Validate failed-login sequence telemetry and alerting.",
        ],
    ),
]

TARGETS: list[Target] = [
    Target(
        id="lab-web-01",
        name="Approved lab web target",
        address="https://lab-web-01.example.test",
        target_type="web",
        environment="lab",
        owner="security-team",
        authorization="approved-lab-fixture",
        allowed_categories=["reconnaissance", "initial-access-surface"],
        allowed_simulations=["sim-t1595-http-fingerprint", "sim-t1190-web-exposure"],
    ),
    Target(
        id="lab-idp-01",
        name="Approved lab identity target",
        address="https://idp-lab.example.test",
        target_type="identity-lab",
        environment="lab",
        owner="identity-security",
        authorization="approved-lab-fixture",
        allowed_categories=["credential-access"],
        allowed_simulations=["sim-t1110-lab-login-sequence"],
    ),
    Target(
        id="lab-egress-agent",
        name="Approved lab egress agent",
        address="agent://lab-egress-agent",
        target_type="lab-agent",
        environment="lab",
        owner="detection-engineering",
        authorization="approved-lab-fixture",
        allowed_categories=["c2-emulation"],
        allowed_simulations=["sim-t1071-controlled-beacon"],
    ),
]


def list_simulations() -> list[dict]:
    return [_simulation_dict(item) for item in SIMULATIONS]


def list_targets() -> list[dict]:
    return [_target_dict(item) for item in TARGETS]


def get_simulation(simulation_id: str) -> Simulation | None:
    return next((item for item in SIMULATIONS if item.id == simulation_id), None)


def get_target(target_id: str) -> Target | None:
    return next((item for item in TARGETS if item.id == target_id), None)


def build_plan(simulation_id: str, target_id: str) -> dict:
    simulation = get_simulation(simulation_id)
    target = get_target(target_id)
    if not simulation or not target:
        raise ValueError("Unknown simulation or target")
    allowed, reasons = is_allowed(simulation, target)
    return {
        "plan_id": f"plan-{uuid4()}",
        "simulation": _simulation_dict(simulation),
        "target": _target_dict(target),
        "allowed": allowed,
        "block_reasons": reasons,
        "execution_mode": "dry_run_required",
        "safety_notice": (
            "This MVP prepares and records validation simulations only. It does not run exploit payloads, "
            "does not accept arbitrary commands, and does not emit external traffic from the API container."
        ),
        "expected_telemetry": simulation.expected_telemetry,
        "steps": simulation.steps,
        "approval_checklist": [
            "Target allowlist entry is registered and approved.",
            "Simulation category is allowed for target.",
            "Analyst reviewed dry-run plan.",
            "Expected telemetry owner is known.",
            "Cleanup and stop criteria are documented.",
        ],
    }


def run_controlled_record(simulation_id: str, target_id: str, analyst_note: str = "") -> dict:
    plan = build_plan(simulation_id, target_id)
    now = datetime.now(timezone.utc).isoformat()
    if not plan["allowed"]:
        return {
            "run_id": f"run-{uuid4()}",
            "status": "blocked",
            "started_at": now,
            "ended_at": now,
            "plan": plan,
            "transcript": ["Simulation blocked by safety policy before execution."],
            "traffic_emitted": False,
            "result": "not_run",
            "validation_status": "not_proven",
            "gaps": plan["block_reasons"],
        }

    simulation = plan["simulation"]
    target = plan["target"]
    transcript = [
        f"Prepared {simulation['id']} for target {target['id']}.",
        "Verified target allowlist and simulation-category policy.",
        "Generated expected telemetry checklist.",
        "No network traffic emitted by the AdversaryGraph API MVP runner.",
        "Analyst must attach external lab evidence before marking detection coverage as passed.",
    ]
    if analyst_note:
        transcript.append(f"Analyst note: {analyst_note}")
    return {
        "run_id": f"run-{uuid4()}",
        "status": "completed_record_only",
        "started_at": now,
        "ended_at": now,
        "plan": plan,
        "transcript": transcript,
        "traffic_emitted": False,
        "result": "telemetry_validation_record_prepared",
        "validation_status": "not_proven",
        "gaps": [
            "No external traffic was emitted by this MVP runner.",
            "Attach SIEM, WAF, firewall, DNS, proxy, EDR, or IdP evidence from an authorized lab run.",
            "Mark as passed only after telemetry and detection firing are verified.",
        ],
        "next_steps": [
            "Run the approved simulation from an isolated lab runner.",
            "Upload or paste observed telemetry evidence.",
            "Record detection result as passed, failed, partial, or not proven.",
        ],
    }


def is_allowed(simulation: Simulation, target: Target) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if simulation.destructive:
        reasons.append("Destructive simulations are disabled.")
    if target.environment != "lab":
        reasons.append("Only lab targets are allowed in the MVP.")
    if simulation.id not in target.allowed_simulations:
        reasons.append("Simulation is not allowlisted for this target.")
    if simulation.category not in target.allowed_categories:
        reasons.append("Simulation category is not allowed for this target.")
    if target.target_type not in simulation.target_types:
        reasons.append("Target type does not match simulation target types.")
    if simulation.risk_level > 2:
        reasons.append("Risk level above 2 is disabled.")
    return not reasons, reasons


def _simulation_dict(item: Simulation) -> dict:
    return {
        "id": item.id,
        "technique_id": item.technique_id,
        "name": item.name,
        "category": item.category,
        "risk_level": item.risk_level,
        "target_types": item.target_types,
        "description": item.description,
        "expected_telemetry": item.expected_telemetry,
        "safety_controls": item.safety_controls,
        "steps": item.steps,
        "destructive": item.destructive,
        "emits_network_traffic": item.emits_network_traffic,
    }


def _target_dict(item: Target) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "address": item.address,
        "target_type": item.target_type,
        "environment": item.environment,
        "owner": item.owner,
        "authorization": item.authorization,
        "allowed_categories": item.allowed_categories,
        "allowed_simulations": item.allowed_simulations,
        "rate_limit": item.rate_limit,
        "allowed_hours": item.allowed_hours,
    }
