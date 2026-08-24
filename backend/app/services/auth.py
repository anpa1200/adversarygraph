import hashlib
import hmac
import os
import secrets
import base64
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.auth import AccessGroup, AuthSession, UserAccessGroup, UserAccount
from app.models.pipeline import AuditEvent

VALID_ROLES = {
    "viewer",
    "analyst",
    "admin",
    "security_admin",
    "threat_intel",
    "detection_engineer",
    "incident_responder",
    "auditor",
    "service_account",
}
SESSION_COOKIE = "ag_session"
PBKDF2_ITERATIONS = 260_000
ALL_PERMISSIONS = {
    "read",
    "run_analysis",
    "review_reports",
    "promote_reports",
    "manage_intel",
    "manage_detections",
    "run_attack_simulation",
    "manage_feeds",
    "forward_siem",
    "upload_files",
    "export_data",
    "manage_users",
    "manage_auth",
    "view_audit",
}
MODULE_CATALOG = {
    "discover": ("Discover", "/discover", "Workspace"),
    "threat_radar": ("Threat Radar", "/threat-radar", "Intelligence"),
    "reports_research": ("Reports / Research", "/reports-research", "Intelligence"),
    "apt_library": ("ATT&CK Group Library", "/apt", "Intelligence"),
    "sector_intel": ("Sector Intelligence", "/sector-intel", "Intelligence"),
    "knowledge": ("Knowledge Library", "/knowledge", "Intelligence"),
    "ioc_library": ("IOC Library", "/ioc-library", "Intelligence"),
    "cve_library": ("CVE Library", "/cve", "Intelligence"),
    "retrohunt": ("RetroHunt Signals", "/retrohunt", "Intelligence"),
    "ai_analysis": ("AI Analysis", "/analyze", "Analyze & Investigate"),
    "navigator": ("Navigator", "/navigator", "Analyze & Investigate"),
    "compare": ("Compare", "/compare", "Analyze & Investigate"),
    "ioc_investigation": ("IOC Investigation", "/ioc-investigation", "Analyze & Investigate"),
    "malware_analysis": ("Malware Analysis", "/malware-analysis", "Analyze & Investigate"),
    "virustotal": ("VirusTotal Lookup", "/virustotal", "Analyze & Investigate"),
    "asset_surface": ("Asset Surface", "/asset-surface", "Analyze & Investigate"),
    "emb3d": ("EMB3D", "/emb3d", "Analyze & Investigate"),
    "evidence_graph": ("Evidence Graph", "/evidence-graph", "Analyze & Investigate"),
    "threat_hunting": ("Threat Hunting", "/threat-hunting", "Hunt & Validate"),
    "query_library": ("Query Library", "/query-library", "Hunt & Validate"),
    "attack_simulation": ("Attack Simulation", "/attack-simulation", "Hunt & Validate"),
    "investigation": ("Investigation", "/report", "Hunt & Validate"),
    "operations": ("Operations", "/operations", "Operations"),
    "pipeline": ("Pipeline", "/pipeline", "Operations"),
    "statistics": ("Statistics", "/statistics", "Operations"),
    "feeds": ("Feeds Management", "/feeds", "Platform"),
    "observability": ("Observability", "/observability", "Platform"),
    "admin": ("Administration", "/admin", "Platform"),
    "examples": ("DFIR Examples", "/examples", "Learn & Support"),
    "help": ("Help / Local Guide", "/help", "Learn & Support"),
    "troubleshooting": ("Troubleshooting", "/troubleshooting", "Learn & Support"),
}
ALL_MODULES = set(MODULE_CATALOG)
ROLE_PERMISSIONS = {
    "viewer": {"read"},
    "auditor": {"read", "view_audit", "export_data"},
    "analyst": {"read", "run_analysis", "review_reports", "manage_intel", "upload_files", "export_data"},
    "threat_intel": {"read", "run_analysis", "review_reports", "promote_reports", "manage_intel", "manage_feeds", "upload_files", "export_data"},
    "detection_engineer": {"read", "run_analysis", "manage_detections", "run_attack_simulation", "forward_siem", "export_data"},
    "incident_responder": {"read", "run_analysis", "review_reports", "manage_intel", "run_attack_simulation", "forward_siem", "upload_files", "export_data"},
    "service_account": {"read", "run_analysis", "manage_feeds", "forward_siem", "export_data"},
    "security_admin": {"read", "run_analysis", "review_reports", "promote_reports", "manage_intel", "manage_detections", "run_attack_simulation", "manage_feeds", "forward_siem", "upload_files", "export_data", "manage_auth", "view_audit"},
    "admin": set(ALL_PERMISSIONS),
}

_READER_MODULES = {
    "discover", "reports_research", "apt_library", "sector_intel", "knowledge",
    "ioc_library", "cve_library", "navigator", "compare", "examples", "help",
    "troubleshooting",
}
_ANALYST_MODULES = ALL_MODULES - {"feeds", "admin"}
ROLE_MODULES = {
    "viewer": set(_READER_MODULES),
    "auditor": {
        "discover", "reports_research", "knowledge", "ioc_library", "cve_library",
        "statistics", "observability", "admin", "examples", "help", "troubleshooting",
    },
    "analyst": set(_ANALYST_MODULES),
    "threat_intel": set(_ANALYST_MODULES) | {"feeds"},
    "detection_engineer": {
        "discover", "reports_research", "knowledge", "ioc_library", "cve_library",
        "navigator", "compare", "evidence_graph", "threat_hunting", "query_library",
        "attack_simulation", "investigation", "operations", "pipeline", "statistics",
        "examples", "help", "troubleshooting",
    },
    "incident_responder": set(_ANALYST_MODULES),
    "service_account": set(ALL_MODULES - {"admin"}),
    "security_admin": set(ALL_MODULES),
    "admin": set(ALL_MODULES),
}

DEFAULT_ACCESS_GROUPS = {
    "soc-manager": {
        "name": "SOC Manager",
        "description": "Owns SOC workflows, investigations, hunting, validation, reporting, and operational oversight without platform-configuration authority.",
        "permissions": {
            "read", "run_analysis", "manage_intel", "manage_detections",
            "run_attack_simulation", "forward_siem", "upload_files",
            "export_data", "view_audit", "review_reports", "promote_reports",
        },
        "modules": ALL_MODULES - {"feeds", "admin"},
    },
    "soc-tier-1": {
        "name": "SOC Tier 1 — Triage",
        "description": "Minimum triage workspace for IOC investigation, alert context, evidence intake, reporting, and escalation.",
        "permissions": {"read", "run_analysis", "upload_files", "export_data"},
        "modules": {
            "discover", "reports_research", "knowledge", "ioc_library",
            "ioc_investigation", "virustotal", "investigation", "examples",
            "help", "troubleshooting",
        },
    },
    "soc-tier-2": {
        "name": "SOC Tier 2 — Investigation",
        "description": "Expanded investigation and correlation access for escalated alerts, assets, vulnerabilities, actors, and evidence.",
        "permissions": {"read", "run_analysis", "review_reports", "manage_intel", "upload_files", "export_data"},
        "modules": {
            "discover", "threat_radar", "reports_research", "apt_library",
            "sector_intel", "knowledge", "ioc_library", "cve_library", "retrohunt",
            "ai_analysis", "navigator", "compare", "ioc_investigation",
            "malware_analysis", "virustotal", "asset_surface", "emb3d",
            "evidence_graph", "investigation", "statistics", "examples", "help",
            "troubleshooting",
        },
    },
    "soc-tier-3": {
        "name": "SOC Tier 3 — Advanced Analysis",
        "description": "Advanced incident, malware, threat-hunting, query, detection-validation, and response-engineering access.",
        "permissions": {
            "read", "run_analysis", "manage_intel", "manage_detections",
            "run_attack_simulation", "forward_siem", "upload_files", "export_data",
            "review_reports",
        },
        "modules": ALL_MODULES - {"feeds", "admin", "observability"},
    },
    "threat-intelligence": {
        "name": "Threat Intelligence",
        "description": "Curates reports, actors, sectors, IOCs, vulnerabilities, ATT&CK mappings, and evidence.",
        "permissions": {"read", "run_analysis", "review_reports", "promote_reports", "manage_intel", "upload_files", "export_data"},
        "modules": {
            "discover", "threat_radar", "reports_research", "apt_library",
            "sector_intel", "knowledge", "ioc_library", "cve_library", "retrohunt",
            "ai_analysis", "navigator", "compare", "ioc_investigation",
            "virustotal", "asset_surface", "evidence_graph", "investigation",
            "examples", "help", "troubleshooting",
        },
    },
    "threat-hunting": {
        "name": "Threat Hunting",
        "description": "Builds hypotheses and detection queries, correlates evidence, and records hunt outcomes.",
        "permissions": {"read", "run_analysis", "manage_detections", "upload_files", "export_data"},
        "modules": {
            "discover", "reports_research", "apt_library", "knowledge",
            "ioc_library", "cve_library", "retrohunt", "ai_analysis", "navigator",
            "compare", "ioc_investigation", "evidence_graph", "threat_hunting",
            "query_library", "investigation", "statistics", "examples", "help",
            "troubleshooting",
        },
    },
    "detection-engineering": {
        "name": "Detection Engineering",
        "description": "Engineers queries, validates detections with controlled simulations, and manages detection pipelines.",
        "permissions": {
            "read", "run_analysis", "manage_detections", "run_attack_simulation",
            "forward_siem", "export_data",
        },
        "modules": {
            "discover", "reports_research", "knowledge", "ioc_library",
            "cve_library", "navigator", "compare", "evidence_graph",
            "threat_hunting", "query_library", "attack_simulation",
            "investigation", "operations", "pipeline", "statistics", "examples",
            "help", "troubleshooting",
        },
    },
    "incident-response": {
        "name": "Incident Response / DFIR",
        "description": "Investigates IOCs and malware, preserves evidence, coordinates response, and produces incident reports.",
        "permissions": {
            "read", "run_analysis", "manage_intel", "run_attack_simulation",
            "forward_siem", "upload_files", "export_data", "review_reports",
        },
        "modules": {
            "discover", "threat_radar", "reports_research", "knowledge",
            "ioc_library", "cve_library", "retrohunt", "ai_analysis", "navigator",
            "compare", "ioc_investigation", "malware_analysis", "virustotal",
            "asset_surface", "emb3d", "evidence_graph", "threat_hunting",
            "query_library", "attack_simulation", "investigation", "operations",
            "statistics", "examples", "help", "troubleshooting",
        },
    },
    "vulnerability-management": {
        "name": "Vulnerability Management",
        "description": "Assesses inventory, attack surface, CVE exposure, prioritization, and remediation evidence.",
        "permissions": {"read", "run_analysis", "manage_intel", "upload_files", "export_data"},
        "modules": {
            "discover", "threat_radar", "reports_research", "knowledge",
            "ioc_library", "cve_library", "retrohunt", "navigator",
            "asset_surface", "emb3d", "evidence_graph", "investigation",
            "statistics", "examples", "help", "troubleshooting",
        },
    },
    "feed-operators": {
        "name": "Intelligence Feed Operators",
        "description": "Maintains ATT&CK, IOC, CVE, and enrichment feeds without user or authentication administration.",
        "permissions": {"read", "manage_intel", "manage_feeds", "view_audit"},
        "modules": {"discover", "ioc_library", "cve_library", "feeds", "observability", "help", "troubleshooting"},
    },
    "audit-read-only": {
        "name": "Audit / Read Only",
        "description": "Read-only assurance access to reports, statistics, operational health, and audit evidence.",
        "permissions": {"read", "view_audit", "export_data"},
        "modules": {
            "discover", "reports_research", "knowledge", "ioc_library",
            "cve_library", "statistics", "observability", "examples", "help",
            "troubleshooting",
        },
    },
    "platform-administrators": {
        "name": "Platform Administrators",
        "description": "Full platform, identity, feed, security, and configuration administration.",
        "permissions": set(ALL_PERMISSIONS),
        "modules": set(ALL_MODULES),
    },
}


@dataclass
class TeamUser:
    name: str
    roles: list[str]
    user_id: str = ""
    auth_source: str = "local"
    permissions: list[str] | None = None
    modules: list[str] | None = None
    groups: list[str] | None = None


def normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in VALID_ROLES:
        raise HTTPException(422, f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    return normalized


def normalize_permissions(permissions: list[str] | None) -> list[str]:
    cleaned = sorted({item.strip() for item in permissions or [] if item and item.strip()})
    invalid = [item for item in cleaned if item not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(422, f"Unknown permissions: {', '.join(invalid)}")
    return cleaned


def normalize_modules(modules: list[str] | None) -> list[str]:
    cleaned = sorted({item.strip() for item in modules or [] if item and item.strip()})
    invalid = [item for item in cleaned if item not in ALL_MODULES]
    if invalid:
        raise HTTPException(422, f"Unknown modules: {', '.join(invalid)}")
    return cleaned


def normalize_group_slug(value: str) -> str:
    normalized = value.strip().lower()
    if (
        not normalized
        or len(normalized) > 80
        or not normalized[0].isalnum()
        or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in normalized)
    ):
        raise HTTPException(
            422,
            "Group slug must be 1-80 lowercase letters, numbers, or hyphens and start with a letter or number",
        )
    return normalized


def module_catalog_out() -> list[dict[str, str]]:
    return [
        {
            "key": key,
            "label": value[0],
            "route": value[1],
            "category": value[2],
        }
        for key, value in MODULE_CATALOG.items()
    ]


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


_DUMMY_PASSWORD_HASH = hash_password(
    "adversarygraph-invalid-account-password",
    salt=b"\x00" * 16,
)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def roles_for(role: str) -> list[str]:
    role = normalize_role(role)
    if role == "admin":
        return ["admin", "analyst", "viewer"]
    if role == "security_admin":
        return ["security_admin", "analyst", "viewer"]
    if role in {"threat_intel", "detection_engineer", "incident_responder", "service_account"}:
        return [role, "analyst", "viewer"]
    if role == "auditor":
        return ["auditor", "viewer"]
    if role == "analyst":
        return ["analyst", "viewer"]
    return ["viewer"]


def permissions_for(role: str, extra_permissions: list[str] | None = None) -> list[str]:
    normalized = normalize_role(role)
    permissions = set(ROLE_PERMISSIONS.get(normalized, {"read"}))
    permissions.update(normalize_permissions(extra_permissions))
    return sorted(permissions)


def modules_for(role: str, group_modules: list[str] | None = None) -> list[str]:
    normalized = normalize_role(role)
    if normalized == "admin":
        return sorted(ALL_MODULES)
    # Once an account is assigned to groups, those groups become the source of
    # module visibility. Ungrouped legacy accounts retain their role defaults.
    if group_modules is not None:
        return normalize_modules(group_modules)
    return sorted(ROLE_MODULES.get(normalized, _READER_MODULES))


async def load_user_groups(
    db: AsyncSession,
    user_id: UUID,
    *,
    include_disabled: bool = False,
) -> list[AccessGroup]:
    membership_rows = await db.execute(
        select(UserAccessGroup).where(UserAccessGroup.user_id == user_id)
    )
    group_ids = [row.group_id for row in membership_rows.scalars().all()]
    if not group_ids:
        return []
    group_rows = await db.execute(
        select(AccessGroup).where(AccessGroup.id.in_(group_ids)).order_by(AccessGroup.name.asc())
    )
    groups = group_rows.scalars().all()
    if include_disabled:
        return list(groups)
    return [group for group in groups if group.enabled]


def group_permissions(groups: list[AccessGroup]) -> list[str]:
    return sorted({
        permission
        for group in groups
        for permission in normalize_permissions(list(group.permissions or []))
    })


def group_modules(groups: list[AccessGroup]) -> list[str]:
    return sorted({
        module
        for group in groups
        for module in normalize_modules(list(group.modules or []))
    })


async def replace_user_groups(
    db: AsyncSession,
    user_id: UUID,
    group_ids: list[UUID],
    *,
    assigned_by: str,
) -> list[AccessGroup]:
    requested_ids = list(dict.fromkeys(group_ids))
    groups: list[AccessGroup] = []
    if requested_ids:
        rows = await db.execute(select(AccessGroup).where(AccessGroup.id.in_(requested_ids)))
        groups = list(rows.scalars().all())
        found = {group.id for group in groups}
        missing = [str(group_id) for group_id in requested_ids if group_id not in found]
        if missing:
            raise HTTPException(422, f"Unknown access groups: {', '.join(missing)}")
        disabled = [group.name for group in groups if not group.enabled]
        if disabled:
            raise HTTPException(422, f"Disabled access groups cannot be assigned: {', '.join(disabled)}")

    existing_rows = await db.execute(
        select(UserAccessGroup).where(UserAccessGroup.user_id == user_id)
    )
    for membership in existing_rows.scalars().all():
        await db.delete(membership)
    for group_id in requested_ids:
        db.add(UserAccessGroup(
            user_id=user_id,
            group_id=group_id,
            assigned_by=assigned_by,
        ))
    await db.flush()
    return groups


async def ensure_default_access_groups(db: AsyncSession) -> int:
    """Create missing built-in SOC profiles without overwriting local policy."""
    # Serialize first-start seeding across API replicas. The lock is released
    # by the commit below and uses a stable application-specific integer key.
    await db.execute(select(func.pg_advisory_xact_lock(0x41475242)))
    rows = await db.execute(select(AccessGroup))
    existing_groups = {group.slug: group for group in rows.scalars().all()}
    created = 0
    for slug, profile in DEFAULT_ACCESS_GROUPS.items():
        existing = existing_groups.get(slug)
        if existing is not None:
            if not existing.system:
                raise RuntimeError(
                    f"Reserved built-in access-group slug is owned by a custom group: {slug}"
                )
            continue
        db.add(AccessGroup(
            slug=slug,
            name=str(profile["name"]),
            description=str(profile["description"]),
            permissions=sorted(profile["permissions"]),
            modules=sorted(profile["modules"]),
            system=True,
            enabled=True,
            created_by="system",
        ))
        created += 1
    if created:
        await db.commit()
    return created


def account_has_permission(user: UserAccount, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role, set()) or permission in set(
        user.permissions or []
    )


def effective_account_permissions(
    role: str,
    extra_permissions: list[str] | None = None,
) -> set[str]:
    """Return the effective grant represented by one managed account."""
    return set(ROLE_PERMISSIONS.get(role, set())) | set(extra_permissions or [])


def effective_team_permissions(user: TeamUser) -> set[str]:
    """Return a request principal's effective permissions defensively.

    ``TeamUser.permissions`` normally already contains the expanded role grant,
    but trusted-proxy identities and tests may construct the object directly.
    Including every declared role keeps the authorization ceiling fail-safe.
    """
    if "admin" in user.roles:
        return set(ALL_PERMISSIONS)
    permissions = set(user.permissions or [])
    for role in user.roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))
    return permissions


def validate_user_grant_scope(
    actor: TeamUser,
    *,
    role: str,
    permissions: list[str],
) -> None:
    """Prevent delegated user managers from granting authority they do not own."""
    if "admin" in actor.roles:
        return
    if role == "admin":
        raise HTTPException(403, "Only an administrator can assign the admin role")

    proposed = effective_account_permissions(role, permissions)
    actor_permissions = effective_team_permissions(actor)
    if "manage_auth" in proposed and "manage_auth" not in actor_permissions:
        raise HTTPException(
            403,
            "The manage_auth permission can only be granted by a principal that has manage_auth",
        )
    if not proposed.issubset(actor_permissions):
        raise HTTPException(
            403,
            "Cannot grant a role or permission outside your own effective permissions",
        )


def validate_user_target_scope(actor: TeamUser, target: UserAccount) -> None:
    """Prevent lifecycle or authentication takeover of a more privileged user."""
    if "admin" in actor.roles:
        return
    if target.role == "admin":
        raise HTTPException(403, "Only an administrator can manage an admin account")

    target_permissions = effective_account_permissions(
        target.role,
        list(target.permissions or []),
    )
    actor_permissions = effective_team_permissions(actor)
    if "manage_auth" in target_permissions and "manage_auth" not in actor_permissions:
        raise HTTPException(
            403,
            "The target account requires manage_auth authority",
        )
    if not target_permissions.issubset(actor_permissions):
        raise HTTPException(
            403,
            "Cannot manage an account above your own effective permissions",
        )


def normalize_identity_name(
    value: str,
    *,
    max_length: int,
    status_code: int = 422,
    label: str = "Username",
) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > max_length or not normalized.isprintable():
        raise HTTPException(
            status_code,
            f"{label} must be 1-{max_length} printable characters after trimming",
        )
    return normalized


async def ensure_user_management_continuity(
    db: AsyncSession,
    target: UserAccount,
    *,
    proposed_role: str,
    proposed_permissions: list[str],
    proposed_enabled: bool,
    proposed_group_permissions: list[str] | None = None,
    proposed_group_modules: list[str] | None = None,
) -> None:
    """Prevent concurrent mutations from removing the final user manager."""
    proposed_effective_permissions = (
        set(ROLE_PERMISSIONS.get(proposed_role, set()))
        | set(proposed_permissions)
        | set(proposed_group_permissions or [])
    )
    if proposed_group_modules is None:
        proposed_effective_modules = set(ROLE_MODULES.get(proposed_role, set()))
        if {"manage_users", "manage_auth"}.intersection(proposed_effective_permissions):
            proposed_effective_modules.add("admin")
    else:
        proposed_effective_modules = set(proposed_group_modules)
    if (
        proposed_enabled
        and "manage_users" in proposed_effective_permissions
        and ("admin" in proposed_effective_modules or proposed_role == "admin")
    ):
        return

    rows = await db.execute(
        select(UserAccount)
        .where(UserAccount.enabled.is_(True))
        .order_by(UserAccount.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    enabled_users = rows.scalars().all()
    locked_target = next((user for user in enabled_users if user.id == target.id), None)
    if locked_target is None:
        return
    locked_groups = await load_user_groups(db, locked_target.id, include_disabled=True)
    locked_principal = user_to_team_user(
        locked_target,
        groups=locked_groups or None,
    )
    if not (
        has_permission(locked_principal, "manage_users")
        and has_module(locked_principal, "admin")
    ):
        return
    enabled_managers = []
    for enabled_user in enabled_users:
        groups = await load_user_groups(db, enabled_user.id, include_disabled=True)
        principal = user_to_team_user(enabled_user, groups=groups or None)
        if has_permission(principal, "manage_users") and has_module(principal, "admin"):
            enabled_managers.append(enabled_user)
    if len(enabled_managers) <= 1:
        raise HTTPException(
            409,
            "At least one enabled account with user-management permission must remain",
        )


async def ensure_group_management_continuity(
    db: AsyncSession,
    target_group: AccessGroup,
    *,
    proposed_permissions: list[str],
    proposed_modules: list[str],
    proposed_enabled: bool,
) -> None:
    """Prevent a group-policy edit from removing the last user manager."""
    current_permissions = set(normalize_permissions(target_group.permissions))
    current_modules = set(normalize_modules(target_group.modules))
    if (
        not target_group.enabled
        or "manage_users" not in current_permissions
        or "admin" not in current_modules
        or (
            proposed_enabled
            and "manage_users" in proposed_permissions
            and "admin" in proposed_modules
        )
    ):
        return
    membership_rows = await db.execute(
        select(UserAccessGroup).where(UserAccessGroup.group_id == target_group.id)
    )
    target_member_ids = {
        membership.user_id for membership in membership_rows.scalars().all()
    }
    if not target_member_ids:
        return

    user_rows = await db.execute(
        select(UserAccount)
        .where(UserAccount.enabled.is_(True))
        .order_by(UserAccount.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    for user in user_rows.scalars().all():
        groups = await load_user_groups(db, user.id, include_disabled=True)
        if user.id in target_member_ids:
            remaining_groups = [
                group
                for group in groups
                if group.id != target_group.id and group.enabled
            ]
            effective_permissions = set(permissions_for(user.role, user.permissions))
            effective_permissions.update(group_permissions(remaining_groups))
            effective_modules = set(group_modules(remaining_groups))
            if proposed_enabled:
                effective_permissions.update(proposed_permissions)
                effective_modules.update(proposed_modules)
            effective_roles = roles_for(user.role)
            if (
                any(
                    group.system and group.slug == "platform-administrators"
                    for group in remaining_groups
                )
                or (
                    target_group.system
                    and target_group.slug == "platform-administrators"
                    and proposed_enabled
                )
            ):
                effective_roles = roles_for("admin")
            principal = TeamUser(
                name=user.username,
                roles=effective_roles,
                permissions=sorted(effective_permissions),
                modules=sorted(effective_modules),
            )
        else:
            principal = user_to_team_user(user, groups=groups or None)
        if has_permission(principal, "manage_users") and has_module(principal, "admin"):
            return
    raise HTTPException(
        409,
        "At least one enabled account with user-management permission must remain",
    )


def user_to_team_user(
    user: UserAccount,
    auth_source: str = "native",
    groups: list[AccessGroup] | None = None,
) -> TeamUser:
    active_groups = [group for group in (groups or []) if group.enabled]
    expanded_permissions = set(permissions_for(user.role, user.permissions))
    expanded_permissions.update(group_permissions(active_groups))
    assigned_modules = group_modules(active_groups) if groups is not None else None
    expanded_modules = set(modules_for(user.role, assigned_modules))
    if groups is None:
        if {"manage_users", "manage_auth"}.intersection(expanded_permissions):
            expanded_modules.add("admin")
        if "manage_feeds" in expanded_permissions:
            expanded_modules.add("feeds")
        if "view_audit" in expanded_permissions:
            expanded_modules.add("observability")
    effective_roles = roles_for(user.role)
    if any(
        group.system and group.slug == "platform-administrators"
        for group in active_groups
    ):
        effective_roles = roles_for("admin")
    return TeamUser(
        name=user.username,
        roles=effective_roles,
        user_id=str(user.id),
        auth_source=auth_source,
        permissions=sorted(expanded_permissions),
        modules=sorted(expanded_modules),
        groups=sorted(group.slug for group in active_groups),
    )


def password_policy() -> dict:
    return {
        "min_length": settings.auth_password_min_length,
        "require_upper": settings.auth_password_require_upper,
        "require_lower": settings.auth_password_require_lower,
        "require_number": settings.auth_password_require_number,
        "require_special": settings.auth_password_require_special,
        # AUTH_MFA_ENABLED is a feature/enrollment toggle. Per-user
        # ``mfa_enabled`` remains the source of truth for login enforcement.
        "mfa_available": settings.auth_mfa_enabled,
        "mfa_required": False,
    }


def validate_password_policy(password: str) -> None:
    errors: list[str] = []
    if len(password) < settings.auth_password_min_length:
        errors.append(f"at least {settings.auth_password_min_length} characters")
    if settings.auth_password_require_upper and not any(ch.isupper() for ch in password):
        errors.append("one uppercase letter")
    if settings.auth_password_require_lower and not any(ch.islower() for ch in password):
        errors.append("one lowercase letter")
    if settings.auth_password_require_number and not any(ch.isdigit() for ch in password):
        errors.append("one number")
    if settings.auth_password_require_special and not any(not ch.isalnum() for ch in password):
        errors.append("one special character")
    if errors:
        raise HTTPException(422, f"Password must contain {', '.join(errors)}")


async def user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(UserAccount)) or 0)


async def bootstrap_admin_if_configured(db: AsyncSession) -> bool:
    if not settings.auth_enabled or not settings.auth_bootstrap_admin_password:
        return False
    if await user_count(db) > 0:
        return False
    validate_password_policy(settings.auth_bootstrap_admin_password)
    username = normalize_identity_name(
        settings.auth_bootstrap_admin_username or "admin",
        max_length=120,
        label="Bootstrap username",
    )
    db.add(UserAccount(
        username=username,
        display_name="Bootstrap Administrator",
        password_hash=hash_password(settings.auth_bootstrap_admin_password),
        role="admin",
        permissions=[],
        enabled=True,
    ))
    await db.commit()
    return True


async def authenticate_credentials(db: AsyncSession, username: str, password: str) -> UserAccount:
    try:
        normalized = normalize_identity_name(username, max_length=120)
    except HTTPException:
        normalized = ""
    row = await db.scalar(select(UserAccount).where(UserAccount.username == normalized))
    password_valid = verify_password(
        password,
        row.password_hash if row is not None else _DUMMY_PASSWORD_HASH,
    )
    if not row or not row.enabled or not password_valid:
        raise HTTPException(401, "Invalid username or password")
    return row


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code or not code.isdigit():
        return False
    counter = int(time.time() // 30)
    return any(hmac.compare_digest(_totp(secret, counter + shift), code.zfill(6)) for shift in range(-window, window + 1))


async def create_session(db: AsyncSession, user: UserAccount, request: Request) -> tuple[str, AuthSession]:
    now = datetime.now(timezone.utc)
    await cleanup_auth_sessions(db, now=now)
    token = new_session_token()
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        user_agent=request.headers.get("user-agent", "")[:2000],
        ip_address=(request.client.host if request.client else "")[:120],
        expires_at=now + timedelta(minutes=max(15, settings.auth_session_minutes)),
    )
    db.add(session)
    await db.flush()
    await db.refresh(session)
    return token, session


async def authenticate_token(db: AsyncSession, token: str) -> UserAccount | None:
    if not token:
        return None
    now = datetime.now(timezone.utc)
    session = await db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == hash_token(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if not session:
        return None
    user = await db.get(UserAccount, session.user_id)
    if not user or not user.enabled:
        return None
    return user


async def revoke_session(db: AsyncSession, token: str) -> None:
    if not token:
        return
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if session and not session.revoked_at:
        session.revoked_at = datetime.now(timezone.utc)
        await db.flush()


async def revoke_user_sessions(db: AsyncSession, user_id: UUID, keep_token: str = "") -> int:
    keep_hash = hash_token(keep_token) if keep_token else ""
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    count = 0
    for session in rows.scalars().all():
        if keep_hash and session.token_hash == keep_hash:
            continue
        session.revoked_at = revoked_at
        count += 1
    await db.flush()
    return count


async def cleanup_auth_sessions(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    retention_days: int = 30,
    limit: int = 1000,
) -> None:
    """Delete a bounded batch of long-expired or long-revoked sessions."""
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=max(1, retention_days))
    stale_ids = (
        select(AuthSession.id)
        .where(
            or_(
                AuthSession.expires_at < cutoff,
                AuthSession.revoked_at < cutoff,
            )
        )
        .order_by(AuthSession.expires_at.asc())
        .limit(max(1, min(limit, 5000)))
    )
    await db.execute(delete(AuthSession).where(AuthSession.id.in_(stale_ids)))


async def audit_event(
    db: AsyncSession,
    actor: str,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(actor=actor, action=action, object_type=object_type, object_id=object_id, details=details or {}))


async def current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    ag_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
    x_internal_proxy_secret: str | None = Header(default=None),
) -> TeamUser:
    # Proxy identity headers are authentication credentials, not hints. Trust
    # them only when the operator configured a shared secret and the proxy
    # supplied it. In particular, an empty PROXY_SECRET must never turn
    # client-controlled X-Auth-* headers into an authentication bypass.
    proxy_identity_verified = bool(
        settings.proxy_secret
        and hmac.compare_digest(x_internal_proxy_secret or "", settings.proxy_secret)
    )
    if not proxy_identity_verified:
        x_auth_user = None
        x_auth_roles = None

    if x_auth_user:
        try:
            identity = normalize_identity_name(
                x_auth_user,
                max_length=255,
                status_code=401,
                label="Trusted proxy username",
            )
            requested_roles = [
                normalize_role(role)
                for role in (x_auth_roles or settings.auth_default_role).split(",")
                if role.strip()
            ]
        except HTTPException as exc:
            raise HTTPException(401, "Invalid trusted proxy identity") from exc
        if not requested_roles:
            try:
                requested_roles = [normalize_role(settings.auth_default_role)]
            except HTTPException as exc:
                raise HTTPException(401, "Invalid trusted proxy identity") from exc
        effective_roles = sorted(
            {effective for role in requested_roles for effective in roles_for(role)}
        )
        effective_permissions = sorted(
            {
                permission
                for role in requested_roles
                for permission in permissions_for(role)
            }
        )
        return TeamUser(
            name=identity,
            roles=effective_roles,
            auth_source=settings.auth_sso_mode,
            permissions=effective_permissions,
            modules=sorted({
                module
                for role in requested_roles
                for module in modules_for(role)
            }),
            groups=[],
        )

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    token = token or ag_session or ""
    user = await authenticate_token(db, token)
    if user:
        groups = await load_user_groups(db, user.id, include_disabled=True)
        return user_to_team_user(user, groups=groups or None)

    if settings.auth_enabled:
        raise HTTPException(401, "Authentication required")
    return TeamUser(
        name="local",
        roles=roles_for(settings.auth_default_role),
        auth_source="local",
        permissions=permissions_for(settings.auth_default_role),
        modules=modules_for(settings.auth_default_role),
        groups=[],
    )


def has_permission(user: TeamUser, permission: str) -> bool:
    permissions = set(user.permissions or [])
    return "admin" in user.roles or permission in permissions


def has_module(user: TeamUser, module: str) -> bool:
    if module not in ALL_MODULES:
        return False
    if "admin" in user.roles:
        return True
    if user.modules is not None:
        return module in set(user.modules)
    # Defensive compatibility for trusted integrations/tests that construct a
    # principal without the newer module claim.
    inferred = {
        candidate
        for role in user.roles
        for candidate in ROLE_MODULES.get(role, set())
    }
    permissions = effective_team_permissions(user)
    if {"manage_users", "manage_auth"}.intersection(permissions):
        inferred.add("admin")
    if "manage_feeds" in permissions:
        inferred.add("feeds")
    if "view_audit" in permissions:
        inferred.add("observability")
    return module in inferred


def require_permission(permission: str):
    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not has_permission(user, permission):
            raise HTTPException(403, f"Permission required: {permission}")
        return user
    return dependency


def require_any_permission(*permissions: str):
    required = tuple(dict.fromkeys(permissions))
    if not required:
        raise ValueError("At least one permission is required")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not any(
            has_permission(user, permission) for permission in required
        ):
            raise HTTPException(403, f"One permission required: {', '.join(required)}")
        return user

    return dependency


def require_module(module: str):
    if module not in ALL_MODULES:
        raise ValueError(f"Unknown module: {module}")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not has_module(user, module):
            raise HTTPException(403, f"Module access required: {module}")
        return user

    return dependency


def require_any_module(*modules: str):
    required = tuple(dict.fromkeys(modules))
    if not required or any(module not in ALL_MODULES for module in required):
        raise ValueError("At least one valid module is required")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not any(has_module(user, module) for module in required):
            raise HTTPException(403, f"One module required: {', '.join(required)}")
        return user

    return dependency


def require_module_permission(module: str, permission: str):
    if module not in ALL_MODULES:
        raise ValueError(f"Unknown module: {module}")
    if permission not in ALL_PERMISSIONS:
        raise ValueError(f"Unknown permission: {permission}")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and (
            not has_module(user, module)
            or not has_permission(user, permission)
        ):
            raise HTTPException(
                403,
                f"Module and permission required: {module}, {permission}",
            )
        return user

    return dependency


def require_module_any_permission(module: str, *permissions: str):
    if module not in ALL_MODULES:
        raise ValueError(f"Unknown module: {module}")
    required = tuple(dict.fromkeys(permissions))
    if not required or any(permission not in ALL_PERMISSIONS for permission in required):
        raise ValueError("At least one valid permission is required")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and (
            not has_module(user, module)
            or not any(has_permission(user, permission) for permission in required)
        ):
            raise HTTPException(
                403,
                f"Module and one permission required: {module}; {', '.join(required)}",
            )
        return user

    return dependency


async def analyst(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not ({"admin", "analyst"}.intersection(user.roles) or has_permission(user, "run_analysis")):
        raise HTTPException(403, "Analyst role required")
    return user


async def admin(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not has_permission(user, "manage_auth"):
        raise HTTPException(403, "Auth administrator permission required")
    return user


async def audit(
    db: AsyncSession,
    user: TeamUser,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    await audit_event(db, user.name, action, object_type, object_id, details)
