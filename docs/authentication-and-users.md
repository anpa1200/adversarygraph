# Authentication and User Management

AdversaryGraph supports native username/password authentication for private
deployments and trusted reverse-proxy SSO for operators who use OIDC or SAML at
an identity-aware gateway.

The same operator guide is available in a running local instance at:

- <http://localhost:3000/auth-guide>

The login page links directly to this guide, and the route remains accessible
before sign-in when `AUTH_ENABLED=true`.

## SOC groups and module access

Named native users can belong to one or more persistent access groups. A group
contains two independent allowlists:

- **modules** decide which workspaces appear in the sidebar and which
  module-backed API routers the account may call;
- **permissions** decide which actions the account may perform inside those
  modules.

Both checks are enforced by the API. Hiding a sidebar item is not treated as a
security boundary. When a user has one or more group assignments, the union of
enabled groups is the user's module allowlist. A user with no group assignments
retains the legacy module defaults for their primary role so an upgrade does not
silently lock out existing accounts. Direct permission grants and the primary
role remain additive action grants.

The API seeds these profiles once. Administrators may then adapt their local
copies without startup overwriting the policy:

| Group | Intended access boundary |
| --- | --- |
| SOC Tier 1 — Triage | IOC Investigation, reports, knowledge, IOC lookup, VirusTotal, evidence intake, and escalation |
| SOC Tier 2 — Investigation | Tier 1 plus Threat Radar, actor/sector/CVE context, RetroHunt, asset surface, malware analysis, correlation, and evidence graph |
| SOC Tier 3 — Advanced Analysis | Advanced investigation, malware, threat hunting, query engineering, simulation, detection operations, and pipeline workflows |
| SOC Manager | All operational SOC modules and audit visibility, but no user/authentication, feed, or platform configuration |
| Threat Intelligence | Reports, actors, sectors, IOC/CVE intelligence, ATT&CK mappings, evidence, and intelligence enrichment |
| Threat Hunting | Hypotheses, detection queries, IOC correlation, evidence, findings, and hunt outcomes |
| Detection Engineering | Query engineering, coverage, controlled attack simulation, SIEM forwarding, detection operations, and pipeline validation |
| Incident Response / DFIR | IOC and malware investigation, evidence preservation, response coordination, and incident reporting |
| Vulnerability Management | Asset inventory, attack surface, CVE prioritization, exposure monitoring, and remediation evidence |
| Intelligence Feed Operators | ATT&CK, IOC, CVE, and enrichment-feed maintenance without identity administration |
| Audit / Read Only | Reports, statistics, operational health, exports, and audit evidence without mutation rights |
| Platform Administrators | Every module and permission, including identity, authentication, feeds, and configuration |

Use groups for normal workforce assignments. Keep the primary role at `viewer`
unless a service integration, trusted-proxy mapping, or backwards-compatible
deployment specifically needs a role baseline. The `admin` role is always
unrestricted and only another administrator may assign it.

## Roles and exact base permissions

The following table mirrors `ROLE_PERMISSIONS` in the API. These are the base
permissions granted by the primary role; an administrator may add explicit
permissions to an individual account, but an extra grant does not remove a
role's base permission.

| Role | Base permissions |
| --- | --- |
| `viewer` | `read` |
| `auditor` | `read`, `view_audit`, `export_data` |
| `analyst` | `read`, `run_analysis`, `manage_intel`, `upload_files`, `export_data` |
| `threat_intel` | `read`, `run_analysis`, `manage_intel`, `manage_feeds`, `upload_files`, `export_data` |
| `detection_engineer` | `read`, `run_analysis`, `manage_detections`, `run_attack_simulation`, `forward_siem`, `export_data` |
| `incident_responder` | `read`, `run_analysis`, `manage_intel`, `run_attack_simulation`, `forward_siem`, `upload_files`, `export_data` |
| `service_account` | `read`, `run_analysis`, `manage_feeds`, `forward_siem`, `export_data` |
| `security_admin` | `read`, `run_analysis`, `manage_intel`, `manage_detections`, `run_attack_simulation`, `manage_feeds`, `forward_siem`, `upload_files`, `export_data`, `manage_auth`, `view_audit` |
| `admin` | Every current permission, including `manage_users` and `manage_auth` |

In particular, `analyst` does **not** implicitly own feed administration,
detection administration, Attack Simulation, or SIEM forwarding. Use the
purpose-built role or an explicit grant. `security_admin` has authentication,
session, MFA, and audit controls but does not receive `manage_users` unless it
is granted explicitly; `admin` receives it by default.

Current permissions are:

`read`, `run_analysis`, `manage_intel`, `manage_detections`,
`run_attack_simulation`, `manage_feeds`, `forward_siem`, `upload_files`,
`export_data`, `manage_users`, `manage_auth`, and `view_audit`.

### Module and action controls

Module membership allows navigation and direct API access to that functional
area. The `read` permission supports safe reads inside the allowed area. Seeing
a page or previously stored record does not grant permission to upload, mutate,
synchronize, execute, export, or forward data.

The sidebar, frontend route, and backend router hide or block workspaces when
the matching module is absent. State-changing controls additionally require the
matching permission:

- analysis workspaces such as EMB3D, Evidence Graph, Threat Radar, Threat
  Hunting, Investigation, IOC Investigation, Operations, Pipeline, and
  Statistics require `run_analysis`;
- Attack Simulation requires `run_attack_simulation`;
- Feeds Management requires `manage_feeds`;
- Observability/audit views require `view_audit`;
- Admin Panel opens for `manage_users`, `manage_auth`, or `view_audit`, while
  each panel and action requires its exact permission.

Within otherwise readable pages, state-changing controls are permission-bound
to the corresponding capability: `manage_intel`, `manage_detections`,
`upload_files`, `export_data`, `forward_siem`, `manage_users`, or
`manage_auth`. The UI boundary is for clarity, not the security boundary; API
routes independently enforce effective permissions and return `403` when a
direct request lacks the required grant.

### Unified RAG and MCP permissions

The **AI RAG assistant** button opens the **Intelligence RAG assistant** dialog
inside Navigator, but its actions
have separate server-side authorization:

| Action | Required permission |
|---|---|
| Read corpus readiness/status | `read` |
| List saved business profiles | `run_analysis` |
| Search, read one indexed entity, list providers, generate a grounded answer, or confirm an expiring proposal | `run_analysis` |
| Create, replace, or delete a business profile | `manage_intel` |
| Queue reconciliation or view index-run history | `manage_feeds` |

Proposal confirmation records the reviewed Add/Replace receipt but does not
save a named Navigator layer. The frontend revalidates the server receipt
before changing its in-memory selection.

Every MCP tool requires `run_analysis`. When authentication is enabled, the
stdio MCP process also requires a valid bearer session in `MCP_API_TOKEN`. That
token is an ordinary AdversaryGraph session—not a separately scoped MCP API
key—so use a dedicated non-administrator analyst or service account with the
smallest effective permission set, protect the client configuration, and revoke
the session when the integration is no longer required. MCP exposes no profile
mutation, reindex, proposal-confirmation, layer-saving, feed, simulation, SIEM,
or response tool.

## Enable Native Login

Set these values in `.env`:

```env
AUTH_ENABLED=true
AUTH_SSO_MODE=proxy
AUTH_DEFAULT_ROLE=viewer
AUTH_SESSION_MINUTES=720
AUTH_PASSWORD_MIN_LENGTH=12
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-temporary-password
```

Start or restart the API container. If no users exist, the API creates the first
administrator from `AUTH_BOOTSTRAP_ADMIN_USERNAME` and
`AUTH_BOOTSTRAP_ADMIN_PASSWORD`.

After signing in and creating permanent named admin accounts, clear
`AUTH_BOOTSTRAP_ADMIN_PASSWORD` and restart the API. Existing users remain in the
database.

For Docker Compose deployments, `docker-compose.yml` passes these variables to
the API, worker, and beat services. The worker and beat receive the same auth
settings so background API clients and scheduled workflows have a consistent
runtime configuration.

## Sign In

When `AUTH_ENABLED=true`, the web application opens on the protected login page.
Successful login creates an HttpOnly session cookie named `ag_session`. API
clients can also use the returned bearer token.

If local MFA is enabled for a user, the login request must also include a TOTP
code. The UI includes an optional MFA code field.

## Admin Panel

Open **Admin Panel** from the sidebar as an admin user.

Admins can:

- create users;
- assign one or more SOC groups to each user;
- create local access groups and edit their module/permission matrices;
- enable or disable groups without deleting their policy;
- assign any built-in role;
- add or remove explicit permission grants;
- enable or disable users;
- reset passwords;
- view recent sessions;
- revoke all sessions for a user;
- disable local MFA for a user;
- review auth audit events.

Built-in SOC groups cannot be deleted; they can be disabled. Custom groups must
have no members before deletion. Disabling a group immediately removes its
module and permission grants from assigned users. The service refuses user or
group changes that would remove the final enabled user-management path.

Delegated accounts with `manage_users` are subject to an authorization ceiling:
they may create or manage only accounts whose complete effective permission set
and module set is contained in their own. They cannot assign the `admin` role,
manage an admin account, change built-in groups, or grant `manage_auth` unless
they already hold it. Password reset, disable, role, membership, and permission
changes use the same target-account ceiling so a user manager cannot take over a
more privileged identity. Session revocation and MFA reset remain `manage_auth`
operations, and only an `admin` may apply them to another admin account.

Users cannot change their own role or explicit permission grants through the
Admin Panel API. Use a second named administrator for administrator-role changes;
this preserves an attributable recovery path and prevents self-promotion or
accidental self-demotion. A full `admin` remains able to create another admin and
manage every lower-privilege account.

The UI never displays stored password hashes. Passwords are hashed with
PBKDF2-HMAC-SHA256 and per-user random salts.

Password resets and disabled accounts revoke active native sessions for the
affected user.

### Create a named user

Use this sequence for every native account:

1. Sign in as a Platform Administrator or a delegated user manager with the
   Administration module and `manage_users`.
2. Open **Admin Panel** and locate **Create user**.
3. Enter a unique username. Leading and trailing whitespace is removed.
4. Enter an optional display name and an initial password. The form reads the
   live policy from `GET /api/auth/status` and shows the required length and
   any uppercase, lowercase, number, or special-character requirements.
5. Select one or more least-privilege SOC groups. For normal workforce
   accounts, keep **Advanced role and direct grants** at `viewer` with no
   direct grants.
6. Leave **Enabled** selected and choose **Create user**.
7. Confirm the user appears in **Users and permissions**, verify the effective
   module count and group assignments, then test the account in a separate
   private browser session.

**Create user** remains actionable so it can explain incomplete input. Missing
fields and password-policy failures appear in an accessible validation
checklist immediately above the action. While the request is running, the
label changes to **Creating user…** and repeat submissions are blocked.
Browser and password-manager autofill are read from the submitted form rather
than relying only on input-change events.

Do not grant `admin`, `manage_users`, or `manage_auth` merely to expose more
analyst modules. Use the supplied SOC profiles or a reviewed custom group.
Maintain at least two tested named Platform Administrator accounts before
removing a bootstrap credential or changing the final user-management path.

The equivalent API workflow is:

```bash
# Inspect the active password policy and available groups.
curl -fsS http://localhost:3000/api/auth/status | jq '.password_policy'
curl -fsS http://localhost:3000/api/auth/groups | jq '.[] | {id, slug, name}'

# Run from an authenticated administrator session. Replace the group UUID and
# use a secret entered through your approved credential workflow.
curl -fsS -X POST http://localhost:3000/api/auth/users \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${ADVERSARYGRAPH_ADMIN_TOKEN}" \
  --data '{
    "username": "tier1.analyst",
    "display_name": "Tier 1 Analyst",
    "password": "replace-with-approved-initial-secret",
    "role": "viewer",
    "permissions": [],
    "group_ids": ["00000000-0000-0000-0000-000000000000"],
    "enabled": true
  }'
```

Do not place a real password or bearer token in shell history. The inline JSON
is an interface example only; use a protected file descriptor, secret manager,
or approved provisioning client in production.

### User-creation troubleshooting

| Symptom | Meaning and action |
| --- | --- |
| Validation checklist appears | Complete every listed field or password-policy requirement, then submit again. |
| `403` / insufficient authority | The current account lacks `manage_users`, the Administration module, or authority over the requested role/groups/grants. Use a Platform Administrator or reduce the requested scope. |
| `409 Username already exists` | Choose another normalized username or update the existing account. |
| `422 Password must contain …` | The API policy changed or the password does not satisfy it. Reload Admin Panel and follow the displayed policy. |
| `422 Disabled access groups cannot be assigned` | Re-enable the intended group after review or choose an enabled group. |
| Groups are empty or fail to load | Check `GET /api/auth/groups`, API health, database startup, and browser network errors. Do not compensate with broad direct grants. |
| The old Create button is still disabled | The browser or container is serving a pre-hotfix frontend. Rebuild/recreate `frontend`, then hard-refresh the page to load the new hashed assets. |
| User was created but cannot sign in | Confirm `enabled=true`, test the exact username, verify `AUTH_ENABLED=true` for enforced login, and reset the initial password if necessary. |

Successful creation returns HTTP `201` and writes `auth.user_create` to the
authentication audit trail. Verify the authoritative count and account record
through `GET /api/auth/users`; do not infer success only from a toast.

## Session Management

Native sessions expire after `AUTH_SESSION_MINUTES`. The Admin Panel lists recent
sessions with user, IP, user-agent, expiry, and active/revoked state.

Available session controls:

- logout revokes the current session;
- password reset revokes all sessions for the affected user;
- disable user revokes all sessions for the affected user;
- admins can revoke all sessions for any user;
- users can revoke their other sessions through `POST /api/auth/sessions/revoke-all`.

## Password Policy And MFA

Local password policy is controlled by:

```env
AUTH_PASSWORD_MIN_LENGTH=12
AUTH_PASSWORD_REQUIRE_UPPER=false
AUTH_PASSWORD_REQUIRE_LOWER=false
AUTH_PASSWORD_REQUIRE_NUMBER=false
AUTH_PASSWORD_REQUIRE_SPECIAL=false
AUTH_MFA_ENABLED=false
```

TOTP MFA endpoints are available for local accounts:

- `POST /api/auth/mfa/setup` starts setup and returns the TOTP secret and
  `otpauth://` URL;
- `POST /api/auth/mfa/confirm` verifies a code and enables MFA;
- `POST /api/auth/users/{user_id}/mfa/disable` lets an auth administrator reset
  MFA for a user.

For enterprise deployments, prefer enforcing MFA in the OIDC/SAML IdP and using
local MFA only for break-glass native accounts.

## OIDC/SAML SSO Through Trusted Proxy

AdversaryGraph does not terminate OIDC or SAML directly. The supported
enterprise pattern is to terminate identity at a trusted reverse proxy or ingress
controller, then forward signed identity headers to the API.

Required operator controls:

- set `AUTH_ENABLED=true`;
- set `AUTH_SSO_MODE=oidc-proxy` or `AUTH_SSO_MODE=saml-proxy`;
- set a strong `PROXY_SECRET`;
- configure the proxy to send `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret`;
- strip any client-supplied `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret` before forwarding traffic to the API.

If `PROXY_SECRET` is configured and the request does not include the correct
internal secret, AdversaryGraph ignores all trusted-header identity fields and
falls back to native session or bearer-token authentication.

Recommended proxy examples:

- oauth2-proxy with OIDC;
- Pomerium;
- Authelia;
- Keycloak or Dex behind an ingress external-auth layer;
- SAML-capable enterprise gateway that can emit trusted headers.

Map IdP groups to AdversaryGraph roles in `X-Auth-Roles`.

## Audit Logs

Auth audit events are stored in the `audit_events` table and visible in the
Admin Panel. Events include:

- login success and failure;
- MFA failure, setup, enable, and admin disable;
- logout;
- user create/update/disable;
- access-group create/update/delete and membership changes;
- password reset;
- session listing and session revocation.

The broader platform already writes audit events for report analysis, imports,
feed sync, CVE sync, IOC enrichment, SIEM forwarding, attack simulation,
asset-surface cases, saved layers, and operational objects.

## Security Notes

- Do not expose an instance with `AUTH_ENABLED=false` to untrusted networks.
- Put production deployments behind TLS.
- Use unique named accounts instead of shared admin users.
- Prefer OIDC/SAML SSO through a trusted identity-aware proxy for enterprise access.
- Require MFA at the IdP and on local break-glass admin accounts.
- Review auth audit events after user, export, feed-sync, SIEM-forwarding, and upload activity.
- Rotate bootstrap credentials after initial setup by clearing
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD`.
- Keep `AUTH_BOOTSTRAP_ADMIN_PASSWORD` blank after bootstrap; otherwise a fresh
  empty database can recreate that bootstrap account.
- Restrict direct network access to the API container.
