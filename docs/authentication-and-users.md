# Authentication and User Management

AdversaryGraph supports native username/password authentication for private
deployments and trusted reverse-proxy SSO for operators who use OIDC or SAML at
an identity-aware gateway.

The same operator guide is available in a running local instance at:

- <http://localhost:3000/auth-guide>

The login page links directly to this guide, and the route remains accessible
before sign-in when `AUTH_ENABLED=true`.

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

### Read-only pages and action controls

`read` allows authenticated navigation and safe read APIs. Viewer-accessible
pages include Discover, Navigator, ATT&CK Group Library, report/knowledge and
IOC/CVE libraries, comparisons, sector context, lookups, help, and
troubleshooting views. Seeing a page or previously stored record does not grant
permission to upload, mutate, synchronize, execute, export, or forward data.

The sidebar and route boundary hide or block these workspaces when the matching
permission is absent:

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
- assign any built-in role;
- add or remove explicit permission grants;
- enable or disable users;
- reset passwords;
- view recent sessions;
- revoke all sessions for a user;
- disable local MFA for a user;
- review auth audit events.

Delegated accounts with `manage_users` are subject to an authorization ceiling:
they may create or manage only accounts whose complete effective permission set
is contained in their own. They cannot assign the `admin` role, manage an admin
account, or grant `manage_auth` unless they already hold it. Password reset,
disable, role, and permission changes use the same target-account ceiling so a
user manager cannot take over a more privileged identity. Session revocation and
MFA reset remain `manage_auth` operations, and only an `admin` may apply them to
another admin account.

Users cannot change their own role or explicit permission grants through the
Admin Panel API. Use a second named administrator for administrator-role changes;
this preserves an attributable recovery path and prevents self-promotion or
accidental self-demotion. A full `admin` remains able to create another admin and
manage every lower-privilege account.

The UI never displays stored password hashes. Passwords are hashed with
PBKDF2-HMAC-SHA256 and per-user random salts.

Password resets and disabled accounts revoke active native sessions for the
affected user.

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
