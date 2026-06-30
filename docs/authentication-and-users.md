# Authentication and User Management

AdversaryGraph supports native username/password authentication for private
deployments and keeps trusted reverse-proxy header authentication for operators
who already use an identity-aware gateway.

The same operator guide is available in a running local instance at:

- <http://localhost:3000/auth-guide>

The login page links directly to this guide, and the route remains accessible
before sign-in when `AUTH_ENABLED=true`.

## Roles

| Role | Access |
| --- | --- |
| `viewer` | Read-only workspace access, matrix navigation, libraries, reports, and lookups. |
| `analyst` | Viewer access plus operational workflows such as attack simulation, feeds, pipeline, and cases. |
| `admin` | Analyst access plus user management. |

Admin inherits analyst and viewer capabilities. Analyst inherits viewer
capabilities.

## Enable Native Login

Set these values in `.env`:

```env
AUTH_ENABLED=true
AUTH_DEFAULT_ROLE=viewer
AUTH_SESSION_MINUTES=720
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

## Admin Panel

Open **Admin Panel** from the sidebar as an admin user.

Admins can:

- create users;
- assign `viewer`, `analyst`, or `admin`;
- enable or disable users;
- reset passwords.

The UI never displays stored password hashes. Passwords are hashed with
PBKDF2-HMAC-SHA256 and per-user random salts.

Password resets and disabled accounts revoke active native sessions for the
affected user.

## Reverse-Proxy Header Auth

Trusted-header authentication remains available for deployments behind an
identity-aware proxy.

Required operator controls:

- set `AUTH_ENABLED=true`;
- set a strong `PROXY_SECRET`;
- configure the proxy to send `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret`;
- strip any client-supplied `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret` before forwarding traffic to the API.

If `PROXY_SECRET` is configured and the request does not include the correct
internal secret, AdversaryGraph ignores all trusted-header identity fields and
falls back to native session or bearer-token authentication.

## Security Notes

- Do not expose an instance with `AUTH_ENABLED=false` to untrusted networks.
- Put production deployments behind TLS.
- Use unique named accounts instead of shared admin users.
- Rotate bootstrap credentials after initial setup by clearing
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD`.
- Keep `AUTH_BOOTSTRAP_ADMIN_PASSWORD` blank after bootstrap; otherwise a fresh
  empty database can recreate that bootstrap account.
- Restrict direct network access to the API container.
