import adversaryGraphIcon from '@/assets/adversarygraph-ai-icon-192.png';

const groupRows = [
  ['SOC Tier 1 — Triage', 'Minimum IOC investigation, reports, evidence intake, VirusTotal, and escalation workspace.'],
  ['SOC Tier 2 — Investigation', 'Adds Threat Radar, asset and CVE context, actors, malware analysis, correlation, and evidence graphs.'],
  ['SOC Tier 3 — Advanced Analysis', 'Adds advanced hunting, query engineering, simulations, operations, and detection validation.'],
  ['SOC Manager', 'All operational SOC capabilities and audit visibility, without users, authentication, feed, or platform configuration.'],
  ['Threat Intelligence', 'Reports, actors, sectors, IOC/CVE intelligence, ATT&CK mapping, evidence, and intelligence enrichment.'],
  ['Threat Hunting', 'Hypotheses, detection queries, IOC correlation, evidence, hunt findings, and outcomes.'],
  ['Detection Engineering', 'Queries, coverage, safe attack simulation, SIEM forwarding, detection operations, and pipeline validation.'],
  ['Incident Response / DFIR', 'IOC and malware investigation, evidence preservation, response coordination, and incident reporting.'],
  ['Vulnerability Management', 'Asset inventory, attack surface, CVE prioritization, remediation evidence, and exposure monitoring.'],
  ['Feed Operators', 'ATT&CK, IOC, CVE, and enrichment-feed maintenance without identity administration.'],
  ['Audit / Read Only', 'Reports, statistics, operational health, exports, and audit evidence without mutation rights.'],
  ['Platform Administrators', 'Full module, identity, authentication, feed, security, and configuration administration.'],
];

const envLines = [
  'AUTH_ENABLED=true',
  'AUTH_SSO_MODE=proxy',
  'AUTH_DEFAULT_ROLE=viewer',
  'AUTH_SESSION_MINUTES=720',
  'AUTH_PASSWORD_MIN_LENGTH=12',
  'AUTH_BOOTSTRAP_ADMIN_USERNAME=admin',
  'AUTH_BOOTSTRAP_ADMIN_PASSWORD=<strong-temporary-password>',
  'PROXY_SECRET=<strong-random-secret-for-sso-proxy>',
];

export function AuthGuide() {
  return (
    <div className="min-h-screen overflow-y-auto bg-mitre-dark px-6 py-8 text-gray-200">
      <main className="mx-auto max-w-5xl">
        <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <img src={adversaryGraphIcon} alt="" className="h-10 w-10 rounded-lg object-cover" />
            <div>
              <h1 className="text-2xl font-bold text-white">Authentication Guide</h1>
              <p className="text-sm text-gray-500">Native login, SOC groups, module RBAC, audit, sessions, SSO, and MFA.</p>
            </div>
          </div>
          <a className="secondary-action" href="/">Back to sign in</a>
        </div>

        <section className="rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">How access works</h2>
          <p className="mt-3 text-sm leading-6 text-gray-300">
            AdversaryGraph supports native username/password login and trusted reverse-proxy SSO authentication for OIDC/SAML frontends.
            When native auth is enabled, the browser receives an HttpOnly session cookie named <code className="rounded bg-black/30 px-1">ag_session</code>.
            API clients can use the bearer token returned by the login endpoint.
          </p>
          <p className="mt-3 text-sm leading-6 text-gray-300">
            Named users are assigned to one or more SOC groups. Groups control module visibility and action permissions; the API enforces the same module boundary even when a user calls an endpoint directly. Legacy roles remain an advanced baseline for compatibility, and an administrator remains unrestricted.
          </p>
          <div className="mt-5 grid gap-3 md:grid-cols-3">
            {groupRows.map(([group, description]) => (
              <div key={group} className="rounded border border-gray-700 bg-gray-950 p-4">
                <h3 className="font-semibold text-mitre-accent">{group}</h3>
                <p className="mt-2 text-sm leading-6 text-gray-400">{description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-6 grid gap-6 lg:grid-cols-[1fr_360px]">
          <div className="rounded border border-gray-700 bg-gray-900 p-5">
            <h2 className="text-lg font-semibold text-white">First administrator bootstrap</h2>
            <ol className="mt-3 list-decimal space-y-3 pl-5 text-sm leading-6 text-gray-300">
              <li>Set the auth environment variables in <code className="rounded bg-black/30 px-1">.env</code>.</li>
              <li>Restart the API container. If no users exist, AdversaryGraph creates the bootstrap admin.</li>
              <li>Sign in with the bootstrap username and password.</li>
              <li>Open <strong>Admin Panel</strong>, create named users, and assign least-privilege SOC groups.</li>
              <li>Clear <code className="rounded bg-black/30 px-1">AUTH_BOOTSTRAP_ADMIN_PASSWORD</code> and restart the API.</li>
            </ol>
            <div className="mt-4 rounded border border-amber-500/40 bg-amber-950/20 p-3 text-sm leading-6 text-amber-100">
              The bootstrap password is only for first setup. Do not leave it configured after permanent admin users exist.
            </div>
          </div>

          <div className="rounded border border-gray-700 bg-gray-950 p-5">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-gray-400">Required .env values</h2>
            <pre className="mt-3 overflow-x-auto rounded bg-black p-4 text-xs leading-6 text-emerald-100">
              {envLines.join('\n')}
            </pre>
          </div>
        </section>

        <section className="mt-6 rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">Create and verify a named user</h2>
          <ol className="mt-3 list-decimal space-y-3 pl-5 text-sm leading-6 text-gray-300">
            <li>Open <strong>Admin Panel</strong> as a Platform Administrator or delegated user manager.</li>
            <li>Enter a unique username, optional display name, and an initial password that satisfies the policy displayed below the password field.</li>
            <li>Select the smallest suitable SOC group. Keep the advanced legacy role at <code className="rounded bg-black/30 px-1">viewer</code> and avoid direct grants for ordinary group-managed accounts.</li>
            <li>Select <strong>Create user</strong>. Incomplete fields and policy failures appear in a checklist above the action; the button remains usable so it can explain what is missing.</li>
            <li>Confirm the account in <strong>Users and permissions</strong>, review its effective module count, and test sign-in plus expected module access in a separate private browser session.</li>
          </ol>
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <div className="rounded border border-cyan-500/30 bg-cyan-950/20 p-3 text-sm leading-6 text-cyan-100">
              Browser/password-manager autofill is read from the submitted form. While the API request is active, the action reads <strong>Creating user…</strong> and blocks duplicate submission.
            </div>
            <div className="rounded border border-amber-500/40 bg-amber-950/20 p-3 text-sm leading-6 text-amber-100">
              If an upgraded installation still shows the old disabled action, rebuild and recreate the frontend container, then hard-refresh the browser so it loads the current hashed assets.
            </div>
          </div>
        </section>

        <section className="mt-6 rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">OIDC/SAML SSO through a trusted proxy</h2>
          <p className="mt-3 text-sm leading-6 text-gray-300">
            For enterprise deployments, terminate OIDC or SAML at an identity-aware proxy such as oauth2-proxy, Pomerium, Authelia, Keycloak Gatekeeper-style middleware, or an ingress controller with external auth. Configure the proxy to set <code className="rounded bg-black/30 px-1">X-Auth-User</code>,
            <code className="mx-1 rounded bg-black/30 px-1">X-Auth-Roles</code>, and <code className="rounded bg-black/30 px-1">X-Internal-Proxy-Secret</code>.
            The proxy must strip any client-supplied identity headers before forwarding traffic to the API.
          </p>
          <div className="mt-4 rounded border border-cyan-500/30 bg-cyan-950/20 p-3 text-sm leading-6 text-cyan-100">
            Map IdP groups to AdversaryGraph roles or comma-separated role headers. The API trusts those headers only when <code className="rounded bg-black/30 px-1">PROXY_SECRET</code> matches.
          </div>
        </section>

        <section className="mt-6 grid gap-6 lg:grid-cols-2">
          <div className="rounded border border-gray-700 bg-gray-900 p-5">
            <h2 className="text-lg font-semibold text-white">Session and MFA controls</h2>
            <ul className="mt-3 space-y-2 text-sm leading-6 text-gray-300">
              <li>Sessions expire after <code className="rounded bg-black/30 px-1">AUTH_SESSION_MINUTES</code>.</li>
              <li>Admins can view active sessions and revoke all sessions for a user.</li>
              <li>Users can revoke their other sessions through the API.</li>
              <li>Local accounts support TOTP setup, confirmation, and admin MFA reset.</li>
              <li>Password policy is controlled by length and optional uppercase, lowercase, number, and special-character requirements.</li>
            </ul>
          </div>
          <div className="rounded border border-gray-700 bg-gray-900 p-5">
            <h2 className="text-lg font-semibold text-white">Audit coverage</h2>
            <p className="mt-3 text-sm leading-6 text-gray-300">
              Auth audit events are written for login success/failure, logout, user and group creation/update/disable, membership changes, password reset, MFA setup/change, session revocation, and admin session review. Existing platform audit events cover report analysis, imports, feed sync, CVE sync, IOC enrichment, exports, SIEM forwarding, attack simulation, asset-surface cases, saved layers, and operational objects.
            </p>
          </div>
        </section>

        <section className="mt-6 rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">Security checklist</h2>
          <div className="mt-3 grid gap-2 text-sm text-gray-300 md:grid-cols-2">
            {[
              'Do not expose AUTH_ENABLED=false deployments to untrusted networks.',
              'Use TLS in production.',
              'Use named accounts instead of shared admin accounts.',
              'Prefer OIDC/SAML SSO through a trusted reverse proxy for enterprise access.',
              'Require MFA for local administrator accounts.',
              'Review auth audit events after user, session, export, sync, and SIEM-forwarding activity.',
              'Store production secrets in a secret manager.',
              'Restrict direct access to API, Postgres, Redis, MalwareGraph, and lab fixtures.',
              'Rotate bootstrap credentials after setup.',
            ].map(item => <div key={item} className="rounded bg-gray-950 px-3 py-2">{item}</div>)}
          </div>
        </section>
      </main>
    </div>
  );
}
