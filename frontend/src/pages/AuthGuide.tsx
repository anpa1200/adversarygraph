import adversaryGraphIcon from '@/assets/adversarygraph-ai-icon-192.png';

const roleRows = [
  ['viewer', 'Read-only workspace access: matrix navigation, libraries, reports, IOC/CVE views, and lookups.'],
  ['analyst', 'Viewer access plus operational workflows: AI analysis, feeds, pipeline, attack simulation, asset surface, and cases.'],
  ['admin', 'Analyst access plus user creation, role changes, account enable/disable, and password reset.'],
];

const envLines = [
  'AUTH_ENABLED=true',
  'AUTH_DEFAULT_ROLE=viewer',
  'AUTH_SESSION_MINUTES=720',
  'AUTH_BOOTSTRAP_ADMIN_USERNAME=admin',
  'AUTH_BOOTSTRAP_ADMIN_PASSWORD=<strong-temporary-password>',
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
              <p className="text-sm text-gray-500">Native login, roles, bootstrap, and operator hardening.</p>
            </div>
          </div>
          <a className="secondary-action" href="/">Back to sign in</a>
        </div>

        <section className="rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">How access works</h2>
          <p className="mt-3 text-sm leading-6 text-gray-300">
            AdversaryGraph supports native username/password login and trusted reverse-proxy header authentication.
            When native auth is enabled, the browser receives an HttpOnly session cookie named <code className="rounded bg-black/30 px-1">ag_session</code>.
            API clients can use the bearer token returned by the login endpoint.
          </p>
          <div className="mt-5 grid gap-3 md:grid-cols-3">
            {roleRows.map(([role, description]) => (
              <div key={role} className="rounded border border-gray-700 bg-gray-950 p-4">
                <h3 className="font-semibold text-mitre-accent">{role}</h3>
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
              <li>Open <strong>Admin Panel</strong> and create named admin/analyst/viewer accounts.</li>
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
          <h2 className="text-lg font-semibold text-white">Reverse-proxy header authentication</h2>
          <p className="mt-3 text-sm leading-6 text-gray-300">
            For deployments behind an identity-aware proxy, configure the proxy to set <code className="rounded bg-black/30 px-1">X-Auth-User</code>,
            <code className="mx-1 rounded bg-black/30 px-1">X-Auth-Roles</code>, and <code className="rounded bg-black/30 px-1">X-Internal-Proxy-Secret</code>.
            The proxy must strip any client-supplied identity headers before forwarding traffic to the API.
          </p>
        </section>

        <section className="mt-6 rounded border border-gray-700 bg-gray-900 p-5">
          <h2 className="text-lg font-semibold text-white">Security checklist</h2>
          <div className="mt-3 grid gap-2 text-sm text-gray-300 md:grid-cols-2">
            {[
              'Do not expose AUTH_ENABLED=false deployments to untrusted networks.',
              'Use TLS in production.',
              'Use named accounts instead of shared admin accounts.',
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
