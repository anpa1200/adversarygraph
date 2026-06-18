import { Header } from '@/components/Layout/Header';
import { useSearchParams } from 'react-router-dom';

const checks = [
  {
    title: 'Run the built-in self-test',
    body: 'This validates API, database, Redis, and ATT&CK/ATLAS data from inside Docker.',
    command: 'docker compose run --rm selftest',
  },
  {
    title: 'Check the API directly',
    body: 'A healthy deployment returns status ok and per-service check results.',
    command: 'curl http://localhost:8000/api/system/selftest | jq',
  },
  {
    title: 'Check the frontend proxy',
    body: 'If this fails but port 8000 works, the frontend container or Vite proxy is the problem.',
    command: 'curl http://localhost:3000/api/system/selftest | jq',
  },
  {
    title: 'Verify ATT&CK matrix data',
    body: 'Enterprise should return tactics and techniques after first startup sync completes.',
    command: "curl 'http://localhost:3000/api/attack/tactics?domain=enterprise-attack' | jq length\ncurl 'http://localhost:3000/api/attack/techniques?domain=enterprise-attack&subtechniques=true' | jq length",
  },
  {
    title: 'Read service logs',
    body: 'Use these when the popup shows HTTP 500, connection reset, or empty matrix data.',
    command: 'docker compose logs --tail=120 api\ndocker compose logs --tail=120 frontend\ndocker compose logs --tail=120 postgres',
  },
  {
    title: 'Restart without deleting data',
    body: 'This recreates containers and keeps Docker volumes, including PostgreSQL and ATT&CK cache.',
    command: 'docker compose down\ndocker compose up -d',
  },
];

const commonIssues = [
  {
    title: 'Navigator shows "No ATT&CK data yet"',
    body: 'The API may still be ingesting references, the first tactic request may have failed during startup, or the browser has cached an old failed query. Wait for self-test OK, then hard refresh the browser.',
  },
  {
    title: 'Self-test returns HTTP 500',
    body: 'Open API logs first. The usual causes are database credentials, Redis connection, missing ATT&CK records, or a migration/startup exception.',
  },
  {
    title: 'Frontend works but API calls fail',
    body: 'Check whether localhost:8000 works. If port 8000 works but localhost:3000/api fails, inspect frontend logs and Vite proxy configuration.',
  },
  {
    title: 'Database password mismatch after changing .env',
    body: 'Existing PostgreSQL volumes keep the old role password. Run the db-apply-env-creds helper or update the role manually.',
  },
];

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="mt-3 overflow-x-auto rounded border border-gray-800 bg-black/50 p-3 text-xs leading-5 text-gray-200">
      <code>{children}</code>
    </pre>
  );
}

export function Troubleshooting() {
  const [params] = useSearchParams();
  const error = params.get('error');
  const status = params.get('status');
  const url = params.get('url');

  return (
    <>
      <Header title="Troubleshooting" />
      <div className="flex-1 overflow-auto p-6">
        <div className="mx-auto max-w-6xl space-y-6">
          {(error || status || url) && (
            <section className="rounded-lg border border-red-500/50 bg-red-950/30 p-4">
              <h2 className="text-sm font-semibold text-red-100">Current Error Context</h2>
              <div className="mt-3 grid gap-2 text-xs text-red-100/90 md:grid-cols-3">
                <div>
                  <div className="font-mono text-red-300">status</div>
                  <div>{status || 'network/client error'}</div>
                </div>
                <div>
                  <div className="font-mono text-red-300">url</div>
                  <div className="break-all">{url || 'not provided'}</div>
                </div>
                <div>
                  <div className="font-mono text-red-300">message</div>
                  <div>{error || 'not provided'}</div>
                </div>
              </div>
            </section>
          )}

          <section>
            <h2 className="text-lg font-semibold text-white">Deployment Checks</h2>
            <p className="mt-2 max-w-3xl text-sm text-gray-400">
              These checks are designed for the Docker deployment. Run them from the AdversaryGraph repository
              directory on the host machine.
            </p>
            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              {checks.map(check => (
                <article key={check.title} className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
                  <h3 className="text-sm font-semibold text-white">{check.title}</h3>
                  <p className="mt-2 text-xs leading-5 text-gray-400">{check.body}</p>
                  <CodeBlock>{check.command}</CodeBlock>
                </article>
              ))}
            </div>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-white">Common Problems</h2>
            <div className="mt-4 grid gap-4 md:grid-cols-2">
              {commonIssues.map(issue => (
                <article key={issue.title} className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
                  <h3 className="text-sm font-semibold text-white">{issue.title}</h3>
                  <p className="mt-2 text-xs leading-5 text-gray-400">{issue.body}</p>
                </article>
              ))}
            </div>
          </section>

          <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
            <h2 className="text-lg font-semibold text-white">Recovery Order</h2>
            <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-gray-300">
              <li>Run the self-test and read the failed check name.</li>
              <li>Check API logs for the first Python exception or database connection error.</li>
              <li>Confirm the API returns tactics and techniques through the frontend proxy.</li>
              <li>Hard refresh the browser after self-test passes.</li>
              <li>Only delete Docker volumes if you intentionally want to rebuild all local data.</li>
            </ol>
          </section>
        </div>
      </div>
    </>
  );
}
