import { Header } from '@/components/Layout/Header';
import { useMutation } from '@tanstack/react-query';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { systemApi, type SelfTestResult, type TroubleshootingAssistantResponse } from '@/api/client';

const checks = [
  {
    title: 'Run the built-in self-test',
    body: 'This validates API, database, Redis, ATT&CK/ATLAS data, and configured provider keys from inside Docker.',
    command: 'docker compose run --rm selftest',
  },
  {
    title: 'Check the API directly',
    body: 'A healthy deployment returns status ok and per-service check results through the frontend proxy.',
    command: 'curl http://localhost:3000/api/system/selftest | jq',
  },
  {
    title: 'Check the frontend proxy',
    body: 'The default Compose deployment keeps the API internal and exposes API routes through localhost:3000.',
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
    body: 'Check frontend and API container logs. In the default Compose deployment, the browser should call localhost:3000/api, while the API container stays internal.',
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
  const [provider, setProvider] = useState<'local' | 'claude' | 'openai' | 'gemini' | 'minimax'>('local');
  const [notes, setNotes] = useState('');
  const [selftest, setSelftest] = useState<SelfTestResult | null>(null);
  const selftestMutation = useMutation({
    mutationFn: systemApi.selftest,
    onSuccess: setSelftest,
  });
  const assistantMutation = useMutation({
    mutationFn: (payload: Parameters<typeof systemApi.troubleshootingAssistant>[0]) => systemApi.troubleshootingAssistant(payload),
  });

  const askAssistant = () => {
    assistantMutation.mutate({
      provider,
      error_message: error ?? '',
      status: status ?? '',
      url: url ?? '',
      operator_notes: notes,
      selftest_result: selftest ?? undefined,
      include_docker_commands: true,
    });
  };

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

          <section className="rounded-lg border border-cyan-500/30 bg-cyan-950/10 p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white">Troubleshooting AI Assistant</h2>
                <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-400">
                  Build an operator-ready remediation plan from the current error, self-test output, and your notes.
                  The assistant avoids destructive actions and falls back to local deterministic guidance if the selected
                  LLM provider is unavailable.
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <select
                  value={provider}
                  onChange={event => setProvider(event.target.value as typeof provider)}
                  className="field min-w-36"
                  aria-label="AI provider"
                >
                  <option value="local">Local</option>
                  <option value="claude">Claude</option>
                  <option value="openai">OpenAI</option>
                  <option value="gemini">Gemini</option>
                  <option value="minimax">MiniMax</option>
                </select>
                <button
                  type="button"
                  onClick={() => selftestMutation.mutate()}
                  disabled={selftestMutation.isPending}
                  className="secondary-action disabled:cursor-wait disabled:opacity-60"
                >
                  {selftestMutation.isPending ? 'Running...' : 'Run self-test'}
                </button>
                <button
                  type="button"
                  onClick={askAssistant}
                  disabled={assistantMutation.isPending}
                  className="primary-action disabled:cursor-wait disabled:opacity-60"
                >
                  {assistantMutation.isPending ? 'Analyzing...' : 'Ask assistant'}
                </button>
              </div>
            </div>
            <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
              <div className="space-y-3">
                <label className="block text-[10px] font-semibold uppercase tracking-wide text-gray-500">Operator notes</label>
                <textarea
                  value={notes}
                  onChange={event => setNotes(event.target.value)}
                  rows={7}
                  placeholder="Paste the failed check, exact error text, recent change, affected page, or deployment context. Do not paste secrets."
                  className="field min-h-40 w-full resize-y"
                />
                <div className="grid gap-2 text-xs text-gray-400 sm:grid-cols-3">
                  <StatusPill label="Self-test" value={selftest?.status ?? (selftestMutation.isError ? 'failed' : 'not run')} tone={selftest?.status === 'ok' ? 'ok' : selftest ? 'warn' : 'muted'} />
                  <StatusPill label="Context status" value={status || 'none'} tone={status && status !== '200' ? 'warn' : 'muted'} />
                  <StatusPill label="Provider" value={provider} tone="muted" />
                </div>
                {selftestMutation.error && (
                  <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-xs text-red-100">
                    Self-test request failed: {String(selftestMutation.error.message || selftestMutation.error)}
                  </div>
                )}
              </div>
              <AssistantResult result={assistantMutation.data} error={assistantMutation.error} pending={assistantMutation.isPending} />
            </div>
          </section>

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

function StatusPill({ label, value, tone }: { label: string; value: string; tone: 'ok' | 'warn' | 'muted' }) {
  const cls = tone === 'ok'
    ? 'border-green-700 bg-green-950/30 text-green-200'
    : tone === 'warn'
      ? 'border-yellow-700 bg-yellow-950/30 text-yellow-100'
      : 'border-gray-800 bg-gray-950/40 text-gray-400';
  return (
    <div className={`rounded border px-3 py-2 ${cls}`}>
      <div className="text-[10px] uppercase tracking-wide opacity-70">{label}</div>
      <div className="mt-1 truncate font-mono">{value}</div>
    </div>
  );
}

function AssistantResult({ result, error, pending }: {
  result?: TroubleshootingAssistantResponse;
  error: Error | null;
  pending: boolean;
}) {
  if (pending) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 text-sm text-gray-400">
        Analyzing deployment context...
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-lg border border-red-500/50 bg-red-950/30 p-4 text-sm text-red-100">
        Assistant failed: {error.message}
      </div>
    );
  }
  if (!result) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-4 text-sm text-gray-500">
        Run self-test, add context, then ask the assistant for a remediation plan.
      </div>
    );
  }
  return (
    <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${severityClass(result.severity)}`}>{result.severity}</span>
        <span className="text-xs text-gray-500">{result.ai_used ? `${result.provider} · ${result.model}` : 'deterministic fallback'}</span>
      </div>
      <div>
        <h3 className="text-sm font-semibold text-white">Summary</h3>
        <p className="mt-1 text-sm leading-6 text-gray-300">{result.summary}</p>
      </div>
      <div>
        <h3 className="text-sm font-semibold text-white">Likely Root Cause</h3>
        <p className="mt-1 text-sm leading-6 text-gray-300">{result.likely_root_cause}</p>
      </div>
      <ListBlock title="Immediate Actions" items={result.immediate_actions} ordered />
      <CodeListBlock title="Validation Commands" items={result.validation_commands} />
      <ListBlock title="Evidence To Collect" items={result.evidence_to_collect} />
      <ListBlock title="Do Not Do" items={result.do_not_do} danger />
    </div>
  );
}

function ListBlock({ title, items, ordered = false, danger = false }: { title: string; items: string[]; ordered?: boolean; danger?: boolean }) {
  const Tag = ordered ? 'ol' : 'ul';
  return (
    <div>
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <Tag className={`mt-2 space-y-1 pl-5 text-sm leading-6 ${ordered ? 'list-decimal' : 'list-disc'} ${danger ? 'text-red-100' : 'text-gray-300'}`}>
        {items.map(item => <li key={item}>{item}</li>)}
      </Tag>
    </div>
  );
}

function CodeListBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <div className="mt-2 space-y-2">
        {items.map(item => (
          <pre key={item} className="overflow-x-auto rounded border border-gray-800 bg-black/50 p-3 text-xs leading-5 text-gray-200">
            <code>{item}</code>
          </pre>
        ))}
      </div>
    </div>
  );
}

function severityClass(severity: TroubleshootingAssistantResponse['severity']) {
  if (severity === 'critical') return 'bg-red-700 text-white';
  if (severity === 'high') return 'bg-red-950 text-red-100';
  if (severity === 'medium') return 'bg-yellow-950 text-yellow-100';
  return 'bg-green-950 text-green-100';
}
