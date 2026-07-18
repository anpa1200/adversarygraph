import { useQuery } from '@tanstack/react-query';
import type React from 'react';
import { Header } from '@/components/Layout/Header';
import { observabilityApi, type ObservabilityTrace } from '@/api/client';

function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h ${minutes}m`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m ${seconds % 60}s`;
}

function statusClass(status: number) {
  if (status >= 500) return 'text-red-300';
  if (status >= 400) return 'text-amber-200';
  if (status >= 300) return 'text-sky-300';
  return 'text-emerald-300';
}

export function Observability() {
  const summary = useQuery({
    queryKey: ['observability-summary'],
    queryFn: observabilityApi.summary,
    refetchInterval: 10000,
  });
  const logs = useQuery({
    queryKey: ['observability-logs'],
    queryFn: () => observabilityApi.logs(120),
    refetchInterval: 15000,
  });
  const metrics = useQuery({
    queryKey: ['observability-metrics'],
    queryFn: observabilityApi.metrics,
    refetchInterval: 15000,
  });

  const data = summary.data;
  const traces = data?.recent_traces ?? [];
  const statusRows = Object.entries(data?.requests_by_status ?? {}).sort(([a], [b]) => a.localeCompare(b));

  return (
    <>
      <Header title="Observability" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <h2 className="text-sm font-semibold text-sky-100">Operational telemetry boundary</h2>
            <p className="mt-2 max-w-4xl text-xs leading-5 text-sky-100/80">
              This dashboard shows API health telemetry, request traces, safe log tails, and Prometheus-compatible metrics.
              It is for platform operation and troubleshooting. It does not expose configured secrets or raw uploaded report content.
            </p>
          </section>

          <section className="grid gap-4 md:grid-cols-4">
            <Metric label="API uptime" value={data ? formatUptime(data.uptime_seconds) : 'loading'} />
            <Metric label="Requests" value={String(data?.requests_total ?? 0)} />
            <Metric label="Average latency" value={`${data?.latency?.avg_ms ?? 0} ms`} />
            <Metric label="Max latency" value={`${data?.latency?.max_ms ?? 0} ms`} tone={(data?.latency?.max_ms ?? 0) > 1500 ? 'warn' : 'ok'} />
          </section>

          <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Request Status">
              <div className="grid gap-3 p-4 sm:grid-cols-4">
                {statusRows.length ? statusRows.map(([family, count]) => (
                  <div key={family} className="rounded border border-gray-800 bg-gray-950 p-3">
                    <div className="text-2xl font-semibold text-white">{count}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-gray-500">{family}</div>
                  </div>
                )) : <p className="text-sm text-gray-500">No request counters yet.</p>}
              </div>
            </Panel>

            <Panel title="Log File">
              <div className="space-y-3 p-4 text-xs text-gray-300">
                <Info label="Path" value={data?.log_file?.path ?? '-'} />
                <Info label="Exists" value={data?.log_file?.exists ? 'yes' : 'no'} />
                <Info label="Size" value={`${data?.log_file?.size_bytes ?? 0} bytes`} />
                <a
                  className="secondary-action block text-center"
                  href="/api/observability/metrics"
                  target="_blank"
                  rel="noreferrer"
                >
                  Open Prometheus metrics
                </a>
              </div>
            </Panel>
          </section>

          <section className="grid gap-5 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
            <Panel title="Recent Request Traces">
              <TraceTable traces={traces} />
            </Panel>

            <Panel title="Top Routes">
              <div className="max-h-[360px] overflow-y-auto p-3">
                {(data?.top_routes ?? []).map(route => (
                  <div key={route.route} className="grid grid-cols-[1fr_72px] gap-3 border-b border-gray-900 py-2 text-xs">
                    <span className="break-all font-mono text-gray-300">{route.route}</span>
                    <span className="text-right text-mitre-accent">{route.count}</span>
                  </div>
                ))}
                {!data?.top_routes?.length && <p className="p-3 text-sm text-gray-500">No routes observed yet.</p>}
              </div>
            </Panel>
          </section>

          <section className="grid gap-5 xl:grid-cols-2">
            <Panel title="API Log Tail">
              <pre className="max-h-[420px] overflow-auto bg-black/50 p-4 text-[11px] leading-5 text-gray-300">
                {(logs.data?.lines ?? ['No log lines returned.']).join('\n')}
              </pre>
            </Panel>

            <Panel title="Prometheus Metrics Preview">
              <pre className="max-h-[420px] overflow-auto bg-black/50 p-4 text-[11px] leading-5 text-gray-300">
                {metrics.data || 'No metrics returned.'}
              </pre>
            </Panel>
          </section>

          {data?.last_error && (
            <section className="rounded-lg border border-red-500/50 bg-red-950/25 p-4">
              <h2 className="text-sm font-semibold text-red-100">Last API error</h2>
              <TraceLine trace={data.last_error} />
            </section>
          )}
        </div>
      </div>
    </>
  );
}

function Metric({ label, value, tone = 'ok' }: { label: string; value: string; tone?: 'ok' | 'warn' }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className={tone === 'warn' ? 'text-2xl font-semibold text-amber-200' : 'text-2xl font-semibold text-white'}>{value}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
      <h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className="text-[10px] uppercase tracking-wide text-gray-600">{label}</div>
      <div className="mt-1 break-all font-mono text-gray-200">{value}</div>
    </div>
  );
}

function TraceTable({ traces }: { traces: ObservabilityTrace[] }) {
  if (!traces.length) return <p className="p-4 text-sm text-gray-500">No request traces yet.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="bg-gray-950 text-gray-500">
          <tr>
            <th className="px-3 py-2">Time</th>
            <th className="px-3 py-2">Method</th>
            <th className="px-3 py-2">Path</th>
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Latency</th>
            <th className="px-3 py-2">Request ID</th>
          </tr>
        </thead>
        <tbody>
          {traces.map(trace => (
            <tr key={`${trace.request_id}-${trace.timestamp}`} className="border-t border-gray-900">
              <td className="px-3 py-2 text-gray-500">{new Date(trace.timestamp).toLocaleTimeString()}</td>
              <td className="px-3 py-2 font-mono text-gray-300">{trace.method}</td>
              <td className="max-w-[360px] break-all px-3 py-2 font-mono text-gray-300">{trace.path}</td>
              <td className={`px-3 py-2 font-semibold ${statusClass(trace.status_code)}`}>{trace.status_code}</td>
              <td className="px-3 py-2 text-gray-400">{trace.duration_ms} ms</td>
              <td className="max-w-[220px] truncate px-3 py-2 font-mono text-gray-600">{trace.request_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function TraceLine({ trace }: { trace: ObservabilityTrace }) {
  return (
    <div className="mt-3 grid gap-3 text-xs md:grid-cols-[120px_1fr_100px_100px]">
      <span className="font-mono text-red-200">{trace.method}</span>
      <span className="break-all font-mono text-red-100">{trace.path}</span>
      <span className={statusClass(trace.status_code)}>{trace.status_code}</span>
      <span className="text-red-100/80">{trace.duration_ms} ms</span>
    </div>
  );
}
