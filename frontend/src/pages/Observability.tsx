import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type React from 'react';
import { useState } from 'react';
import type { Edge, Node } from '@xyflow/react';
import { Header } from '@/components/Layout/Header';
import { PermissionNotice } from '@/components/PermissionNotice';
import { EntityGraph } from '@/components/ui/graph';
import { useHasPermission } from '@/hooks/useCurrentUser';
import {
  observabilityApi,
  type ObservabilityTrace,
  type PlatformArchitectureSnapshot,
  type PersistedRuntimeGraph,
  type RuntimeTopology,
} from '@/api/client';

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
  const queryClient = useQueryClient();
  const canViewAudit = useHasPermission('view_audit');
  const canManageRuntime = useHasPermission('manage_intel');
  const [runtimeQuery, setRuntimeQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [runtimeWindow, setRuntimeWindow] = useState(60);
  const [selectedRuntimeServices, setSelectedRuntimeServices] = useState<string[]>([]);
  const summary = useQuery({
    queryKey: ['observability-summary'],
    queryFn: observabilityApi.summary,
    refetchInterval: 30000,
    enabled: canViewAudit,
  });
  const architecture = useQuery({
    queryKey: ['platform-architecture', runtimeWindow],
    queryFn: () => observabilityApi.architecture(runtimeWindow),
    refetchInterval: 30000,
    enabled: canViewAudit,
  });
  const logs = useQuery({
    queryKey: ['observability-logs'],
    queryFn: () => observabilityApi.logs(120),
    refetchInterval: 30000,
    enabled: canViewAudit,
  });
  const metrics = useQuery({
    queryKey: ['observability-metrics'],
    queryFn: observabilityApi.metrics,
    refetchInterval: 30000,
    enabled: canViewAudit,
  });
  const skywalkingStatus = useQuery({
    queryKey: ['skywalking-status'],
    queryFn: observabilityApi.skywalkingStatus,
    refetchInterval: 30000,
  });
  const runtimeTopology = useQuery({
    queryKey: ['skywalking-topology', submittedQuery, runtimeWindow],
    queryFn: () => submittedQuery
      ? observabilityApi.skywalkingInvestigate({ query: submittedQuery, minutes: runtimeWindow })
      : observabilityApi.skywalkingTopology({ minutes: runtimeWindow }),
    enabled: skywalkingStatus.data?.connected === true,
  });
  const storedRuntime = useQuery({
    queryKey: ['stored-runtime-graph', submittedQuery],
    queryFn: () => observabilityApi.storedRuntimeGraph({ query: submittedQuery, limit: 300 }),
  });
  const syncRuntime = useMutation({
    mutationFn: () => observabilityApi.syncSkywalking({
      minutes: runtimeWindow,
      tlp: 'TLP:AMBER+STRICT',
    }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['stored-runtime-graph'] });
    },
  });
  const promoteRuntime = useMutation({
    mutationFn: () => observabilityApi.promoteRuntimeEvidence(selectedRuntimeServices),
    onSuccess: () => setSelectedRuntimeServices([]),
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

          {canViewAudit && (
            <PlatformArchitectureDashboard
              snapshot={architecture.data}
              loading={architecture.isFetching}
              error={architecture.error}
              windowMinutes={runtimeWindow}
            />
          )}

          <RuntimeDependencyInvestigation
            status={skywalkingStatus.data}
            topology={runtimeTopology.data}
            loading={runtimeTopology.isFetching}
            error={runtimeTopology.error}
            stored={storedRuntime.data}
            syncResult={syncRuntime.data}
            promoteResult={promoteRuntime.data}
            selectedServiceIds={selectedRuntimeServices}
            query={runtimeQuery}
            windowMinutes={runtimeWindow}
            onQueryChange={setRuntimeQuery}
            onWindowChange={setRuntimeWindow}
            onSubmit={() => setSubmittedQuery(runtimeQuery.trim())}
            onSync={() => syncRuntime.mutate()}
            onPromote={() => promoteRuntime.mutate()}
            onSelectionChange={setSelectedRuntimeServices}
            syncPending={syncRuntime.isPending}
            promotePending={promoteRuntime.isPending}
            canManage={canManageRuntime}
            onClear={() => {
              setRuntimeQuery('');
              setSubmittedQuery('');
            }}
          />

          {canViewAudit ? <>
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
          </> : (
            <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
              <PermissionNotice permission="view_audit" action="view API traces, logs, and platform metrics" compact />
            </section>
          )}
        </div>
      </div>
    </>
  );
}

const layerOrder = ['experience', 'application', 'intelligence', 'telemetry', 'runtime', 'storage'];
const layerLabels: Record<string, string> = {
  experience: 'EXPERIENCE',
  application: 'APPLICATION & APIs',
  intelligence: 'INTELLIGENCE STREAMS',
  telemetry: 'OBSERVABILITY',
  runtime: 'LIVE RUNTIME',
  storage: 'DATA PLANE',
};
const layerColors: Record<string, string> = {
  experience: '#38bdf8',
  application: '#a78bfa',
  intelligence: '#f43f5e',
  telemetry: '#22d3ee',
  runtime: '#34d399',
  storage: '#f59e0b',
};

function compactNumber(value: number | null | undefined) {
  if (value == null) return '—';
  return Intl.NumberFormat(undefined, { notation: value >= 10000 ? 'compact' : 'standard', maximumFractionDigits: 1 }).format(value);
}

function PlatformArchitectureDashboard({
  snapshot,
  loading,
  error,
  windowMinutes,
}: {
  snapshot?: PlatformArchitectureSnapshot;
  loading: boolean;
  error: Error | null;
  windowMinutes: number;
}) {
  const grouped = new Map<string, PlatformArchitectureSnapshot['nodes']>();
  for (const node of snapshot?.nodes ?? []) {
    grouped.set(node.layer, [...(grouped.get(node.layer) ?? []), node]);
  }
  const graphNodes: Node[] = [];
  let layerX = 0;
  for (const layer of layerOrder) {
    const values = grouped.get(layer) ?? [];
    values.forEach((item, row) => {
      const color = layerColors[layer];
      graphNodes.push({
        id: item.id,
        position: {
          x: layerX + Math.floor(row / 5) * 240,
          y: (row % 5) * 118,
        },
        style: {
          width: 220,
          minHeight: 82,
          border: `1px solid ${item.observed ? color : '#374151'}`,
          borderRadius: 8,
          background: item.observed ? `${color}16` : '#080d18',
          color: '#f8fafc',
          padding: 0,
          boxShadow: item.observed ? `0 0 22px ${color}18` : 'none',
        },
        data: {
          label: (
            <div className="p-3 text-left">
              <div className="flex items-start justify-between gap-2">
                <span className="text-[9px] font-semibold tracking-[0.15em]" style={{ color }}>{layerLabels[layer]}</span>
                <span className={`h-2 w-2 rounded-full ${item.observed ? 'animate-pulse' : ''}`} style={{ background: item.observed ? color : '#4b5563' }} />
              </div>
              <div className="mt-1 truncate text-xs font-semibold" title={item.label}>{item.label}</div>
              <div className="mt-1 flex items-end justify-between gap-2 text-[9px] text-gray-400">
                <span className="truncate">{item.technology || item.kind.replace(/_/g, ' ')}</span>
                {item.metric != null && <strong className="text-sm text-white">{compactNumber(item.metric)}</strong>}
              </div>
              {item.metric_label && <div className="mt-0.5 text-right text-[8px] text-gray-500">{item.metric_label}</div>}
            </div>
          ),
        },
      });
    });
    layerX += Math.max(1, Math.ceil(values.length / 5)) * 240 + 40;
  }
  const edgeColors: Record<string, string> = {
    runtime_call: '#34d399',
    api_traffic: '#38bdf8',
    correlation: '#f43f5e',
    index_flow: '#a78bfa',
    validation_flow: '#f59e0b',
    telemetry: '#22d3ee',
  };
  const graphEdges: Edge[] = (snapshot?.edges ?? []).map(item => ({
    id: item.id,
    source: item.source,
    target: item.target,
    label: item.count != null ? `${item.label} · ${compactNumber(item.count)}` : item.label,
    animated: item.observed,
    style: {
      stroke: edgeColors[item.kind] ?? '#4b5563',
      strokeWidth: item.observed ? 2 : 1,
      strokeDasharray: item.observed ? undefined : '5 5',
    },
    labelStyle: { fill: '#94a3b8', fontSize: 9 },
    labelBgStyle: { fill: '#080d18', fillOpacity: 0.9 },
  }));

  return (
    <section className="overflow-hidden rounded-xl border border-sky-900/70 bg-gradient-to-br from-gray-950 via-gray-950 to-sky-950/30">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-800 p-4">
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-sky-400">Live platform architecture</p>
          <h2 className="mt-1 text-xl font-semibold text-white">Intelligence, API, runtime and evidence mesh</h2>
          <p className="mt-1 text-xs text-gray-400">
            Database counts, API middleware telemetry, redacted log activity and SkyWalking calls in one provenance-labelled view.
          </p>
        </div>
        <div className="flex gap-2 text-[10px]">
          <Legend color="#34d399" label="observed" />
          <Legend color="#4b5563" label="configured" dashed />
          <span className="rounded border border-gray-800 bg-black/30 px-2 py-1.5 text-gray-400">{windowMinutes} min window</span>
          <span className={`rounded border px-2 py-1.5 ${snapshot?.skywalking.health.connected ? 'border-emerald-800 text-emerald-300' : 'border-amber-800 text-amber-300'}`}>
            OAP {snapshot?.skywalking.health.status ?? 'checking'}
          </span>
        </div>
      </div>
      {error ? (
        <p className="m-4 rounded border border-red-900 bg-red-950/20 p-3 text-xs text-red-200">{error.message}</p>
      ) : (
        <>
          <div className="h-[660px] p-3">
            {snapshot ? <EntityGraph nodes={graphNodes} edges={graphEdges} /> : <div className="grid h-full place-items-center text-sm text-gray-500">{loading ? 'Building architecture snapshot…' : 'No architecture data.'}</div>}
          </div>
          {snapshot && (
            <div className="grid gap-3 border-t border-gray-800 p-4 xl:grid-cols-[1.05fr_1fr_1fr]">
              <ArchitectureStreams snapshot={snapshot} />
              <ArchitectureCorrelations snapshot={snapshot} />
              <ArchitectureOperations snapshot={snapshot} />
            </div>
          )}
        </>
      )}
      {snapshot && (
        <p className="border-t border-sky-900/50 bg-sky-950/20 px-4 py-3 text-[10px] leading-5 text-sky-100/70">
          <strong className="text-sky-200">Evidence boundary:</strong> {snapshot.provenance.boundary}
          {' '}Solid animated links are measured or observed; dashed links are configured architecture.
          Snapshot {new Date(snapshot.generated_at).toLocaleString()}.
        </p>
      )}
    </section>
  );
}

function Legend({ color, label, dashed = false }: { color: string; label: string; dashed?: boolean }) {
  return <span className="flex items-center gap-1.5 rounded border border-gray-800 bg-black/30 px-2 py-1.5 text-gray-400">
    <span className="w-5" style={{ borderTop: `2px ${dashed ? 'dashed' : 'solid'} ${color}` }} />{label}
  </span>;
}

function ArchitectureStreams({ snapshot }: { snapshot: PlatformArchitectureSnapshot }) {
  const rows = [
    ['IOC records', snapshot.streams.ioc.records, `${snapshot.streams.ioc.enabled ?? '—'} feeds · ${snapshot.streams.ioc.degraded ?? '—'} degraded`],
    ['CVE records', snapshot.streams.cve.records, `${compactNumber(snapshot.streams.cve.known_exploited)} KEV`],
    ['RAG documents', snapshot.streams.rag.documents, `${compactNumber(snapshot.streams.rag.chunks)} chunks`],
    ['ATT&CK techniques', snapshot.counts.attack?.value, `${compactNumber(snapshot.counts.actors?.value)} groups`],
  ] as const;
  return <div className="rounded border border-gray-800 bg-black/30 p-3">
    <h3 className="text-xs font-semibold text-white">Intelligence streams</h3>
    <div className="mt-2 grid grid-cols-2 gap-2">
      {rows.map(([label, value, note]) => <div key={label} className="rounded border border-gray-800 bg-gray-950/70 p-2">
        <div className="text-lg font-semibold text-white">{compactNumber(value)}</div>
        <div className="text-[10px] text-gray-400">{label}</div>
        <div className="mt-1 text-[9px] text-gray-600">{note}</div>
      </div>)}
    </div>
  </div>;
}

function ArchitectureCorrelations({ snapshot }: { snapshot: PlatformArchitectureSnapshot }) {
  return <div className="rounded border border-gray-800 bg-black/30 p-3">
    <h3 className="text-xs font-semibold text-white">Cross-linked knowledge</h3>
    <div className="mt-2 space-y-2">
      {snapshot.correlations.map(item => <div key={item.id} className="flex items-center justify-between rounded border border-gray-800 bg-gray-950/70 px-3 py-2">
        <span className="text-[11px] text-gray-300">{item.label}</span>
        <strong className="text-sm text-mitre-accent">{compactNumber(item.count)}</strong>
      </div>)}
    </div>
  </div>;
}

function ArchitectureOperations({ snapshot }: { snapshot: PlatformArchitectureSnapshot }) {
  return <div className="rounded border border-gray-800 bg-black/30 p-3">
    <h3 className="text-xs font-semibold text-white">API and log pulse</h3>
    <div className="mt-2 grid grid-cols-3 gap-2">
      <MiniMetric label="Requests" value={compactNumber(snapshot.api.requests_total)} />
      <MiniMetric label="Avg latency" value={`${snapshot.api.latency.avg_ms} ms`} />
      <MiniMetric label="Errors" value={compactNumber((snapshot.api.requests_by_status?.['5xx'] ?? 0) + (snapshot.logs.levels.error ?? 0))} />
    </div>
    <div className="mt-2 max-h-28 overflow-y-auto">
      {snapshot.api.top_routes.slice(0, 6).map(route => <div key={route.route} className="flex justify-between gap-2 border-t border-gray-900 py-1.5 text-[9px]">
        <span className="truncate font-mono text-gray-400">{route.route}</span>
        <span className="text-sky-300">{route.count}</span>
      </div>)}
    </div>
  </div>;
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-gray-800 bg-gray-950/70 p-2">
    <div className="text-sm font-semibold text-white">{value}</div>
    <div className="text-[9px] text-gray-500">{label}</div>
  </div>;
}

function RuntimeDependencyInvestigation({
  status,
  topology,
  loading,
  error,
  stored,
  syncResult,
  promoteResult,
  selectedServiceIds,
  query,
  windowMinutes,
  onQueryChange,
  onWindowChange,
  onSubmit,
  onSync,
  onPromote,
  onSelectionChange,
  syncPending,
  promotePending,
  canManage,
  onClear,
}: {
  status?: Awaited<ReturnType<typeof observabilityApi.skywalkingStatus>>;
  topology?: RuntimeTopology;
  loading: boolean;
  error: Error | null;
  stored?: PersistedRuntimeGraph;
  syncResult?: Awaited<ReturnType<typeof observabilityApi.syncSkywalking>>;
  promoteResult?: Awaited<ReturnType<typeof observabilityApi.promoteRuntimeEvidence>>;
  selectedServiceIds: string[];
  query: string;
  windowMinutes: number;
  onQueryChange: (value: string) => void;
  onWindowChange: (value: number) => void;
  onSubmit: () => void;
  onSync: () => void;
  onPromote: () => void;
  onSelectionChange: (ids: string[]) => void;
  syncPending: boolean;
  promotePending: boolean;
  canManage: boolean;
  onClear: () => void;
}) {
  const labels = new Map((topology?.nodes ?? []).map(node => [node.id, node.label]));
  return (
    <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Runtime dependency investigation</h2>
          <p className="mt-1 text-xs text-gray-500">
            Apache SkyWalking service calls, normalized as a read-only evidence graph with explicit provenance.
          </p>
        </div>
        <span className={`rounded-full border px-2 py-1 text-[10px] uppercase ${
          status?.connected ? 'border-emerald-700 text-emerald-300' : 'border-gray-700 text-gray-500'
        }`}>
          {status?.status ?? 'checking'}
        </span>
      </div>
      <div className="space-y-4 p-4">
        {!status?.enabled ? (
          <div className="rounded border border-gray-800 bg-gray-950 p-4 text-xs leading-5 text-gray-400">
            SkyWalking is optional and currently disabled. Set <code>SKYWALKING_ENABLED=true</code> and point
            <code> SKYWALKING_GRAPHQL_URL</code> at an operator-controlled OAP GraphQL endpoint.
          </div>
        ) : !status.connected ? (
          <div className="rounded border border-amber-800/70 bg-amber-950/20 p-4 text-xs text-amber-100">
            {status.message}
          </div>
        ) : (
          <>
            <form
              className="grid gap-3 md:grid-cols-[minmax(0,1fr)_150px_auto_auto]"
              onSubmit={event => {
                event.preventDefault();
                onSubmit();
              }}
            >
              <label className="grid gap-1 text-xs text-gray-400">
                Service, technology, endpoint clue, or incident term
                <input
                  className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white outline-none focus:border-mitre-accent"
                  value={query}
                  maxLength={200}
                  onChange={event => onQueryChange(event.target.value)}
                  placeholder="checkout, PostgreSQL, auth..."
                />
              </label>
              <label className="grid gap-1 text-xs text-gray-400">
                Observation window
                <select
                  className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
                  value={windowMinutes}
                  onChange={event => onWindowChange(Number(event.target.value))}
                >
                  <option value={15}>15 minutes</option>
                  <option value={60}>1 hour</option>
                  <option value={360}>6 hours</option>
                  <option value={1440}>24 hours</option>
                  <option value={10080}>7 days</option>
                </select>
              </label>
              <button className="primary-action self-end" type="submit" disabled={loading || query.trim().length === 1}>
                {loading ? 'Loading…' : 'Investigate'}
              </button>
              <button className="secondary-action self-end" type="button" onClick={onClear}>Clear</button>
            </form>

            {error && <p className="rounded border border-red-800 bg-red-950/20 p-3 text-xs text-red-200">{error.message}</p>}

            <div className="flex flex-wrap items-center gap-3 rounded border border-gray-800 bg-gray-950 p-3">
              <button className="primary-action" type="button" onClick={onSync} disabled={syncPending || !canManage}>
                {syncPending ? 'Synchronizing…' : 'Sync into AdversaryGraph'}
              </button>
              <p className="max-w-3xl text-[11px] leading-5 text-gray-500">
                Stores normalized services and calls, proposes inventory links, enforces retention, and immediately refreshes
                exact and full-text RAG records. Vector refresh remains in scheduled reconciliation. Raw spans, logs, and
                request bodies are not imported.
              </p>
            </div>
            {syncResult && (
              <p className="rounded border border-emerald-800/60 bg-emerald-950/20 p-3 text-xs text-emerald-200">
                Snapshot {syncResult.snapshot_id}: {syncResult.services_created} services and {syncResult.calls_created} calls created;
                {' '}{syncResult.asset_links_created} candidate asset links; RAG {syncResult.rag.status}.
              </p>
            )}

            <div className="grid gap-3 sm:grid-cols-3">
              <Metric label="Observed services" value={String(topology?.counts.nodes ?? 0)} />
              <Metric label="Runtime calls" value={String(topology?.counts.edges ?? 0)} />
              <Metric label="Window" value={`${topology?.window_minutes ?? windowMinutes} min`} />
            </div>

            <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.75fr)]">
              <div className="rounded border border-gray-800 bg-gray-950 p-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Observed entities</h3>
                <div className="mt-3 grid max-h-[360px] gap-2 overflow-y-auto sm:grid-cols-2">
                  {(topology?.nodes ?? []).map(node => (
                    <article key={node.id} className="rounded border border-gray-800 bg-gray-900 p-3">
                      <div className="truncate text-sm font-semibold text-white" title={node.label}>{node.label}</div>
                      <div className="mt-1 text-[10px] uppercase text-sky-300">{node.technology}</div>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {node.layers.map(layer => <span key={layer} className="rounded border border-gray-700 px-1.5 py-0.5 text-[9px] text-gray-400">{layer}</span>)}
                      </div>
                    </article>
                  ))}
                  {!topology?.nodes.length && <p className="text-xs text-gray-500">No matching runtime services in this window.</p>}
                </div>
              </div>
              <div className="rounded border border-gray-800 bg-gray-950 p-3">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Observed relationships</h3>
                <div className="mt-3 max-h-[360px] space-y-2 overflow-y-auto">
                  {(topology?.edges ?? []).map(edge => (
                    <div key={edge.id} className="rounded border border-gray-800 bg-gray-900 p-3 text-xs">
                      <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2">
                        <span className="truncate text-gray-200" title={labels.get(edge.source)}>{labels.get(edge.source) ?? edge.source}</span>
                        <span className="text-mitre-accent">→</span>
                        <span className="truncate text-gray-200" title={labels.get(edge.target)}>{labels.get(edge.target) ?? edge.target}</span>
                      </div>
                      {!!edge.detect_points.length && <div className="mt-2 text-[10px] text-gray-600">{edge.detect_points.join(' · ')}</div>}
                    </div>
                  ))}
                  {!topology?.edges.length && <p className="text-xs text-gray-500">No matching runtime calls in this window.</p>}
                </div>
              </div>
            </div>
            {topology?.provenance && (
              <p className="rounded border border-sky-900/60 bg-sky-950/20 p-3 text-[11px] leading-5 text-sky-100/70">
                <strong className="text-sky-200">Evidence boundary:</strong> {topology.provenance.statement}
                {topology.truncated && ' The result was truncated at the configured node limit.'}
              </p>
            )}

            <PersistedRuntimeEvidence
              graph={stored}
              selected={selectedServiceIds}
              onSelectionChange={onSelectionChange}
              onPromote={onPromote}
              promoting={promotePending}
              result={promoteResult}
              canManage={canManage}
            />
          </>
        )}
      </div>
    </section>
  );
}

function PersistedRuntimeEvidence({
  graph,
  selected,
  onSelectionChange,
  onPromote,
  promoting,
  result,
  canManage,
}: {
  graph?: PersistedRuntimeGraph;
  selected: string[];
  onSelectionChange: (ids: string[]) => void;
  onPromote: () => void;
  promoting: boolean;
  result?: Awaited<ReturnType<typeof observabilityApi.promoteRuntimeEvidence>>;
  canManage: boolean;
}) {
  const selectedSet = new Set(selected);
  const toggle = (id: string) => onSelectionChange(
    selectedSet.has(id) ? selected.filter(value => value !== id) : [...selected, id]
  );
  return (
    <section className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">AdversaryGraph runtime evidence store</h3>
          <p className="mt-1 text-[11px] text-gray-600">
            Persisted, TLP-marked observations available to RAG, the AI assistant, MCP, asset correlation, and Evidence Graph.
          </p>
        </div>
        <button
          type="button"
          className="secondary-action"
          disabled={!canManage || !selected.length || promoting}
          onClick={onPromote}
        >
          {promoting ? 'Promoting…' : `Promote ${selected.length || ''} to Evidence Graph`}
        </button>
      </div>
      <div className="mt-3 grid max-h-[320px] gap-2 overflow-y-auto sm:grid-cols-2 xl:grid-cols-3">
        {(graph?.nodes ?? []).map(node => (
          <article key={node.id} className="flex gap-2 rounded border border-gray-800 bg-gray-900 p-3">
            <input
              type="checkbox"
              disabled={!canManage}
              checked={selectedSet.has(node.id)}
              onChange={() => toggle(node.id)}
              className="mt-0.5"
              aria-label={`Select ${node.label} for Evidence Graph promotion`}
            />
            <span className="min-w-0">
              <span className="block truncate text-xs font-semibold text-white" title={node.label}>{node.label}</span>
              <span className="mt-1 block text-[10px] text-sky-300">{node.technology} · {node.observation_count} observations</span>
              <span className="mt-1 block text-[9px] text-gray-600">{node.tlp} · last {new Date(node.last_observed_at).toLocaleString()}</span>
              {(graph?.asset_links ?? []).filter(link => link.runtime_service_id === node.id).map(link => (
                <a
                  key={link.asset_id}
                  href={link.route}
                  className="mt-2 block text-[10px] text-emerald-300 hover:underline"
                  onClick={event => event.stopPropagation()}
                >
                  Candidate asset: {link.asset_name} · {link.confidence}% ↗
                </a>
              ))}
            </span>
          </article>
        ))}
        {!graph?.nodes.length && <p className="text-xs text-gray-600">No synchronized runtime services yet.</p>}
      </div>
      {result && (
        <p className="mt-3 rounded border border-sky-900 bg-sky-950/20 p-3 text-xs text-sky-200">
          Created {result.nodes_created} evidence nodes and {result.edges_created} relationships.
          {' '}<a href={result.route} className="underline">Open Evidence Graph</a>. {result.boundary}
        </p>
      )}
    </section>
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
