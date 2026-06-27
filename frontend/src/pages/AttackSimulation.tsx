import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { simulationApi } from '@/api/client';
import type {
  AttackSimulationCatalogItem,
  AttackSimulationForwardResult,
  AttackSimulationLogs,
  AttackSimulationManualResult,
  AttackSimulationPlan,
  AttackSimulationRun,
} from '@/api/client';
import { TtpLink } from '@/utils/ctiLinks';

type DetectionResult = 'passed' | 'failed' | 'partial' | 'not_proven';

export function AttackSimulation() {
  const navigate = useNavigate();
  const { simulationId: routeSimulationId } = useParams();
  const [simulationId, setSimulationId] = useState(routeSimulationId ?? '');
  const [targetId, setTargetId] = useState('lab-web-01');
  const [targetAddress, setTargetAddress] = useState('');
  const [analystNote, setAnalystNote] = useState('');
  const [evidence, setEvidence] = useState('');
  const [gaps, setGaps] = useState('Detection result not proven until SIEM/WAF/firewall evidence is attached.');
  const [detectionResult, setDetectionResult] = useState<DetectionResult>('not_proven');
  const [plan, setPlan] = useState<AttackSimulationPlan | null>(null);
  const [run, setRun] = useState<AttackSimulationRun | null>(null);
  const [manual, setManual] = useState<AttackSimulationManualResult | null>(null);
  const [followRunId, setFollowRunId] = useState('');
  const [liveLogsEnabled, setLiveLogsEnabled] = useState(true);
  const [siemUrl, setSiemUrl] = useState('');
  const [siemToken, setSiemToken] = useState('');
  const [siemSource, setSiemSource] = useState<'web' | 'run'>('web');

  const catalogQuery = useQuery({ queryKey: ['simulation-catalog'], queryFn: simulationApi.catalog });
  const targetsQuery = useQuery({ queryKey: ['simulation-targets'], queryFn: simulationApi.targets });
  const catalog = catalogQuery.data ?? [];
  const targets = targetsQuery.data ?? [];
  const selectedSimulation = catalog.find(item => item.id === simulationId);
  const selectedTarget = targets.find(item => item.id === targetId);

  useEffect(() => {
    setSimulationId(routeSimulationId ?? '');
    setPlan(null);
    setRun(null);
    setManual(null);
  }, [routeSimulationId]);

  useEffect(() => {
    if (selectedTarget) setTargetAddress(selectedTarget.address);
  }, [selectedTarget]);

  const compatibleTargets = useMemo(() => {
    if (!selectedSimulation) return targets;
    return targets.filter(target => target.allowed_simulations.includes(selectedSimulation.id));
  }, [selectedSimulation, targets]);

  useEffect(() => {
    if (!compatibleTargets.length) return;
    if (!compatibleTargets.some(target => target.id === targetId)) {
      setTargetId(compatibleTargets[0].id);
    }
  }, [compatibleTargets, targetId]);

  const actionNote = useMemo(() => {
    const addressContext = targetAddress.trim() ? `Target address context: ${targetAddress.trim()}` : '';
    return [analystNote.trim(), addressContext].filter(Boolean).join('\n');
  }, [analystNote, targetAddress]);

  const planMutation = useMutation({
    mutationFn: () => simulationApi.plan({ simulation_id: simulationId, target_id: targetId, analyst_note: actionNote }),
    onSuccess: next => {
      setPlan(next);
      setRun(null);
      setManual(null);
    },
  });
  const runMutation = useMutation({
    mutationFn: () => simulationApi.run({ simulation_id: simulationId, target_id: targetId, analyst_note: actionNote }),
    onSuccess: next => {
      setRun(next);
      setPlan(next.plan);
      setManual(null);
      setFollowRunId(next.run_id);
      setLiveLogsEnabled(true);
    },
  });
  const manualMutation = useMutation({
    mutationFn: () => simulationApi.manualResult({
      simulation_id: simulationId,
      target_id: targetId,
      detection_result: detectionResult,
      evidence,
      gaps: gaps.split('\n').map(item => item.trim()).filter(Boolean),
    }),
    onSuccess: next => {
      setManual(next);
      setPlan(next.plan);
    },
  });
  const forwardLogsMutation = useMutation({
    mutationFn: () => simulationApi.forwardLogs({
      source: siemSource,
      run_id: followRunId || undefined,
      destination_url: normalizeSiemDestination(siemUrl),
      limit: 200,
      bearer_token: siemToken,
    }),
  });

  const canAct = Boolean(simulationId && targetId);
  const liveLogsQuery = useQuery({
    queryKey: ['attack-simulation-live-logs', followRunId || 'latest-web', liveLogsEnabled],
    queryFn: () => simulationApi.logs({ source: 'web', run_id: followRunId || undefined, limit: 80 }),
    enabled: Boolean(routeSimulationId) && liveLogsEnabled,
    refetchInterval: runMutation.isPending || liveLogsEnabled ? 1000 : false,
    retry: false,
  });

  if (!routeSimulationId) {
    return (
      <div className="flex h-full flex-col">
        <Header title="Attack Simulation" />
        <main className="min-h-0 flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-6xl space-y-5">
            <section className="rounded border border-gray-800 bg-gray-950 p-5">
              <h1 className="text-xl font-semibold text-white">Choose a TTP to simulate</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-400">
                Select the ATT&amp;CK technique first. The next page opens the attack simulation workspace with target configuration,
                safety gates, dry-run planning, telemetry expectations, and validation evidence capture.
              </p>
            </section>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {catalog.map(item => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => navigate(`/attack-simulation/${item.id}`)}
                  className="rounded border border-gray-800 bg-gray-900/40 p-4 text-left transition hover:border-mitre-accent hover:bg-gray-900"
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <TtpLink id={item.technique_id} />
                    <span className={`rounded px-2 py-1 text-[10px] ${item.risk_level <= 1 ? 'bg-green-950 text-green-300' : 'bg-amber-950 text-amber-300'}`}>Risk {item.risk_level}</span>
                  </div>
                  <div className="font-semibold text-white">{item.name}</div>
                  <p className="mt-2 min-h-[60px] text-xs leading-5 text-gray-400">{item.description}</p>
                  <div className="mt-3 flex flex-wrap gap-1">
                    <Chip>{item.category}</Chip>
                    {item.target_types.map(type => <Chip key={type}>{type}</Chip>)}
                  </div>
                </button>
              ))}
            </div>
            {!catalog.length && (
              <div className="rounded border border-gray-800 bg-gray-950 p-6 text-sm text-gray-400">
                Loading attack simulation catalog...
              </div>
            )}
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <Header title="Attack Simulation" />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto xl:grid-cols-[420px_minmax(0,1fr)] xl:overflow-hidden">
        <aside className="min-h-0 overflow-y-auto border-r border-gray-700 p-4">
          <Panel title="Safety Boundary">
            <div className="space-y-2 p-3 text-xs leading-5 text-amber-100">
              <p>This MVP prepares and records authorized ATT&CK simulations. It does not execute arbitrary commands, does not run exploit payloads, and does not emit external traffic from the API runner.</p>
              <p>Use approved lab targets only. Attach observed telemetry from your lab before marking coverage as passed.</p>
            </div>
          </Panel>

          <Panel title="Selected TTP">
            <div className="space-y-3 p-3">
              <button type="button" className="secondary-action w-full" onClick={() => navigate('/attack-simulation')}>
                Change TTP
              </button>
              {selectedSimulation && <SimulationSummary item={selectedSimulation} />}
            </div>
          </Panel>

          <Panel title="Attack Configuration">
            <div className="space-y-3 p-3">
              <label className="label">Approved target registry</label>
              <select className="field" value={targetId} onChange={event => setTargetId(event.target.value)}>
                {(compatibleTargets.length ? compatibleTargets : targets).map(item => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </select>
              {selectedTarget && (
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
                  <b className="block text-gray-200">{selectedTarget.id}</b>
                  <div className="mt-1 font-mono text-[11px] text-gray-500">{selectedTarget.address}</div>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    <Mini label="Type" value={selectedTarget.target_type} />
                    <Mini label="Environment" value={selectedTarget.environment} />
                    <Mini label="Owner" value={selectedTarget.owner} />
                    <Mini label="Authorization" value={selectedTarget.authorization} />
                  </div>
                </div>
              )}
              <label className="label">Target address / endpoint</label>
              <input
                className="field font-mono text-xs"
                value={targetAddress}
                onChange={event => setTargetAddress(event.target.value)}
                placeholder="Approved lab target address"
              />
              <div className="rounded border border-amber-900 bg-amber-950/20 p-2 text-xs leading-5 text-amber-100">
                In this version the run record is allowed only when the selected target exists in the approved lab registry. Free-form addresses are captured for analyst context, not executed by the platform.
              </div>
              <label className="label">Analyst note</label>
              <textarea className="field min-h-[80px]" value={analystNote} onChange={event => setAnalystNote(event.target.value)} placeholder="Purpose, ticket, maintenance window, or validation objective" />
              <div className="grid grid-cols-2 gap-2">
                <button type="button" disabled={!canAct || planMutation.isPending} onClick={() => planMutation.mutate()} className="secondary-action disabled:opacity-40">
                  Dry-run plan
                </button>
                <button type="button" disabled={!canAct || runMutation.isPending} onClick={() => runMutation.mutate()} className="primary-action disabled:opacity-40">
                  Run attack
                </button>
              </div>
              {(planMutation.error || runMutation.error) && (
                <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">
                  {String(planMutation.error || runMutation.error)}
                </div>
              )}
            </div>
          </Panel>
        </aside>

        <main className="min-h-0 overflow-y-auto p-6">
          {!plan && !run && (
            <div className="mx-auto mt-16 max-w-3xl rounded border border-gray-800 bg-gray-950 p-6">
              <h2 className="text-lg font-semibold text-white">Configure the target and generate an attack simulation plan.</h2>
              <p className="mt-3 text-sm leading-6 text-gray-400">
                Start with dry-run planning for the selected TTP. The platform records safety gates, expected telemetry, and validation gaps before any lab evidence is accepted.
              </p>
            </div>
          )}

          {plan && <PlanView plan={plan} />}
          {run && <RunView run={run} />}
          <LiveLogsView
            logs={liveLogsQuery.data}
            isLoading={liveLogsQuery.isLoading}
            isFetching={liveLogsQuery.isFetching}
            enabled={liveLogsEnabled}
            followRunId={followRunId}
            onToggle={() => setLiveLogsEnabled(value => !value)}
            onClearFollow={() => setFollowRunId('')}
            onRefresh={() => liveLogsQuery.refetch()}
          />
          <SiemForwarder
            destinationUrl={siemUrl}
            bearerToken={siemToken}
            source={siemSource}
            followRunId={followRunId}
            result={forwardLogsMutation.data}
            error={forwardLogsMutation.error}
            isPending={forwardLogsMutation.isPending}
            onDestinationUrlChange={setSiemUrl}
            onBearerTokenChange={setSiemToken}
            onSourceChange={setSiemSource}
            onSend={() => forwardLogsMutation.mutate()}
          />

          {plan && (
            <Panel title="Manual Detection Result">
              <div className="grid gap-4 p-4 lg:grid-cols-[260px_minmax(0,1fr)]">
                <div className="space-y-3">
                  <label className="label">Detection result</label>
                  <select className="field" value={detectionResult} onChange={event => setDetectionResult(event.target.value as DetectionResult)}>
                    <option value="not_proven">Not proven</option>
                    <option value="passed">Passed</option>
                    <option value="partial">Partial</option>
                    <option value="failed">Failed</option>
                  </select>
                  <label className="label">Validation gaps</label>
                  <textarea className="field min-h-[120px]" value={gaps} onChange={event => setGaps(event.target.value)} />
                </div>
                <div className="space-y-3">
                  <label className="label">Evidence</label>
                  <textarea
                    className="field min-h-[180px] font-mono text-xs"
                    value={evidence}
                    onChange={event => setEvidence(event.target.value)}
                    placeholder="Paste SIEM event IDs, firewall/WAF log snippets, DNS/proxy observations, rule names, timestamps, and analyst notes."
                  />
                  <button type="button" disabled={manualMutation.isPending} onClick={() => manualMutation.mutate()} className="primary-action disabled:opacity-40">
                    Save manual validation result
                  </button>
                </div>
              </div>
              {manual && (
                <div className="border-t border-gray-800 p-4 text-sm text-gray-300">
                  Saved manual result <span className="font-mono text-mitre-accent">{manual.result_id}</span>: {manual.detection_result}.
                </div>
              )}
            </Panel>
          )}
        </main>
      </div>
    </div>
  );
}

function SimulationSummary({ item }: { item: AttackSimulationCatalogItem }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
      <div className="mb-2 flex items-center justify-between gap-2">
        <TtpLink id={item.technique_id} />
        <span className={`rounded px-2 py-1 text-[10px] ${item.risk_level <= 1 ? 'bg-green-950 text-green-300' : 'bg-amber-950 text-amber-300'}`}>Risk {item.risk_level}</span>
      </div>
      <p className="leading-5">{item.description}</p>
      <div className="mt-2 flex flex-wrap gap-1">
        <Chip>{item.category}</Chip>
        {item.target_types.map(type => <Chip key={type}>{type}</Chip>)}
      </div>
    </div>
  );
}

function PlanView({ plan }: { plan: AttackSimulationPlan }) {
  return (
    <div className="mb-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Panel title="Dry-run Plan">
        <div className="space-y-4 p-4">
          <div className={`rounded border p-3 text-sm ${plan.allowed ? 'border-green-900 bg-green-950/20 text-green-200' : 'border-red-900 bg-red-950/30 text-red-200'}`}>
            {plan.allowed ? 'Allowed by safety policy' : `Blocked: ${plan.block_reasons.join('; ')}`}
          </div>
          <p className="text-sm leading-6 text-amber-100">{plan.safety_notice}</p>
          <Section title="Attack Simulation Steps" items={plan.steps} />
          <Section title="Approval Checklist" items={plan.approval_checklist} />
        </div>
      </Panel>
      <Panel title="Expected Telemetry">
        <div className="space-y-2 p-3">
          {plan.expected_telemetry.map(item => <div key={item} className="rounded border border-gray-800 bg-gray-950 p-2 text-xs text-gray-300">{item}</div>)}
        </div>
      </Panel>
    </div>
  );
}

function RunView({ run }: { run: AttackSimulationRun }) {
  return (
    <Panel title="Run Record">
      <div className="grid gap-4 p-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <div className="space-y-2">
          <Mini label="Run" value={run.run_id} />
          <Mini label="Status" value={run.status} />
          <Mini label="Traffic emitted" value={run.traffic_emitted ? 'yes' : 'no'} />
          <Mini label="Validation" value={run.validation_status} />
          {run.telemetry?.server?.url && <Mini label="Lab server" value={run.telemetry.server.url} />}
          {typeof run.telemetry?.request_count === 'number' && <Mini label="Requests" value={`${run.telemetry.success_count ?? 0} / ${run.telemetry.request_count}`} />}
        </div>
        <div>
          <div className="rounded border border-gray-800 bg-gray-950 p-3 font-mono text-xs leading-6 text-gray-300">
            {run.transcript.map((line, index) => <div key={`${line}-${index}`}>{line}</div>)}
          </div>
          {run.telemetry && <TelemetryView telemetry={run.telemetry} />}
          <Section title="Gaps" items={run.gaps} />
          {run.next_steps && <Section title="Next Steps" items={run.next_steps} />}
        </div>
      </div>
    </Panel>
  );
}

function LiveLogsView({
  logs,
  isLoading,
  isFetching,
  enabled,
  followRunId,
  onToggle,
  onClearFollow,
  onRefresh,
}: {
  logs?: AttackSimulationLogs;
  isLoading: boolean;
  isFetching: boolean;
  enabled: boolean;
  followRunId: string;
  onToggle: () => void;
  onClearFollow: () => void;
  onRefresh: () => void;
}) {
  const events = logs?.events ?? [];
  return (
    <Panel title="Real-Time Attack Logs">
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs leading-5 text-gray-400">
            <span className={enabled ? 'text-green-300' : 'text-gray-500'}>{enabled ? 'Live follow enabled' : 'Live follow paused'}</span>
            <span className="mx-2 text-gray-700">|</span>
            <span>{followRunId ? `Filtering run ${followRunId}` : 'Showing latest web access telemetry'}</span>
            {logs?.log_file && <span className="ml-2 font-mono text-gray-500">{logs.log_file}</span>}
          </div>
          <div className="flex gap-2">
            {followRunId && (
              <button type="button" onClick={onClearFollow} className="secondary-action">
                Show all
              </button>
            )}
            <button type="button" onClick={onRefresh} className="secondary-action">
              Refresh
            </button>
            <button type="button" onClick={onToggle} className={enabled ? 'secondary-action' : 'primary-action'}>
              {enabled ? 'Pause' : 'Follow'}
            </button>
          </div>
        </div>

        <div className="max-h-[360px] overflow-auto rounded border border-gray-800 bg-black/40">
          <table className="w-full min-w-[920px] text-left text-xs">
            <thead className="sticky top-0 bg-gray-950 text-gray-500">
              <tr>
                <th className="border-b border-gray-800 px-2 py-2">Time</th>
                <th className="border-b border-gray-800 px-2 py-2">Event</th>
                <th className="border-b border-gray-800 px-2 py-2">Run</th>
                <th className="border-b border-gray-800 px-2 py-2">Method</th>
                <th className="border-b border-gray-800 px-2 py-2">Path</th>
                <th className="border-b border-gray-800 px-2 py-2">Status</th>
                <th className="border-b border-gray-800 px-2 py-2">Client</th>
                <th className="border-b border-gray-800 px-2 py-2">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={`${event.timestamp}-${event.run_id}-${event.request_index}-${index}`} className="text-gray-300">
                  <td className="border-b border-gray-900 px-2 py-2 font-mono text-[11px] text-gray-500">{formatLogTime(event.timestamp)}</td>
                  <td className="border-b border-gray-900 px-2 py-2">{String(event.event_type ?? '-')}</td>
                  <td className="border-b border-gray-900 px-2 py-2 font-mono text-[11px]">{shortRun(event.run_id)}</td>
                  <td className="border-b border-gray-900 px-2 py-2 font-mono">{String(event.method ?? '-')}</td>
                  <td className="border-b border-gray-900 px-2 py-2 font-mono">{String(event.path ?? event.url ?? '-')}</td>
                  <td className={Number(event.status) >= 200 && Number(event.status) < 400 ? 'border-b border-gray-900 px-2 py-2 text-green-300' : 'border-b border-gray-900 px-2 py-2 text-amber-300'}>{String(event.status ?? '-')}</td>
                  <td className="border-b border-gray-900 px-2 py-2 font-mono">{String(event.client_ip ?? '-')}</td>
                  <td className="border-b border-gray-900 px-2 py-2 font-mono">{String(event.response_bytes ?? '-')}</td>
                </tr>
              ))}
              {!events.length && (
                <tr>
                  <td colSpan={8} className="px-3 py-8 text-center text-gray-500">
                    {isLoading || isFetching ? 'Waiting for live telemetry...' : 'No attack logs yet. Run a web simulation to generate telemetry.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="text-[11px] text-gray-600">
          {logs?.returned_at ? `Last update ${formatLogTime(logs.returned_at)} · ${logs.line_count} events returned` : 'Live log source is the built-in lab web access JSONL file.'}
        </div>
      </div>
    </Panel>
  );
}

function SiemForwarder({
  destinationUrl,
  bearerToken,
  source,
  followRunId,
  result,
  error,
  isPending,
  onDestinationUrlChange,
  onBearerTokenChange,
  onSourceChange,
  onSend,
}: {
  destinationUrl: string;
  bearerToken: string;
  source: 'web' | 'run';
  followRunId: string;
  result?: AttackSimulationForwardResult;
  error: unknown;
  isPending: boolean;
  onDestinationUrlChange: (value: string) => void;
  onBearerTokenChange: (value: string) => void;
  onSourceChange: (value: 'web' | 'run') => void;
  onSend: () => void;
}) {
  const canSend = Boolean(destinationUrl.trim()) && (source === 'web' || Boolean(followRunId));
  return (
    <Panel title="Forward Logs To SIEM">
      <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_260px]">
        <div className="space-y-3">
          <label className="label">SIEM IP / URL</label>
          <input
            className="field font-mono text-xs"
            value={destinationUrl}
            onChange={event => onDestinationUrlChange(event.target.value)}
            placeholder="192.168.1.10:8088/services/collector/event or https://siem.example/api/events"
          />
          {destinationUrl.trim() && (
            <div className="rounded bg-gray-950 px-3 py-2 text-[11px] leading-5 text-gray-500">
              Destination used: <span className="font-mono text-gray-300">{normalizeSiemDestination(destinationUrl)}</span>
            </div>
          )}
          <label className="label">Bearer token</label>
          <input
            className="field font-mono text-xs"
            type="password"
            value={bearerToken}
            onChange={event => onBearerTokenChange(event.target.value)}
            placeholder="Optional SIEM token"
          />
          <div className="rounded border border-amber-900 bg-amber-950/20 p-2 text-xs leading-5 text-amber-100">
            Sends generated Attack Simulation telemetry as JSON over HTTP POST. Unsafe URL schemes and metadata/link-local destinations are blocked.
          </div>
        </div>
        <div className="space-y-3">
          <label className="label">Log source</label>
          <select className="field" value={source} onChange={event => onSourceChange(event.target.value as 'web' | 'run')}>
            <option value="web">Web access log</option>
            <option value="run">Run telemetry log</option>
          </select>
          <Mini label="Run filter" value={followRunId || 'all web events'} />
          <button type="button" disabled={!canSend || isPending} onClick={onSend} className="primary-action w-full disabled:opacity-40">
            Send logs
          </button>
          {result && (
            <div className={`rounded border p-3 text-xs ${result.ok ? 'border-green-900 bg-green-950/20 text-green-200' : 'border-red-900 bg-red-950/30 text-red-200'}`}>
              <b className="block">{result.ok ? 'Delivered' : 'Delivery failed'} · HTTP {result.status}</b>
              <span>{result.event_count} events · {result.duration_ms} ms</span>
              {result.error && <span className="mt-1 block">{result.error}</span>}
            </div>
          )}
          {Boolean(error) && (
            <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">
              {String(error)}
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}

function TelemetryView({ telemetry }: { telemetry: NonNullable<AttackSimulationRun['telemetry']> }) {
  return (
    <div className="mt-4 rounded border border-gray-800 bg-gray-950">
      <div className="border-b border-gray-800 px-3 py-2 text-xs font-semibold uppercase text-gray-500">Local Lab Telemetry</div>
      <div className="space-y-3 p-3 text-xs text-gray-300">
        <div className="grid gap-2 md:grid-cols-2">
          {telemetry.log_file && <Mini label="Attack log" value={telemetry.log_file} />}
          {telemetry.web_access_log_file && <Mini label="Web access log" value={telemetry.web_access_log_file} />}
        </div>
        {telemetry.events?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-xs">
              <thead className="text-gray-500">
                <tr>
                  <th className="border-b border-gray-800 px-2 py-2">#</th>
                  <th className="border-b border-gray-800 px-2 py-2">Method</th>
                  <th className="border-b border-gray-800 px-2 py-2">Path</th>
                  <th className="border-b border-gray-800 px-2 py-2">Status</th>
                  <th className="border-b border-gray-800 px-2 py-2">Duration</th>
                  <th className="border-b border-gray-800 px-2 py-2">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {telemetry.events.map(event => (
                  <tr key={`${event.request_index}-${event.method}-${event.path}`} className="text-gray-300">
                    <td className="border-b border-gray-900 px-2 py-2 font-mono">{event.request_index}</td>
                    <td className="border-b border-gray-900 px-2 py-2 font-mono">{event.method}</td>
                    <td className="border-b border-gray-900 px-2 py-2 font-mono">{event.path}</td>
                    <td className={event.ok ? 'border-b border-gray-900 px-2 py-2 text-green-300' : 'border-b border-gray-900 px-2 py-2 text-red-300'}>{event.status}</td>
                    <td className="border-b border-gray-900 px-2 py-2 font-mono">{event.duration_ms} ms</td>
                    <td className="border-b border-gray-900 px-2 py-2 font-mono">{event.response_bytes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded border border-gray-800 p-3 text-gray-500">No local telemetry events returned.</div>
        )}
      </div>
    </div>
  );
}

function formatLogTime(value?: string) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString();
}

function shortRun(value?: string) {
  if (!value) return '-';
  return value.length > 16 ? `${value.slice(0, 12)}...${value.slice(-4)}` : value;
}

function normalizeSiemDestination(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `http://${trimmed}`;
}

function Section({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="mt-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      <ul className="space-y-1 text-sm text-gray-300">
        {items.map(item => <li key={item} className="rounded border border-gray-800 bg-gray-950 px-3 py-2">{item}</li>)}
      </ul>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mb-4 rounded border border-gray-800 bg-gray-900/30">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      {children}
    </section>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded bg-gray-950 px-3 py-2">
      <div className="text-[10px] uppercase text-gray-600">{label}</div>
      <div className="truncate text-xs text-gray-300">{value}</div>
    </div>
  );
}

function Chip({ children }: { children: ReactNode }) {
  return <span className="rounded border border-gray-700 bg-gray-900 px-2 py-0.5 text-[10px] text-gray-400">{children}</span>;
}
