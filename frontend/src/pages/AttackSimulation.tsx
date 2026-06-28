import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { simulationApi } from '@/api/client';
import { AttackMatrix } from '@/components/Navigator/AttackMatrix';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { useAppStore } from '@/store';
import type {
  AttackSimulationCatalogItem,
  AttackSimulationForwardResult,
  AttackSimulationLogSource,
  AttackSimulationLogs,
  AttackSimulationManualResult,
  AttackSimulationPlan,
  AttackSimulationRun,
} from '@/api/client';
import { TtpLink } from '@/utils/ctiLinks';

type DetectionResult = 'passed' | 'failed' | 'partial' | 'not_proven';
type SiemAuthType = 'none' | 'bearer' | 'token' | 'basic' | 'custom_header';
type SiemConnectionMode = 'auto' | 'direct' | 'docker_host';
type SiemPayloadFormat = 'per_event' | 'json_lines' | 'envelope';
type SiemDestinationHistoryItem = {
  id: string;
  url: string;
  authType: SiemAuthType;
  username: string;
  headerName: string;
  connectionMode: SiemConnectionMode;
  allowHttpFallback: boolean;
  payloadFormat: SiemPayloadFormat;
  source: AttackSimulationLogSource;
  savedAt: string;
};

const SIEM_HISTORY_KEY = 'adversarygraph.attackSimulation.siemHistory.v1';
const SIEM_HISTORY_LIMIT = 10;

export function AttackSimulation() {
  const navigate = useNavigate();
  const { simulationId: routeSimulationId } = useParams();
  const { domain, version } = useAppStore();
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
  const [siemAuthType, setSiemAuthType] = useState<SiemAuthType>('none');
  const [siemUsername, setSiemUsername] = useState('');
  const [siemPassword, setSiemPassword] = useState('');
  const [siemToken, setSiemToken] = useState('');
  const [siemHeaderName, setSiemHeaderName] = useState('Authorization');
  const [siemConnectionMode, setSiemConnectionMode] = useState<SiemConnectionMode>('auto');
  const [allowHttpFallback, setAllowHttpFallback] = useState(true);
  const [siemPayloadFormat, setSiemPayloadFormat] = useState<SiemPayloadFormat>('per_event');
  const [liveLogSource, setLiveLogSource] = useState<AttackSimulationLogSource>('access');
  const [siemSource, setSiemSource] = useState<AttackSimulationLogSource>('access');
  const [siemHistory, setSiemHistory] = useState<SiemDestinationHistoryItem[]>(() => loadSiemHistory());

  const catalogQuery = useQuery({ queryKey: ['simulation-catalog'], queryFn: simulationApi.catalog });
  const targetsQuery = useQuery({ queryKey: ['simulation-targets'], queryFn: simulationApi.targets });
  const matrixData = useAttackMatrix(domain, version);
  const catalog = catalogQuery.data ?? [];
  const targets = targetsQuery.data ?? [];
  const selectedSimulation = catalog.find(item => item.id === simulationId);
  const selectedTarget = targets.find(item => item.id === targetId);
  const simulationByTechnique = useMemo(() => {
    const map = new Map<string, AttackSimulationCatalogItem>();
    for (const item of catalog) {
      if (!map.has(item.technique_id)) map.set(item.technique_id, item);
    }
    return map;
  }, [catalog]);
  const simulationTechniqueIds = useMemo(() => new Set(simulationByTechnique.keys()), [simulationByTechnique]);
  const simulationExpandedParents = useMemo(() => {
    const parents = new Set<string>();
    for (const [parent, subs] of matrixData.subtechsByParent) {
      if (subs.some(sub => simulationTechniqueIds.has(sub.attack_id))) parents.add(parent);
    }
    return parents;
  }, [matrixData.subtechsByParent, simulationTechniqueIds]);

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
      auth_type: siemAuthType,
      username: siemUsername,
      password: siemPassword,
      token: siemToken,
      header_name: siemHeaderName,
      connection_mode: siemConnectionMode,
      allow_http_fallback: allowHttpFallback,
      payload_format: siemPayloadFormat,
    }),
    onSuccess: () => {
      const next = saveSiemHistoryItem({
        url: siemUrl,
        authType: siemAuthType,
        username: siemUsername,
        headerName: siemHeaderName,
        connectionMode: siemConnectionMode,
        allowHttpFallback,
        payloadFormat: siemPayloadFormat,
        source: siemSource,
      });
      setSiemHistory(next);
    },
  });

  const saveCurrentSiemDestination = () => {
    const next = saveSiemHistoryItem({
      url: siemUrl,
      authType: siemAuthType,
      username: siemUsername,
      headerName: siemHeaderName,
      connectionMode: siemConnectionMode,
      allowHttpFallback,
      payloadFormat: siemPayloadFormat,
      source: siemSource,
    });
    setSiemHistory(next);
  };
  const applySiemDestination = (item: SiemDestinationHistoryItem) => {
    setSiemUrl(item.url);
    setSiemAuthType(item.authType);
    setSiemUsername(item.username);
    setSiemPassword('');
    setSiemToken('');
    setSiemHeaderName(item.headerName || 'Authorization');
    setSiemConnectionMode(item.connectionMode);
    setAllowHttpFallback(item.allowHttpFallback);
    setSiemPayloadFormat(item.payloadFormat);
    setSiemSource(item.source);
  };
  const clearSiemHistory = () => {
    localStorage.removeItem(SIEM_HISTORY_KEY);
    setSiemHistory([]);
  };

  const canAct = Boolean(simulationId && targetId);
  const liveLogsQuery = useQuery({
    queryKey: ['attack-simulation-live-logs', liveLogSource, followRunId || 'latest-web', liveLogsEnabled],
    queryFn: () => simulationApi.logs({ source: liveLogSource, run_id: followRunId || undefined, limit: 80 }),
    enabled: Boolean(routeSimulationId) && liveLogsEnabled,
    refetchInterval: runMutation.isPending || liveLogsEnabled ? 1000 : false,
    retry: false,
  });

  if (!routeSimulationId) {
    return (
      <div className="flex h-full flex-col">
        <Header title="Attack Simulation" />
        <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <section className="border-b border-gray-800 bg-gray-950 px-6 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h1 className="text-lg font-semibold text-white">Choose a TTP from the ATT&amp;CK matrix</h1>
                <p className="mt-1 text-sm text-gray-400">
                  Green cells have an available Attack Simulation scenario. Click a green cell to configure the target and run the attack flow.
                </p>
              </div>
              <div className="rounded border border-green-900 bg-green-950/30 px-3 py-2 text-xs text-green-200">
                {simulationTechniqueIds.size} simulation TTPs
              </div>
            </div>
          </section>
          <div className="min-h-0 flex-1">
            {matrixData.isLoading && <div className="p-6 text-sm text-gray-400">Loading ATT&amp;CK matrix...</div>}
            {!matrixData.isLoading && (
              <AttackMatrix
                tactics={matrixData.tactics}
                techniquesByTactic={matrixData.techniquesByTactic}
                subtechsByParent={matrixData.subtechsByParent}
                parentsWithSubs={matrixData.parentsWithSubs}
                selectedTechniques={new Set()}
                overlayTechniques={new Set()}
                comparisonLayers={[]}
                coverageTechniques={new Set()}
                simulationTechniques={simulationTechniqueIds}
                simulationMode
                expandedTechniques={simulationExpandedParents}
                onToggleTechnique={(id) => {
                  const simulation = simulationByTechnique.get(id);
                  if (simulation) navigate(`/attack-simulation/${simulation.id}`);
                }}
                onToggleExpanded={() => {}}
              />
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
            source={liveLogSource}
            onToggle={() => setLiveLogsEnabled(value => !value)}
            onClearFollow={() => setFollowRunId('')}
            onRefresh={() => liveLogsQuery.refetch()}
            onSourceChange={setLiveLogSource}
          />
          <SiemForwarder
            destinationUrl={siemUrl}
            authType={siemAuthType}
            username={siemUsername}
            password={siemPassword}
            token={siemToken}
            headerName={siemHeaderName}
            connectionMode={siemConnectionMode}
            allowHttpFallback={allowHttpFallback}
            payloadFormat={siemPayloadFormat}
            history={siemHistory}
            source={siemSource}
            followRunId={followRunId}
            result={forwardLogsMutation.data}
            error={forwardLogsMutation.error}
            isPending={forwardLogsMutation.isPending}
            onDestinationUrlChange={setSiemUrl}
            onAuthTypeChange={setSiemAuthType}
            onUsernameChange={setSiemUsername}
            onPasswordChange={setSiemPassword}
            onTokenChange={setSiemToken}
            onHeaderNameChange={setSiemHeaderName}
            onConnectionModeChange={setSiemConnectionMode}
            onAllowHttpFallbackChange={setAllowHttpFallback}
            onPayloadFormatChange={setSiemPayloadFormat}
            onSaveDestination={saveCurrentSiemDestination}
            onUseHistoryItem={applySiemDestination}
            onClearHistory={clearSiemHistory}
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
  source,
  onToggle,
  onClearFollow,
  onRefresh,
  onSourceChange,
}: {
  logs?: AttackSimulationLogs;
  isLoading: boolean;
  isFetching: boolean;
  enabled: boolean;
  followRunId: string;
  source: AttackSimulationLogSource;
  onToggle: () => void;
  onClearFollow: () => void;
  onRefresh: () => void;
  onSourceChange: (value: AttackSimulationLogSource) => void;
}) {
  const events = logs?.events ?? [];
  return (
    <Panel title="Real-Time Attack Logs">
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs leading-5 text-gray-400">
            <span className={enabled ? 'text-green-300' : 'text-gray-500'}>{enabled ? 'Live follow enabled' : 'Live follow paused'}</span>
            <span className="mx-2 text-gray-700">|</span>
            <span>{followRunId ? `Filtering run ${followRunId}` : `Showing latest ${source} telemetry`}</span>
            {logs?.log_file && <span className="ml-2 font-mono text-gray-500">{logs.log_file}</span>}
          </div>
          <div className="flex flex-wrap gap-2">
            <select className="field w-56 py-1 text-xs" value={source} onChange={event => onSourceChange(event.target.value as AttackSimulationLogSource)}>
              <option value="access">Real web access log</option>
              <option value="auth">Real auth log</option>
              <option value="security">Real WAF/security log</option>
              <option value="error">Real web error log</option>
              <option value="web">Structured web JSONL</option>
              <option value="run">Attack run JSONL</option>
            </select>
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
                <th className="border-b border-gray-800 px-2 py-2">Raw log</th>
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
                  <td className="max-w-[520px] truncate border-b border-gray-900 px-2 py-2 font-mono text-[11px] text-gray-500" title={String(event.raw_line ?? event.message ?? '')}>
                    {String(event.raw_line ?? event.message ?? '-')}
                  </td>
                </tr>
              ))}
              {!events.length && (
                <tr>
                  <td colSpan={9} className="px-3 py-8 text-center text-gray-500">
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
  authType,
  username,
  password,
  token,
  headerName,
  connectionMode,
  allowHttpFallback,
  payloadFormat,
  history,
  source,
  followRunId,
  result,
  error,
  isPending,
  onDestinationUrlChange,
  onAuthTypeChange,
  onUsernameChange,
  onPasswordChange,
  onTokenChange,
  onHeaderNameChange,
  onConnectionModeChange,
  onAllowHttpFallbackChange,
  onPayloadFormatChange,
  onSaveDestination,
  onUseHistoryItem,
  onClearHistory,
  onSourceChange,
  onSend,
}: {
  destinationUrl: string;
  authType: SiemAuthType;
  username: string;
  password: string;
  token: string;
  headerName: string;
  connectionMode: SiemConnectionMode;
  allowHttpFallback: boolean;
  payloadFormat: SiemPayloadFormat;
  history: SiemDestinationHistoryItem[];
  followRunId: string;
  result?: AttackSimulationForwardResult;
  error: unknown;
  isPending: boolean;
  onDestinationUrlChange: (value: string) => void;
  onAuthTypeChange: (value: SiemAuthType) => void;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onTokenChange: (value: string) => void;
  onHeaderNameChange: (value: string) => void;
  onConnectionModeChange: (value: SiemConnectionMode) => void;
  onAllowHttpFallbackChange: (value: boolean) => void;
  onPayloadFormatChange: (value: SiemPayloadFormat) => void;
  onSaveDestination: () => void;
  onUseHistoryItem: (item: SiemDestinationHistoryItem) => void;
  onClearHistory: () => void;
  source: AttackSimulationLogSource;
  onSourceChange: (value: AttackSimulationLogSource) => void;
  onSend: () => void;
}) {
  const authReady =
    authType === 'none' ||
    ((authType === 'bearer' || authType === 'token') && Boolean(token.trim())) ||
    (authType === 'basic' && Boolean(username.trim()) && Boolean(password)) ||
    (authType === 'custom_header' && Boolean(headerName.trim()) && Boolean(token.trim()));
  const canSend = Boolean(destinationUrl.trim()) && authReady && (source !== 'run' || Boolean(followRunId));
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
          <div className="flex flex-wrap gap-2">
            <button type="button" disabled={!destinationUrl.trim()} onClick={onSaveDestination} className="secondary-action disabled:opacity-40">
              Save destination
            </button>
            {history.length > 0 && (
              <button type="button" onClick={onClearHistory} className="secondary-action">
                Clear history
              </button>
            )}
          </div>
          {history.length > 0 && (
            <div className="rounded border border-gray-800 bg-gray-950 p-3">
              <div className="mb-2 text-[10px] font-semibold uppercase text-gray-500">Recent SIEM destinations</div>
              <div className="space-y-2">
                {history.map(item => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onUseHistoryItem(item)}
                    className="w-full rounded border border-gray-800 bg-gray-900 px-3 py-2 text-left hover:border-cyan-800"
                  >
                    <span className="block truncate font-mono text-xs text-cyan-100">{item.url}</span>
                    <span className="mt-1 block text-[10px] uppercase text-gray-500">
                      {item.connectionMode} · {item.payloadFormat} · {item.authType} · {item.source} · {formatHistoryTime(item.savedAt)}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
          {destinationUrl.trim() && (
            <div className="rounded bg-gray-950 px-3 py-2 text-[11px] leading-5 text-gray-500">
              Destination used: <span className="font-mono text-gray-300">{normalizeSiemDestination(destinationUrl)}</span>
              {isWildcardDestination(destinationUrl) && (
                <span className="mt-1 block text-amber-200">
                  0.0.0.0 is a server bind address. The forwarder converts it to a connectable target: host.docker.internal for Auto/Docker host gateway, or 127.0.0.1 for Direct.
                </span>
              )}
              {isLoopbackDestination(destinationUrl) && connectionMode === 'docker_host' && (
                <span className="mt-1 block text-amber-200">
                  Docker host gateway mode forwards localhost/127.0.0.1 through host.docker.internal. The collector must listen on the host network interface or 0.0.0.0, and the selected scheme must match the collector.
                </span>
              )}
              {isLoopbackDestination(destinationUrl) && connectionMode === 'direct' && (
                <span className="mt-1 block text-cyan-200">
                  Direct mode preserves this exact loopback address from the API runtime. In Docker, that means the API container itself, not your browser or host loopback.
                </span>
              )}
            </div>
          )}
          <label className="label">Connection route</label>
          <select className="field" value={connectionMode} onChange={event => onConnectionModeChange(event.target.value as SiemConnectionMode)}>
            <option value="auto">Auto</option>
            <option value="docker_host">Docker host gateway</option>
            <option value="direct">Direct exact address</option>
          </select>
          <label className="label">Payload format</label>
          <select className="field" value={payloadFormat} onChange={event => onPayloadFormatChange(event.target.value as SiemPayloadFormat)}>
            <option value="per_event">One event per request (Logeye)</option>
            <option value="json_lines">JSON lines</option>
            <option value="envelope">Batch envelope</option>
          </select>
          <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">
            <input
              type="checkbox"
              checked={allowHttpFallback}
              onChange={event => onAllowHttpFallbackChange(event.target.checked)}
              className="mt-1"
            />
            <span>
              Allow HTTP fallback if HTTPS TLS handshake fails. Use this for local collectors that are configured with an HTTPS-looking URL but actually listen over plain HTTP.
            </span>
          </label>
          <label className="label">Authentication type</label>
          <select className="field" value={authType} onChange={event => onAuthTypeChange(event.target.value as SiemAuthType)}>
            <option value="none">None</option>
            <option value="bearer">Bearer token</option>
            <option value="token">Token auth</option>
            <option value="basic">Username / password</option>
            <option value="custom_header">Custom token header</option>
          </select>
          {authType === 'basic' && (
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="label">Username</label>
                <input className="field font-mono text-xs" value={username} onChange={event => onUsernameChange(event.target.value)} placeholder="admin" />
              </div>
              <div>
                <label className="label">Password</label>
                <input className="field font-mono text-xs" type="password" value={password} onChange={event => onPasswordChange(event.target.value)} placeholder="Password" />
              </div>
            </div>
          )}
          {(authType === 'bearer' || authType === 'token') && (
            <div>
              <label className="label">{authType === 'bearer' ? 'Bearer token' : 'Token'}</label>
              <input
                className="field font-mono text-xs"
                type="password"
                value={token}
                onChange={event => onTokenChange(event.target.value)}
                placeholder={authType === 'bearer' ? 'Authorization: Bearer <token>' : 'Authorization: Token <token>'}
              />
            </div>
          )}
          {authType === 'custom_header' && (
            <div className="grid gap-3 md:grid-cols-[220px_minmax(0,1fr)]">
              <div>
                <label className="label">Header name</label>
                <input className="field font-mono text-xs" value={headerName} onChange={event => onHeaderNameChange(event.target.value)} placeholder="X-API-Key" />
              </div>
              <div>
                <label className="label">Header token/value</label>
                <input className="field font-mono text-xs" type="password" value={token} onChange={event => onTokenChange(event.target.value)} placeholder="Token value" />
              </div>
            </div>
          )}
          <div className="rounded border border-amber-900 bg-amber-950/20 p-2 text-xs leading-5 text-amber-100">
            Sends generated Attack Simulation telemetry as JSON over HTTP POST. Credentials are used only for this request and are not stored. Unsafe URL schemes and metadata/link-local destinations are blocked.
          </div>
        </div>
        <div className="space-y-3">
          <label className="label">Log source</label>
          <select className="field" value={source} onChange={event => onSourceChange(event.target.value as AttackSimulationLogSource)}>
            <option value="access">Real web access log</option>
            <option value="auth">Real auth log</option>
            <option value="security">Real WAF/security log</option>
            <option value="error">Real web error log</option>
            <option value="web">Structured web JSONL</option>
            <option value="run">Attack run JSONL</option>
          </select>
          <Mini label="Run filter" value={followRunId || `all ${source} events`} />
          <button type="button" disabled={!canSend || isPending} onClick={onSend} className="primary-action w-full disabled:opacity-40">
            Send logs
          </button>
          {result && (
            <div className={`rounded border p-3 text-xs ${result.ok ? 'border-green-900 bg-green-950/20 text-green-200' : 'border-red-900 bg-red-950/30 text-red-200'}`}>
              <b className="block">{result.ok ? 'Delivered' : 'Delivery failed'} · HTTP {result.status}</b>
              <span>{result.sent_event_count ?? result.event_count} / {result.event_count} events sent · {result.duration_ms} ms</span>
              {result.payload_format && <span className="mt-1 block">Format: {result.payload_format}</span>}
              {result.http_fallback_used && <span className="mt-1 block text-amber-100">{result.fallback_note}</span>}
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
          {telemetry.web_access_log_file && <Mini label="Structured web JSONL" value={telemetry.web_access_log_file} />}
          {telemetry.web_server_access_log_file && <Mini label="Real access log" value={telemetry.web_server_access_log_file} />}
          {telemetry.web_auth_log_file && <Mini label="Auth log" value={telemetry.web_auth_log_file} />}
          {telemetry.web_security_log_file && <Mini label="Security log" value={telemetry.web_security_log_file} />}
          {telemetry.web_error_log_file && <Mini label="Error log" value={telemetry.web_error_log_file} />}
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

function loadSiemHistory(): SiemDestinationHistoryItem[] {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(SIEM_HISTORY_KEY) || '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(isSiemHistoryItem)
      .slice(0, SIEM_HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function saveSiemHistoryItem(item: Omit<SiemDestinationHistoryItem, 'id' | 'savedAt'>) {
  const url = item.url.trim();
  if (!url) return loadSiemHistory();
  const nextItem: SiemDestinationHistoryItem = {
    ...item,
    url,
    username: item.authType === 'basic' ? item.username.trim() : '',
    headerName: item.authType === 'custom_header' ? item.headerName.trim() : item.headerName || 'Authorization',
    id: `${normalizeSiemDestination(url)}|${item.connectionMode}|${item.payloadFormat}|${item.authType}|${item.source}`,
    savedAt: new Date().toISOString(),
  };
  const existing = loadSiemHistory();
  const next = [
    nextItem,
    ...existing.filter(entry => entry.id !== nextItem.id && normalizeSiemDestination(entry.url) !== normalizeSiemDestination(url)),
  ].slice(0, SIEM_HISTORY_LIMIT);
  window.localStorage.setItem(SIEM_HISTORY_KEY, JSON.stringify(next));
  return next;
}

function isSiemHistoryItem(value: unknown): value is SiemDestinationHistoryItem {
  if (!value || typeof value !== 'object') return false;
  const item = value as Record<string, unknown>;
  return (
    typeof item.id === 'string' &&
    typeof item.url === 'string' &&
    ['none', 'bearer', 'token', 'basic', 'custom_header'].includes(String(item.authType)) &&
    ['auto', 'direct', 'docker_host'].includes(String(item.connectionMode)) &&
    ['per_event', 'json_lines', 'envelope'].includes(String(item.payloadFormat)) &&
    ['web', 'run', 'access', 'security', 'error', 'auth'].includes(String(item.source))
  );
}

function formatHistoryTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'saved';
  return date.toLocaleString();
}

function isLoopbackDestination(value: string) {
  try {
    const parsed = new URL(normalizeSiemDestination(value));
    return parsed.hostname === '127.0.0.1' || parsed.hostname === 'localhost';
  } catch {
    return false;
  }
}

function isWildcardDestination(value: string) {
  try {
    const parsed = new URL(normalizeSiemDestination(value));
    return parsed.hostname === '0.0.0.0' || parsed.hostname === '[::]';
  } catch {
    return false;
  }
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
