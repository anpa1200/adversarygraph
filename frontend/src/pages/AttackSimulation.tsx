import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { ColumnDef } from '@tanstack/react-table';
import type { Edge, Node } from '@xyflow/react';
import { useNavigate, useParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { simulationApi } from '@/api/client';
import { AttackMatrix } from '@/components/Navigator/AttackMatrix';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { useAppStore } from '@/store';
import type {
  AttackSimulationCatalogItem,
  AttackSimulationForwardResult,
  AttackSimulationAiAssistantResult,
  AttackSimulationAiAssistantScenario,
  AttackSimulationLogSource,
  AttackSimulationLogs,
  AttackSimulationManualResult,
  AttackSimulationPlan,
  AttackSimulationRun,
  AttackSimulationSiemDestination,
} from '@/api/client';
import { TtpLink } from '@/utils/ctiLinks';
import { DataTable } from '@/components/ui/data-table';
import { VirtualList } from '@/components/ui/virtual-list';
import { EntityGraph } from '@/components/ui/graph';

type DetectionResult = 'passed' | 'failed' | 'partial' | 'not_proven';
type SiemAuthType = 'none' | 'bearer' | 'token' | 'basic' | 'custom_header';
type SiemConnectionMode = 'auto' | 'direct' | 'docker_host';
type SiemPayloadFormat = 'raw_lines' | 'per_event' | 'json_lines' | 'envelope';
type AiAssistantMode = 'ttps' | 'actor' | 'challenge';
type AiProvider = 'local' | 'claude' | 'openai' | 'gemini' | 'minimax';
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
  const qc = useQueryClient();
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
  const [showAllLiveLogs, setShowAllLiveLogs] = useState(false);
  const [liveLogsEnabled, setLiveLogsEnabled] = useState(true);
  const [siemUrl, setSiemUrl] = useState('');
  const [siemAuthType, setSiemAuthType] = useState<SiemAuthType>('none');
  const [siemUsername, setSiemUsername] = useState('');
  const [siemPassword, setSiemPassword] = useState('');
  const [siemToken, setSiemToken] = useState('');
  const [siemHeaderName, setSiemHeaderName] = useState('Authorization');
  const [siemConnectionMode, setSiemConnectionMode] = useState<SiemConnectionMode>('auto');
  const [allowHttpFallback, setAllowHttpFallback] = useState(true);
  const [siemPayloadFormat, setSiemPayloadFormat] = useState<SiemPayloadFormat>('raw_lines');
  const [aiAssistantMode, setAiAssistantMode] = useState<AiAssistantMode>('challenge');
  const [aiAssistantProvider, setAiAssistantProvider] = useState<AiProvider>('local');
  const [aiAssistantComplicated, setAiAssistantComplicated] = useState(false);
  const [aiAssistantScenarioId, setAiAssistantScenarioId] = useState('web-to-endpoint-intrusion');
  const [aiAssistantTtps, setAiAssistantTtps] = useState('T1190, T1110.001, T1078, T1059.001, T1003.001');
  const [aiAssistantActor, setAiAssistantActor] = useState('generic-intrusion');
  const [aiAssistantGoal, setAiAssistantGoal] = useState('Generate a realistic multi-stage detection challenge with correlated endpoint, auth, web, and exfiltration signals.');
  const [liveLogSource, setLiveLogSource] = useState<AttackSimulationLogSource>('access');
  const [siemSource, setSiemSource] = useState<AttackSimulationLogSource>('access');
  const [siemHistory, setSiemHistory] = useState<SiemDestinationHistoryItem[]>(() => loadSiemHistory());
  const [simulationExpandedParents, setSimulationExpandedParents] = useState<Set<string>>(new Set());
  const [simulationExpansionTouched, setSimulationExpansionTouched] = useState(false);

  const catalogQuery = useQuery({ queryKey: ['simulation-catalog'], queryFn: simulationApi.catalog });
  const targetsQuery = useQuery({ queryKey: ['simulation-targets'], queryFn: simulationApi.targets });
  const aiScenariosQuery = useQuery({ queryKey: ['simulation-ai-assistant-scenarios'], queryFn: simulationApi.aiAssistantScenarios });
  const siemHistoryQuery = useQuery({ queryKey: ['simulation-siem-destinations'], queryFn: simulationApi.siemDestinations, retry: false });
  const matrixData = useAttackMatrix(domain, version);
  const catalog = catalogQuery.data ?? [];
  const targets = targetsQuery.data ?? [];
  const aiScenarios = aiScenariosQuery.data ?? [];
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
  const runnableSubtechParents = useMemo(() => {
    const parents = new Set<string>();
    for (const [parent, subs] of matrixData.subtechsByParent) {
      if (subs.some(sub => simulationTechniqueIds.has(sub.attack_id))) parents.add(parent);
    }
    return parents;
  }, [matrixData.subtechsByParent, simulationTechniqueIds]);

  useEffect(() => {
    if (simulationExpansionTouched) return;
    setSimulationExpandedParents(new Set(runnableSubtechParents));
  }, [runnableSubtechParents, simulationExpansionTouched]);

  const toggleSimulationExpanded = (id: string) => {
    setSimulationExpansionTouched(true);
    setSimulationExpandedParents(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const expandSimulationParents = (ids: Iterable<string>) => {
    setSimulationExpansionTouched(true);
    setSimulationExpandedParents(new Set(ids));
  };

  const collapseSimulationParents = () => {
    setSimulationExpansionTouched(true);
    setSimulationExpandedParents(new Set());
  };

  useEffect(() => {
    setSimulationId(routeSimulationId ?? '');
    setPlan(null);
    setRun(null);
    setManual(null);
  }, [routeSimulationId]);

  useEffect(() => {
    if (window.location.hash !== '#ai-attack-assistant') return;
    const handle = window.setTimeout(() => {
      document.getElementById('ai-attack-assistant')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 100);
    return () => window.clearTimeout(handle);
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
      setShowAllLiveLogs(false);
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
    onMutate: () => {
      if (!siemUrl.trim()) return;
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
      saveSiemDestinationMutation.mutate();
    },
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
      qc.invalidateQueries({ queryKey: ['simulation-siem-destinations'] });
    },
  });
  const saveSiemDestinationMutation = useMutation({
    mutationFn: () => simulationApi.saveSiemDestination(toSiemDestinationPayload({
      url: siemUrl,
      authType: siemAuthType,
      username: siemUsername,
      headerName: siemHeaderName,
      connectionMode: siemConnectionMode,
      allowHttpFallback,
      payloadFormat: siemPayloadFormat,
      source: siemSource,
    })),
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
      qc.invalidateQueries({ queryKey: ['simulation-siem-destinations'] });
    },
  });
  const aiAssistantMutation = useMutation({
    onMutate: () => {
      if (!siemUrl.trim()) return;
      const next = saveSiemHistoryItem({
        url: siemUrl,
        authType: siemAuthType,
        username: siemUsername,
        headerName: siemHeaderName,
        connectionMode: siemConnectionMode,
        allowHttpFallback,
      payloadFormat: siemPayloadFormat === 'raw_lines' ? 'per_event' : siemPayloadFormat,
        source: 'endpoint',
      });
      setSiemHistory(next);
    },
    mutationFn: () => simulationApi.aiAssistantTelemetry({
      mode: aiAssistantMode,
      ai_provider: aiAssistantProvider,
      complicated_attack: aiAssistantComplicated,
      scenario_id: aiAssistantComplicated && aiAssistantMode === 'challenge' ? aiAssistantScenarioId : undefined,
      technique_ids: parseTechniqueInput(aiAssistantTtps),
      actor_profile: aiAssistantActor,
      analyst_goal: aiAssistantGoal,
      destination_url: normalizeSiemDestination(siemUrl),
      auth_type: siemAuthType,
      username: siemUsername,
      password: siemPassword,
      token: siemToken,
      header_name: siemHeaderName,
      connection_mode: siemConnectionMode,
      allow_http_fallback: allowHttpFallback,
      payload_format: aiAssistantComplicated ? 'raw_lines' : (siemPayloadFormat === 'raw_lines' ? 'per_event' : siemPayloadFormat),
    }),
    onSuccess: next => {
      setFollowRunId(next.run_id);
      setLiveLogSource('endpoint');
      setShowAllLiveLogs(false);
      setLiveLogsEnabled(true);
      qc.invalidateQueries({ queryKey: ['simulation-siem-destinations'] });
      qc.invalidateQueries({ queryKey: ['attack-simulation-live-logs'] });
    },
  });
  const clearSiemDestinationsMutation = useMutation({
    mutationFn: simulationApi.clearSiemDestinations,
    onSuccess: () => {
      localStorage.removeItem(SIEM_HISTORY_KEY);
      setSiemHistory([]);
      qc.invalidateQueries({ queryKey: ['simulation-siem-destinations'] });
    },
  });

  useEffect(() => {
    if (siemHistoryQuery.data) {
      const serverHistory = siemHistoryQuery.data.map(fromServerSiemDestination);
      setSiemHistory(serverHistory.length ? serverHistory : loadSiemHistory());
    }
  }, [siemHistoryQuery.data]);

  const saveCurrentSiemDestination = () => {
    if (siemUrl.trim()) {
      saveSiemDestinationMutation.mutate();
      return;
    }
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
    clearSiemDestinationsMutation.mutate();
  };
  const openAiAssistant = () => {
    const target = document.getElementById('ai-attack-assistant');
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }
    const firstSimulation = catalog[0];
    if (firstSimulation) navigate(`/attack-simulation/${firstSimulation.id}#ai-attack-assistant`);
  };

  const canAct = Boolean(simulationId && targetId);
  const activeLiveLogRunId = showAllLiveLogs || liveLogSource === 'run' ? '' : followRunId;
  const liveLogLimit = showAllLiveLogs ? 500 : 120;
  const liveLogsQuery = useQuery({
    queryKey: ['attack-simulation-live-logs', liveLogSource, activeLiveLogRunId || 'all-shared', liveLogLimit, liveLogsEnabled],
    queryFn: () => simulationApi.logs({ source: liveLogSource, run_id: activeLiveLogRunId || undefined, limit: liveLogLimit }),
    enabled: Boolean(routeSimulationId) && liveLogsEnabled && liveLogSource !== 'run',
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
              <div className="flex flex-wrap gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => expandSimulationParents(matrixData.parentsWithSubs)}
                  className="secondary-action"
                  disabled={!matrixData.parentsWithSubs.size}
                  title="Expand every technique group with sub-techniques"
                >
                  Extend all
                </button>
                <button
                  type="button"
                  onClick={() => expandSimulationParents(runnableSubtechParents)}
                  className="secondary-action"
                  disabled={!runnableSubtechParents.size}
                  title="Expand only parent techniques that contain runnable simulation sub-techniques"
                >
                  Extend runnable
                </button>
                <button
                  type="button"
                  onClick={collapseSimulationParents}
                  className="secondary-action"
                  disabled={!simulationExpandedParents.size}
                  title="Minimize all sub-technique groups"
                >
                  Minimize all
                </button>
              </div>
              <button
                type="button"
                disabled={!catalog.length}
                onClick={openAiAssistant}
                className="primary-action disabled:opacity-40"
              >
                AI Assistant Attack
              </button>
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
                onToggleExpanded={toggleSimulationExpanded}
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
              <label className="label">Simulation scenario</label>
              <select
                className="field text-xs"
                value={simulationId}
                onChange={event => navigate(`/attack-simulation/${event.target.value}`)}
              >
                {catalog.map(item => (
                  <option key={item.id} value={item.id}>
                    {item.technique_id} - {item.name}
                  </option>
                ))}
              </select>
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
          <div className="mb-4 flex justify-end">
            <button type="button" onClick={openAiAssistant} className="primary-action">
              AI Assistant Attack
            </button>
          </div>
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
            activeRunFilter={activeLiveLogRunId}
            showingAllLogs={showAllLiveLogs}
            source={liveLogSource}
            onToggle={() => setLiveLogsEnabled(value => !value)}
            onClearFollow={() => {
              setLiveLogSource('attacked_server');
              setShowAllLiveLogs(true);
              setLiveLogsEnabled(true);
            }}
            onFollowRun={() => setShowAllLiveLogs(false)}
            onRefresh={() => liveLogsQuery.refetch()}
            onSourceChange={(value) => {
              setLiveLogSource(value);
              if (value === 'run') setShowAllLiveLogs(false);
            }}
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
          <div id="ai-attack-assistant" className="scroll-mt-6">
            <AiAttackAssistant
              mode={aiAssistantMode}
              aiProvider={aiAssistantProvider}
              complicated={aiAssistantComplicated}
              ttps={aiAssistantTtps}
              actor={aiAssistantActor}
              goal={aiAssistantGoal}
              scenarios={aiScenarios}
              scenarioId={aiAssistantScenarioId}
              destinationUrl={siemUrl}
              payloadFormat={aiAssistantComplicated ? 'raw_lines' : (siemPayloadFormat === 'raw_lines' ? 'per_event' : siemPayloadFormat)}
              result={aiAssistantMutation.data}
              error={aiAssistantMutation.error}
              isPending={aiAssistantMutation.isPending}
              onModeChange={setAiAssistantMode}
              onAiProviderChange={setAiAssistantProvider}
              onComplicatedChange={setAiAssistantComplicated}
              onTtpsChange={setAiAssistantTtps}
              onActorChange={setAiAssistantActor}
              onGoalChange={setAiAssistantGoal}
              onScenarioChange={setAiAssistantScenarioId}
              onRun={() => aiAssistantMutation.mutate()}
            />
          </div>

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
  const context = simulationDetectionContext(item);
  const brief = item.detection_brief;
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
      <div className="mb-2 flex items-center justify-between gap-2">
        <TtpLink id={item.technique_id} />
        <span className={`rounded px-2 py-1 text-[10px] ${item.risk_level <= 1 ? 'bg-green-950 text-green-300' : 'bg-amber-950 text-amber-300'}`}>Risk {item.risk_level}</span>
      </div>
      <p className="leading-5 text-gray-300">{item.description}</p>
      <div className="mt-2 flex flex-wrap gap-1">
        <Chip>{item.category}</Chip>
        {item.target_types.map(type => <Chip key={type}>{type}</Chip>)}
      </div>
      <div className="mt-3 space-y-3 border-t border-gray-800 pt-3">
        <InfoBlock title={brief ? 'Adversary Activity' : 'What Happens'} text={brief?.adversary_activity || context.whatHappens} />
        <InfoBlock title={brief ? 'Production Log Sources' : 'Telemetry Source'} text={brief?.production_log_sources || context.telemetrySource} />
        <InfoBlock title={brief ? 'Detection Logic' : 'System / Event Structure'} text={brief?.detection_logic || context.eventStructure} />
        {brief && <InfoBlock title="Discriminators / Tuning" text={brief.discriminators_tuning} />}
        <div>
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-gray-500">Detection Focus</div>
          <ul className="space-y-1">
            {context.detectionFocus.map(focus => (
              <li key={focus} className="rounded border border-gray-800 bg-gray-900/40 px-2 py-1 leading-5 text-gray-300">
                {focus}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function InfoBlock({ title, text }: { title: string; text: string }) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-gray-500">{title}</div>
      <p className="leading-5 text-gray-300">{text}</p>
    </div>
  );
}

function simulationDetectionContext(item: AttackSimulationCatalogItem) {
  const isAtomic = item.category === 'atomic-event-artifact';
  const isWeb = item.target_types.includes('web') || item.target_types.includes('http') || item.target_types.includes('https');
  const isEndpoint = item.target_types.includes('endpoint') || item.target_types.includes('windows-endpoint') || item.target_types.includes('linux-endpoint');
  const provider = item.expected_telemetry.find(value => / event$/i.test(value))?.replace(/ event$/i, '');
  const eventId = item.expected_telemetry.find(value => value.startsWith('event_id='))?.replace('event_id=', '');
  const eventName = item.expected_telemetry.find(value => value.startsWith('event_name='))?.replace('event_name=', '');

  const telemetrySource = isAtomic
    ? `${provider || 'Vendor'} telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.`
    : isWeb
      ? 'Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.'
      : isEndpoint
        ? 'Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.'
        : 'Approved lab target telemetry from the selected simulation target.';

  const eventStructure = isAtomic
    ? atomicEventStructure(provider, eventId, eventName)
    : isWeb
      ? 'Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.'
      : isEndpoint
        ? 'Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.'
        : 'The simulation records a plan and expected evidence fields for the target telemetry owner.';

  const firstSteps = item.steps.slice(0, 2).join(' ');
  const whatHappens = isAtomic
    ? `One high-signal event is emitted for ${item.technique_id}. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.`
    : firstSteps || item.description;

  const detectionFocus = item.expected_telemetry.length
    ? item.expected_telemetry.slice(0, 6)
    : [
        'Presence of the expected ATT&CK-shaped artifact',
        'Correct source system and event type',
        'Run correlation fields',
      ];

  return { whatHappens, telemetrySource, eventStructure, detectionFocus };
}

function atomicEventStructure(provider?: string, eventId?: string, eventName?: string) {
  const normalized = (provider || '').toLowerCase();
  if (['sysmon', 'windows_security', 'windows_system', 'windows_defender', 'windows_powershell'].includes(normalized)) {
    return [
      `Strict Windows Event Log shaped JSON${eventId ? ` for EventID ${eventId}` : ''}${eventName ? ` (${eventName})` : ''}.`,
      'Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.',
    ].join(' ');
  }
  return [
    `Structured ${provider || 'vendor'} JSON${eventId ? ` with code ${eventId}` : ''}${eventName ? ` (${eventName})` : ''}.`,
    'Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.',
  ].join(' ');
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
  activeRunFilter,
  showingAllLogs,
  source,
  onToggle,
  onClearFollow,
  onFollowRun,
  onRefresh,
  onSourceChange,
}: {
  logs?: AttackSimulationLogs;
  isLoading: boolean;
  isFetching: boolean;
  enabled: boolean;
  followRunId: string;
  activeRunFilter: string;
  showingAllLogs: boolean;
  source: AttackSimulationLogSource;
  onToggle: () => void;
  onClearFollow: () => void;
  onFollowRun: () => void;
  onRefresh: () => void;
  onSourceChange: (value: AttackSimulationLogSource) => void;
}) {
  const events = logs?.events ?? [];
  const sourceLabel = source === 'attacked_server' ? 'attacked-server' : source;
  const logScopeText = activeRunFilter ? `Filtering run ${activeRunFilter}` : `Showing all ${sourceLabel} events`;
  const footerScopeText = activeRunFilter ? `filtered run ${shortRun(activeRunFilter)}` : 'all shared events';
  return (
    <Panel title="Real-Time Attack Logs">
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs leading-5 text-gray-400">
            <span className={enabled ? 'text-green-300' : 'text-gray-500'}>{enabled ? 'Live follow enabled' : 'Live follow paused'}</span>
            <span className="mx-2 text-gray-700">|</span>
            <span>{logScopeText}</span>
            {logs?.log_file && <span className="ml-2 font-mono text-gray-500">{logs.log_file}</span>}
          </div>
          <div className="flex flex-wrap gap-2">
            <select className="field w-56 py-1 text-xs" value={source} onChange={event => onSourceChange(event.target.value as AttackSimulationLogSource)}>
              <option value="attacked_server">All attacked-server events</option>
              <option value="access">Real web access log</option>
              <option value="auth">Real auth log</option>
              <option value="endpoint">Endpoint EDR/Sysmon log</option>
              <option value="security">Real WAF/security log</option>
              <option value="error">Real web error log</option>
              <option value="web">Structured web JSONL</option>
              <option value="run">Attack run JSONL</option>
            </select>
            {followRunId && !showingAllLogs && source !== 'run' && (
              <button type="button" onClick={onClearFollow} className="secondary-action">
                Show all
              </button>
            )}
            {followRunId && showingAllLogs && source !== 'run' && (
              <button type="button" onClick={onFollowRun} className="secondary-action">
                Follow run
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

        <div className="overflow-hidden rounded border border-gray-800 bg-black/40">
          <div className="min-w-[920px]">
            <div className="grid grid-cols-[82px_150px_110px_70px_210px_70px_120px_70px_minmax(260px,1fr)] bg-gray-950 text-xs text-gray-500">
              {['Time', 'Event', 'Run', 'Method', 'Path', 'Status', 'Client', 'Bytes', 'Raw log'].map(label => (
                <div key={label} className="border-b border-gray-800 px-2 py-2 font-semibold">{label}</div>
              ))}
            </div>
            {events.length ? (
              <VirtualList
                items={events}
                height={320}
                estimateSize={36}
                renderItem={(event, index) => <LogEventRow event={event} index={index} />}
              />
            ) : (
              <div className="px-3 py-8 text-center text-xs text-gray-500">
                {isLoading || isFetching ? 'Waiting for live telemetry...' : 'No attack logs yet. Run a web simulation to generate telemetry.'}
              </div>
            )}
          </div>
        </div>
        <div className="text-[11px] text-gray-600">
          {logs?.returned_at ? `Last update ${formatLogTime(logs.returned_at)} · ${logs.line_count} ${footerScopeText} returned` : 'Live log source is the built-in lab web access JSONL file.'}
        </div>
      </div>
    </Panel>
  );
}

function LogEventRow({ event, index }: { event: AttackSimulationLogs['events'][number]; index: number }) {
  const status = Number(event.status);
  return (
    <div
      className="grid grid-cols-[82px_150px_110px_70px_210px_70px_120px_70px_minmax(260px,1fr)] border-b border-gray-900 text-xs text-gray-300"
      title={String(event.raw_line ?? event.message ?? '')}
    >
      <div className="px-2 py-2 font-mono text-[11px] text-gray-500">{formatLogTime(event.timestamp)}</div>
      <div className="truncate px-2 py-2">{String(event.event_type ?? '-')}</div>
      <div className="px-2 py-2 font-mono text-[11px]">{shortRun(event.run_id)}</div>
      <div className="px-2 py-2 font-mono">{String(event.method ?? '-')}</div>
      <div className="truncate px-2 py-2 font-mono">{String(event.path ?? event.url ?? '-')}</div>
      <div className={status >= 200 && status < 400 ? 'px-2 py-2 text-green-300' : 'px-2 py-2 text-amber-300'}>{String(event.status ?? '-')}</div>
      <div className="truncate px-2 py-2 font-mono">{String(event.client_ip ?? '-')}</div>
      <div className="px-2 py-2 font-mono">{String(event.response_bytes ?? '-')}</div>
      <div className="truncate px-2 py-2 font-mono text-[11px] text-gray-500">
        {String(event.raw_line ?? event.message ?? `event-${index}`)}
      </div>
    </div>
  );
}

function AiAttackAssistant({
  mode,
  aiProvider,
  complicated,
  ttps,
  actor,
  goal,
  scenarios,
  scenarioId,
  destinationUrl,
  payloadFormat,
  result,
  error,
  isPending,
  onModeChange,
  onAiProviderChange,
  onComplicatedChange,
  onTtpsChange,
  onActorChange,
  onGoalChange,
  onScenarioChange,
  onRun,
}: {
  mode: AiAssistantMode;
  aiProvider: AiProvider;
  complicated: boolean;
  ttps: string;
  actor: string;
  goal: string;
  scenarios: AttackSimulationAiAssistantScenario[];
  scenarioId: string;
  destinationUrl: string;
  payloadFormat: SiemPayloadFormat;
  result?: AttackSimulationAiAssistantResult;
  error: unknown;
  isPending: boolean;
  onModeChange: (value: AiAssistantMode) => void;
  onAiProviderChange: (value: AiProvider) => void;
  onComplicatedChange: (value: boolean) => void;
  onTtpsChange: (value: string) => void;
  onActorChange: (value: string) => void;
  onGoalChange: (value: string) => void;
  onScenarioChange: (value: string) => void;
  onRun: () => void;
}) {
  const selectedTtps = parseTechniqueInput(ttps);
  const canRun = Boolean(destinationUrl.trim()) && (mode !== 'ttps' || selectedTtps.length > 0);
  const [showExplanation, setShowExplanation] = useState(false);
  const selectedScenario = scenarios.find(item => item.id === scenarioId) ?? scenarios[0];

  useEffect(() => {
    setShowExplanation(false);
  }, [result?.run_id]);

  return (
    <Panel title="AI Attack Assistant">
      <div className="grid gap-4 p-4 lg:grid-cols-[320px_minmax(0,1fr)]">
        <div className="space-y-3">
          <div className="rounded border border-cyan-900 bg-cyan-950/20 p-3 text-xs leading-5 text-cyan-100">
            Generates a correlated malicious telemetry story and sends it to the configured SIEM destination. This does not execute malware, exploit targets, or run arbitrary commands.
          </div>
          <label className="label">Assistant mode</label>
          <select className="field" value={mode} onChange={event => onModeChange(event.target.value as AiAssistantMode)}>
            <option value="challenge">Challenge me</option>
            <option value="ttps">Selected TTPs</option>
            <option value="actor">Threat actor profile</option>
          </select>
          <label className="label">LLM provider</label>
          <select className="field" value={aiProvider} onChange={event => onAiProviderChange(event.target.value as AiProvider)}>
            <option value="local">Local</option>
            <option value="claude">Claude</option>
            <option value="openai">OpenAI</option>
            <option value="gemini">Gemini</option>
            <option value="minimax">MiniMax</option>
          </select>
          <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">
            <input
              type="checkbox"
              checked={complicated}
              onChange={event => onComplicatedChange(event.target.checked)}
              className="mt-1"
            />
            <span>
              Complicated attack: generate a longer multi-source flow and send original vendor/source-shaped raw events: firewall, Windows Event, Sysmon, EDR, DNS, proxy, web, and WAF patterns.
            </span>
          </label>
          {mode === 'ttps' && (
            <div>
              <label className="label">TTPs to simulate</label>
              <textarea
                className="field min-h-24 font-mono text-xs"
                value={ttps}
                onChange={event => onTtpsChange(event.target.value)}
                placeholder="T1190, T1110.001, T1078, T1059.001"
              />
              <div className="mt-1 text-[11px] text-gray-500">{selectedTtps.length} parsed techniques</div>
            </div>
          )}
          {mode === 'actor' && (
            <div>
              <label className="label">Threat actor profile</label>
              <select className="field" value={actor} onChange={event => onActorChange(event.target.value)}>
                <option value="generic-intrusion">Generic intrusion chain</option>
                <option value="apt29">APT29-style identity and PowerShell chain</option>
                <option value="fin7">FIN7-style web, credential, and persistence chain</option>
                <option value="lazarus">Lazarus-style delivery and exfiltration chain</option>
              </select>
            </div>
          )}
          {mode === 'challenge' && complicated && selectedScenario && (
            <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">
              <label className="label">Scenario library</label>
              <select className="field mb-3" value={selectedScenario.id} onChange={event => onScenarioChange(event.target.value)}>
                {scenarios.map(item => (
                  <option key={item.id} value={item.id}>{item.name}</option>
                ))}
              </select>
              <div className="font-semibold text-white">{selectedScenario.name}</div>
              <p className="mt-1 text-gray-400">{selectedScenario.description}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                <Chip>{selectedScenario.difficulty}</Chip>
                {selectedScenario.tags.map(tag => <Chip key={tag}>{tag}</Chip>)}
              </div>
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                <ScenarioList title="Preconditions" items={selectedScenario.preconditions} />
                <ScenarioList title="Success criteria" items={selectedScenario.success_criteria} />
              </div>
              <div className="mt-3">
                <ScenarioList title="Expected detections" items={selectedScenario.expected_detections} />
              </div>
              <div className="mt-3">
                <Mini label="Telemetry sources" value={selectedScenario.telemetry_sources.join(', ')} />
              </div>
            </div>
          )}
          <div>
            <label className="label">Analyst goal</label>
            <textarea
              className="field min-h-24 text-xs"
              value={goal}
              onChange={event => onGoalChange(event.target.value)}
              placeholder="Example: generate a noisy web-to-endpoint challenge with credential access and exfiltration"
            />
          </div>
          <Mini label="SIEM destination" value={destinationUrl.trim() ? normalizeSiemDestination(destinationUrl) : 'Set SIEM URL in Forward Logs To SIEM first'} />
          <Mini label="Payload format" value={complicated ? 'raw original vendor/source lines' : payloadFormat} />
          <button type="button" disabled={!canRun || isPending} onClick={onRun} className="primary-action w-full disabled:opacity-40">
            {isPending ? 'Generating and sending...' : 'Generate and send AI attack telemetry'}
          </button>
          {Boolean(error) && <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">{String(error)}</div>}
        </div>
        <div className="space-y-3">
          {!result && (
            <div className="rounded border border-gray-800 bg-gray-950 p-4 text-sm leading-6 text-gray-400">
              Choose a mode and run the assistant to receive a generated kill-chain plan, strict event sources, and SIEM delivery status.
            </div>
          )}
          {result && (
            <>
              <div className={`rounded border p-3 text-xs ${result.delivery.ok ? 'border-green-900 bg-green-950/20 text-green-200' : 'border-red-900 bg-red-950/30 text-red-200'}`}>
                <b className="block">{result.delivery.ok ? 'Delivered' : 'Delivery failed'} · HTTP {result.delivery.status}</b>
                <span>{result.delivery.sent_event_count} / {result.delivery.event_count} events sent · run {result.run_id}</span>
                <span className="mt-1 block">
                  Provider: {result.ai_provider}{result.ai_model ? ` · ${result.ai_model}` : ''} · {result.ai_used ? 'AI planning used' : 'deterministic fallback'} · {result.complicated_attack ? 'complicated raw-source flow' : 'standard generated flow'}
                </span>
                {result.ai_planner_summary && <span className="mt-1 block">AI plan: {result.ai_planner_summary}</span>}
                {result.ai_error && <span className="mt-1 block text-amber-100">AI planning failed: {result.ai_error}</span>}
                {result.scenario && <span className="mt-1 block">Scenario: {result.scenario.name} · {result.scenario.difficulty}</span>}
                {result.delivery.error && <span className="mt-1 block">{result.delivery.error}</span>}
              </div>
              <div className="rounded border border-gray-800 bg-gray-950 p-3">
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <div className="text-sm font-semibold text-white">{result.attack_plan.summary}</div>
                  {result.mode === 'challenge' && (
                    <button type="button" onClick={() => setShowExplanation(value => !value)} className="secondary-action">
                      Explain attack
                    </button>
                  )}
                </div>
                <div className="mb-3 text-xs text-gray-500">{result.attack_plan.validation_note}</div>
                {result.mode === 'challenge' && showExplanation && <AttackExplanation result={result} />}
                <AttackChainGraph result={result} />
                <div className="space-y-2">
                  {result.attack_plan.kill_chain.map(step => (
                    <div key={`${step.step}-${step.technique_id}`} className="rounded border border-gray-800 bg-gray-900/50 p-2 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <TtpLink id={step.technique_id} />
                        <span className="font-mono text-gray-500">{step.event_source} · {step.event_id} · {step.source_format || 'json'} · {step.event_count ?? 1} events</span>
                      </div>
                      {step.flow_stage && <div className="mt-1 text-[10px] uppercase text-gray-500">{step.flow_stage}</div>}
                      <div className="mt-1 text-gray-300">{step.detection_goal}</div>
                      <div className="mt-2 flex flex-wrap gap-1">
                        {step.focus.map(item => <Chip key={item}>{item}</Chip>)}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}

function AttackChainGraph({ result }: { result: AttackSimulationAiAssistantResult }) {
  const graphNodes = useMemo<Node[]>(() => result.attack_plan.kill_chain.map((step, index) => ({
    id: `${step.step}-${step.technique_id}`,
    position: { x: index * 230, y: 60 + (index % 2) * 80 },
    data: { label: `${step.technique_id}\n${humanizePhase(step.flow_stage || 'activity')}\n${step.event_count ?? 1} events` },
    style: {
      width: 190,
      border: '1px solid #374151',
      background: '#020617',
      color: '#e5e7eb',
      fontSize: 11,
      whiteSpace: 'pre-line',
    },
  })), [result.attack_plan.kill_chain]);
  const graphEdges = useMemo<Edge[]>(() => result.attack_plan.kill_chain.slice(0, -1).map((step, index) => ({
    id: `phase-${step.step}-to-${result.attack_plan.kill_chain[index + 1].step}`,
    source: `${step.step}-${step.technique_id}`,
    target: `${result.attack_plan.kill_chain[index + 1].step}-${result.attack_plan.kill_chain[index + 1].technique_id}`,
    style: { stroke: '#64748b' },
  })), [result.attack_plan.kill_chain]);
  return (
    <div className="mb-3 rounded border border-gray-800 bg-gray-950 p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-semibold uppercase text-gray-400">Attack Chain Graph</div>
        <div className="text-[11px] text-gray-500">{result.attack_plan.kill_chain.length} phases · {result.events.length} events</div>
      </div>
      <div className="mb-3 h-[320px]">
        <EntityGraph nodes={graphNodes} edges={graphEdges} />
      </div>
      <div className="space-y-0">
        {result.attack_plan.kill_chain.map((step, index) => (
          <div key={`graph-${step.step}-${step.technique_id}`} className="grid grid-cols-[32px_minmax(0,1fr)] gap-3">
            <div className="flex flex-col items-center">
              <div className="flex h-7 w-7 items-center justify-center rounded-full border border-mitre-accent bg-gray-900 text-[10px] font-semibold text-mitre-accent">
                {step.step}
              </div>
              {index < result.attack_plan.kill_chain.length - 1 && <div className="min-h-8 flex-1 border-l border-gray-700" />}
            </div>
            <div className={`mb-2 rounded border border-gray-800 bg-gray-900/70 p-3 ${index === result.attack_plan.kill_chain.length - 1 ? 'mb-0' : ''}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-mitre-accent"><TtpLink id={step.technique_id} /></span>
                  <span className="rounded bg-gray-950 px-2 py-0.5 text-[10px] uppercase text-gray-400">{humanizePhase(step.flow_stage || 'activity')}</span>
                </div>
                <span className="font-mono text-[11px] text-gray-500">{step.event_count ?? 1} events</span>
              </div>
              <div className="mt-2 text-xs leading-5 text-gray-300">{step.detection_goal}</div>
              <div className="mt-2 grid gap-2 md:grid-cols-2">
                <Mini label="Telemetry source" value={`${step.event_source} · ${step.event_id}`} />
                <Mini label="Raw format" value={step.source_format || 'normalized_json'} />
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {step.focus.map(item => <Chip key={`graph-${step.step}-${item}`}>{item}</Chip>)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function AttackExplanation({ result }: { result: AttackSimulationAiAssistantResult }) {
  const totalEvents = result.events.length;
  const firstPhase = result.attack_plan.kill_chain[0];
  const lastPhase = result.attack_plan.kill_chain[result.attack_plan.kill_chain.length - 1];
  const sources = Array.from(new Set(result.attack_plan.kill_chain.map(step => step.event_source))).join(', ');
  const formats = Array.from(new Set(result.attack_plan.kill_chain.map(step => step.source_format).filter(Boolean))).join(', ');
  const techniques = Array.from(new Set(result.attack_plan.kill_chain.map(step => step.technique_id)));
  return (
    <div className="mb-3 rounded border border-cyan-900 bg-cyan-950/10 p-3 text-xs leading-5 text-gray-300">
      <div className="mb-2 text-sm font-semibold text-cyan-100">Attack Explanation</div>
      <p>
        This challenge generated {totalEvents} correlated events across {result.attack_plan.kill_chain.length} phases. The flow starts with {firstPhase?.flow_stage || firstPhase?.detection_goal || 'initial activity'} and ends with {lastPhase?.flow_stage || lastPhase?.detection_goal || 'follow-on activity'}.
      </p>
      <div className="mt-3 grid gap-2 md:grid-cols-3">
        <Mini label="Techniques" value={techniques.join(', ')} />
        <Mini label="Telemetry sources" value={sources || 'endpoint'} />
        <Mini label="Event format" value={result.attack_plan.payload_style || (formats || 'structured JSON')} />
        <Mini label="AI planner" value={result.ai_used ? `${result.ai_provider}${result.ai_model ? ` / ${result.ai_model}` : ''}` : `fallback${result.ai_error ? `: ${result.ai_error}` : ''}`} />
        <Mini label="Run ID" value={result.run_id} />
      </div>
      {result.scenario && (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          <ScenarioList title="Scenario success criteria" items={result.scenario.success_criteria} />
          <ScenarioList title="Expected detections" items={result.scenario.expected_detections} />
        </div>
      )}
      <div className="mt-3 space-y-2">
        {result.attack_plan.kill_chain.map(step => (
          <div key={`explain-${step.step}-${step.technique_id}`} className="rounded border border-gray-800 bg-gray-950 p-2">
            <div className="font-semibold text-white">
              Step {step.step}: {step.technique_id} · {step.flow_stage || 'activity'} · {step.event_count ?? 1} events
            </div>
            <p className="mt-1 text-gray-400">
              The simulated attacker produced {step.detection_goal.toLowerCase()}. Inspect {step.event_source} telemetry with event ID {step.event_id}{step.source_format ? ` in ${step.source_format} format` : ''}; correlate by run ID, source identity, host, user, and time proximity.
            </p>
            <div className="mt-2 flex flex-wrap gap-1">
              {step.focus.map(item => <Chip key={`explain-${step.step}-${item}`}>{item}</Chip>)}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 rounded border border-amber-900 bg-amber-950/20 p-2 text-amber-100">
        Detection validation: confirm that your SIEM groups related events by source, account, host, and run ID; then verify alerts fire on the sequence, not only on a single atomic event.
      </div>
    </div>
  );
}

function humanizePhase(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
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
            className="field font-mono text-xs placeholder:text-gray-600"
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
            <option value="raw_lines">Raw original line per request</option>
            <option value="per_event">JSON event per request</option>
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
            <option value="attacked_server">All attacked-server events</option>
            <option value="access">Real web access log</option>
            <option value="auth">Real auth log</option>
            <option value="endpoint">Endpoint EDR/Sysmon log</option>
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
  type TelemetryEvent = NonNullable<NonNullable<AttackSimulationRun['telemetry']>['events']>[number];
  const telemetryColumns = useMemo<ColumnDef<TelemetryEvent>[]>(() => [
    { header: '#', cell: ({ row }) => <span className="font-mono">{row.original.request_index}</span> },
    { header: 'Method', cell: ({ row }) => <span className="font-mono">{row.original.method}</span> },
    { header: 'Path', cell: ({ row }) => <span className="font-mono">{row.original.path}</span> },
    { header: 'Status', cell: ({ row }) => <span className={row.original.ok ? 'text-green-300' : 'text-red-300'}>{row.original.status}</span> },
    { header: 'Duration', cell: ({ row }) => <span className="font-mono">{row.original.duration_ms} ms</span> },
    { header: 'Bytes', cell: ({ row }) => <span className="font-mono">{row.original.response_bytes}</span> },
  ], []);
  return (
    <div className="mt-4 rounded border border-gray-800 bg-gray-950">
      <div className="border-b border-gray-800 px-3 py-2 text-xs font-semibold uppercase text-gray-500">Local Lab Telemetry</div>
      <div className="space-y-3 p-3 text-xs text-gray-300">
        <div className="grid gap-2 md:grid-cols-2">
          {telemetry.log_file && <Mini label="Attack log" value={telemetry.log_file} />}
          {telemetry.web_access_log_file && <Mini label="Structured web JSONL" value={telemetry.web_access_log_file} />}
          {telemetry.web_server_access_log_file && <Mini label="Real access log" value={telemetry.web_server_access_log_file} />}
          {telemetry.web_auth_log_file && <Mini label="Auth log" value={telemetry.web_auth_log_file} />}
          {telemetry.endpoint_log_file && <Mini label="Endpoint log" value={telemetry.endpoint_log_file} />}
          {telemetry.web_security_log_file && <Mini label="Security log" value={telemetry.web_security_log_file} />}
          {telemetry.web_error_log_file && <Mini label="Error log" value={telemetry.web_error_log_file} />}
        </div>
        {telemetry.events?.length ? (
          <DataTable data={telemetry.events} columns={telemetryColumns} />
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

function toSiemDestinationPayload(item: Omit<SiemDestinationHistoryItem, 'id' | 'savedAt'>) {
  return {
    destination_url: normalizeSiemDestination(item.url),
    auth_type: item.authType,
    username: item.authType === 'basic' ? item.username.trim() : '',
    header_name: item.authType === 'custom_header' ? item.headerName.trim() : item.headerName || 'Authorization',
    connection_mode: item.connectionMode,
    allow_http_fallback: item.allowHttpFallback,
    payload_format: item.payloadFormat,
    source: item.source,
  };
}

function fromServerSiemDestination(item: AttackSimulationSiemDestination): SiemDestinationHistoryItem {
  return {
    id: item.id,
    url: item.destination_url,
    authType: item.auth_type,
    username: item.username,
    headerName: item.header_name || 'Authorization',
    connectionMode: item.connection_mode,
    allowHttpFallback: item.allow_http_fallback,
    payloadFormat: item.payload_format,
    source: item.source,
    savedAt: item.updated_at,
  };
}

function parseTechniqueInput(value: string) {
  const seen = new Set<string>();
  return value
    .split(/[\s,;]+/)
    .map(item => item.trim().toUpperCase())
    .filter(item => /^T\d{4}(?:\.\d{3})?$/.test(item))
    .filter(item => {
      if (seen.has(item)) return false;
      seen.add(item);
      return true;
    })
    .slice(0, 12);
}

function isSiemHistoryItem(value: unknown): value is SiemDestinationHistoryItem {
  if (!value || typeof value !== 'object') return false;
  const item = value as Record<string, unknown>;
  return (
    typeof item.id === 'string' &&
    typeof item.url === 'string' &&
    ['none', 'bearer', 'token', 'basic', 'custom_header'].includes(String(item.authType)) &&
    ['auto', 'direct', 'docker_host'].includes(String(item.connectionMode)) &&
    ['raw_lines', 'per_event', 'json_lines', 'envelope'].includes(String(item.payloadFormat)) &&
    ['attacked_server', 'web', 'run', 'access', 'security', 'error', 'auth', 'endpoint'].includes(String(item.source))
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

function ScenarioList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="mb-1 text-[10px] uppercase text-gray-600">{title}</div>
      <ul className="space-y-1">
        {items.map(item => <li key={item} className="rounded bg-gray-900 px-2 py-1 text-[11px] text-gray-300">{item}</li>)}
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
