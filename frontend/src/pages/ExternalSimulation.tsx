import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { simulationApi } from '@/api/client';
import type {
  ExternalSimulationCatalogItem,
  ExternalSimulationManualResult,
  ExternalSimulationPlan,
  ExternalSimulationRun,
} from '@/api/client';
import { TtpLink } from '@/utils/ctiLinks';

type DetectionResult = 'passed' | 'failed' | 'partial' | 'not_proven';

export function ExternalSimulation() {
  const [simulationId, setSimulationId] = useState('sim-t1595-http-fingerprint');
  const [targetId, setTargetId] = useState('lab-web-01');
  const [analystNote, setAnalystNote] = useState('');
  const [evidence, setEvidence] = useState('');
  const [gaps, setGaps] = useState('Detection result not proven until SIEM/WAF/firewall evidence is attached.');
  const [detectionResult, setDetectionResult] = useState<DetectionResult>('not_proven');
  const [plan, setPlan] = useState<ExternalSimulationPlan | null>(null);
  const [run, setRun] = useState<ExternalSimulationRun | null>(null);
  const [manual, setManual] = useState<ExternalSimulationManualResult | null>(null);

  const catalogQuery = useQuery({ queryKey: ['simulation-catalog'], queryFn: simulationApi.catalog });
  const targetsQuery = useQuery({ queryKey: ['simulation-targets'], queryFn: simulationApi.targets });
  const catalog = catalogQuery.data ?? [];
  const targets = targetsQuery.data ?? [];
  const selectedSimulation = catalog.find(item => item.id === simulationId);
  const selectedTarget = targets.find(item => item.id === targetId);
  const compatibleTargets = useMemo(() => {
    if (!selectedSimulation) return targets;
    return targets.filter(target => target.allowed_simulations.includes(selectedSimulation.id));
  }, [selectedSimulation, targets]);

  const planMutation = useMutation({
    mutationFn: () => simulationApi.plan({ simulation_id: simulationId, target_id: targetId, analyst_note: analystNote }),
    onSuccess: next => {
      setPlan(next);
      setRun(null);
      setManual(null);
    },
  });
  const runMutation = useMutation({
    mutationFn: () => simulationApi.run({ simulation_id: simulationId, target_id: targetId, analyst_note: analystNote }),
    onSuccess: next => {
      setRun(next);
      setPlan(next.plan);
      setManual(null);
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

  const canAct = Boolean(simulationId && targetId);

  return (
    <div className="flex h-full flex-col">
      <Header title="External TTP Simulation" />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto xl:grid-cols-[420px_minmax(0,1fr)] xl:overflow-hidden">
        <aside className="min-h-0 overflow-y-auto border-r border-gray-700 p-4">
          <Panel title="Safety Boundary">
            <div className="space-y-2 p-3 text-xs leading-5 text-amber-100">
              <p>This MVP prepares and records authorized external TTP simulations. It does not execute arbitrary commands, does not run exploit payloads, and does not emit external traffic from the API runner.</p>
              <p>Use approved lab targets only. Attach observed telemetry from your lab before marking coverage as passed.</p>
            </div>
          </Panel>

          <Panel title="Simulation">
            <div className="space-y-3 p-3">
              <label className="label">TTP Simulation</label>
              <select className="field" value={simulationId} onChange={event => setSimulationId(event.target.value)}>
                {catalog.map(item => (
                  <option key={item.id} value={item.id}>{item.technique_id} · {item.name}</option>
                ))}
              </select>
              {selectedSimulation && <SimulationSummary item={selectedSimulation} />}
            </div>
          </Panel>

          <Panel title="Approved Target">
            <div className="space-y-3 p-3">
              <label className="label">Target registry</label>
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
              <label className="label">Analyst note</label>
              <textarea className="field min-h-[80px]" value={analystNote} onChange={event => setAnalystNote(event.target.value)} placeholder="Purpose, ticket, maintenance window, or validation objective" />
              <div className="grid grid-cols-2 gap-2">
                <button type="button" disabled={!canAct || planMutation.isPending} onClick={() => planMutation.mutate()} className="secondary-action disabled:opacity-40">
                  Dry-run plan
                </button>
                <button type="button" disabled={!canAct || runMutation.isPending} onClick={() => runMutation.mutate()} className="primary-action disabled:opacity-40">
                  Create run record
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
              <h2 className="text-lg font-semibold text-white">Select a simulation and target to generate a validation plan.</h2>
              <p className="mt-3 text-sm leading-6 text-gray-400">
                Start with dry-run planning. The platform records safety gates, expected telemetry, and validation gaps before any lab evidence is accepted.
              </p>
            </div>
          )}

          {plan && <PlanView plan={plan} />}
          {run && <RunView run={run} />}

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

function SimulationSummary({ item }: { item: ExternalSimulationCatalogItem }) {
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

function PlanView({ plan }: { plan: ExternalSimulationPlan }) {
  return (
    <div className="mb-5 grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
      <Panel title="Dry-run Plan">
        <div className="space-y-4 p-4">
          <div className={`rounded border p-3 text-sm ${plan.allowed ? 'border-green-900 bg-green-950/20 text-green-200' : 'border-red-900 bg-red-950/30 text-red-200'}`}>
            {plan.allowed ? 'Allowed by safety policy' : `Blocked: ${plan.block_reasons.join('; ')}`}
          </div>
          <p className="text-sm leading-6 text-amber-100">{plan.safety_notice}</p>
          <Section title="Simulation Steps" items={plan.steps} />
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

function RunView({ run }: { run: ExternalSimulationRun }) {
  return (
    <Panel title="Run Record">
      <div className="grid gap-4 p-4 lg:grid-cols-[260px_minmax(0,1fr)]">
        <div className="space-y-2">
          <Mini label="Run" value={run.run_id} />
          <Mini label="Status" value={run.status} />
          <Mini label="Traffic emitted" value={run.traffic_emitted ? 'yes' : 'no'} />
          <Mini label="Validation" value={run.validation_status} />
        </div>
        <div>
          <div className="rounded border border-gray-800 bg-gray-950 p-3 font-mono text-xs leading-6 text-gray-300">
            {run.transcript.map((line, index) => <div key={`${line}-${index}`}>{line}</div>)}
          </div>
          <Section title="Gaps" items={run.gaps} />
          {run.next_steps && <Section title="Next Steps" items={run.next_steps} />}
        </div>
      </div>
    </Panel>
  );
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
