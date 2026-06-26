import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  malwareGraphApi,
  type MalwareGraphRuntimeDebugSession,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import {
  Empty,
  Info,
  Metric,
  Panel,
  RUNTIME_DEBUG_DISCLAIMER,
  analysisTargets,
  caseIdentifier,
  caseTitle,
  field,
  malwareInput,
  primarySampleRef,
  readHiddenCases,
  shortLabel,
  statusColor,
  visibleJobs,
} from '@/pages/malwareShared';

export function DynamicAnalysis() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [jobId, setJobId]                         = useState(params.get('job_id') ?? '');
  const [sampleRef, setSampleRef]                 = useState(params.get('sample_ref') ?? '');
  const [disclaimerAccepted, setDisclaimer]       = useState(params.get('dynamic') === 'true');
  const [session, setSession]                     = useState<MalwareGraphRuntimeDebugSession | null>(null);
  const [autoStepping, setAutoStepping]           = useState(false);

  const jobs     = useQuery({ queryKey: ['malwaregraph-jobs'],             queryFn: malwareGraphApi.jobs,      retry: false });
  const analysis = useQuery({ queryKey: ['malwaregraph-analysis', jobId], queryFn: () => malwareGraphApi.analysis(jobId), enabled: Boolean(jobId) });

  const currentJob = useMemo(() => jobs.data?.find(job => job.job_id === jobId), [jobId, jobs.data]);
  const targets    = useMemo(() => analysisTargets(analysis.data), [analysis.data]);

  useEffect(() => {
    if (jobId && readHiddenCases().has(jobId)) { setJobId(''); setSampleRef(''); }
  }, [jobId]);
  useEffect(() => {
    const visible = visibleJobs(jobs.data ?? []);
    if (!jobId && visible.length) setJobId(visible[0].job_id);
  }, [jobId, jobs.data]);
  useEffect(() => {
    if (!sampleRef && analysis.data) setSampleRef(primarySampleRef(analysis.data));
  }, [analysis.data, sampleRef]);
  useEffect(() => {
    const next = new URLSearchParams();
    if (jobId)              next.set('job_id',   jobId);
    if (sampleRef)          next.set('sample_ref', sampleRef);
    if (disclaimerAccepted) next.set('dynamic',  'true');
    setParams(next, { replace: true });
  }, [disclaimerAccepted, jobId, sampleRef, setParams]);

  // Auto-step effect: fires whenever current_step advances while auto-stepping
  useEffect(() => {
    if (!autoStepping || !session || session.completed || stepSession.isPending) return;
    stepSession.mutate();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStepping, session?.current_step, session?.completed]);

  const createSession = useMutation({
    mutationFn: () => malwareGraphApi.runtimeDebugSession(jobId, sampleRef, disclaimerAccepted, disclaimerAccepted),
    onSuccess: result => { setSession(result); setAutoStepping(false); },
  });

  const stepSession = useMutation({
    mutationFn: () => malwareGraphApi.stepRuntimeDebugSession(session!.session_id),
    onSuccess: result => {
      setSession(result);
      if (result.completed) setAutoStepping(false);
    },
  });

  const isRunning = autoStepping || stepSession.isPending;
  const canStep   = Boolean(session && !session.completed && !isRunning);

  function handleRunAll() {
    if (!canStep) return;
    setAutoStepping(true);
    stepSession.mutate();
  }

  return <div className="flex h-full flex-col">
    <Header title="Dynamic Analysis" />
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mx-auto grid max-w-7xl gap-4 xl:grid-cols-[340px_1fr]">

        <aside className="space-y-4">
          <Panel title="Runtime Target">
            <div className="space-y-3 p-3">
              <label className="block text-[10px] uppercase text-gray-600">Analysis case</label>
              <select value={jobId} onChange={e => { setJobId(e.target.value); setSampleRef(''); setSession(null); setAutoStepping(false); }} className={malwareInput}>
                {visibleJobs(jobs.data ?? []).map(job => (
                  <option key={job.job_id} value={job.job_id}>{caseTitle(job, undefined)} · {job.case_id ?? job.job_id}</option>
                ))}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">Runtime target</label>
              <select value={sampleRef} onChange={e => { setSampleRef(e.target.value); setSession(null); setAutoStepping(false); }} className={malwareInput}>
                {targets.map(target => <option key={target.id} value={target.id}>{target.label}</option>)}
              </select>
              <label className="flex items-start gap-3 rounded border border-amber-500/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                <input className="mt-0.5 shrink-0" type="checkbox" checked={disclaimerAccepted} onChange={e => setDisclaimer(e.target.checked)} />
                <span>{RUNTIME_DEBUG_DISCLAIMER}</span>
              </label>
              <button
                className="primary w-full"
                onClick={() => createSession.mutate()}
                disabled={!jobId || !sampleRef || !disclaimerAccepted || createSession.isPending}
              >
                {createSession.isPending ? 'Preparing...' : 'Prepare isolated runtime session'}
              </button>
              {session && !session.completed && <>
                <button className="primary w-full" onClick={handleRunAll} disabled={!canStep}>
                  {isRunning ? `Running step ${session.current_step + 1} / ${session.steps.length}...` : 'Run all steps'}
                </button>
                <button className="secondary-action w-full" onClick={() => stepSession.mutate()} disabled={!canStep}>
                  {stepSession.isPending ? 'Stepping...' : 'Step once'}
                </button>
                {autoStepping && (
                  <button className="secondary-action w-full" onClick={() => setAutoStepping(false)}>Stop auto-run</button>
                )}
              </>}
              {session?.completed && (
                <div className="rounded border border-green-600/30 bg-green-950/20 px-3 py-2 text-xs text-green-300">
                  Session complete — all steps executed
                </div>
              )}
              <button className="secondary-action w-full" onClick={() => navigate(`/malware-analysis?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}`)}>
                ← Back to case
              </button>
              {(createSession.error || stepSession.error) && (
                <p className="text-xs text-red-300">{String(createSession.error ?? stepSession.error)}</p>
              )}
            </div>
          </Panel>

          <Panel title="Case Context">
            {analysis.data ? <div className="grid gap-2 p-3 text-xs">
              <Info label="Case" value={caseTitle(currentJob, analysis.data)} />
              <Info label="Case ID" value={caseIdentifier(currentJob, analysis.data)} />
              <Info label="Job" value={analysis.data.job_id} />
              <Info label="Target" value={targets.find(t => t.id === sampleRef)?.label ?? sampleRef} />
            </div> : <Empty text="Select a case." />}
          </Panel>
        </aside>

        <main className="space-y-4">
          {session
            ? <DynamicSession
                session={session}
                isRunning={isRunning}
                onOpenDebugger={() => navigate(`/malware-debug?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}${session.dynamic_enabled ? '&dynamic=true' : ''}`)}
              />
            : <div className="rounded border border-amber-500/40 bg-amber-950/30 p-4 text-sm font-semibold text-amber-100">
                Accept the disclaimer and click "Prepare isolated runtime session" to start.
              </div>
          }
        </main>
      </div>
    </div>
  </div>;
}

// ── Session view ──────────────────────────────────────────────────────────────

function DynamicSession({ session, isRunning, onOpenDebugger }: {
  session: MalwareGraphRuntimeDebugSession;
  isRunning: boolean;
  onOpenDebugger: () => void;
}) {
  const current = session.steps[session.current_step] ?? session.steps[0] ?? null;
  const done    = session.steps.filter(s => s.status === 'completed').length;
  const findings = extractAllFindings(session);

  return <>
    {/* Status strip */}
    <div className="grid gap-3 md:grid-cols-5">
      <Metric label="Mode" value={session.mode} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Dynamic" value={session.dynamic_enabled ? 'enabled' : 'off'} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Progress" value={`${done} / ${session.steps.length}`} tone={session.completed ? 'good' : isRunning ? 'warn' : 'default'} />
      <Metric label="Status" value={session.completed ? 'complete' : isRunning ? 'running' : current?.action ?? 'ready'} tone={session.completed ? 'good' : 'default'} />
      <Metric label="Findings" value={findings.total} tone={findings.total > 0 ? 'warn' : 'default'} />
    </div>

    {session.warning && (
      <div className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-100">{session.warning}</div>
    )}

    {/* Workflow graph */}
    <Panel title="Runtime Workflow Graph" actions={<button className="secondary-action" onClick={onOpenDebugger}>Open IDE debug</button>}>
      <RuntimeGraph session={session} />
    </Panel>

    {/* Findings summary — shown after any step completes */}
    {findings.total > 0 && <FindingsSummary findings={findings} />}

    {/* Per-step detail */}
    <Panel title="Step Results">
      <div className="divide-y divide-gray-800">
        {session.steps.map((step, index) => (
          <StepRow key={step.step_id} step={step} isCurrent={index === session.current_step} index={index} />
        ))}
      </div>
    </Panel>

    {/* Isolation */}
    <Panel title="Isolation Profile">
      <div className="grid gap-2 p-3 text-xs md:grid-cols-2">
        {Object.entries(session.isolation).map(([key, value]) => (
          <Info key={key} label={key.replace(/_/g, ' ')} value={field(value)} />
        ))}
      </div>
    </Panel>
  </>;
}

// ── Step row with extracted findings ─────────────────────────────────────────

function StepRow({ step, isCurrent, index }: {
  step: MalwareGraphRuntimeDebugSession['steps'][number];
  isCurrent: boolean;
  index: number;
}) {
  const [open, setOpen] = useState(step.status === 'completed');
  const snap = step.snapshot ?? {};
  const hasData = Object.keys(snap).length > 0;
  const stepFindings = extractStepFindings(snap);

  return <div className={`text-xs ${isCurrent ? 'bg-mitre-accent/5' : ''}`}>
    <button
      type="button"
      onClick={() => setOpen(v => !v)}
      className="flex w-full items-center justify-between gap-2 p-3 text-left hover:bg-gray-900/40"
    >
      <div className="flex items-center gap-3">
        <span className={`w-5 h-5 shrink-0 rounded-full flex items-center justify-center text-[10px] font-bold ${isCurrent ? 'bg-mitre-accent text-white' : step.status === 'completed' ? 'bg-green-800 text-green-200' : step.status === 'error' ? 'bg-red-900 text-red-200' : 'bg-gray-800 text-gray-400'}`}>
          {index + 1}
        </span>
        <div>
          <b className="text-gray-200">{step.action}</b>
          {step.target && <span className="ml-2 text-[10px] text-gray-500 font-mono">{shortLabel(step.target, 30)}</span>}
        </div>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {stepFindings.total > 0 && (
          <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-[10px] text-amber-300">{stepFindings.total} findings</span>
        )}
        <span style={{ color: statusColor(step.status) }} className="text-[11px]">{step.status}</span>
        <span className="text-gray-600">{open ? '▲' : '▼'}</span>
      </div>
    </button>

    {open && <div className="border-t border-gray-800/60 p-3 space-y-3">
      {step.notes && <p className="text-gray-500 leading-relaxed">{step.notes}</p>}
      {!hasData && step.status !== 'completed' && <p className="text-gray-600">No snapshot data yet.</p>}
      {hasData && <StepFindings findings={stepFindings} raw={snap} />}
    </div>}
  </div>;
}

// ── Findings extraction & display ─────────────────────────────────────────────

interface StepFindingsData {
  apiCalls:       string[];
  processes:      Array<{ name?: string; pid?: number | string; cmd?: string; [k: string]: unknown }>;
  fileOps:        Array<{ path?: string; operation?: string; [k: string]: unknown }>;
  registryOps:    Array<{ key?: string; operation?: string; [k: string]: unknown }>;
  networkConns:   Array<{ host?: string; ip?: string; port?: number | string; protocol?: string; [k: string]: unknown }>;
  iocs:           Array<{ type?: string; value?: string; [k: string]: unknown }>;
  strings:        string[];
  total:          number;
}

function extractStepFindings(snap: Record<string, unknown>): StepFindingsData {
  const apiCalls:     string[]                                       = asStrings(snap.api_calls ?? snap.api_trace ?? snap.calls);
  const processes:    StepFindingsData['processes']                  = asObjects(snap.processes ?? snap.spawned_processes);
  const fileOps:      StepFindingsData['fileOps']                   = asObjects(snap.file_operations ?? snap.file_ops ?? snap.files);
  const registryOps:  StepFindingsData['registryOps']               = asObjects(snap.registry_operations ?? snap.registry_ops ?? snap.registry);
  const networkConns: StepFindingsData['networkConns']              = asObjects(snap.network_activity ?? snap.network_connections ?? snap.connections ?? snap.network);
  const iocs:         StepFindingsData['iocs']                      = asObjects(snap.iocs ?? snap.indicators);
  const strings:      string[]                                       = asStrings(snap.captured_strings ?? snap.interesting_strings ?? snap.strings);
  const total = apiCalls.length + processes.length + fileOps.length + registryOps.length + networkConns.length + iocs.length + strings.length;
  return { apiCalls, processes, fileOps, registryOps, networkConns, iocs, strings, total };
}

interface AllFindings extends StepFindingsData {}

function extractAllFindings(session: MalwareGraphRuntimeDebugSession): AllFindings {
  const merged: AllFindings = { apiCalls: [], processes: [], fileOps: [], registryOps: [], networkConns: [], iocs: [], strings: [], total: 0 };
  for (const step of session.steps) {
    const f = extractStepFindings(step.snapshot ?? {});
    merged.apiCalls.push(...f.apiCalls);
    merged.processes.push(...f.processes);
    merged.fileOps.push(...f.fileOps);
    merged.registryOps.push(...f.registryOps);
    merged.networkConns.push(...f.networkConns);
    merged.iocs.push(...f.iocs);
    merged.strings.push(...f.strings);
  }
  merged.total = merged.apiCalls.length + merged.processes.length + merged.fileOps.length + merged.registryOps.length + merged.networkConns.length + merged.iocs.length + merged.strings.length;
  return merged;
}

function StepFindings({ findings, raw }: { findings: StepFindingsData; raw: Record<string, unknown> }) {
  const knownKeys = new Set(['api_calls','api_trace','calls','processes','spawned_processes','file_operations','file_ops','files','registry_operations','registry_ops','registry','network_activity','network_connections','connections','network','iocs','indicators','captured_strings','interesting_strings','strings']);
  const unknownEntries = Object.entries(raw).filter(([k]) => !knownKeys.has(k));

  return <div className="space-y-3">
    {findings.processes.length > 0 && <FindingsGroup label="Processes" count={findings.processes.length}>
      {findings.processes.map((p, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          <span className="font-mono text-gray-200">{String(p.name ?? p.cmd ?? JSON.stringify(p))}</span>
          {p.pid != null && <span className="text-gray-600">pid:{String(p.pid)}</span>}
        </div>
      ))}
    </FindingsGroup>}

    {findings.apiCalls.length > 0 && <FindingsGroup label="API Calls" count={findings.apiCalls.length}>
      <div className="flex flex-wrap gap-1.5">
        {findings.apiCalls.slice(0, 80).map((call, i) => (
          <span key={i} className="rounded border border-gray-700 bg-gray-900 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">{call}</span>
        ))}
        {findings.apiCalls.length > 80 && <span className="text-gray-600 text-[10px]">+{findings.apiCalls.length - 80} more</span>}
      </div>
    </FindingsGroup>}

    {findings.fileOps.length > 0 && <FindingsGroup label="File Operations" count={findings.fileOps.length}>
      {findings.fileOps.slice(0, 40).map((f, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {f.operation && <span className="shrink-0 rounded bg-blue-900/30 px-1.5 py-0.5 text-[9px] uppercase text-blue-300">{String(f.operation)}</span>}
          <span className="min-w-0 break-all font-mono text-[10px] text-gray-300">{String(f.path ?? JSON.stringify(f))}</span>
        </div>
      ))}
    </FindingsGroup>}

    {findings.registryOps.length > 0 && <FindingsGroup label="Registry" count={findings.registryOps.length}>
      {findings.registryOps.slice(0, 40).map((r, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {r.operation && <span className="shrink-0 rounded bg-purple-900/30 px-1.5 py-0.5 text-[9px] uppercase text-purple-300">{String(r.operation)}</span>}
          <span className="min-w-0 break-all font-mono text-[10px] text-gray-300">{String(r.key ?? JSON.stringify(r))}</span>
        </div>
      ))}
    </FindingsGroup>}

    {findings.networkConns.length > 0 && <FindingsGroup label="Network" count={findings.networkConns.length}>
      {findings.networkConns.slice(0, 40).map((n, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {n.protocol && <span className="shrink-0 text-[10px] text-gray-500 uppercase">{String(n.protocol)}</span>}
          <span className="font-mono text-[10px] text-amber-300">{String(n.host ?? n.ip ?? JSON.stringify(n))}</span>
          {n.port != null && <span className="text-gray-600">:{String(n.port)}</span>}
        </div>
      ))}
    </FindingsGroup>}

    {findings.iocs.length > 0 && <FindingsGroup label="IOC Indicators" count={findings.iocs.length}>
      {findings.iocs.map((ioc, i) => (
        <div key={i} className="flex items-center gap-2 rounded bg-gray-900/40 px-2 py-1.5">
          {ioc.type && <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[9px] text-gray-400">{String(ioc.type)}</span>}
          <span className="break-all font-mono text-[10px] text-mitre-accent">{String(ioc.value ?? JSON.stringify(ioc))}</span>
        </div>
      ))}
    </FindingsGroup>}

    {findings.strings.length > 0 && <FindingsGroup label="Captured Strings" count={findings.strings.length}>
      <div className="max-h-40 overflow-y-auto space-y-0.5">
        {findings.strings.slice(0, 100).map((s, i) => (
          <div key={i} className="rounded bg-gray-900/40 px-2 py-0.5 font-mono text-[10px] text-gray-400">{s}</div>
        ))}
      </div>
    </FindingsGroup>}

    {/* Unknown snapshot keys as collapsible raw JSON */}
    {unknownEntries.length > 0 && <details className="rounded border border-gray-800">
      <summary className="cursor-pointer px-3 py-2 text-[10px] uppercase text-gray-500 hover:text-gray-300">Raw snapshot data</summary>
      <pre className="max-h-60 overflow-auto p-3 text-[10px] text-gray-500">{JSON.stringify(Object.fromEntries(unknownEntries), null, 2)}</pre>
    </details>}
  </div>;
}

function FindingsSummary({ findings }: { findings: AllFindings }) {
  return <Panel title="Dynamic Findings Summary">
    <div className="grid gap-3 p-3 md:grid-cols-4">
      <Metric label="API Calls"    value={findings.apiCalls.length}     tone={findings.apiCalls.length > 0 ? 'warn' : 'default'} />
      <Metric label="Processes"    value={findings.processes.length}    tone={findings.processes.length > 0 ? 'warn' : 'default'} />
      <Metric label="File Ops"     value={findings.fileOps.length}      tone={findings.fileOps.length > 0 ? 'warn' : 'default'} />
      <Metric label="Registry"     value={findings.registryOps.length}  tone={findings.registryOps.length > 0 ? 'warn' : 'default'} />
      <Metric label="Network"      value={findings.networkConns.length} tone={findings.networkConns.length > 0 ? 'bad' : 'default'} />
      <Metric label="IOCs"         value={findings.iocs.length}         tone={findings.iocs.length > 0 ? 'bad' : 'default'} />
      <Metric label="Strings"      value={findings.strings.length}      tone={findings.strings.length > 0 ? 'warn' : 'default'} />
      <Metric label="Total"        value={findings.total}               tone={findings.total > 0 ? 'warn' : 'good'} />
    </div>
    {findings.networkConns.length > 0 && (
      <div className="border-t border-gray-800 p-3">
        <div className="mb-2 text-[10px] uppercase text-gray-500">Network activity</div>
        <div className="flex flex-wrap gap-1.5">
          {findings.networkConns.map((n, i) => (
            <span key={i} className="rounded border border-amber-600/30 bg-amber-950/20 px-2 py-0.5 font-mono text-[10px] text-amber-300">
              {String(n.host ?? n.ip ?? JSON.stringify(n))}{n.port ? `:${String(n.port)}` : ''}
            </span>
          ))}
        </div>
      </div>
    )}
    {findings.iocs.length > 0 && (
      <div className="border-t border-gray-800 p-3">
        <div className="mb-2 text-[10px] uppercase text-gray-500">IOC indicators</div>
        <div className="flex flex-wrap gap-1.5">
          {findings.iocs.map((ioc, i) => (
            <span key={i} className="rounded border border-red-600/30 bg-red-950/20 px-2 py-0.5 font-mono text-[10px] text-red-300">
              {String(ioc.value ?? JSON.stringify(ioc))}
            </span>
          ))}
        </div>
      </div>
    )}
  </Panel>;
}

function FindingsGroup({ label, count, children }: { label: string; count: number; children: React.ReactNode }) {
  return <div>
    <div className="mb-1.5 flex items-center gap-2">
      <span className="text-[10px] font-semibold uppercase text-gray-400">{label}</span>
      <span className="rounded bg-gray-800 px-1 py-0.5 text-[9px] text-gray-500">{count}</span>
    </div>
    <div className="space-y-1 text-[11px]">{children}</div>
  </div>;
}

// ── Workflow graph ─────────────────────────────────────────────────────────────

function RuntimeGraph({ session }: { session: MalwareGraphRuntimeDebugSession }) {
  const nodeWidth = 210; const nodeHeight = 48; const gap = 62; const x = 52; const width = 760;
  const height = 72 + session.steps.length * (nodeHeight + gap);

  return <div className="overflow-auto p-3">
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block rounded border border-gray-800 bg-gray-950">
      <defs>
        <marker id={`arrow-${session.session_id}`} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#64748b" />
        </marker>
      </defs>
      {session.steps.map((step, index) => {
        const y     = 34 + index * (nodeHeight + gap);
        const color = statusColor(step.status);
        const isCur = index === session.current_step;
        return <g key={step.step_id}>
          {index < session.steps.length - 1 && (
            <line x1={x + nodeWidth / 2} y1={y + nodeHeight} x2={x + nodeWidth / 2} y2={y + nodeHeight + gap - 8} stroke="#64748b" markerEnd={`url(#arrow-${session.session_id})`} />
          )}
          <rect x={x} y={y} width={nodeWidth} height={nodeHeight} rx="4" fill="#111827" stroke={isCur ? '#38bdf8' : color} strokeWidth={isCur ? 2.2 : 1.4} />
          <rect x={x} y={y} width="5" height={nodeHeight} rx="2" fill={color} />
          <text x={x + 14} y={y + 19} fill="#e5e7eb" fontSize="11" fontWeight="700">{shortLabel(step.action, 28)}</text>
          <text x={x + 14} y={y + 35} fill="#64748b" fontSize="10">{shortLabel(step.target ?? step.status, 30)}</text>
          <text x={x + nodeWidth + 18} y={y + 20} fill={color} fontSize="11">{step.status}</text>
          <title>{step.action} · {step.status} · {step.notes}</title>
        </g>;
      })}
    </svg>
  </div>;
}

// ── Utilities ──────────────────────────────────────────────────────────────────

function asStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter(item => typeof item === 'string') as string[];
}

function asObjects<T extends Record<string, unknown>>(value: unknown): T[] {
  if (!Array.isArray(value)) return [];
  return value.filter(item => item && typeof item === 'object' && !Array.isArray(item)) as T[];
}
