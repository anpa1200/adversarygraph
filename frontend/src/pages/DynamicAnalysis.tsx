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
  const [jobId, setJobId] = useState(params.get('job_id') ?? '');
  const [sampleRef, setSampleRef] = useState(params.get('sample_ref') ?? '');
  const [disclaimerAccepted, setDisclaimerAccepted] = useState(params.get('dynamic') === 'true');
  const [session, setSession] = useState<MalwareGraphRuntimeDebugSession | null>(null);

  const jobs = useQuery({ queryKey: ['malwaregraph-jobs'], queryFn: malwareGraphApi.jobs, retry: false });
  const analysis = useQuery({
    queryKey: ['malwaregraph-analysis', jobId],
    queryFn: () => malwareGraphApi.analysis(jobId),
    enabled: Boolean(jobId),
  });

  const currentJob = useMemo(() => jobs.data?.find(job => job.job_id === jobId), [jobId, jobs.data]);
  const targets = useMemo(() => analysisTargets(analysis.data), [analysis.data]);

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
    if (jobId) next.set('job_id', jobId);
    if (sampleRef) next.set('sample_ref', sampleRef);
    if (disclaimerAccepted) next.set('dynamic', 'true');
    setParams(next, { replace: true });
  }, [disclaimerAccepted, jobId, sampleRef, setParams]);

  const createSession = useMutation({
    mutationFn: () => malwareGraphApi.runtimeDebugSession(jobId, sampleRef, disclaimerAccepted, disclaimerAccepted),
    onSuccess: setSession,
  });

  const stepSession = useMutation({
    mutationFn: () => malwareGraphApi.stepRuntimeDebugSession(session!.session_id),
    onSuccess: setSession,
  });

  return <div className="flex h-full flex-col">
    <Header title="Dynamic Analysis" />
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mx-auto grid max-w-7xl gap-4 xl:grid-cols-[360px_1fr]">
        <aside className="space-y-4">
          <Panel title="Runtime Target">
            <div className="space-y-3 p-3">
              <label className="block text-[10px] uppercase text-gray-600">Analysis case</label>
              <select value={jobId} onChange={event => { setJobId(event.target.value); setSampleRef(''); setSession(null); }} className={malwareInput}>
                {visibleJobs(jobs.data ?? []).map(job => <option key={job.job_id} value={job.job_id}>{caseTitle(job, undefined)} - {job.case_id ?? job.job_id}</option>)}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">Runtime target</label>
              <select value={sampleRef} onChange={event => { setSampleRef(event.target.value); setSession(null); }} className={malwareInput}>
                {targets.map(target => <option key={target.id} value={target.id}>{target.label}</option>)}
              </select>
              <label className="flex items-start gap-3 rounded border border-amber-500/30 bg-amber-950/20 px-3 py-2 text-xs text-amber-100">
                <input className="mt-0.5" type="checkbox" checked={disclaimerAccepted} onChange={event => setDisclaimerAccepted(event.target.checked)} />
                <span>{RUNTIME_DEBUG_DISCLAIMER}</span>
              </label>
              <button className="primary w-full" onClick={() => createSession.mutate()} disabled={!jobId || !sampleRef || !disclaimerAccepted || createSession.isPending}>
                {createSession.isPending ? 'Preparing runtime...' : 'Prepare isolated runtime session'}
              </button>
              <button className="secondary-action w-full" onClick={() => stepSession.mutate()} disabled={!session || session.completed || stepSession.isPending}>
                {stepSession.isPending ? 'Stepping...' : session?.completed ? 'Session complete' : 'Step runtime'}
              </button>
              <button className="secondary-action w-full" onClick={() => navigate(`/malware-analysis?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}`)}>Back to case</button>
              {(createSession.error || stepSession.error) && <p className="text-xs text-red-300">{String(createSession.error ?? stepSession.error)}</p>}
            </div>
          </Panel>

          <Panel title="Case Context">
            {analysis.data ? <div className="grid gap-2 p-3 text-xs">
              <Info label="Case" value={caseTitle(currentJob, analysis.data)} />
              <Info label="Case ID" value={caseIdentifier(currentJob, analysis.data)} />
              <Info label="Job" value={analysis.data.job_id} />
              <Info label="Target" value={targets.find(target => target.id === sampleRef)?.label ?? sampleRef} />
            </div> : <Empty text="Select a case." />}
          </Panel>
        </aside>

        <main className="space-y-4">
          <div className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm font-semibold text-amber-100">
            Dynamic analysis is an isolated workflow. Check the dynamic box to prepare the runtime profile for this request.
          </div>
          {session ? <DynamicSession session={session} onOpenDebugger={() => navigate(`/malware-debug?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}${session.dynamic_enabled ? '&dynamic=true' : ''}`)} /> : <Empty text="Accept the disclaimer and prepare an isolated runtime session to see dynamic analysis state." />}
        </main>
      </div>
    </div>
  </div>;
}

function DynamicSession({ session, onOpenDebugger }: { session: MalwareGraphRuntimeDebugSession; onOpenDebugger: () => void }) {
  const current = session.steps[session.current_step] ?? session.steps[0] ?? null;
  return <>
    <div className="grid gap-3 md:grid-cols-5">
      <Metric label="Mode" value={session.mode} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Dynamic enabled" value={session.dynamic_enabled ? 'yes' : 'no'} tone={session.dynamic_enabled ? 'good' : 'warn'} />
      <Metric label="Current step" value={current?.action ?? 'none'} />
      <Metric label="Completed" value={session.completed ? 'yes' : 'no'} tone={session.completed ? 'good' : 'default'} />
      <Metric label="API link" value={field(session.isolation.adversarygraph_connection ?? 'api-only')} />
    </div>
    {session.warning && <div className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-100">{session.warning}</div>}
    <Panel title="Runtime Workflow Graph" actions={<button className="secondary-action" onClick={onOpenDebugger}>Open IDE debug</button>}>
      <RuntimeGraph session={session} />
    </Panel>
    <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
      <Panel title="Runtime Steps">
        <div className="max-h-[540px] overflow-y-auto divide-y divide-gray-800">
          {session.steps.map((step, index) => <div key={step.step_id} className={index === session.current_step ? 'bg-mitre-accent/10 p-3 text-xs' : 'p-3 text-xs'}>
            <div className="flex items-center justify-between gap-2">
              <b className="text-gray-200">{step.action}</b>
              <span style={{ color: statusColor(step.status) }}>{step.status}</span>
            </div>
            <p className="mt-1 text-gray-500">{step.notes}</p>
            {Object.keys(step.snapshot ?? {}).length > 0 && <pre className="mt-2 max-h-40 overflow-auto rounded border border-gray-800 bg-gray-950 p-2 text-[10px] text-gray-500">{JSON.stringify(step.snapshot, null, 2)}</pre>}
          </div>)}
        </div>
      </Panel>
      <Panel title="Isolation">
        <div className="grid gap-2 p-3 text-xs">
          {Object.entries(session.isolation).map(([key, value]) => <Info key={key} label={key.replace(/_/g, ' ')} value={field(value)} />)}
        </div>
      </Panel>
    </div>
  </>;
}

function RuntimeGraph({ session }: { session: MalwareGraphRuntimeDebugSession }) {
  const width = 760;
  const nodeWidth = 210;
  const nodeHeight = 48;
  const gap = 62;
  const height = 72 + session.steps.length * (nodeHeight + gap);
  const x = 52;
  return <div className="max-h-[520px] overflow-auto p-3">
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block rounded border border-gray-800 bg-gray-950">
      <defs>
        <marker id={`dynamic-arrow-${session.session_id}`} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#64748b" />
        </marker>
      </defs>
      {session.steps.map((step, index) => {
        const y = 34 + index * (nodeHeight + gap);
        const color = statusColor(step.status);
        return <g key={step.step_id}>
          {index < session.steps.length - 1 && <line x1={x + nodeWidth / 2} y1={y + nodeHeight} x2={x + nodeWidth / 2} y2={y + nodeHeight + gap - 8} stroke="#64748b" markerEnd={`url(#dynamic-arrow-${session.session_id})`} />}
          <rect x={x} y={y} width={nodeWidth} height={nodeHeight} rx="4" fill="#111827" stroke={index === session.current_step ? '#38bdf8' : color} strokeWidth={index === session.current_step ? 2.2 : 1.4} />
          <rect x={x} y={y} width="5" height={nodeHeight} rx="2" fill={color} />
          <text x={x + 14} y={y + 19} fill="#e5e7eb" fontSize="11" fontWeight="700">{shortLabel(step.action, 28)}</text>
          <text x={x + 14} y={y + 35} fill="#64748b" fontSize="10">{shortLabel(step.target ?? step.status, 30)}</text>
          <text x={x + nodeWidth + 18} y={y + 20} fill={color} fontSize="11">{step.status}</text>
          <title>{step.action} - {step.status} - {step.notes}</title>
        </g>;
      })}
    </svg>
  </div>;
}
