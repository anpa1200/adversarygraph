import { useEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent, ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import {
  malwareGraphApi,
  type MalwareGraphDebugAssistant,
  type MalwareGraphDecompilation,
  type MalwareGraphDebuggerWorkspace,
  type MalwareGraphFirstAnalysis,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { RUNTIME_DEBUG_DISCLAIMER, readHiddenCases, visibleJobs } from '@/pages/malwareShared';

const input = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 outline-none focus:border-mitre-accent';

type DebugTrace = MalwareGraphDebuggerWorkspace['function_traces'][number];

export function Debugger() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [jobId, setJobId] = useState(params.get('job_id') ?? '');
  const [sampleRef, setSampleRef] = useState(params.get('sample_ref') ?? '');
  const [aiProvider, setAiProvider] = useState(params.get('ai_provider') ?? 'local');
  const [dynamicDebug, setDynamicDebug] = useState(params.get('dynamic') === 'true');
  const [workspace, setWorkspace] = useState<MalwareGraphDebuggerWorkspace | null>(null);
  const [decompilation, setDecompilation] = useState<MalwareGraphDecompilation | null>(null);
  const [aiAssistant, setAiAssistant] = useState<MalwareGraphDebugAssistant | null>(null);
  const [selectedTraceId, setSelectedTraceId] = useState<string>('');

  const jobs = useQuery({ queryKey: ['malwaregraph-jobs'], queryFn: malwareGraphApi.jobs, retry: false });
  const providers = useQuery({ queryKey: ['malwaregraph-providers'], queryFn: malwareGraphApi.providers, retry: false });
  const analysis = useQuery({
    queryKey: ['malwaregraph-analysis', jobId],
    queryFn: () => malwareGraphApi.analysis(jobId),
    enabled: Boolean(jobId),
  });
  const targets = useMemo(() => {
    const firstPass = (analysis.data?.artifacts ?? []).filter(isFirstAnalysis) as unknown as MalwareGraphFirstAnalysis[];
    if (firstPass.length) {
      return firstPass.map(item => ({
        id: item.target_entity_id,
        label: item.target_name,
        detail: `${item.file_type} · entropy ${item.entropy.toFixed(3)}`,
      }));
    }
    return (analysis.data?.entities ?? [])
      .filter(entity => entity.type === 'file' && entity.entity_id !== 'archive--file--0001')
      .map(entity => ({
        id: entity.entity_id,
        label: entity.normalized_value || entity.value,
        detail: String(entity.metadata.file_type ?? entity.source_stage),
      }));
  }, [analysis.data?.artifacts, analysis.data?.entities]);

  useEffect(() => {
    if (jobId && readHiddenCases().has(jobId)) { setJobId(''); setSampleRef(''); }
  }, [jobId]);

  useEffect(() => {
    const visible = visibleJobs(jobs.data ?? []);
    if (!jobId && visible.length) setJobId(visible[0].job_id);
  }, [jobId, jobs.data]);

  useEffect(() => {
    if (!sampleRef && targets.length) setSampleRef(targets[0].id);
  }, [sampleRef, targets]);

  useEffect(() => {
    const next = new URLSearchParams();
    if (jobId) next.set('job_id', jobId);
    if (sampleRef) next.set('sample_ref', sampleRef);
    next.set('ai_provider', aiProvider);
    if (dynamicDebug) next.set('dynamic', 'true');
    setParams(next, { replace: true });
  }, [aiProvider, dynamicDebug, jobId, sampleRef, setParams]);

  useEffect(() => {
    if (workspace?.current_trace_id) setSelectedTraceId(workspace.current_trace_id);
  }, [workspace?.current_trace_id]);

  const createWorkspace = useMutation({
    mutationFn: () => malwareGraphApi.debugWorkspace(jobId, sampleRef, aiProvider, dynamicDebug, dynamicDebug),
    onSuccess: result => {
      setWorkspace(result);
      setAiAssistant(result.ai_assistant ?? null);
      if (isDecompilation(result.decompilation)) setDecompilation(result.decompilation);
    },
  });
  const stepWorkspace = useMutation({
    mutationFn: () => malwareGraphApi.stepDebugWorkspace(workspace!.session_id),
    onSuccess: setWorkspace,
  });
  const loadDecompilation = useMutation({
    mutationFn: () => malwareGraphApi.decompilation(jobId, sampleRef),
    onSuccess: setDecompilation,
  });
  const runAiAssistant = useMutation({
    mutationFn: () => malwareGraphApi.debugWorkspaceAiAssistant(workspace!.session_id, aiProvider),
    onSuccess: result => {
      setAiAssistant(result);
      setWorkspace(current => current ? { ...current, ai_assistant: result } : current);
    },
  });

  const currentTrace = workspace?.function_traces.find(trace => trace.trace_id === workspace.current_trace_id)
    ?? workspace?.function_traces[workspace.current_trace_index]
    ?? workspace?.function_traces[0]
    ?? null;
  const selectedTrace = workspace?.function_traces.find(trace => trace.trace_id === selectedTraceId)
    ?? currentTrace;

  return <div className="flex h-full flex-col">
    <Header title="Decompilation & Debug IDE" />
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mx-auto grid max-w-[1800px] gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="space-y-4">
          <Panel title="Source">
            <div className="space-y-3 p-3">
              <label className="block text-[10px] uppercase text-gray-600">Analysis job</label>
              <select value={jobId} onChange={event => { setJobId(event.target.value); setSampleRef(''); setWorkspace(null); setDecompilation(null); setAiAssistant(null); }} className={input}>
                {visibleJobs(jobs.data ?? []).map(job => <option key={job.job_id} value={job.job_id}>{job.archive_name ?? job.job_id}</option>)}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">Debug target</label>
              <select value={sampleRef} onChange={event => { setSampleRef(event.target.value); setWorkspace(null); setDecompilation(null); setAiAssistant(null); }} className={input}>
                {targets.map(target => <option key={target.id} value={target.id}>{target.label}</option>)}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">AI provider</label>
              <select value={aiProvider} onChange={event => setAiProvider(event.target.value)} className={input}>
                {(providers.data ?? []).map(provider => <option key={provider.provider} value={provider.provider}>{provider.provider} · {provider.configured ? provider.model : provider.env_var}</option>)}
              </select>
              <label className="flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/10 p-2 text-[11px] leading-relaxed text-amber-100">
                <input className="mt-0.5" type="checkbox" checked={dynamicDebug} onChange={event => setDynamicDebug(event.target.checked)} />
                <span>
                  <b className="block text-amber-50">Dynamic debug</b>
                  {RUNTIME_DEBUG_DISCLAIMER}
                </span>
              </label>
              <button className="primary w-full" onClick={() => createWorkspace.mutate()} disabled={!jobId || !sampleRef || createWorkspace.isPending}>{createWorkspace.isPending ? 'Creating...' : 'Create debug workspace'}</button>
              <button className="secondary-action w-full" onClick={() => loadDecompilation.mutate()} disabled={!jobId || !sampleRef || loadDecompilation.isPending}>{loadDecompilation.isPending ? 'Decompiling...' : 'Load decompilation'}</button>
              <button className="secondary-action w-full" onClick={() => stepWorkspace.mutate()} disabled={!workspace || workspace.completed || stepWorkspace.isPending}>{stepWorkspace.isPending ? 'Stepping...' : workspace?.completed ? 'Session complete' : 'Step function'}</button>
              <button className="secondary-action w-full" onClick={() => runAiAssistant.mutate()} disabled={!workspace || runAiAssistant.isPending}>{runAiAssistant.isPending ? 'AI assistant running...' : 'AI debug assistant'}</button>
              <button className="secondary-action w-full" onClick={() => navigate(`/dynamic-analysis?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}${dynamicDebug ? '&dynamic=true' : ''}`)}>Dynamic analysis</button>
              <button className="secondary-action w-full" onClick={() => navigate(`/malware-analysis?job_id=${encodeURIComponent(jobId)}&sample_ref=${encodeURIComponent(sampleRef)}`)}>Back to Malware Analysis</button>
              {(createWorkspace.error || stepWorkspace.error || loadDecompilation.error || runAiAssistant.error) && <p className="text-xs text-red-300">{String(createWorkspace.error ?? stepWorkspace.error ?? loadDecompilation.error ?? runAiAssistant.error)}</p>}
            </div>
          </Panel>
          <Panel title="Controls">
            {workspace ? <div className="divide-y divide-gray-800">
              {workspace.controls.map(control => <div key={String(control.control_id)} className="flex items-center justify-between px-3 py-2 text-xs">
                <span className="text-gray-300">{field(control.label)}</span>
                <span style={{ color: statusColor(field(control.status)) }}>{field(control.status)}</span>
              </div>)}
            </div> : <Empty text="Create a debug workspace." />}
          </Panel>
          <Panel title="Breakpoints">
            {workspace ? <div className="max-h-80 overflow-y-auto divide-y divide-gray-800">
              {workspace.breakpoints.map(item => <div key={field(item.breakpoint_id)} className="p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <b className="font-mono text-gray-200">{field(item.address)}</b>
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{field(item.source)}</span>
                </div>
                <div className="mt-1 truncate text-gray-500">{field(item.name)}</div>
              </div>)}
            </div> : <Empty text="No breakpoints." />}
          </Panel>
        </div>

        <div className="space-y-4">
          {workspace ? <>
            {workspace.warning && <div className="rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm font-semibold text-amber-100">{workspace.warning}</div>}
            <div className="grid gap-3 md:grid-cols-5">
              <Metric label="Target" value={workspace.target_name} />
              <Metric label="Mode" value={workspace.mode} />
              <Metric label="Functions" value={workspace.function_traces.length} />
              <Metric label="API hooks" value={workspace.api_hooks.length} />
              <Metric label="Step" value={`${workspace.step_count}/${Math.max(0, workspace.function_traces.length - 1)}`} />
            </div>
            <Panel title="Decompilation">
              {decompilation ? <DecompilationPane result={decompilation} /> : <Empty text="Load decompilation to view pseudocode, recovered APIs, and interesting strings." />}
            </Panel>
            <Panel title="Entrypoint Finding">
              <EntrypointFinding workspace={workspace} decompilation={decompilation} onTrace={setSelectedTraceId} />
            </Panel>
            <Panel title="AIDebug Function Graph">
              <DebuggerGraph workspace={workspace} selectedTrace={selectedTrace} onTrace={setSelectedTraceId} />
            </Panel>
            <Panel title={`AI Debug Assistant${aiAssistant?.provider ? ` · ${aiAssistant.provider}` : ''}`}>
              <AiAssistantPanel result={aiAssistant} pending={runAiAssistant.isPending} />
            </Panel>
            <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
              <Panel title="Function Traces">
                <TraceList workspace={workspace} selectedTraceId={selectedTrace?.trace_id ?? ''} onTrace={setSelectedTraceId} />
              </Panel>
              <Panel title="Current Function">
                {selectedTrace ? <CurrentFunction trace={selectedTrace} /> : <Empty text="No selected function." />}
              </Panel>
            </div>
            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title="Registers">
                <Registers workspace={workspace} />
              </Panel>
              <Panel title="Memory Regions">
                <MemoryRegions workspace={workspace} />
              </Panel>
              <Panel title="API Hooks">
                <ApiHooks workspace={workspace} />
              </Panel>
              <Panel title="IOC / TTP Leads">
                <Leads workspace={workspace} />
              </Panel>
            </div>
            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title="Debug Events">
                <Events workspace={workspace} />
              </Panel>
              <Panel title="AIDebug JSON Export">
                <pre className="max-h-96 overflow-auto p-3 text-[10px] leading-relaxed text-gray-500">{JSON.stringify(workspace.export, null, 2)}</pre>
              </Panel>
            </div>
          </> : decompilation ? <Panel title="Decompilation">
            <DecompilationPane result={decompilation} />
          </Panel> : <Empty text="Select a MalwareGraph job and target to create a debugger workspace or load decompilation." />}
        </div>
      </div>
    </div>
  </div>;
}

function DebuggerGraph({ workspace, selectedTrace, onTrace }: { workspace: MalwareGraphDebuggerWorkspace; selectedTrace: DebugTrace | null; onTrace: (traceId: string) => void }) {
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const dragRef = useRef({ active: false, x: 0, y: 0, left: 0, top: 0, moved: false });
  const traces = workspace.function_traces;
  const lanes = ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const left = 92;
  const right = 220;
  const top = 86;
  const laneHeight = 86;
  const spacing = 170;
  const nodeWidth = 140;
  const nodeHeight = 46;
  const width = Math.max(1100, left + Math.max(1, traces.length) * spacing + nodeWidth + right);
  const height = top + (lanes.length - 1) * laneHeight + nodeHeight + 70;
  const edgeBySource = new Map(workspace.graph.edges.map(edge => [edge.source, edge]));

  const onPointerDown = (event: PointerEvent<HTMLDivElement>) => {
    const element = scrollerRef.current;
    if (!element) return;
    dragRef.current = {
      active: true,
      x: event.clientX,
      y: event.clientY,
      left: element.scrollLeft,
      top: element.scrollTop,
      moved: false,
    };
    element.setPointerCapture(event.pointerId);
  };
  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    const element = scrollerRef.current;
    const drag = dragRef.current;
    if (!element || !drag.active) return;
    event.preventDefault();
    const dx = event.clientX - drag.x;
    const dy = event.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    element.scrollLeft = drag.left - dx;
    element.scrollTop = drag.top - dy;
  };
  const stopDrag = (event: PointerEvent<HTMLDivElement>) => {
    dragRef.current.active = false;
    event.currentTarget.releasePointerCapture?.(event.pointerId);
  };

  return <div
    ref={scrollerRef}
    className="h-[560px] max-w-full cursor-grab select-none overflow-auto overscroll-contain p-3 active:cursor-grabbing"
    style={{ touchAction: 'none' }}
    onPointerDown={onPointerDown}
    onPointerMove={onPointerMove}
    onPointerUp={stopDrag}
    onPointerCancel={stopDrag}
  >
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} className="block max-w-none rounded border border-gray-800 bg-gray-950">
      <defs>
        <marker id={`debugger-arrow-${workspace.session_id}`} markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth">
          <path d="M 0 0 L 8 4 L 0 8 z" fill="#64748b" />
        </marker>
      </defs>
      {lanes.map((risk, index) => <g key={risk}>
        <line x1={left - 28} y1={top + index * laneHeight + nodeHeight / 2} x2={width - right / 2} y2={top + index * laneHeight + nodeHeight / 2} stroke="#111827" />
        <text x={left - 28} y={top + index * laneHeight - 14} fill={riskColor(risk)} fontSize="11" fontWeight="700">{risk}</text>
      </g>)}
      {traces.map((trace, index) => {
        const x = left + index * spacing;
        const lane = riskLane(trace.risk_level);
        const y = top + lane * laneHeight;
        const active = selectedTrace?.trace_id === trace.trace_id;
        const edge = edgeBySource.get(trace.node_id);
        const nextIndex = edge ? traces.findIndex(item => item.node_id === edge.target) : index + 1;
        const color = trace.is_entrypoint ? '#22c55e' : active ? '#38bdf8' : riskColor(trace.risk_level);
        const nextX = left + nextIndex * spacing;
        const nextY = top + riskLane(traces[nextIndex]?.risk_level ?? 'UNKNOWN') * laneHeight + nodeHeight / 2;
        return <g key={trace.trace_id}>
          {nextIndex > index && nextIndex < traces.length && <path
            d={`M ${x + nodeWidth} ${y + nodeHeight / 2} C ${x + nodeWidth + 42} ${y - 38}, ${nextX - 52} ${nextY - 38}, ${nextX} ${nextY}`}
            fill="none"
            stroke="#475569"
            strokeWidth="1"
            opacity="0.7"
            markerEnd={`url(#debugger-arrow-${workspace.session_id})`}
          />}
          <g data-debug-node="true" role="button" tabIndex={0} className="cursor-pointer" onClick={() => {
            if (dragRef.current.moved) return;
            onTrace(trace.trace_id);
          }} onKeyDown={event => {
            if (event.key === 'Enter' || event.key === ' ') onTrace(trace.trace_id);
          }}>
            <rect x={x} y={y} width={nodeWidth} height={nodeHeight} rx="4" fill="#111827" stroke={color} strokeWidth={active ? 2.4 : 1.3} />
            <rect x={x} y={y} width="5" height={nodeHeight} rx="2" fill={color} />
            <text x={x + 12} y={y + 17} fill="#e5e7eb" fontSize="11" fontWeight="700">{shortLabel(trace.is_entrypoint ? 'entrypoint' : trace.name, 18)}</text>
            <text x={x + 12} y={y + 33} fill="#64748b" fontSize="10">{trace.address}</text>
            <title>{trace.name} · {trace.risk_level} · {trace.summary}</title>
          </g>
        </g>;
      })}
    </svg>
  </div>;
}

function TraceList({ workspace, selectedTraceId, onTrace }: { workspace: MalwareGraphDebuggerWorkspace; selectedTraceId: string; onTrace: (traceId: string) => void }) {
  return <div className="max-h-[520px] overflow-y-auto divide-y divide-gray-800">
    {workspace.function_traces.map(trace => <button key={trace.trace_id} onClick={() => onTrace(trace.trace_id)} className={`block w-full p-3 text-left text-xs ${trace.trace_id === selectedTraceId ? 'bg-mitre-accent/10' : 'hover:bg-gray-900'}`}>
      <div className="flex items-start justify-between gap-2">
        <b className="min-w-0 truncate font-mono text-gray-200">{trace.name}</b>
        <span className="shrink-0" style={{ color: riskColor(trace.risk_level) }}>{trace.risk_level}</span>
      </div>
      <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-gray-600">
        <span>{trace.address}</span>
        <span>{trace.instruction_count} insn</span>
        <span>{trace.status}</span>
      </div>
      <p className="mt-1 line-clamp-2 text-[11px] leading-relaxed text-gray-500">{trace.summary}</p>
    </button>)}
  </div>;
}

function CurrentFunction({ trace }: { trace: DebugTrace }) {
  return <div className="divide-y divide-gray-800 text-xs">
    <div className="grid gap-2 p-3 md:grid-cols-4">
      <Info label="Address" value={trace.address} />
      <Info label="Risk" value={trace.risk_level} />
      <Info label="ATT&CK" value={trace.mitre_technique || 'none'} />
      <Info label="Source" value={`${trace.source}${trace.is_entrypoint ? ' · entrypoint' : ''}`} />
    </div>
    <div className="p-3">
      <b className="text-gray-200">{trace.name}</b>
      <p className="mt-2 leading-relaxed text-gray-400">{trace.summary}</p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {trace.behaviors.map(item => <span key={item} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300">{item}</span>)}
      </div>
    </div>
    {(trace.api_hooks ?? []).length > 0 && <div className="p-3">
      <b className="text-gray-200">Function API hooks</b>
      <div className="mt-2 flex max-h-24 flex-wrap gap-1.5 overflow-y-auto">
        {(trace.api_hooks ?? []).map(value => <span key={value} className="rounded border border-gray-700 px-2 py-1 font-mono text-[10px] text-gray-300">{value}</span>)}
      </div>
    </div>}
    {trace.strings_referenced.length > 0 && <div className="p-3">
      <b className="text-gray-200">Referenced strings</b>
      <div className="mt-2 max-h-28 overflow-y-auto rounded border border-gray-800 bg-gray-950">
        {trace.strings_referenced.map((value, index) => <div key={`${value}-${index}`} className="break-all border-b border-gray-900 px-2 py-1 font-mono text-[10px] text-gray-500">{value}</div>)}
      </div>
    </div>}
    <div className="p-3">
      <b className="text-gray-200">Disassembly</b>
      <pre className="mt-2 max-h-[360px] overflow-auto rounded border border-gray-800 bg-gray-950 p-3 font-mono text-[10px] leading-relaxed text-gray-400">{trace.disassembly.map(row => field(row.text)).join('\n') || 'No disassembly recovered.'}</pre>
    </div>
  </div>;
}

function EntrypointFinding({ workspace, decompilation, onTrace }: { workspace: MalwareGraphDebuggerWorkspace; decompilation: MalwareGraphDecompilation | null; onTrace: (traceId: string) => void }) {
  const entryTrace = workspace.function_traces.find(trace => trace.is_entrypoint || trace.name === 'entrypoint');
  const entry = workspace.entrypoint ?? decompilation?.entrypoint_details ?? {};
  return <div className="grid gap-3 p-3 text-xs md:grid-cols-[1fr_auto]">
    <div className="grid gap-2 md:grid-cols-4">
      <Info label="Status" value={field(entry.status ?? (entryTrace ? 'found' : 'missing'))} />
      <Info label="RVA" value={field(entry.rva ?? decompilation?.entrypoint ?? entryTrace?.rva)} />
      <Info label="VA" value={field(entry.va ?? entryTrace?.address)} />
      <Info label="Section" value={field(entry.section ?? entryTrace?.section)} />
    </div>
    <div className="flex items-center">
      <button className="secondary-action min-w-32" disabled={!entryTrace} onClick={() => entryTrace && onTrace(entryTrace.trace_id)}>Select entrypoint</button>
    </div>
    <div className="md:col-span-2 text-[11px] leading-relaxed text-gray-500">
      {entryTrace ? `${entryTrace.summary} Source: ${entryTrace.source}. File offset: ${field(entry.file_offset) || 'unknown'}.` : 'No entrypoint trace was recovered for this target.'}
    </div>
  </div>;
}

function AiAssistantPanel({ result, pending }: { result: MalwareGraphDebugAssistant | null; pending: boolean }) {
  if (pending) return <Empty text="AI assistant is analyzing the debug workspace." />;
  if (!result) return <Empty text="Run AI debug assistant to prioritize entrypoint validation, suspicious functions, hooks, IOC/TTP leads, and next steps." />;
  const assessment = result.assessment ?? {};
  return <div className="grid gap-4 p-3 text-xs xl:grid-cols-[1fr_1fr]">
    <div className="space-y-3">
      <div>
        <b className="text-gray-200">Main Purpose</b>
        <p className="mt-1 leading-relaxed text-gray-400">{field(assessment.main_purpose) || 'Main purpose was not returned.'}</p>
      </div>
      <div>
        <b className="text-gray-200">Summary</b>
        <p className="mt-1 leading-relaxed text-gray-400">{field(assessment.summary) || 'No summary returned.'}</p>
      </div>
      <div>
        <b className="text-gray-200">Entrypoint</b>
        <p className="mt-1 leading-relaxed text-gray-400">{field(assessment.entrypoint_assessment) || 'No entrypoint assessment returned.'}</p>
      </div>
      <ObjectList title="Function Analysis" items={assessment.function_analysis ?? []} limit={80} />
      <ListBlock title="Next Steps" items={assessment.debug_next_steps ?? []} />
      <ListBlock title="Validation Gaps" items={assessment.validation_gaps ?? []} />
    </div>
    <div className="space-y-3">
      <ObjectList title="Malicious / Suspicious Functions" items={assessment.malicious_or_suspicious_functions ?? assessment.suspicious_functions ?? []} />
      <ObjectList title="TTPs" items={assessment.ttps ?? []} />
      <ObjectList title="IOCs" items={assessment.iocs ?? []} />
      <ListBlock title="API Hooks To Prioritize" items={assessment.api_hooks_to_prioritize ?? []} mono />
      <ObjectList title="IOC / TTP Leads" items={assessment.ioc_or_ttp_leads ?? []} />
      {result.error && <div className="rounded border border-amber-500/30 bg-amber-950/20 p-2 text-amber-100">{result.error}</div>}
    </div>
  </div>;
}

function ListBlock({ title, items, mono = false }: { title: string; items: unknown[]; mono?: boolean }) {
  return <div>
    <b className="text-gray-200">{title}</b>
    <div className={`mt-2 max-h-40 overflow-y-auto rounded border border-gray-800 bg-gray-950 ${mono ? 'font-mono' : ''}`}>
      {items.length ? items.slice(0, 40).map((item, index) => <div key={`${field(item)}-${index}`} className="border-b border-gray-900 px-2 py-1.5 text-[11px] leading-relaxed text-gray-400">{field(item)}</div>) : <div className="p-2 text-gray-600">none</div>}
    </div>
  </div>;
}

function ObjectList({ title, items, limit = 40 }: { title: string; items: Array<Record<string, unknown>>; limit?: number }) {
  return <div>
    <b className="text-gray-200">{title}</b>
    <div className="mt-2 max-h-56 overflow-y-auto rounded border border-gray-800 bg-gray-950">
      {items.length ? items.slice(0, limit).map((item, index) => <div key={index} className="border-b border-gray-900 p-2 text-[11px] leading-relaxed text-gray-400">
        <ObjectHeader item={item} />
        <div className="mt-1 space-y-1 text-gray-500">
          {objectDetailRows(item).map(row => <div key={row.key}>
            <span className="text-gray-600">{row.key}: </span>
            <span className={row.mono ? 'break-all font-mono text-gray-400' : 'text-gray-500'}>{row.value}</span>
          </div>)}
        </div>
      </div>) : <div className="p-2 text-gray-600">none</div>}
    </div>
  </div>;
}

function ObjectHeader({ item }: { item: Record<string, unknown> }) {
  const title = field(item.name ?? item.attack_id ?? item.value ?? item.address ?? item.type) || 'item';
  const href = objectRoute(item);
  const meta = [field(item.address), field(item.risk), field(item.confidence)].filter(Boolean).join(' · ');
  const className = "break-all font-mono text-gray-200 hover:text-mitre-accent";
  return <div>
    {href ? <a className={className} href={href}>{title}</a> : <div className="break-all font-mono text-gray-200">{title}</div>}
    {meta && <div className="mt-0.5 text-[10px] uppercase text-gray-600">{meta}</div>}
  </div>;
}

function objectRoute(item: Record<string, unknown>) {
  const attackId = field(item.attack_id ?? (field(item.type) === 'ttp' ? item.value : ''));
  if (/^T\d{4}(?:\.\d{3})?$/.test(attackId)) return `/navigator?technique=${encodeURIComponent(attackId)}`;
  if (field(item.type) === 'ioc' || item.value) return `/ioc-library?search=${encodeURIComponent(field(item.value ?? item.name))}`;
  return '';
}

function objectDetailRows(item: Record<string, unknown>) {
  const keys = [
    'role',
    'description',
    'reason',
    'evidence',
    'ttps',
    'iocs',
    'next_debug_action',
    'type',
    'value',
  ];
  return keys
    .filter(key => item[key] !== undefined && item[key] !== null && field(item[key]) !== '')
    .map(key => ({
      key: key.replace(/_/g, ' '),
      value: field(item[key]),
      mono: ['value', 'iocs', 'ttps'].includes(key),
    }));
}

function Registers({ workspace }: { workspace: MalwareGraphDebuggerWorkspace }) {
  return <div className="max-h-80 overflow-auto">
    <table className="w-full min-w-[420px] text-left text-xs">
      <thead className="bg-gray-950 text-[10px] uppercase text-gray-600"><tr><th className="px-3 py-2">Register</th><th className="px-3 py-2">Entry</th><th className="px-3 py-2">Exit</th></tr></thead>
      <tbody className="divide-y divide-gray-800">
        {workspace.registers.map(row => <tr key={row.name}>
          <td className="px-3 py-2 font-mono text-gray-200">{row.name}</td>
          <td className="px-3 py-2 font-mono text-gray-500">{row.entry}</td>
          <td className={row.changed ? 'px-3 py-2 font-mono text-mitre-accent' : 'px-3 py-2 font-mono text-gray-500'}>{row.exit}</td>
        </tr>)}
      </tbody>
    </table>
  </div>;
}

function MemoryRegions({ workspace }: { workspace: MalwareGraphDebuggerWorkspace }) {
  return <div className="max-h-80 overflow-y-auto divide-y divide-gray-800">
    {workspace.memory_regions.map((region, index) => <div key={`${field(region.name)}-${index}`} className="grid gap-2 p-3 text-xs md:grid-cols-4">
      <Info label="Name" value={field(region.name)} />
      <Info label="Address" value={field(region.address)} />
      <Info label="Size" value={field(region.size_bytes)} />
      <Info label="Perm" value={field(region.permissions)} />
    </div>)}
  </div>;
}

function ApiHooks({ workspace }: { workspace: MalwareGraphDebuggerWorkspace }) {
  return <div className="max-h-80 overflow-y-auto divide-y divide-gray-800">
    {workspace.api_hooks.map((hook, index) => <div key={`${field(hook.name)}-${index}`} className="p-3 text-xs">
      <div className="flex items-center justify-between gap-2">
        <b className="font-mono text-gray-200">{field(hook.name)}</b>
        <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{field(hook.category)}</span>
      </div>
      <div className="mt-1 text-gray-500">{field(hook.module)} · {field(hook.status)}</div>
    </div>)}
    {!workspace.api_hooks.length && <Empty text="No API hooks planned." />}
  </div>;
}

function Leads({ workspace }: { workspace: MalwareGraphDebuggerWorkspace }) {
  return <div className="grid gap-4 p-3 text-xs md:grid-cols-2">
    <div>
      <b className="text-gray-200">TTP leads</b>
      <div className="mt-2 space-y-2">
        {workspace.attack_leads.map((lead, index) => <a key={`${field(lead.attack_id)}-${index}`} href={field(lead.navigator_route)} className="block rounded border border-gray-800 p-2 hover:border-mitre-accent">
          <div className="font-mono text-mitre-accent">{field(lead.attack_id)}</div>
          <div className="text-gray-400">{field(lead.name)}</div>
        </a>)}
        {!workspace.attack_leads.length && <div className="text-gray-600">none</div>}
      </div>
    </div>
    <div>
      <b className="text-gray-200">IOC leads</b>
      <div className="mt-2 max-h-56 overflow-y-auto space-y-2">
        {workspace.ioc_leads.map((lead, index) => <a key={`${field(lead.value)}-${index}`} href={field(lead.adversarygraph_route) || `/ioc-library?search=${encodeURIComponent(field(lead.value))}`} className="block rounded border border-gray-800 p-2 hover:border-mitre-accent">
          <div className="break-all font-mono text-gray-200">{field(lead.value)}</div>
          <div className="text-gray-500">{field(lead.type)}</div>
        </a>)}
        {!workspace.ioc_leads.length && <div className="text-gray-600">none</div>}
      </div>
    </div>
  </div>;
}

function Events({ workspace }: { workspace: MalwareGraphDebuggerWorkspace }) {
  return <div className="max-h-96 overflow-y-auto divide-y divide-gray-800">
    {workspace.events.slice().reverse().map((event, index) => <div key={`${field(event.timestamp)}-${index}`} className="p-3 text-xs">
      <div className="flex items-center justify-between gap-2">
        <b className="text-gray-200">{field(event.type)}</b>
        <span style={{ color: statusColor(field(event.status)) }}>{field(event.status)}</span>
      </div>
      <p className="mt-1 text-gray-500">{field(event.message)}</p>
    </div>)}
  </div>;
}

function DecompilationPane({ result }: { result: MalwareGraphDecompilation }) {
  return <div className="grid gap-4 p-3 xl:grid-cols-[1fr_360px]">
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[10px] uppercase text-gray-500">
        <span>{result.toolchain}</span>
        <span>{result.mode}</span>
        <span>{result.executed ? 'executed' : 'static'}</span>
      </div>
      <pre className="max-h-[420px] overflow-auto rounded border border-gray-800 bg-gray-950 p-3 font-mono text-[11px] leading-relaxed text-gray-300">{result.pseudocode.join('\n') || 'No pseudocode recovered.'}</pre>
    </div>
    <div className="space-y-3">
      {result.warnings.length > 0 && <div className="rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-100">{result.warnings.join(' ')}</div>}
      <div className="rounded border border-gray-800 bg-gray-950 p-3">
        <b className="text-xs text-gray-200">Recovered APIs</b>
        <div className="mt-2 flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
          {result.api_calls.slice(0, 100).map(value => <span key={value} className="rounded border border-gray-700 px-2 py-1 font-mono text-[10px] text-gray-300">{value}</span>)}
          {!result.api_calls.length && <span className="text-xs text-gray-600">none</span>}
        </div>
      </div>
      <div className="rounded border border-gray-800 bg-gray-950 p-3">
        <b className="text-xs text-gray-200">Interesting strings</b>
        <div className="mt-2 max-h-48 overflow-y-auto divide-y divide-gray-900 font-mono text-[10px] text-gray-500">
          {result.interesting_strings.slice(0, 80).map((value, index) => <div key={`${value}-${index}`} className="break-all py-1">{value}</div>)}
          {!result.interesting_strings.length && <div className="text-xs text-gray-600">none</div>}
        </div>
      </div>
    </div>
  </div>;
}

function isFirstAnalysis(artifact: unknown): artifact is MalwareGraphFirstAnalysis {
  if (!artifact || typeof artifact !== 'object') return false;
  const item = artifact as Record<string, unknown>;
  return item.type === 'first-analysis'
    && typeof item.target_entity_id === 'string'
    && typeof item.target_name === 'string'
    && typeof item.entropy === 'number';
}

function isDecompilation(value: unknown): value is MalwareGraphDecompilation {
  if (!value || typeof value !== 'object') return false;
  const item = value as Record<string, unknown>;
  return item.type === 'decompilation'
    && typeof item.target_entity_id === 'string'
    && Array.isArray(item.pseudocode)
    && Array.isArray(item.api_calls);
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="overflow-hidden rounded border border-gray-800 bg-gray-900/40">
    <div className="border-b border-gray-800 px-3 py-2 text-sm font-semibold text-white">{title}</div>
    {children}
  </section>;
}

function Metric({ label, value }: { label: string; value: number | string }) {
  return <div className="rounded border border-gray-800 bg-gray-900/60 p-3"><div className="truncate text-2xl font-semibold text-white">{value}</div><div className="text-xs text-gray-500">{label}</div></div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="rounded bg-gray-900 p-2">
    <div className="text-[10px] uppercase text-gray-600">{label}</div>
    <div className="mt-1 break-all font-mono text-[11px] text-gray-300">{value}</div>
  </div>;
}

function Empty({ text }: { text: string }) {
  return <div className="p-4 text-center text-xs text-gray-600">{text}</div>;
}

function field(value: unknown): string {
  if (value === null || value === undefined || value === '') return '';
  if (typeof value === 'number') return Number.isInteger(value) ? value.toLocaleString() : value.toFixed(3);
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (Array.isArray(value)) return value.map(item => field(item)).join(', ');
  return String(value);
}

function riskColor(risk: string) {
  if (risk === 'CRITICAL') return '#f87171';
  if (risk === 'HIGH') return '#ef4444';
  if (risk === 'MEDIUM') return '#f59e0b';
  if (risk === 'LOW') return '#22c55e';
  return '#64748b';
}

function riskLane(risk: string) {
  if (risk === 'HIGH' || risk === 'CRITICAL') return 0;
  if (risk === 'MEDIUM') return 1;
  if (risk === 'LOW') return 2;
  return 3;
}

function statusColor(status: string) {
  if (status === 'completed') return '#22c55e';
  if (status === 'blocked') return '#ef4444';
  if (status === 'requires-dynamic-checkbox') return '#f59e0b';
  if (status === 'ready' || status === 'selected') return '#38bdf8';
  if (status === 'planned') return '#a78bfa';
  return '#f59e0b';
}

function shortLabel(value: string, limit: number) {
  return value.length <= limit ? value : `${value.slice(0, Math.max(0, limit - 3))}...`;
}
