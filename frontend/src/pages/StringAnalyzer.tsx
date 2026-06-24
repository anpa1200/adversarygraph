import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  malwareGraphApi,
  type MalwareGraphFirstAnalysis,
  type MalwareGraphStringsAnalysis,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { readHiddenCases, visibleJobs } from '@/pages/malwareShared';

const input = 'w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200 outline-none focus:border-mitre-accent';

export function StringAnalyzer() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [jobId, setJobId] = useState(params.get('job_id') ?? '');
  const [sampleRef, setSampleRef] = useState(params.get('sample_ref') ?? '');
  const [mode, setMode] = useState<'all' | 'smart' | 'ai'>((params.get('mode') as 'all' | 'smart' | 'ai' | null) ?? ((params.get('ai') ?? 'true') !== 'false' ? 'ai' : 'smart'));
  const [minChars, setMinChars] = useState(Number(params.get('min_chars') ?? 4));
  const [maxChars, setMaxChars] = useState(params.get('max_chars') ? Number(params.get('max_chars')) : 4096);
  const [aiProvider, setAiProvider] = useState(params.get('ai_provider') ?? 'local');

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
    next.set('mode', mode);
    next.set('ai', String(mode === 'ai'));
    next.set('ai_provider', aiProvider);
    next.set('min_chars', String(minChars));
    if (maxChars) next.set('max_chars', String(maxChars));
    setParams(next, { replace: true });
  }, [aiProvider, jobId, maxChars, minChars, mode, sampleRef, setParams]);

  const strings = useQuery({
    queryKey: ['malwaregraph-string-analyzer', jobId, sampleRef, mode, aiProvider, minChars, maxChars],
    queryFn: () => malwareGraphApi.strings(jobId, sampleRef, mode === 'ai', aiProvider, { min_chars: minChars, max_chars: maxChars || null }),
    enabled: Boolean(jobId && sampleRef),
    retry: false,
  });
  const result = strings.data;

  return <div className="flex h-full flex-col">
    <Header title="String Analyzer" />
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mx-auto grid max-w-7xl gap-4 xl:grid-cols-[360px_1fr]">
        <div className="space-y-4">
          <Panel title="Source">
            <div className="space-y-3 p-3">
              <label className="block text-[10px] uppercase text-gray-600">Analysis job</label>
              <select value={jobId} onChange={event => { setJobId(event.target.value); setSampleRef(''); }} className={input}>
                {visibleJobs(jobs.data ?? []).map(job => <option key={job.job_id} value={job.job_id}>{job.archive_name ?? job.job_id}</option>)}
              </select>
              <label className="block text-[10px] uppercase text-gray-600">Extracted target</label>
              <select value={sampleRef} onChange={event => setSampleRef(event.target.value)} className={input}>
                {targets.map(target => <option key={target.id} value={target.id}>{target.label}</option>)}
              </select>
              <div className="grid grid-cols-3 gap-1 text-xs">
                <ModeButton active={mode === 'all'} label="All strings" onClick={() => setMode('all')} />
                <ModeButton active={mode === 'smart'} label="Smart" onClick={() => setMode('smart')} />
                <ModeButton active={mode === 'ai'} label="AI analysis" onClick={() => setMode('ai')} />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <label className="text-[10px] uppercase text-gray-600">Min chars<input type="number" min={1} max={4096} value={minChars} onChange={event => setMinChars(Number(event.target.value || 1))} className={`${input} mt-1`} /></label>
                <label className="text-[10px] uppercase text-gray-600">Max chars<input type="number" min={minChars} max={32768} value={maxChars} onChange={event => setMaxChars(Number(event.target.value || 0))} className={`${input} mt-1`} /></label>
              </div>
              {mode === 'ai' && <select value={aiProvider} onChange={event => setAiProvider(event.target.value)} className={input}>
                {(providers.data ?? []).map(provider => <option key={provider.provider} value={provider.provider}>{provider.provider} · {provider.configured ? provider.model : provider.env_var}</option>)}
              </select>}
              <button className="primary w-full" onClick={() => strings.refetch()} disabled={!jobId || !sampleRef || strings.isFetching}>{strings.isFetching ? 'Analyzing...' : 'Analyze strings'}</button>
              {jobId && <button className="secondary-action w-full" onClick={() => navigate(`/malware-analysis`)}>Back to Malware Analysis</button>}
              {strings.error && <p className="text-xs text-red-300">{String(strings.error)}</p>}
            </div>
          </Panel>
          <Panel title="Category Counts">
            {result ? <div className="divide-y divide-gray-800">
              {Object.entries(result.categories).map(([category, values]) => <div key={category} className="flex items-center justify-between px-3 py-2 text-xs">
                <span className="text-gray-300">{category}</span>
                <span className="text-mitre-accent">{values.length}</span>
              </div>)}
            </div> : <Empty text="Run string analysis to see category counts." />}
          </Panel>
        </div>

        <div className="space-y-4">
          {result ? <StringResults result={result} mode={mode} /> : <Empty text="Select a MalwareGraph job and target to run full entropy-aware string analysis." />}
        </div>
      </div>
    </div>
  </div>;
}

function StringResults({ result, mode }: { result: MalwareGraphStringsAnalysis; mode: 'all' | 'smart' | 'ai' }) {
  return <>
    <div className="grid gap-3 md:grid-cols-4">
      <Metric label="Target" value={result.target_name} />
      <Metric label="Strings" value={result.strings_total} />
      <Metric label="Entropy" value={result.entropy.toFixed(3)} />
      <Metric label="Obfuscated" value={result.obfuscated ? 'yes' : 'no'} />
    </div>
    {mode === 'ai' && <Panel title={`AI String Analysis${result.ai_provider ? ` · ${result.ai_provider}` : ''}`}>
      <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2 text-[10px] uppercase text-gray-500">
        <span>Status</span>
        <span className={result.ai_status === 'llm-complete' ? 'text-green-300' : result.ai_status === 'llm-fallback' ? 'text-amber-300' : 'text-gray-400'}>{result.ai_status}</span>
      </div>
      <pre className="max-h-[680px] overflow-y-auto whitespace-pre-wrap break-words p-3 text-sm leading-relaxed text-gray-300">{result.ai_analysis || 'AI analysis was not returned for this request.'}</pre>
    </Panel>}
    <CategorySections result={result} />
    {mode === 'all' && <Panel title={`All Extracted Strings (${result.strings.length})`}>
      <div className="max-h-[620px] overflow-y-auto divide-y divide-gray-900 p-3 font-mono text-[10px]">
        {result.strings.map(value => {
          const route = stringIocRoute(value);
          return route ? <a key={value} href={route} className="block break-all py-1 text-mitre-accent hover:underline">{value}</a> : <div key={value} className="break-all py-1 text-gray-500">{value}</div>;
        })}
      </div>
    </Panel>}
    {mode !== 'all' && <div className="grid gap-4 xl:grid-cols-2">
      <Panel title={`IOC Leads (${result.ioc_leads.length})`}>
        <div className="max-h-[520px] overflow-y-auto divide-y divide-gray-800">
          {result.ioc_leads.map(lead => <a key={`${lead.type}:${lead.value}`} href={lead.adversarygraph_route ?? `/ioc-library?search=${encodeURIComponent(lead.value)}`} className="block p-3 hover:bg-gray-900">
            <div className="flex items-center justify-between gap-2">
              <b className="break-all font-mono text-xs text-gray-200">{lead.value}</b>
              <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{lead.type}</span>
            </div>
            <small className="text-[10px] text-gray-600">{lead.category} · confidence {Math.round(lead.confidence * 100)}%</small>
          </a>)}
          {!result.ioc_leads.length && <Empty text="No IOC leads were extracted from strings." />}
        </div>
      </Panel>
      <Panel title={`TTP Leads (${result.ttp_leads.length})`}>
        <div className="max-h-[520px] overflow-y-auto divide-y divide-gray-800">
          {result.ttp_leads.map(lead => <a key={lead.attack_id} href={lead.navigator_route} className="block p-3 hover:bg-gray-900">
            <div className="flex items-center justify-between gap-2">
              <b className="text-xs text-gray-200">{lead.attack_id} {lead.name}</b>
              <span className="text-[10px] text-mitre-accent">{Math.round(lead.confidence * 100)}%</span>
            </div>
            <p className="mt-1 text-[11px] leading-relaxed text-gray-500">{lead.evidence}</p>
          </a>)}
          {!result.ttp_leads.length && <Empty text="Enable AI IOC/TTP extraction to produce ATT&CK leads." />}
        </div>
      </Panel>
    </div>}
    {mode !== 'all' && <Panel title={`Smart Findings (${result.findings.length})`}>
      <div className="grid gap-2 p-3 md:grid-cols-2">
        {result.findings.slice(0, 120).map((finding, index) => finding.adversarygraph_route ? (
          <a key={`${finding.category}-${index}`} href={finding.adversarygraph_route} className="rounded border border-gray-800 bg-gray-950 p-2 hover:border-mitre-accent">
            <Finding finding={finding} />
          </a>
        ) : <div key={`${finding.category}-${index}`} className="rounded border border-gray-800 bg-gray-950 p-2"><Finding finding={finding} /></div>)}
      </div>
    </Panel>}
    {mode !== 'all' && <Panel title="Extracted Strings">
      <div className="max-h-80 overflow-y-auto p-3 font-mono text-[10px] text-gray-500">
        {result.strings_preview.map(value => {
          const route = stringIocRoute(value);
          return route ? <a key={value} href={route} className="block break-all border-b border-gray-900 py-1 text-mitre-accent hover:underline">{value}</a> : <div key={value} className="break-all border-b border-gray-900 py-1">{value}</div>;
        })}
      </div>
    </Panel>}
  </>;
}

const CATEGORY_ORDER = [
  ['URLS', 'URLs'],
  ['DOMAINS', 'Domains'],
  ['IPS', 'IP addresses'],
  ['EMAILS', 'Emails'],
  ['CMD_COMMANDS', 'Command shell'],
  ['POWERSHELL_COMMANDS', 'PowerShell'],
  ['WINDOWS_REGISTRY_KEYS', 'Registry keys'],
  ['WINDOWS_API_COMMANDS', 'WinAPI / functions'],
  ['ANDROID_APIS', 'Android APIs'],
  ['ANDROID_PERMISSIONS', 'Android permissions'],
  ['FILES', 'Files'],
  ['DLLS', 'DLLs'],
  ['DECODED_BASE64', 'Decoded Base64'],
  ['DECODED_HEX', 'Decoded hex'],
  ['SUSPICIOUS_KEYWORDS', 'Suspicious keywords'],
] as const;

function CategorySections({ result }: { result: MalwareGraphStringsAnalysis }) {
  const populated = CATEGORY_ORDER
    .map(([key, label]) => ({ key, label, values: result.categories[key] ?? [] }))
    .filter(item => item.values.length > 0);
  return <Panel title="Sorted String Categories">
    <div className="grid gap-3 p-3 xl:grid-cols-2">
      {populated.map(item => <section key={item.key} className="overflow-hidden rounded border border-gray-800 bg-gray-950">
        <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2">
          <b className="text-xs text-gray-200">{item.label}</b>
          <span className="text-[10px] text-mitre-accent">{item.values.length}</span>
        </div>
        <div className="max-h-56 overflow-y-auto divide-y divide-gray-900 font-mono text-[10px]">
          {item.values.slice(0, 120).map(value => {
            const route = stringIocRoute(value);
            return route ? <a key={value} href={route} className="block break-all px-3 py-1.5 text-mitre-accent hover:underline">{value}</a> : <div key={value} className="break-all px-3 py-1.5 text-gray-500">{value}</div>;
          })}
        </div>
      </section>)}
      {!populated.length && <Empty text="No smart string categories matched the selected filters." />}
    </div>
  </Panel>;
}

function ModeButton({ active, label, onClick }: { active: boolean; label: string; onClick: () => void }) {
  return <button type="button" onClick={onClick} className={active ? 'rounded bg-mitre-accent px-2 py-1 text-white' : 'rounded border border-gray-700 px-2 py-1 text-gray-300 hover:border-mitre-accent'}>{label}</button>;
}

function Finding({ finding }: { finding: MalwareGraphStringsAnalysis['findings'][number] }) {
  return <>
    <div className="mb-1 flex items-center justify-between gap-2">
      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{finding.category}</span>
      <span className={finding.severity === 'high' ? 'text-red-300 text-[10px]' : finding.severity === 'medium' ? 'text-amber-300 text-[10px]' : 'text-gray-500 text-[10px]'}>{finding.severity}</span>
    </div>
    <div className="break-all font-mono text-xs text-gray-200">{finding.value}</div>
  </>;
}

function stringIocRoute(value: string) {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 512) return null;
  if (/^https?:\/\/[^\s"'<>]+$/i.test(trimmed)) return `/ioc-node?type=url&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$/.test(trimmed)) return `/ioc-node?type=ipv4&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^[A-Fa-f0-9]{32}$/.test(trimmed)) return `/ioc-node?type=md5&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^[A-Fa-f0-9]{40}$/.test(trimmed)) return `/ioc-node?type=sha1&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^[A-Fa-f0-9]{64}$/.test(trimmed)) return `/ioc-node?type=sha256&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(trimmed)) return `/ioc-node?type=email&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$/.test(trimmed) && !/\.(dll|exe|sys|ocx)$/i.test(trimmed)) return `/ioc-node?type=domain&value=${encodeURIComponent(trimmed)}&tier=0&sources=MalwareGraph`;
  if (/^(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\/i.test(trimmed)) return `/ioc-library?search=${encodeURIComponent(trimmed)}`;
  return null;
}

function isFirstAnalysis(artifact: unknown): artifact is MalwareGraphFirstAnalysis {
  if (!artifact || typeof artifact !== 'object') return false;
  const item = artifact as Record<string, unknown>;
  return item.type === 'first-analysis'
    && typeof item.target_entity_id === 'string'
    && typeof item.target_name === 'string'
    && typeof item.entropy === 'number';
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

function Empty({ text }: { text: string }) {
  return <div className="p-4 text-center text-xs text-gray-600">{text}</div>;
}
