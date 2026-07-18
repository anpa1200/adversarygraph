import { useMemo, useState } from 'react';
import type React from 'react';
import { Link } from 'react-router-dom';
import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { analyzeApi, reportsApi, type LinkedAnalysisReport, type ReportCollectionItem, type ReportCollectionTag } from '@/api/client';
import { useAppStore } from '@/store';
import { safeHref } from '@/utils/url';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

const TAG_BUCKETS = [
  ['reports', 'Reports'],
  ['ttps', 'TTPs'],
  ['iocs', 'IOCs'],
  ['cves', 'CVEs'],
  ['threat_actors', 'Threat Actors'],
  ['sectors', 'Sectors'],
  ['infrastructure', 'Infrastructure'],
] as const;

const REPORT_PAGE_SIZE = 50;

export function ReportsResearch() {
  const { domain } = useAppStore();
  const queryClient = useQueryClient();
  const canManageIntel = useHasPermission('manage_intel');
  const canRunAnalysis = useHasPermission('run_analysis');
  const canUploadFiles = useHasPermission('upload_files');
  const [queryText, setQueryText] = useState('');
  const [activeBucket, setActiveBucket] = useState<string>('all');
  const [researchTitle, setResearchTitle] = useState('');
  const [researchFile, setResearchFile] = useState<File | null>(null);
  const [researchUrl, setResearchUrl] = useState('');
  const [urlTitle, setUrlTitle] = useState('');
  const [urlParseWithAi, setUrlParseWithAi] = useState(true);
  const [parseWithAi, setParseWithAi] = useState(true);
  const canUploadFile = canUploadFiles && (parseWithAi ? canRunAnalysis : canManageIntel);
  const [provider, setProvider] = useState('claude');
  const [lastUpload, setLastUpload] = useState<{ session_id: string; title: string; parsed: boolean; source_url?: string } | null>(null);
  const collection = useInfiniteQuery({
    queryKey: ['report-research-collection'],
    queryFn: ({ pageParam }) => analyzeApi.reportCollection(REPORT_PAGE_SIZE, pageParam),
    initialPageParam: 0,
    getNextPageParam: lastPage => lastPage.items.length === REPORT_PAGE_SIZE
      ? lastPage.offset + lastPage.items.length
      : undefined,
    staleTime: 30_000,
  });
  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!researchFile) throw new Error('Choose a research file first.');
      const fd = new FormData();
      fd.append('domain', domain);
      fd.append('name', researchTitle.trim() || researchFile.name);
      fd.append('file', researchFile);
      if (parseWithAi) {
        fd.append('provider', provider);
        const result = await analyzeApi.submit(fd);
        return { session_id: result.session_id, title: researchTitle.trim() || researchFile.name, parsed: true };
      }
      const result = await analyzeApi.storeResearch(fd);
      return { session_id: result.session_id, title: result.title, parsed: false };
    },
    onSuccess: data => {
      setLastUpload(data);
      setResearchFile(null);
      setResearchTitle('');
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const urlMutation = useMutation({
    mutationFn: async () => {
      if (!researchUrl.trim()) throw new Error('Paste a report URL first.');
      const fd = new FormData();
      fd.append('url', researchUrl.trim());
      fd.append('domain', domain);
      fd.append('name', urlTitle.trim());
      fd.append('parse_with_ai', String(urlParseWithAi));
      if (urlParseWithAi) fd.append('provider', provider);
      const result = await analyzeApi.ingestResearchUrl(fd);
      return { session_id: result.session_id, title: result.title, parsed: urlParseWithAi, source_url: result.source_url };
    },
    onSuccess: data => {
      setLastUpload(data);
      setResearchUrl('');
      setUrlTitle('');
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const items = useMemo(
    () => collection.data?.pages.flatMap(page => page.items) ?? [],
    [collection.data?.pages],
  );
  const filtered = useMemo(() => filterReports(items, queryText, activeBucket), [items, queryText, activeBucket]);
  const totals = useMemo(() => collectionTotals(items), [items]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Header title="Reports / Research Collection" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <Panel title="Analyzed report collection">
              <div className="space-y-4 p-4">
                <p className="text-sm leading-6 text-gray-400">
                  Browse analyzed CTI reports and research notes as tagged intelligence objects. Each report is tagged with mapped TTPs,
                  IOCs, CVEs, threat actors, target sectors, and infrastructure indicators, then linked back into the platform.
                </p>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  <Metric label="Reports loaded" value={String(items.length)} />
                  <Metric label="TTP tags" value={String(totals.ttps)} />
                  <Metric label="IOC tags" value={String(totals.iocs)} />
                  <Metric label="CVE tags" value={String(totals.cves)} />
                  <Metric label="Actor tags" value={String(totals.threat_actors)} />
                  <Metric label="Infrastructure tags" value={String(totals.infrastructure)} />
                </div>
              </div>
            </Panel>
            <Panel title="Add research">
              <div className="space-y-3 p-4">
                {!canManageIntel && <PermissionNotice permission="manage_intel" action="ingest report URLs or manage stored research" compact />}
                <div className="rounded border border-gray-800 bg-gray-950/60 p-3">
                  <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">Upload from URL</div>
                  <div className="space-y-2">
                    <input
                      disabled={!canManageIntel}
                      value={researchUrl}
                      onChange={event => setResearchUrl(event.target.value)}
                      placeholder="https://vendor.example/report.html or report.pdf"
                      className="field w-full"
                    />
                    <input
                      disabled={!canManageIntel}
                      value={urlTitle}
                      onChange={event => setUrlTitle(event.target.value)}
                      placeholder="Optional report title"
                      className="field w-full"
                    />
                    <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">
                      <input
                        type="checkbox"
                        disabled={!canManageIntel}
                        checked={urlParseWithAi}
                        onChange={event => setUrlParseWithAi(event.target.checked)}
                        className="mt-1"
                      />
                      <span>
                        <span className="block font-semibold text-white">Parse URL with AI</span>
                        Fetch the report, extract text and original image references, then map TTPs, CVEs, IOCs, actors, sectors, and infrastructure.
                      </span>
                    </label>
                    {urlParseWithAi && (
                      <select disabled={!canManageIntel} value={provider} onChange={event => setProvider(event.target.value)} className="field w-full">
                        <option value="claude">Claude</option>
                        <option value="openai">OpenAI</option>
                        <option value="gemini">Gemini</option>
                        <option value="minimax">MiniMax</option>
                        <option value="local">Local LLM</option>
                      </select>
                    )}
                    <button
                      type="button"
                      onClick={() => urlMutation.mutate()}
                      disabled={!canManageIntel || !researchUrl.trim() || urlMutation.isPending}
                      className="primary-action w-full disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {urlMutation.isPending ? 'Fetching report URL...' : 'Upload from URL'}
                    </button>
                    {urlMutation.isError && (
                      <div className="rounded border border-red-800 bg-red-950/30 p-3 text-xs text-red-200">
                        {urlMutation.error instanceof Error ? urlMutation.error.message : 'URL ingestion failed.'}
                      </div>
                    )}
                  </div>
                </div>
                <div className="border-t border-gray-800 pt-3 text-xs font-semibold uppercase tracking-wide text-gray-500">Upload file</div>
                {!canUploadFiles && <PermissionNotice permission="upload_files" action="upload research files" compact />}
                <input
                  disabled={!canUploadFile}
                  value={researchTitle}
                  onChange={event => setResearchTitle(event.target.value)}
                  placeholder="Research title"
                  className="field w-full"
                />
                <label className="flex cursor-pointer flex-col gap-2 rounded border border-dashed border-gray-700 bg-gray-950/70 p-4 text-xs text-gray-400 hover:border-gray-500">
                  <span className="font-semibold text-gray-200">Upload research file</span>
                  <span>PDF, DOCX, TXT, MD, CSV, or report export.</span>
                  <input
                    type="file"
                    disabled={!canUploadFile}
                    accept=".pdf,.docx,.txt,.md,.markdown,.csv,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/markdown,text/csv"
                    className="sr-only"
                    onChange={event => setResearchFile(event.target.files?.[0] ?? null)}
                  />
                  {researchFile && <span className="rounded bg-gray-900 px-2 py-1 text-gray-100">{researchFile.name}</span>}
                </label>
                <label className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">
                  <input
                    type="checkbox"
                    disabled={!canRunAnalysis && !canManageIntel}
                    checked={parseWithAi}
                    onChange={event => setParseWithAi(event.target.checked)}
                    className="mt-1"
                  />
                  <span>
                    <span className="block font-semibold text-white">Parse with AI</span>
                    Extract TTPs, CVEs, IOCs, actors, sectors, and infrastructure tags immediately. Unchecked stores the source as unparsed research.
                  </span>
                </label>
                {parseWithAi && (
                  <select disabled={!canRunAnalysis} value={provider} onChange={event => setProvider(event.target.value)} className="field w-full">
                    <option value="claude">Claude</option>
                    <option value="openai">OpenAI</option>
                    <option value="gemini">Gemini</option>
                    <option value="minimax">MiniMax</option>
                    <option value="local">Local LLM</option>
                  </select>
                )}
                <button
                  type="button"
                  onClick={() => uploadMutation.mutate()}
                  disabled={!canUploadFile || !researchFile || uploadMutation.isPending}
                  className="primary-action w-full disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {uploadMutation.isPending ? (parseWithAi ? 'Parsing research...' : 'Storing research...') : 'Upload research'}
                </button>
                {canUploadFiles && !canUploadFile && <PermissionNotice permission={parseWithAi ? 'run_analysis' : 'manage_intel'} action={parseWithAi ? 'upload and parse research with AI' : 'store research without AI parsing'} compact />}
                {uploadMutation.isError && (
                  <div className="rounded border border-red-800 bg-red-950/30 p-3 text-xs text-red-200">
                    {uploadMutation.error instanceof Error ? uploadMutation.error.message : 'Upload failed.'}
                  </div>
                )}
                {lastUpload && (
                  <div className="rounded border border-green-800 bg-green-950/20 p-3 text-xs leading-5 text-green-100">
                    <div>{lastUpload.parsed ? 'Parsed with AI' : 'Stored without AI parsing'}: {lastUpload.title}</div>
                    {lastUpload.source_url && <div className="truncate text-green-200/70">Source: {lastUpload.source_url}</div>}
                    <Link to={`/analyze/${lastUpload.session_id}/report`} className="mt-2 inline-flex text-mitre-accent hover:text-mitre-accent/80">
                      Open linked report
                    </Link>
                  </div>
                )}
              </div>
            </Panel>
          </section>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
            <Panel title="Collection filters">
              <div className="space-y-3 p-4">
                <input
                  value={queryText}
                  onChange={event => setQueryText(event.target.value)}
                  placeholder="Search loaded reports by title, summary, TTP, IOC, CVE, actor, sector..."
                  className="field w-full"
                />
                <select value={activeBucket} onChange={event => setActiveBucket(event.target.value)} className="field w-full">
                  <option value="all">All tag buckets</option>
                  {TAG_BUCKETS.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                </select>
                <div className="rounded border border-blue-500/30 bg-blue-950/20 p-3 text-xs leading-relaxed text-blue-100">
                  Tagging is deterministic from stored analysis, report intake metadata, CVE/IOC extraction, and conservative sector/infrastructure keyword matching.
                </div>
                <p className="text-xs leading-5 text-gray-500">
                  {items.length} report{items.length === 1 ? '' : 's'} loaded. Filters and metrics cover loaded pages; load older reports to expand the collection.
                </p>
              </div>
            </Panel>
            <Panel title="Research workflow">
              <div className="space-y-3 p-4 text-sm leading-6 text-gray-400">
                <p>Upload research with AI parsing when you want immediate ATT&CK, CVE, IOC, actor, sector, and infrastructure tagging.</p>
                <p>Store without AI when you only need the source available in the collection before analyst review.</p>
              </div>
            </Panel>
          </section>

          {collection.isLoading && <Empty text="Loading analyzed report collection..." />}
          {collection.isError && <Empty text={collection.error instanceof Error ? collection.error.message : 'Unable to load report collection.'} tone="bad" />}
          {!collection.isLoading && !collection.isError && filtered.length === 0 && <Empty text="No reports match this filter." />}

          <div className="grid gap-4">
            {filtered.map(item => <ReportCard key={item.session_id} item={item} provider={provider} />)}
          </div>
          {collection.hasNextPage && (
            <div className="flex justify-center">
              <button
                type="button"
                className="secondary-action min-w-48"
                disabled={collection.isFetchingNextPage}
                onClick={() => void collection.fetchNextPage()}
              >
                {collection.isFetchingNextPage ? 'Loading older reports…' : 'Load older reports'}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ReportCard({ item, provider }: { item: ReportCollectionItem; provider: string }) {
  const queryClient = useQueryClient();
  const canManageIntel = useHasPermission('manage_intel');
  const canRunAnalysis = useHasPermission('run_analysis');
  const canExport = useHasPermission('export_data');
  const sourceHref = safeHref(item.source_url);
  const reparseMutation = useMutation({
    mutationFn: () => analyzeApi.reparseLinkedReport(item.session_id, { provider }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: () => reportsApi.remove(item.session_id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const downloadReport = async (kind: 'raw' | 'parsed') => {
    const report = await analyzeApi.linkedReport(item.session_id);
    if (kind === 'raw') {
      downloadText(`${slug(item.title)}-raw.txt`, report.source_text || '', 'text/plain;charset=utf-8');
      return;
    }
    downloadText(`${slug(item.title)}-parsed.json`, JSON.stringify(buildParsedExport(report), null, 2), 'application/json;charset=utf-8');
  };
  return (
    <article className="overflow-hidden rounded border border-gray-800 bg-gray-900/50">
      <div className="grid gap-4 border-b border-gray-800 p-4 xl:grid-cols-[minmax(0,1fr)_280px]">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wide text-gray-500">
            <span>{item.provider} / {item.model}</span>
            <span>{item.domain}</span>
            <span>{new Date(item.created_at).toLocaleString()}</span>
            <span className={item.source_text_available ? 'text-green-300' : 'text-amber-300'}>
              {item.source_text_available ? 'source text stored' : 'summary fallback'}
            </span>
          </div>
          <h2 className="break-words text-lg font-semibold text-white">{item.title}</h2>
          <p className="mt-2 line-clamp-3 text-sm leading-6 text-gray-400">{item.summary || 'No summary stored.'}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Link to={`/analyze/${item.session_id}/report`} className="primary-action">Open linked report</Link>
            {canRunAnalysis && item.status === 'completed' && item.source_text_available && item.domain === 'enterprise-attack' && (
              <Link to={huntHypothesisUrl(item.session_id)} className="secondary-action border-cyan-800 text-cyan-100">Create AI hunt hypothesis</Link>
            )}
            {canRunAnalysis && <Link to="/analyze" className="secondary-action">AI Analysis</Link>}
            {canRunAnalysis && <Link to="/operations" className="secondary-action">Report intake</Link>}
            {sourceHref && <a href={sourceHref} target="_blank" rel="noreferrer" className="secondary-action">Source</a>}
            {canManageIntel && <button type="button" onClick={() => reparseMutation.mutate()} disabled={reparseMutation.isPending} className="secondary-action disabled:opacity-40">
              {reparseMutation.isPending ? 'Reparsing...' : 'Reparse with AI'}
            </button>}
            {canExport && <button type="button" onClick={() => downloadReport('raw')} className="secondary-action">Download raw</button>}
            {canExport && <button type="button" onClick={() => downloadReport('parsed')} className="secondary-action">Download parsed</button>}
            {canManageIntel && <button
              type="button"
              onClick={() => {
                if (window.confirm(`Delete report "${item.title}"?`)) deleteMutation.mutate();
              }}
              disabled={deleteMutation.isPending}
              className="secondary-action border-red-900/70 text-red-300 hover:border-red-500 disabled:opacity-40"
            >
              {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
            </button>}
            {!canManageIntel && <PermissionNotice permission="manage_intel" action="reparse or delete this report" compact />}
          </div>
          {(reparseMutation.isError || deleteMutation.isError) && (
            <div className="mt-3 rounded border border-red-800 bg-red-950/30 p-2 text-xs text-red-200">
              {(reparseMutation.error instanceof Error && reparseMutation.error.message) || (deleteMutation.error instanceof Error && deleteMutation.error.message) || 'Report action failed.'}
            </div>
          )}
        </div>
        <div className="grid grid-cols-3 gap-2 text-xs">
          {TAG_BUCKETS.map(([key, label]) => (
            <div key={key} className="rounded border border-gray-800 bg-gray-950 p-2">
              <div className="text-base font-semibold text-white">{item.counts[key] ?? 0}</div>
              <div className="text-[10px] text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="space-y-4 p-4">
        {TAG_BUCKETS.map(([key, label]) => (
          <TagBucket key={key} title={label} tags={item.tags[key] ?? []} empty={`No ${label.toLowerCase()} tags found.`} />
        ))}
      </div>
    </article>
  );
}

function buildParsedExport(report: LinkedAnalysisReport) {
  return {
    session_id: report.session_id,
    name: report.name,
    provider: report.provider,
    model: report.model,
    domain: report.domain,
    tlp: report.tlp,
    created_at: report.created_at,
    summary: report.summary,
    techniques: report.techniques,
    apt_matches: report.apt_matches,
    entities: report.entities,
    report_images: report.report_images,
    report_intake: report.report_intake,
  };
}

function downloadText(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'report';
}

function huntHypothesisUrl(sessionId: string) {
  return `/threat-hunting/new?${new URLSearchParams({
    assistant: 'hypothesis',
    source: 'report',
    source_session_id: sessionId,
    source_ref: sessionId,
  }).toString()}`;
}

function TagBucket({ title, tags, empty }: { title: string; tags: ReportCollectionTag[]; empty: string }) {
  return (
    <section>
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
        <span className="text-[10px] text-gray-600">{tags.length}</span>
      </div>
      {tags.length === 0 ? (
        <div className="rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-xs text-gray-600">{empty}</div>
      ) : (
        <div className="flex flex-wrap gap-2">
          {tags.slice(0, 80).map(tag => {
            const content = (
              <span
                className={`inline-flex max-w-full items-center gap-1 rounded border px-2 py-1 text-xs ${tagTone(tag.type)}`}
                title={`${tag.type}: ${tag.label} (${tag.confidence})`}
              >
                <span className="truncate">{tag.label}</span>
                <span className="text-[10px] opacity-70">{tag.confidence}</span>
              </span>
            );
            return tag.route ? (
              <Link key={`${tag.type}:${tag.value}:${tag.route}`} to={tag.route} className="max-w-full">
                {content}
              </Link>
            ) : (
              <span key={`${tag.type}:${tag.value}`} className="max-w-full">{content}</span>
            );
          })}
          {tags.length > 80 && <span className="rounded border border-gray-800 px-2 py-1 text-xs text-gray-600">+{tags.length - 80} more</span>}
        </div>
      )}
    </section>
  );
}

function filterReports(items: ReportCollectionItem[], queryText: string, activeBucket: string) {
  const q = queryText.trim().toLowerCase();
  return items.filter(item => {
    if (activeBucket !== 'all' && (item.tags[activeBucket] ?? []).length === 0) return false;
    if (!q) return true;
    const tagText = Object.values(item.tags).flat().map(tag => `${tag.label} ${tag.value}`).join(' ');
    return `${item.title} ${item.publisher} ${item.summary} ${tagText}`.toLowerCase().includes(q);
  });
}

function collectionTotals(items: ReportCollectionItem[]) {
  return TAG_BUCKETS.reduce<Record<string, number>>((acc, [key]) => {
    acc[key] = items.reduce((sum, item) => sum + (item.counts[key] ?? 0), 0);
    return acc;
  }, {});
}

function tagTone(type: string) {
  if (type === 'report') return 'border-slate-700 bg-slate-950/40 text-slate-100';
  if (type === 'ttp') return 'border-cyan-800 bg-cyan-950/30 text-cyan-200';
  if (type === 'ioc') return 'border-amber-800 bg-amber-950/30 text-amber-200';
  if (type === 'cve') return 'border-red-800 bg-red-950/30 text-red-200';
  if (type === 'threat_actor') return 'border-violet-800 bg-violet-950/30 text-violet-200';
  if (type === 'sector') return 'border-blue-800 bg-blue-950/30 text-blue-200';
  if (type === 'infrastructure') return 'border-emerald-800 bg-emerald-950/30 text-emerald-200';
  return 'border-gray-800 bg-gray-950 text-gray-300';
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-gray-800 bg-gray-950 p-3"><div className="text-xl font-semibold text-white">{value}</div><div className="text-xs text-gray-500">{label}</div></div>;
}

function Empty({ text, tone = 'default' }: { text: string; tone?: 'default' | 'bad' }) {
  const color = tone === 'bad' ? 'text-red-300 border-red-900/60' : 'text-gray-500 border-gray-800';
  return <div className={`rounded border p-10 text-center text-sm ${color}`}>{text}</div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="overflow-hidden rounded border border-gray-800 bg-gray-900/50"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}
