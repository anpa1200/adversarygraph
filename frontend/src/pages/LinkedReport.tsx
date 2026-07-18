import { useMemo, useState } from 'react';
import type React from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { analyzeApi, reportsApi, type LinkedAnalysisReport, type LinkedReportEntity, type ReportTlp } from '@/api/client';
import { safeHref, safeInternalHref } from '@/utils/url';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

type InlineMatch = {
  start: number;
  end: number;
  text: string;
  entity: LinkedReportEntity;
};

const ENTITY_ORDER = ['technique', 'cve', 'group', 'ioc'];
const REPORT_TLP_OPTIONS: ReportTlp[] = ['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'];

type ReportEditForm = {
  name: string;
  source_url: string;
  publisher: string;
  summary: string;
  source_text: string;
  tlp: ReportTlp;
};

export function LinkedReport() {
  const { sessionId = '' } = useParams();
  const canManageIntel = useHasPermission('manage_intel');
  const canRunAnalysis = useHasPermission('run_analysis');
  const canExport = useHasPermission('export_data');
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState('claude');
  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState<ReportEditForm>({
    name: '',
    source_url: '',
    publisher: '',
    summary: '',
    source_text: '',
    tlp: 'TLP:AMBER+STRICT',
  });
  const query = useQuery({
    queryKey: ['linked-report', sessionId],
    queryFn: () => analyzeApi.linkedReport(sessionId),
    enabled: Boolean(sessionId),
  });

  const report = query.data ?? null;
  const grouped = useMemo(() => groupEntities(report?.entities ?? []), [report?.entities]);
  const matches = useMemo(() => findInlineMatches(report?.source_text ?? '', report?.entities ?? []), [report?.source_text, report?.entities]);
  const rawSourceUrl = typeof report?.report_intake?.url === 'string' ? report.report_intake.url : '';
  const sourceUrl = safeHref(rawSourceUrl);
  const reparseMutation = useMutation({
    mutationFn: () => analyzeApi.reparseLinkedReport(sessionId, { provider }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['linked-report', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const editMutation = useMutation({
    mutationFn: () => analyzeApi.editLinkedReport(sessionId, {
      name: editForm.name,
      source_url: editForm.source_url,
      publisher: editForm.publisher,
      summary: editForm.summary,
      source_text: editForm.source_text,
      tlp: editForm.tlp,
    }),
    onSuccess: () => {
      setEditOpen(false);
      queryClient.invalidateQueries({ queryKey: ['linked-report', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    },
  });
  const deleteMutation = useMutation({
    mutationFn: () => reportsApi.remove(sessionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
      navigate('/reports-research');
    },
  });

  const openEdit = () => {
    if (!report || !canManageIntel) return;
    setEditForm({
      name: report.name || '',
      source_url: rawSourceUrl,
      publisher: typeof report.report_intake?.publisher === 'string' ? report.report_intake.publisher : '',
      summary: report.summary || '',
      source_text: report.source_text || '',
      tlp: report.tlp,
    });
    setEditOpen(true);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <Header title="Linked Report Review" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          {query.isLoading && <Panel title="Loading report"><div className="p-4 text-sm text-gray-500">Loading linked report...</div></Panel>}
          {query.isError && <Panel title="Report unavailable"><div className="p-4 text-sm text-red-300">{query.error instanceof Error ? query.error.message : 'Unable to open linked report.'}</div></Panel>}
          {report && (
            <>
              <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
                <Panel title={report.name || `Analysis ${report.session_id.slice(0, 8)}`}>
                  <div className="space-y-4 p-4">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
                      <span className="rounded bg-gray-950 px-2 py-1 font-mono">{report.provider} / {report.model}</span>
                      <span className="rounded bg-gray-950 px-2 py-1 font-mono">{report.domain}</span>
                      <span
                        aria-label="Stored report TLP"
                        className={`rounded border px-2 py-1 font-semibold ${tlpTone(report.tlp)}`}
                      >
                        Stored TLP · {report.tlp}
                      </span>
                      <span>{new Date(report.created_at).toLocaleString()}</span>
                    </div>
                    {report.source_note && (
                      <div className="rounded border border-amber-500/40 bg-amber-950/20 p-3 text-xs leading-relaxed text-amber-100">
                        {report.source_note}
                      </div>
                    )}
                    <div>
                      <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">AI summary</div>
                      <p className="mt-2 text-sm leading-7 text-gray-200">{report.summary || 'No summary stored.'}</p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {canRunAnalysis && <Link to="/analyze" className="secondary-action">Back to analysis</Link>}
                      <Link to="/reports-research" className="secondary-action">Reports collection</Link>
                      {canRunAnalysis && report.source_text_available && report.domain === 'enterprise-attack' && (
                        <Link to={huntHypothesisUrl(report.session_id)} className="secondary-action border-cyan-800 text-cyan-100">Create AI hunt hypothesis</Link>
                      )}
                      <Link to="/navigator" className="secondary-action">Open Navigator</Link>
                      {sourceUrl && (
                        <a href={sourceUrl} target="_blank" rel="noreferrer" className="secondary-action">
                          Source report
                        </a>
                      )}
                      {canManageIntel && <button type="button" onClick={openEdit} className="secondary-action">Edit</button>}
                      {canManageIntel && <select value={provider} onChange={event => setProvider(event.target.value)} className="field h-9 w-auto min-w-32 py-1 text-xs">
                        <option value="claude">Claude</option>
                        <option value="openai">OpenAI</option>
                        <option value="gemini">Gemini</option>
                        <option value="minimax">MiniMax</option>
                        <option value="local">Local LLM</option>
                      </select>}
                      {canManageIntel && <button type="button" onClick={() => reparseMutation.mutate()} disabled={reparseMutation.isPending} className="secondary-action disabled:opacity-40">
                        {reparseMutation.isPending ? 'Reparsing...' : 'Reparse with AI'}
                      </button>}
                      {canExport && <button type="button" onClick={() => downloadText(`${slug(report.name || 'report')}-raw.txt`, report.source_text || '', 'text/plain;charset=utf-8')} className="secondary-action">Download raw</button>}
                      {canExport && <button type="button" onClick={() => downloadText(`${slug(report.name || 'report')}-parsed.json`, JSON.stringify(buildParsedExport(report), null, 2), 'application/json;charset=utf-8')} className="secondary-action">Download parsed</button>}
                      {canManageIntel && <button
                        type="button"
                        onClick={() => {
                          if (window.confirm(`Delete report "${report.name || report.session_id}"?`)) deleteMutation.mutate();
                        }}
                        disabled={deleteMutation.isPending}
                        className="secondary-action border-red-900/70 text-red-300 hover:border-red-500 disabled:opacity-40"
                      >
                        {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
                      </button>}
                      {!canManageIntel && <PermissionNotice permission="manage_intel" action="edit, reparse, or delete this report" compact />}
                      {!canExport && <PermissionNotice permission="export_data" action="download raw or parsed report data" compact />}
                    </div>
                    {(reparseMutation.isError || editMutation.isError || deleteMutation.isError) && (
                      <div className="rounded border border-red-800 bg-red-950/30 p-3 text-xs text-red-200">
                        {(reparseMutation.error instanceof Error && reparseMutation.error.message) ||
                          (editMutation.error instanceof Error && editMutation.error.message) ||
                          (deleteMutation.error instanceof Error && deleteMutation.error.message) ||
                          'Report action failed.'}
                      </div>
                    )}
                  </div>
                </Panel>

                <Panel title="Linked entities">
                  <div className="space-y-3 p-4">
                    <EntityCounts entities={report.entities} />
                    {ENTITY_ORDER.map(type => (
                      <EntityGroup key={type} type={type} entities={grouped[type] ?? []} />
                    ))}
                  </div>
                </Panel>
              </section>

              {editOpen && canManageIntel && (
                <Panel title="Edit report">
                  <div className="grid gap-3 p-4 xl:grid-cols-2">
                    <label className="space-y-1 text-xs text-gray-400">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Title</span>
                      <input value={editForm.name} onChange={event => setEditForm({ ...editForm, name: event.target.value })} className="field w-full" />
                    </label>
                    <label className="space-y-1 text-xs text-gray-400">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Original source URL</span>
                      <input value={editForm.source_url} onChange={event => setEditForm({ ...editForm, source_url: event.target.value })} className="field w-full" />
                    </label>
                    <label className="space-y-1 text-xs text-gray-400">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Publisher</span>
                      <input value={editForm.publisher} onChange={event => setEditForm({ ...editForm, publisher: event.target.value })} className="field w-full" />
                    </label>
                    <label className="space-y-1 text-xs text-gray-400">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Report TLP</span>
                      <select
                        aria-label="Report TLP"
                        value={editForm.tlp}
                        onChange={event => setEditForm({ ...editForm, tlp: event.target.value as ReportTlp })}
                        className="field w-full"
                      >
                        {REPORT_TLP_OPTIONS.map(value => <option key={value} value={value}>{value}</option>)}
                      </select>
                      <span className="block text-[10px] leading-4 text-gray-600">The stored report marking is authoritative for report-backed AI processing.</span>
                    </label>
                    <label className="space-y-1 text-xs text-gray-400 xl:col-span-2">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Summary</span>
                      <textarea value={editForm.summary} onChange={event => setEditForm({ ...editForm, summary: event.target.value })} className="field h-28 w-full resize-y" />
                    </label>
                    <label className="space-y-1 text-xs text-gray-400 xl:col-span-2">
                      <span className="font-semibold uppercase tracking-wide text-gray-500">Raw report text</span>
                      <textarea value={editForm.source_text} onChange={event => setEditForm({ ...editForm, source_text: event.target.value })} className="field h-96 w-full resize-y font-mono text-xs" />
                    </label>
                    <div className="flex flex-wrap gap-2 xl:col-span-2">
                      <button type="button" onClick={() => editMutation.mutate()} disabled={editMutation.isPending} className="primary-action disabled:opacity-40">
                        {editMutation.isPending ? 'Saving...' : 'Save changes'}
                      </button>
                      <button type="button" onClick={() => setEditOpen(false)} className="secondary-action">Cancel</button>
                    </div>
                  </div>
                </Panel>
              )}

              {report.report_images.length > 0 && (
                <Panel title="Original pictures and infographics">
                  <div className="border-b border-gray-800 px-4 py-3 text-xs leading-relaxed text-gray-500">
                    External images are listed as references and are not loaded inside AdversaryGraph. Open a reference explicitly to review it on the original host.
                  </div>
                  <div className="grid gap-4 p-4 md:grid-cols-2 xl:grid-cols-3">
                    {report.report_images.slice(0, 24).map((image, index) => {
                      const href = safeHref(image.url);
                      if (!href) return null;
                      return (
                        <figure key={`${image.url}-${index}`} className="overflow-hidden rounded border border-gray-800 bg-gray-950">
                          <div className="flex h-28 items-center justify-center border-b border-gray-800 bg-black/50 px-4 text-center">
                            <span className="text-xs font-semibold uppercase tracking-wide text-gray-600">External image reference {index + 1}</span>
                          </div>
                          <figcaption className="space-y-2 p-3 text-xs leading-5 text-gray-400">
                            <div className="line-clamp-2">{image.caption || image.alt || 'Report image'}</div>
                            <div className="truncate font-mono text-[10px] text-gray-600">{image.url}</div>
                            <a
                              href={href}
                              target="_blank"
                              rel="noopener noreferrer"
                              aria-label={`Open original image: ${image.alt || image.caption || index + 1}`}
                              className="secondary-action inline-flex"
                            >
                              Open original image ↗
                            </a>
                          </figcaption>
                        </figure>
                      );
                    })}
                  </div>
                </Panel>
              )}

              <Panel title="Report with inline platform links">
                <div className="border-b border-gray-800 px-4 py-3 text-xs leading-relaxed text-gray-500">
                  Inline links resolve to ATT&CK Navigator, IOC Library, CVE Library, and ATT&CK Group pages. Report text is rendered as text nodes, not inserted HTML.
                </div>
                <div className="max-h-[72vh] overflow-auto bg-gray-950 p-5">
                  <LinkedReportText text={report.source_text || 'No report text available.'} matches={matches} />
                </div>
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function LinkedReportText({ text, matches }: { text: string; matches: InlineMatch[] }) {
  const nodes: React.ReactNode[] = [];
  let cursor = 0;
  matches.forEach((match, index) => {
    if (match.start > cursor) {
      nodes.push(<span key={`text-${index}`}>{text.slice(cursor, match.start)}</span>);
    }
    nodes.push(
      <Link
        key={`match-${index}-${match.start}`}
        to={entityHref(match.entity)}
        className={`rounded px-1 font-semibold underline decoration-dotted underline-offset-4 ${entityTone(match.entity.type)}`}
        title={`${match.entity.type.toUpperCase()}: ${match.entity.label}`}
      >
        {match.text}
      </Link>
    );
    cursor = match.end;
  });
  if (cursor < text.length) nodes.push(<span key="text-tail">{text.slice(cursor)}</span>);

  return <pre className="whitespace-pre-wrap break-words font-mono text-[13px] leading-7 text-gray-200">{nodes}</pre>;
}

function EntityCounts({ entities }: { entities: LinkedReportEntity[] }) {
  const counts = groupEntities(entities);
  return (
    <div className="grid grid-cols-2 gap-2">
      {ENTITY_ORDER.map(type => (
        <div key={type} className="rounded border border-gray-800 bg-gray-950 p-3">
          <div className="text-lg font-semibold text-white">{(counts[type] ?? []).length}</div>
          <div className="text-[10px] uppercase tracking-wide text-gray-500">{type}</div>
        </div>
      ))}
    </div>
  );
}

function EntityGroup({ type, entities }: { type: string; entities: LinkedReportEntity[] }) {
  if (entities.length === 0) return null;
  return (
    <section>
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">{type}</h3>
        <span className="text-[10px] text-gray-600">{entities.length}</span>
      </div>
      <div className="max-h-52 space-y-1 overflow-y-auto pr-1">
        {entities.slice(0, 100).map(entity => (
          <Link
            key={`${entity.type}:${entity.id}:${entity.value}`}
            to={entityHref(entity)}
            className="block truncate rounded border border-gray-800 bg-gray-950 px-2 py-1.5 text-xs text-gray-300 hover:border-mitre-accent hover:text-white"
            title={entity.label}
          >
            <span className={entityTone(entity.type)}>{entity.id}</span>
            {entity.label !== entity.id && <span className="ml-2 text-gray-500">{entity.label}</span>}
          </Link>
        ))}
        {entities.length > 100 && <div className="text-[10px] text-gray-600">Showing first 100.</div>}
      </div>
    </section>
  );
}

function groupEntities(entities: LinkedReportEntity[]) {
  return entities.reduce<Record<string, LinkedReportEntity[]>>((acc, entity) => {
    const type = entity.type || 'entity';
    acc[type] = acc[type] || [];
    acc[type].push(entity);
    return acc;
  }, {});
}

function findInlineMatches(text: string, entities: LinkedReportEntity[]): InlineMatch[] {
  if (!text || entities.length === 0) return [];
  const haystack = text.toLowerCase();
  const rawCandidates = entities.flatMap(entity => entityCandidates(entity).map(candidate => ({ entity, candidate })));
  const candidates = rawCandidates
    .filter(item => item.candidate.length >= 4 && item.candidate.length <= 220)
    .sort((a, b) => b.candidate.length - a.candidate.length);

  const matches: InlineMatch[] = [];
  for (const { entity, candidate } of candidates) {
    const needle = candidate.toLowerCase();
    let index = haystack.indexOf(needle);
    while (index !== -1) {
      const end = index + needle.length;
      if (hasBoundary(text, index, end, entity.type)) {
        matches.push({ start: index, end, text: text.slice(index, end), entity });
      }
      if (matches.length > 2500) break;
      index = haystack.indexOf(needle, index + Math.max(1, needle.length));
    }
    if (matches.length > 2500) break;
  }

  return matches
    .sort((a, b) => a.start - b.start || b.end - a.end || entityPriority(a.entity.type) - entityPriority(b.entity.type))
    .reduce<InlineMatch[]>((acc, match) => {
      const previous = acc[acc.length - 1];
      if (previous && match.start < previous.end) return acc;
      acc.push(match);
      return acc;
    }, []);
}

function entityCandidates(entity: LinkedReportEntity) {
  const candidates = new Set<string>();
  [entity.id, entity.value, entity.label, ...entity.aliases].forEach(item => {
    const value = String(item || '').trim();
    if (!value) return;
    candidates.add(value);
    if (entity.type === 'technique') candidates.add(value.split(/\s+/)[0]);
  });
  return Array.from(candidates);
}

function hasBoundary(text: string, start: number, end: number, type: string) {
  if (type === 'ioc') return true;
  const before = start > 0 ? text[start - 1] : '';
  const after = end < text.length ? text[end] : '';
  return !/[A-Za-z0-9_.-]/.test(before) && !/[A-Za-z0-9_.-]/.test(after);
}

function entityHref(entity: LinkedReportEntity) {
  const value = entity.value || entity.id || entity.label;
  if (entity.type === 'technique') return `/navigator?technique=${encodeURIComponent(entity.id)}`;
  if (entity.type === 'cve') return `/cve?cve=${encodeURIComponent(entity.id)}`;
  if (entity.type === 'group') return entity.id.startsWith('G') ? `/apt?group=${encodeURIComponent(entity.id)}` : `/apt?search=${encodeURIComponent(entity.label)}`;
  const safeRoute = safeInternalHref(entity.route);
  if (entity.type === 'ioc' && safeRoute?.startsWith('/ioc-library/')) return safeRoute;
  if (entity.type === 'ioc') return `/ioc-library?search=${encodeURIComponent(value)}`;
  return safeRoute || '/discover';
}

function entityPriority(type: string) {
  const index = ENTITY_ORDER.indexOf(type);
  return index === -1 ? ENTITY_ORDER.length : index;
}

function entityTone(type: string) {
  if (type === 'technique') return 'text-cyan-300';
  if (type === 'cve') return 'text-red-300';
  if (type === 'group') return 'text-violet-300';
  if (type === 'ioc') return 'text-amber-300';
  return 'text-mitre-accent';
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

function tlpTone(value: ReportTlp) {
  if (value === 'TLP:RED') return 'border-red-700 bg-red-950/40 text-red-200';
  if (value === 'TLP:AMBER+STRICT' || value === 'TLP:AMBER') return 'border-amber-700 bg-amber-950/40 text-amber-200';
  if (value === 'TLP:GREEN') return 'border-emerald-700 bg-emerald-950/40 text-emerald-200';
  return 'border-sky-700 bg-sky-950/40 text-sky-200';
}

function huntHypothesisUrl(sessionId: string) {
  return `/threat-hunting/new?${new URLSearchParams({
    assistant: 'hypothesis',
    source: 'report',
    source_session_id: sessionId,
    source_ref: sessionId,
  }).toString()}`;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded border border-gray-800 bg-gray-900/40">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      {children}
    </section>
  );
}
