import { useMemo } from 'react';
import type React from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { analyzeApi, type LinkedReportEntity } from '@/api/client';

type InlineMatch = {
  start: number;
  end: number;
  text: string;
  entity: LinkedReportEntity;
};

const ENTITY_ORDER = ['technique', 'cve', 'group', 'ioc'];

export function LinkedReport() {
  const { sessionId = '' } = useParams();
  const query = useQuery({
    queryKey: ['linked-report', sessionId],
    queryFn: () => analyzeApi.linkedReport(sessionId),
    enabled: Boolean(sessionId),
  });

  const report = query.data ?? null;
  const grouped = useMemo(() => groupEntities(report?.entities ?? []), [report?.entities]);
  const matches = useMemo(() => findInlineMatches(report?.source_text ?? '', report?.entities ?? []), [report?.source_text, report?.entities]);
  const sourceUrl = typeof report?.report_intake?.url === 'string' ? report.report_intake.url : '';

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
                      <Link to="/analyze" className="secondary-action">Back to analysis</Link>
                      <Link to="/navigator" className="secondary-action">Open Navigator</Link>
                      {sourceUrl && (
                        <a href={sourceUrl} target="_blank" rel="noreferrer" className="secondary-action">
                          Source report
                        </a>
                      )}
                    </div>
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
  if (entity.type === 'ioc' && entity.route.startsWith('/ioc-library/')) return entity.route;
  if (entity.type === 'ioc') return `/ioc-library?search=${encodeURIComponent(value)}`;
  return entity.route || '/discover';
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

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded border border-gray-800 bg-gray-900/40">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      {children}
    </section>
  );
}
