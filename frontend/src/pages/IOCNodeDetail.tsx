import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { aptApi, attackApi, iocApi } from '@/api/client';
import { useAppStore } from '@/store';
import { RelationshipGraph } from './IOCInvestigation';
import { IocLink, TtpLink } from '@/utils/ctiLinks';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

const NETWORK_FINGERPRINT_TYPES = new Set(['ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'ja4l', 'ja4ls', 'ja4x', 'ja4ssh', 'ja4t']);
const OBSERVABLE_TYPES = new Set(['ioc', 'ip', 'ipv4', 'ipv6', 'domain', 'url', 'email', 'hash', 'md5', 'sha1', 'sha256', ...NETWORK_FINGERPRINT_TYPES]);
const SEARCHABLE_OBJECT_TYPES = new Set([...OBSERVABLE_TYPES, 'file', 'report', 'collection']);

export function IOCNodeDetail() {
  const canRunAnalysis = useHasPermission('run_analysis');
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { domain, version, addTechniques, replaceTechniques } = useAppStore();
  const value = params.get('value') ?? '';
  const type = params.get('type') ?? 'unknown';
  const tier = params.get('tier') ?? '';
  const sources = useMemo(() => (params.get('sources') ?? '').split(',').map(item => item.trim()).filter(Boolean), [params]);
  const isObservable = OBSERVABLE_TYPES.has(type);
  const isTechnique = /^T\d{4}(?:\.\d{3})?$/i.test(value);
  const isActorId = /^G\d{4}$/i.test(value);
  const canSearchIocs = Boolean(value.trim()) && SEARCHABLE_OBJECT_TYPES.has(type);
  const library = useQuery({
    queryKey: ['ioc-node-library', type, value],
    queryFn: () => iocApi.library({ search: value, limit: 10 }),
    enabled: canSearchIocs,
  });
  const relationshipInvestigation = useQuery({
    queryKey: ['ioc-node-relationship-investigation', domain, value],
    queryFn: () => iocApi.investigate({
      artifact: value,
      domain,
      depth: 2,
      max_tier_nodes: 35,
      ai_summarize: false,
      ai_provider: 'local',
    }),
    enabled: canRunAnalysis && isObservable && Boolean(value.trim()),
    staleTime: 60_000,
    retry: 1,
  });
  const actorSearch = useQuery({
    queryKey: ['ioc-node-actor-search', domain, version, value],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined, search: value }),
    enabled: (type === 'actor' || isActorId) && Boolean(value.trim()),
    staleTime: 5 * 60_000,
  });
  const selectedActorId = useMemo(() => {
    if (isActorId) return value.toUpperCase();
    return actorSearch.data?.[0]?.attack_id ?? '';
  }, [actorSearch.data, isActorId, value]);
  const actorDetail = useQuery({
    queryKey: ['ioc-node-actor-detail', selectedActorId, domain, version],
    queryFn: () => aptApi.group(selectedActorId, domain, version ?? undefined),
    enabled: Boolean(selectedActorId),
    staleTime: 5 * 60_000,
  });
  const techniqueDetail = useQuery({
    queryKey: ['ioc-node-technique-detail', value, domain, version],
    queryFn: () => attackApi.technique(value.toUpperCase(), domain, version ?? undefined),
    enabled: isTechnique,
    staleTime: 5 * 60_000,
  });
  const matchedTechniqueIds = useMemo(() => {
    const fromItems = library.data?.items.flatMap(item => item.technique_ids ?? []) ?? [];
    const fromInvestigation = relationshipInvestigation.data?.techniques.map(item => item.attack_id) ?? [];
    const fromActor = actorDetail.data?.techniques.map(item => item.attack_id) ?? [];
    return Array.from(new Set([...(isTechnique ? [value.toUpperCase()] : []), ...fromItems, ...fromInvestigation, ...fromActor])).sort();
  }, [actorDetail.data?.techniques, isTechnique, library.data?.items, relationshipInvestigation.data?.techniques, value]);

  const showOnMatrix = () => {
    replaceTechniques(matchedTechniqueIds);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Investigation Node Detail" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-300">{type}</span>
                  {tier && <span className="rounded bg-gray-800 px-2 py-1 text-[10px] text-gray-400">Tier {tier}</span>}
                  {sources.map(source => <span key={source} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-400">{source}</span>)}
                </div>
                <h2 className="mt-3 break-all font-mono text-xl font-semibold text-white">{value || 'Unknown node'}</h2>
                <p className="mt-3 max-w-4xl text-sm leading-relaxed text-gray-400">{nodeSummary(type, value)}</p>
              </div>
              <div className="grid min-w-[260px] gap-2 text-xs">
                {isObservable && <button onClick={() => navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`)} className="primary-action">Investigate IOC</button>}
                {canSearchIocs && <button onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(value)}`)} className="secondary-action">Search IOC Library</button>}
                {isObservable && !NETWORK_FINGERPRINT_TYPES.has(type) && <button onClick={() => navigate(`/virustotal?indicator=${encodeURIComponent(value)}`)} className="secondary-action">VirusTotal Lookup</button>}
                {isTechnique && <button onClick={() => navigate(`/navigator?technique=${value.toUpperCase()}`)} className="secondary-action">Open Technique</button>}
                {selectedActorId && <button onClick={() => navigate(`/apt?group=${selectedActorId}`)} className="secondary-action">Open Actor</button>}
                {type === 'actor' && !selectedActorId && <button onClick={() => navigate(`/apt?search=${encodeURIComponent(value)}`)} className="secondary-action">Search Actor Library</button>}
              </div>
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-3">
            <ContextCard title="Relationship context" loading={relationshipInvestigation.isLoading} error={relationshipInvestigation.error}>
              {relationshipInvestigation.data ? (
                <div className="space-y-2 text-xs text-gray-400">
                  <Metric label="Verdict" value={`${relationshipInvestigation.data.verdict} (${relationshipInvestigation.data.suspicion_score}/100)`} />
                  <Metric label="Nodes" value={relationshipInvestigation.data.relationships.nodes.length} />
                  <Metric label="Edges" value={relationshipInvestigation.data.relationships.edges.length} />
                  <p className="line-clamp-4 leading-5">{relationshipInvestigation.data.summary}</p>
                </div>
              ) : <Empty text={isObservable ? 'Relationship context will load automatically.' : 'Relationship investigation is available for IOC, IP, domain, URL, hash, and network fingerprint nodes.'} />}
            </ContextCard>
            <ContextCard title="Actor context" loading={actorSearch.isLoading || actorDetail.isLoading} error={actorSearch.error || actorDetail.error}>
              {actorDetail.data ? (
                <div className="space-y-2 text-xs text-gray-400">
                  <Metric label="Actor" value={`${actorDetail.data.name} (${actorDetail.data.attack_id})`} />
                  <Metric label="Techniques" value={actorDetail.data.techniques.length} />
                  <Metric label="Campaigns" value={actorDetail.data.campaign_count} />
                  <p className="line-clamp-4 leading-5">{actorDetail.data.description || 'No ATT&CK description available.'}</p>
                </div>
              ) : actorSearch.data?.length ? (
                <div className="space-y-2">
                  {actorSearch.data.slice(0, 5).map(actor => (
                    <button key={actor.attack_id} type="button" onClick={() => navigate(`/apt?group=${actor.attack_id}`)} className="block w-full rounded border border-gray-800 bg-gray-950/50 p-2 text-left hover:border-mitre-accent">
                      <b className="text-xs text-gray-100">{actor.name}</b>
                      <p className="text-[10px] text-gray-500">{actor.attack_id} · {actor.technique_count} techniques</p>
                    </button>
                  ))}
                </div>
              ) : <Empty text="No actor profile found for this node." />}
            </ContextCard>
            <ContextCard title="Technique context" loading={techniqueDetail.isLoading} error={techniqueDetail.error}>
              {techniqueDetail.data ? (
                <div className="space-y-2 text-xs text-gray-400">
                  <Metric label="Technique" value={`${techniqueDetail.data.attack_id} ${techniqueDetail.data.name}`} />
                  <Metric label="Tactic" value={techniqueDetail.data.tactics.join(', ') || 'unknown'} />
                  <p className="line-clamp-5 leading-5">{techniqueDetail.data.description || 'No ATT&CK description available.'}</p>
                </div>
              ) : matchedTechniqueIds.length ? (
                <div className="flex flex-wrap gap-1.5">
                  {matchedTechniqueIds.slice(0, 20).map(id => (
                    <button key={id} type="button" onClick={() => navigate(`/navigator?technique=${id}`)} className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-2 py-1 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent hover:text-white">{id}</button>
                  ))}
                </div>
              ) : <Empty text="No direct technique mapping was found." />}
            </ContextCard>
          </section>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Investigation Questions">
              <Question title="Malicious?" answer={maliciousAnswer(type)} refText={sourceRef(sources)}>
                {maliciousWhy(type, value)}
              </Question>
              <Question title="TTP?" answer={matchedTechniqueIds.length ? 'possible / mapped' : isTechnique ? 'direct technique' : 'no direct mapping'} refText={matchedTechniqueIds.join(', ') || sourceRef(sources)}>
                {matchedTechniqueIds.length
                  ? 'This node has direct or IOC-library ATT&CK technique context. Validate the behavior evidence before using it in a client report.'
                  : 'This node does not currently carry a direct ATT&CK mapping. Use it as pivot or context unless a source provides behavior evidence.'}
              </Question>
              <Question title="Actor?" answer={type === 'actor' || isActorId ? 'actor lead' : 'not direct actor evidence'} refText={sourceRef(sources)}>
                {type === 'actor' || isActorId
                  ? 'This node points to an actor name or ATT&CK group ID. Treat it as a lead requiring source validation, not attribution.'
                  : 'This node is not an actor. Actor relevance requires a source-backed actor link, alias match, or report context.'}
              </Question>
            </Panel>

            <Panel title="Actions">
              <div className="space-y-2">
                <button disabled={!matchedTechniqueIds.length} onClick={() => addTechniques(matchedTechniqueIds)} className="primary-action w-full disabled:opacity-40">Add mapped TTPs</button>
                <button disabled={!matchedTechniqueIds.length} onClick={showOnMatrix} className="secondary-action w-full disabled:opacity-40">Show mapped TTPs on Matrix</button>
                <button onClick={() => navigator.clipboard.writeText(value)} className="secondary-action w-full">Copy node value</button>
              </div>
            </Panel>
          </section>

          {canSearchIocs && (
            <Panel title={`Matching IOC Library Records (${library.data?.total ?? 0})`}>
              {library.isLoading && <Empty text="Searching local IOC library..." />}
              {library.error && <ErrorBox error={library.error} />}
              {!library.isLoading && !library.error && !library.data?.items.length && <Empty text="No local IOC records match this node yet." />}
              <div className="space-y-2">
                {library.data?.items.map(item => (
                  <article
                    key={item.id}
                    className="w-full rounded border border-gray-800 bg-gray-950/50 p-3 text-left"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0 flex flex-wrap items-center gap-2">
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">{item.type}</span>
                        <IocLink value={item.value} type={item.type} source={item.source} className="break-all font-mono text-sm text-white hover:text-cyan-200 hover:underline" />
                      </div>
                      <button type="button" onClick={() => navigate(`/ioc-library/${item.id}`)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Open record</button>
                    </div>
                    <div className="mt-1 text-[11px] text-gray-500">{item.source} · confidence {item.confidence} · last seen {item.last_seen || '-'}</div>
                    {item.description && <p className="mt-2 line-clamp-2 text-xs text-gray-400">{item.description}</p>}
                    {item.technique_ids.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {item.technique_ids.slice(0, 12).map(id => (
                          <TtpLink key={id} id={id} className="rounded bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent/20" />
                        ))}
                      </div>
                    )}
                  </article>
                ))}
              </div>
            </Panel>
          )}

          {relationshipInvestigation.data && (
            <RelationshipGraph
              result={relationshipInvestigation.data}
              canRunAnalysis={canRunAnalysis}
              onPivotNode={node => {
                if (OBSERVABLE_TYPES.has(node.type)) {
                  navigate(`/ioc-node?type=${encodeURIComponent(node.type)}&value=${encodeURIComponent(node.value)}&tier=${node.tier}&sources=${encodeURIComponent(node.sources.join(','))}`);
                }
              }}
            />
          )}
          {!canRunAnalysis && isObservable && (
            <PermissionNotice permission="run_analysis" action="expand this IOC relationship investigation" />
          )}
        </div>
      </div>
    </div>
  );
}

function nodeSummary(type: string, value: string) {
  if (!value) return 'This page was opened without a node value.';
  if (NETWORK_FINGERPRINT_TYPES.has(type)) return 'Network fingerprint observable. Use this page to pivot into local IOC records, reports, related infrastructure, and technique mappings from the source evidence.';
  if (OBSERVABLE_TYPES.has(type)) return 'Observable node. Use this page to pivot into IOC Library records, enrichment, VirusTotal lookup, and a deeper IOC investigation.';
  if (type === 'file') return 'File artifact node. Use this page to search local IOC records and pivot to hashes or report evidence when available.';
  if (type === 'report' || type === 'collection') return 'Collection or report node. Use it as source context for the related observables and evidence, not as direct attribution.';
  if (type === 'actor') return 'Actor lead node. It can help pivot into ATT&CK group context, but it should not be treated as attribution without source-backed evidence.';
  if (type === 'suspicious-pattern') return 'Behavior pattern node from investigation enrichment. Use it as a clue for TTP mapping and maliciousness assessment.';
  if (type === 'tag' || type === 'classification' || type === 'reputation') return 'Context node from an enrichment source. It can support triage but usually needs another source before a firm conclusion.';
  return 'Relationship graph node. Use the source context and matching IOC records to decide whether this is an actionable pivot.';
}

function maliciousAnswer(type: string) {
  if (['malware', 'suspicious-pattern', 'reputation', 'vulnerability'].includes(type)) return 'suspicious lead';
  if (OBSERVABLE_TYPES.has(type)) return 'needs enrichment';
  return 'context';
}

function maliciousWhy(type: string, value: string) {
  if (['malware', 'suspicious-pattern', 'reputation', 'vulnerability'].includes(type)) {
    return `${value} has security-relevant context by node type. Validate the original source before marking it malicious.`;
  }
  if (NETWORK_FINGERPRINT_TYPES.has(type)) {
    return `${value} is a network fingerprint. It is useful for clustering traffic or infrastructure, but it becomes malicious only when source evidence, report context, or related observables support that conclusion.`;
  }
  if (OBSERVABLE_TYPES.has(type)) {
    return `${value} is an observable. It becomes malicious only when enrichment, reports, sandbox behavior, or source reputation supports that conclusion.`;
  }
  return `${value || 'This node'} is context for pivoting. It is not enough by itself to assess maliciousness.`;
}

function sourceRef(sources: string[]) {
  return sources.length ? sources.join(', ') : 'No source metadata was provided in the node URL.';
}

function Question({ title, answer, refText, children }: { title: string; answer: string; refText: string; children: ReactNode }) {
  return (
    <div className="mb-3 rounded border border-gray-800 bg-gray-950/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-gray-200">{title}</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{answer}</span>
      </div>
      <p className="mt-2 text-sm leading-6 text-gray-400">{children}</p>
      <div className="mt-2 break-all text-[10px] text-gray-600">Ref. {refText}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Empty({ text }: { text: string }) {
  return <p className="text-sm text-gray-600">{text}</p>;
}

function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

function ContextCard({ title, loading, error, children }: { title: string; loading?: boolean; error?: unknown; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <div className="mt-3">
        {loading ? <Empty text="Loading..." /> : error ? <ErrorBox error={error} /> : children}
      </div>
    </section>
  );
}

function Metric({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded border border-gray-800 bg-gray-950/60 px-2 py-1.5">
      <span className="text-[10px] uppercase tracking-wide text-gray-600">{label}</span>
      <span className="break-all text-right text-xs text-gray-200">{value}</span>
    </div>
  );
}
