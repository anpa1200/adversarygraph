import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { AddToInvestigationButton } from '@/components/AddToInvestigationButton';
import { iocApi, type IOCInvestigationHistoryItem, type IOCInvestigationResult } from '@/api/client';
import { useAppStore } from '@/store';
import { TtpLink } from '@/utils/ctiLinks';
import clsx from 'clsx';
import * as d3 from 'd3';
import { safeHref } from '@/utils/url';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

export function IOCInvestigation() {
  const navigate = useNavigate();
  const canRunAnalysis = useHasPermission('run_analysis');
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const { domain, replaceTechniques, addTechniques } = useAppStore();
  const [artifact, setArtifact] = useState(params.get('indicator') ?? '');
  const [depth, setDepth] = useState(2);
  const [aiSummarize, setAiSummarize] = useState(false);
  const [provider, setProvider] = useState<'local' | 'claude' | 'openai' | 'gemini' | 'minimax'>('local');
  const [loadedResult, setLoadedResult] = useState<IOCInvestigationResult | null>(null);
  const [deletedSessionIds, setDeletedSessionIds] = useState<Set<string>>(new Set());
  const history = useQuery({
    queryKey: ['ioc-investigations'],
    queryFn: () => iocApi.investigations(75, 0),
    staleTime: 15_000,
  });
  const mutation = useMutation({
    mutationFn: (nextArtifact?: string) => iocApi.investigate({
      artifact: (nextArtifact ?? artifact).trim(),
      domain,
      depth,
      max_tier_nodes: 25,
      ai_summarize: aiSummarize,
      ai_provider: provider,
    }),
    onMutate: () => {
      setLoadedResult(null);
    },
    onSuccess: (data, requestedArtifact) => {
      if (requestedArtifact) setArtifact(requestedArtifact);
      if (data.session_id) {
        setDeletedSessionIds(previous => {
          const next = new Set(previous);
          next.delete(data.session_id as string);
          return next;
        });
      }
      queryClient.invalidateQueries({ queryKey: ['ioc-investigations'] });
    },
  });
  const loadInvestigation = useMutation({
    mutationFn: iocApi.investigation,
    onSuccess: data => {
      setLoadedResult(data);
      setArtifact(data.artifact);
      setDepth(data.depth);
      if (data.session_id) {
        setDeletedSessionIds(previous => {
          const next = new Set(previous);
          next.delete(data.session_id as string);
          return next;
        });
      }
    },
  });
  const deleteInvestigation = useMutation({
    mutationFn: iocApi.deleteInvestigation,
    onSuccess: (_data, sessionId) => {
      setDeletedSessionIds(previous => new Set(previous).add(sessionId));
      if (loadedResult?.session_id === sessionId || mutation.data?.session_id === sessionId) {
        setLoadedResult(null);
      }
      queryClient.invalidateQueries({ queryKey: ['ioc-investigations'] });
    },
  });
  const rawResult = loadedResult ?? mutation.data;
  const result = rawResult?.session_id && deletedSessionIds.has(rawResult.session_id) ? null : rawResult;
  const techniqueIds = useMemo(() => result?.techniques.map(item => item.attack_id) ?? [], [result]);
  const resetIocMutation = mutation.reset;

  useEffect(() => {
    const value = params.get('indicator')?.trim();
    if (value && value !== artifact) {
      setArtifact(value);
      setLoadedResult(null);
      resetIocMutation();
    }
  }, [artifact, params, resetIocMutation]);

  const showOnMatrix = () => {
    replaceTechniques(techniqueIds);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="IOC Investigation" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
              <div>
                <h2 className="text-base font-semibold text-white">Investigate artifact relationships and ATT&CK context</h2>
                <p className="mt-2 max-w-4xl text-sm text-gray-400">
                  Enter an IP, domain, URL, hash, or suspicious artifact. AdversaryGraph queries configured enrichment sources,
                  expands Tier 1, Tier 2, and Tier 3 relationships, maps TTP/actor leads, and prepares an AI-ready investigation summary.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  {!canRunAnalysis && <PermissionNotice permission="run_analysis" action="run or delete IOC investigations" compact />}
                  <input
                    disabled={!canRunAnalysis}
                    value={artifact}
                    onChange={event => setArtifact(event.target.value)}
                    onKeyDown={event => {
                      if (canRunAnalysis && event.key === 'Enter' && artifact.trim()) mutation.mutate(undefined);
                    }}
                    placeholder="IP, domain, URL, MD5, SHA1, SHA256, or artifact..."
                    className="min-w-[360px] flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent"
                  />
                  <select disabled={!canRunAnalysis} value={depth} onChange={event => setDepth(Number(event.target.value))} className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200">
                    <option value={1}>Tier 1 only</option>
                    <option value={2}>Tier 1 + Tier 2</option>
                    <option value={3}>Tier 1 + Tier 2 + Tier 3</option>
                  </select>
                  <select value={provider} onChange={event => setProvider(event.target.value as typeof provider)} disabled={!canRunAnalysis || !aiSummarize} className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 disabled:opacity-50">
                    <option value="local">Local LLM</option>
                    <option value="claude">Claude</option>
                    <option value="openai">OpenAI</option>
                    <option value="gemini">Gemini</option>
                    <option value="minimax">MiniMax</option>
                  </select>
                  <label className="inline-flex items-center gap-2 rounded border border-gray-700 px-3 py-2 text-sm text-gray-300">
                    <input type="checkbox" disabled={!canRunAnalysis} checked={aiSummarize} onChange={event => setAiSummarize(event.target.checked)} />
                    AI summary
                  </label>
                  <button
                    type="button"
                    disabled={!canRunAnalysis || !artifact.trim() || mutation.isPending}
                    onClick={() => mutation.mutate(undefined)}
                    className="rounded bg-mitre-accent px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {mutation.isPending ? 'Investigating...' : 'Investigate'}
                  </button>
                </div>
                {(mutation.error || loadInvestigation.error || deleteInvestigation.error) && (
                  <ErrorBox error={mutation.error || loadInvestigation.error || deleteInvestigation.error} />
                )}
              </div>
              <div className="space-y-3">
                <div className="rounded border border-gray-800 bg-black/30 p-3 text-xs text-gray-400">
                  <div className="font-semibold text-gray-200">Investigation targets</div>
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    {['IOC type', 'Tier 1 pivots', 'Tier 2 pivots', 'Tier 3 pivots', 'urlscan activity', 'TTPs', 'Kill chain', 'Actor/APT leads', 'Source evidence', 'AI report input'].map(item => (
                      <div key={item} className="rounded border border-gray-800 bg-gray-950/70 px-2 py-1">{item}</div>
                    ))}
                  </div>
                </div>
                <PreviousInvestigations
                  items={history.data ?? []}
                  loading={history.isLoading}
                  activeSessionId={result?.session_id ?? null}
                  loadingSessionId={loadInvestigation.variables ?? null}
                  deletingSessionId={deleteInvestigation.variables ?? null}
                  canDelete={canRunAnalysis}
                  onOpen={sessionId => loadInvestigation.mutate(sessionId)}
                  onDelete={sessionId => {
                    if (window.confirm('Delete this IOC investigation?')) {
                      deleteInvestigation.mutate(sessionId);
                    }
                  }}
                />
              </div>
            </div>
          </section>

          {result && (
            <>
              <InvestigationSummary result={result} />
              <InvestigationIntelligence result={result} />
              <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
                <section className="space-y-5">
                  <SourceResults result={result} />
                  <RelationshipGraph
                    result={result}
                    canRunAnalysis={canRunAnalysis}
                    onPivotNode={node => {
                      setLoadedResult(null);
                      mutation.mutate(node.value);
                    }}
                  />
                </section>
                <aside className="space-y-5">
                  <Actions
                    result={result}
                    techniqueIds={techniqueIds}
                    onShowMatrix={showOnMatrix}
                    onAddTtps={() => addTechniques(techniqueIds)}
                  />
                  <TtpPanel result={result} />
                  <ActorPanel result={result} />
                  <KillChainPanel result={result} />
                </aside>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function InvestigationSummary({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className={clsx('rounded px-2 py-1 text-xs font-bold uppercase', scoreClass(result.suspicion_score))}>{result.verdict}</span>
        <span className="text-sm text-gray-400">Score</span>
        <span className="text-lg font-bold text-white">{result.suspicion_score}/100</span>
        <span className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300">{result.artifact_type}</span>
        <span className="break-all font-mono text-sm text-gray-200">{result.artifact}</span>
      </div>
      <p className="mt-3 text-sm leading-6 text-gray-300">{result.summary}</p>
      {result.ai_error && (
        <p className="mt-3 rounded border border-amber-700/60 bg-amber-950/20 p-2 text-xs leading-5 text-amber-200">
          AI summary failed, but enrichment completed. {result.ai_error}
        </p>
      )}
    </section>
  );
}

function InvestigationIntelligence({ result }: { result: IOCInvestigationResult }) {
  const evidence = useMemo(() => rankEvidence(result), [result]);
  const pivots = useMemo(() => rankPivots(result), [result]);
  const timeline = useMemo(() => extractTimeline(result), [result]);
  const conflicts = useMemo(() => sourceConflicts(result), [result]);

  return (
    <section className="grid gap-4 xl:grid-cols-4">
      <IntelligenceCard title="Evidence Ranking" subtitle="Strongest source-backed relations first">
        <div className="space-y-2">
          {evidence.slice(0, 6).map(item => (
            <div key={`${item.source}-${item.target}-${item.score}`} className="rounded border border-gray-800 bg-gray-950/50 p-2">
              <div className="flex items-center justify-between gap-2">
                <span className="rounded bg-mitre-accent/10 px-1.5 py-0.5 text-[10px] font-semibold text-mitre-accent">{item.score}</span>
                <span className="truncate text-[10px] text-gray-500">{item.source} · T{item.tier}</span>
              </div>
              <div className="mt-1 break-all text-xs font-semibold text-gray-200">{item.target}</div>
              <div className="mt-1 text-[11px] leading-4 text-gray-500">{item.reason}</div>
              {item.ref && <div className="mt-1 break-all text-[10px] text-gray-600">Ref. {item.ref}</div>}
            </div>
          ))}
          {!evidence.length && <Empty text="No relationship evidence found yet." />}
        </div>
      </IntelligenceCard>

      <IntelligenceCard title="Next Best Pivots" subtitle="Useful nodes to investigate next">
        <PivotList pivots={pivots.slice(0, 7)} />
      </IntelligenceCard>

      <IntelligenceCard title="Timeline" subtitle="First/last seen and source dates">
        <div className="space-y-2">
          {timeline.slice(0, 7).map(item => (
            <div key={`${item.date}-${item.source}-${item.label}`} className="rounded border border-gray-800 bg-gray-950/50 p-2">
              <div className="font-mono text-[10px] text-mitre-accent">{item.date}</div>
              <div className="mt-1 text-xs text-gray-200">{item.label}</div>
              <div className="text-[10px] text-gray-600">{item.source}</div>
            </div>
          ))}
          {!timeline.length && <Empty text="No dates were found in enrichment data." />}
        </div>
      </IntelligenceCard>

      <IntelligenceCard title="Source Conflicts" subtitle="Agreement and disagreement">
        <div className="space-y-2">
          {conflicts.map(item => (
            <div key={item.label} className="rounded border border-gray-800 bg-gray-950/50 p-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-gray-200">{item.label}</span>
                <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-semibold', item.level === 'warning' ? 'bg-amber-950 text-amber-300' : item.level === 'bad' ? 'bg-red-950 text-red-300' : 'bg-green-950 text-green-300')}>
                  {item.level}
                </span>
              </div>
              <p className="mt-1 text-[11px] leading-4 text-gray-500">{item.detail}</p>
            </div>
          ))}
        </div>
      </IntelligenceCard>
    </section>
  );
}

function IntelligenceCard({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        <p className="mt-1 text-[11px] text-gray-500">{subtitle}</p>
      </div>
      <div className="max-h-[380px] overflow-y-auto p-3">{children}</div>
    </section>
  );
}

function PivotList({ pivots }: { pivots: PivotItem[] }) {
  const navigate = useNavigate();
  return (
    <div className="space-y-2">
      {pivots.map(item => (
        <div key={`${item.type}-${item.value}`} className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <div className="flex items-center justify-between gap-2">
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{item.type}</span>
            <span className="rounded bg-mitre-accent/10 px-1.5 py-0.5 text-[10px] font-semibold text-mitre-accent">{item.score}</span>
          </div>
          <div className="mt-1 break-all font-mono text-xs text-gray-200">{item.value}</div>
          <div className="mt-1 text-[11px] leading-4 text-gray-500">{item.reason}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            <button type="button" onClick={() => navigate(nodeDetailUrl(item))} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Open</button>
            {['ioc', 'ip', 'domain', 'url', 'hash'].includes(item.type) && (
              <button type="button" onClick={() => navigate(`/ioc-investigation?indicator=${encodeURIComponent(item.value)}`)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Investigate</button>
            )}
          </div>
        </div>
      ))}
      {!pivots.length && <Empty text="No useful pivot candidates found." />}
    </div>
  );
}

function Actions({ result, techniqueIds, onShowMatrix, onAddTtps }: { result: IOCInvestigationResult; techniqueIds: string[]; onShowMatrix: () => void; onAddTtps: () => void }) {
  const navigate = useNavigate();
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">Actions</h3>
      <div className="mt-3 grid gap-2">
        <AddToInvestigationButton
          payload={{
            label: `IOC investigation ${result.artifact}`,
            domain: 'enterprise-attack',
            techniqueIds,
            actorIds: result.actors.map(item => item.attack_id).filter(Boolean),
            reportIds: result.session_id ? [result.session_id] : [],
            evidenceNodes: [
              {
                id: `ioc-investigation:${result.session_id || result.artifact}`,
                type: 'ioc-investigation',
                value: result.artifact,
                label: result.artifact,
                artifact_type: result.artifact_type,
                verdict: result.verdict,
                suspicion_score: result.suspicion_score,
                summary: result.summary,
                source: 'ioc-investigation',
                source_ref: `ioc-investigation:${result.session_id || result.artifact}`,
                sources: result.sources.map(source => ({ source: source.source, status: source.status, summary: source.summary })),
              },
              {
                id: `ioc:${result.artifact}`,
                type: 'ioc',
                value: result.artifact,
                ioc_type: result.artifact_type,
                source: 'ioc-investigation',
                source_ref: `ioc-investigation:${result.session_id || result.artifact}`,
                description: result.summary,
                verdict: result.verdict,
                suspicion_score: result.suspicion_score,
              },
              ...result.techniques.slice(0, 120).map(item => ({
                id: `ttp-evidence:${result.session_id || result.artifact}:${item.attack_id}`,
                type: 'ttp-evidence',
                attack_id: item.attack_id,
                label: `${item.attack_id} ${item.name || 'Technique lead'}`,
                source: 'ioc-investigation',
                source_ref: `ioc-investigation:${result.session_id || result.artifact}`,
                tactic: item.tactics.join(', '),
                evidence: item.evidence_sources?.join('; ') || result.summary,
                references: item.evidence_sources ?? [],
              })),
              ...result.relationships.nodes.slice(0, 120).map(node => ({
                ...node,
                id: `ioc-node:${node.id}`,
              })),
            ],
            evidenceEdges: result.relationships.edges.slice(0, 200).map(edge => ({
              ...edge,
              id: `ioc-edge:${edge.source}->${edge.target}:${edge.type}`,
            })),
            timelineEvent: `Added IOC investigation for ${result.artifact}`,
          }}
          disabled={!techniqueIds.length && !result.relationships.nodes.length}
          className="secondary-action disabled:opacity-40"
        />
        <button disabled={!techniqueIds.length} onClick={onShowMatrix} className="primary disabled:opacity-40">Show TTPs on Matrix</button>
        <button disabled={!techniqueIds.length} onClick={onAddTtps} className="secondary-action disabled:opacity-40">Add TTPs to My TTPs</button>
        <button onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(result.artifact)}`)} className="secondary-action">Search IOC Library</button>
        <button onClick={() => navigate(`/virustotal?indicator=${encodeURIComponent(result.artifact)}`)} className="secondary-action">Open VirusTotal Lookup</button>
      </div>
    </section>
  );
}

function PreviousInvestigations({
  items,
  loading,
  activeSessionId,
  loadingSessionId,
  deletingSessionId,
  canDelete,
  onOpen,
  onDelete,
}: {
  items: IOCInvestigationHistoryItem[];
  loading: boolean;
  activeSessionId: string | null;
  loadingSessionId: string | null;
  deletingSessionId: string | null;
  canDelete: boolean;
  onOpen: (sessionId: string) => void;
  onDelete: (sessionId: string) => void;
}) {
  return (
    <section className="rounded border border-gray-800 bg-black/30">
      <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2">
        <div className="text-xs font-semibold text-gray-200">Previous investigations</div>
        <span className="text-[10px] text-gray-600">{items.length}</span>
      </div>
      <div className="max-h-72 overflow-y-auto">
        {loading && <div className="p-3 text-xs text-gray-600">Loading saved investigations...</div>}
        {!loading && !items.length && (
          <div className="p-3 text-xs leading-5 text-gray-600">
            Completed IOC investigations will be saved here for review, reuse, and deletion.
          </div>
        )}
        {items.map(item => {
          const isActive = activeSessionId === item.session_id;
          const isLoading = loadingSessionId === item.session_id;
          const isDeleting = deletingSessionId === item.session_id;
          return (
            <div key={item.session_id} className={clsx('border-b border-gray-900 p-3', isActive ? 'bg-mitre-accent/10' : 'hover:bg-gray-900/50')}>
              <button
                type="button"
                onClick={() => onOpen(item.session_id)}
                disabled={isLoading || isDeleting}
                className="w-full text-left"
              >
                <div className="flex items-center gap-2">
                  <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase', scoreClass(item.suspicion_score))}>{item.verdict}</span>
                  {isActive && <span className="text-[10px] text-mitre-accent">open</span>}
                </div>
                <div className="mt-2 break-all font-mono text-xs text-gray-200">{item.artifact}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[10px] text-gray-600">
                  <span>{item.artifact_type}</span>
                  <span>T{item.depth}</span>
                  <span>{item.suspicion_score}/100</span>
                  <span>{item.technique_count} TTPs</span>
                  <span>{item.actor_count} actors</span>
                </div>
              </button>
              <div className="mt-2 flex items-center gap-2">
                <span className="truncate text-[10px] text-gray-600">{new Date(item.created_at).toLocaleString()}</span>
                {canDelete && <button
                  type="button"
                  onClick={() => onDelete(item.session_id)}
                  disabled={isDeleting}
                  className="ml-auto text-[10px] text-gray-600 hover:text-red-400 disabled:opacity-40"
                >
                  {isDeleting ? 'Deleting...' : 'Delete'}
                </button>}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function SourceResults({ result }: { result: IOCInvestigationResult }) {
  const pivotSources = [...result.tier2_sources, ...(result.tier3_sources ?? [])] as unknown as IOCInvestigationResult['sources'];
  const rows = [...result.sources, ...pivotSources];
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Enrichment Sources</h3>
      </div>
      <div className="divide-y divide-gray-800">
        {rows.map((source, index) => (
          <div key={`${source.source}-${index}`} className="grid gap-3 p-4 lg:grid-cols-[180px_1fr_auto]">
            <div>
              <div className="font-semibold text-white">{source.source}</div>
              <span className={clsx('mt-2 inline-block rounded px-2 py-1 text-[11px] font-bold', statusClass(source.status))}>{source.status}</span>
            </div>
            <div className="text-sm text-gray-300">
              <div>{source.summary}</div>
              {source.error && <div className="mt-2 text-xs text-red-300">{source.error}</div>}
              <UrlscanActivity source={source} />
            </div>
            <div className="text-right text-xs text-gray-500">
              <div>{source.relationships?.length ?? 0} relations</div>
              <div>{source.technique_ids?.length ?? 0} TTPs</div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function UrlscanActivity({ source }: { source: IOCInvestigationResult['sources'][number] }) {
  if (source.source !== 'urlscan') return null;
  const activity = source.raw?.activity_analysis as {
    mode?: string;
    summary?: string;
    findings?: Array<{ severity?: string; pattern?: string; evidence?: string; rationale?: string }>;
    technique_ids?: string[];
    ai_error?: string;
  } | undefined;
  if (!activity) return null;
  return (
    <div className="mt-3 rounded border border-gray-800 bg-gray-950/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-white">urlscan activity analysis</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-400">{activity.mode || 'heuristic'}</span>
        {(activity.technique_ids ?? []).map(id => (
          <TtpLink key={id} id={id} className="rounded bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent/20" />
        ))}
      </div>
      {activity.summary && <p className="mt-2 text-xs leading-5 text-gray-400">{activity.summary}</p>}
      {activity.ai_error && <p className="mt-2 text-[10px] text-amber-300">AI urlscan analysis fallback: {activity.ai_error}</p>}
      {(activity.findings ?? []).length > 0 && (
        <div className="mt-2 space-y-2">
          {(activity.findings ?? []).slice(0, 6).map((finding, index) => (
            <div key={`${finding.pattern}-${index}`} className="rounded border border-gray-800 bg-black/30 p-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className={clsx('rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase', finding.severity === 'high' ? 'bg-red-950 text-red-300' : finding.severity === 'medium' ? 'bg-amber-950 text-amber-300' : 'bg-gray-800 text-gray-400')}>
                  {finding.severity || 'info'}
                </span>
                <span className="text-xs font-semibold text-gray-200">{finding.pattern || 'suspicious pattern'}</span>
              </div>
              {finding.evidence && <p className="mt-1 text-[11px] text-gray-400">{finding.evidence}</p>}
              {finding.rationale && <p className="mt-1 text-[10px] text-gray-600">{finding.rationale}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type GraphNode = IOCInvestigationResult['relationships']['nodes'][number] & d3.SimulationNodeDatum;
type RelationshipEdge = IOCInvestigationResult['relationships']['edges'][number];
type GraphLink = Omit<RelationshipEdge, 'source' | 'target'> & d3.SimulationLinkDatum<GraphNode> & {
  source: GraphNode;
  target: GraphNode;
  index: number;
};
type EvidenceItem = { target: string; source: string; tier: number; score: number; reason: string; ref: string };
type PivotItem = Pick<GraphNode, 'type' | 'value' | 'tier' | 'sources'> & { score: number; reason: string };
type TimelineItem = { date: string; source: string; label: string };
type ConflictItem = { label: string; detail: string; level: 'ok' | 'warning' | 'bad' };

function rankEvidence(result: IOCInvestigationResult): EvidenceItem[] {
  const sourceCounts = new Map<string, number>();
  result.relationships.edges.forEach(edge => {
    sourceCounts.set(edge.target.toLowerCase(), (sourceCounts.get(edge.target.toLowerCase()) ?? 0) + 1);
  });
  return result.relationships.edges
    .map(edge => {
      const evidenceText = `${edge.type} ${edge.evidence} ${edge.evidence_source}`;
      let score = sourceReliability(edge.evidence_source);
      score += Math.max(0, 18 - edge.tier * 4);
      score += Math.min(18, (sourceCounts.get(edge.target.toLowerCase()) ?? 1) * 4);
      if (['malware', 'actor', 'report', 'suspicious-pattern', 'vulnerability', 'hash'].includes(edge.type)) score += 16;
      if (/malicious|ransom|phish|c2|command.?and.?control|payload|exploit|abuse|botnet|trojan/i.test(evidenceText)) score += 18;
      if (['tag', 'name', 'classification'].includes(edge.type)) score -= 14;
      score = clamp(score, 1, 100);
      return {
        target: edge.target,
        source: edge.evidence_source || 'unknown',
        tier: edge.tier,
        score,
        reason: evidenceReason(edge),
        ref: edge.evidence || `${edge.source} -> ${edge.target}`,
      };
    })
    .sort((a, b) => b.score - a.score || a.tier - b.tier);
}

function rankPivots(result: IOCInvestigationResult): PivotItem[] {
  const evidenceByTarget = new Map<string, EvidenceItem[]>();
  for (const item of rankEvidence(result)) {
    const key = item.target.toLowerCase();
    evidenceByTarget.set(key, [...(evidenceByTarget.get(key) ?? []), item]);
  }
  return result.relationships.nodes
    .filter(node => node.tier > 0 && isActionableGraphNode(node))
    .map(node => {
      const evidence = evidenceByTarget.get(node.value.toLowerCase()) ?? [];
      let score = Math.max(...evidence.map(item => item.score), 0);
      score += node.sources.length * 4;
      if (['ip', 'domain', 'url', 'hash', 'malware', 'actor', 'suspicious-pattern'].includes(node.type) || NETWORK_FINGERPRINT_TYPES.has(node.type)) score += 12;
      if (node.tier >= 3) score -= 12;
      score = clamp(score, 1, 100);
      return {
        type: node.type,
        value: node.value,
        tier: node.tier,
        sources: node.sources,
        score,
        reason: pivotReason(node, evidence),
      };
    })
    .sort((a, b) => b.score - a.score || a.tier - b.tier)
    .filter((item, index, all) => all.findIndex(other => other.type === item.type && other.value.toLowerCase() === item.value.toLowerCase()) === index);
}

function extractTimeline(result: IOCInvestigationResult): TimelineItem[] {
  const items: TimelineItem[] = [];
  const sources = [...result.sources, ...result.tier2_sources, ...(result.tier3_sources ?? [])] as IOCInvestigationResult['sources'];
  for (const source of sources) {
    const raw = source.raw ?? {};
    collectDateStrings(raw).slice(0, 8).forEach(date => {
      items.push({ date, source: source.source, label: source.summary || 'Source timestamp' });
    });
  }
  return items
    .filter((item, index, all) => all.findIndex(other => other.date === item.date && other.source === item.source && other.label === item.label) === index)
    .sort((a, b) => b.date.localeCompare(a.date));
}

function sourceConflicts(result: IOCInvestigationResult): ConflictItem[] {
  const sources = result.sources;
  const ok = sources.filter(item => item.status === 'ok').map(item => item.source);
  const failed = sources.filter(item => ['error', 'failed'].includes(item.status)).map(item => item.source);
  const skipped = sources.filter(item => item.status === 'skipped').map(item => item.source);
  const rawText = JSON.stringify(sources.map(item => ({ source: item.source, summary: item.summary, raw: item.raw }))).toLowerCase();
  const hasBad = /malicious|ransom|phish|c2|botnet|trojan|abuse|suspicious/.test(rawText) || result.suspicion_score >= 60;
  const hasBenign = /benign|known scanner|search engine|cdn|parking|clean/.test(rawText);
  const conflicts: ConflictItem[] = [
    {
      label: 'Source coverage',
      level: ok.length ? 'ok' : 'warning',
      detail: ok.length ? `${ok.length} source(s) returned data: ${ok.join(', ')}.` : 'No enrichment source returned positive data.',
    },
  ];
  if (hasBad && hasBenign) {
    conflicts.push({
      label: 'Mixed reputation',
      level: 'warning',
      detail: 'At least one source contains suspicious/malicious wording while another contains benign/clean wording. Review source priority before conclusion.',
    });
  } else if (hasBad) {
    conflicts.push({
      label: 'Suspicious consensus',
      level: result.suspicion_score >= 75 ? 'bad' : 'warning',
      detail: `Suspicious context exists and the current score is ${result.suspicion_score}/100.`,
    });
  } else {
    conflicts.push({
      label: 'No strong malicious wording',
      level: 'ok',
      detail: 'No strong malicious keyword signal was found in available source summaries.',
    });
  }
  if (failed.length) conflicts.push({ label: 'Failed sources', level: 'warning', detail: `${failed.join(', ')} did not complete. Missing sources can hide useful context.` });
  if (skipped.length) conflicts.push({ label: 'Skipped sources', level: 'ok', detail: `${skipped.length} source(s) were skipped because they do not apply to this IOC type or are not configured.` });
  return conflicts;
}

function evidenceReason(edge: RelationshipEdge) {
  if (edge.type === 'actor') return 'Actor lead relation. Useful for hypothesis generation, not attribution.';
  if (edge.type === 'malware') return 'Malware-family relation. Prioritize if confirmed by more than one source.';
  if (edge.type === 'suspicious-pattern') return 'Behavioral pattern from analysis. Review page activity or sandbox evidence.';
  if (NETWORK_FINGERPRINT_TYPES.has(edge.type)) return 'Network fingerprint pivot. Use it for clustering traffic or infrastructure when source evidence is recent.';
  if (['ip', 'domain', 'url', 'hash'].includes(edge.type)) return 'Observable pivot. Investigate if recent or confirmed by multiple sources.';
  if (edge.type === 'vulnerability' || edge.type.includes('port')) return 'Infrastructure exposure context. Useful for attack-surface pivots.';
  return 'Context relation. Lower confidence unless supported by additional evidence.';
}

function pivotReason(node: Pick<GraphNode, 'type' | 'tier' | 'sources'>, evidence: EvidenceItem[]) {
  const sourceText = node.sources.join(', ') || 'unknown source';
  const evidenceText = evidence.length ? `${evidence.length} supporting relation(s)` : 'no direct evidence row';
  return `Tier ${node.tier} ${node.type} pivot from ${sourceText}; ${evidenceText}.`;
}

function sourceReliability(source: string) {
  const normalized = source.toLowerCase();
  if (normalized.includes('local-db') || normalized.includes('manual') || normalized.includes('opencti') || normalized.includes('misp')) return 42;
  if (normalized.includes('virustotal') || normalized.includes('threatfox') || normalized.includes('malwarebazaar')) return 38;
  if (normalized.includes('urlscan') || normalized.includes('greynoise') || normalized.includes('abuseipdb') || normalized.includes('censys') || normalized.includes('shodan')) return 32;
  if (normalized.includes('otx')) return 26;
  return 20;
}

function collectDateStrings(value: unknown): string[] {
  const seen = new Set<string>();
  const dates: string[] = [];
  const visit = (item: unknown) => {
    if (dates.length > 80 || item == null) return;
    if (typeof item === 'string') {
      const matches = item.match(/\b20\d{2}-\d{2}-\d{2}(?:[T ][0-2]\d:[0-5]\d(?::[0-5]\d)?Z?)?\b/g) ?? [];
      matches.forEach(match => {
        const normalized = match.replace(' ', 'T');
        if (!seen.has(normalized)) {
          seen.add(normalized);
          dates.push(normalized);
        }
      });
      return;
    }
    if (typeof item === 'number' && item > 946684800 && item < 4102444800) {
      const normalized = new Date(item * 1000).toISOString().slice(0, 19);
      if (!seen.has(normalized)) {
        seen.add(normalized);
        dates.push(normalized);
      }
      return;
    }
    if (Array.isArray(item)) item.slice(0, 80).forEach(visit);
    else if (typeof item === 'object') Object.values(item as Record<string, unknown>).slice(0, 80).forEach(visit);
  };
  visit(value);
  return dates;
}

function clamp(value: number, min: number, max: number) {
  return Math.max(min, Math.min(max, Math.round(value)));
}

export function RelationshipGraph({
  result,
  onPivotNode,
  canRunAnalysis,
}: {
  result: IOCInvestigationResult;
  onPivotNode: (node: GraphNode) => void;
  canRunAnalysis: boolean;
}) {
  const navigate = useNavigate();
  const { domain } = useAppStore();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(result.relationships.nodes[0]?.id ?? null);
  const [selectedEdgeIndex, setSelectedEdgeIndex] = useState<number | null>(null);
  const [tierFilter, setTierFilter] = useState<'all' | '0' | '1' | '2' | '3'>('all');
  const [typeFilter, setTypeFilter] = useState('actionable');
  const [focusNodeId, setFocusNodeId] = useState<string | null>(null);
  const [expandedResults, setExpandedResults] = useState<Record<string, IOCInvestigationResult>>({});
  const expandNode = useMutation({
    mutationFn: (node: GraphNode) => iocApi.investigate({
      artifact: node.value,
      domain,
      depth: 2,
      max_tier_nodes: 35,
      ai_summarize: false,
      ai_provider: 'local',
    }),
    onSuccess: (data, node) => {
      setExpandedResults(previous => ({ ...previous, [node.id]: data }));
    },
  });
  const expandedList = useMemo(() => Object.values(expandedResults), [expandedResults]);
  const graphResult = useMemo(() => mergeInvestigationGraphs(result, expandedList), [expandedList, result]);
  const scoredNodes = useMemo(
    () => graphResult.relationships.nodes.map(node => ({
      ...node,
      suspicious: effectiveNodeRisk(node, graphResult, graphResult.relationships.edges),
    })),
    [graphResult]
  );
  const baseNodes = useMemo(() => {
    const filtered = scoredNodes.filter(node => tierFilter === 'all' || String(node.tier) === tierFilter);
    if (typeFilter === 'all') return filtered;
    if (typeFilter === 'actionable') return filtered.filter(isActionableGraphNode);
    return filtered.filter(node => node.type === typeFilter);
  }, [scoredNodes, tierFilter, typeFilter]);
  const baseNodeKeys = useMemo(() => new Set(baseNodes.flatMap(node => [node.id, node.value.toLowerCase()])), [baseNodes]);
  const baseEdges = useMemo(() => graphResult.relationships.edges.filter(edge => {
    const targetId = graphNodeId(edge.type, edge.target);
    return baseNodeKeys.has(edge.source.toLowerCase()) && (baseNodeKeys.has(targetId) || baseNodeKeys.has(edge.target.toLowerCase()));
  }), [baseNodeKeys, graphResult.relationships.edges]);
  const nodes = useMemo(() => {
    if (!focusNodeId) return baseNodes;
    const focused = baseNodes.find(node => node.id === focusNodeId);
    if (!focused) return baseNodes;
    const connectedValues = new Set<string>([focused.id, focused.value.toLowerCase()]);
    for (const edge of baseEdges) {
      const targetId = graphNodeId(edge.type, edge.target);
      if (edge.source.toLowerCase() === focused.value.toLowerCase() || edge.source.toLowerCase() === focused.id || edge.target.toLowerCase() === focused.value.toLowerCase() || targetId === focused.id) {
        connectedValues.add(edge.source.toLowerCase());
        connectedValues.add(edge.target.toLowerCase());
        connectedValues.add(targetId);
      }
    }
    return baseNodes.filter(node => connectedValues.has(node.id) || connectedValues.has(node.value.toLowerCase()));
  }, [baseEdges, baseNodes, focusNodeId]);
  const nodeKeys = useMemo(() => new Set(nodes.flatMap(node => [node.id, node.value.toLowerCase()])), [nodes]);
  const edges = useMemo(() => baseEdges.filter(edge => {
    const targetId = graphNodeId(edge.type, edge.target);
    return nodeKeys.has(edge.source.toLowerCase()) && (nodeKeys.has(targetId) || nodeKeys.has(edge.target.toLowerCase()));
  }), [baseEdges, nodeKeys]);
  const typeOptions = useMemo(() => Array.from(new Set(scoredNodes.map(node => node.type))).sort(), [scoredNodes]);
  const hiddenContextCount = useMemo(() => scoredNodes.filter(node => !isActionableGraphNode(node)).length, [scoredNodes]);
  const selectedNode = nodes.find(node => node.id === selectedNodeId) ?? nodes[0] ?? null;
  const selectedEdge = selectedEdgeIndex == null ? null : edges[selectedEdgeIndex] ?? null;
  const selectedNodeEdges = useMemo(() => {
    if (!selectedNode) return [];
    const nodeValue = selectedNode.value.toLowerCase();
    const nodeId = selectedNode.id.toLowerCase();
    return edges.filter(edge => {
      const source = edge.source.toLowerCase();
      const target = edge.target.toLowerCase();
      const targetId = graphNodeId(edge.type, edge.target);
      return source === nodeValue || target === nodeValue || source === nodeId || targetId === nodeId;
    });
  }, [edges, selectedNode]);

  useEffect(() => {
    setSelectedNodeId(result.relationships.nodes[0]?.id ?? null);
    setSelectedEdgeIndex(null);
    setFocusNodeId(null);
    setExpandedResults({});
  }, [result.artifact, result.relationships.nodes]);

  useEffect(() => {
    const svgEl = svgRef.current;
    if (!svgEl) return;
    const width = svgEl.clientWidth || 900;
    const height = svgEl.clientHeight || 520;
    const graphNodes: GraphNode[] = nodes.map(node => ({ ...node }));
    const byId = new Map(graphNodes.map(node => [node.id, node]));
    const byValue = new Map(graphNodes.map(node => [node.value.toLowerCase(), node]));
    const graphEdges: GraphLink[] = edges
      .map((edge, index) => {
        const source = byValue.get(edge.source.toLowerCase()) ?? byId.get(graphNodeId('ioc', edge.source)) ?? byId.get(graphNodeId('artifact', edge.source));
        const target = byValue.get(edge.target.toLowerCase()) ?? byId.get(graphNodeId(edge.type, edge.target));
        return source && target ? { ...edge, source, target, index } : null;
      })
      .filter((edge): edge is GraphLink => Boolean(edge));

    const svg = d3.select(svgEl);
    svg.selectAll('*').remove();
    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const defs = svg.append('defs');
    defs.append('marker')
      .attr('id', 'relationship-arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#64748b');

    const root = svg.append('g');
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.35, 2.5])
      .on('zoom', event => root.attr('transform', event.transform.toString()));
    svg.call(zoom);

    const link = root.append('g')
      .attr('stroke', '#334155')
      .attr('stroke-opacity', 0.78)
      .selectAll<SVGLineElement, GraphLink>('line')
      .data(graphEdges)
      .join('line')
      .attr('stroke-width', edge => edge.tier >= 3 ? 0.9 : edge.tier === 2 ? 1.1 : 1.8)
      .attr('stroke-dasharray', edge => edge.tier >= 3 ? '2 5' : edge.tier === 2 ? '4 4' : null)
      .attr('marker-end', 'url(#relationship-arrow)')
      .style('cursor', 'pointer')
      .on('click', (_, edge) => {
        setSelectedEdgeIndex(edge.index);
        setSelectedNodeId(null);
      });

    const edgeLabel = root.append('g')
      .selectAll<SVGTextElement, GraphLink>('text')
      .data(graphEdges.filter(edge => edge.tier <= 1 && graphEdges.length <= 28).slice(0, 28))
      .join('text')
      .attr('font-size', 9)
      .attr('fill', '#94a3b8')
      .attr('paint-order', 'stroke')
      .attr('stroke', '#020617')
      .attr('stroke-width', 3)
      .text(edge => edge.evidence_source);

    const node = root.append('g')
      .selectAll<SVGGElement, GraphNode>('g')
      .data(graphNodes)
      .join('g')
      .style('cursor', 'pointer')
      .on('click', (_, graphNode) => {
        setSelectedNodeId(graphNode.id);
        setSelectedEdgeIndex(null);
        setFocusNodeId(graphNode.id);
        if (canRunAnalysis && isInvestigableNode(graphNode) && !expandedResults[graphNode.id]) {
          expandNode.mutate(graphNode);
        }
      })
      .call(
        d3.drag<SVGGElement, GraphNode>()
          .on('start', (event, graphNode) => {
            if (!event.active) simulation.alphaTarget(0.25).restart();
            graphNode.fx = graphNode.x;
            graphNode.fy = graphNode.y;
          })
          .on('drag', (event, graphNode) => {
            graphNode.fx = event.x;
            graphNode.fy = event.y;
          })
          .on('end', (event, graphNode) => {
            if (!event.active) simulation.alphaTarget(0);
            graphNode.fx = null;
            graphNode.fy = null;
          })
      );

    node.append('circle')
      .attr('r', nodeRadius)
      .attr('fill', nodeColor)
      .attr('stroke', node => node.id === selectedNodeId ? '#f8fafc' : '#0f172a')
      .attr('stroke-width', node => node.id === selectedNodeId ? 3 : 1.5);

    node.append('text')
      .attr('dy', node => nodeRadius(node) + 13)
      .attr('text-anchor', 'middle')
      .attr('font-size', 10)
      .attr('fill', '#dbeafe')
      .attr('paint-order', 'stroke')
      .attr('stroke', '#020617')
      .attr('stroke-width', 3)
      .text(node => nodeLabel(node, graphNodes.length));

    node.append('title').text(node => `${node.value}\n${node.type}\nTier ${node.tier}\n${node.sources.join(', ')}`);

    const simulation = d3.forceSimulation<GraphNode>(graphNodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(graphEdges).id(node => node.id).distance(edge => edge.tier >= 3 ? 125 : edge.tier === 2 ? 145 : 175).strength(0.66))
      .force('charge', d3.forceManyBody().strength(-560))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<GraphNode>().radius(node => nodeRadius(node) + 34))
      .force('tierX', d3.forceX<GraphNode>(node => width * tierPosition(node.tier)).strength(0.08))
      .force('tierY', d3.forceY(height / 2).strength(0.04));

    simulation.on('tick', () => {
      link
        .attr('x1', edge => nodeX(edge.source))
        .attr('y1', edge => nodeY(edge.source))
        .attr('x2', edge => nodeX(edge.target))
        .attr('y2', edge => nodeY(edge.target));
      edgeLabel
        .attr('x', edge => (nodeX(edge.source) + nodeX(edge.target)) / 2)
        .attr('y', edge => (nodeY(edge.source) + nodeY(edge.target)) / 2);
      node.attr('transform', graphNode => `translate(${graphNode.x ?? width / 2},${graphNode.y ?? height / 2})`);
    });

    return () => {
      simulation.stop();
    };
  }, [canRunAnalysis, edges, expandNode, expandedResults, navigate, nodes, selectedNodeId]);

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <div>
          <h3 className="text-sm font-semibold text-white">Relationship Graph</h3>
          <p className="mt-1 text-xs text-gray-500">
            Analyst-focused pivot map. Generic tags and labels are hidden by default; switch to All nodes for raw enrichment context.
          </p>
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-gray-500">
            <span>{nodes.length} visible nodes</span>
            <span>{edges.length} visible edges</span>
            {typeFilter === 'actionable' && hiddenContextCount > 0 && <span>{hiddenContextCount} context nodes hidden</span>}
            {focusNodeId && <span className="text-mitre-accent">focused on selected node</span>}
            {expandNode.isPending && <span className="text-mitre-accent">loading selected-node relationships</span>}
            {expandedList.length > 0 && <span>{expandedList.length} expanded pivot graph{expandedList.length === 1 ? '' : 's'}</span>}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          {focusNodeId && (
            <button
              type="button"
              onClick={() => setFocusNodeId(null)}
              className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:border-mitre-accent"
            >
              Clear focus
            </button>
          )}
          <select value={tierFilter} onChange={event => setTierFilter(event.target.value as typeof tierFilter)} className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200">
            <option value="all">All tiers</option>
            <option value="0">Tier 0</option>
            <option value="1">Tier 1</option>
            <option value="2">Tier 2</option>
            <option value="3">Tier 3</option>
          </select>
          <select value={typeFilter} onChange={event => setTypeFilter(event.target.value)} className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200">
            <option value="actionable">Actionable graph</option>
            <option value="all">All nodes</option>
            {typeOptions.map(type => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 px-4 py-2 text-[10px] text-gray-500">
        <LegendDot color="#38bdf8" label="No reputation" />
        <LegendDot color="#22c55e" label="Low / benign" />
        <LegendDot color="#facc15" label="Needs review" />
        <LegendDot color="#fb923c" label="Suspicious" />
        <LegendDot color="#ef4444" label="High risk" />
      </div>
      <div className="grid gap-4 p-4 xl:grid-cols-[1fr_300px]">
        <div className="min-h-[540px] overflow-hidden rounded border border-gray-800 bg-[radial-gradient(circle_at_center,#111827_0,#020617_75%)]">
          {nodes.length ? (
            <svg ref={svgRef} className="h-[540px] w-full" role="img" aria-label="IOC relationship graph" />
          ) : (
            <div className="flex h-[540px] items-center justify-center text-sm text-gray-500">No graph relationships after filters.</div>
          )}
        </div>
        <GraphInspector
          result={graphResult}
          node={selectedNode}
          edge={selectedEdge}
          connectedEdges={selectedNodeEdges}
          onOpenNode={node => navigate(nodeDetailUrl(node))}
          onFocusNode={node => {
            setTypeFilter('all');
            setTierFilter('all');
            setSelectedNodeId(node.id);
            setSelectedEdgeIndex(null);
            setFocusNodeId(node.id);
            if (canRunAnalysis && isInvestigableNode(node) && !expandedResults[node.id]) {
              expandNode.mutate(node);
            }
          }}
          canRunAnalysis={canRunAnalysis}
          onInvestigateNode={onPivotNode}
        />
      </div>
      <div className="grid gap-4 border-t border-gray-800 p-4 lg:grid-cols-2">
        <details open>
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-500">Nodes ({nodes.length})</summary>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Nodes</h4>
          <div className="mt-2 max-h-[420px] overflow-y-auto rounded border border-gray-800 bg-black/30">
            {nodes.map(node => (
              <div
                key={node.id}
                className="border-b border-gray-900 px-3 py-2 hover:bg-gray-900/60"
              >
                <button
                  type="button"
                  onClick={() => {
                    setSelectedNodeId(node.id);
                    setSelectedEdgeIndex(null);
                    setFocusNodeId(node.id);
                    if (canRunAnalysis && isInvestigableNode(node) && !expandedResults[node.id]) {
                      expandNode.mutate(node);
                    }
                  }}
                  className="block w-full text-left"
                >
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">T{node.tier}</span>
                    <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{node.type}</span>
                  </div>
                  <div className="mt-1 break-all text-sm text-gray-200">{node.value}</div>
                  <div className="mt-1 text-[11px] text-gray-500">{node.sources.join(', ')}</div>
                </button>
                <div className="mt-2 flex flex-wrap gap-1">
                  <button type="button" onClick={() => navigate(nodeDetailUrl(node))} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Open</button>
                  {canRunAnalysis && isInvestigableNode(node) && (
                    <button type="button" onClick={() => onPivotNode(node)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Investigate</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </details>
        <details>
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-500">Edges ({edges.length})</summary>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Edges</h4>
          <div className="mt-2 max-h-[420px] overflow-y-auto rounded border border-gray-800 bg-black/30">
            {edges.map((edge, index) => (
              <div key={`${edge.source}-${edge.target}-${index}`} className="border-b border-gray-900 px-3 py-2 text-sm">
                <div className="break-all text-gray-200">{edge.source} <span className="text-mitre-accent">→</span> {edge.target}</div>
                <div className="mt-1 text-[11px] text-gray-500">Tier {edge.tier} · {edge.type} · {edge.evidence_source}</div>
                {edge.evidence && <div className="mt-1 text-xs text-gray-400">{edge.evidence}</div>}
              </div>
            ))}
          </div>
        </details>
      </div>
    </section>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function GraphInspector({
  result,
  node,
  edge,
  connectedEdges,
  onOpenNode,
  onFocusNode,
  onInvestigateNode,
  canRunAnalysis,
}: {
  result: IOCInvestigationResult;
  node: GraphNode | null;
  edge: RelationshipEdge | null;
  connectedEdges: RelationshipEdge[];
  onOpenNode: (node: GraphNode) => void;
  onFocusNode: (node: GraphNode) => void;
  onInvestigateNode: (node: GraphNode) => void;
  canRunAnalysis: boolean;
}) {
  if (edge) {
    const explanation = explainEdge(edge, result);
    return (
      <aside className="rounded border border-gray-800 bg-black/30 p-3">
        <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Selected edge</div>
        <div className="mt-3 break-all text-sm text-gray-200">{edgeEndpoint(edge.source)} <span className="text-mitre-accent">→</span> {edgeEndpoint(edge.target)}</div>
        <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
          <InfoPill label="Type" value={edge.type} />
          <InfoPill label="Tier" value={`T${edge.tier}`} />
          <InfoPill label="Source" value={edge.evidence_source} wide />
        </div>
        {edge.evidence && <p className="mt-3 rounded border border-gray-800 bg-gray-950/70 p-2 text-xs leading-5 text-gray-400">{edge.evidence}</p>}
        <AnalystExplanation title="Relation meaning" text={explanation.meaning} />
        <InvestigationAnswer title="Malicious?" answer={explanation.malicious.answer} why={explanation.malicious.why} refs={explanation.malicious.refs} />
        <InvestigationAnswer title="TTP?" answer={explanation.ttp.answer} why={explanation.ttp.why} refs={explanation.ttp.refs} />
        <InvestigationAnswer title="Actor?" answer={explanation.actor.answer} why={explanation.actor.why} refs={explanation.actor.refs} />
      </aside>
    );
  }
  if (!node) {
    return (
      <aside className="rounded border border-gray-800 bg-black/30 p-3 text-sm text-gray-500">
        Select a node or edge to inspect source evidence.
      </aside>
    );
  }
  const explanation = explainNode(node, connectedEdges, result);
  return (
    <aside className="rounded border border-gray-800 bg-black/30 p-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Selected node</div>
      <div className="mt-3 flex items-center gap-2">
        <span className="h-3 w-3 rounded-full" style={{ backgroundColor: nodeColor(node) }} />
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">T{node.tier}</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{node.type}</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{nodeRiskLabel(node)}</span>
      </div>
      <div className="mt-3 break-all font-mono text-sm text-white">{node.value}</div>
      <div className="mt-3 text-xs text-gray-500">Sources</div>
      <div className="mt-2 flex flex-wrap gap-1">
        {node.sources.map(source => <span key={source} className="rounded border border-gray-700 px-2 py-0.5 text-[10px] text-gray-300">{source}</span>)}
      </div>
      <div className="mt-3 grid gap-2">
        <button type="button" onClick={() => onFocusNode(node)} className="rounded bg-mitre-accent px-3 py-2 text-xs font-semibold text-white hover:bg-red-600">
          Show connected nodes
        </button>
        {canRunAnalysis && isInvestigableNode(node) && (
          <button type="button" onClick={() => onInvestigateNode(node)} className="rounded border border-gray-700 px-3 py-2 text-xs font-semibold text-gray-200 hover:border-mitre-accent">
            Investigate from this node
          </button>
        )}
        <button type="button" onClick={() => onOpenNode(node)} className="rounded border border-gray-700 px-3 py-2 text-xs font-semibold text-gray-200 hover:border-mitre-accent">
          Open node page
        </button>
      </div>
      <AnalystExplanation title="Node meaning" text={explanation.meaning} />
      <InvestigationAnswer title="Malicious?" answer={explanation.malicious.answer} why={explanation.malicious.why} refs={explanation.malicious.refs} />
      <InvestigationAnswer title="TTP?" answer={explanation.ttp.answer} why={explanation.ttp.why} refs={explanation.ttp.refs} />
      <InvestigationAnswer title="Actor?" answer={explanation.actor.answer} why={explanation.actor.why} refs={explanation.actor.refs} />
      {connectedEdges.length > 0 && (
        <div className="mt-3 rounded border border-gray-800 bg-gray-950/70 p-2">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">Connected relations</div>
          <div className="mt-2 space-y-2">
            {connectedEdges.slice(0, 6).map((item, index) => (
              <div key={`${item.source}-${item.target}-${index}`} className="text-[11px] leading-4 text-gray-400">
                <span className="break-all text-gray-300">{item.source}</span>
                <span className="px-1 text-mitre-accent">→</span>
                <span className="break-all text-gray-300">{item.target}</span>
                <span className="block text-gray-600">Ref. {item.evidence_source}{item.evidence ? `: ${item.evidence}` : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </aside>
  );
}

type InvestigationExplanation = {
  meaning: string;
  malicious: { answer: string; why: string; refs: string[] };
  ttp: { answer: string; why: string; refs: string[] };
  actor: { answer: string; why: string; refs: string[] };
};

function AnalystExplanation({ title, text }: { title: string; text: string }) {
  return (
    <div className="mt-3 rounded border border-gray-800 bg-gray-950/70 p-2">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">{title}</div>
      <p className="mt-1 text-xs leading-5 text-gray-400">{text}</p>
    </div>
  );
}

function InvestigationAnswer({ title, answer, why, refs }: { title: string; answer: string; why: string; refs: string[] }) {
  return (
    <div className="mt-2 rounded border border-gray-800 bg-gray-950/70 p-2">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">{title}</span>
        <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-semibold text-gray-200">{answer}</span>
      </div>
      <p className="mt-1 text-xs leading-5 text-gray-400">{why}</p>
      {refs.length > 0 && (
        <div className="mt-2 space-y-1">
          {refs.slice(0, 4).map((ref, index) => (
            <div key={`${title}-${index}`} className="break-all text-[10px] text-gray-600">Ref. {ref}</div>
          ))}
        </div>
      )}
    </div>
  );
}

function explainNode(node: GraphNode, edges: RelationshipEdge[], result: IOCInvestigationResult): InvestigationExplanation {
  const refs = nodeRefs(node, edges);
  const sourceList = node.sources.join(', ') || 'unknown source';
  const type = node.type.toLowerCase();
  const connectedEvidence = edges.map(edge => edge.evidence).filter(Boolean);
  const actorRefs = result.actors.map(actor => `${actor.source}: ${actor.name || actor.attack_id}${actor.evidence ? ` - ${actor.evidence}` : ''}`);
  const ttpRefs = result.techniques.map(tech => `${tech.attack_id} ${tech.name || ''}${tech.evidence_sources?.length ? ` - ${tech.evidence_sources.join(', ')}` : ''}`.trim());

  const meaning = node.type === 'actor'
    ? `${node.value} is an actor lead node. It means a source or local alias relationship connected this investigation to an actor name or ATT&CK group identifier. Treat it as a lead, not attribution.`
    : node.type === 'suspicious-pattern'
      ? `${node.value} is a behavior pattern extracted from urlscan activity analysis. It describes suspicious page behavior observed around the submitted artifact or a pivoted artifact.`
      : node.tier === 0
        ? `${node.value} is the original submitted artifact. Tier 0 is the investigation root; other nodes are pivots or context connected to it.`
        : `${node.value} is a Tier ${node.tier} ${node.type} node. It was connected through ${sourceList}; higher tiers are pivots from already discovered observables, so they need stronger validation before client-facing conclusions.`;

  const malicious = (() => {
    if (node.tier === 0) {
      return {
        answer: result.verdict,
        why: `The whole investigation scored ${result.suspicion_score}/100. This is based on source responses, suspicious patterns, actor/TTP leads, and relationship density.`,
        refs: [result.summary, ...refs],
      };
    }
    if (['malware', 'suspicious-pattern', 'reputation', 'vulnerability'].includes(type) || connectedEvidence.some(item => /malicious|abuse|c2|phish|ransom|suspicious/i.test(item))) {
      return {
        answer: 'suspicious lead',
        why: `This node carries suspicious context by type or evidence. Validate the source record before treating it as malicious in a report.`,
        refs,
      };
    }
    if (['tag', 'name', 'classification', 'service-port', 'software'].includes(type)) {
      return {
        answer: 'context only',
        why: `This node is enrichment context. It can support the investigation, but by itself it is not enough to mark the artifact malicious.`,
        refs,
      };
    }
    return {
      answer: 'needs validation',
      why: `This observable is related to the root or a pivot, but the relation alone does not establish maliciousness.`,
      refs,
    };
  })();

  const ttp = (() => {
    if (type === 'suspicious-pattern') {
      return {
        answer: result.techniques.length ? 'possible' : 'not mapped',
        why: result.techniques.length
          ? `Behavioral analysis produced ATT&CK leads. Review whether the evidence matches the technique definitions before adding them to coverage.`
          : `No ATT&CK technique was resolved for this pattern yet.`,
        refs: ttpRefs.length ? ttpRefs : refs,
      };
    }
    if (result.techniques.length && refs.some(ref => /attack|ttp|urlscan|virustotal|threatfox|malwarebazaar/i.test(ref))) {
      return {
        answer: 'possible',
        why: `The investigation has ATT&CK leads and this node is connected through a source that can carry behavior or malware context.`,
        refs: ttpRefs,
      };
    }
    return {
      answer: 'no direct mapping',
      why: `This node is not itself a TTP. Use it as evidence context unless a source maps it to ATT&CK behavior.`,
      refs: ttpRefs.length ? ttpRefs : refs,
    };
  })();

  const actor = (() => {
    if (type === 'actor') {
      return {
        answer: 'actor lead',
        why: `${node.value} is represented as an actor node. This means a source or alias link connected the artifact to that actor name; it does not establish attribution.`,
        refs: actorRefs.length ? actorRefs : refs,
      };
    }
    if (result.actors.length) {
      return {
        answer: 'possible leads',
        why: `Actor leads exist in this investigation, but this selected node is not itself an actor. Use the connected evidence and source confidence to decide whether the lead is relevant.`,
        refs: actorRefs,
      };
    }
    return {
      answer: 'none found',
      why: `No source-backed actor lead is attached to the current investigation result.`,
      refs,
    };
  })();

  return { meaning, malicious, ttp, actor };
}

function explainEdge(edge: RelationshipEdge, result: IOCInvestigationResult): InvestigationExplanation {
  const evidence = edge.evidence || 'No additional evidence text was provided by the source.';
  const ref = `${edge.evidence_source}: ${evidence}`;
  const type = edge.type.toLowerCase();
  const ttpRefs = result.techniques.map(tech => `${tech.attack_id} ${tech.name || ''}${tech.evidence_sources?.length ? ` - ${tech.evidence_sources.join(', ')}` : ''}`.trim());
  const actorRefs = result.actors.map(actor => `${actor.source}: ${actor.name || actor.attack_id}${actor.evidence ? ` - ${actor.evidence}` : ''}`);
  const meaning = `This relation says the source artifact ${edge.source} is connected to ${edge.target} as ${edge.type}. The connection came from ${edge.evidence_source} at Tier ${edge.tier}. It is evidence for pivoting and triage, not a final conclusion.`;
  const malicious = {
    answer: /malicious|abuse|c2|phish|ransom|suspicious|malware|reputation|vulnerability/i.test(`${type} ${evidence}`) ? 'suspicious lead' : 'context',
    why: /malicious|abuse|c2|phish|ransom|suspicious|malware|reputation|vulnerability/i.test(`${type} ${evidence}`)
      ? `The relation type or evidence contains suspicious security context. Validate with the original source before declaring the IOC malicious.`
      : `This relation provides context for investigation. It does not by itself prove malicious activity.`,
    refs: [ref],
  };
  const ttp = {
    answer: result.techniques.length ? 'possible' : 'not mapped',
    why: result.techniques.length
      ? `The investigation has ATT&CK leads. Use this relation as supporting evidence only when the edge evidence describes behavior matching the technique.`
      : `No ATT&CK technique is directly mapped from this relation.`,
    refs: ttpRefs.length ? ttpRefs : [ref],
  };
  const actor = {
    answer: type === 'actor' || result.actors.length ? 'possible lead' : 'none found',
    why: type === 'actor'
      ? `The edge points directly to an actor-like target. Treat this as an actor lead requiring source validation, not attribution.`
      : result.actors.length
        ? `Actor leads exist elsewhere in the investigation, but this relation is not direct actor evidence.`
        : `No actor lead is associated with this relation.`,
    refs: actorRefs.length ? actorRefs : [ref],
  };
  return { meaning, malicious, ttp, actor };
}

function nodeRefs(node: GraphNode, edges: RelationshipEdge[]) {
  const refs = edges.map(edge => `${edge.evidence_source}: ${edge.evidence || `${edge.source} -> ${edge.target}`}`);
  if (!refs.length) refs.push(`node sources: ${node.sources.join(', ') || 'unknown'}`);
  return refs;
}

function InfoPill({ label, value, wide = false }: { label: string; value: string | number; wide?: boolean }) {
  return (
    <div className={clsx('rounded border border-gray-800 bg-gray-950/70 p-2', wide && 'col-span-2')}>
      <div className="text-[10px] uppercase tracking-wide text-gray-600">{label}</div>
      <div className="mt-1 break-all text-gray-300">{value}</div>
    </div>
  );
}

function graphNodeId(type: string, value: string) {
  return `${type}:${value}`.toLowerCase();
}

function mergeInvestigationGraphs(base: IOCInvestigationResult, expansions: IOCInvestigationResult[]): IOCInvestigationResult {
  if (!expansions.length) return base;
  const nodes = new Map<string, IOCInvestigationResult['relationships']['nodes'][number]>();
  const edges = new Map<string, IOCInvestigationResult['relationships']['edges'][number]>();
  const sources = new Map<string, IOCInvestigationResult['sources'][number]>();
  const techniques = new Map<string, IOCInvestigationResult['techniques'][number]>();
  const actors = new Map<string, IOCInvestigationResult['actors'][number]>();
  const addNode = (node: IOCInvestigationResult['relationships']['nodes'][number]) => {
    const existing = nodes.get(node.id);
    if (!existing) {
      nodes.set(node.id, { ...node, sources: [...node.sources] });
      return;
    }
    existing.tier = Math.min(existing.tier, node.tier);
    existing.sources = Array.from(new Set([...existing.sources, ...node.sources]));
    existing.suspicious = Math.max(existing.suspicious ?? -1, node.suspicious ?? -1);
  };
  const addEdge = (edge: IOCInvestigationResult['relationships']['edges'][number]) => {
    edges.set(`${edge.source}|${edge.target}|${edge.type}|${edge.evidence_source}|${edge.tier}`, edge);
  };
  const addResult = (item: IOCInvestigationResult) => {
    item.relationships.nodes.forEach(addNode);
    item.relationships.edges.forEach(addEdge);
    item.sources.forEach(source => sources.set(`${source.source}:${source.summary}`, source));
    item.techniques.forEach(technique => techniques.set(technique.attack_id, technique));
    item.actors.forEach(actor => actors.set(`${actor.attack_id}:${actor.name}:${actor.source}`, actor));
  };
  addResult(base);
  expansions.forEach(addResult);
  const maxScore = Math.max(base.suspicion_score, ...expansions.map(item => item.suspicion_score));
  return {
    ...base,
    suspicion_score: maxScore,
    verdict: verdictFromScore(maxScore),
    sources: Array.from(sources.values()),
    techniques: Array.from(techniques.values()),
    actors: Array.from(actors.values()),
    relationships: {
      nodes: Array.from(nodes.values()).sort((a, b) => a.tier - b.tier || a.type.localeCompare(b.type) || a.value.localeCompare(b.value)),
      edges: Array.from(edges.values()),
    },
  };
}

function verdictFromScore(score: number) {
  if (score >= 75) return 'highly suspicious';
  if (score >= 45) return 'suspicious';
  if (score >= 20) return 'needs review';
  return 'low signal';
}

const NETWORK_FINGERPRINT_TYPES = new Set(['ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'ja4l', 'ja4ls', 'ja4x', 'ja4ssh', 'ja4t']);
const GRAPH_OBJECT_NODE_TYPES = new Set(['ioc', 'ip', 'ipv4', 'ipv6', 'domain', 'url', 'hash', 'md5', 'sha1', 'sha256', 'file', 'report', 'collection', ...NETWORK_FINGERPRINT_TYPES]);
const INVESTIGABLE_NODE_TYPES = new Set(['ioc', 'ip', 'ipv4', 'ipv6', 'domain', 'url', 'hash', 'md5', 'sha1', 'sha256', ...NETWORK_FINGERPRINT_TYPES]);

function isActionableGraphNode(node: Pick<GraphNode, 'type' | 'tier' | 'value'>) {
  if (node.tier === 0) return true;
  return GRAPH_OBJECT_NODE_TYPES.has(node.type);
}

function isInvestigableNode(node: Pick<GraphNode, 'type' | 'value'>) {
  if (!node.value) return false;
  return INVESTIGABLE_NODE_TYPES.has(node.type);
}

function nodeDetailUrl(node: Pick<GraphNode, 'type' | 'value' | 'tier' | 'sources'>) {
  const params = new URLSearchParams({
    type: node.type,
    value: node.value,
    tier: String(node.tier),
  });
  if (node.sources.length) params.set('sources', node.sources.join(','));
  return `/ioc-node?${params.toString()}`;
}

function effectiveNodeRisk(node: GraphNode, result: IOCInvestigationResult, allEdges: RelationshipEdge[]) {
  let risk = typeof node.suspicious === 'number' && node.suspicious > 0 ? node.suspicious : -1;
  const nodeValue = node.value.toLowerCase();
  const nodeId = node.id.toLowerCase();
  if (node.tier === 0 || nodeValue === result.artifact.toLowerCase()) {
    risk = Math.max(risk, result.suspicion_score);
  }
  const connectedEdges = allEdges.filter(edge => {
    const targetId = graphNodeId(edge.type, edge.target);
    return edge.source.toLowerCase() === nodeValue
      || edge.target.toLowerCase() === nodeValue
      || edge.source.toLowerCase() === nodeId
      || targetId === nodeId;
  });
  const sourceNames = new Set([
    ...node.sources.map(source => source.toLowerCase()),
    ...connectedEdges.map(edge => edge.evidence_source.toLowerCase()),
  ]);
  for (const source of result.sources) {
    if (!sourceNames.has(source.source.toLowerCase())) continue;
    risk = Math.max(risk, sourceRisk(source));
  }
  const evidenceText = [
    node.value,
    node.type,
    ...node.sources,
    ...connectedEdges.flatMap(edge => [edge.type, edge.evidence_source, edge.evidence, edge.source, edge.target]),
  ].join(' ').toLowerCase();
  if (/highly suspicious|malicious|ransom|phish|c2|command.?and.?control|botnet|trojan|stealer|backdoor|abuse|exploit|payload/i.test(evidenceText)) {
    risk = Math.max(risk, 70);
  } else if (/suspicious|needs review|threat|attack|apt|malware|ioc|indicator/i.test(evidenceText)) {
    risk = Math.max(risk, 45);
  }
  if (result.techniques.length && connectedEdges.length) risk = Math.max(risk, node.tier === 0 ? result.suspicion_score : 35);
  if (result.actors.length && connectedEdges.some(edge => /otx|opencti|local|report|censys|urlscan/i.test(edge.evidence_source))) {
    risk = Math.max(risk, node.tier === 0 ? result.suspicion_score : 45);
  }
  if (risk < 0 && /benign|harmless|clean|known good/i.test(evidenceText)) return 10;
  return risk > 0 ? clamp(risk, 0, 100) : -1;
}

function sourceRisk(source: IOCInvestigationResult['sources'][number]) {
  if (source.status !== 'ok') return -1;
  let risk = -1;
  const raw = source.raw ?? {};
  const text = JSON.stringify({ summary: source.summary, raw, technique_ids: source.technique_ids, actors: source.actors }).toLowerCase();
  const vtStats = findNestedStats(raw, 'last_analysis_stats');
  if (vtStats) {
    const malicious = Number(vtStats.malicious ?? 0);
    const suspicious = Number(vtStats.suspicious ?? 0);
    const harmless = Number(vtStats.harmless ?? 0);
    if (malicious || suspicious) risk = Math.max(risk, Math.min(100, malicious * 8 + suspicious * 5));
    else if (harmless > 0) risk = Math.max(risk, 10);
  }
  const abuseScore = findNestedNumber(raw, 'abuseConfidenceScore');
  if (abuseScore != null) risk = Math.max(risk, abuseScore);
  const activity = typeof raw.activity_analysis === 'object' && raw.activity_analysis ? raw.activity_analysis as { findings?: Array<{ severity?: string }> } : null;
  for (const finding of activity?.findings ?? []) {
    const severity = String(finding.severity ?? '').toLowerCase();
    if (severity === 'high') risk = Math.max(risk, 85);
    else if (severity === 'medium') risk = Math.max(risk, 60);
    else if (severity) risk = Math.max(risk, 30);
  }
  if (source.technique_ids.length) risk = Math.max(risk, 45);
  if (source.actors.length) risk = Math.max(risk, 45);
  if (/highly suspicious|malicious|ransom|phish|c2|command.?and.?control|botnet|trojan|stealer|backdoor|abuse|exploit|payload/i.test(text)) {
    risk = Math.max(risk, 70);
  } else if (/suspicious|threat|attack|apt|malware|indicator/i.test(text)) {
    risk = Math.max(risk, 45);
  }
  if (risk < 0 && /benign|harmless|clean|known good/i.test(text)) return 10;
  return risk;
}

function findNestedStats(value: unknown, key: string): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const direct = record[key];
  if (direct && typeof direct === 'object' && !Array.isArray(direct)) return direct as Record<string, unknown>;
  for (const item of Object.values(record)) {
    const nested = findNestedStats(item, key);
    if (nested) return nested;
  }
  return null;
}

function findNestedNumber(value: unknown, key: string): number | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const direct = record[key];
  if (typeof direct === 'number') return direct;
  if (typeof direct === 'string' && direct.trim() && !Number.isNaN(Number(direct))) return Number(direct);
  for (const item of Object.values(record)) {
    const nested = findNestedNumber(item, key);
    if (nested != null) return nested;
  }
  return null;
}

function nodeColor(node: Pick<GraphNode, 'suspicious'>) {
  const risk = typeof node.suspicious === 'number' ? node.suspicious : -1;
  if (risk < 0) return '#38bdf8';
  if (risk < 20) return '#22c55e';
  if (risk < 45) return '#facc15';
  if (risk < 75) return '#fb923c';
  return '#ef4444';
}

function nodeRiskLabel(node: Pick<GraphNode, 'suspicious'>) {
  const risk = typeof node.suspicious === 'number' ? node.suspicious : -1;
  if (risk < 0) return 'no reputation';
  if (risk < 20) return `low ${risk}/100`;
  if (risk < 45) return `review ${risk}/100`;
  if (risk < 75) return `suspicious ${risk}/100`;
  return `high risk ${risk}/100`;
}

function nodeRadius(node: Pick<GraphNode, 'tier' | 'sources'>) {
  if (node.tier === 0) return 18;
  const sourceBoost = Math.min(8, Math.max(0, node.sources.length - 1) * 2);
  return node.tier === 1 ? 13 + sourceBoost : 9 + sourceBoost;
}

function nodeLabel(node: GraphNode, visibleNodeCount: number) {
  if (visibleNodeCount > 45 && node.tier > 1 && !GRAPH_OBJECT_NODE_TYPES.has(node.type)) return '';
  const limit = node.tier === 0 ? 30 : visibleNodeCount > 35 ? 16 : 24;
  return shortLabel(node.value, limit);
}

function tierPosition(tier: number) {
  if (tier <= 0) return 0.18;
  if (tier === 1) return 0.42;
  if (tier === 2) return 0.68;
  return 0.88;
}

function nodeX(node: string | number | GraphNode | undefined) {
  return typeof node === 'object' && node ? node.x ?? 0 : 0;
}

function nodeY(node: string | number | GraphNode | undefined) {
  return typeof node === 'object' && node ? node.y ?? 0 : 0;
}

function edgeEndpoint(value: string | number | GraphNode | undefined) {
  if (typeof value === 'object' && value) return value.value;
  return String(value ?? '');
}

function shortLabel(value: string, limit: number) {
  if (value.length <= limit) return value;
  const head = Math.ceil((limit - 1) / 2);
  const tail = Math.floor((limit - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

function TtpPanel({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">ATT&CK TTP Leads ({result.techniques.length})</h3>
      <div className="mt-3 space-y-2">
        {result.techniques.map(tech => (
          <a key={tech.attack_id} href={safeHref(tech.url)} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 bg-black/20 p-2 hover:border-mitre-accent">
            <div className="font-mono text-xs text-mitre-accent">{tech.attack_id}</div>
            <div className="text-sm text-white">{tech.name || 'Technique lead'}</div>
            <div className="text-[11px] text-gray-500">{tech.tactics.join(', ') || 'tactic pending'}</div>
          </a>
        ))}
        {!result.techniques.length && <Empty text="No source-backed ATT&CK IDs found yet." />}
      </div>
    </section>
  );
}

function ActorPanel({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">Actor / APT Leads ({result.actors.length})</h3>
      <div className="mt-3 space-y-2">
        {result.actors.map((actor, index) => (
          <div key={`${actor.attack_id}-${actor.name}-${index}`} className="rounded border border-gray-800 bg-black/20 p-2">
            <div className="text-sm font-semibold text-white">{actor.name || actor.attack_id || 'Actor lead'}</div>
            <div className="text-xs text-mitre-accent">{actor.attack_id}</div>
            <div className="mt-1 text-[11px] text-gray-500">{actor.source} · confidence {actor.confidence}</div>
            {actor.evidence && <div className="mt-1 text-xs text-gray-400">{actor.evidence}</div>}
          </div>
        ))}
        {!result.actors.length && <Empty text="No source-backed actor lead found." />}
      </div>
    </section>
  );
}

function KillChainPanel({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">Kill Chain / Tactic Coverage</h3>
      <div className="mt-3 space-y-2">
        {result.kill_chain.map(item => (
          <div key={item.phase}>
            <div className="flex justify-between text-xs text-gray-300"><span>{item.phase}</span><span>{item.techniques}</span></div>
            <div className="mt-1 h-1.5 rounded bg-gray-800"><div className="h-1.5 rounded bg-mitre-accent" style={{ width: `${Math.min(100, item.techniques * 18)}%` }} /></div>
          </div>
        ))}
        {!result.kill_chain.length && <Empty text="No tactic coverage yet." />}
      </div>
    </section>
  );
}

function ErrorBox({ error }: { error: unknown }) {
  return <div className="mt-3 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">{error instanceof Error ? error.message : String(error)}</div>;
}

function Empty({ text }: { text: string }) {
  return <div className="rounded border border-dashed border-gray-800 p-3 text-xs text-gray-500">{text}</div>;
}

function scoreClass(score: number) {
  if (score >= 75) return 'bg-red-500 text-white';
  if (score >= 45) return 'bg-orange-500 text-black';
  if (score >= 20) return 'bg-yellow-400 text-black';
  return 'bg-green-600 text-white';
}

function statusClass(status: string) {
  if (status === 'ok') return 'bg-green-900/80 text-green-200';
  if (status === 'skipped' || status === 'not_configured') return 'bg-gray-800 text-gray-300';
  return 'bg-red-950 text-red-200';
}
