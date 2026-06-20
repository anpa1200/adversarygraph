import { useEffect, useMemo, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { iocApi, type IOCInvestigationResult } from '@/api/client';
import { useAppStore } from '@/store';
import clsx from 'clsx';

export function IOCInvestigation() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { domain, replaceTechniques, addTechniques } = useAppStore();
  const [artifact, setArtifact] = useState(params.get('indicator') ?? '');
  const [depth, setDepth] = useState(2);
  const [aiSummarize, setAiSummarize] = useState(false);
  const [provider, setProvider] = useState<'local' | 'claude' | 'openai' | 'gemini' | 'minimax'>('local');
  const mutation = useMutation({
    mutationFn: () => iocApi.investigate({
      artifact: artifact.trim(),
      domain,
      depth,
      max_tier_nodes: 25,
      ai_summarize: aiSummarize,
      ai_provider: provider,
    }),
  });
  const result = mutation.data ?? null;
  const techniqueIds = useMemo(() => result?.techniques.map(item => item.attack_id) ?? [], [result]);

  useEffect(() => {
    const value = params.get('indicator')?.trim();
    if (value) setArtifact(value);
  }, [params]);

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
                  expands Tier 1 and Tier 2 relationships, maps TTP/actor leads, and prepares an AI-ready investigation summary.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <input
                    value={artifact}
                    onChange={event => setArtifact(event.target.value)}
                    onKeyDown={event => {
                      if (event.key === 'Enter' && artifact.trim()) mutation.mutate();
                    }}
                    placeholder="IP, domain, URL, MD5, SHA1, SHA256, or artifact..."
                    className="min-w-[360px] flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent"
                  />
                  <select value={depth} onChange={event => setDepth(Number(event.target.value))} className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200">
                    <option value={1}>Tier 1 only</option>
                    <option value={2}>Tier 1 + Tier 2</option>
                  </select>
                  <select value={provider} onChange={event => setProvider(event.target.value as typeof provider)} disabled={!aiSummarize} className="rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 disabled:opacity-50">
                    <option value="local">Local LLM</option>
                    <option value="claude">Claude</option>
                    <option value="openai">OpenAI</option>
                    <option value="gemini">Gemini</option>
                    <option value="minimax">MiniMax</option>
                  </select>
                  <label className="inline-flex items-center gap-2 rounded border border-gray-700 px-3 py-2 text-sm text-gray-300">
                    <input type="checkbox" checked={aiSummarize} onChange={event => setAiSummarize(event.target.checked)} />
                    AI summary
                  </label>
                  <button
                    type="button"
                    disabled={!artifact.trim() || mutation.isPending}
                    onClick={() => mutation.mutate()}
                    className="rounded bg-mitre-accent px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {mutation.isPending ? 'Investigating...' : 'Investigate'}
                  </button>
                </div>
                {mutation.error && <ErrorBox error={mutation.error} />}
              </div>
              <div className="rounded border border-gray-800 bg-black/30 p-3 text-xs text-gray-400">
                <div className="font-semibold text-gray-200">Investigation targets</div>
                <div className="mt-2 grid grid-cols-2 gap-2">
                  {['IOC type', 'Tier 1 pivots', 'Tier 2 pivots', 'TTPs', 'Kill chain', 'Actor/APT leads', 'Source evidence', 'AI report input'].map(item => (
                    <div key={item} className="rounded border border-gray-800 bg-gray-950/70 px-2 py-1">{item}</div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {result && (
            <>
              <InvestigationSummary result={result} />
              <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
                <section className="space-y-5">
                  <SourceResults result={result} />
                  <RelationshipGraph result={result} />
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
    </section>
  );
}

function Actions({ result, techniqueIds, onShowMatrix, onAddTtps }: { result: IOCInvestigationResult; techniqueIds: string[]; onShowMatrix: () => void; onAddTtps: () => void }) {
  const navigate = useNavigate();
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">Actions</h3>
      <div className="mt-3 grid gap-2">
        <button disabled={!techniqueIds.length} onClick={onShowMatrix} className="primary disabled:opacity-40">Show TTPs on Matrix</button>
        <button disabled={!techniqueIds.length} onClick={onAddTtps} className="secondary-action disabled:opacity-40">Add TTPs to My TTPs</button>
        <button onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(result.artifact)}`)} className="secondary-action">Search IOC Library</button>
        <button onClick={() => navigate(`/virustotal?indicator=${encodeURIComponent(result.artifact)}`)} className="secondary-action">Open VirusTotal Lookup</button>
      </div>
    </section>
  );
}

function SourceResults({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Enrichment Sources</h3>
      </div>
      <div className="divide-y divide-gray-800">
        {result.sources.map(source => (
          <div key={source.source} className="grid gap-3 p-4 lg:grid-cols-[180px_1fr_auto]">
            <div>
              <div className="font-semibold text-white">{source.source}</div>
              <span className={clsx('mt-2 inline-block rounded px-2 py-1 text-[11px] font-bold', statusClass(source.status))}>{source.status}</span>
            </div>
            <div className="text-sm text-gray-300">
              <div>{source.summary}</div>
              {source.error && <div className="mt-2 text-xs text-red-300">{source.error}</div>}
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

function RelationshipGraph({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h3 className="text-sm font-semibold text-white">Relationship Expansion</h3>
      </div>
      <div className="grid gap-4 p-4 lg:grid-cols-2">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Nodes</h4>
          <div className="mt-2 max-h-[420px] overflow-y-auto rounded border border-gray-800 bg-black/30">
            {result.relationships.nodes.map(node => (
              <div key={node.id} className="border-b border-gray-900 px-3 py-2">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">T{node.tier}</span>
                  <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{node.type}</span>
                </div>
                <div className="mt-1 break-all text-sm text-gray-200">{node.value}</div>
                <div className="mt-1 text-[11px] text-gray-500">{node.sources.join(', ')}</div>
              </div>
            ))}
          </div>
        </div>
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Edges</h4>
          <div className="mt-2 max-h-[420px] overflow-y-auto rounded border border-gray-800 bg-black/30">
            {result.relationships.edges.map((edge, index) => (
              <div key={`${edge.source}-${edge.target}-${index}`} className="border-b border-gray-900 px-3 py-2 text-sm">
                <div className="break-all text-gray-200">{edge.source} <span className="text-mitre-accent">→</span> {edge.target}</div>
                <div className="mt-1 text-[11px] text-gray-500">Tier {edge.tier} · {edge.type} · {edge.evidence_source}</div>
                {edge.evidence && <div className="mt-1 text-xs text-gray-400">{edge.evidence}</div>}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function TtpPanel({ result }: { result: IOCInvestigationResult }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <h3 className="text-sm font-semibold text-white">ATT&CK TTP Leads ({result.techniques.length})</h3>
      <div className="mt-3 space-y-2">
        {result.techniques.map(tech => (
          <a key={tech.attack_id} href={tech.url} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 bg-black/20 p-2 hover:border-mitre-accent">
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
