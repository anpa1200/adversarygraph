import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { iocApi, type IOCInvestigationResult } from '@/api/client';
import { useAppStore } from '@/store';
import clsx from 'clsx';
import * as d3 from 'd3';

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

type GraphNode = IOCInvestigationResult['relationships']['nodes'][number] & d3.SimulationNodeDatum;
type RelationshipEdge = IOCInvestigationResult['relationships']['edges'][number];
type GraphLink = Omit<RelationshipEdge, 'source' | 'target'> & d3.SimulationLinkDatum<GraphNode> & {
  source: GraphNode;
  target: GraphNode;
  index: number;
};

function RelationshipGraph({ result }: { result: IOCInvestigationResult }) {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(result.relationships.nodes[0]?.id ?? null);
  const [selectedEdgeIndex, setSelectedEdgeIndex] = useState<number | null>(null);
  const [tierFilter, setTierFilter] = useState<'all' | '0' | '1' | '2'>('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const nodes = useMemo(() => {
    const filtered = result.relationships.nodes.filter(node => tierFilter === 'all' || String(node.tier) === tierFilter);
    return typeFilter === 'all' ? filtered : filtered.filter(node => node.type === typeFilter);
  }, [result.relationships.nodes, tierFilter, typeFilter]);
  const nodeKeys = useMemo(() => new Set(nodes.flatMap(node => [node.id, node.value.toLowerCase()])), [nodes]);
  const edges = useMemo(() => result.relationships.edges.filter(edge => {
    const targetId = graphNodeId(edge.type, edge.target);
    return nodeKeys.has(edge.source.toLowerCase()) && (nodeKeys.has(targetId) || nodeKeys.has(edge.target.toLowerCase()));
  }), [nodeKeys, result.relationships.edges]);
  const typeOptions = useMemo(() => Array.from(new Set(result.relationships.nodes.map(node => node.type))).sort(), [result.relationships.nodes]);
  const selectedNode = nodes.find(node => node.id === selectedNodeId) ?? nodes[0] ?? null;
  const selectedEdge = selectedEdgeIndex == null ? null : edges[selectedEdgeIndex] ?? null;

  useEffect(() => {
    setSelectedNodeId(result.relationships.nodes[0]?.id ?? null);
    setSelectedEdgeIndex(null);
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
      .attr('stroke-width', edge => edge.tier === 2 ? 1.1 : 1.8)
      .attr('stroke-dasharray', edge => edge.tier === 2 ? '4 4' : null)
      .attr('marker-end', 'url(#relationship-arrow)')
      .style('cursor', 'pointer')
      .on('click', (_, edge) => {
        setSelectedEdgeIndex(edge.index);
        setSelectedNodeId(null);
      });

    const edgeLabel = root.append('g')
      .selectAll<SVGTextElement, GraphLink>('text')
      .data(graphEdges.filter(edge => edge.tier <= 1).slice(0, 60))
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
      .text(node => shortLabel(node.value, 24));

    node.append('title').text(node => `${node.value}\n${node.type}\nTier ${node.tier}\n${node.sources.join(', ')}`);

    const simulation = d3.forceSimulation<GraphNode>(graphNodes)
      .force('link', d3.forceLink<GraphNode, GraphLink>(graphEdges).id(node => node.id).distance(edge => edge.tier === 2 ? 120 : 155).strength(0.72))
      .force('charge', d3.forceManyBody().strength(-420))
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
  }, [edges, nodes, selectedNodeId]);

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <div>
          <h3 className="text-sm font-semibold text-white">Relationship Graph</h3>
          <p className="mt-1 text-xs text-gray-500">Interactive Tier 1 / Tier 2 pivot map for source-backed IOC relationships.</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <select value={tierFilter} onChange={event => setTierFilter(event.target.value as typeof tierFilter)} className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200">
            <option value="all">All tiers</option>
            <option value="0">Tier 0</option>
            <option value="1">Tier 1</option>
            <option value="2">Tier 2</option>
          </select>
          <select value={typeFilter} onChange={event => setTypeFilter(event.target.value)} className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200">
            <option value="all">All types</option>
            {typeOptions.map(type => <option key={type} value={type}>{type}</option>)}
          </select>
        </div>
      </div>
      <div className="grid gap-4 p-4 xl:grid-cols-[1fr_300px]">
        <div className="min-h-[540px] overflow-hidden rounded border border-gray-800 bg-[radial-gradient(circle_at_center,#111827_0,#020617_75%)]">
          {nodes.length ? (
            <svg ref={svgRef} className="h-[540px] w-full" role="img" aria-label="IOC relationship graph" />
          ) : (
            <div className="flex h-[540px] items-center justify-center text-sm text-gray-500">No graph relationships after filters.</div>
          )}
        </div>
        <GraphInspector node={selectedNode} edge={selectedEdge} />
      </div>
      <div className="grid gap-4 border-t border-gray-800 p-4 lg:grid-cols-2">
        <details open>
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-500">Nodes ({nodes.length})</summary>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Nodes</h4>
          <div className="mt-2 max-h-[420px] overflow-y-auto rounded border border-gray-800 bg-black/30">
            {nodes.map(node => (
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

function GraphInspector({ node, edge }: { node: GraphNode | null; edge: RelationshipEdge | null }) {
  if (edge) {
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
  return (
    <aside className="rounded border border-gray-800 bg-black/30 p-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Selected node</div>
      <div className="mt-3 flex items-center gap-2">
        <span className="h-3 w-3 rounded-full" style={{ backgroundColor: nodeColor(node) }} />
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">T{node.tier}</span>
        <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{node.type}</span>
      </div>
      <div className="mt-3 break-all font-mono text-sm text-white">{node.value}</div>
      <div className="mt-3 text-xs text-gray-500">Sources</div>
      <div className="mt-2 flex flex-wrap gap-1">
        {node.sources.map(source => <span key={source} className="rounded border border-gray-700 px-2 py-0.5 text-[10px] text-gray-300">{source}</span>)}
      </div>
    </aside>
  );
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

function nodeColor(node: Pick<GraphNode, 'type' | 'tier' | 'kind'>) {
  if (node.tier === 0) return '#f43f5e';
  if (node.type === 'actor') return '#a855f7';
  if (node.type === 'malware') return '#f97316';
  if (node.type === 'report') return '#38bdf8';
  if (node.type === 'tag' || node.type === 'classification' || node.type === 'reputation') return '#facc15';
  if (node.type === 'domain' || node.type === 'url') return '#22c55e';
  if (node.type === 'ip' || node.type === 'ioc') return '#06b6d4';
  if (node.type === 'hash') return '#60a5fa';
  if (node.type.includes('port') || node.type === 'vulnerability') return '#fb7185';
  return node.kind === 'artifact' ? '#14b8a6' : '#94a3b8';
}

function nodeRadius(node: Pick<GraphNode, 'tier' | 'sources'>) {
  if (node.tier === 0) return 18;
  const sourceBoost = Math.min(8, Math.max(0, node.sources.length - 1) * 2);
  return node.tier === 1 ? 13 + sourceBoost : 9 + sourceBoost;
}

function tierPosition(tier: number) {
  if (tier <= 0) return 0.18;
  if (tier === 1) return 0.52;
  return 0.82;
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
