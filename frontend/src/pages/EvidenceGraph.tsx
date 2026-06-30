import { useMemo, useState } from 'react';
import type { Edge, Node } from '@xyflow/react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  evidenceGraphApi,
  type EvidenceGraphEdge,
  type EvidenceGraphGap,
  type EvidenceGraphNode,
  type EvidenceGraphNodeType,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { EntityGraph } from '@/components/ui/graph';

const NODE_LABELS: Record<EvidenceGraphNodeType, string> = {
  evidence: 'Evidence',
  claim: 'Claim',
  behavior: 'Behavior',
  attack_technique: 'ATT&CK Technique',
  required_telemetry: 'Required Telemetry',
  detection_candidate: 'Detection Candidate',
  detection_rule: 'Detection Rule',
  validation_scenario: 'Validation Scenario',
  siem_result: 'SIEM Result',
  analyst_decision: 'Analyst Decision',
};

const NODE_COLORS: Record<EvidenceGraphNodeType, string> = {
  evidence: '#38bdf8',
  claim: '#a78bfa',
  behavior: '#22c55e',
  attack_technique: '#fb7185',
  required_telemetry: '#facc15',
  detection_candidate: '#fb923c',
  detection_rule: '#60a5fa',
  validation_scenario: '#2dd4bf',
  siem_result: '#e879f9',
  analyst_decision: '#f8fafc',
};

const NEXT_STEP: Partial<Record<EvidenceGraphNodeType, { node_type: EvidenceGraphNodeType; title: string; edge_type: string }>> = {
  evidence: { node_type: 'claim', title: 'Draft claim from evidence', edge_type: 'SUPPORTS' },
  claim: { node_type: 'behavior', title: 'Normalized behavior', edge_type: 'DESCRIBES' },
  behavior: { node_type: 'attack_technique', title: 'ATT&CK mapping candidate', edge_type: 'MAPS_TO' },
  attack_technique: { node_type: 'required_telemetry', title: 'Required telemetry', edge_type: 'REQUIRES_TELEMETRY' },
  required_telemetry: { node_type: 'detection_candidate', title: 'Detection candidate', edge_type: 'ENABLES_DETECTION' },
  detection_candidate: { node_type: 'detection_rule', title: 'Detection rule draft', edge_type: 'IMPLEMENTED_AS' },
  detection_rule: { node_type: 'validation_scenario', title: 'Validation scenario', edge_type: 'VALIDATED_BY' },
  validation_scenario: { node_type: 'siem_result', title: 'SIEM validation result', edge_type: 'PRODUCED_RESULT' },
  siem_result: { node_type: 'analyst_decision', title: 'Analyst decision', edge_type: 'REVIEWED_AS' },
};

export function EvidenceGraph() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<'overview' | 'path' | 'gaps' | 'review'>('overview');
  const [selectedId, setSelectedId] = useState<string>('');
  const [filters, setFilters] = useState({ search: '', node_type: '', review_status: '', technique_id: '', onlyGaps: false, onlyAi: false });
  const [newEvidenceTitle, setNewEvidenceTitle] = useState('');
  const [newEvidenceText, setNewEvidenceText] = useState('');

  const summary = useQuery({ queryKey: ['evidence-graph-summary'], queryFn: evidenceGraphApi.summary });
  const graph = useQuery({
    queryKey: ['evidence-graph', filters],
    queryFn: () => evidenceGraphApi.query({
      search: filters.search || undefined,
      node_type: filters.node_type || undefined,
      review_status: filters.review_status || undefined,
      technique_id: filters.technique_id || undefined,
      include_ai_suggestions: !filters.onlyAi,
      max_depth: 8,
    }),
  });
  const gaps = useQuery({ queryKey: ['evidence-graph-gaps'], queryFn: evidenceGraphApi.gaps });
  const paths = useQuery({
    queryKey: ['evidence-graph-paths', selectedId, filters.technique_id],
    queryFn: () => evidenceGraphApi.paths({ from_node_id: selectedId || undefined, technique_id: filters.technique_id || undefined }),
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['evidence-graph-summary'] });
    qc.invalidateQueries({ queryKey: ['evidence-graph'] });
    qc.invalidateQueries({ queryKey: ['evidence-graph-gaps'] });
    qc.invalidateQueries({ queryKey: ['evidence-graph-paths'] });
  };
  const createNode = useMutation({ mutationFn: evidenceGraphApi.createNode, onSuccess: invalidate });
  const updateNode = useMutation({ mutationFn: ({ id, body }: { id: string; body: Partial<EvidenceGraphNode> }) => evidenceGraphApi.updateNode(id, body), onSuccess: invalidate });
  const createEdge = useMutation({ mutationFn: evidenceGraphApi.createEdge, onSuccess: invalidate });

  const nodes = graph.data?.nodes ?? [];
  const edges = graph.data?.edges ?? [];
  const selected = nodes.find(node => node.id === selectedId) ?? nodes[0];
  const reviewQueue = useMemo(() => nodes.filter(node =>
    (node.ai_generated && node.review_status === 'draft')
    || node.review_status === 'needs_evidence'
    || node.node_type === 'siem_result' && !node.decision
  ), [nodes]);
  const visibleGaps = (gaps.data?.gaps ?? []).filter(gap => !filters.search || JSON.stringify(gap).toLowerCase().includes(filters.search.toLowerCase()));
  const flowNodes = useMemo<Node[]>(() => buildFlowNodes(nodes, setSelectedId), [nodes]);
  const flowEdges = useMemo<Edge[]>(() => buildFlowEdges(edges), [edges]);

  const createEvidence = () => {
    const title = newEvidenceTitle.trim();
    if (!title) return;
    createNode.mutate({
      node_type: 'evidence',
      title,
      source_type: 'analyst_note',
      raw_excerpt: newEvidenceText,
      normalized_summary: newEvidenceText,
      review_status: 'draft',
      confidence: 60,
      metadata_json: { origin: 'manual-evidence-graph' },
    });
    setNewEvidenceTitle('');
    setNewEvidenceText('');
  };

  const createNextStep = async (node: EvidenceGraphNode) => {
    const spec = NEXT_STEP[node.node_type];
    if (!spec) return;
    const created = await createNode.mutateAsync({
      node_type: spec.node_type,
      title: `${spec.title}: ${node.title}`.slice(0, 500),
      technique_id: node.technique_id,
      review_status: 'draft',
      confidence: Math.max(30, node.confidence - 5),
      metadata_json: { created_from_node: node.id, workflow_action: 'create-next-step' },
    });
    await createEdge.mutateAsync({
      source_node_id: node.id,
      target_node_id: created.id,
      edge_type: spec.edge_type,
      rationale: `Analyst created next reasoning step from ${NODE_LABELS[node.node_type]}.`,
      confidence: Math.max(30, node.confidence - 5),
      review_status: 'draft',
    });
    setSelectedId(created.id);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Header title="Evidence Graph" />
      <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
        <div className="mx-auto grid max-w-[1800px] gap-4 xl:grid-cols-[minmax(0,1fr)_390px]">
          <main className="space-y-4">
            <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-semibold text-white">Evidence-to-Detection Graph</h2>
                  <p className="mt-1 max-w-4xl text-xs leading-5 text-gray-400">
                    Preserve the reasoning chain from raw evidence to analyst decision. AI suggestions remain drafts until reviewed;
                    TTP overlap is investigation context, not attribution proof.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(['json', 'markdown', 'csv', 'evidence-pack'] as const).map(format => (
                    <a key={format} href={evidenceGraphApi.exportUrl(format)} className="secondary-action px-3 py-2 text-xs">
                      Export {format}
                    </a>
                  ))}
                </div>
              </div>
              <div className="grid gap-3 md:grid-cols-4 xl:grid-cols-7">
                <Metric label="Readiness" value={`${summary.data?.detection_readiness_score ?? 0}/100`} tone="green" />
                <Metric label="Nodes" value={Object.values(summary.data?.node_counts ?? {}).reduce((a, b) => a + b, 0)} />
                <Metric label="Edges" value={Object.values(summary.data?.edge_counts ?? {}).reduce((a, b) => a + b, 0)} />
                <Metric label="Open gaps" value={summary.data?.unresolved_gaps ?? 0} tone="red" />
                <Metric label="AI drafts" value={summary.data?.unreviewed_ai_suggestions ?? 0} tone="amber" />
                <Metric label="Validation" value={`${summary.data?.validation_coverage?.coverage_percent ?? 0}%`} />
                <Metric label="Decisions" value={summary.data?.latest_analyst_decisions?.length ?? 0} />
              </div>
            </section>

            <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
              <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_160px_170px_150px]">
                <input className="field" placeholder="Search evidence, technique, rule, IOC, asset..." value={filters.search} onChange={event => setFilters({ ...filters, search: event.target.value })} />
                <select className="field" value={filters.node_type} onChange={event => setFilters({ ...filters, node_type: event.target.value })}>
                  <option value="">All node types</option>
                  {Object.entries(NODE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
                <select className="field" value={filters.review_status} onChange={event => setFilters({ ...filters, review_status: event.target.value })}>
                  <option value="">All review states</option>
                  <option value="draft">Draft</option>
                  <option value="analyst_reviewed">Analyst reviewed</option>
                  <option value="needs_evidence">Needs evidence</option>
                  <option value="rejected">Rejected</option>
                </select>
                <input className="field" placeholder="T1059.001" value={filters.technique_id} onChange={event => setFilters({ ...filters, technique_id: event.target.value })} />
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {(['overview', 'path', 'gaps', 'review'] as const).map(item => (
                  <button key={item} onClick={() => setTab(item)} className={tab === item ? 'primary-action px-3 py-2 text-xs' : 'secondary-action px-3 py-2 text-xs'}>
                    {item === 'overview' ? 'Graph Overview' : item === 'path' ? 'Reasoning Path' : item === 'gaps' ? 'Gap View' : 'Review Queue'}
                  </button>
                ))}
              </div>
            </section>

            {tab === 'overview' && (
              <section className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_360px]">
                <div className="min-h-[560px]">
                  <EntityGraph nodes={flowNodes} edges={flowEdges} />
                </div>
                <div className="rounded border border-gray-800 bg-gray-950/40 p-4">
                  <h3 className="font-semibold text-white">Manual Evidence</h3>
                  <p className="mt-1 text-xs leading-5 text-gray-500">Create a draft evidence node from analyst notes. This does not auto-approve any claim.</p>
                  <input className="field mt-3 w-full" placeholder="Evidence title" value={newEvidenceTitle} onChange={event => setNewEvidenceTitle(event.target.value)} />
                  <textarea className="field mt-2 h-32 w-full" placeholder="Raw excerpt or analyst note" value={newEvidenceText} onChange={event => setNewEvidenceText(event.target.value)} />
                  <button className="primary-action mt-3 w-full" disabled={!newEvidenceTitle.trim() || createNode.isPending} onClick={createEvidence}>
                    Create Evidence
                  </button>
                  <WarningBox />
                </div>
              </section>
            )}

            {tab === 'path' && <PathView paths={paths.data?.paths ?? graph.data?.grouped_paths?.map(item => item.steps) ?? []} />}
            {tab === 'gaps' && <GapTable gaps={visibleGaps} onSelect={setSelectedId} />}
            {tab === 'review' && <ReviewQueue nodes={reviewQueue} onSelect={setSelectedId} onApprove={id => updateNode.mutate({ id, body: { review_status: 'analyst_reviewed' } })} onReject={id => updateNode.mutate({ id, body: { review_status: 'rejected' } })} />}
          </main>

          <aside className="space-y-4">
            <NodeDetail
              node={selected}
              edges={edges.filter(edge => selected && (edge.source_node_id === selected.id || edge.target_node_id === selected.id))}
              onApprove={node => updateNode.mutate({ id: node.id, body: { review_status: 'analyst_reviewed' } })}
              onReject={node => updateNode.mutate({ id: node.id, body: { review_status: 'rejected' } })}
              onNeedsEvidence={node => updateNode.mutate({ id: node.id, body: { review_status: 'needs_evidence' } })}
              onNext={createNextStep}
            />
            <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
              <h3 className="font-semibold text-white">Top Detection Gaps</h3>
              <div className="mt-3 space-y-2">
                {(summary.data?.top_techniques_by_detection_gap ?? []).slice(0, 6).map(item => (
                  <button key={item.technique} className="w-full rounded border border-gray-800 bg-gray-950 p-2 text-left hover:border-mitre-accent" onClick={() => setFilters({ ...filters, technique_id: item.technique })}>
                    <span className="block text-sm font-semibold text-mitre-accent">{item.technique}</span>
                    <span className="block truncate text-xs text-gray-400">{item.name}</span>
                    <span className="text-xs text-yellow-300">{item.gap_count} gaps</span>
                  </button>
                ))}
              </div>
            </section>
          </aside>
        </div>
      </div>
    </div>
  );
}

function buildFlowNodes(nodes: EvidenceGraphNode[], onSelect: (id: string) => void): Node[] {
  const columns = ['evidence', 'claim', 'behavior', 'attack_technique', 'required_telemetry', 'detection_candidate', 'detection_rule', 'validation_scenario', 'siem_result', 'analyst_decision'];
  const counters = new Map<string, number>();
  return nodes.map(node => {
    const column = Math.max(0, columns.indexOf(node.node_type));
    const row = counters.get(node.node_type) ?? 0;
    counters.set(node.node_type, row + 1);
    return {
      id: node.id,
      position: { x: column * 245, y: row * 125 },
      data: {
        label: (
          <button type="button" onClick={() => onSelect(node.id)} className="max-w-[190px] text-left">
            <span className="block text-[10px] uppercase text-gray-400">{NODE_LABELS[node.node_type]}</span>
            <span className="block truncate text-xs font-semibold text-white">{node.title}</span>
            <span className="mt-1 block text-[10px] text-gray-400">{node.review_status}{node.ai_generated ? ' · AI draft' : ''}</span>
          </button>
        ),
      },
      style: {
        border: `1px solid ${NODE_COLORS[node.node_type]}`,
        background: '#020617',
        color: '#fff',
        borderRadius: 6,
        width: 210,
      },
    };
  });
}

function buildFlowEdges(edges: EvidenceGraphEdge[]): Edge[] {
  return edges.map(edge => ({
    id: edge.id,
    source: edge.source_node_id,
    target: edge.target_node_id,
    label: edge.edge_type,
    animated: edge.review_status === 'draft',
    style: { stroke: edge.review_status === 'rejected' ? '#7f1d1d' : '#64748b' },
    labelStyle: { fill: '#cbd5e1', fontSize: 10 },
  }));
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'green' | 'red' | 'amber' }) {
  const color = tone === 'green' ? 'text-green-300' : tone === 'red' ? 'text-red-300' : tone === 'amber' ? 'text-yellow-300' : 'text-white';
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className={`text-xl font-bold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
    </div>
  );
}

function PathView({ paths }: { paths: EvidenceGraphNode[][] }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
      <h3 className="font-semibold text-white">Reasoning Path View</h3>
      <div className="mt-4 space-y-4">
        {paths.length === 0 && <p className="text-sm text-gray-500">No complete path yet. Create or link the next reasoning steps.</p>}
        {paths.map((path, index) => (
          <div key={index} className="overflow-x-auto rounded border border-gray-800 bg-gray-950 p-3">
            <div className="flex min-w-max items-stretch gap-2">
              {path.map((node, nodeIndex) => (
                <div key={node.id} className="flex items-center gap-2">
                  <div className="w-52 rounded border border-gray-700 bg-gray-900 p-3">
                    <div className="text-[10px] uppercase text-gray-500">{NODE_LABELS[node.node_type]}</div>
                    <div className="mt-1 truncate text-sm font-semibold text-white">{node.title}</div>
                    <div className="mt-2 text-[10px] text-gray-500">{node.review_status} · confidence {node.confidence}</div>
                  </div>
                  {nodeIndex < path.length - 1 && <span className="text-gray-600">→</span>}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function GapTable({ gaps, onSelect }: { gaps: EvidenceGraphGap[]; onSelect: (id: string) => void }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-950/40">
      <div className="border-b border-gray-800 p-4">
        <h3 className="font-semibold text-white">Detection Gap View</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-xs">
          <thead className="bg-gray-950 text-gray-500">
            <tr>
              {['Technique', 'Evidence', 'Missing step', 'Required telemetry', 'Detection candidate', 'Rule status', 'Validation status', 'Analyst decision', 'Recommended next action'].map(head => <th key={head} className="px-3 py-2">{head}</th>)}
            </tr>
          </thead>
          <tbody>
            {gaps.map((gap, index) => (
              <tr key={`${gap.node_id}-${index}`} className="border-t border-gray-800">
                <td className="px-3 py-3 font-semibold text-mitre-accent">{gap.technique}</td>
                <td className="max-w-sm px-3 py-3 text-gray-300">{gap.evidence}</td>
                <td className="px-3 py-3 text-red-300">{gap.missing_step}</td>
                <td className="px-3 py-3 text-gray-400">{gap.required_telemetry || '-'}</td>
                <td className="px-3 py-3 text-gray-400">{gap.detection_candidate || '-'}</td>
                <td className="px-3 py-3 text-gray-400">{gap.rule_status || '-'}</td>
                <td className="px-3 py-3 text-gray-400">{gap.validation_status || '-'}</td>
                <td className="px-3 py-3 text-gray-400">{gap.analyst_decision || '-'}</td>
                <td className="px-3 py-3"><button className="text-left text-yellow-200 hover:text-yellow-100" onClick={() => gap.node_id && onSelect(gap.node_id)}>{gap.recommended_next_action}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ReviewQueue({ nodes, onSelect, onApprove, onReject }: { nodes: EvidenceGraphNode[]; onSelect: (id: string) => void; onApprove: (id: string) => void; onReject: (id: string) => void }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
      <h3 className="font-semibold text-white">Analyst Review Queue</h3>
      <div className="mt-4 grid gap-2">
        {nodes.length === 0 && <p className="text-sm text-gray-500">No unreviewed AI suggestions or blocked review items.</p>}
        {nodes.map(node => (
          <div key={node.id} className="rounded border border-gray-800 bg-gray-950 p-3">
            <button className="block w-full text-left" onClick={() => onSelect(node.id)}>
              <span className="text-[10px] uppercase text-gray-500">{NODE_LABELS[node.node_type]}</span>
              <span className="block text-sm font-semibold text-white">{node.title}</span>
              <span className="text-xs text-gray-400">{node.review_status}{node.ai_generated ? ' · AI-generated draft' : ''}</span>
            </button>
            <div className="mt-3 flex gap-2">
              <button className="secondary-action px-3 py-1 text-xs" onClick={() => onApprove(node.id)}>Approve</button>
              <button className="secondary-action px-3 py-1 text-xs text-red-200" onClick={() => onReject(node.id)}>Reject</button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function NodeDetail({ node, edges, onApprove, onReject, onNeedsEvidence, onNext }: { node?: EvidenceGraphNode; edges: EvidenceGraphEdge[]; onApprove: (node: EvidenceGraphNode) => void; onReject: (node: EvidenceGraphNode) => void; onNeedsEvidence: (node: EvidenceGraphNode) => void; onNext: (node: EvidenceGraphNode) => void }) {
  if (!node) {
    return <section className="rounded border border-gray-800 bg-gray-950/40 p-4 text-sm text-gray-500">Select a graph node to inspect details.</section>;
  }
  return (
    <section className="rounded border border-gray-800 bg-gray-950/40 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] uppercase text-gray-500">{NODE_LABELS[node.node_type]}</div>
          <h3 className="mt-1 text-lg font-semibold text-white">{node.title}</h3>
        </div>
        <span className={node.review_status === 'analyst_reviewed' ? 'rounded bg-green-900/40 px-2 py-1 text-xs text-green-200' : node.review_status === 'rejected' ? 'rounded bg-red-900/40 px-2 py-1 text-xs text-red-200' : 'rounded bg-yellow-900/40 px-2 py-1 text-xs text-yellow-200'}>
          {node.review_status}
        </span>
      </div>
      <div className="mt-4 grid gap-2 text-xs">
        <Info label="Confidence" value={`${node.confidence}/100`} />
        <Info label="Technique" value={node.technique_id || node.technique_name || '-'} />
        <Info label="Source" value={node.source_type || node.source_ref || '-'} />
        <Info label="Status" value={node.status || node.test_status || node.forwarding_status || node.decision || '-'} />
      </div>
      <TextBlock title="Description" text={node.description || node.statement || node.behavior_description || node.detection_hypothesis || node.mapping_rationale || node.raw_excerpt || node.normalized_summary} />
      <TextBlock title="Evidence excerpt" text={node.raw_excerpt} />
      <div className="mt-4 flex flex-wrap gap-2">
        <button className="secondary-action px-3 py-2 text-xs" onClick={() => onApprove(node)}>Approve</button>
        <button className="secondary-action px-3 py-2 text-xs" onClick={() => onNeedsEvidence(node)}>Needs evidence</button>
        <button className="secondary-action px-3 py-2 text-xs text-red-200" onClick={() => onReject(node)}>Reject</button>
        {NEXT_STEP[node.node_type] && <button className="primary-action px-3 py-2 text-xs" onClick={() => onNext(node)}>Create next-step node</button>}
      </div>
      <div className="mt-5">
        <h4 className="text-xs font-semibold uppercase text-gray-500">Linked edges</h4>
        <div className="mt-2 space-y-1">
          {edges.map(edge => <div key={edge.id} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs text-gray-400">{edge.edge_type} · {edge.review_status}</div>)}
          {edges.length === 0 && <div className="text-xs text-gray-600">No linked edges.</div>}
        </div>
      </div>
    </section>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="rounded bg-gray-950 p-2"><span className="block text-[10px] uppercase text-gray-600">{label}</span><span className="text-gray-200">{value}</span></div>;
}

function TextBlock({ title, text }: { title: string; text?: string }) {
  if (!text) return null;
  return (
    <div className="mt-4">
      <h4 className="text-xs font-semibold uppercase text-gray-500">{title}</h4>
      <p className="mt-2 max-h-48 overflow-y-auto whitespace-pre-wrap rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-300">{text}</p>
    </div>
  );
}

function WarningBox() {
  return (
    <div className="mt-4 rounded border border-yellow-700/60 bg-yellow-950/20 p-3 text-xs leading-5 text-yellow-100">
      AI output requires analyst review. Do not treat ATT&CK overlap as attribution proof. Static malware indicators are not behavior proof without validation.
    </div>
  );
}
