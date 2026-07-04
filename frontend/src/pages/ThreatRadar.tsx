import { useMemo, useState } from 'react';
import type React from 'react';
import type { Edge, Node } from '@xyflow/react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { EntityGraph } from '@/components/ui/graph';
import {
  threatRadarApi,
  type ThreatRadarCase,
  type ThreatRadarCreateSignal,
  type ThreatRadarProductMapping,
  type ThreatRadarReport,
  type ThreatRadarSignal,
  type ThreatSignalType,
} from '@/api/client';

const SIGNAL_TYPES: Array<{ id: ThreatSignalType; label: string }> = [
  { id: 'cve_disclosure', label: 'CVE disclosure' },
  { id: 'cisa_kev_active_exploitation', label: 'CISA KEV / active exploitation' },
  { id: 'public_poc', label: 'Public PoC' },
  { id: 'zero_day_claim', label: 'Zero-day claim' },
  { id: 'exploit_sale_claim', label: 'Exploit-sale claim' },
  { id: 'darknet_provider_mention', label: 'Closed-source provider mention' },
  { id: 'marketplace_hardware_listing', label: 'Hardware / prototype listing' },
  { id: 'firmware_dump_claim', label: 'Firmware dump claim' },
  { id: 'source_code_leak_claim', label: 'Source-code leak claim' },
  { id: 'credential_exposure', label: 'Credential exposure' },
  { id: 'supplier_breach', label: 'Supplier breach' },
  { id: 'malicious_package', label: 'Malicious package' },
  { id: 'critical_dependency_vulnerability', label: 'Critical dependency vulnerability' },
  { id: 'customer_report', label: 'Customer report' },
  { id: 'internal_telemetry_anomaly', label: 'Internal telemetry anomaly' },
];

const TABS = [
  ['dashboard', 'Dashboard'],
  ['inbox', 'Signal Inbox'],
  ['detail', 'Signal Detail'],
  ['cases', 'Cases'],
  ['graph', 'Case Graph'],
  ['exposure', 'Product Exposure'],
  ['watchlists', 'Watchlists'],
  ['workflows', 'Workflows'],
  ['reports', 'Reports'],
  ['settings', 'Settings / Sources'],
] as const;

type Tab = typeof TABS[number][0];

export function ThreatRadar() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>('dashboard');
  const [selectedSignalId, setSelectedSignalId] = useState('');
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [search, setSearch] = useState('');
  const [form, setForm] = useState({
    title: 'New active exploitation signal',
    signal_type: 'cisa_kev_active_exploitation' as ThreatSignalType,
    description: 'Threat signal that needs product exposure triage.',
    source_name: 'Manual analyst input',
    source_url: '',
    confidence: 80,
    severity: 'high',
    cve_ids: 'CVE-2026-0001',
    technique_ids: 'T1190',
    product: 'Customer-facing gateway',
    component: 'admin-ui',
    dependency: '',
    version: '',
    exposure: 'internet',
    environment: 'production',
    relevance: 4,
    blast_radius: 4,
    evidence: 'Sanitized source summary. No exploit material, credentials, or stolen data stored.',
    legal_sensitive: false,
  });

  const signals = useQuery({
    queryKey: ['threat-radar-signals', search],
    queryFn: () => threatRadarApi.signals({ q: search || undefined, limit: 100 }),
  });
  const cases = useQuery({ queryKey: ['threat-radar-cases'], queryFn: () => threatRadarApi.cases({ limit: 100 }) });
  const sources = useQuery({ queryKey: ['threat-radar-sources'], queryFn: threatRadarApi.sources });
  const exposure = useQuery({ queryKey: ['threat-radar-product-exposure'], queryFn: threatRadarApi.productExposure });
  const selectedSignal = useQuery({
    queryKey: ['threat-radar-signal', selectedSignalId],
    queryFn: () => threatRadarApi.signal(selectedSignalId),
    enabled: Boolean(selectedSignalId),
  });
  const selectedCase = useQuery({
    queryKey: ['threat-radar-case', selectedCaseId],
    queryFn: () => threatRadarApi.caseDetail(selectedCaseId),
    enabled: Boolean(selectedCaseId),
  });
  const graph = useQuery({
    queryKey: ['threat-radar-case-graph', selectedCaseId],
    queryFn: () => threatRadarApi.caseGraph(selectedCaseId),
    enabled: Boolean(selectedCaseId),
  });
  const watchlists = useQuery({
    queryKey: ['threat-radar-watchlists'],
    queryFn: async () => ({
      cve: await threatRadarApi.watchlist('cve'),
      zeroDay: await threatRadarApi.watchlist('zero-day'),
      supplyChain: await threatRadarApi.watchlist('supply-chain'),
      hardware: await threatRadarApi.watchlist('hardware'),
    }),
  });
  const queues = useQuery({
    queryKey: ['threat-radar-queues'],
    queryFn: async () => ({
      hunts: await threatRadarApi.queue('hunts'),
      psirt: await threatRadarApi.queue('psirt'),
      ir: await threatRadarApi.queue('ir'),
      detections: await threatRadarApi.queue('detections'),
      reports: await threatRadarApi.queue('reports'),
      actions: await threatRadarApi.queue('actions'),
      audit: await threatRadarApi.queue('audit'),
    }),
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['threat-radar-signals'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-cases'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-product-exposure'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-watchlists'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-queues'] });
    if (selectedSignalId) qc.invalidateQueries({ queryKey: ['threat-radar-signal', selectedSignalId] });
    if (selectedCaseId) {
      qc.invalidateQueries({ queryKey: ['threat-radar-case', selectedCaseId] });
      qc.invalidateQueries({ queryKey: ['threat-radar-case-graph', selectedCaseId] });
    }
  };

  const createSignal = useMutation({
    mutationFn: () => threatRadarApi.createSignal(buildCreatePayload(form)),
    onSuccess: data => {
      setSelectedSignalId(data.signal.id);
      if (data.case?.id) setSelectedCaseId(data.case.id);
      setTab('detail');
      invalidate();
    },
  });
  const actionMutation = useMutation({
    mutationFn: ({ caseId, type }: { caseId: string; type: string }) => {
      if (type === 'hunt') return threatRadarApi.createHunt(caseId);
      if (type === 'psirt') return threatRadarApi.createPsirtTask(caseId);
      if (type === 'ir') return threatRadarApi.createIrEscalation(caseId);
      return threatRadarApi.createDetectionRequirement(caseId);
    },
    onSuccess: invalidate,
  });
  const reportMutation = useMutation({
    mutationFn: ({ caseId, reportType }: { caseId: string; reportType: 'flash_note' | 'product_impact' | 'hunt_pack' | 'psirt_appendix' | 'executive_summary' }) =>
      threatRadarApi.generateReport(caseId, reportType),
    onSuccess: invalidate,
  });

  const stats = useMemo(() => {
    const rows = signals.data ?? [];
    const caseRows = cases.data ?? [];
    return {
      signals: rows.length,
      p0p1: caseRows.filter(item => item.priority.startsWith('P0') || item.priority.startsWith('P1')).length,
      legal: rows.filter(item => item.legal_sensitive).length,
      actions: caseRows.reduce((sum, item) => sum + (item.recommended_actions?.length ?? 0), 0),
    };
  }, [signals.data, cases.data]);

  const graphElements = useMemo(() => toFlowGraph(graph.data), [graph.data]);

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Threat Radar" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Product Security CTI early-warning radar</h2>
                <p className="mt-2 max-w-5xl text-sm leading-6 text-sky-100/80">
                  Collect threat signals, preserve sanitized evidence, map claims to products/components/dependencies,
                  score exposure, and turn decisions into PSIRT, Threat Hunt, IR, Legal, Engineering, Detection, and report workflows.
                  Closed-source and restricted intelligence is stored only as sanitized metadata with TLP and legal-sensitive flags.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
                <Metric label="Signals" value={stats.signals} />
                <Metric label="P0/P1 cases" value={stats.p0p1} tone="bad" />
                <Metric label="Legal-sensitive" value={stats.legal} tone="warn" />
                <Metric label="Recommended actions" value={stats.actions} />
              </div>
            </div>
          </section>

          <nav className="flex flex-wrap gap-2 rounded-lg border border-gray-800 bg-gray-950 p-2">
            {TABS.map(([id, label]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`rounded px-3 py-2 text-xs font-semibold transition-colors ${tab === id ? 'bg-mitre-accent text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'}`}
              >
                {label}
              </button>
            ))}
          </nav>

          {tab === 'dashboard' && (
            <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
              <Panel title="Create Threat Signal">
                <SignalForm form={form} setForm={setForm} onSubmit={() => createSignal.mutate()} pending={createSignal.isPending} error={createSignal.error} />
              </Panel>
              <Panel title="Risk Decision Logic">
                <div className="space-y-3 p-4 text-sm leading-6 text-gray-300">
                  <p>Score = source reliability, claim credibility, product relevance, exploitability, exposure, and blast radius.</p>
                  <PriorityLegend />
                  <div className="rounded border border-amber-500/40 bg-amber-950/20 p-3 text-xs text-amber-100">
                    Safety boundary: do not store exploit payloads, stolen credentials, stolen source, or illegal forum access data.
                    Use provider-derived sanitized metadata, TLP, and legal-sensitive flags only.
                  </div>
                </div>
              </Panel>
            </section>
          )}

          {tab === 'inbox' && (
            <Panel title="Signal Inbox">
              <div className="border-b border-gray-800 p-4">
                <input value={search} onChange={event => setSearch(event.target.value)} className="field w-full max-w-xl" placeholder="Search signals, products, sources..." />
              </div>
              <SignalTable
                signals={signals.data ?? []}
                loading={signals.isLoading}
                onSelect={signal => {
                  setSelectedSignalId(signal.id);
                  if (signal.score?.priority) setTab('detail');
                }}
              />
            </Panel>
          )}

          {tab === 'detail' && (
            <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
              <SignalDetail signal={selectedSignal.data ?? null} loading={selectedSignal.isLoading} />
              <CasePicker cases={cases.data ?? []} selectedCaseId={selectedCaseId} setSelectedCaseId={setSelectedCaseId} setTab={setTab} />
            </section>
          )}

          {tab === 'cases' && (
            <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_460px]">
              <Panel title="Case Detail">
                <CaseTable cases={cases.data ?? []} selectedCaseId={selectedCaseId} onSelect={item => setSelectedCaseId(item.id)} />
              </Panel>
              <CaseDetail
                detail={selectedCase.data ?? null}
                onCreateAction={(type) => selectedCaseId && actionMutation.mutate({ caseId: selectedCaseId, type })}
                actionPending={actionMutation.isPending}
                onReport={(reportType) => selectedCaseId && reportMutation.mutate({ caseId: selectedCaseId, reportType })}
                reportPending={reportMutation.isPending}
              />
            </section>
          )}

          {tab === 'graph' && (
            <Panel title="Case Graph">
              <div className="h-[620px] p-4">
                {selectedCaseId ? (
                  <EntityGraph nodes={graphElements.nodes} edges={graphElements.edges} />
                ) : (
                  <p className="text-sm text-gray-500">Select a case first.</p>
                )}
              </div>
            </Panel>
          )}

          {tab === 'exposure' && (
            <Panel title="Product Exposure">
              <ProductExposure rows={exposure.data ?? []} />
            </Panel>
          )}

          {tab === 'watchlists' && (
            <section className="grid gap-5 xl:grid-cols-2">
              <Watchlist title="CVE Watchlist" rows={watchlists.data?.cve ?? []} onSelect={setSelectedSignalId} />
              <Watchlist title="Zero-Day Claims" rows={watchlists.data?.zeroDay ?? []} onSelect={setSelectedSignalId} />
              <Watchlist title="Supply-Chain Watch" rows={watchlists.data?.supplyChain ?? []} onSelect={setSelectedSignalId} />
              <Watchlist title="Hardware / Marketplace Watch" rows={watchlists.data?.hardware ?? []} onSelect={setSelectedSignalId} />
            </section>
          )}

          {tab === 'workflows' && (
            <section className="grid gap-5 xl:grid-cols-2">
              <Queue title="Threat Hunt Requests" rows={queues.data?.hunts ?? []} />
              <Queue title="PSIRT Queue" rows={queues.data?.psirt ?? []} />
              <Queue title="IR Escalations" rows={queues.data?.ir ?? []} />
              <Queue title="Detection Requirements" rows={queues.data?.detections ?? []} />
              <Queue title="Actions" rows={queues.data?.actions ?? []} />
              <Queue title="Audit Log" rows={queues.data?.audit ?? []} />
            </section>
          )}

          {tab === 'reports' && (
            <Panel title="Reports">
              <Queue title="Generated Reports" rows={queues.data?.reports ?? []} />
            </Panel>
          )}

          {tab === 'settings' && (
            <Panel title="Settings / Sources">
              <SourceList rows={sources.data ?? []} />
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

function SignalForm({ form, setForm, onSubmit, pending, error }: {
  form: Record<string, string | number | boolean | ThreatSignalType>;
  setForm: React.Dispatch<React.SetStateAction<any>>;
  onSubmit: () => void;
  pending: boolean;
  error: unknown;
}) {
  const update = (key: string, value: string | number | boolean) => setForm((current: any) => ({ ...current, [key]: value }));
  return (
    <div className="space-y-4 p-4">
      <div className="grid gap-3 md:grid-cols-2">
        <label className="text-xs text-gray-400">Title<input className="field mt-1 w-full" value={String(form.title)} onChange={e => update('title', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Signal type
          <select className="field mt-1 w-full" value={String(form.signal_type)} onChange={e => update('signal_type', e.target.value)}>
            {SIGNAL_TYPES.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
          </select>
        </label>
        <label className="text-xs text-gray-400">Source<input className="field mt-1 w-full" value={String(form.source_name)} onChange={e => update('source_name', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Source URL<input className="field mt-1 w-full" value={String(form.source_url)} onChange={e => update('source_url', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Severity<select className="field mt-1 w-full" value={String(form.severity)} onChange={e => update('severity', e.target.value)}>{['critical', 'high', 'medium', 'low', 'unknown'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label className="text-xs text-gray-400">Confidence<input className="field mt-1 w-full" type="number" min={0} max={100} value={Number(form.confidence)} onChange={e => update('confidence', Number(e.target.value))} /></label>
        <label className="text-xs text-gray-400">CVEs<input className="field mt-1 w-full" value={String(form.cve_ids)} onChange={e => update('cve_ids', e.target.value)} placeholder="CVE-2026-0001, CVE-2026-0002" /></label>
        <label className="text-xs text-gray-400">TTPs<input className="field mt-1 w-full" value={String(form.technique_ids)} onChange={e => update('technique_ids', e.target.value)} placeholder="T1190, T1059" /></label>
      </div>
      <label className="block text-xs text-gray-400">Description<textarea className="field mt-1 min-h-24 w-full" value={String(form.description)} onChange={e => update('description', e.target.value)} /></label>
      <div className="grid gap-3 md:grid-cols-3">
        <label className="text-xs text-gray-400">Product<input className="field mt-1 w-full" value={String(form.product)} onChange={e => update('product', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Component<input className="field mt-1 w-full" value={String(form.component)} onChange={e => update('component', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Dependency<input className="field mt-1 w-full" value={String(form.dependency)} onChange={e => update('dependency', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Version<input className="field mt-1 w-full" value={String(form.version)} onChange={e => update('version', e.target.value)} /></label>
        <label className="text-xs text-gray-400">Exposure<select className="field mt-1 w-full" value={String(form.exposure)} onChange={e => update('exposure', e.target.value)}>{['internet', 'third-party', 'internal', 'lab', 'unknown'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label className="text-xs text-gray-400">Environment<select className="field mt-1 w-full" value={String(form.environment)} onChange={e => update('environment', e.target.value)}>{['production', 'staging', 'development', 'customer', 'unknown'].map(v => <option key={v}>{v}</option>)}</select></label>
        <label className="text-xs text-gray-400">Product relevance<input className="field mt-1 w-full" type="number" min={0} max={5} value={Number(form.relevance)} onChange={e => update('relevance', Number(e.target.value))} /></label>
        <label className="text-xs text-gray-400">Blast radius<input className="field mt-1 w-full" type="number" min={0} max={5} value={Number(form.blast_radius)} onChange={e => update('blast_radius', Number(e.target.value))} /></label>
        <label className="flex items-center gap-2 rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-300">
          <input type="checkbox" checked={Boolean(form.legal_sensitive)} onChange={e => update('legal_sensitive', e.target.checked)} />
          Legal-sensitive / restricted metadata
        </label>
      </div>
      <label className="block text-xs text-gray-400">Sanitized evidence summary<textarea className="field mt-1 min-h-24 w-full" value={String(form.evidence)} onChange={e => update('evidence', e.target.value)} /></label>
      {Boolean(error) && <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-xs text-red-100">{error instanceof Error ? error.message : 'Create failed'}</div>}
      <button className="primary-action min-h-10 w-full" onClick={onSubmit} disabled={pending}>{pending ? 'Creating...' : 'Create signal, score, map, and open case'}</button>
    </div>
  );
}

function SignalTable({ signals, loading, onSelect }: { signals: ThreatRadarSignal[]; loading: boolean; onSelect: (signal: ThreatRadarSignal) => void }) {
  if (loading) return <p className="p-4 text-sm text-gray-500">Loading signals...</p>;
  if (signals.length === 0) return <p className="p-4 text-sm text-gray-500">No threat signals yet.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="bg-gray-950 text-xs uppercase text-gray-500"><tr><th className="p-3">Signal</th><th>Score</th><th>Type</th><th>Source</th><th>Tags</th></tr></thead>
        <tbody>
          {signals.map(signal => (
            <tr key={signal.id} onClick={() => onSelect(signal)} className="cursor-pointer border-t border-gray-800 hover:bg-gray-900/60">
              <td className="p-3"><b className="text-white">{signal.title}</b><p className="mt-1 line-clamp-2 text-xs text-gray-500">{signal.description}</p></td>
              <td><ScoreBadge score={signal.score?.score ?? 0} priority={signal.score?.priority ?? 'P4'} /></td>
              <td className="font-mono text-xs text-gray-400">{signal.signal_type}</td>
              <td className="text-xs text-gray-500">{signal.source_name || '-'}</td>
              <td><TagList tags={[...signal.cve_ids, ...signal.technique_ids, ...signal.tags].slice(0, 8)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SignalDetail({ signal, loading }: { signal: ThreatRadarSignal | null; loading: boolean }) {
  if (loading) return <Panel title="Signal Detail"><p className="p-4 text-sm text-gray-500">Loading signal...</p></Panel>;
  if (!signal) return <Panel title="Signal Detail"><p className="p-4 text-sm text-gray-500">Select a signal from the inbox or create a new signal.</p></Panel>;
  return (
    <Panel title={signal.title}>
      <div className="space-y-4 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <ScoreBadge score={signal.score?.score ?? 0} priority={signal.score?.priority ?? 'P4 Low/Archive'} />
          <span className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-400">{signal.signal_type}</span>
          <span className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-400">{signal.tlp}</span>
          {signal.legal_sensitive && <span className="rounded bg-amber-900/60 px-2 py-1 text-xs text-amber-100">legal-sensitive</span>}
        </div>
        <p className="leading-6 text-gray-300">{signal.description}</p>
        <FactorGrid factors={signal.score?.factors ?? {}} />
        <InfoBlock title="Product Mapping">
          {signal.product_mappings.length ? <ProductExposure rows={signal.product_mappings} compact /> : <p className="text-xs text-gray-500">No product mapping recorded.</p>}
        </InfoBlock>
        <InfoBlock title="Recommended Actions">
          <ActionList actions={signal.recommended_actions} />
        </InfoBlock>
        <InfoBlock title="Sanitized Metadata">
          <pre className="max-h-52 overflow-auto whitespace-pre-wrap rounded bg-gray-950 p-3 text-xs text-gray-400">{JSON.stringify(signal.raw_metadata, null, 2)}</pre>
        </InfoBlock>
      </div>
    </Panel>
  );
}

function CasePicker({ cases, selectedCaseId, setSelectedCaseId, setTab }: { cases: ThreatRadarCase[]; selectedCaseId: string; setSelectedCaseId: (id: string) => void; setTab: (tab: Tab) => void }) {
  return (
    <Panel title="Cases">
      <div className="space-y-2 p-4">
        {cases.map(item => (
          <button key={item.id} onClick={() => { setSelectedCaseId(item.id); setTab('cases'); }} className={`w-full rounded border p-3 text-left text-sm ${selectedCaseId === item.id ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-800 bg-gray-950 hover:border-gray-600'}`}>
            <b className="text-white">{item.title}</b>
            <div className="mt-2 flex items-center gap-2"><ScoreBadge score={item.risk_score} priority={item.priority} /></div>
          </button>
        ))}
        {cases.length === 0 && <p className="text-sm text-gray-500">No cases yet.</p>}
      </div>
    </Panel>
  );
}

function CaseTable({ cases, selectedCaseId, onSelect }: { cases: ThreatRadarCase[]; selectedCaseId: string; onSelect: (item: ThreatRadarCase) => void }) {
  if (cases.length === 0) return <p className="p-4 text-sm text-gray-500">No cases yet.</p>;
  return <div className="divide-y divide-gray-800">{cases.map(item => (
    <button key={item.id} onClick={() => onSelect(item)} className={`w-full p-4 text-left hover:bg-gray-900/60 ${selectedCaseId === item.id ? 'bg-mitre-accent/10' : ''}`}>
      <div className="flex items-start justify-between gap-3"><b className="text-white">{item.title}</b><ScoreBadge score={item.risk_score} priority={item.priority} /></div>
      <p className="mt-2 line-clamp-2 text-xs leading-5 text-gray-500">{item.summary}</p>
      <TagList tags={item.tags.slice(0, 8)} />
    </button>
  ))}</div>;
}

function CaseDetail({ detail, onCreateAction, actionPending, onReport, reportPending }: {
  detail: { case: ThreatRadarCase; actions: Array<Record<string, unknown>>; reports: ThreatRadarReport[] } | null;
  onCreateAction: (type: string) => void;
  actionPending: boolean;
  onReport: (reportType: 'flash_note' | 'product_impact' | 'hunt_pack' | 'psirt_appendix' | 'executive_summary') => void;
  reportPending: boolean;
}) {
  if (!detail) return <Panel title="Selected Case"><p className="p-4 text-sm text-gray-500">Select a case to work actions and reports.</p></Panel>;
  return (
    <Panel title="Selected Case">
      <div className="space-y-4 p-4 text-sm">
        <div className="flex items-center gap-2"><ScoreBadge score={detail.case.risk_score} priority={detail.case.priority} />{detail.case.legal_sensitive && <span className="rounded bg-amber-900/60 px-2 py-1 text-xs text-amber-100">legal-sensitive</span>}</div>
        <p className="leading-6 text-gray-300">{detail.case.summary}</p>
        <InfoBlock title="Create Workflow">
          <div className="grid grid-cols-2 gap-2">
            {['hunt', 'psirt', 'ir', 'detection'].map(type => <button key={type} className="secondary-action" disabled={actionPending} onClick={() => onCreateAction(type)}>{type}</button>)}
          </div>
        </InfoBlock>
        <InfoBlock title="Generate Reports">
          <div className="grid grid-cols-1 gap-2">
            {[
              ['flash_note', 'Flash Intelligence Note'],
              ['product_impact', 'Product Impact Assessment'],
              ['hunt_pack', 'Threat Hunt Pack'],
              ['psirt_appendix', 'PSIRT Intelligence Appendix'],
              ['executive_summary', 'Executive Summary'],
            ].map(([id, label]) => <button key={id} className="secondary-action" disabled={reportPending} onClick={() => onReport(id as any)}>{label}</button>)}
          </div>
        </InfoBlock>
        <InfoBlock title="Actions"><QueueRows rows={detail.actions} /></InfoBlock>
        <InfoBlock title="Reports"><QueueRows rows={detail.reports} /></InfoBlock>
      </div>
    </Panel>
  );
}

function ProductExposure({ rows, compact = false }: { rows: ThreatRadarProductMapping[]; compact?: boolean }) {
  if (!rows.length) return <p className="p-4 text-sm text-gray-500">No product exposure mappings yet.</p>;
  return (
    <div className={compact ? '' : 'overflow-x-auto'}>
      <table className="w-full text-left text-sm">
        <thead className="bg-gray-950 text-xs uppercase text-gray-500"><tr><th className="p-3">Product</th><th>Component</th><th>Exposure</th><th>Rel.</th><th>Blast</th></tr></thead>
        <tbody>{rows.map((row, idx) => <tr key={row.id ?? idx} className="border-t border-gray-800"><td className="p-3 text-white">{row.product}</td><td className="text-gray-400">{row.component || row.dependency || '-'}</td><td className="text-gray-400">{row.exposure}</td><td>{row.relevance ?? '-'}/5</td><td>{row.blast_radius ?? '-'}/5</td></tr>)}</tbody>
      </table>
    </div>
  );
}

function Watchlist({ title, rows, onSelect }: { title: string; rows: ThreatRadarSignal[]; onSelect: (id: string) => void }) {
  return <Panel title={title}>{rows.length ? <div className="divide-y divide-gray-800">{rows.map(row => <button key={row.id} onClick={() => onSelect(row.id)} className="w-full p-4 text-left hover:bg-gray-900/60"><b className="text-white">{row.title}</b><div className="mt-2"><ScoreBadge score={row.score?.score ?? 0} priority={row.score?.priority ?? 'P4'} /></div></button>)}</div> : <p className="p-4 text-sm text-gray-500">No signals in this watchlist.</p>}</Panel>;
}

function Queue({ title, rows }: { title: string; rows: Array<Record<string, unknown>> }) {
  return <Panel title={title}><QueueRows rows={rows} /></Panel>;
}

function QueueRows({ rows }: { rows: Array<Record<string, unknown> | ThreatRadarReport> }) {
  if (!rows.length) return <p className="p-4 text-sm text-gray-500">No records yet.</p>;
  return <div className="divide-y divide-gray-800">{rows.slice(0, 50).map((row, idx) => <pre key={String(row.id ?? idx)} className="overflow-auto whitespace-pre-wrap p-3 text-xs text-gray-400">{JSON.stringify(row, null, 2)}</pre>)}</div>;
}

function SourceList({ rows }: { rows: Array<{ id: string; name: string; source_type: string; reliability: number; tlp: string; legal_sensitive: boolean; enabled: boolean; url: string }> }) {
  if (!rows.length) return <p className="p-4 text-sm text-gray-500">No configured Threat Radar sources yet. Creating a signal with a source will register one.</p>;
  return <div className="divide-y divide-gray-800">{rows.map(row => <div key={row.id} className="p-4"><b className="text-white">{row.name}</b><p className="mt-1 text-xs text-gray-500">{row.source_type} · reliability {row.reliability}/5 · {row.tlp} · {row.legal_sensitive ? 'legal-sensitive' : 'standard'}</p><p className="mt-1 truncate text-xs text-gray-600">{row.url}</p></div>)}</div>;
}

function buildCreatePayload(form: Record<string, any>): ThreatRadarCreateSignal {
  const legalSensitiveTypes = new Set(['exploit_sale_claim', 'darknet_provider_mention', 'marketplace_hardware_listing', 'firmware_dump_claim', 'source_code_leak_claim', 'credential_exposure', 'supplier_breach']);
  return {
    title: String(form.title).trim(),
    signal_type: form.signal_type,
    description: String(form.description),
    source: {
      name: String(form.source_name || 'Manual analyst input'),
      source_type: 'manual',
      url: String(form.source_url || ''),
      reliability: form.signal_type === 'cisa_kev_active_exploitation' ? 5 : 3,
      tlp: legalSensitiveTypes.has(form.signal_type) || form.legal_sensitive ? 'TLP:AMBER' : 'TLP:CLEAR',
      legal_sensitive: Boolean(form.legal_sensitive || legalSensitiveTypes.has(form.signal_type)),
    },
    confidence: Number(form.confidence),
    severity: String(form.severity),
    cve_ids: splitList(String(form.cve_ids)),
    technique_ids: splitList(String(form.technique_ids)).map(item => item.toUpperCase()),
    legal_sensitive: Boolean(form.legal_sensitive || legalSensitiveTypes.has(form.signal_type)),
    raw_metadata: { product_relevance: Number(form.relevance), exposure: exposureFactor(String(form.exposure)), blast_radius: Number(form.blast_radius) },
    evidence: [{ title: 'Sanitized evidence summary', summary: String(form.evidence), legal_sensitive: Boolean(form.legal_sensitive) }],
    claims: [{ statement: String(form.description), credibility: Number(form.confidence) >= 80 ? 4 : 3 }],
    product_mappings: [{
      product: String(form.product),
      component: String(form.component),
      dependency: String(form.dependency),
      version: String(form.version),
      exposure: String(form.exposure),
      environment: String(form.environment),
      relevance: Number(form.relevance),
      blast_radius: Number(form.blast_radius),
      evidence: String(form.evidence),
      tags: [String(form.exposure), String(form.environment)],
      technique_ids: splitList(String(form.technique_ids)),
    }],
    create_case: true,
  };
}

function toFlowGraph(graph: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> } | undefined): { nodes: Node[]; edges: Edge[] } {
  if (!graph) return { nodes: [], edges: [] };
  return {
    nodes: graph.nodes.map((node, index) => ({
      id: String(node.id),
      data: { label: `${String(node.type ?? 'node')}\n${String(node.label ?? node.id)}` },
      position: { x: (index % 4) * 240, y: Math.floor(index / 4) * 150 },
      style: { background: '#020617', color: '#e5e7eb', border: '1px solid #334155', width: 190, fontSize: 11, whiteSpace: 'pre-line' },
    })),
    edges: graph.edges.map((edge, index) => ({
      id: `edge-${index}`,
      source: String(edge.source),
      target: String(edge.target),
      label: String(edge.relationship ?? ''),
      style: { stroke: '#fb7185' },
    })),
  };
}

function splitList(value: string) {
  return value.split(/[,\s]+/).map(item => item.trim()).filter(Boolean);
}

function exposureFactor(value: string) {
  if (value === 'internet') return 5;
  if (value === 'third-party') return 4;
  if (value === 'internal') return 3;
  return 2;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/30"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function Metric({ label, value, tone = 'neutral' }: { label: string; value: number; tone?: 'neutral' | 'bad' | 'warn' }) {
  const color = tone === 'bad' ? 'text-red-200' : tone === 'warn' ? 'text-amber-200' : 'text-white';
  return <div className="min-w-28 rounded border border-gray-800 bg-gray-950 px-3 py-2"><div className={`text-xl font-semibold ${color}`}>{value}</div><div className="text-[11px] text-gray-500">{label}</div></div>;
}

function ScoreBadge({ score, priority }: { score: number; priority: string }) {
  const tone = score >= 75 ? 'bg-red-900/60 text-red-100' : score >= 55 ? 'bg-amber-900/60 text-amber-100' : 'bg-gray-800 text-gray-300';
  return <span className={`inline-flex rounded px-2 py-1 text-xs font-semibold ${tone}`}>{score}/100 · {priority}</span>;
}

function PriorityLegend() {
  return <div className="grid gap-2 text-xs">{['90-100 P0 Emergency', '75-89 P1 High', '55-74 P2 Medium', '30-54 P3 Monitor', '0-29 P4 Low/Archive'].map(item => <div key={item} className="rounded bg-gray-950 px-3 py-2 text-gray-400">{item}</div>)}</div>;
}

function FactorGrid({ factors }: { factors: Record<string, number> }) {
  return <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{Object.entries(factors).map(([key, value]) => <div key={key} className="rounded border border-gray-800 bg-gray-950 p-3"><div className="text-xs uppercase text-gray-500">{key.replace(/_/g, ' ')}</div><div className="mt-1 text-lg font-semibold text-white">{value}/5</div></div>)}</div>;
}

function InfoBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return <section><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>{children}</section>;
}

function ActionList({ actions }: { actions: Array<{ type: string; title: string; owner_team: string; description: string }> }) {
  if (!actions.length) return <p className="text-xs text-gray-500">No actions recommended.</p>;
  return <div className="space-y-2">{actions.map(action => <div key={`${action.type}-${action.title}`} className="rounded border border-gray-800 bg-gray-950 p-3"><b className="text-sm text-white">{action.title}</b><p className="mt-1 text-xs text-gray-500">{action.owner_team} · {action.description}</p></div>)}</div>;
}

function TagList({ tags }: { tags: string[] }) {
  if (!tags.length) return null;
  return <div className="mt-2 flex flex-wrap gap-1">{tags.map(tag => <span key={tag} className="rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400">{tag}</span>)}</div>;
}
