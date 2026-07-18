import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { aptApi, attackApi, analyzeApi, iocApi, operationsApi, type IOCItem, type Investigation } from '@/api/client';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';
import { IocLink } from '@/utils/ctiLinks';
import { safeHref } from '@/utils/url';

type Provider = 'local' | 'claude' | 'openai' | 'gemini' | 'minimax';
type ReportFormat = 'md' | 'txt' | 'pdf';
type ReportSections = {
  navigator: boolean;
  ttps: boolean;
  actors: boolean;
  iocs: boolean;
};
type ReportRow = {
  id: string;
  name: string;
  assessment: {
    evidence?: string;
    source?: string;
    confidence?: string;
    mapping?: string;
    notes?: string;
    maturity?: string;
  };
  covered: boolean;
};
type SavedReportNode = {
  id: string;
  type: string;
  label: string;
  summary?: string;
  content?: string;
  provider?: string;
  format?: string;
  created_at?: string;
};
type SourceTaggedEvidence = {
  sourceTag: string;
  reference: string;
  evidence: string;
  confidence?: string | number;
};
type EvidenceIndex = {
  ttps: Map<string, SourceTaggedEvidence[]>;
  iocs: Map<string, SourceTaggedEvidence[]>;
};
type ReportIocItem = {
  value: string;
  type: string;
  sourceTag: string;
  reference: string;
  source?: string;
  source_url?: string;
  first_seen?: string | null;
  last_seen?: string | null;
  confidence?: number;
  tlp?: string;
  malware_family?: string;
  campaign?: string;
  technique_ids?: string[];
  evidence?: string;
};

const providerOptions: { id: Provider; label: string }[] = [
  { id: 'local', label: 'Local LLM' },
  { id: 'claude', label: 'Claude' },
  { id: 'openai', label: 'OpenAI' },
  { id: 'gemini', label: 'Gemini' },
  { id: 'minimax', label: 'MiniMax' },
];

const INVESTIGATION_REPORT_SYSTEM_PROMPT = [
  'You are the AdversaryGraph investigation report writer.',
  'Create a polished, human-readable threat intelligence report in Markdown.',
  'Do not output raw JSON, schema labels, or compressed one-line Markdown.',
  'Use clear paragraphs, analyst language, and defensible caveats.',
  '',
  'Required report schema:',
  '# <report title>',
  '## Executive Summary',
  'Short narrative summary of what was observed, what matters, and what remains uncertain.',
  '## Scope and Inputs',
  'Describe selected domain, investigation workspace, selected TTPs, report/log inputs, IOC enrichment, and actor comparison inputs.',
  '## Key Findings',
  'Use concise findings with evidence and operational meaning.',
  '## ATT&CK TTP Evidence',
  'For every TTP you report, include exactly these fields in readable prose or bullets:',
  '- Technique: ATT&CK ID and name',
  '- Source tag: log, pcap, report, manual, ioc-investigation, or feed/source name',
  '- Why it is relevant: explain the behavior or platform signal that caused this TTP to be included',
  '- Evidence: quote or summarize the evidence from logs, reports, analyst notes, Navigator coverage, or enrichment',
  '- Reference: the exact source of the TTP, such as log filename, PCAP filename, report/session ID, manual Navigator selection, IOC investigation ID, feed, or enrichment platform',
  '- Confidence: high / medium / low and why',
  'If a TTP has no direct evidence, mark it as a coverage/planning item and do not present it as observed behavior.',
  '## IOC Evidence and Enrichment',
  'For every IOC you report, include exactly these fields:',
  '- Indicator: value and type',
  '- Source tag: log, pcap, report, manual, ioc-investigation, or feed/source name',
  '- Why it is relevant: actor link, report link, feed hit, local extraction, or enrichment relationship',
  '- Evidence: source result, malware/campaign context, first/last seen, confidence, or extracted log context',
  '- Reference: the exact source of the IOC, such as log filename, PCAP filename, report/session ID, manual entry, IOC investigation ID, feed, OpenCTI/MISP/TAXII/source URL, or enrichment platform',
  '- Recommended handling: monitor, block, hunt, enrich further, or validate first',
  '## Threat Actor Comparison',
  'Explain overlap as hypothesis generation only. Include shared TTPs and why high-frequency TTPs are weaker signals.',
  '## Detection and Hunting Priorities',
  'Translate TTPs and IOCs into practical detection/hunting actions.',
  '## Limitations and Caveats',
  'State missing evidence, enrichment uncertainty, source conflicts, and that overlap is not attribution.',
  '## Recommended Next Actions',
  'Give concrete analyst next steps.',
  '',
  'Rules:',
  '- Never use proves, confirms, attributes, or matches for attribution.',
  '- Do not invent evidence, IOCs, references, actors, or TTPs.',
  '- Prefer fewer well-explained TTPs/IOCs over a long weak list.',
  '- If evidence is missing, say what validation is required.',
  '- Do not use generic workspace references when a specific source tag or source reference is available.',
].join('\n');

export function InvestigationReport() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { domain, version, selectedTechniques, coverageTechniques, techniqueAssessments, replaceTechniques } = useAppStore();
  const canRunAnalysis = useHasPermission('run_analysis');
  const canManageIntel = useHasPermission('manage_intel');
  const canExportData = useHasPermission('export_data');
  const ids = useMemo(() => [...selectedTechniques].sort(), [selectedTechniques]);
  const [activeInvestigationId, setActiveInvestigationId] = useState('');
  const [newInvestigationName, setNewInvestigationName] = useState('');
  const [sections, setSections] = useState<ReportSections>({
    navigator: true,
    ttps: true,
    actors: true,
    iocs: true,
  });
  const [provider, setProvider] = useState<Provider>('local');
  const [reportTitle, setReportTitle] = useState('AdversaryGraph Investigation Report');
  const [generatedReport, setGeneratedReport] = useState('');
  const [selectedSavedReportId, setSelectedSavedReportId] = useState('');
  const [aiSummary, setAiSummary] = useState('');
  const [summaryViewer, setSummaryViewer] = useState<{ title: string; text: string; source?: string } | null>(null);
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [isSummaryGenerating, setIsSummaryGenerating] = useState(false);
  const [aiError, setAiError] = useState('');
  const [workflowMessage, setWorkflowMessage] = useState('');
  const { data: investigations = [] } = useQuery({
    queryKey: ['operations-investigations'],
    queryFn: operationsApi.investigations,
    enabled: canRunAnalysis,
  });
  const activeInvestigation = useMemo(
    () => investigations.find(item => item.id === activeInvestigationId) ?? investigations[0] ?? null,
    [activeInvestigationId, investigations],
  );
  const investigationIds = useMemo(
    () => Array.from(new Set([...(activeInvestigation?.technique_ids ?? []), ...ids])).sort(),
    [activeInvestigation, ids],
  );
  const createInvestigation = useMutation({
    mutationFn: () => operationsApi.createInvestigation({
      name: newInvestigationName.trim() || `Investigation ${new Date().toLocaleString()}`,
      description: 'Structured AdversaryGraph investigation workspace.',
      status: 'active',
      domain,
      actor_ids: [],
      technique_ids: ids,
      report_ids: [],
      evidence_nodes: [],
      evidence_edges: [],
      timeline: [{ at: new Date().toISOString(), event: 'Investigation created' }],
    }),
    onSuccess: row => {
      setActiveInvestigationId(row.id);
      setNewInvestigationName('');
      queryClient.invalidateQueries({ queryKey: ['operations-investigations'] });
    },
  });

  const { data: techniques = [] } = useQuery({
    queryKey: ['report-techniques', domain, version],
    queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }),
  });
  const { data: matches = [], isFetching: matchesLoading } = useQuery({
    queryKey: ['report-matches', domain, version, investigationIds.join(',')],
    queryFn: () => aptApi.compare({ technique_ids: investigationIds, domain, version: version ?? undefined, top_n: 10 }),
    enabled: canRunAnalysis && investigationIds.length > 0,
  });

  const actorIocQueries = useQueries({
    queries: sections.iocs
      ? matches.slice(0, 5).map(match => ({
        queryKey: ['report-actor-iocs', match.group_attack_id],
        queryFn: () => iocApi.actor(match.group_attack_id, { days: 180, active_only: true, limit: 20 }),
        enabled: canRunAnalysis && investigationIds.length > 0,
      }))
      : [],
  });

  const rows = useMemo(() => investigationIds.map(id => ({
    id,
    name: techniques.find(item => item.attack_id === id)?.name ?? id,
    assessment: techniqueAssessments[id] ?? {},
    covered: coverageTechniques.has(id),
  })), [coverageTechniques, investigationIds, techniqueAssessments, techniques]);

  const relevantIocs = useMemo(
    () => actorIocQueries.flatMap(query => (query.data ?? []) as IOCItem[]),
    [actorIocQueries],
  );
  const evidenceIndex = useMemo(() => buildEvidenceIndex(activeInvestigation), [activeInvestigation]);
  const localReport = useMemo(
    () => buildLocalReport({ title: reportTitle, domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation, evidenceIndex }),
    [activeInvestigation, domain, evidenceIndex, matches, relevantIocs, reportTitle, rows, sections],
  );
  const savedReports = useMemo(() => savedReportNodes(activeInvestigation), [activeInvestigation]);
  const selectedSavedReport = useMemo(
    () => savedReports.find(report => report.id === selectedSavedReportId) ?? null,
    [savedReports, selectedSavedReportId],
  );
  const activeReport = selectedSavedReport?.content || generatedReport || localReport;
  const activeReportTitle = selectedSavedReport?.label || reportTitle || 'adversarygraph-investigation-report';
  const selectedSectionCount = Object.values(sections).filter(Boolean).length;

  const updateActiveInvestigation = useMutation({
    mutationFn: (body: Omit<Investigation, 'id' | 'created_at' | 'updated_at'>) => {
      if (!activeInvestigation) throw new Error('Create or select an investigation first.');
      return operationsApi.updateInvestigation(activeInvestigation.id, body);
    },
    onSuccess: row => {
      setActiveInvestigationId(row.id);
      queryClient.invalidateQueries({ queryKey: ['operations-investigations'] });
    },
  });

  const toggleSection = (key: keyof ReportSections) => {
    setSections(current => ({ ...current, [key]: !current[key] }));
  };

  const openLayerOnMatrix = () => {
    if (!investigationIds.length) return;
    replaceTechniques(investigationIds);
    setWorkflowMessage(`Loaded ${investigationIds.length} investigation TTPs into the matrix.`);
    navigate('/navigator');
  };

  const compareAndSave = async () => {
    if (!canRunAnalysis || !canManageIntel) {
      setWorkflowMessage('run_analysis and manage_intel permissions are required to compare and save actor leads.');
      return;
    }
    if (!activeInvestigation || !investigationIds.length) {
      setWorkflowMessage('Create/select an investigation and add TTPs before comparing.');
      return;
    }
    setWorkflowMessage('');
    try {
      const results = await aptApi.compare({ technique_ids: investigationIds, domain, version: version ?? undefined, top_n: 10 });
      await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
        actor_ids: results.slice(0, 10).map(item => item.group_attack_id),
        evidence_nodes: [{
          id: `actor-comparison:${Date.now()}`,
          type: 'actor-comparison',
          label: 'Threat actor TTP comparison',
          summary: `Compared ${investigationIds.length} investigation TTPs against known actor profiles.`,
          results: results.slice(0, 10),
        }],
        timeline: [{
          at: new Date().toISOString(),
          event: `Compared investigation TTP layer with threat actors (${results.length} results)`,
          source: 'Investigation',
          technique_count: investigationIds.length,
        }],
      }));
      replaceTechniques(investigationIds);
      setWorkflowMessage(`Saved ${Math.min(results.length, 10)} actor-comparison leads to ${activeInvestigation.name}.`);
    } catch (error) {
      setWorkflowMessage(error instanceof Error ? error.message : String(error));
    }
  };

  const summarizeInvestigation = async () => {
    if (!canRunAnalysis || !canManageIntel) {
      setWorkflowMessage('run_analysis and manage_intel permissions are required to generate and save an investigation summary.');
      return;
    }
    if (!activeInvestigation || !investigationIds.length) {
      setWorkflowMessage('Create/select an investigation and add evidence before AI summary.');
      return;
    }
    setIsSummaryGenerating(true);
    setAiError('');
    setWorkflowMessage('');
    try {
      const context = buildReportContext({ domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation, evidenceIndex });
      const response = await analyzeApi.chat({
        provider,
        context,
        message: [
          `Summarize the active investigation "${activeInvestigation.name}".`,
          'Use this structure: current assessment, strongest evidence, IOC findings, TTP layer, actor-comparison leads, caveats, and next actions.',
          'Use only the provided evidence. Do not claim attribution. Separate direct evidence from enrichment leads.',
        ].join(' '),
      });
      const summary = (await readSseText(response)).trim() || 'AI summary returned no content.';
      setAiSummary(summary);
      await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
        evidence_nodes: [{
          id: `ai-summary:${Date.now()}`,
          type: 'ai-summary',
          label: 'AI investigation summary',
          summary,
          provider,
        }],
        timeline: [{
          at: new Date().toISOString(),
          event: 'Generated AI investigation summary',
          source: provider,
          technique_count: investigationIds.length,
        }],
      }));
      setWorkflowMessage(`AI summary saved to ${activeInvestigation.name}.`);
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsSummaryGenerating(false);
    }
  };

  const saveGeneratedReport = async (content: string, mode: 'local' | Provider, title = reportTitle) => {
    if (!activeInvestigation || !canManageIntel) {
      setGeneratedReport(content);
      setWorkflowMessage(!activeInvestigation
        ? 'Report generated. Create or select an investigation to save it to the report list.'
        : 'Report generated in read-only mode. manage_intel is required to save it to the investigation.');
      return;
    }
    const reportNode = buildSavedReportNode({ title, content, provider: mode, format: 'markdown' });
    await updateActiveInvestigation.mutateAsync(mergeInvestigation(activeInvestigation, {
      report_ids: [reportNode.id],
      evidence_nodes: [reportNode],
      timeline: [{
        at: new Date().toISOString(),
        event: `Generated investigation report: ${title}`,
        source: mode,
        technique_count: investigationIds.length,
      }],
    }));
    setSelectedSavedReportId(reportNode.id);
    setWorkflowMessage(`Report saved to ${activeInvestigation.name}.`);
  };

  const generateLocal = async () => {
    setAiError('');
    setGeneratedReport(localReport);
    await saveGeneratedReport(localReport, 'local');
  };

  const generateWithAi = async () => {
    if (!canRunAnalysis || !investigationIds.length || !selectedSectionCount) return;
    setIsAiGenerating(true);
    setAiError('');
    setGeneratedReport('');
    try {
      const context = buildReportContext({ domain, rows, matches, relevantIocs, sections, investigation: activeInvestigation, evidenceIndex });
      const response = await analyzeApi.chat({
        provider,
        context,
        system_prompt: INVESTIGATION_REPORT_SYSTEM_PROMPT,
        message: [
          `Generate the investigation report titled "${reportTitle}".`,
          'Use the required report schema from the system instructions.',
          'Use only the provided context.',
          'For every TTP and IOC included, explain why it is relevant, what evidence supports it, and which reference/source it came from.',
          'If a TTP or IOC lacks direct evidence, state that it is a hypothesis or coverage item requiring validation.',
          'Make the report client-ready, readable, concise, and actionable.',
        ].join(' '),
      });
      const text = await readSseText(response);
      const report = text.trim() || localReport;
      setGeneratedReport(report);
      await saveGeneratedReport(report, provider);
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsAiGenerating(false);
    }
  };

  const download = (format: ReportFormat) => {
    if (!canExportData) return;
    const filenameBase = slug(activeReportTitle || 'adversarygraph-investigation-report');
    if (format === 'pdf') {
      const pdf = buildSimplePdf(markdownToPlainText(activeReport));
      downloadBlob(pdf, `${filenameBase}.pdf`, 'application/pdf');
      return;
    }
    const content = format === 'txt' ? markdownToPlainText(activeReport) : activeReport;
    downloadBlob(content, `${filenameBase}.${format}`, format === 'md' ? 'text/markdown' : 'text/plain');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Investigation" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <Panel title="Investigation flow">
            <div className="grid gap-3 p-3 lg:grid-cols-3">
              <FlowStep number={1} title="Create new investigation" text="Open a case workspace before analysis so every result has a destination." />
              <FlowStep number={2} title="Analyze logs one by one" text="Open AI Analysis Log / PCAP mode. Analyze firewall logs first, then EDR logs as a separate run. No manual prompt is needed." actionLabel="Open AI Analysis" onAction={() => navigate('/analyze')} />
              <FlowStep number={3} title="Add each result to my investigation" text="After each log analysis run, use Add to investigation and choose this case." />
              <FlowStep number={4} title="Do additional IOC investigations" text="Investigate extracted IOCs and add useful IOC results back to the same case." actionLabel="Open IOC Investigation" onAction={() => navigate('/ioc-investigation')} />
              <FlowStep number={5} title="Keep investigation structured" text="Review logs, reports, TTP layer, IOC list, evidence nodes, and timeline below." />
              <FlowStep number={6} title="Create Navigator-like TTP layer" text="Send all investigation TTPs to the ATT&CK matrix." actionLabel="Send to matrix" onAction={openLayerOnMatrix} disabled={!investigationIds.length} />
              <FlowStep number={7} title="Compare TTPs with threat actors" text="Compare the investigation layer and save overlap leads to this case." actionLabel="Compare + save" onAction={() => void compareAndSave()} disabled={!canManageIntel || !activeInvestigation || !investigationIds.length || updateActiveInvestigation.isPending} />
              <FlowStep number={8} title="Summarize investigation with AI" text="Summarize saved evidence, TTPs, IOCs, actor leads, and caveats." actionLabel={isSummaryGenerating ? 'Summarizing...' : 'Summarize'} onAction={() => void summarizeInvestigation()} disabled={!canManageIntel || !activeInvestigation || !investigationIds.length || isSummaryGenerating} />
              <FlowStep number={9} title="Create investigation report" text="Generate a local or AI-assisted report, then export PDF / Markdown / TXT." />
            </div>
            {(workflowMessage || updateActiveInvestigation.error) && (
              <div className="border-t border-gray-800 px-4 py-3 text-xs">
                {workflowMessage && <p className="text-green-300">{workflowMessage}</p>}
                {updateActiveInvestigation.error && (
                  <p className="text-red-300">{updateActiveInvestigation.error instanceof Error ? updateActiveInvestigation.error.message : String(updateActiveInvestigation.error)}</p>
                )}
              </div>
            )}
          </Panel>

          <Panel title="Investigation workspace">
            <div className="space-y-4 p-3">
              {!canManageIntel && (
                <PermissionNotice permission="manage_intel" action="create investigations or save comparison, summary, and report results" compact />
              )}
              <div className="grid gap-3 xl:grid-cols-[minmax(260px,1fr)_minmax(320px,1.4fr)]">
                <div className="grid gap-2 sm:grid-cols-[minmax(220px,1fr)_auto]">
                  <input
                    value={newInvestigationName}
                    onChange={event => setNewInvestigationName(event.target.value)}
                    placeholder="New investigation name"
                    className="field"
                  />
                  <button
                    type="button"
                    onClick={() => createInvestigation.mutate()}
                    disabled={!canManageIntel || createInvestigation.isPending}
                    className="primary-action disabled:opacity-50"
                  >
                    Open the new investigation
                  </button>
                </div>
                <select
                  value={activeInvestigation?.id ?? ''}
                  onChange={event => setActiveInvestigationId(event.target.value)}
                  className="field w-full"
                >
                  {investigations.length ? investigations.map(item => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  )) : <option value="">No investigation yet</option>}
                </select>
              </div>
              {createInvestigation.error && (
                <p className="rounded border border-red-500/50 bg-red-950/30 p-2 text-xs text-red-200">
                  {createInvestigation.error instanceof Error ? createInvestigation.error.message : String(createInvestigation.error)}
                </p>
              )}
              <InvestigationStructure
                investigation={activeInvestigation}
                rows={rows}
                selectedTechniqueCount={ids.length}
                onOpenTtp={id => {
                  replaceTechniques([id]);
                  navigate('/navigator');
                }}
                onOpenAllTtps={openLayerOnMatrix}
                onInvestigateIoc={value => navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`)}
                onSearchIoc={value => navigate(`/ioc-library?search=${encodeURIComponent(value)}`)}
                onOpenSummary={summary => setSummaryViewer(summary)}
              />
            </div>
          </Panel>

          <section className="grid gap-5 xl:grid-cols-[420px_minmax(0,1fr)]">
            <div className="space-y-5">
              <Panel title="Report builder">
                <div className="space-y-4 p-3">
                  <label className="block">
                    <span className="mb-1 block text-xs font-semibold uppercase text-gray-500">Report title</span>
                    <input value={reportTitle} onChange={event => setReportTitle(event.target.value)} className="field w-full" />
                  </label>

                  <div>
                    <div className="mb-2 text-xs font-semibold uppercase text-gray-500">Include platform actions</div>
                    <div className="space-y-2">
                      <CheckRow
                        checked={sections.navigator}
                        title="Navigator"
                        text="Current matrix context, selected TTP count, covered TTPs, and coverage gaps."
                        onChange={() => toggleSection('navigator')}
                      />
                      <CheckRow
                        checked={sections.ttps}
                        title="TTPs"
                        text="Selected ATT&CK techniques, analyst evidence, mapping confidence, and maturity."
                        onChange={() => toggleSection('ttps')}
                      />
                      <CheckRow
                        checked={sections.actors}
                        title="Comparison with threat actors"
                        text="Behavior-overlap hypotheses from selected TTPs against actor profiles."
                        onChange={() => toggleSection('actors')}
                      />
                      <CheckRow
                        checked={sections.iocs}
                        title="Relevant IOC enrichment"
                        text="Recent actor-linked IOCs, malware family context, source, confidence, and mapped TTPs."
                        onChange={() => toggleSection('iocs')}
                      />
                    </div>
                  </div>

                  <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
                    <div className="mb-2 text-xs font-semibold uppercase text-gray-500">Generation mode</div>
                    <div className="mb-2 grid grid-cols-3 gap-2">
                      <button
                        type="button"
                        onClick={openLayerOnMatrix}
                        disabled={!investigationIds.length}
                        className="secondary-action disabled:opacity-40"
                      >
                        Put TTPs on matrix
                      </button>
                      <button
                        type="button"
                        onClick={() => void compareAndSave()}
                        disabled={!canManageIntel || !activeInvestigation || !investigationIds.length || updateActiveInvestigation.isPending}
                        className="secondary-action disabled:opacity-40"
                      >
                        Compare + save result
                      </button>
                      <button
                        type="button"
                        onClick={() => void summarizeInvestigation()}
                        disabled={!canManageIntel || !activeInvestigation || !investigationIds.length || isSummaryGenerating}
                        className="primary-action disabled:opacity-40"
                      >
                        {isSummaryGenerating ? 'Summarizing...' : 'Complete AI analysis'}
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={() => void generateLocal()}
                      disabled={!investigationIds.length || !selectedSectionCount}
                      className="secondary-action mb-2 w-full disabled:opacity-40"
                    >
                      Generate locally from selected sections
                    </button>
                    <div className="grid grid-cols-[1fr_auto] gap-2">
                      <select value={provider} onChange={event => setProvider(event.target.value as Provider)} className="field">
                        {providerOptions.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
                      </select>
                      <button
                        type="button"
                        onClick={generateWithAi}
                        disabled={!canRunAnalysis || !investigationIds.length || !selectedSectionCount || isAiGenerating}
                        className="primary-action disabled:opacity-40"
                      >
                        {isAiGenerating ? 'Generating...' : 'AI assistant'}
                      </button>
                    </div>
                    <p className="mt-2 text-[10px] leading-4 text-gray-500">
                      AI mode sends the selected Navigator/TTP/actor/IOC parameters to the configured LLM and writes a client-ready report.
                    </p>
                    {aiError && <p className="mt-2 rounded border border-red-500/50 bg-red-950/30 p-2 text-xs text-red-200">{aiError}</p>}
                  </div>
                </div>
              </Panel>

              <Panel title="Saved reports">
                <div className="space-y-3 p-3">
                  {savedReports.length ? (
                    <>
                      <select
                        value={selectedSavedReportId}
                        onChange={event => setSelectedSavedReportId(event.target.value)}
                        className="field w-full"
                      >
                        <option value="">Current generated / live preview</option>
                        {savedReports.map(report => (
                          <option key={report.id} value={report.id}>
                            {report.label} · {formatReportDate(report.created_at)} · {report.provider || 'saved'}
                          </option>
                        ))}
                      </select>
                      <div className="max-h-64 divide-y divide-gray-800 overflow-auto rounded border border-gray-800 bg-gray-950/40">
                        {savedReports.map(report => (
                          <button
                            key={report.id}
                            type="button"
                            onClick={() => setSelectedSavedReportId(report.id)}
                            className={`block w-full p-3 text-left hover:bg-gray-900 ${selectedSavedReportId === report.id ? 'bg-mitre-accent/10' : ''}`}
                          >
                            <div className="flex items-start justify-between gap-3">
                              <b className="text-xs text-gray-100">{report.label}</b>
                              <span className="shrink-0 rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-gray-300">
                                {report.provider || 'saved'}
                              </span>
                            </div>
                            <p className="mt-1 text-[10px] text-gray-500">
                              {formatReportDate(report.created_at)} · {report.content?.length.toLocaleString() ?? 0} chars
                            </p>
                            {report.summary && <p className="mt-2 line-clamp-2 text-[10px] leading-4 text-gray-400">{report.summary}</p>}
                          </button>
                        ))}
                      </div>
                    </>
                  ) : (
                    <p className="text-xs leading-5 text-gray-500">
                      No saved reports yet. Generate locally or with AI to save the report into the active investigation.
                    </p>
                  )}
                </div>
              </Panel>

              <Panel title="Download">
                <div className="space-y-3 p-3">
                  {!canExportData && (
                    <PermissionNotice permission="export_data" action="download investigation reports" compact />
                  )}
                  <p className="text-[10px] leading-4 text-gray-500">
                    Downloading: <span className="text-gray-300">{selectedSavedReport?.label ?? 'Current generated / live preview'}</span>
                  </p>
                  <div className="grid grid-cols-3 gap-2">
                    <button type="button" onClick={() => download('pdf')} disabled={!canExportData || !activeReport.trim()} className="secondary-action disabled:opacity-40">PDF</button>
                    <button type="button" onClick={() => download('md')} disabled={!canExportData || !activeReport.trim()} className="secondary-action disabled:opacity-40">MD</button>
                    <button type="button" onClick={() => download('txt')} disabled={!canExportData || !activeReport.trim()} className="secondary-action disabled:opacity-40">TXT</button>
                  </div>
                </div>
              </Panel>

              <Panel title="Report inputs">
                <div className="grid grid-cols-2 gap-2 p-3">
                  <Metric label="Selected TTPs" value={rows.length} />
                  <Metric label="Covered TTPs" value={rows.filter(row => row.covered).length} />
                  <Metric label="Actor matches" value={matches.length} />
                  <Metric label="Relevant IOCs" value={relevantIocs.length} />
                </div>
                {matchesLoading && <p className="px-3 pb-3 text-xs text-gray-500">Loading actor comparison...</p>}
                {!investigationIds.length && <p className="px-3 pb-3 text-xs text-amber-300">Select TTPs or add analytic results to an investigation before generating a report.</p>}
              </Panel>

              {aiSummary && (
                <Panel title="AI investigation summary">
                  <div className="p-3">
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-xs text-gray-500">Full AI summary is available in a readable investigation view.</p>
                      <button
                        type="button"
                        onClick={() => setSummaryViewer({ title: 'AI investigation summary', text: aiSummary, source: provider })}
                        className="secondary-action"
                      >
                        Open summary
                      </button>
                    </div>
                    <p className="mt-3 line-clamp-5 whitespace-pre-wrap text-xs leading-5 text-gray-300">{aiSummary}</p>
                  </div>
                </Panel>
              )}
            </div>

            <Panel title={selectedSavedReport ? `Report preview: ${selectedSavedReport.label}` : 'Report preview'}>
              <div className="max-h-[calc(100vh-220px)] overflow-auto p-6">
                {activeReport.trim() ? <ReadableMarkdown text={activeReport} /> : <p className="text-sm text-gray-500">No report content yet.</p>}
              </div>
            </Panel>
          </section>

          {rows.length > 0 && (
            <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_420px]">
              <Panel title="Selected TTP evidence">
                <div className="divide-y divide-gray-800">
                  {rows.map(row => (
                    <div key={row.id} className="p-3">
                      <div className="flex items-start justify-between gap-3">
                        <b className="text-sm text-gray-200"><span className="mr-2 font-mono text-mitre-accent">{row.id}</span>{row.name}</b>
                        <span className={`text-[10px] ${row.covered ? 'text-green-400' : 'text-amber-500'}`}>{row.covered ? 'covered' : 'gap'}</span>
                      </div>
                      <p className="mt-1 text-[10px] text-gray-500">
                        {row.assessment.mapping ?? 'weak'} mapping · {row.assessment.confidence ?? 'low'} confidence · {row.assessment.maturity ?? 'none'} maturity
                      </p>
                      {row.assessment.evidence && <p className="mt-1 text-xs text-gray-400">{row.assessment.evidence}</p>}
                    </div>
                  ))}
                </div>
              </Panel>
              <Panel title="Threat actor comparison">
                <div className="divide-y divide-gray-800">
                  {matches.map((item, index) => (
                    <div key={item.group_attack_id} className="p-3">
                      <b className="text-xs text-gray-300">{index + 1}. {item.group_name}</b>
                      <p className="mt-1 text-[10px] text-gray-500">
                        {item.group_attack_id} · {Math.round(item.similarity * 100)}% Jaccard · {item.shared_count} shared
                      </p>
                    </div>
                  ))}
                  {!matches.length && <p className="p-3 text-xs text-gray-500">No actor comparison yet.</p>}
                </div>
              </Panel>
            </section>
          )}
        </div>
      </div>
      {summaryViewer && (
        <SummaryViewer
          title={summaryViewer.title}
          text={summaryViewer.text}
          source={summaryViewer.source}
          onClose={() => setSummaryViewer(null)}
        />
      )}
    </div>
  );
}

function buildLocalReport({
  title,
  domain,
  rows,
  matches,
  relevantIocs,
  sections,
  investigation,
  evidenceIndex,
}: {
  title: string;
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
  investigation: Investigation | null;
  evidenceIndex: EvidenceIndex;
}) {
  const covered = rows.filter(row => row.covered).length;
  const lines: string[] = [
    `# ${title || 'AdversaryGraph Investigation Report'}`,
    '',
    `Generated: ${new Date().toISOString()}`,
    `Domain: ${domain}`,
    `Selected techniques: ${rows.length}`,
    `Covered techniques: ${covered}`,
    `Coverage gaps: ${Math.max(0, rows.length - covered)}`,
    '',
    '## Executive Summary',
    '',
    rows.length
      ? `This report summarizes ${rows.length} selected ATT&CK techniques, ${matches.length} behavior-overlap actor hypotheses, and ${relevantIocs.length} relevant IOC enrichment records available in AdversaryGraph.`
      : 'No selected techniques were available. Select TTPs or load a workspace before generating the report.',
    '',
  ];
  if (sections.navigator) {
    lines.push('## Navigator', '', `- Current domain: ${domain}`, `- Selected TTPs: ${rows.length}`, `- Covered TTPs: ${covered}`, `- Coverage gaps: ${Math.max(0, rows.length - covered)}`, '');
  }
  if (sections.ttps) {
    lines.push('## ATT&CK TTP Evidence', '');
    rows.forEach(row => {
      const sourceEvidence = evidenceIndex.ttps.get(row.id) ?? [];
      const evidence = cleanReportValue(row.assessment.evidence) || sourceEvidence[0]?.evidence || '';
      const source = cleanReportValue(row.assessment.source) || formatSourceReferences(sourceEvidence) || 'manual / navigator selection';
      const sourceTag = sourceEvidence[0]?.sourceTag || (row.assessment.source ? sourceTagFromValue(row.assessment.source) : 'manual');
      const notes = cleanReportValue(row.assessment.notes);
      const confidence = row.assessment.confidence ?? (evidence ? 'medium' : 'low');
      lines.push(
        `### ${row.id} - ${row.name}`,
        '',
        `**Source tag:** ${sourceTag}`,
        '',
        `**Why it is relevant:** ${ttpRelevance(row, evidence)}`,
        '',
        `**Evidence:** ${evidence || 'No direct source-backed evidence is attached to this technique in the current workspace. Treat it as a planning or coverage item until validated against logs, reports, or enrichment sources.'}`,
        '',
        `**Reference:** ${source || 'AdversaryGraph investigation layer / Navigator selection.'}`,
        '',
        `**Confidence:** ${confidence}. ${confidence === 'low' && !evidence ? 'Low confidence because no direct evidence text is attached.' : 'Confidence is based on the available analyst evidence and mapping context.'}`,
        notes ? `\n**Analyst notes:** ${notes}` : '',
        '',
      );
    });
  }
  if (investigation) {
    const logNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('log'));
    const reportNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('report') || String(item.type ?? '').includes('analysis'));
    const iocNodes = investigation.evidence_nodes.filter(item => String(item.type ?? '').includes('ioc') || String(item.type ?? '').includes('indicator'));
    lines.push('## Investigation Workspace', '', `Investigation: ${investigation.name}`, `Status: ${investigation.status}`, '');
    lines.push('### Logs - Result Analysis', '');
    if (logNodes.length) logNodes.slice(0, 20).forEach(node => lines.push(`- ${String(node.label ?? node.value ?? node.id ?? 'Log analysis')} - ${String(node.summary ?? node.description ?? '')}`));
    else lines.push('- No log analysis evidence has been added yet.');
    lines.push('', '### Report Analysis', '');
    if (reportNodes.length) reportNodes.slice(0, 20).forEach(node => lines.push(`- ${String(node.label ?? node.value ?? node.id ?? 'Report analysis')} - ${String(node.summary ?? node.description ?? '')}`));
    else lines.push('- No report analysis evidence has been added yet.');
    lines.push('', '### IOC List', '');
    if (iocNodes.length) iocNodes.slice(0, 60).forEach(node => lines.push(`- ${String(node.value ?? node.label ?? node.id)} (${String(node.ioc_type ?? node.type ?? 'ioc')})`));
    else lines.push('- No IOC evidence nodes have been added yet.');
    lines.push('', '### Timeline', '');
    if (investigation.timeline.length) investigation.timeline.slice(-20).forEach(item => lines.push(`- ${String(item.at ?? '')}: ${String(item.event ?? item.source ?? 'Investigation event')}`));
    else lines.push('- No timeline events yet.');
    lines.push('');
  }
  if (sections.actors) {
    lines.push('## Comparison With Threat Actors', '');
    if (matches.length) {
      matches.forEach((item, index) => {
        lines.push(
          `${index + 1}. ${item.group_name} (${item.group_attack_id})`,
          `   - Similarity: ${Math.round(item.similarity * 100)}% Jaccard overlap`,
          `   - Shared TTPs: ${item.shared_count}`,
          `   - Shared technique IDs: ${item.shared_techniques.join(', ') || 'None'}`,
        );
      });
    } else {
      lines.push('No behavior-overlap actor hypotheses were available.');
    }
    lines.push('');
  }
  if (sections.iocs) {
    lines.push('## Relevant IOC Enrichment', '');
    const reportIocs = buildReportIocItems(relevantIocs, evidenceIndex);
    if (reportIocs.length) {
      reportIocs.slice(0, 80).forEach(item => {
        lines.push(
          `### ${item.value}`,
          '',
          `**Indicator type:** ${item.type}`,
          '',
          `**Source tag:** ${item.sourceTag}`,
          '',
          `**Why it is relevant:** ${iocRelevance(item)}`,
          '',
          `**Evidence:** ${iocEvidence(item)}`,
          '',
          `**Reference:** ${item.reference}`,
          '',
          `**Recommended handling:** ${iocHandling(item)}`,
          '',
        );
      });
    } else {
      lines.push('No actor-linked IOC enrichment records were available for the current comparison set.');
    }
    lines.push('');
  }
  lines.push(
    '## Analytic Caveats',
    '',
    '- TTP overlap supports prioritization and hypothesis generation. It is not definitive attribution evidence.',
    '- IOC enrichment should be validated against source reports, timestamps, and local telemetry before operational use.',
    '- AI-generated report text must be analyst-reviewed before customer delivery.',
  );
  return lines.join('\n');
}

function cleanReportValue(value?: string) {
  const cleaned = String(value ?? '').trim();
  if (!cleaned || /^not recorded$/i.test(cleaned) || /^none$/i.test(cleaned)) return '';
  return cleaned;
}

function ttpRelevance(row: ReportRow, evidence: string) {
  if (evidence) {
    return `${row.id} is included because the workspace contains analyst evidence for ${row.name}.`;
  }
  if (row.covered) {
    return `${row.id} is included because it is part of the current covered Navigator layer for ${row.name}. It should be reviewed as coverage context, not as directly observed behavior.`;
  }
  return `${row.id} is included because it is present in the current investigation TTP layer for ${row.name}. It is currently a coverage gap or hypothesis item requiring validation.`;
}

function iocRelevance(item: ReportIocItem) {
  const links = [
    item.malware_family ? `malware family ${item.malware_family}` : '',
    item.campaign ? `campaign ${item.campaign}` : '',
    item.technique_ids?.length ? `mapped TTPs ${item.technique_ids.slice(0, 6).join(', ')}` : '',
  ].filter(Boolean);
  if (links.length) return `The indicator is relevant because enrichment links it to ${links.join(', ')}.`;
  return 'The indicator is relevant because it appears in the selected actor or investigation enrichment context and should be validated before operational action.';
}

function iocEvidence(item: ReportIocItem) {
  if (item.evidence) return item.evidence;
  const evidence = [
    `Source: ${item.source || 'unknown'}`,
    item.first_seen ? `first seen ${item.first_seen}` : '',
    item.last_seen ? `last seen ${item.last_seen}` : '',
    `confidence ${item.confidence ?? 0}`,
    item.tlp ? `TLP ${item.tlp}` : '',
  ].filter(Boolean);
  return evidence.join('; ') || 'No detailed enrichment evidence was returned for this indicator.';
}

function iocHandling(item: ReportIocItem) {
  const confidence = item.confidence ?? 0;
  if (confidence >= 80) return 'Prioritize for hunting or preventive control review, then validate against local telemetry before blocking.';
  if (confidence >= 50) return 'Use for threat hunting and correlation. Validate source freshness and local sightings before enforcement.';
  return 'Enrich further and validate source context before alerting or blocking.';
}

function buildReportIocItems(relevantIocs: IOCItem[], evidenceIndex: EvidenceIndex): ReportIocItem[] {
  const merged = new Map<string, ReportIocItem>();
  relevantIocs.forEach(item => {
    const sourceEvidence = evidenceIndex.iocs.get(item.value) ?? [];
    merged.set(item.value.toLowerCase(), {
      ...item,
      sourceTag: sourceEvidence[0]?.sourceTag || sourceTagFromValue(item.source || 'feed'),
      reference: formatSourceReferences(sourceEvidence) || item.source_url || item.source || 'ioc-feed',
      evidence: sourceEvidence[0]?.evidence,
    });
  });
  evidenceIndex.iocs.forEach((items, value) => {
    if (merged.has(value.toLowerCase())) return;
    const first = items[0];
    merged.set(value.toLowerCase(), {
      value,
      type: inferIocType(value),
      sourceTag: first?.sourceTag || 'manual',
      reference: formatSourceReferences(items) || first?.reference || 'investigation evidence',
      source: first?.sourceTag,
      confidence: typeof first?.confidence === 'number' ? first.confidence : undefined,
      evidence: first?.evidence,
    });
  });
  return Array.from(merged.values());
}

function InvestigationStructure({
  investigation,
  rows,
  selectedTechniqueCount,
  onOpenTtp,
  onOpenAllTtps,
  onInvestigateIoc,
  onSearchIoc,
  onOpenSummary,
}: {
  investigation: Investigation | null;
  rows: ReportRow[];
  selectedTechniqueCount: number;
  onOpenTtp: (id: string) => void;
  onOpenAllTtps: () => void;
  onInvestigateIoc: (value: string) => void;
  onSearchIoc: (value: string) => void;
  onOpenSummary: (summary: { title: string; text: string; source?: string }) => void;
}) {
  const nodes = investigation?.evidence_nodes ?? [];
  const logNodes = nodes.filter(item => String(item.type ?? '').includes('log'));
  const reportNodes = nodes.filter(item => String(item.type ?? '').includes('report') || String(item.type ?? '').includes('analysis'));
  const summaryNodes = nodes.filter(item => String(item.type ?? '') === 'ai-summary');
  const iocNodes = uniqueIocNodes(nodes);
  const behaviorNodes = uniqueSuspiciousBehaviorNodes(nodes);
  const ttpEvidenceNodes = uniqueTtpEvidenceNodes(nodes);
  const ttpRefsById = ttpEvidenceNodes.reduce((acc, item) => {
    acc.set(item.attackId, mergeArrays(acc.get(item.attackId) ?? [], [item.sourceRef]));
    return acc;
  }, new Map<string, string[]>());
  const ttpRows = rows.length
    ? rows
    : (investigation?.technique_ids ?? []).map(id => ({ id, name: id, covered: false, assessment: {} }));
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5">
        <InvestigationBucket title="Logs - result analysis" count={logNodes.length} text="Log / PCAP findings, suspicious commands, observables, and mapped behavior." />
        <InvestigationBucket title="Report analysis" count={reportNodes.length} text="CTI reports, uploaded analysis sessions, summaries, and source-backed TTPs." />
        <InvestigationBucket title="Suspicious behaviors" count={behaviorNodes.length} text="Expected behavior patterns found in logs, mapped to TTP and IOC leads." />
        <InvestigationBucket title="Founded TTP layer" count={investigation?.technique_ids.length ?? selectedTechniqueCount} text="Merged ATT&CK layer from Navigator, AI analysis, IOC investigation, and reports." />
        <InvestigationBucket title="IOC list" count={iocNodes.length} text="Extracted indicators, enrichment nodes, source records, and graph pivots." />
      </div>

      {summaryNodes.length > 0 && (
        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-3">
            <b className="text-xs text-gray-200">AI summaries</b>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{summaryNodes.length}</span>
          </div>
          <div className="grid gap-2 lg:grid-cols-2">
            {summaryNodes.slice(-4).map(node => {
              const text = String(node.summary ?? node.description ?? '');
              const title = String(node.label ?? 'AI investigation summary');
              return (
                <div key={String(node.id ?? title)} className="rounded border border-gray-800 bg-gray-950 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <b className="text-sm text-gray-100">{title}</b>
                    <span className="rounded bg-cyan-950 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">{String(node.provider ?? node.source ?? 'ai')}</span>
                  </div>
                  <p className="mt-2 line-clamp-3 text-xs leading-5 text-gray-400">{text}</p>
                  <button
                    type="button"
                    onClick={() => onOpenSummary({ title, text, source: String(node.provider ?? node.source ?? 'ai') })}
                    className="secondary-action mt-3"
                  >
                    Open summary
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid gap-3 2xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.35fr)]">
        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">Log analysis results</b>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{logNodes.length}</span>
          </div>
          {logNodes.length ? (
            <div className="grid gap-2 lg:grid-cols-2 2xl:grid-cols-1">
              {logNodes.slice(-20).map(node => (
                <div key={String(node.id ?? node.label)} className="rounded border border-gray-800 bg-gray-950 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <b className="text-sm text-gray-100">{String(node.label ?? 'Log / PCAP analysis')}</b>
                    <span className="rounded bg-cyan-950 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">
                      {String(node.source_ref ?? node.analysis_id ?? 'log-source')}
                    </span>
                  </div>
                  <p className="mt-2 line-clamp-4 text-xs leading-5 text-gray-400">{String(node.summary ?? '')}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {Array.isArray(node.observables) && node.observables.slice(0, 10).map((observable, index) => {
                      const value = String((observable as Record<string, unknown>).value ?? '');
                      if (!value) return null;
                      return (
                        <button key={`${value}-${index}`} type="button" onClick={() => onInvestigateIoc(value)} className="max-w-[180px] truncate rounded border border-cyan-900 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200 hover:border-cyan-400" title={value}>
                          {value}
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500">No Log / PCAP analysis results have been added to this investigation yet.</p>
          )}
        </div>

        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">Expected suspicious behaviors</b>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{behaviorNodes.length}</span>
          </div>
          {behaviorNodes.length ? (
            <div className="max-h-[360px] overflow-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead className="sticky top-0 z-10 bg-gray-950 text-[10px] uppercase tracking-wide text-gray-500">
                  <tr>
                    <th className="border-b border-gray-800 px-3 py-2">Evidence</th>
                    <th className="border-b border-gray-800 px-3 py-2">Why it matters</th>
                    <th className="border-b border-gray-800 px-3 py-2">TTP / IOC tags</th>
                  </tr>
                </thead>
                <tbody>
                  {behaviorNodes.map(node => (
                    <tr key={node.key} className="bg-red-950/10">
                      <td className="border-b border-gray-800 px-3 py-2 align-top">
                        <p className="font-medium text-gray-100">{node.evidence}</p>
                        {node.sourceRefs.length > 0 && (
                          <div className="mt-1 flex flex-wrap gap-1">
                            {node.sourceRefs.map(ref => (
                              <span key={ref} className="rounded bg-cyan-950 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">{ref}</span>
                            ))}
                          </div>
                        )}
                        {node.refs.length > 0 && <p className="mt-1 line-clamp-2 font-mono text-[10px] text-gray-500">{node.refs[0]}</p>}
                      </td>
                      <td className="border-b border-gray-800 px-3 py-2 align-top text-gray-300">{node.why}</td>
                      <td className="border-b border-gray-800 px-3 py-2 align-top">
                        <div className="flex max-w-lg flex-wrap gap-1.5">
                          {node.ttps.map(id => (
                            <button
                              key={id}
                              type="button"
                              onClick={() => onOpenTtp(id)}
                              className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent hover:text-white"
                            >
                              {id}
                            </button>
                          ))}
                          {node.iocs.map(value => (
                            <button
                              key={value}
                              type="button"
                              onClick={() => onInvestigateIoc(value)}
                              className="max-w-[220px] truncate rounded border border-cyan-700/60 bg-cyan-950/20 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200 hover:border-cyan-400"
                              title={value}
                            >
                              {value}
                            </button>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-xs text-gray-500">No expected suspicious behavior rows have been added to this investigation yet.</p>
          )}
        </div>
      </div>

      <div className="grid gap-3 xl:grid-cols-[minmax(0,1.1fr)_minmax(340px,0.9fr)]">
        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">TTPs</b>
            <button
              type="button"
              onClick={onOpenAllTtps}
              disabled={!ttpRows.length}
              className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent disabled:opacity-40"
            >
              Open all on matrix
            </button>
          </div>
          <div className="max-h-52 overflow-auto">
            {ttpRows.length ? (
              <div className="flex flex-wrap gap-2">
                {ttpRows.map(row => (
                  <button
                    key={row.id}
                    type="button"
                    onClick={() => onOpenTtp(row.id)}
                    title={`Open ${row.id} on matrix`}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-left text-[11px] text-gray-200 hover:border-mitre-accent hover:text-white"
                  >
                    <span className="font-mono text-mitre-accent">{row.id}</span>
                    <span className="ml-1 text-gray-400">{row.name}</span>
                    {(ttpRefsById.get(row.id) ?? []).slice(0, 3).map(ref => (
                      <span key={`${row.id}-${ref}`} className="ml-1 rounded bg-cyan-950 px-1 py-0.5 font-mono text-[9px] text-cyan-200">{ref}</span>
                    ))}
                  </button>
                ))}
                {ttpEvidenceNodes.filter(item => !ttpRows.some(row => row.id === item.attackId)).map(item => (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => onOpenTtp(item.attackId)}
                    title={`Open ${item.attackId} on matrix`}
                    className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-left text-[11px] text-gray-200 hover:border-mitre-accent hover:text-white"
                  >
                    <span className="font-mono text-mitre-accent">{item.attackId}</span>
                    <span className="ml-1 text-gray-400">{item.label.replace(item.attackId, '').trim()}</span>
                    <span className="ml-1 rounded bg-cyan-950 px-1 py-0.5 font-mono text-[9px] text-cyan-200">{item.sourceRef}</span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No TTPs have been added to this investigation yet.</p>
            )}
          </div>
        </div>

        <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="mb-2 flex items-center justify-between gap-2">
            <b className="text-xs text-gray-200">IOCs</b>
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{iocNodes.length}</span>
          </div>
          <div className="max-h-52 divide-y divide-gray-800 overflow-auto">
            {iocNodes.length ? iocNodes.map(node => (
              <div key={node.key} className="py-2">
                <IocLink
                  value={node.value}
                  type={node.type}
                  source={node.source || 'Investigation'}
                  className="block w-full truncate text-left font-mono text-xs text-gray-100 hover:text-mitre-accent"
                />
                <p className="mt-1 line-clamp-2 text-[10px] leading-4 text-gray-500">
                  {node.type} · {node.source || 'investigation evidence'}{node.description ? ` · ${node.description}` : ''}
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <button type="button" onClick={() => onInvestigateIoc(node.value)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Investigate IOC</button>
                  <button type="button" onClick={() => onSearchIoc(node.value)} className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-300 hover:border-mitre-accent">Search IOC Library</button>
                </div>
              </div>
            )) : (
              <p className="py-2 text-xs text-gray-500">No IOCs have been added to this investigation yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function InvestigationBucket({ title, count, text }: { title: string; count: number; text: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <div className="flex items-start justify-between gap-2">
        <b className="text-xs text-gray-200">{title}</b>
        <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{count}</span>
      </div>
      <p className="mt-2 text-[10px] leading-4 text-gray-500">{text}</p>
    </div>
  );
}

function ReadableMarkdown({ text }: { text: string }) {
  const blocks = markdownBlocks(text);
  if (!blocks.length) return <p className="text-sm text-gray-500">No report content yet.</p>;
  return (
    <article className="space-y-5 text-sm leading-7 text-gray-300">
      {blocks.map((block, index) => {
        if (block.kind === 'heading') {
          const headingClass = block.level <= 1
            ? 'text-2xl font-semibold text-white'
            : block.level === 2
              ? 'mt-8 border-b border-gray-800 pb-2 text-lg font-semibold text-white'
              : 'mt-5 text-base font-semibold text-gray-100';
          const Tag = (`h${Math.min(block.level, 3)}` as 'h1' | 'h2' | 'h3');
          return <Tag key={index} className={headingClass}>{renderInlineMarkdown(block.text)}</Tag>;
        }
        if (block.kind === 'paragraph') {
          return <p key={index} className="max-w-none text-gray-300">{renderInlineMarkdown(block.text)}</p>;
        }
        if (block.kind === 'bullet') {
          return (
            <ul key={index} className="space-y-2 rounded border border-gray-800 bg-gray-950/35 p-4 pl-7 text-gray-300">
              {block.items.map((item, itemIndex) => <li key={itemIndex} className="list-disc">{renderInlineMarkdown(item)}</li>)}
            </ul>
          );
        }
        if (block.kind === 'numbered') {
          return (
            <ol key={index} className="space-y-2 rounded border border-gray-800 bg-gray-950/35 p-4 pl-7 text-gray-300">
              {block.items.map((item, itemIndex) => <li key={itemIndex} className="list-decimal">{renderInlineMarkdown(item)}</li>)}
            </ol>
          );
        }
        if (block.kind === 'code') {
          return (
            <pre key={index} className="overflow-auto rounded border border-gray-800 bg-gray-950 p-4 font-mono text-xs leading-6 text-cyan-100">
              <code>{block.text}</code>
            </pre>
          );
        }
        return null;
      })}
    </article>
  );
}

function markdownBlocks(text: string) {
  const normalized = normalizeMarkdownPreview(text);
  const lines = normalized.split('\n');
  const blocks: Array<
    | { kind: 'heading'; level: number; text: string }
    | { kind: 'paragraph'; text: string }
    | { kind: 'bullet'; items: string[] }
    | { kind: 'numbered'; items: string[] }
    | { kind: 'code'; text: string }
  > = [];
  let paragraph: string[] = [];
  let bullets: string[] = [];
  let numbered: string[] = [];
  let code: string[] = [];
  let inCode = false;

  const flushParagraph = () => {
    const textValue = paragraph.join(' ').replace(/\s+/g, ' ').trim();
    if (textValue) blocks.push({ kind: 'paragraph', text: textValue });
    paragraph = [];
  };
  const flushBullets = () => {
    if (bullets.length) blocks.push({ kind: 'bullet', items: bullets });
    bullets = [];
  };
  const flushNumbered = () => {
    if (numbered.length) blocks.push({ kind: 'numbered', items: numbered });
    numbered = [];
  };
  const flushListsAndParagraph = () => {
    flushParagraph();
    flushBullets();
    flushNumbered();
  };

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (line.trim().startsWith('```')) {
      if (inCode) {
        blocks.push({ kind: 'code', text: code.join('\n') });
        code = [];
        inCode = false;
      } else {
        flushListsAndParagraph();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      code.push(line);
      continue;
    }
    if (!line.trim()) {
      flushListsAndParagraph();
      continue;
    }
    const heading = line.match(/^(#{1,6})\s+(.+)$/);
    const bullet = line.match(/^[-*]\s+(.+)$/);
    const numberedItem = line.match(/^\d+[.)]\s+(.+)$/);
    if (heading) {
      flushListsAndParagraph();
      blocks.push({ kind: 'heading', level: heading[1].length, text: cleanInline(heading[2]) });
    } else if (bullet) {
      flushParagraph();
      flushNumbered();
      bullets.push(cleanInline(bullet[1]));
    } else if (numberedItem) {
      flushParagraph();
      flushBullets();
      numbered.push(cleanInline(numberedItem[1]));
    } else {
      flushBullets();
      flushNumbered();
      paragraph.push(line.trim());
    }
  }
  if (inCode && code.length) blocks.push({ kind: 'code', text: code.join('\n') });
  flushListsAndParagraph();
  return blocks;
}

function normalizeMarkdownPreview(text: string) {
  return text
    .replace(/\r/g, '')
    .replace(/([^\n])(\s+#{1,6}\s+)/g, (_match, before: string, heading: string) => `${before}\n\n${heading.trimStart()}`)
    .replace(/([^\n])(\s+-\s+)/g, (_match, before: string, bullet: string) => `${before}\n${bullet.trimStart()}`)
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function renderInlineMarkdown(text: string) {
  const parts = cleanInline(text).split(/(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\]\([^)]+\))/g);
  return parts.filter(Boolean).map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={index} className="rounded bg-gray-950 px-1.5 py-0.5 font-mono text-xs text-cyan-200">{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index} className="font-semibold text-gray-100">{part.slice(2, -2)}</strong>;
    }
    const link = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (link) {
      const href = safeHref(link[2]);
      return href
        ? <a key={index} href={href} target="_blank" rel="noreferrer" className="text-cyan-300 underline decoration-cyan-900 underline-offset-4 hover:text-cyan-100">{link[1]}</a>
        : <span key={index}>{link[1]}</span>;
    }
    return <span key={index}>{part}</span>;
  });
}

function SummaryViewer({
  title,
  text,
  source,
  onClose,
}: {
  title: string;
  text: string;
  source?: string;
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6">
      <section className="flex max-h-[88vh] w-full max-w-5xl flex-col overflow-hidden rounded-lg border border-gray-700 bg-gray-950 shadow-2xl">
        <header className="flex items-start justify-between gap-4 border-b border-gray-800 bg-gray-900 px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold text-white">{title}</h2>
            {source && <p className="mt-1 text-xs text-gray-500">Source: {source}</p>}
          </div>
          <div className="flex gap-2">
            <button type="button" onClick={() => navigator.clipboard.writeText(text)} className="secondary-action">Copy</button>
            <button type="button" onClick={onClose} className="secondary-action">Close</button>
          </div>
        </header>
        <div className="overflow-auto p-6">
          <ReadableSummary text={text} />
        </div>
      </section>
    </div>
  );
}

function ReadableSummary({ text }: { text: string }) {
  const blocks = summaryBlocks(text);
  if (!blocks.length) return <p className="text-sm text-gray-500">No summary text was saved.</p>;
  return (
    <article className="space-y-4 text-sm leading-7 text-gray-300">
      {blocks.map((block, index) => {
        if (block.kind === 'heading') {
          return <h3 key={index} className="border-b border-gray-800 pb-2 text-base font-semibold text-white">{block.text}</h3>;
        }
        if (block.kind === 'bullet') {
          return (
            <ul key={index} className="list-disc space-y-2 pl-5">
              {block.items.map((item, itemIndex) => <li key={itemIndex}>{inlineSummaryText(item)}</li>)}
            </ul>
          );
        }
        return <p key={index}>{inlineSummaryText(block.text)}</p>;
      })}
    </article>
  );
}

function summaryBlocks(text: string) {
  const lines = text.replace(/\r/g, '').split('\n').map(line => line.trim()).filter(Boolean);
  const blocks: Array<{ kind: 'heading'; text: string } | { kind: 'paragraph'; text: string } | { kind: 'bullet'; items: string[] }> = [];
  let paragraph: string[] = [];
  let bullets: string[] = [];
  const flushParagraph = () => {
    if (paragraph.length) {
      blocks.push({ kind: 'paragraph', text: paragraph.join(' ') });
      paragraph = [];
    }
  };
  const flushBullets = () => {
    if (bullets.length) {
      blocks.push({ kind: 'bullet', items: bullets });
      bullets = [];
    }
  };
  for (const line of lines) {
    const heading = line.match(/^#{1,4}\s+(.+)$/) ?? line.match(/^\*\*(.+?)\*\*:?\s*$/);
    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (heading) {
      flushParagraph();
      flushBullets();
      blocks.push({ kind: 'heading', text: cleanInline(heading[1]) });
    } else if (bullet) {
      flushParagraph();
      bullets.push(cleanInline(bullet[1]));
    } else {
      flushBullets();
      paragraph.push(cleanInline(line));
    }
  }
  flushParagraph();
  flushBullets();
  return blocks;
}

function inlineSummaryText(text: string) {
  const parts = cleanInline(text).split(/(`[^`]+`)/g);
  return parts.map((part, index) => part.startsWith('`') && part.endsWith('`')
    ? <code key={index} className="rounded bg-gray-900 px-1.5 py-0.5 font-mono text-xs text-cyan-200">{part.slice(1, -1)}</code>
    : <span key={index}>{part}</span>);
}

function cleanInline(text: string) {
  return text
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/^#+\s*/, '')
    .trim();
}

function uniqueIocNodes(nodes: Array<Record<string, unknown>>) {
  const merged = new Map<string, { key: string; value: string; type: string; source: string; description: string; sourceRefs: string[] }>();
  nodes
    .filter(node => isIocEvidenceNode(node))
    .map(node => {
      const rawValue = String(node.value ?? node.indicator ?? node.observable ?? node.label ?? '');
      const value = rawValue.trim();
      const type = String(node.ioc_type ?? node.indicator_type ?? node.type ?? 'ioc');
      const source = String(node.source ?? node.provider ?? node.evidence_source ?? '');
      const description = String(node.description ?? node.summary ?? '');
      const sourceRefs = collectNodeSourceRefs(node);
      return { key: `${type}:${value}`, value, type, source, description, sourceRefs };
    })
    .forEach(node => {
      if (!node.value) return false;
      const normalized = node.key.toLowerCase();
      const existing = merged.get(normalized);
      if (!existing) {
        merged.set(normalized, node);
        return true;
      }
      merged.set(normalized, {
        ...existing,
        sourceRefs: mergeArrays(existing.sourceRefs, node.sourceRefs),
        source: existing.source || node.source,
        description: existing.description || node.description,
      });
      return true;
    });
  return Array.from(merged.values()).slice(0, 100);
}

function buildEvidenceIndex(investigation: Investigation | null): EvidenceIndex {
  const ttps = new Map<string, SourceTaggedEvidence[]>();
  const iocs = new Map<string, SourceTaggedEvidence[]>();
  if (!investigation) return { ttps, iocs };
  const nodes = investigation.evidence_nodes ?? [];
  nodes.forEach(node => {
    const record = node as Record<string, unknown>;
    const refs = collectNodeSourceRefs(record);
    const sourceTag = sourceTagFromNode(record);
    const reference = refs.join(', ') || sourceTag;
    const evidence = String(record.evidence ?? record.summary ?? record.description ?? record.label ?? '').trim();
    const confidence = record.confidence as string | number | undefined;

    if (String(record.type ?? '') === 'ttp-evidence') {
      addEvidence(ttps, String(record.attack_id ?? '').toUpperCase(), { sourceTag, reference, evidence, confidence });
    }

    stringArray(record.ttps).forEach(id => {
      addEvidence(ttps, id.toUpperCase(), { sourceTag, reference, evidence, confidence });
    });

    if (Array.isArray(record.techniques)) {
      record.techniques.forEach(item => {
        if (!item || typeof item !== 'object') return;
        const technique = item as Record<string, unknown>;
        const attackId = String(technique.attack_id ?? '').toUpperCase();
        addEvidence(ttps, attackId, {
          sourceTag,
          reference,
          evidence: String(technique.evidence ?? evidence ?? '').trim(),
          confidence: technique.confidence as string | number | undefined,
        });
      });
    }

    const value = String(record.value ?? record.indicator ?? record.observable ?? '').trim();
    if (value && isIocEvidenceNode(record)) {
      addEvidence(iocs, value, { sourceTag, reference, evidence, confidence });
    }

    if (Array.isArray(record.observables)) {
      record.observables.forEach(item => {
        if (!item || typeof item !== 'object') return;
        const observable = item as Record<string, unknown>;
        const observableValue = String(observable.value ?? '').trim();
        addEvidence(iocs, observableValue, {
          sourceTag,
          reference,
          evidence: String(observable.description ?? evidence ?? '').trim(),
          confidence: observable.confidence as string | number | undefined,
        });
      });
    }

    stringArray(record.iocs).forEach(item => {
      addEvidence(iocs, item, { sourceTag, reference, evidence, confidence });
    });
  });
  return { ttps, iocs };
}

function addEvidence(map: Map<string, SourceTaggedEvidence[]>, key: string, evidence: SourceTaggedEvidence) {
  const normalized = key.trim();
  if (!normalized) return;
  const current = map.get(normalized) ?? [];
  const next = [...current, evidence].filter(item => item.reference || item.evidence);
  const seen = new Set<string>();
  map.set(normalized, next.filter(item => {
    const dedupeKey = `${item.sourceTag}:${item.reference}:${item.evidence}`.toLowerCase();
    if (seen.has(dedupeKey)) return false;
    seen.add(dedupeKey);
    return true;
  }).slice(0, 8));
}

function formatSourceReferences(items: SourceTaggedEvidence[]) {
  return items
    .map(item => `${item.sourceTag}: ${item.reference || item.evidence}`)
    .filter(Boolean)
    .slice(0, 5)
    .join('; ');
}

function sourceTagFromNode(node: Record<string, unknown>) {
  const raw = [
    String(node.source ?? ''),
    String(node.source_ref ?? ''),
    String(node.type ?? ''),
    ...stringArray(node.source_refs),
  ].join(' ');
  return sourceTagFromValue(raw);
}

function sourceTagFromValue(value: string) {
  const lowered = value.toLowerCase();
  if (/pcap|pcapng|zeek|suricata/.test(lowered)) return 'pcap';
  if (/log|edr|firewall|dns|proxy|windows event|sysmon/.test(lowered)) return 'log';
  if (/report|cti|article|pdf|docx/.test(lowered)) return 'report';
  if (/ioc-investigation|virustotal|urlscan|otx|threatfox|malwarebazaar|greynoise|shodan|censys|abuseipdb/.test(lowered)) return lowered.includes('ioc-investigation') ? 'ioc-investigation' : 'feed';
  if (/manual|navigator|my ttps|selected/.test(lowered)) return 'manual';
  return value.trim() ? value.trim().slice(0, 32) : 'manual';
}

function inferIocType(value: string) {
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
  return 'domain';
}

function isIocEvidenceNode(node: Record<string, unknown>) {
  const type = String(node.ioc_type ?? node.indicator_type ?? node.type ?? '').toLowerCase();
  if (['ai-summary', 'investigation-report', 'actor-comparison', 'suspicious-behavior'].includes(type)) return false;
  const value = String(node.value ?? node.indicator ?? node.observable ?? '').trim();
  if (!value) return false;
  if (/(^|\b)(ioc|indicator|observable|ip|domain|url|hash|sha1|sha256|md5)(\b|$)/i.test(type)) return true;
  return looksLikeObservable(value);
}

function looksLikeObservable(value: string) {
  if (/^https?:\/\/\S+$/i.test(value)) return true;
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value)) return true;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return true;
  return /^[a-z0-9*_.-]+\.[a-z0-9_.-]+$/i.test(value) && !/\s/.test(value);
}

function uniqueSuspiciousBehaviorNodes(nodes: Array<Record<string, unknown>>) {
  const directNodes = nodes.filter(node => String(node.type ?? '') === 'suspicious-behavior');
  const nestedNodes = nodes.flatMap(node => {
    const nested = node.expected_suspicious_behaviors;
    return Array.isArray(nested) ? nested.filter(item => item && typeof item === 'object') as Array<Record<string, unknown>> : [];
  });
  const seen = new Set<string>();
  return [...directNodes, ...nestedNodes]
    .map(node => {
      const evidence = String(node.evidence ?? node.label ?? '');
      const why = String(node.why ?? node.reason ?? '');
      const refs = stringArray(node.refs);
      const ttps = stringArray(node.ttps);
      const iocs = stringArray(node.iocs);
      const found = node.found !== false;
      const sourceRefs = collectNodeSourceRefs(node);
      return {
        key: `${sourceRefs.join('|')}:${evidence}:${why}`.toLowerCase(),
        evidence,
        why,
        refs,
        ttps,
        iocs,
        found,
        sourceRefs,
      };
    })
    .filter(node => {
      if (!node.found || !node.evidence) return false;
      if (seen.has(node.key)) return false;
      seen.add(node.key);
      return true;
    })
    .slice(0, 60);
}

function uniqueTtpEvidenceNodes(nodes: Array<Record<string, unknown>>) {
  const seen = new Set<string>();
  return nodes
    .filter(node => String(node.type ?? '') === 'ttp-evidence')
    .map(node => {
      const attackId = String(node.attack_id ?? node.id ?? '').toUpperCase();
      const label = String(node.label ?? attackId);
      const sourceRef = collectNodeSourceRefs(node)[0] ?? String(node.source ?? 'analysis');
      return {
        key: `${sourceRef}:${attackId}`,
        attackId,
        label,
        sourceRef,
      };
    })
    .filter(node => {
      if (!node.attackId) return false;
      const key = node.key.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 250);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map(item => String(item)).filter(Boolean);
}

function collectNodeSourceRefs(node: Record<string, unknown>) {
  return mergeArrays([
    ...stringArray(node.source_refs),
    ...stringArray(node.references),
    ...stringArray(node.refs),
    String(node.source_ref ?? '').trim(),
    String(node.analysis_id ?? '').trim(),
    String(node.source ?? '').trim(),
  ].filter(Boolean), []);
}

function mergeArrays(a: string[], b: string[]) {
  return Array.from(new Set([...a, ...b].filter(Boolean)));
}

function buildReportContext({
  domain,
  rows,
  matches,
  relevantIocs,
  sections,
  investigation,
  evidenceIndex,
}: {
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
  investigation: Investigation | null;
  evidenceIndex: EvidenceIndex;
}) {
  const lines = [
    `Domain: ${domain}`,
    `Included sections: ${Object.entries(sections).filter(([, enabled]) => enabled).map(([name]) => name).join(', ')}`,
    `Navigator summary: ${rows.length} selected TTPs, ${rows.filter(row => row.covered).length} covered, ${rows.filter(row => !row.covered).length} coverage gaps.`,
    '',
  ];
  if (sections.ttps) {
    lines.push('TTP evidence:');
    rows.slice(0, 45).forEach(row => {
      const sourceEvidence = evidenceIndex.ttps.get(row.id) ?? [];
      lines.push([
        `${row.id} ${row.name}`,
        `coverage=${row.covered ? 'covered' : 'gap'}`,
        `mapping=${row.assessment.mapping ?? 'weak'}`,
        `confidence=${row.assessment.confidence ?? 'low'}`,
        `maturity=${row.assessment.maturity ?? 'none'}`,
        row.assessment.evidence ? `evidence=${truncate(row.assessment.evidence, 120)}` : '',
        row.assessment.source ? `source=${truncate(row.assessment.source, 80)}` : '',
        sourceEvidence.length ? `source_tags=${sourceEvidence.map(item => item.sourceTag).join(', ')}` : 'source_tags=manual',
        sourceEvidence.length ? `references=${truncate(formatSourceReferences(sourceEvidence), 180)}` : '',
      ].filter(Boolean).join(' | '));
    });
    if (rows.length > 45) lines.push(`Additional TTPs omitted from AI context: ${rows.length - 45}.`);
    lines.push('');
  }
  if (sections.actors) {
    lines.push('Threat actor comparison:');
    matches.slice(0, 8).forEach((item, index) => {
      lines.push(`${index + 1}. ${item.group_name} (${item.group_attack_id}) | similarity=${Math.round(item.similarity * 100)}% | shared=${item.shared_count} | shared_ttps=${item.shared_techniques.slice(0, 18).join(', ')}`);
    });
    lines.push('');
  }
  if (sections.iocs) {
    lines.push('Relevant IOC enrichment:');
    buildReportIocItems(relevantIocs, evidenceIndex).slice(0, 35).forEach(item => {
      lines.push(`${item.value} (${item.type}) | source_tag=${item.sourceTag} | reference=${truncate(item.reference, 160)} | source=${item.source || 'unknown'} | malware=${item.malware_family || 'unknown'} | campaign=${item.campaign || 'unknown'} | ttps=${item.technique_ids?.slice(0, 8).join(', ') || 'none'} | confidence=${item.confidence ?? 0}`);
    });
    if (relevantIocs.length > 25) lines.push(`Additional IOCs omitted from AI context: ${relevantIocs.length - 25}.`);
  }
  if (investigation) {
    lines.push('', 'Investigation workspace evidence:');
    lines.push(`Name: ${investigation.name}`);
    lines.push(`TTP layer: ${investigation.technique_ids.join(', ')}`);
    lines.push(`Actor leads: ${investigation.actor_ids.join(', ') || 'none'}`);
    lines.push(`Report/log/IOC evidence nodes: ${investigation.evidence_nodes.length}`);
    investigation.evidence_nodes.slice(-30).forEach(node => {
      lines.push(`${String(node.type ?? 'evidence')} | ${String(node.label ?? node.value ?? node.id ?? '')} | ${String(node.summary ?? node.description ?? '').slice(0, 180)}`);
    });
    lines.push('Timeline:');
    investigation.timeline.slice(-20).forEach(item => lines.push(`${String(item.at ?? '')} | ${String(item.event ?? item.source ?? '')}`));
  }
  return truncate(lines.join('\n'), 7600);
}

function truncate(value: string, limit: number) {
  return value.length > limit ? `${value.slice(0, Math.max(0, limit - 3))}...` : value;
}

function buildSavedReportNode({
  title,
  content,
  provider,
  format,
}: {
  title: string;
  content: string;
  provider: string;
  format: string;
}): SavedReportNode {
  const createdAt = new Date().toISOString();
  return {
    id: `investigation-report:${Date.now()}`,
    type: 'investigation-report',
    label: title || 'AdversaryGraph Investigation Report',
    summary: truncate(content.replace(/\s+/g, ' ').trim(), 500),
    content,
    provider,
    format,
    created_at: createdAt,
  };
}

function savedReportNodes(investigation: Investigation | null): SavedReportNode[] {
  if (!investigation) return [];
  return (investigation.evidence_nodes ?? [])
    .filter(node => String(node.type ?? '') === 'investigation-report')
    .map((node, index) => {
      const record = node as Record<string, unknown>;
      const label = String(record.label ?? record.title ?? 'Investigation report');
      const content = String(record.content ?? record.report ?? record.markdown ?? record.body ?? record.summary ?? '');
      return {
        id: String(record.id ?? `investigation-report:${index}`),
        type: 'investigation-report',
        label,
        summary: String(record.summary ?? truncate(content.replace(/\s+/g, ' ').trim(), 500)),
        content,
        provider: String(record.provider ?? record.source ?? ''),
        format: String(record.format ?? 'markdown'),
        created_at: String(record.created_at ?? record.generated_at ?? ''),
      };
    })
    .filter(report => Boolean(report.content.trim()))
    .sort((a, b) => String(b.created_at ?? b.id).localeCompare(String(a.created_at ?? a.id)));
}

function formatReportDate(value?: string) {
  if (!value) return 'saved';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

async function readSseText(response: Response) {
  if (!response.ok || !response.body) {
    throw new Error(await response.text() || `HTTP ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let output = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop() ?? '';
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      const raw = line.slice(6);
      try {
        const event = JSON.parse(raw);
        if (event.type === 'token') output += event.content ?? '';
        if (event.type === 'error') throw new Error(event.message ?? 'AI generation failed');
      } catch (error) {
        if (error instanceof SyntaxError) continue;
        throw error;
      }
    }
  }
  return output;
}

function downloadBlob(content: BlobPart, filename: string, type: string) {
  const url = URL.createObjectURL(content instanceof Blob ? content : new Blob([content], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function markdownToPlainText(markdown: string) {
  return markdown
    .replace(/^#{1,6}\s+/gm, '')
    .replace(/\*\*(.*?)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[(.*?)\]\((.*?)\)/g, '$1 ($2)');
}

function buildSimplePdf(text: string) {
  const escapedLines = wrapText(text, 92).flatMap(line => line === '' ? [' '] : [line]);
  const pages: string[][] = [];
  for (let i = 0; i < escapedLines.length; i += 46) pages.push(escapedLines.slice(i, i + 46));
  if (!pages.length) pages.push(['No report content.']);

  const objects: string[] = [];
  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  objects.push(`<< /Type /Pages /Kids [${pages.map((_, index) => `${3 + index * 2} 0 R`).join(' ')}] /Count ${pages.length} >>`);
  pages.forEach((page, index) => {
    const pageObj = 3 + index * 2;
    const contentObj = pageObj + 1;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents ${contentObj} 0 R >>`);
    const stream = [
      'BT',
      '/F1 10 Tf',
      '50 750 Td',
      ...page.map((line, lineIndex) => `${lineIndex === 0 ? '' : '0 -14 Td'}(${escapePdf(line)}) Tj`),
      'ET',
    ].join('\n');
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
  });

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach(offset => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new Blob([pdf], { type: 'application/pdf' });
}

function wrapText(text: string, width: number) {
  return text.split('\n').flatMap(line => {
    if (line.length <= width) return [line];
    const words = line.split(/\s+/);
    const lines: string[] = [];
    let current = '';
    words.forEach(word => {
      if ((current + ' ' + word).trim().length > width) {
        lines.push(current);
        current = word;
      } else {
        current = `${current} ${word}`.trim();
      }
    });
    if (current) lines.push(current);
    return lines;
  });
}

function escapePdf(text: string) {
  return text.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'adversarygraph-report';
}

function FlowStep({
  number,
  title,
  text,
  actionLabel,
  onAction,
  disabled = false,
}: {
  number: number;
  title: string;
  text: string;
  actionLabel?: string;
  onAction?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <div className="flex items-start gap-3">
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded bg-mitre-accent text-xs font-bold text-white">{number}</span>
        <div className="min-w-0">
          <b className="block text-sm text-gray-200">{title}</b>
          <p className="mt-1 text-xs leading-5 text-gray-500">{text}</p>
          {actionLabel && onAction && (
            <button type="button" onClick={onAction} disabled={disabled} className="secondary-action mt-3 text-xs disabled:opacity-40">
              {actionLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function mergeInvestigation(
  row: Investigation,
  patch: Partial<Pick<Investigation, 'actor_ids' | 'technique_ids' | 'report_ids' | 'evidence_nodes' | 'evidence_edges' | 'timeline'>>,
): Omit<Investigation, 'id' | 'created_at' | 'updated_at'> {
  return {
    name: row.name,
    description: row.description,
    status: row.status || 'active',
    domain: row.domain,
    actor_ids: mergeStrings(row.actor_ids, patch.actor_ids),
    technique_ids: mergeStrings(row.technique_ids, patch.technique_ids?.map(item => item.toUpperCase())),
    report_ids: mergeStrings(row.report_ids, patch.report_ids),
    evidence_nodes: mergeObjects(row.evidence_nodes, patch.evidence_nodes),
    evidence_edges: mergeObjects(row.evidence_edges, patch.evidence_edges),
    timeline: [...(row.timeline ?? []), ...(patch.timeline ?? [])].slice(-250),
  };
}

function mergeStrings(current: string[] = [], incoming: string[] = []) {
  return Array.from(new Set([...current, ...incoming].filter(Boolean))).sort();
}

function mergeObjects(current: Array<Record<string, unknown>> = [], incoming: Array<Record<string, unknown>> = []) {
  const seen = new Set<string>();
  return [...current, ...incoming].filter(item => {
    const key = String(item.id ?? item.value ?? item.label ?? JSON.stringify(item));
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(-500);
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/50">
      <h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function CheckRow({ checked, title, text, onChange }: { checked: boolean; title: string; text: string; onChange: () => void }) {
  return (
    <label className="flex cursor-pointer gap-3 rounded border border-gray-800 bg-gray-950/40 p-3 hover:border-gray-700">
      <input type="checkbox" checked={checked} onChange={onChange} className="mt-1 h-4 w-4 accent-mitre-accent" />
      <span>
        <span className="block text-sm font-semibold text-gray-200">{title}</span>
        <span className="mt-1 block text-xs leading-5 text-gray-500">{text}</span>
      </span>
    </label>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <b className="block text-lg text-white">{value}</b>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  );
}
