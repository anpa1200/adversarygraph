import { useMemo, useState } from 'react';
import { useQueries, useQuery } from '@tanstack/react-query';
import { aptApi, attackApi, analyzeApi, iocApi, type IOCItem } from '@/api/client';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';

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

const providerOptions: { id: Provider; label: string }[] = [
  { id: 'local', label: 'Local LLM' },
  { id: 'claude', label: 'Claude' },
  { id: 'openai', label: 'OpenAI' },
  { id: 'gemini', label: 'Gemini' },
  { id: 'minimax', label: 'MiniMax' },
];

export function InvestigationReport() {
  const { domain, version, selectedTechniques, coverageTechniques, techniqueAssessments } = useAppStore();
  const ids = useMemo(() => [...selectedTechniques].sort(), [selectedTechniques]);
  const [sections, setSections] = useState<ReportSections>({
    navigator: true,
    ttps: true,
    actors: true,
    iocs: true,
  });
  const [provider, setProvider] = useState<Provider>('local');
  const [reportTitle, setReportTitle] = useState('AdversaryGraph Investigation Report');
  const [generatedReport, setGeneratedReport] = useState('');
  const [isAiGenerating, setIsAiGenerating] = useState(false);
  const [aiError, setAiError] = useState('');

  const { data: techniques = [] } = useQuery({
    queryKey: ['report-techniques', domain, version],
    queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }),
  });
  const { data: matches = [], isFetching: matchesLoading } = useQuery({
    queryKey: ['report-matches', domain, version, ids.join(',')],
    queryFn: () => aptApi.compare({ technique_ids: ids, domain, version: version ?? undefined, top_n: 10 }),
    enabled: ids.length > 0,
  });

  const actorIocQueries = useQueries({
    queries: sections.iocs
      ? matches.slice(0, 5).map(match => ({
        queryKey: ['report-actor-iocs', match.group_attack_id],
        queryFn: () => iocApi.actor(match.group_attack_id, { days: 180, active_only: true, limit: 20 }),
        enabled: ids.length > 0,
      }))
      : [],
  });

  const rows = useMemo(() => ids.map(id => ({
    id,
    name: techniques.find(item => item.attack_id === id)?.name ?? id,
    assessment: techniqueAssessments[id] ?? {},
    covered: coverageTechniques.has(id),
  })), [coverageTechniques, ids, techniqueAssessments, techniques]);

  const relevantIocs = useMemo(
    () => actorIocQueries.flatMap(query => (query.data ?? []) as IOCItem[]),
    [actorIocQueries],
  );
  const localReport = useMemo(
    () => buildLocalReport({ title: reportTitle, domain, rows, matches, relevantIocs, sections }),
    [domain, matches, relevantIocs, reportTitle, rows, sections],
  );
  const activeReport = generatedReport || localReport;
  const selectedSectionCount = Object.values(sections).filter(Boolean).length;

  const toggleSection = (key: keyof ReportSections) => {
    setSections(current => ({ ...current, [key]: !current[key] }));
  };

  const generateLocal = () => {
    setAiError('');
    setGeneratedReport(localReport);
  };

  const generateWithAi = async () => {
    if (!ids.length || !selectedSectionCount) return;
    setIsAiGenerating(true);
    setAiError('');
    setGeneratedReport('');
    try {
      const context = buildReportContext({ domain, rows, matches, relevantIocs, sections });
      const response = await analyzeApi.chat({
        provider,
        context,
        message: [
          `Generate a professional threat intelligence investigation report titled "${reportTitle}".`,
          'Use only the provided context. Do not invent evidence, IOCs, actors, or TTPs.',
          'Write in Markdown with these sections when data exists: Executive Summary, Scope, Navigator Layer, ATT&CK TTP Evidence, Threat Actor Comparison, Relevant IOC Enrichment, Detection and Coverage Priorities, Analytic Caveats.',
          'Make it client-ready, concise, and actionable.',
        ].join(' '),
      });
      const text = await readSseText(response);
      setGeneratedReport(text.trim() || localReport);
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setIsAiGenerating(false);
    }
  };

  const download = (format: ReportFormat) => {
    const filenameBase = slug(reportTitle || 'adversarygraph-investigation-report');
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
      <Header title="Investigation Report" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
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
                    <button
                      type="button"
                      onClick={generateLocal}
                      disabled={!ids.length || !selectedSectionCount}
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
                        disabled={!ids.length || !selectedSectionCount || isAiGenerating}
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

              <Panel title="Download">
                <div className="grid grid-cols-3 gap-2 p-3">
                  <button type="button" onClick={() => download('pdf')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">PDF</button>
                  <button type="button" onClick={() => download('md')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">MD</button>
                  <button type="button" onClick={() => download('txt')} disabled={!activeReport.trim()} className="secondary-action disabled:opacity-40">TXT</button>
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
                {!ids.length && <p className="px-3 pb-3 text-xs text-amber-300">Select TTPs in Navigator, AI Analysis, IOC enrichment, or actor pages before generating a report.</p>}
              </Panel>
            </div>

            <Panel title="Report preview">
              <pre className="max-h-[calc(100vh-220px)] overflow-auto whitespace-pre-wrap p-4 text-xs leading-6 text-gray-300">
                {activeReport || 'No report content yet.'}
              </pre>
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
}: {
  title: string;
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
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
      lines.push(
        `### ${row.id} - ${row.name}`,
        `- Coverage: ${row.covered ? 'covered' : 'gap'}`,
        `- Mapping: ${row.assessment.mapping ?? 'weak'}`,
        `- Confidence: ${row.assessment.confidence ?? 'low'}`,
        `- Maturity: ${row.assessment.maturity ?? 'none'}`,
        `- Evidence: ${row.assessment.evidence ?? 'Not recorded'}`,
        `- Source: ${row.assessment.source ?? 'Not recorded'}`,
        `- Notes: ${row.assessment.notes ?? 'Not recorded'}`,
        '',
      );
    });
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
    if (relevantIocs.length) {
      relevantIocs.slice(0, 60).forEach(item => {
        lines.push(
          `- ${item.value} (${item.type})`,
          `  - Source: ${item.source || 'unknown'}`,
          `  - Malware: ${item.malware_family || 'unknown'}`,
          `  - Campaign: ${item.campaign || 'unknown'}`,
          `  - TTPs: ${item.technique_ids?.join(', ') || 'none mapped'}`,
          `  - Confidence: ${item.confidence ?? 0}`,
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

function buildReportContext({
  domain,
  rows,
  matches,
  relevantIocs,
  sections,
}: {
  domain: string;
  rows: ReportRow[];
  matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  relevantIocs: IOCItem[];
  sections: ReportSections;
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
      lines.push([
        `${row.id} ${row.name}`,
        `coverage=${row.covered ? 'covered' : 'gap'}`,
        `mapping=${row.assessment.mapping ?? 'weak'}`,
        `confidence=${row.assessment.confidence ?? 'low'}`,
        `maturity=${row.assessment.maturity ?? 'none'}`,
        row.assessment.evidence ? `evidence=${truncate(row.assessment.evidence, 120)}` : '',
        row.assessment.source ? `source=${truncate(row.assessment.source, 80)}` : '',
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
    relevantIocs.slice(0, 25).forEach(item => {
      lines.push(`${item.value} (${item.type}) | source=${item.source || 'unknown'} | malware=${item.malware_family || 'unknown'} | campaign=${item.campaign || 'unknown'} | ttps=${item.technique_ids?.slice(0, 8).join(', ') || 'none'} | confidence=${item.confidence ?? 0}`);
    });
    if (relevantIocs.length > 25) lines.push(`Additional IOCs omitted from AI context: ${relevantIocs.length - 25}.`);
  }
  return truncate(lines.join('\n'), 7600);
}

function truncate(value: string, limit: number) {
  return value.length > limit ? `${value.slice(0, Math.max(0, limit - 3))}...` : value;
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
