import { useState, useCallback, useEffect } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAppStore } from '@/store';
import { analyzeApi, exportApi, reportsApi } from '@/api/client';
import type { AnalysisResult, LogPcapAnalysisResult } from '@/api/client';
import { useSseStream } from '@/hooks/useSseStream';
import { Header } from '@/components/Layout/Header';
import { AddToInvestigationButton } from '@/components/AddToInvestigationButton';
import type { ReportSession } from '@/types/attack';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

type Provider = 'claude' | 'openai' | 'gemini' | 'minimax' | 'local';
type AnalysisMode = 'cti' | 'log-pcap';
type LogPcapHistoryItem = LogPcapAnalysisResult & {
  history_id: string;
  created_at: string;
  name: string;
  technique_count: number;
  observable_count: number;
  suspicious_count: number;
};

const LOG_PCAP_HISTORY_KEY = 'adversarygraph-log-pcap-history-v1';
const LOG_PCAP_HISTORY_LIMIT = 20;

const PROVIDERS: { id: Provider; label: string; color: string }[] = [
  { id: 'claude',  label: 'Claude',  color: 'border-orange-600 bg-orange-900/20 text-orange-300' },
  { id: 'openai',  label: 'OpenAI',  color: 'border-green-700  bg-green-900/20  text-green-300'  },
  { id: 'gemini',  label: 'Gemini',  color: 'border-blue-600   bg-blue-900/20   text-blue-300'   },
  { id: 'minimax', label: 'MiniMax', color: 'border-violet-600 bg-violet-900/20 text-violet-300' },
  { id: 'local',   label: 'Local',   color: 'border-cyan-600   bg-cyan-900/20   text-cyan-300'   },
];

export function Analyze() {
  const { domain, addTechniques, addComparisonLayer } = useAppStore();
  const canRunAnalysis = useHasPermission('run_analysis');
  const canManageIntel = useHasPermission('manage_intel');
  const canExport = useHasPermission('export_data');
  const canUploadFiles = useHasPermission('upload_files');
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [provider, setProvider] = useState<Provider>('claude');
  const [mode, setMode] = useState<AnalysisMode>('cti');
  const [text,     setText]     = useState('');
  const [file,     setFile]     = useState<File | null>(null);
  const [loadedResult, setLoadedResult] = useState<AnalysisResult | null>(null);
  const [logPcapResult, setLogPcapResult] = useState<LogPcapAnalysisResult | null>(null);
  const [logPcapHistory, setLogPcapHistory] = useState<LogPcapHistoryItem[]>(() => loadLogPcapHistory());
  const [activeLogPcapHistoryId, setActiveLogPcapHistoryId] = useState<string | null>(null);

  // result: populated by the server-side "result" SSE event (includes group-similarity leads)
  // tokens: raw LLM token stream shown live while waiting
  const { tokens, result, error, streaming, run, abort, reset } = useSseStream<AnalysisResult>();
  const activeResult = result ?? loadedResult;

  const { data: previousReports = [], isLoading: historyLoading } = useQuery({
    queryKey: ['report-sessions'],
    queryFn: () => reportsApi.list(100, 0),
    staleTime: 30_000,
  });

  const loadReportMutation = useMutation({
    mutationFn: (sessionId: string) => analyzeApi.getResult(sessionId),
    onSuccess: data => {
      reset();
      setLoadedResult(data);
      setLogPcapResult(null);
      setActiveLogPcapHistoryId(null);
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (sessionId: string) => reportsApi.remove(sessionId),
    onSuccess: (_data, sessionId) => {
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
      if (loadedResult?.session_id === sessionId || result?.session_id === sessionId) {
        setLoadedResult(null);
        reset();
      }
    },
  });

  const logPcapMutation = useMutation({
    mutationFn: (fd: FormData) => analyzeApi.logPcap(fd),
    onSuccess: data => {
      const item = createLogPcapHistoryItem(data);
      reset();
      setLoadedResult(null);
      setLogPcapResult(item);
      setActiveLogPcapHistoryId(item.history_id);
      setLogPcapHistory(current => {
        const next = [item, ...current].slice(0, LOG_PCAP_HISTORY_LIMIT);
        saveLogPcapHistory(next);
        return next;
      });
    },
  });

  useEffect(() => {
    if (result?.session_id) {
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
    }
  }, [queryClient, result?.session_id]);

  const handleRun = useCallback(async () => {
    if (!canRunAnalysis || (file && !canUploadFiles)) return;
    const fd = new FormData();
    fd.append('provider', provider);
    fd.append('domain', domain);
    if (file) fd.append('file', file);
    else if (text.trim()) fd.append('text', text.trim());
    else return;

    reset();
    setLoadedResult(null);
    setLogPcapResult(null);
    setActiveLogPcapHistoryId(null);
    if (mode === 'log-pcap') {
      logPcapMutation.mutate(fd);
      return;
    }
    await run(signal => analyzeApi.stream(fd, signal));
  }, [canRunAnalysis, canUploadFiles, provider, domain, file, text, reset, mode, logPcapMutation, run]);

  const onDrop = useCallback(([f]: File[]) => { if (canRunAnalysis && canUploadFiles && f) { setFile(f); setText(''); } }, [canRunAnalysis, canUploadFiles]);
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'text/plain': ['.txt', '.log', '.evtx', '.csv'],
      'application/vnd.tcpdump.pcap': ['.pcap', '.pcapng', '.cap'],
    },
    maxFiles: 1,
    disabled: !canRunAnalysis || !canUploadFiles,
  });

  const canSubmit = canRunAnalysis && (!!text.trim() || (!!file && canUploadFiles)) && !streaming && !logPcapMutation.isPending;

  return (
    <div className="flex flex-col h-full">
      <Header title="AI Analysis" />

      <div className="flex flex-1 overflow-hidden">

        {/* ── Left: input panel ─────────────────────────────────────────────── */}
        <div className="w-[380px] shrink-0 border-r border-gray-700 flex flex-col">

          {/* Provider selector */}
          <div className="p-4 border-b border-gray-800">
            <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">LLM Provider</div>
            <div className="flex flex-col gap-1.5">
              {PROVIDERS.map(p => (
                <button
                  key={p.id}
                  disabled={!canRunAnalysis}
                  onClick={() => setProvider(p.id)}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg border text-sm font-medium transition-colors ${
                    provider === p.id ? p.color : 'border-gray-700 text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span className="flex-1 text-left">{p.label}</span>
                  <span className="text-[10px] opacity-60">server-selected model</span>
                </button>
              ))}
            </div>
          </div>

          {/* Text input */}
          <div className="p-4 border-b border-gray-800 flex-1 flex flex-col">
            <div className="mb-3 grid grid-cols-2 gap-1 rounded bg-gray-950 p-1 text-xs">
              <button
                type="button"
                disabled={!canRunAnalysis}
                onClick={() => setMode('cti')}
                className={`rounded px-2 py-1.5 ${mode === 'cti' ? 'bg-mitre-accent text-white' : 'text-gray-500 hover:text-gray-300'}`}
              >
                CTI report
              </button>
              <button
                type="button"
                disabled={!canRunAnalysis}
                onClick={() => setMode('log-pcap')}
                className={`rounded px-2 py-1.5 ${mode === 'log-pcap' ? 'bg-mitre-accent text-white' : 'text-gray-500 hover:text-gray-300'}`}
              >
                Log / PCAP
              </button>
            </div>
            {mode === 'log-pcap' && (
              <div className="mb-3 rounded border border-cyan-700/40 bg-cyan-950/20 p-3 text-[11px] leading-5 text-cyan-100">
                No manual prompt is needed. AdversaryGraph uses the built-in Log / PCAP analysis system prompt. Analyze one source at a time, for example firewall logs first and EDR logs second, then add each result to your investigation.
              </div>
            )}
            <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">Paste text</div>
            <textarea
              disabled={!canRunAnalysis}
              value={text}
              onChange={e => { setText(e.target.value); setFile(null); }}
              rows={8}
              className="flex-1 bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none resize-none font-mono placeholder-gray-600"
              placeholder={mode === 'log-pcap' ? 'Paste logs, PowerShell transcript, EDR output, firewall/DNS/proxy lines, Zeek/Suricata output...' : 'Paste incident report, investigation notes, IOC list, threat intel blog…'}
            />

            {/* File upload */}
            <div className="mt-3">
              <div className="text-xs text-gray-500 mb-2 font-semibold uppercase tracking-wide">
                Or upload {mode === 'log-pcap' ? '(LOG / TXT / CSV / PCAP / PCAPNG)' : '(PDF / DOCX / TXT)'}
              </div>
              <div
                {...getRootProps()}
                className={`border-2 border-dashed rounded-lg p-4 text-center cursor-pointer transition-colors text-xs ${
                  isDragActive ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-700 hover:border-gray-500'
                }`}
              >
                <input {...getInputProps()} />
                {file ? (
                  <div className="text-gray-300 flex items-center justify-center gap-2">
                    <span className="text-mitre-accent">✓</span>
                    <span>{file.name}</span>
                    <button className="text-gray-500 hover:text-red-400 text-xs" onClick={e => { e.stopPropagation(); setFile(null); }}>✕</button>
                  </div>
                ) : (
                  <p className="text-gray-600">{isDragActive ? 'Drop here' : 'Drag & drop or click'}</p>
                )}
              </div>
              {!canUploadFiles && <div className="mt-2"><PermissionNotice permission="upload_files" action="upload report, log, or PCAP files" compact /></div>}
            </div>
          </div>

          {/* Submit */}
          <div className="p-4 border-b border-gray-800">
            {!canRunAnalysis && <div className="mb-3"><PermissionNotice permission="run_analysis" action="submit CTI, log, or PCAP analysis" compact /></div>}
            {streaming ? (
              <button
                onClick={abort}
                className="w-full bg-gray-700 hover:bg-gray-600 text-white py-2.5 rounded font-medium text-sm transition-colors"
              >
                Stop analysis
              </button>
            ) : (
              <button
                onClick={handleRun}
                disabled={!canSubmit}
                className="w-full bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white py-2.5 rounded font-medium text-sm transition-colors"
              >
                {logPcapMutation.isPending ? 'Analysing log / PCAP...' : mode === 'log-pcap' ? 'Analyse log / PCAP' : 'Analyse with AI'}
              </button>
            )}
            {(error || logPcapMutation.error) && (
              <div className="mt-3 text-xs text-red-400 bg-red-900/20 px-3 py-2 rounded">
                {error || (logPcapMutation.error instanceof Error ? logPcapMutation.error.message : String(logPcapMutation.error))}
              </div>
            )}
          </div>

          <div className="border-b border-gray-800 p-3">
            <button
              type="button"
              onClick={() => navigate('/reports-research')}
              className="secondary-action w-full"
            >
              Open Reports / Research Collection
            </button>
          </div>

          {mode === 'log-pcap' ? (
            <PreviousLogPcapAnalysisList
              items={logPcapHistory}
              activeHistoryId={activeLogPcapHistoryId}
              onOpen={item => {
                reset();
                setLoadedResult(null);
                setLogPcapResult(item);
                setActiveLogPcapHistoryId(item.history_id);
              }}
              onDelete={historyId => {
                if (!window.confirm('Delete this stored log analysis?')) return;
                setLogPcapHistory(current => {
                  const next = current.filter(item => item.history_id !== historyId);
                  saveLogPcapHistory(next);
                  return next;
                });
                if (activeLogPcapHistoryId === historyId) {
                  setLogPcapResult(null);
                  setActiveLogPcapHistoryId(null);
                }
              }}
            />
          ) : (
            <PreviousAnalysisList
              reports={previousReports}
              loading={historyLoading}
              activeSessionId={activeResult?.session_id ?? null}
              loadingSessionId={loadReportMutation.variables ?? null}
              deletingSessionId={deleteReportMutation.variables ?? null}
              canDelete={canManageIntel}
              canExport={canExport}
              onOpen={sessionId => loadReportMutation.mutate(sessionId)}
              onDelete={sessionId => {
                if (window.confirm('Delete this stored analysis?')) {
                  deleteReportMutation.mutate(sessionId);
                }
              }}
            />
          )}
        </div>

        {/* ── Right: results panel ──────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {/* Live token stream */}
          {streaming && (
            <div className="border-b border-gray-800 bg-gray-900/50">
              <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-800">
                <div className="w-2 h-2 rounded-full bg-mitre-accent animate-pulse" />
                <span className="text-xs text-gray-400">Analysing…</span>
              </div>
              <pre className="text-[10px] font-mono text-gray-400 px-4 py-3 max-h-40 overflow-y-auto whitespace-pre-wrap">
                {tokens || ' '}
              </pre>
            </div>
          )}

          {/* Empty state */}
          {!streaming && !tokens && !activeResult && !logPcapResult && (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-gray-600">
              <div className="text-5xl mb-4">⬢</div>
              <p className="text-gray-500">Submit a report, log, or PCAP to extract ATT&CK techniques.</p>
              <p className="text-xs mt-2 text-gray-600">
                Previous analyses are remembered locally and can be reopened from the left panel.
              </p>
            </div>
          )}

          {/* Full parsed result from server (includes group-similarity leads) */}
          {activeResult && (
            <ResultsView
              result={activeResult}
              domain={domain}
              addTechniques={addTechniques}
              addComparisonLayer={addComparisonLayer}
              navigate={navigate}
            />
          )}

          {logPcapResult && (
            <LogPcapResultView
              result={logPcapResult}
              domain={domain}
              addTechniques={addTechniques}
              addComparisonLayer={addComparisonLayer}
              navigate={navigate}
            />
          )}

          {/* Fallback: parse raw tokens when stream ended without a result event */}
          {!result && !streaming && tokens && (
            <StreamResultParser
              tokens={tokens}
              domain={domain}
              addTechniques={addTechniques}
              addComparisonLayer={addComparisonLayer}
              navigate={navigate}
            />
          )}
        </div>
      </div>
    </div>
  );
}

function LogPcapResultView({
  result,
  domain,
  addTechniques,
  addComparisonLayer,
  navigate,
}: {
  result: LogPcapAnalysisResult;
  domain: string;
  addTechniques: (ids: string[]) => void;
  addComparisonLayer: (layer: { name: string; techniqueIds: string[]; source?: string; color?: string }) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const canExport = useHasPermission('export_data');
  const ttpIds = result.techniques.filter(item => item.review_status !== 'rejected').map(item => item.attack_id);
  const iocCandidates = result.observables.filter(item => ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256'].includes(item.type));
  const expectedBehaviors = buildExpectedSuspiciousBehaviors(result);
  const analysisId = getLogPcapAnalysisId(result);
  const sourceRef = result.filename || `log-pcap-${analysisId.slice(0, 8)}`;
  const addToMyTtps = () => addTechniques(ttpIds);
  const compareOnMatrix = () => {
    addComparisonLayer({
      name: `Log/PCAP ${result.filename || new Date().toLocaleTimeString()}`,
      techniqueIds: ttpIds,
      source: 'log-pcap-analysis',
    });
    navigate('/navigator');
  };
  const downloadReport = (format: 'md' | 'txt') => {
    const content = format === 'md' ? result.report : result.report.replace(/^#{1,6}\s+/gm, '');
    const url = URL.createObjectURL(new Blob([content], { type: format === 'md' ? 'text/markdown' : 'text/plain' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `adversarygraph-log-pcap-report.${format}`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="border-b border-gray-800 bg-gray-900/50 px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <span className="text-xs text-gray-500 font-mono">{result.provider} / {result.model}</span>
            <h2 className="mt-1 text-lg font-semibold text-white">Log / PCAP Analysis</h2>
            <p className="mt-1 max-w-4xl text-sm text-gray-300">{result.summary || 'No AI summary returned.'}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <AddToInvestigationButton
              payload={{
                label: `Log/PCAP analysis ${sourceRef}`,
                domain,
                techniqueIds: ttpIds,
                actorIds: result.apt_matches.map(item => item.group_attack_id),
                evidenceNodes: [
                  {
                    id: `log-pcap:${analysisId}`,
                    type: 'log-pcap-analysis',
                    label: sourceRef,
                    source_ref: sourceRef,
                    analysis_id: analysisId,
                    summary: result.summary,
                    report: result.report,
                    observables: result.observables,
                    suspicious_findings: result.suspicious_findings,
                    expected_suspicious_behaviors: expectedBehaviors,
                  },
                  ...expectedBehaviors.filter(item => item.found).map((item, index) => ({
                    id: `suspicious-behavior:${analysisId}:${item.id}:${index}`,
                    type: 'suspicious-behavior',
                    label: item.evidence,
                    source_ref: sourceRef,
                    analysis_id: analysisId,
                    evidence: item.evidence,
                    why: item.why,
                    found: item.found,
                    refs: item.refs,
                    ttps: item.ttps,
                    iocs: item.iocs,
                    source: 'log-pcap-analysis',
                  })),
                  ...result.techniques.slice(0, 100).map(item => ({
                    id: `ttp-evidence:${analysisId}:${item.attack_id}`,
                    type: 'ttp-evidence',
                    attack_id: item.attack_id,
                    label: `${item.attack_id} ${item.name}`,
                    source_ref: sourceRef,
                    analysis_id: analysisId,
                    tactic: item.tactic,
                    confidence: item.confidence,
                    evidence: item.evidence,
                    status: item.review_status,
                    source: 'log-pcap-analysis',
                  })),
                  ...iocCandidates.slice(0, 100).map(item => ({
                    id: `ioc:${item.value}`,
                    type: 'ioc',
                    value: item.value,
                    ioc_type: item.type,
                    source_ref: sourceRef,
                    analysis_id: analysisId,
                    description: item.description,
                    source: 'log-pcap-analysis',
                  })),
                ],
                timelineEvent: `Added Log/PCAP analysis ${sourceRef}`.trim(),
              }}
              disabled={!ttpIds.length && !iocCandidates.length}
              className="text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white px-3 py-1.5 rounded"
            />
            <button onClick={addToMyTtps} disabled={!ttpIds.length} className="text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white px-3 py-1.5 rounded">+ My TTPs</button>
            <button onClick={compareOnMatrix} disabled={!ttpIds.length} className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-3 py-1.5 rounded">⇄ Matrix compare</button>
            {canExport && <button onClick={() => downloadReport('md')} className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded">↓ MD report</button>}
            {canExport && <button onClick={() => downloadReport('txt')} className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded">↓ TXT report</button>}
          </div>
        </div>
      </div>

      <div className="grid gap-4 p-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <section className="space-y-4">
          <ExpectedSuspiciousBehaviorsPanel
            rows={expectedBehaviors}
            onOpenTtp={(id) => {
              addTechniques([id]);
              navigate('/navigator');
            }}
            onOpenIoc={(value) => navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`)}
          />

          <Panel title={`Suspicious / malicious findings (${result.suspicious_findings.length})`}>
            {result.suspicious_findings.length ? result.suspicious_findings.map((finding, index) => (
              <div key={`${finding.category}-${index}`} className="border-t border-gray-800 p-3">
                <div className="flex items-center gap-2">
                  <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${finding.severity === 'high' ? 'bg-red-950 text-red-300' : finding.severity === 'medium' ? 'bg-amber-950 text-amber-300' : 'bg-gray-800 text-gray-400'}`}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <b className="text-sm text-white">{finding.category}</b>
                </div>
                <p className="mt-1 text-xs text-gray-500">{finding.reason}</p>
                <pre className="mt-2 whitespace-pre-wrap rounded bg-gray-950 p-2 text-[10px] text-gray-400">{finding.evidence}</pre>
              </div>
            )) : <p className="p-3 text-xs text-gray-500">No suspicious heuristic findings.</p>}
          </Panel>

          <Panel title={`Mapped TTPs (${result.techniques.length})`}>
            {result.techniques.length ? result.techniques.map(technique => (
              <div key={technique.attack_id} className="border-t border-gray-800 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <a href={`/navigator?technique=${technique.attack_id}`} className="font-mono text-sm text-mitre-accent hover:underline">{technique.attack_id}</a>
                  <b className="text-sm text-white">{technique.name}</b>
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{technique.tactic}</span>
                  <span className="rounded bg-green-950 px-1.5 py-0.5 text-[10px] text-green-300">{Math.round(technique.confidence * 100)}%</span>
                </div>
                <p className="mt-1 text-xs italic text-gray-500">{technique.evidence}</p>
              </div>
            )) : <p className="p-3 text-xs text-gray-500">No TTPs mapped.</p>}
          </Panel>

          <Panel title="Report">
            <pre className="max-h-96 overflow-auto whitespace-pre-wrap p-3 text-xs leading-6 text-gray-300">{result.report}</pre>
          </Panel>
        </section>

        <aside className="space-y-4">
          <Panel title={`Possible IOCs for enrichment (${iocCandidates.length})`}>
            <div className="max-h-[520px] overflow-y-auto">
              {iocCandidates.length ? iocCandidates.slice(0, 150).map((ioc, index) => (
                <div key={`${ioc.value}-${index}`} className="border-t border-gray-800 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="break-all font-mono text-xs text-gray-200">{ioc.value}</span>
                    <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{ioc.type}</span>
                  </div>
                  <p className="mt-1 text-[10px] text-gray-500">{ioc.description}</p>
                  <div className="mt-2 flex gap-2">
                    <button onClick={() => navigate(`/virustotal?indicator=${encodeURIComponent(ioc.value)}`)} className="secondary-action text-[10px]">Enrich</button>
                    <button onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(ioc.value)}`)} className="secondary-action text-[10px]">Search IOC DB</button>
                  </div>
                </div>
              )) : <p className="p-3 text-xs text-gray-500">No IOC candidates extracted.</p>}
            </div>
          </Panel>

          <Panel title={`Actor overlap (${result.apt_matches.length})`}>
            {result.apt_matches.length ? result.apt_matches.slice(0, 10).map(match => (
              <div key={match.group_attack_id} className="border-t border-gray-800 p-3">
                <a href={`/apt?group=${match.group_attack_id}`} className="text-sm font-semibold text-white hover:text-mitre-accent">{match.group_name}</a>
                <p className="mt-1 text-[10px] text-gray-500">{match.group_attack_id} · {Math.round(match.similarity * 100)}% overlap · {match.shared_count} shared TTPs</p>
              </div>
            )) : <p className="p-3 text-xs text-gray-500">No actor overlap.</p>}
          </Panel>
        </aside>
      </div>
    </div>
  );
}

function PreviousAnalysisList({
  reports,
  loading,
  activeSessionId,
  loadingSessionId,
  deletingSessionId,
  onOpen,
  onDelete,
  canDelete,
  canExport,
}: {
  reports: ReportSession[];
  loading: boolean;
  activeSessionId: string | null;
  loadingSessionId: string | null;
  deletingSessionId: string | null;
  onOpen: (sessionId: string) => void;
  onDelete: (sessionId: string) => void;
  canDelete: boolean;
  canExport: boolean;
}) {
  return (
    <div className="min-h-[180px] max-h-[320px] flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide">Previous analysis</div>
        <span className="text-[10px] text-gray-600">{reports.length}</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {loading && <div className="px-4 py-3 text-xs text-gray-600">Loading saved analyses...</div>}
        {!loading && reports.length === 0 && (
          <div className="px-4 py-3 text-xs text-gray-600 leading-relaxed">
            Completed analyses will appear here for reuse, export, comparison, or deletion.
          </div>
        )}
        {reports.map(report => {
          const title = report.name || report.filename || `Analysis ${report.session_id.slice(0, 8)}`;
          const created = new Date(report.created_at).toLocaleString();
          const isActive = activeSessionId === report.session_id;
          const isLoading = loadingSessionId === report.session_id;
          const isDeleting = deletingSessionId === report.session_id;

          return (
            <div
              key={report.session_id}
              className={`group border-b border-gray-800 px-4 py-3 ${isActive ? 'bg-mitre-accent/10' : 'hover:bg-gray-900/60'}`}
            >
              <button
                type="button"
                onClick={() => onOpen(report.session_id)}
                className="w-full min-w-0 text-left"
                disabled={isLoading || isDeleting}
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm text-gray-200 font-medium">{title}</span>
                  {isActive && <span className="text-[10px] text-mitre-accent">open</span>}
                </div>
                <div className="mt-1 flex items-center gap-2 text-[10px] text-gray-600">
                  <span>{report.technique_count} TTPs</span>
                  <span>{report.provider}</span>
                  <span className="truncate">{created}</span>
                </div>
              </button>
              <div className="mt-2 flex items-center gap-2">
                {canExport && <a
                  href={exportApi.analysisUrl(report.session_id)}
                  download={`analysis-${report.session_id.slice(0, 8)}.pdf`}
                  className="text-[10px] text-gray-500 hover:text-gray-200"
                >
                  PDF
                </a>}
                {canExport && <a
                  href={exportApi.analysisStixUrl(report.session_id)}
                  download={`analysis-${report.session_id.slice(0, 8)}-opencti.stix.json`}
                  className="text-[10px] text-gray-500 hover:text-gray-200"
                >
                  STIX
                </a>}
                <a
                  href={`/analyze/${report.session_id}/report`}
                  className="text-[10px] text-mitre-accent hover:text-red-300"
                >
                  Linked report
                </a>
                {canDelete && <button
                  type="button"
                  onClick={() => onDelete(report.session_id)}
                  className="ml-auto text-[10px] text-gray-600 hover:text-red-400"
                  disabled={isDeleting}
                >
                  {isDeleting ? 'Deleting...' : 'Delete'}
                </button>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PreviousLogPcapAnalysisList({
  items,
  activeHistoryId,
  onOpen,
  onDelete,
}: {
  items: LogPcapHistoryItem[];
  activeHistoryId: string | null;
  onOpen: (item: LogPcapHistoryItem) => void;
  onDelete: (historyId: string) => void;
}) {
  return (
    <div className="min-h-[180px] max-h-[320px] flex flex-col">
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
        <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide">Previous log analyses</div>
        <span className="text-[10px] text-gray-600">{items.length}/20</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {items.length === 0 && (
          <div className="px-4 py-3 text-xs text-gray-600 leading-relaxed">
            The last 20 Log / PCAP analyses will be remembered here for reuse or deletion.
          </div>
        )}
        {items.map(item => {
          const created = new Date(item.created_at).toLocaleString();
          const isActive = activeHistoryId === item.history_id;

          return (
            <div
              key={item.history_id}
              className={`group border-b border-gray-800 px-4 py-3 ${isActive ? 'bg-mitre-accent/10' : 'hover:bg-gray-900/60'}`}
            >
              <button
                type="button"
                onClick={() => onOpen(item)}
                className="w-full min-w-0 text-left"
              >
                <div className="flex items-center gap-2">
                  <span className="truncate text-sm text-gray-200 font-medium">{item.name}</span>
                  {isActive && <span className="text-[10px] text-mitre-accent">open</span>}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-gray-600">
                  <span>{item.technique_count} TTPs</span>
                  <span>{item.observable_count} IOCs</span>
                  <span>{item.suspicious_count} findings</span>
                  <span>{item.provider}</span>
                </div>
                <div className="mt-1 truncate text-[10px] text-gray-600">{created}</div>
              </button>
              <div className="mt-2 flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => onDelete(item.history_id)}
                  className="ml-auto text-[10px] text-gray-600 hover:text-red-400"
                >
                  Delete
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Result view ───────────────────────────────────────────────────────────────

function ResultsView({
  result, domain, addTechniques, addComparisonLayer, navigate,
}: {
  result: AnalysisResult;
  domain: string;
  addTechniques: (ids: string[]) => void;
  addComparisonLayer: (layer: { name: string; techniqueIds: string[]; source?: string; color?: string }) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  const canManageIntel = useHasPermission('manage_intel');
  const canExport = useHasPermission('export_data');
  const [tab, setTab] = useState<'techniques' | 'groups' | 'raw'>('techniques');
  const [displayResult, setDisplayResult] = useState(result);

  useEffect(() => {
    setDisplayResult(result);
  }, [result]);

  const reviewMutation = useMutation({
    mutationFn: ({
      attackId,
      reviewStatus,
      evidence,
    }: {
      attackId: string;
      reviewStatus: NonNullable<AnalysisResult['techniques'][number]['review_status']>;
      evidence: string;
    }) =>
      analyzeApi.updateTechniqueReview(result.session_id, attackId, {
        review_status: reviewStatus,
        evidence,
      }),
    onSuccess: updated => {
      setDisplayResult(current => ({
        ...current,
        techniques: current.techniques.map(technique =>
          technique.attack_id === updated.attack_id ? { ...technique, ...updated } : technique
        ),
      }));
    },
  });

  const acceptedTechniqueIds = () =>
    displayResult.techniques
      .filter(t => t.review_status !== 'rejected')
      .map(t => t.attack_id);

  const injectAsMyTtps = () => {
    addTechniques(acceptedTechniqueIds());
  };

  const injectAndNavigate = () => {
    addTechniques(acceptedTechniqueIds());
    navigate('/navigator');
  };

  const compareOnMatrix = () => {
    addComparisonLayer({
      name: `AI ${displayResult.provider} ${new Date().toLocaleTimeString()}`,
      techniqueIds: acceptedTechniqueIds(),
      source: 'ai-analysis',
    });
    navigate('/navigator');
  };

  const canReview = canManageIntel && result.session_id !== 'stream';
  const canInject = acceptedTechniqueIds().length > 0;
  const acceptedCount = displayResult.techniques.filter(t => t.review_status === 'accepted').length;
  const needsEvidenceCount = displayResult.techniques.filter(t => t.review_status === 'needs-evidence').length;
  const rejectedCount = displayResult.techniques.filter(t => t.review_status === 'rejected').length;
  const sourceBoundCount = displayResult.techniques.filter(t => t.evidence_source === 'source-text').length;
  const averageConfidence = displayResult.techniques.length
    ? displayResult.techniques.reduce((sum, t) => sum + Number(t.confidence || 0), 0) / displayResult.techniques.length
    : 0;
  const groupedTechniques = groupTechniquesByTactic(displayResult.techniques);
  const topActorLead = displayResult.apt_matches[0] ?? null;

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Summary bar */}
      <div className="space-y-4 border-b border-gray-800 bg-gray-900/50 px-6 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <span className="text-xs text-gray-500 font-mono">{displayResult.provider} / {displayResult.model}</span>
            <h2 className="mt-1 text-xl font-semibold text-white">AI CTI Analysis Result</h2>
            <p className="mt-1 text-xs text-gray-500">
              Review the extracted techniques before using them for coverage, comparison, or reporting.
            </p>
          </div>
          <div className="flex flex-wrap justify-end gap-2">
            <AddToInvestigationButton
              payload={{
                label: `AI report analysis ${displayResult.session_id.slice(0, 8)}`,
                domain,
                techniqueIds: acceptedTechniqueIds(),
                actorIds: displayResult.apt_matches.map(item => item.group_attack_id),
                reportIds: [displayResult.session_id],
                evidenceNodes: [
                  {
                    id: `analysis:${displayResult.session_id}`,
                    type: 'report-analysis',
                    label: 'AI CTI Analysis Result',
                    provider: displayResult.provider,
                    model: displayResult.model,
                    source: 'report',
                    source_ref: `report:${displayResult.session_id.slice(0, 8)}`,
                    summary: displayResult.summary,
                    techniques: displayResult.techniques,
                    actor_matches: displayResult.apt_matches,
                  },
                  ...displayResult.techniques.slice(0, 120).map(item => ({
                    id: `ttp-evidence:${displayResult.session_id}:${item.attack_id}`,
                    type: 'ttp-evidence',
                    attack_id: item.attack_id,
                    label: `${item.attack_id} ${item.name}`,
                    source: 'report',
                    source_ref: `report:${displayResult.session_id.slice(0, 8)}`,
                    analysis_id: displayResult.session_id,
                    tactic: item.tactic,
                    confidence: item.confidence,
                    evidence: item.evidence,
                    status: item.review_status,
                    evidence_source: item.evidence_source,
                  })),
                ],
                timelineEvent: `Added AI report analysis ${displayResult.session_id.slice(0, 8)}`,
              }}
              disabled={!canInject && !displayResult.summary}
              className="text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white px-3 py-1.5 rounded"
            />
            {canExport && <a
              href={exportApi.analysisUrl(displayResult.session_id)}
              download={`analysis-${displayResult.session_id.slice(0, 8)}.pdf`}
              className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
            >
              ↓ PDF report
            </a>}
            {canExport && <a
              href={exportApi.analysisStixUrl(displayResult.session_id)}
              download={`analysis-${displayResult.session_id.slice(0, 8)}-opencti.stix.json`}
              className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
              title="Download a STIX 2.1 bundle for OpenCTI import"
            >
              ↓ STIX/OpenCTI
            </a>}
            {canReview && (
              <a
                href={`/analyze/${displayResult.session_id}/report`}
                className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
              >
                ↗ Linked report
              </a>
            )}
            <button
              type="button"
              onClick={injectAsMyTtps}
              disabled={!canInject}
              className="text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-white px-3 py-1.5 rounded transition-colors"
            >
              + My TTPs
            </button>
            <button
              type="button"
              onClick={injectAndNavigate}
              disabled={!canInject}
              className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-3 py-1.5 rounded transition-colors"
            >
              → Navigator
            </button>
            <button
              type="button"
              onClick={compareOnMatrix}
              disabled={!canInject}
              className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-3 py-1.5 rounded transition-colors"
            >
              ⇄ Matrix compare
            </button>
          </div>
        </div>
        <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_520px]">
          <section className="rounded-lg border border-gray-800 bg-gray-950/50 p-4">
            <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Executive summary</div>
            <p className="mt-2 text-sm leading-7 text-gray-200">
              {displayResult.summary || 'No summary was returned by the selected model.'}
            </p>
          </section>
          <section className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <ResultMetric label="Techniques" value={displayResult.techniques.length} detail={`${sourceBoundCount} source-bound`} />
            <ResultMetric label="Avg confidence" value={`${Math.round(averageConfidence * 100)}%`} detail={confidenceLabel(averageConfidence)} />
            <ResultMetric label="Actor leads" value={displayResult.apt_matches.length} detail={topActorLead ? topActorLead.group_name : 'none'} />
            <ResultMetric label="Review queue" value={needsEvidenceCount} detail={`${acceptedCount} accepted, ${rejectedCount} rejected`} />
          </section>
        </div>
        {displayResult.apt_hints.length > 0 && (
          <div className="flex gap-1.5 flex-wrap mt-2">
            <span className="text-xs text-gray-500">Mentioned:</span>
            {displayResult.apt_hints.map(h => (
              <span key={h} className="text-xs bg-yellow-900/30 text-yellow-400 border border-yellow-800 px-2 py-0.5 rounded-full">{h}</span>
            ))}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-4 px-6 py-2 border-b border-gray-800 text-xs">
        <TabBtn active={tab === 'techniques'} onClick={() => setTab('techniques')}>
          Techniques ({displayResult.techniques.length})
        </TabBtn>
        <TabBtn active={tab === 'groups'} onClick={() => setTab('groups')}>
          Group Similarity Leads ({displayResult.apt_matches.length})
        </TabBtn>
        <TabBtn active={tab === 'raw'} onClick={() => setTab('raw')}>
          Raw response
        </TabBtn>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-4">
        {tab === 'techniques' && (
          <div className="space-y-4">
            {displayResult.techniques.length === 0 && <p className="text-gray-500 text-sm">No techniques extracted.</p>}
            {groupedTechniques.map(group => (
              <section key={group.tactic} className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/50">
                <div className="flex items-center justify-between border-b border-gray-800 bg-gray-950/60 px-4 py-3">
                  <div>
                    <h3 className="text-sm font-semibold text-white">{group.tactic || 'Unmapped tactic'}</h3>
                    <p className="text-[10px] text-gray-500">{group.items.length} technique{group.items.length === 1 ? '' : 's'} extracted</p>
                  </div>
                  <div className="h-2 w-28 overflow-hidden rounded-full bg-gray-800">
                    <div
                      className="h-full rounded-full bg-mitre-accent"
                      style={{ width: `${Math.min(100, Math.max(8, group.items.length * 12))}%` }}
                    />
                  </div>
                </div>
                <div className="divide-y divide-gray-800">
                  {group.items.map(t => (
                    <article key={t.attack_id} className="grid gap-3 p-4 lg:grid-cols-[112px_minmax(0,1fr)_180px]">
                      <div>
                        <a href={`/navigator?technique=${t.attack_id}`} className="font-mono text-sm font-semibold text-mitre-accent hover:underline">
                          {t.attack_id}
                        </a>
                        <div className="mt-2">
                          <ConfidenceBadge value={t.confidence} />
                        </div>
                      </div>
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <h4 className="text-sm font-semibold text-white">{t.name || 'Technique'}</h4>
                          {t.evidence_source === 'source-text' && (
                            <span className="rounded border border-green-800 bg-green-950/40 px-1.5 py-0.5 text-[10px] text-green-300">
                              source-bound
                            </span>
                          )}
                        </div>
                        {t.evidence ? (
                          <blockquote className="mt-2 rounded border-l-2 border-mitre-accent bg-gray-950/70 px-3 py-2 text-xs leading-6 text-gray-300">
                            {t.evidence}
                          </blockquote>
                        ) : (
                          <p className="mt-2 text-xs text-amber-300">No evidence excerpt was returned. Mark as needs-evidence before relying on it.</p>
                        )}
                        {typeof t.evidence_start === 'number' && typeof t.evidence_end === 'number' && (
                          <p className="mt-2 text-[10px] text-gray-600">
                            Evidence span: chars {t.evidence_start}-{t.evidence_end}
                          </p>
                        )}
                      </div>
                      <div className="flex flex-col items-start gap-2 lg:items-end">
                        <ReviewStatusSelect
                          value={t.review_status ?? 'suggested'}
                          disabled={!canReview || reviewMutation.isPending}
                          onChange={reviewStatus =>
                            reviewMutation.mutate({
                              attackId: t.attack_id,
                              reviewStatus,
                              evidence: t.evidence,
                            })
                          }
                        />
                        <button
                          type="button"
                          onClick={() => {
                            addComparisonLayer({
                              name: `${t.attack_id} from AI analysis`,
                              techniqueIds: [t.attack_id],
                              source: 'ai-analysis-technique',
                            });
                            navigate('/navigator');
                          }}
                          className="secondary-action text-[10px]"
                        >
                          Show on matrix
                        </button>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>
        )}

        {tab === 'groups' && (
          <div className="space-y-3">
            {displayResult.apt_matches.length === 0 && <p className="text-gray-500 text-sm">No group-similarity leads.</p>}
            {displayResult.apt_matches.map((m, i) => (
              <article key={m.group_attack_id} className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <div className="flex flex-wrap items-center gap-3">
                  <span className="rounded bg-gray-950 px-2 py-1 text-xs text-gray-500">#{i + 1}</span>
                  <div className="min-w-[120px] flex-1">
                    <div className="mb-1 flex items-center justify-between gap-2">
                      <a href={`/apt?group=${m.group_attack_id}`} className="text-sm font-semibold text-white hover:text-mitre-accent">{m.group_name}</a>
                      <span className="font-mono text-xs text-mitre-accent">{Math.round(m.similarity * 100)}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-gray-800">
                      <div className="h-2 rounded-full bg-mitre-accent" style={{ width: `${m.similarity * 100}%` }} />
                    </div>
                  </div>
                  <span className="text-xs font-mono text-gray-500">{m.group_attack_id}</span>
                  <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{m.shared_count} shared TTPs</span>
                </div>
                {m.shared_techniques.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {m.shared_techniques.map(id => (
                      <span key={id} className="text-[10px] font-mono bg-mitre-accent/10 text-mitre-accent px-1.5 py-0.5 rounded">
                        {id}
                      </span>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        )}

        {tab === 'raw' && (
          <div className="space-y-4">
            <Panel title="Readable model response">
              <FormattedText text={displayResult.raw_response || displayResult.summary || 'No raw response stored.'} />
            </Panel>
            <Panel title="Full structured JSON">
              <pre className="max-h-[560px] overflow-auto bg-gray-950 p-4 text-[10px] font-mono text-gray-400 whitespace-pre-wrap">
                {JSON.stringify(displayResult, null, 2)}
              </pre>
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}

// Parses stream tokens into a result when no explicit result event arrived
function StreamResultParser({
  tokens, domain, addTechniques, addComparisonLayer, navigate,
}: {
  tokens: string;
  domain: string;
  addTechniques: (ids: string[]) => void;
  addComparisonLayer: (layer: { name: string; techniqueIds: string[]; source?: string; color?: string }) => void;
  navigate: ReturnType<typeof useNavigate>;
}) {
  try {
    let cleaned = tokens.trim().replace(/^```(?:json)?\s*/m, '').replace(/\s*```$/m, '');
    const data = JSON.parse(cleaned);
    const result: AnalysisResult = {
      session_id: 'stream',
      provider: 'stream',
      model: '',
      summary: data.summary || '',
      techniques: (data.techniques || []).map((t: Record<string, unknown>) => ({
        attack_id: String(t.attack_id || '').toUpperCase(),
        name: String(t.name || ''),
        tactic: String(t.tactic || ''),
        confidence: Number(t.confidence || 0.5),
        evidence: String(t.evidence || ''),
        review_status: (t.review_status as AnalysisResult['techniques'][number]['review_status']) || 'suggested',
        evidence_start: typeof t.evidence_start === 'number' ? t.evidence_start : null,
        evidence_end: typeof t.evidence_end === 'number' ? t.evidence_end : null,
        evidence_source: String(t.evidence_source || 'llm'),
      })),
      apt_matches: [],
      apt_hints: data.apt_hints || [],
    };
    return (
      <ResultsView
        result={result}
        domain={domain}
        addTechniques={addTechniques}
        addComparisonLayer={addComparisonLayer}
        navigate={navigate}
      />
    );
  } catch {
    // Couldn't parse yet — show raw
    return (
      <div className="flex-1 overflow-y-auto p-6">
        <pre className="text-[10px] font-mono text-gray-400 whitespace-pre-wrap">{tokens}</pre>
      </div>
    );
  }
}

function ReviewStatusSelect({
  value,
  disabled,
  onChange,
}: {
  value: NonNullable<AnalysisResult['techniques'][number]['review_status']>;
  disabled: boolean;
  onChange: (value: NonNullable<AnalysisResult['techniques'][number]['review_status']>) => void;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={event => onChange(event.target.value as NonNullable<AnalysisResult['techniques'][number]['review_status']>)}
      className={`text-[10px] px-1.5 py-0.5 rounded border outline-none ${reviewStatusClass(value)} ${
        disabled ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'
      }`}
      title="Analyst review status"
    >
      <option value="suggested" className={reviewStatusOptionClass('suggested')}>suggested</option>
      <option value="accepted" className={reviewStatusOptionClass('accepted')}>accepted</option>
      <option value="rejected" className={reviewStatusOptionClass('rejected')}>rejected</option>
      <option value="needs-evidence" className={reviewStatusOptionClass('needs-evidence')}>needs-evidence</option>
    </select>
  );
}

function reviewStatusClass(status: AnalysisResult['techniques'][number]['review_status']) {
  switch (status) {
    case 'accepted':
      return 'border-emerald-500 bg-emerald-500/20 text-emerald-100';
    case 'rejected':
      return 'border-red-500 bg-red-500/20 text-red-100';
    case 'needs-evidence':
      return 'border-amber-400 bg-amber-400/20 text-amber-100';
    default:
      return 'border-sky-500 bg-sky-500/20 text-sky-100';
  }
}

function reviewStatusOptionClass(status: NonNullable<AnalysisResult['techniques'][number]['review_status']>) {
  switch (status) {
    case 'accepted':
      return 'bg-emerald-950 text-emerald-100';
    case 'rejected':
      return 'bg-red-950 text-red-100';
    case 'needs-evidence':
      return 'bg-amber-950 text-amber-100';
    default:
      return 'bg-sky-950 text-sky-100';
  }
}

// ── Sub-components ────────────────────────────────────────────────────────────

type ExpectedBehaviorRow = {
  id: string;
  evidence: string;
  why: string;
  found: boolean;
  refs: string[];
  ttps: string[];
  iocs: string[];
};

const EXPECTED_BEHAVIOR_PATTERNS: Array<{
  id: string;
  evidence: string;
  why: string;
  patterns: RegExp[];
  ttps: string[];
}> = [
  {
    id: 'office-powershell',
    evidence: 'WINWORD.EXE spawning powershell.exe',
    why: 'Office-to-script execution chain',
    patterns: [/winword\.exe[\s\S]{0,160}powershell\.exe/i, /powershell\.exe[\s\S]{0,160}winword\.exe/i],
    ttps: ['T1204.002', 'T1059.001'],
  },
  {
    id: 'powershell-download',
    evidence: 'PowerShell downloading setup.exe',
    why: 'Ingress tool transfer pattern',
    patterns: [/powershell[\s\S]{0,240}(downloadstring|downloadfile|invoke-webrequest|iwr|curl|wget)[\s\S]{0,240}setup\.exe/i, /setup\.exe[\s\S]{0,240}powershell/i],
    ttps: ['T1059.001', 'T1105'],
  },
  {
    id: 'unsigned-programdata',
    evidence: 'setup.exe unsigned in C:\\ProgramData\\Microsoft\\',
    why: 'Masquerading and suspicious staging path',
    patterns: [/c:\\\\?programdata\\\\?microsoft\\\\?[\s\S]{0,120}setup\.exe/i, /setup\.exe[\s\S]{0,120}(unsigned|signature=none|signer=unknown)/i],
    ttps: ['T1036', 'T1105'],
  },
  {
    id: 'host-account-discovery',
    evidence: 'whoami /all, hostname, ipconfig /all',
    why: 'Host and account discovery',
    patterns: [/whoami\s+\/all/i, /\bhostname\b/i, /ipconfig\s+\/all/i],
    ttps: ['T1033', 'T1082'],
  },
  {
    id: 'domain-discovery',
    evidence: 'net view /domain, nltest /dclist',
    why: 'Domain and network discovery',
    patterns: [/net\s+view\s+\/domain/i, /nltest\s+\/dclist/i],
    ttps: ['T1482', 'T1018'],
  },
  {
    id: 'process-discovery',
    evidence: 'tasklist /v',
    why: 'Process discovery',
    patterns: [/tasklist\s+\/v/i],
    ttps: ['T1057'],
  },
  {
    id: 'rundll32-proxy',
    evidence: 'rundll32.exe ... msupdate.dat,StartW',
    why: 'DLL/proxy execution through signed Windows binary',
    patterns: [/rundll32\.exe[\s\S]{0,240}msupdate\.dat[\s\S]{0,80}startw/i],
    ttps: ['T1218.011', 'T1574.002'],
  },
  {
    id: 'wmic-remote-exec',
    evidence: 'wmic /node ... process call create',
    why: 'Remote execution / lateral movement lead',
    patterns: [/wmic[\s\S]{0,120}\/node[\s\S]{0,160}process\s+call\s+create/i],
    ttps: ['T1047', 'T1021.006'],
  },
  {
    id: 'certutil-download',
    evidence: 'certutil -urlcache -split -f',
    why: 'File retrieval using a signed Windows utility',
    patterns: [/certutil[\s\S]{0,120}-urlcache[\s\S]{0,80}-split[\s\S]{0,80}-f/i],
    ttps: ['T1105', 'T1140'],
  },
  {
    id: 'run-key-persistence',
    evidence: 'Run key persistence',
    why: 'User-level persistence',
    patterns: [/\\currentversion\\run/i, /\breg(\.exe)?\s+add[\s\S]{0,160}\\run/i, /hkc[ul][\s\S]{0,80}\\run/i],
    ttps: ['T1547.001'],
  },
];

function ExpectedSuspiciousBehaviorsPanel({
  rows,
  onOpenTtp,
  onOpenIoc,
}: {
  rows: ExpectedBehaviorRow[];
  onOpenTtp: (id: string) => void;
  onOpenIoc: (value: string) => void;
}) {
  const foundCount = rows.filter(row => row.found).length;
  return (
    <Panel title={`Expected suspicious behaviors (${foundCount}/${rows.length})`}>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-gray-950/70 text-[10px] uppercase tracking-wide text-gray-500">
            <tr>
              <th className="border-b border-gray-800 px-3 py-2">Evidence</th>
              <th className="border-b border-gray-800 px-3 py-2">Why it matters</th>
              <th className="border-b border-gray-800 px-3 py-2">TTP / IOC tags</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(row => (
              <tr key={row.id} className={row.found ? 'bg-red-950/10' : 'opacity-55'}>
                <td className="border-b border-gray-800 px-3 py-2 align-top">
                  <div className="flex items-start gap-2">
                    <span className={`mt-0.5 rounded px-1.5 py-0.5 text-[10px] font-semibold ${row.found ? 'bg-red-950 text-red-300' : 'bg-gray-800 text-gray-500'}`}>
                      {row.found ? 'FOUND' : 'NOT SEEN'}
                    </span>
                    <div>
                      <p className="font-medium text-gray-100">{row.evidence}</p>
                      {row.refs.length > 0 && (
                        <p className="mt-1 line-clamp-2 font-mono text-[10px] text-gray-500">{row.refs[0]}</p>
                      )}
                    </div>
                  </div>
                </td>
                <td className="border-b border-gray-800 px-3 py-2 align-top text-gray-300">{row.why}</td>
                <td className="border-b border-gray-800 px-3 py-2 align-top">
                  <div className="flex max-w-lg flex-wrap gap-1.5">
                    {row.ttps.map(id => (
                      <button
                        key={id}
                        type="button"
                        onClick={() => onOpenTtp(id)}
                        className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 font-mono text-[10px] text-mitre-accent hover:bg-mitre-accent hover:text-white"
                      >
                        {id}
                      </button>
                    ))}
                    {row.iocs.map(value => (
                      <button
                        key={value}
                        type="button"
                        onClick={() => onOpenIoc(value)}
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
    </Panel>
  );
}

function buildExpectedSuspiciousBehaviors(result: LogPcapAnalysisResult): ExpectedBehaviorRow[] {
  const searchable = [
    result.summary,
    result.report,
    ...result.suspicious_findings.flatMap(item => [item.category, item.reason, item.evidence]),
    ...result.techniques.flatMap(item => [item.attack_id, item.name, item.evidence]),
    ...result.observables.flatMap(item => [item.value, item.description]),
  ].join('\n');
  const observableValues = result.observables.map(item => item.value).filter(Boolean);
  return EXPECTED_BEHAVIOR_PATTERNS.map(pattern => {
    const refs = pattern.patterns
      .map(regex => searchable.match(regex)?.[0] ?? '')
      .filter(Boolean)
      .slice(0, 3);
    const found = refs.length > 0 || pattern.ttps.some(id => result.techniques.some(technique => technique.attack_id === id));
    return {
      id: pattern.id,
      evidence: pattern.evidence,
      why: pattern.why,
      found,
      refs,
      ttps: pattern.ttps,
      iocs: found ? extractRelatedIocs(searchable, observableValues, pattern.patterns) : [],
    };
  });
}

function extractRelatedIocs(searchable: string, observables: string[], patterns: RegExp[]) {
  const matches = new Set<string>();
  const windows = patterns.map(regex => searchable.match(regex)?.[0] ?? '').filter(Boolean);
  const candidates = observables.filter(value => value.length > 2);
  windows.forEach(windowText => {
    candidates.forEach(value => {
      if (windowText.includes(value)) matches.add(value);
    });
  });
  if (!matches.size && windows.length) {
    candidates.slice(0, 4).forEach(value => matches.add(value));
  }
  return Array.from(matches).slice(0, 8);
}

function loadLogPcapHistory(): LogPcapHistoryItem[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.localStorage.getItem(LOG_PCAP_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(isLogPcapHistoryItem)
      .slice(0, LOG_PCAP_HISTORY_LIMIT);
  } catch {
    return [];
  }
}

function saveLogPcapHistory(items: LogPcapHistoryItem[]) {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(LOG_PCAP_HISTORY_KEY, JSON.stringify(items.slice(0, LOG_PCAP_HISTORY_LIMIT)));
  } catch {
    // Local history is a convenience feature; analysis results should still render if storage is unavailable.
  }
}

function createLogPcapHistoryItem(result: LogPcapAnalysisResult): LogPcapHistoryItem {
  const createdAt = new Date().toISOString();
  const id = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return {
    ...result,
    history_id: id,
    created_at: createdAt,
    name: result.filename || `Log / PCAP ${new Date(createdAt).toLocaleString()}`,
    technique_count: result.techniques.length,
    observable_count: result.observables.length,
    suspicious_count: result.suspicious_findings.length,
  };
}

function getLogPcapAnalysisId(result: LogPcapAnalysisResult) {
  const historyId = (result as Partial<LogPcapHistoryItem>).history_id;
  if (historyId) return historyId;
  return `adhoc-${simpleHash([
    result.filename ?? '',
    result.provider,
    result.model,
    result.summary,
    result.report,
  ].join('|'))}`;
}

function simpleHash(value: string) {
  let hash = 5381;
  for (let index = 0; index < value.length; index += 1) {
    hash = ((hash << 5) + hash) ^ value.charCodeAt(index);
  }
  return (hash >>> 0).toString(16);
}

function isLogPcapHistoryItem(value: unknown): value is LogPcapHistoryItem {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<LogPcapHistoryItem>;
  return (
    typeof candidate.history_id === 'string' &&
    typeof candidate.created_at === 'string' &&
    typeof candidate.name === 'string' &&
    Array.isArray(candidate.techniques) &&
    Array.isArray(candidate.observables) &&
    Array.isArray(candidate.suspicious_findings) &&
    Array.isArray(candidate.apt_matches)
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/50">
      <h2 className="border-b border-gray-800 px-3 py-2 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`pb-1.5 border-b-2 transition-colors ${
        active ? 'border-mitre-accent text-white' : 'border-transparent text-gray-500 hover:text-gray-300'
      }`}
    >
      {children}
    </button>
  );
}

function ConfidenceBadge({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const cls = pct >= 80 ? 'bg-green-900/50 text-green-400' : pct >= 50 ? 'bg-yellow-900/50 text-yellow-400' : 'bg-gray-700 text-gray-400';
  return <span className={`text-[10px] px-1.5 py-0.5 rounded ${cls}`}>{pct}%</span>;
}

function ResultMetric({ label, value, detail }: { label: string; value: React.ReactNode; detail: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-2 truncate text-2xl font-semibold text-white">{value}</div>
      <div className="mt-1 truncate text-[10px] text-gray-500" title={detail}>{detail}</div>
    </div>
  );
}

function groupTechniquesByTactic(techniques: AnalysisResult['techniques']) {
  const groups = new Map<string, AnalysisResult['techniques']>();
  techniques.forEach(technique => {
    const tactic = technique.tactic || 'Unmapped tactic';
    groups.set(tactic, [...(groups.get(tactic) ?? []), technique]);
  });
  return Array.from(groups.entries())
    .map(([tactic, items]) => ({
      tactic,
      items: [...items].sort((a, b) => a.attack_id.localeCompare(b.attack_id)),
    }))
    .sort((a, b) => a.tactic.localeCompare(b.tactic));
}

function confidenceLabel(value: number) {
  if (value >= 0.8) return 'strong model confidence';
  if (value >= 0.5) return 'moderate model confidence';
  if (value > 0) return 'low model confidence';
  return 'no mapped confidence';
}

function FormattedText({ text }: { text: string }) {
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!lines.length) return <p className="p-4 text-xs text-gray-500">No readable text available.</p>;

  return (
    <div className="space-y-2 p-4 text-sm leading-7 text-gray-300">
      {lines.map((line, index) => {
        const heading = line.match(/^#{1,6}\s+(.+)$/);
        if (heading) {
          return <h3 key={`${line}-${index}`} className="pt-2 text-base font-semibold text-white">{heading[1]}</h3>;
        }
        if (/^[-*]\s+/.test(line)) {
          return (
            <div key={`${line}-${index}`} className="flex gap-2">
              <span className="mt-3 h-1.5 w-1.5 shrink-0 rounded-full bg-mitre-accent" />
              <span>{line.replace(/^[-*]\s+/, '')}</span>
            </div>
          );
        }
        if (/^\d+[.)]\s+/.test(line)) {
          return (
            <div key={`${line}-${index}`} className="flex gap-2">
              <span className="font-mono text-xs text-mitre-accent">{line.match(/^\d+/)?.[0]}.</span>
              <span>{line.replace(/^\d+[.)]\s+/, '')}</span>
            </div>
          );
        }
        return <p key={`${line}-${index}`}>{line}</p>;
      })}
    </div>
  );
}
