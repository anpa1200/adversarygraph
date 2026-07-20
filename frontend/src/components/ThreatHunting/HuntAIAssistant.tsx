import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useInfiniteQuery, useMutation, useQuery } from '@tanstack/react-query';

import {
  analyzeApi,
  threatHuntingApi,
  type ReportCollectionItem,
  type ThreatHuntAIAssistResponse,
  type ThreatHuntAICitation,
  type ThreatHuntAIHypothesisCandidate,
  type ThreatHuntAIHypothesisResponse,
  type ThreatHuntAIProviderId,
  type ThreatHuntAIStage,
  type ThreatHuntFindingInput,
  type ThreatHuntInput,
  type ThreatHuntQueryLanguage,
} from '@/api/client';
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from '@/components/ui/dialog';
import { queryLanguageLabel, THREAT_HUNT_QUERY_LANGUAGE_OPTIONS } from './queryLanguages';

export type HuntAIAssistantMode = ThreatHuntAIStage | 'hypothesis';

const REPORT_PAGE_SIZE = 50;

const MODE_LABELS: Record<HuntAIAssistantMode, string> = {
  hypothesis: 'Report-to-hypothesis',
  plan: 'Plan and scope',
  query: 'Query and telemetry',
  findings: 'Findings review',
  outcome: 'Outcome and handoff',
};

export function HuntAIAssistant({
  open,
  mode,
  huntId,
  context,
  readOnly,
  initialSourceSessionId,
  initialSourceType,
  onOpenChange,
  onApplyPatch,
  onUseFindingDraft,
}: {
  open: boolean;
  mode: HuntAIAssistantMode;
  huntId?: string;
  context: ThreatHuntInput;
  readOnly: boolean;
  initialSourceSessionId?: string;
  initialSourceType?: string;
  onOpenChange: (open: boolean) => void;
  onApplyPatch: (patch: Partial<ThreatHuntInput>, stage: HuntAIAssistantMode) => void;
  onUseFindingDraft: (draft: Partial<ThreatHuntFindingInput>) => void;
}) {
  const [providerId, setProviderId] = useState<ThreatHuntAIProviderId>('local');
  const [analystFocus, setAnalystFocus] = useState('');
  const [targetQueryLanguage, setTargetQueryLanguage] = useState<ThreatHuntQueryLanguage>(context.query_language);
  const [cloudAcknowledged, setCloudAcknowledged] = useState(false);
  const [sourceSessionId, setSourceSessionId] = useState(initialSourceSessionId ?? '');
  const [sourceType, setSourceType] = useState<'report' | 'research'>(initialSourceType === 'research' ? 'research' : 'report');
  const [sourceSearch, setSourceSearch] = useState('');
  const [lastAssist, setLastAssist] = useState<ThreatHuntAIAssistResponse | null>(null);
  const [lastHypotheses, setLastHypotheses] = useState<ThreatHuntAIHypothesisResponse | null>(null);
  const [applyState, setApplyState] = useState('');
  const providerInitialized = useRef(false);
  const appliedContext = useRef('');
  const assistantOpen = useRef(open);

  const providers = useQuery({
    queryKey: ['threat-hunting-ai-providers'],
    queryFn: threatHuntingApi.aiProviders,
    enabled: open,
    staleTime: 0,
    refetchOnMount: 'always',
    retry: 1,
  });
  const reports = useInfiniteQuery({
    queryKey: ['report-research-collection', 'hunt-hypothesis-picker'],
    queryFn: ({ pageParam }) => analyzeApi.reportCollection(REPORT_PAGE_SIZE, pageParam),
    initialPageParam: 0,
    getNextPageParam: lastPage => lastPage.items.length === REPORT_PAGE_SIZE
      ? lastPage.offset + lastPage.items.length
      : undefined,
    enabled: open && mode === 'hypothesis',
    staleTime: 30_000,
    retry: 1,
  });

  const selectedProvider = providers.data?.find(provider => provider.id === providerId);
  const reportItems = useMemo(
    () => reports.data?.pages.flatMap(page => page.items) ?? [],
    [reports.data?.pages],
  );
  const eligibleReports = reportItems.filter(isEligibleHypothesisSource);
  const normalizedSourceSearch = sourceSearch.trim().toLowerCase();
  const visibleEligibleReports = normalizedSourceSearch
    ? eligibleReports.filter(item => `${item.title} ${item.publisher} ${item.summary}`.toLowerCase().includes(normalizedSourceSearch))
    : eligibleReports;
  const selectedReport = reportItems.find(item => item.session_id === sourceSessionId);
  const sourceRevision = selectedReport?.updated_at ?? '';
  const selectedSourceEligible = !selectedReport || isEligibleHypothesisSource(selectedReport);
  // A stored report is the authoritative classification for report-backed AI.
  // Keep linked reports local-only until their collection metadata has loaded;
  // the backend applies the same conservative classification to legacy rows.
  const effectiveRequestTlp = mode === 'hypothesis'
    ? selectedReport?.tlp ?? (sourceSessionId ? 'TLP:AMBER+STRICT' : context.tlp)
    : context.tlp;
  const restrictedTlp = effectiveRequestTlp === 'TLP:AMBER+STRICT' || effectiveRequestTlp === 'TLP:RED';
  const requiresSavedHunt = mode !== 'hypothesis' && mode !== 'plan' && !huntId;
  const remoteBlocked = Boolean(selectedProvider?.remote && restrictedTlp);
  const needsAcknowledgement = Boolean(
    selectedProvider?.available
    && (selectedProvider.remote || selectedProvider.requires_acknowledgement),
  );
  const contextFingerprint = useMemo(() => assistantContextFingerprint(context), [context]);

  useEffect(() => {
    if (initialSourceSessionId) setSourceSessionId(initialSourceSessionId);
  }, [initialSourceSessionId]);

  useEffect(() => {
    assistantOpen.current = open;
  }, [open]);

  useEffect(() => {
    if (initialSourceType === 'report' || initialSourceType === 'research') setSourceType(initialSourceType);
  }, [initialSourceType]);

  useEffect(() => {
    if (open && mode === 'query') setTargetQueryLanguage(context.query_language);
  }, [context.query_language, mode, open]);

  useEffect(() => {
    setCloudAcknowledged(false);
  }, [analystFocus, contextFingerprint, mode, providerId, sourceRevision, sourceSessionId, sourceType, targetQueryLanguage]);

  useEffect(() => {
    setLastAssist(null);
    setLastHypotheses(null);
    if (appliedContext.current) appliedContext.current = '';
    else setApplyState('');
  }, [contextFingerprint]);

  useEffect(() => {
    setLastAssist(null);
    setLastHypotheses(null);
    setApplyState('');
    appliedContext.current = '';
  }, [analystFocus, mode, providerId, sourceRevision, sourceSessionId, sourceType, targetQueryLanguage]);

  useEffect(() => {
    if (!providers.data?.length) return;
    const current = providers.data.find(provider => provider.id === providerId);
    const currentUsable = current?.available && !(current.remote && restrictedTlp);
    if (currentUsable && providerInitialized.current) return;
    const availableDefault = providers.data.find(provider => provider.default && provider.available && !(
      provider.remote && restrictedTlp
    ));
    const local = providers.data.find(provider => provider.id === 'local' && provider.available);
    const first = providers.data.find(provider => provider.available && !(
      provider.remote && restrictedTlp
    ));
    const selected = availableDefault || (currentUsable ? current : null) || local || first;
    providerInitialized.current = true;
    if (selected) setProviderId(selected.id);
  }, [providerId, providers.data, restrictedTlp]);

  const assistMutation = useMutation({
    mutationFn: async () => {
      if (mode === 'hypothesis') throw new Error('Select a hunt stage for this request.');
      const result = await threatHuntingApi.assist({
        provider: providerId,
        model: selectedProvider?.model || undefined,
        stage: mode,
        hunt_id: huntId || undefined,
        context: mode === 'query' ? { ...context, query_language: targetQueryLanguage } : context,
        target_query_language: mode === 'query' ? targetQueryLanguage : undefined,
        analyst_focus: analystFocus.trim() || undefined,
        cloud_processing_acknowledged: needsAcknowledgement ? cloudAcknowledged : false,
      });
      if (result.stage !== mode || result.lifecycle_status !== 'suggested') {
        throw new Error('The assistant returned a response for a different hunt stage. Retry the request.');
      }
      return result;
    },
    onSuccess: result => {
      if (!assistantOpen.current) return;
      setLastAssist(result);
      setApplyState('');
    },
    onSettled: () => setCloudAcknowledged(false),
  });

  const hypothesisMutation = useMutation({
    mutationFn: async () => {
      if (!sourceSessionId) throw new Error('Choose a stored report or research item first.');
      const result = await threatHuntingApi.generateHypotheses({
        provider: providerId,
        model: selectedProvider?.model || undefined,
        source_session_id: sourceSessionId,
        source_type: sourceType,
        source_title: selectedReport?.title,
        source_ref: sourceSessionId,
        tlp: effectiveRequestTlp,
        analyst_focus: analystFocus.trim() || undefined,
        cloud_processing_acknowledged: needsAcknowledgement ? cloudAcknowledged : false,
      });
      if (result.source_session_id !== sourceSessionId || result.lifecycle_status !== 'suggested') {
        throw new Error('The assistant returned a response for a different report. Retry the request.');
      }
      return result;
    },
    onSuccess: result => {
      if (!assistantOpen.current) return;
      setLastHypotheses(result);
      setApplyState('');
    },
    onSettled: () => setCloudAcknowledged(false),
  });

  const pending = assistMutation.isPending || hypothesisMutation.isPending;
  const requestError = errorMessage(assistMutation.error || hypothesisMutation.error || providers.error);
  const selectedAvailable = Boolean(selectedProvider?.available);
  const acknowledged = !needsAcknowledgement || cloudAcknowledged;
  const sourceReady = mode !== 'hypothesis' || (Boolean(sourceSessionId) && selectedSourceEligible);
  const canGenerate = selectedAvailable && !remoteBlocked && acknowledged && sourceReady && !requiresSavedHunt && !pending;
  const assistResult = lastAssist?.stage === mode ? lastAssist : null;
  const hypothesisResult = mode === 'hypothesis' && lastHypotheses?.source_session_id === sourceSessionId
    ? lastHypotheses
    : null;

  const run = () => {
    setApplyState('');
    assistMutation.reset();
    hypothesisMutation.reset();
    if (mode === 'hypothesis') hypothesisMutation.mutate();
    else assistMutation.mutate();
  };

  const handleOpenChange = (nextOpen: boolean) => {
    assistantOpen.current = nextOpen;
    if (!nextOpen) {
      setCloudAcknowledged(false);
      setLastAssist(null);
      setLastHypotheses(null);
      setApplyState('');
      appliedContext.current = '';
      assistMutation.reset();
      hypothesisMutation.reset();
    }
    onOpenChange(nextOpen);
  };

  const applyPatch = (patch: Partial<ThreatHuntInput>, stage: HuntAIAssistantMode) => {
    appliedContext.current = contextFingerprint;
    onApplyPatch(patch, stage);
    setApplyState(stage === 'query' && patch.query_text
      ? `${queryLanguageLabel((patch.query_language || targetQueryLanguage) as ThreatHuntQueryLanguage)} query added to the unsaved hunt draft. Review it in the query editor, then save explicitly.`
      : 'Suggestions added to the unsaved hunt draft. Review them, then save explicitly.');
  };

  const useFindingDraft = (draft: Partial<ThreatHuntFindingInput>) => {
    onUseFindingDraft(draft);
    setApplyState('Suggestion added to an unsaved finding form. Review it before saving.');
    handleOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="w-[min(96vw,1040px)]">
        <div className="flex items-start justify-between gap-4 border-b border-gray-800 pr-4">
          <div>
            <DialogTitle>AI Assistant · {MODE_LABELS[mode]}</DialogTitle>
            <DialogDescription className="pb-3">
              Generates analyst-review suggestions only. It cannot run telemetry queries, change the hunt lifecycle, or save evidence.
            </DialogDescription>
          </div>
          <DialogClose asChild>
            <button type="button" className="mt-3 rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:text-white">
              Close
            </button>
          </DialogClose>
        </div>

        <DialogBody className="max-h-[76vh]">
          <div className="grid gap-5 lg:grid-cols-[330px_minmax(0,1fr)]">
            <div className="space-y-4">
              <section className="rounded border border-cyan-900/70 bg-cyan-950/20 p-3 text-xs leading-5 text-cyan-100/80">
                <b className="block text-cyan-100">Human review is required</b>
                AI output is a lead, not evidence. Verify ATT&amp;CK mappings, citations, syntax, assumptions, and scope before accepting it.
              </section>

              <label className="block text-xs text-gray-500">
                AI provider
                <select
                  aria-label="Threat hunting AI provider"
                  className="field mt-1"
                  value={providerId}
                  disabled={providers.isLoading || pending}
                  onChange={event => setProviderId(event.target.value as ThreatHuntAIProviderId)}
                >
                  {(providers.data ?? []).map(provider => {
                    const blocked = provider.remote && restrictedTlp;
                    const requestStatus = !provider.available
                      ? providerStatusLabel(provider.status)
                      : blocked
                        ? `blocked for ${effectiveRequestTlp}`
                        : providerStatusLabel(provider.status);
                    return (
                      <option key={provider.id} value={provider.id} disabled={!provider.available || blocked}>
                        {provider.label}{provider.model ? ` · ${provider.model}` : ''}
                        {` · ${provider.remote ? 'remote' : 'local/private'} · ${requestStatus}`}
                      </option>
                    );
                  })}
                  {!providers.data?.length && <option value="local">{providers.isLoading ? 'Loading providers…' : 'No provider available'}</option>}
                </select>
              </label>

              <div className="-mt-2 flex items-center justify-between gap-3 text-[11px] text-gray-600">
                <span>Configuration and policy; local endpoint/model readiness</span>
                <button
                  type="button"
                  className="text-cyan-400 hover:text-cyan-200 disabled:opacity-50"
                  disabled={providers.isFetching || pending}
                  onClick={() => void providers.refetch()}
                >
                  {providers.isFetching ? 'Checking…' : 'Recheck'}
                </button>
              </div>

              {selectedProvider && (
                <div
                  role="status"
                  data-testid="threat-hunt-provider-status"
                  className={selectedProvider.available && !remoteBlocked
                    ? 'rounded border border-emerald-900/70 bg-emerald-950/20 px-3 py-2 text-xs leading-5 text-emerald-100'
                    : 'rounded border border-amber-800/60 bg-amber-950/20 px-3 py-2 text-xs leading-5 text-amber-100'}
                >
                  <b className="block">
                    {selectedProvider.label}: {remoteBlocked ? `blocked for ${effectiveRequestTlp}` : providerStatusLabel(selectedProvider.status)}
                    {' · '}{selectedProvider.remote ? 'remote processing' : 'local/private processing'}
                  </b>
                  <span>
                    {remoteBlocked
                      ? `${effectiveRequestTlp} content cannot be sent to a remote AI provider.`
                      : selectedProvider.reason}
                  </span>
                  {selectedProvider.remote && selectedProvider.available && !remoteBlocked && (
                    <span className="mt-1 block text-amber-100">
                      Operator policy permits this provider for {effectiveRequestTlp}. Nothing is sent until you explicitly acknowledge this request below.
                    </span>
                  )}
                </div>
              )}

              {mode === 'hypothesis' && (
                <div className="space-y-2">
                  <label className="block text-xs text-gray-500">
                    Source type
                    <select
                      aria-label="Hypothesis source type"
                      className="field mt-1"
                      value={sourceType}
                      disabled={pending}
                      onChange={event => setSourceType(event.target.value as 'report' | 'research')}
                    >
                      <option value="report">Threat report</option>
                      <option value="research">Research note</option>
                    </select>
                  </label>
                  <label className="block text-xs text-gray-500">
                    Search loaded sources
                    <input
                      aria-label="Search hypothesis sources"
                      className="field mt-1"
                      value={sourceSearch}
                      disabled={reports.isLoading || pending}
                      onChange={event => setSourceSearch(event.target.value)}
                      placeholder="Title, publisher, or summary"
                    />
                  </label>
                  <label className="block text-xs text-gray-500">
                    Stored report or research
                    <select
                      aria-label="Hypothesis source report"
                      className="field mt-1"
                      value={sourceSessionId}
                      disabled={reports.isLoading || pending}
                      onChange={event => setSourceSessionId(event.target.value)}
                    >
                      <option value="">Select a stored source</option>
                      {selectedReport && !selectedSourceEligible && (
                        <option value={selectedReport.session_id} disabled>Not eligible · {selectedReport.title}</option>
                      )}
                      {initialSourceSessionId && !reportItems.some(item => item.session_id === initialSourceSessionId) && (
                        <option value={initialSourceSessionId}>Linked report · {initialSourceSessionId.slice(0, 12)}</option>
                      )}
                      {selectedReport && selectedSourceEligible && !visibleEligibleReports.some(item => item.session_id === selectedReport.session_id) && (
                        <option value={selectedReport.session_id}>{selectedReport.title}</option>
                      )}
                      {visibleEligibleReports.map(item => (
                        <option key={item.session_id} value={item.session_id}>{item.title}</option>
                      ))}
                    </select>
                  </label>
                  {selectedReport && (
                    <p
                      aria-label="Selected report TLP"
                      className="rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-[11px] leading-4 text-gray-400"
                    >
                      Stored report TLP: <b className="text-gray-200">{selectedReport.tlp}</b>. This authoritative marking controls which AI providers can process the source.
                    </p>
                  )}
                  {sourceSessionId && !selectedReport && (
                    <p role="status" className="rounded border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-[11px] leading-4 text-amber-200">
                      Stored report TLP has not loaded. Remote AI remains unavailable until the source metadata is available.
                    </p>
                  )}
                  <div className="flex items-center justify-between gap-3 text-[11px] leading-4 text-gray-600">
                    <span>{reportItems.length} source{reportItems.length === 1 ? '' : 's'} loaded; search covers loaded sources.</span>
                    {reports.hasNextPage && (
                      <button
                        type="button"
                        className="secondary-action shrink-0 px-2 py-1"
                        disabled={reports.isFetchingNextPage || pending}
                        onClick={() => void reports.fetchNextPage()}
                      >
                        {reports.isFetchingNextPage ? 'Loading…' : 'Load older sources'}
                      </button>
                    )}
                  </div>
                  <p className="text-[11px] leading-4 text-gray-600">
                    Eligible sources are completed Enterprise ATT&amp;CK reports with stored source text. Upload and review new material in Reports / Research first.
                  </p>
                  {selectedReport && !selectedSourceEligible && (
                    <p role="alert" className="text-xs text-amber-300">This source is not eligible for hypothesis generation. Complete its analysis and ensure Enterprise ATT&amp;CK source text is stored.</p>
                  )}
                  <Link to="/reports-research" className="inline-flex text-xs text-cyan-300 hover:text-cyan-100">Open Reports / Research →</Link>
                  {reports.isError && <p role="alert" className="text-xs text-red-300">{errorMessage(reports.error)}</p>}
                </div>
              )}

              {mode === 'query' && (
                <label className="block text-xs text-gray-500">
                  Target query language
                  <select
                    aria-label="AI target query language"
                    className="field mt-1"
                    value={targetQueryLanguage}
                    disabled={pending}
                    onChange={event => setTargetQueryLanguage(event.target.value as ThreatHuntQueryLanguage)}
                  >
                    {THREAT_HUNT_QUERY_LANGUAGE_OPTIONS.map(option => (
                      <option key={option.value} value={option.value}>{option.label}</option>
                    ))}
                  </select>
                  <span className="mt-1 block text-[10px] leading-4 text-gray-600">
                    The assistant must generate one query in this language from the hunt hypothesis, scope, ATT&amp;CK techniques, and telemetry requirements.
                  </span>
                </label>
              )}

              <label className="block text-xs text-gray-500">
                Analyst focus <span className="text-gray-700">(optional)</span>
                <textarea
                  aria-label="Analyst focus"
                  className="field mt-1 min-h-28 resize-y"
                  value={analystFocus}
                  maxLength={2000}
                  disabled={pending}
                  onChange={event => setAnalystFocus(event.target.value)}
                  placeholder={focusPlaceholder(mode)}
                />
                <span className="mt-1 block text-right text-[10px] text-gray-700">{analystFocus.length}/2000</span>
              </label>

              {needsAcknowledgement && !remoteBlocked && (
                <label className="flex items-start gap-2 rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={cloudAcknowledged}
                    disabled={pending}
                    onChange={event => setCloudAcknowledged(event.target.checked)}
                  />
                  <span>
                    I explicitly authorize sending {mode === 'hypothesis' ? 'the selected report context' : !huntId && mode === 'plan' ? 'this unsaved plan draft and analyst focus' : 'this stage-scoped hunt context'} to <b>{selectedProvider?.label}</b> for this request. The content is marked {effectiveRequestTlp} and will be processed under my organization’s data-handling policy. This authorization resets after the request or any provider or scope change.
                  </span>
                </label>
              )}

              {restrictedTlp && (
                <p role="status" className="rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
                  {mode === 'hypothesis'
                    ? `Selected report is ${effectiveRequestTlp} and is local-only. Remote providers are unavailable for this request.`
                    : `${effectiveRequestTlp} hunt context is local-only. Remote providers are unavailable for this request.`}
                </p>
              )}
              {requiresSavedHunt && (
                <p role="status" className="rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
                  Create the hunt draft before requesting {MODE_LABELS[mode].toLowerCase()} assistance. Saved hunts use canonical server context and TLP controls.
                </p>
              )}

              <button
                type="button"
                className="primary-action w-full disabled:cursor-not-allowed disabled:opacity-40"
                disabled={!canGenerate}
                onClick={run}
              >
                {pending
                  ? mode === 'query' ? `Generating ${queryLanguageLabel(targetQueryLanguage)} query…` : 'Generating suggestions…'
                  : mode === 'hypothesis' ? 'Generate hunt hypotheses'
                    : mode === 'query' ? `Generate ${queryLanguageLabel(targetQueryLanguage)} query`
                      : `Assist with ${MODE_LABELS[mode].toLowerCase()}`}
              </button>
              {pending && <p role="status" aria-live="polite" className="text-center text-xs text-cyan-200">AI generation is in progress. Your current hunt draft remains unchanged.</p>}
              {requestError && <p role="alert" className="rounded border border-red-800 bg-red-950/30 p-3 text-xs leading-5 text-red-200">{requestError}</p>}
              {providers.data && !providers.data.some(provider => provider.available && !(provider.remote && restrictedTlp)) && (
                <p role="alert" className="rounded border border-red-800 bg-red-950/30 p-3 text-xs text-red-200">
                  No AI provider is available for this request under the current TLP, operator policy, and runtime state. Recheck provider status or ask an operator to review the AI configuration.
                </p>
              )}
            </div>

            <div className="min-w-0 space-y-4">
              {!assistResult && !hypothesisResult && !pending && (
                <div className="rounded border border-dashed border-gray-800 p-10 text-center text-sm leading-6 text-gray-600">
                  Configure the request, generate suggestions, then review every proposed field before applying it to the unsaved draft.
                </div>
              )}
              {hypothesisResult && (
                <HypothesisResult
                  result={hypothesisResult}
                  readOnly={readOnly}
                  onApply={candidate => applyPatch(withHypothesisProvenance(candidate, hypothesisResult), 'hypothesis')}
                />
              )}
              {assistResult && (
                <AssistResult
                  result={assistResult}
                  readOnly={readOnly}
                  hasExistingQuery={Boolean(context.query_text.trim())}
                  onApplyPatch={patch => applyPatch(patch, assistResult.stage)}
                  onUseFindingDraft={useFindingDraft}
                />
              )}
              {applyState && <p role="status" aria-live="polite" className="rounded border border-emerald-800 bg-emerald-950/20 p-3 text-xs text-emerald-100">{applyState}</p>}
              {readOnly && (assistResult || hypothesisResult) && (
                <p role="status" className="rounded border border-gray-700 bg-gray-900 p-3 text-xs text-gray-400">
                  This hunt is read-only. Suggestions remain available for review, but cannot be applied.
                </p>
              )}
            </div>
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  );
}

function providerStatusLabel(status: string) {
  return ({
    ready: 'ready',
    configured_and_permitted: 'configured and permitted',
    disabled_by_policy: 'disabled by policy',
    missing_credential: 'not configured',
    missing_configuration: 'not configured',
    invalid_endpoint: 'invalid endpoint',
    runtime_check_required: 'readiness check required',
    unreachable: 'endpoint unreachable',
    model_missing: 'model not installed',
    auth_error: 'authentication failed',
    endpoint_error: 'endpoint error',
    invalid_response: 'invalid endpoint response',
  } as Record<string, string>)[status] ?? 'unavailable';
}

function HypothesisResult({
  result,
  readOnly,
  onApply,
}: {
  result: ThreatHuntAIHypothesisResponse;
  readOnly: boolean;
  onApply: (candidate: ThreatHuntAIHypothesisCandidate) => void;
}) {
  return (
    <section className="space-y-3" aria-label="Generated hunt hypotheses">
      <ResultMeta
        assistanceId={result.assistance_id}
        provider={result.provider}
        model={result.model}
        generatedAt={result.generated_at}
        promptVersion={result.prompt_version}
        warnings={result.warnings}
        executionBoundary={result.execution_boundary}
      />
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3 text-xs text-gray-400">
        Source: <b className="text-gray-200">{result.source_title || result.source_session_id}</b>
        <span className="ml-2 font-mono text-[10px] text-gray-600">{result.source_session_id}</span>
      </div>
      {result.candidates.map((candidate, index) => (
        <article key={`${candidate.title}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">Candidate {index + 1}</p>
              <h3 className="mt-1 text-sm font-semibold text-white">{candidate.title}</h3>
            </div>
            <button type="button" className="secondary-action" disabled={readOnly} onClick={() => onApply(candidate)}>
              Apply safe fields
            </button>
          </div>
          <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-200">{candidate.hypothesis}</p>
          {candidate.rationale && <p className="mt-3 whitespace-pre-wrap text-xs leading-5 text-gray-500">{candidate.rationale}</p>}
          <PatchPreview patch={candidate} />
          <Citations citations={candidate.source_evidence} />
        </article>
      ))}
    </section>
  );
}

function AssistResult({
  result,
  readOnly,
  hasExistingQuery,
  onApplyPatch,
  onUseFindingDraft,
}: {
  result: ThreatHuntAIAssistResponse;
  readOnly: boolean;
  hasExistingQuery: boolean;
  onApplyPatch: (patch: Partial<ThreatHuntInput>) => void;
  onUseFindingDraft: (draft: Partial<ThreatHuntFindingInput>) => void;
}) {
  const hasPatch = meaningfulPatchEntries(result.suggested_patch).length > 0;
  const hasQueryDraft = result.stage === 'query' && Boolean(result.suggested_patch.query_text?.trim());
  const queryLanguage = result.suggested_patch.query_language || 'generic';
  const applyLabel = hasQueryDraft
    ? hasExistingQuery
      ? `Replace query with ${queryLanguageLabel(queryLanguage)} draft`
      : `Use ${queryLanguageLabel(queryLanguage)} query draft`
    : 'Apply safe suggestions';
  return (
    <section className="space-y-4" aria-label={`${MODE_LABELS[result.stage]} AI suggestions`}>
      <ResultMeta
        assistanceId={result.assistance_id}
        provider={result.provider}
        model={result.model}
        generatedAt={result.generated_at}
        promptVersion={result.prompt_version}
        warnings={result.warnings}
        executionBoundary={result.execution_boundary}
      />
      <div className="rounded border border-gray-800 bg-gray-950/60 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">Suggested · human review required</p>
            <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-200">{result.summary}</p>
          </div>
          {hasPatch && (
            <button type="button" className="secondary-action" disabled={readOnly} onClick={() => onApplyPatch(result.suggested_patch)}>
              {applyLabel}
            </button>
          )}
        </div>
        {hasQueryDraft && hasExistingQuery && (
          <p className="mt-3 rounded border border-amber-900/60 bg-amber-950/20 px-3 py-2 text-xs leading-5 text-amber-100">
            This explicit action replaces the current unsaved query text and query type. It does not save the hunt or execute the query; save only after reviewing the generated syntax and field mappings.
          </p>
        )}
        <PatchPreview patch={result.suggested_patch} />
      </div>
      <div className="grid gap-3 md:grid-cols-2">
        <ResultList title="Recommended actions" items={result.recommended_actions} />
        <ResultList title="Questions for the analyst" items={result.questions} />
        <ResultList title="Evidence gaps" items={result.evidence_gaps} tone="amber" />
        <ResultList title="Cautions" items={result.cautions} tone="amber" />
      </div>
      {result.finding_drafts.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Proposed finding drafts</h3>
          {result.finding_drafts.map((finding, index) => (
            <article key={`${finding.title ?? 'finding'}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-3">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <b className="text-sm text-white">{finding.title || `Finding draft ${index + 1}`}</b>
                  <p className="mt-1 whitespace-pre-wrap text-xs leading-5 text-gray-500">{finding.summary || 'No summary proposed.'}</p>
                </div>
                <button type="button" className="secondary-action" disabled={readOnly} onClick={() => onUseFindingDraft(finding)}>
                  Open editable draft
                </button>
              </div>
            </article>
          ))}
        </section>
      )}
      <Citations citations={result.citations} />
    </section>
  );
}

function ResultMeta({
  assistanceId,
  provider,
  model,
  generatedAt,
  promptVersion,
  warnings,
  executionBoundary,
}: {
  assistanceId: string;
  provider: string;
  model: string;
  generatedAt: string;
  promptVersion: string;
  warnings: string[];
  executionBoundary: string;
}) {
  return (
    <div className="rounded border border-cyan-900/60 bg-cyan-950/15 p-3 text-xs leading-5 text-cyan-100/80">
      <div className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10px] text-cyan-200/70">
        <span title={assistanceId}>assistance {assistanceId.slice(0, 12)}</span>
        <span>{provider} / {model || 'server default'}</span>
        <span>prompt {promptVersion}</span>
        <span>{formatDate(generatedAt)}</span>
      </div>
      <p className="mt-2">{executionBoundary || 'No query execution or automatic hunt mutation occurred.'}</p>
      {warnings.map((warning, index) => <p key={`${warning}-${index}`} className="mt-2 text-amber-200">Warning: {warning}</p>)}
    </div>
  );
}

function PatchPreview({ patch }: { patch: Partial<ThreatHuntInput> | ThreatHuntAIHypothesisCandidate }) {
  const entries = meaningfulPatchEntries(patch);
  if (!entries.length) return null;
  return (
    <details className="mt-3 rounded border border-gray-800 bg-gray-900/50">
      <summary className="cursor-pointer px-3 py-2 text-xs text-gray-400">Review proposed fields ({entries.length})</summary>
      <dl className="grid gap-2 border-t border-gray-800 p-3">
        {entries.map(([key, value]) => (
          <div key={key} className="grid gap-1 text-xs md:grid-cols-[150px_minmax(0,1fr)]">
            <dt className="font-mono text-[10px] text-gray-600">{key}</dt>
            <dd className="whitespace-pre-wrap break-words text-gray-300">{formatPatchValue(value)}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

function ResultList({ title, items, tone = 'default' }: { title: string; items: string[]; tone?: 'default' | 'amber' }) {
  if (!items.length) return null;
  return (
    <section className={`rounded border p-3 ${tone === 'amber' ? 'border-amber-900/60 bg-amber-950/15' : 'border-gray-800 bg-gray-950/60'}`}>
      <h3 className={`text-[10px] font-semibold uppercase tracking-wide ${tone === 'amber' ? 'text-amber-300' : 'text-gray-500'}`}>{title}</h3>
      <ul className="mt-2 list-disc space-y-1 pl-4 text-xs leading-5 text-gray-400">
        {items.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
      </ul>
    </section>
  );
}

function Citations({ citations }: { citations: ThreatHuntAICitation[] }) {
  if (!citations.length) return null;
  return (
    <section className="mt-3 space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Source citations</h3>
      {citations.map((citation, index) => (
        <blockquote key={`${citation.source_ref}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-3 text-xs leading-5 text-gray-400">
          <p className="whitespace-pre-wrap">{citation.quote || 'No exact source excerpt returned.'}</p>
          <footer className="mt-2 flex flex-wrap gap-2 font-mono text-[10px] text-gray-600">
            <span>{citation.source_type}</span>
            <span>{citation.source_ref}</span>
            <span className={citation.verified ? 'text-emerald-400' : 'text-amber-400'}>{citation.verified ? 'verified span' : 'verify manually'}</span>
          </footer>
        </blockquote>
      ))}
    </section>
  );
}

function meaningfulPatchEntries(patch: object) {
  const ignored = new Set(['rationale', 'source_evidence', 'status', 'tlp', 'owner', 'disposition', 'priority']);
  return Object.entries(patch).filter(([key, value]) => {
    if (ignored.has(key) || value == null) return false;
    if (typeof value === 'string') return Boolean(value.trim());
    if (Array.isArray(value)) return value.length > 0;
    return false;
  });
}

function formatPatchValue(value: unknown) {
  if (Array.isArray(value)) return value.join(', ');
  return String(value ?? '');
}

function focusPlaceholder(mode: HuntAIAssistantMode) {
  if (mode === 'hypothesis') return 'Example: prioritize identity abuse affecting finance and require falsifiable endpoint evidence.';
  if (mode === 'query') return 'Example: target Microsoft Sentinel and explain every field assumption.';
  if (mode === 'findings') return 'Example: challenge benign explanations and identify evidence gaps.';
  if (mode === 'outcome') return 'Example: summarize limitations and defensive handoffs without overstating confidence.';
  return 'Example: constrain the scope to managed Windows endpoints and a seven-day timebox.';
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : error ? String(error) : '';
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown generation time' : date.toLocaleString();
}

function isEligibleHypothesisSource(item: ReportCollectionItem) {
  return item.status === 'completed' && item.source_text_available && item.domain === 'enterprise-attack';
}

function assistantContextFingerprint(context: ThreatHuntInput) {
  return JSON.stringify({
    title: context.title,
    hypothesis: context.hypothesis,
    description: context.description,
    scope: context.scope,
    status: context.status,
    priority: context.priority,
    owner: context.owner,
    tlp: context.tlp,
    technique_ids: context.technique_ids,
    tactics: context.tactics,
    telemetry_sources: context.telemetry_sources,
    required_fields: context.required_fields,
    tags: context.tags,
    query_language: context.query_language,
    query_text: context.query_text,
    time_range_start: context.time_range_start,
    time_range_end: context.time_range_end,
    expected_evidence: context.expected_evidence,
    false_positive_notes: context.false_positive_notes,
    assumptions: context.assumptions,
    result_summary: context.result_summary,
    disposition: context.disposition,
  });
}

function withHypothesisProvenance(
  candidate: ThreatHuntAIHypothesisCandidate,
  result: ThreatHuntAIHypothesisResponse,
): ThreatHuntAIHypothesisCandidate {
  const sourceType = result.source_type === 'research' ? 'research' : 'report';
  const sourceRef = (result.source_ref || result.source_session_id).trim().slice(0, 488);
  const assistanceId = result.assistance_id.trim().slice(0, 485);
  const provenanceTags = [
    `context:${sourceType}`,
    ...(sourceRef ? [`context-ref:${sourceRef}`] : []),
    ...(assistanceId ? [`ai-assistance:${assistanceId}`] : []),
  ];
  return {
    ...candidate,
    tags: Array.from(new Set([...provenanceTags, ...(candidate.tags ?? [])])).slice(0, 100),
  };
}
