import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  analyzeApi,
  type ReportReviewAiAdvisory,
  type ReportReviewAnalystVerdict,
  type ReportReviewAssessment,
  type ReportReviewClaim,
  type ReportReviewClaimStatus,
  type ReportReviewClaimType,
  type ReportReviewEvidenceRef,
  type ReportReviewGate,
  type ReportReviewGateKey,
  type ReportReviewProfile,
  type ReportReviewPromotionTarget,
} from '@/api/client';
import { PermissionNotice } from '@/components/PermissionNotice';
import { ReviewStateBadge } from './ReviewStateBadge';
import { isReportReviewAssessment } from './reviewState';

const GATES: Array<{
  key: ReportReviewGateKey;
  number: number;
  title: string;
  question: string;
  reasonCodes: string[];
}> = [
  { key: 'source_provenance', number: 1, title: 'Source provenance', question: 'Is the source URL genuine, accessible, and bound to the stored report?', reasonCodes: ['source_verified', 'internal_source_verified', 'archived_source_verified', 'source_unreachable', 'source_mismatch', 'insufficient_provenance'] },
  { key: 'publication_date', number: 2, title: 'Publication date', question: 'Is the publication date supported by source metadata or explicit report evidence?', reasonCodes: ['date_verified', 'internal_record_date_verified', 'internal_record_no_publication', 'date_conflict', 'date_missing', 'date_unverified'] },
  { key: 'procedure_relevance', number: 3, title: 'Procedure relevance', question: 'Does the report describe adversary behavior rather than merely name a tool, actor, or technique?', reasonCodes: ['procedure_relevant', 'name_only_mention', 'not_security_procedure', 'insufficient_procedure_context'] },
  { key: 'procedure_level_claim', number: 4, title: 'Procedure-level claim', question: 'Is at least one specific, source-bound procedure claim suitable for promotion?', reasonCodes: ['source_bound_claims', 'generic_tool_only', 'claim_not_source_bound', 'insufficient_procedure_detail'] },
  { key: 'actor_identification', number: 5, title: 'Actor identification', question: 'Is actor attribution explicit and evidenced, or clearly recorded as an inference or unknown?', reasonCodes: ['explicit_attribution', 'source_reported_attribution', 'no_actor_claim', 'tooling_overlap_only', 'inferred_attribution', 'conflicting_attribution'] },
];

const ANALYST_VERDICTS: Array<{ value: Exclude<ReportReviewAnalystVerdict, 'pending'>; label: string }> = [
  { value: 'pass', label: 'Pass' },
  { value: 'fail', label: 'Fail' },
  { value: 'needs_information', label: 'Needs information' },
  { value: 'not_applicable', label: 'Not applicable' },
];

const OPTIONAL_PROMOTION_TARGETS: Array<{ value: Exclude<ReportReviewPromotionTarget, 'canonical_intelligence'>; label: string; description: string }> = [
  { value: 'rag', label: 'RAG retrieval', description: 'Expose accepted claims to trusted retrieval.' },
  { value: 'hunting', label: 'Threat hunting', description: 'Materialize accepted procedures and indicators for hunting.' },
  { value: 'exports', label: 'Trusted exports', description: 'Allow accepted claims in governed export workflows.' },
];

const INDICATOR_TYPES = ['ipv4', 'ipv6', 'ip:port', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'ja3', 'ja3s', 'ja4', 'ja4s', 'ja4h', 'ja4l', 'ja4ls', 'ja4x', 'ja4ssh', 'ja4t'] as const;
type ManualIndicatorType = (typeof INDICATOR_TYPES)[number];

type GateDraft = {
  verdict: ReportReviewAnalystVerdict;
  reasonCode: string;
  rationale: string;
  selectedEvidence: string[];
};

type ManualClaimDraft = {
  claimType: ReportReviewClaimType;
  subject: string;
  predicate: string;
  object: string;
  statement: string;
  attackId: string;
  actorId: string;
  indicatorType: ManualIndicatorType;
  attributionBasis: 'explicit' | 'source_reported' | 'inferred' | 'tooling_overlap_only' | 'none' | 'conflicting';
  evidenceStart: string;
  evidenceEnd: string;
};

type ReviewWrite =
  | { kind: 'start'; profile: ReportReviewProfile }
  | { kind: 'preflight'; version: number }
  | { kind: 'gate'; version: number; gateKey: ReportReviewGateKey; draft: GateDraft; evidenceRefs: ReportReviewEvidenceRef[] }
  | { kind: 'claim'; version: number; claim: ReportReviewClaim; status: ReportReviewClaimStatus; rationale: string }
  | { kind: 'create_claim'; version: number; claim: ManualClaimDraft }
  | { kind: 'coverage_exception'; version: number; reason: string }
  | { kind: 'submit'; version: number }
  | { kind: 'approve'; version: number; note: string }
  | { kind: 'request_changes'; version: number; reason: string }
  | { kind: 'reject'; version: number; reason: string }
  | { kind: 'promote'; version: number; targets: ReportReviewPromotionTarget[]; note: string }
  | { kind: 'revoke'; version: number; reason: string };

export function ReportReviewGate({
  sessionId,
  canReview,
  canPromote,
  sourceText = '',
}: {
  sessionId: string;
  canReview: boolean;
  canPromote: boolean;
  sourceText?: string;
}) {
  const queryClient = useQueryClient();
  const [profile, setProfile] = useState<ReportReviewProfile>('external_cti');
  const [gateDrafts, setGateDrafts] = useState<Record<string, GateDraft>>({});
  const [claimRationales, setClaimRationales] = useState<Record<string, string>>({});
  const [claimFilter, setClaimFilter] = useState<'all' | ReportReviewClaimStatus>('all');
  const [manualClaim, setManualClaim] = useState<ManualClaimDraft>(blankManualClaim());
  const [coverageExceptionReason, setCoverageExceptionReason] = useState('');
  const [approvalNote, setApprovalNote] = useState('');
  const [reviewDecisionReason, setReviewDecisionReason] = useState('');
  const [promotionTargets, setPromotionTargets] = useState<ReportReviewPromotionTarget[]>(['canonical_intelligence']);
  const [promotionNote, setPromotionNote] = useState('');
  const [revocationReason, setRevocationReason] = useState('');
  const [aiProvider, setAiProvider] = useState('local');
  const [cloudProcessingAcknowledged, setCloudProcessingAcknowledged] = useState(false);
  const [aiAdvisory, setAiAdvisory] = useState<ReportReviewAiAdvisory | null>(null);
  const [operationError, setOperationError] = useState('');
  const [versionConflict, setVersionConflict] = useState('');

  const reviewQuery = useQuery({
    queryKey: ['report-review', sessionId],
    queryFn: () => analyzeApi.reportReview(sessionId),
    enabled: Boolean(sessionId),
    retry: false,
  });
  const review = isReportReviewAssessment(reviewQuery.data) ? reviewQuery.data : null;

  const historyQuery = useQuery({
    queryKey: ['report-review-history', sessionId],
    queryFn: () => analyzeApi.reportReviewHistory(sessionId),
    enabled: Boolean(review),
    retry: false,
  });

  useEffect(() => {
    if (!review) return;
    const drafts: Record<string, GateDraft> = {};
    for (const definition of GATES) {
      const gate = review.gates.find(candidate => candidate.gate_key === definition.key);
      drafts[definition.key] = {
        verdict: gate?.analyst_verdict ?? 'pending',
        reasonCode: gate?.reason_code || defaultReasonCode(definition.key, gate?.analyst_verdict ?? 'pending'),
        rationale: gate?.rationale || '',
        selectedEvidence: (gate?.evidence_refs ?? []).map(evidenceKey),
      };
    }
    setGateDrafts(drafts);
    setClaimRationales(Object.fromEntries(review.claims.map(claim => [claim.id, claim.rationale || ''])));
  }, [review]);

  const writeMutation = useMutation({
    mutationFn: async (action: ReviewWrite) => {
      if (action.kind === 'start') {
        return analyzeApi.startReportReview(sessionId, {
          profile: action.profile,
        });
      }
      if (action.kind === 'preflight') return analyzeApi.runReportReviewPreflight(sessionId, action.version);
      if (action.kind === 'gate') {
        if (action.draft.verdict === 'pending') throw new Error('Choose an analyst verdict before saving.');
        return analyzeApi.updateReportReviewGate(sessionId, action.gateKey, {
          expected_version: action.version,
          verdict: action.draft.verdict,
          reason_code: action.draft.reasonCode.trim(),
          rationale: action.draft.rationale.trim(),
          evidence_refs: action.evidenceRefs,
        });
      }
      if (action.kind === 'claim') {
        return analyzeApi.updateReportReviewClaim(sessionId, action.claim.id, {
          expected_version: action.version,
          status: action.status,
          rationale: action.rationale.trim(),
        });
      }
      if (action.kind === 'create_claim') {
        const evidenceStart = Number(action.claim.evidenceStart);
        const evidenceEnd = Number(action.claim.evidenceEnd);
        return analyzeApi.createReportReviewClaim(sessionId, {
          expected_version: action.version,
          claim_type: action.claim.claimType,
          subject: action.claim.subject.trim(),
          action: action.claim.predicate.trim(),
          object: action.claim.object.trim(),
          statement: action.claim.statement.trim(),
          attack_id: action.claim.attackId.trim() || undefined,
          actor_id: action.claim.actorId.trim() || undefined,
          evidence_refs: [{
            kind: 'source_text',
            label: 'Analyst-selected exact source span',
            excerpt: sourceText.slice(evidenceStart, evidenceEnd),
            evidence_start: evidenceStart,
            evidence_end: evidenceEnd,
          }],
          metadata: action.claim.claimType === 'actor'
            ? { attribution_basis: action.claim.attributionBasis }
            : action.claim.claimType === 'indicator' ? { indicator_type: action.claim.indicatorType } : {},
        });
      }
      if (action.kind === 'coverage_exception') {
        return analyzeApi.setReportReviewCoverageException(sessionId, { expected_version: action.version, reason: action.reason.trim() });
      }
      if (action.kind === 'submit') return analyzeApi.submitReportReview(sessionId, action.version);
      if (action.kind === 'approve') return analyzeApi.approveReportReview(sessionId, { expected_version: action.version, decision_note: action.note.trim() });
      if (action.kind === 'request_changes') return analyzeApi.requestReportReviewChanges(sessionId, { expected_version: action.version, reason: action.reason.trim() });
      if (action.kind === 'reject') return analyzeApi.rejectReportReview(sessionId, { expected_version: action.version, reason: action.reason.trim() });
      if (action.kind === 'promote') {
        return analyzeApi.promoteReportReview(sessionId, {
          expected_version: action.version,
          targets: action.targets,
          note: action.note.trim(),
        });
      }
      return analyzeApi.revokeReportReview(sessionId, { expected_version: action.version, reason: action.reason.trim() });
    },
    onMutate: () => {
      setOperationError('');
      setVersionConflict('');
    },
    onSuccess: response => {
      const assessment = unwrapAssessment(response);
      queryClient.setQueryData(['report-review', sessionId], assessment);
      void queryClient.invalidateQueries({ queryKey: ['report-review-history', sessionId] });
      void queryClient.invalidateQueries({ queryKey: ['report-research-collection'] });
      setApprovalNote('');
      setReviewDecisionReason('');
      setPromotionNote('');
      setRevocationReason('');
      setManualClaim(blankManualClaim());
      setCoverageExceptionReason('');
    },
    onError: error => {
      const message = error instanceof Error ? error.message : 'Review action failed.';
      if (isVersionConflict(message)) {
        setVersionConflict('The review changed after this page was loaded. The latest version was fetched; your write was not replayed. Re-check the evidence and submit again.');
        void queryClient.invalidateQueries({ queryKey: ['report-review', sessionId] });
      } else {
        setOperationError(message);
      }
    },
  });

  const aiMutation = useMutation({
    mutationFn: () => {
      if (!review) throw new Error('Start the deterministic review before requesting AI assistance.');
      return analyzeApi.assistReportReview(sessionId, {
        expected_version: review.version,
        provider: aiProvider,
        cloud_processing_acknowledged: aiProvider === 'local' ? false : cloudProcessingAcknowledged,
      });
    },
    onMutate: () => {
      setOperationError('');
      setVersionConflict('');
      setAiAdvisory(null);
    },
    onSuccess: response => {
      setAiAdvisory(response);
      if (response.review) queryClient.setQueryData(['report-review', sessionId], response.review);
      else if (response.assessment) queryClient.setQueryData(['report-review', sessionId], response.assessment);
      else void queryClient.invalidateQueries({ queryKey: ['report-review', sessionId] });
      void queryClient.invalidateQueries({ queryKey: ['report-review-history', sessionId] });
    },
    onError: error => {
      const message = error instanceof Error ? error.message : 'AI advisory failed.';
      if (isVersionConflict(message)) {
        setVersionConflict('The report or review changed before the AI advisory completed. No AI result was applied. Refresh and try again if it is still useful.');
        void queryClient.invalidateQueries({ queryKey: ['report-review', sessionId] });
      } else {
        setOperationError(message);
      }
    },
  });

  const orderedGates = useMemo(() => GATES.map(definition => ({
    definition,
    gate: review?.gates.find(candidate => candidate.gate_key === definition.key),
  })), [review?.gates]);
  const filteredClaims = useMemo(
    () => (review?.claims ?? []).filter(claim => claimFilter === 'all' || claim.status === claimFilter),
    [claimFilter, review?.claims],
  );
  const editable = Boolean(review && canReview && ['draft', 'changes_requested'].includes(review.state));
  const terminalCanRestart = Boolean(review && ['stale', 'revoked', 'rejected'].includes(review.state));
  const remoteAiProvider = aiProvider !== 'local';
  const manualClaimValidation = validateManualClaim(manualClaim, sourceText);

  return (
    <section aria-labelledby="report-review-title" className="overflow-hidden rounded border border-cyan-900/70 bg-gray-900/70">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <div>
          <h2 id="report-review-title" className="text-sm font-semibold text-white">Deterministic report Review Gate</h2>
          <p className="mt-1 text-xs leading-5 text-gray-500">Only analyst-approved, source-bound claims from a promoted revision may enter trusted intelligence workflows.</p>
        </div>
        {review ? <ReviewStateBadge state={review.state} /> : <ReviewStateBadge state="unreviewed" />}
      </div>

      {reviewQuery.isLoading && <div className="p-5 text-sm text-gray-500">Loading review assessment…</div>}

      {!reviewQuery.isLoading && !review && (
        <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="rounded border border-amber-800/60 bg-amber-950/20 p-4">
            <h3 className="text-sm font-semibold text-amber-100">No review revision exists</h3>
            <p className="mt-2 text-xs leading-5 text-amber-100/80">
              Parsed entities and AI mappings remain candidates. Start a review to fingerprint the current source and analysis, run deterministic preflight, and record the five analyst decisions.
            </p>
            {reviewQuery.isError && <p className="mt-2 text-[11px] text-amber-200/70">The review API returned: {errorMessage(reviewQuery.error)}</p>}
          </div>
          <StartReview profile={profile} setProfile={setProfile} canReview={canReview} pending={writeMutation.isPending} onStart={() => writeMutation.mutate({ kind: 'start', profile })} />
        </div>
      )}

      {review && (
        <div className="space-y-5 p-4">
          <ReviewOverview review={review} />

          {review.coverage_complete === false && (
            <CoverageExceptionControl
              review={review}
              reason={coverageExceptionReason}
              setReason={setCoverageExceptionReason}
              editable={editable && canPromote}
              pending={writeMutation.isPending}
              onRecord={() => writeMutation.mutate({ kind: 'coverage_exception', version: review.version, reason: coverageExceptionReason })}
            />
          )}

          {(versionConflict || operationError) && (
            <div role="alert" className={`rounded border p-3 text-xs leading-5 ${versionConflict ? 'border-amber-700 bg-amber-950/30 text-amber-100' : 'border-red-800 bg-red-950/30 text-red-200'}`}>
              {versionConflict || operationError}
            </div>
          )}

          {terminalCanRestart && (
            <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-amber-800/60 bg-amber-950/20 p-3">
              <div className="text-xs leading-5 text-amber-100">
                This revision is {review.state}. Start a new revision to bind decisions to the current source and analysis fingerprints.
              </div>
              <button type="button" disabled={!canReview || writeMutation.isPending} onClick={() => writeMutation.mutate({ kind: 'start', profile: review.profile })} className="secondary-action border-amber-700 text-amber-100 disabled:opacity-40">
                Start new revision
              </button>
            </div>
          )}

          <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_340px]">
            <section aria-labelledby="preflight-heading" className="rounded border border-gray-800 bg-gray-950/50 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h3 id="preflight-heading" className="text-sm font-semibold text-white">Deterministic preflight</h3>
                  <p className="mt-1 text-xs leading-5 text-gray-500">Reproducible checks evaluate stored metadata, exact evidence offsets, coverage, and policy rules. They never decide for the analyst.</p>
                </div>
                <button type="button" disabled={!editable || writeMutation.isPending} onClick={() => writeMutation.mutate({ kind: 'preflight', version: review.version })} className="secondary-action disabled:opacity-40">
                  {writeMutation.isPending ? 'Working…' : 'Run preflight'}
                </button>
              </div>
            </section>

            <section aria-labelledby="ai-advisory-heading" className="rounded border border-violet-900/70 bg-violet-950/15 p-4">
              <h3 id="ai-advisory-heading" className="text-sm font-semibold text-violet-100">Optional AI assistant</h3>
              <p className="mt-1 text-xs leading-5 text-violet-200/70">Advisory only. AI may suggest evidence and claims; it cannot set analyst verdicts, accept claims, approve, or promote.</p>
              <div className="mt-3 flex gap-2">
                <label className="sr-only" htmlFor="review-ai-provider">AI provider</label>
                <select id="review-ai-provider" value={aiProvider} onChange={event => {
                  setAiProvider(event.target.value);
                  setCloudProcessingAcknowledged(false);
                }} disabled={!editable || aiMutation.isPending} className="field min-w-28 flex-1 text-xs">
                  <option value="local">Local LLM</option>
                  <option value="claude">Claude</option>
                  <option value="openai">OpenAI</option>
                  <option value="gemini">Gemini</option>
                  <option value="minimax">MiniMax</option>
                </select>
                <button type="button" disabled={!editable || aiMutation.isPending || (remoteAiProvider && !cloudProcessingAcknowledged)} onClick={() => aiMutation.mutate()} className="secondary-action border-violet-800 text-violet-100 disabled:opacity-40">
                  {aiMutation.isPending ? 'Analyzing…' : 'Ask AI'}
                </button>
              </div>
              {remoteAiProvider && (
                <label className="mt-3 flex items-start gap-2 rounded border border-violet-800/60 bg-violet-950/25 p-2 text-[11px] leading-5 text-violet-100/80">
                  <input type="checkbox" className="mt-1" checked={cloudProcessingAcknowledged} onChange={event => setCloudProcessingAcknowledged(event.target.checked)} disabled={!editable || aiMutation.isPending} />
                  <span>I acknowledge that the stored report text and its TLP marking will be sent to the selected remote AI provider for this advisory request.</span>
                </label>
              )}
              {aiAdvisory && <AiAdvisoryReceipt advisory={aiAdvisory} />}
            </section>
          </div>

          <section aria-labelledby="five-gates-heading">
            <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
              <div>
                <h3 id="five-gates-heading" className="text-sm font-semibold text-white">Five analyst gates</h3>
                <p className="mt-1 text-xs text-gray-500">Machine findings and analyst decisions are intentionally separate.</p>
              </div>
              <span className="text-xs text-gray-500">Review version {review.version}{review.revision ? ` · revision ${review.revision}` : ''}</span>
            </div>
            <div className="space-y-3">
              {orderedGates.map(({ definition, gate }) => {
                const draft = gateDrafts[definition.key] ?? blankGateDraft();
                const evidenceOptions = uniqueEvidence([...(gate?.machine_evidence_refs ?? gate?.machine_evidence ?? []), ...(gate?.evidence_refs ?? [])]);
                const selectedRefs = evidenceOptions.filter(ref => draft.selectedEvidence.includes(evidenceKey(ref)));
                const validation = validateGateDraft(draft, selectedRefs, definition.key, review.claims);
                return (
                  <GateEditor
                    key={definition.key}
                    definition={definition}
                    gate={gate}
                    draft={draft}
                    evidenceOptions={evidenceOptions}
                    profile={review.profile}
                    editable={editable}
                    pending={writeMutation.isPending}
                    validation={validation}
                    onDraft={next => setGateDrafts(current => ({ ...current, [definition.key]: next }))}
                    onSave={() => writeMutation.mutate({ kind: 'gate', version: review.version, gateKey: definition.key, draft, evidenceRefs: selectedRefs })}
                  />
                );
              })}
            </div>
          </section>

          <section aria-labelledby="claims-heading" className="rounded border border-gray-800 bg-gray-950/30">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
              <div>
                <h3 id="claims-heading" className="text-sm font-semibold text-white">Source-bound claims</h3>
                <p className="mt-1 text-xs text-gray-500">Each claim is reviewed independently. Suggested does not mean accepted.</p>
              </div>
              <label className="flex items-center gap-2 text-xs text-gray-400">
                <span>Status</span>
                <select value={claimFilter} onChange={event => setClaimFilter(event.target.value as typeof claimFilter)} className="field py-1 text-xs">
                  <option value="all">All claims</option>
                  <option value="suggested">Suggested</option>
                  <option value="accepted">Accepted only</option>
                  <option value="needs_evidence">Needs evidence</option>
                  <option value="rejected">Rejected</option>
                </select>
              </label>
            </div>
            {filteredClaims.length === 0 ? (
              <div className="p-5 text-sm text-gray-600">No claims match this filter.</div>
            ) : (
              <div className="divide-y divide-gray-800">
                {filteredClaims.map(claim => (
                  <ClaimEditor
                    key={claim.id}
                    claim={claim}
                    rationale={claimRationales[claim.id] ?? ''}
                    editable={editable}
                    pending={writeMutation.isPending}
                    onRationale={value => setClaimRationales(current => ({ ...current, [claim.id]: value }))}
                    onDecision={status => writeMutation.mutate({ kind: 'claim', version: review.version, claim, status, rationale: claimRationales[claim.id] ?? '' })}
                  />
                ))}
              </div>
            )}
            <ManualClaimForm
              draft={manualClaim}
              setDraft={setManualClaim}
              sourceText={sourceText}
              validation={manualClaimValidation}
              editable={editable}
              pending={writeMutation.isPending}
              onCreate={() => writeMutation.mutate({ kind: 'create_claim', version: review.version, claim: manualClaim })}
            />
          </section>

          <LifecycleActions
            review={review}
            canReview={canReview}
            canPromote={canPromote}
            pending={writeMutation.isPending}
            approvalNote={approvalNote}
            setApprovalNote={setApprovalNote}
            reviewDecisionReason={reviewDecisionReason}
            setReviewDecisionReason={setReviewDecisionReason}
            promotionTargets={promotionTargets}
            setPromotionTargets={setPromotionTargets}
            promotionNote={promotionNote}
            setPromotionNote={setPromotionNote}
            revocationReason={revocationReason}
            setRevocationReason={setRevocationReason}
            onSubmit={() => writeMutation.mutate({ kind: 'submit', version: review.version })}
            onApprove={() => writeMutation.mutate({ kind: 'approve', version: review.version, note: approvalNote })}
            onRequestChanges={() => writeMutation.mutate({ kind: 'request_changes', version: review.version, reason: reviewDecisionReason })}
            onReject={() => writeMutation.mutate({ kind: 'reject', version: review.version, reason: reviewDecisionReason })}
            onPromote={() => writeMutation.mutate({ kind: 'promote', version: review.version, targets: promotionTargets, note: promotionNote })}
            onRevoke={() => writeMutation.mutate({ kind: 'revoke', version: review.version, reason: revocationReason })}
          />

          {!canReview && <PermissionNotice permission="review_reports" action="record analyst gate and claim decisions" compact />}
          {review.state === 'approved' && !canPromote && <PermissionNotice permission="promote_reports" action="promote approved report intelligence" compact />}

          <History events={historyQuery.data ?? []} loading={historyQuery.isLoading} />
        </div>
      )}
    </section>
  );
}

function StartReview({ profile, setProfile, canReview, pending, onStart }: {
  profile: ReportReviewProfile;
  setProfile: (profile: ReportReviewProfile) => void;
  canReview: boolean;
  pending: boolean;
  onStart: () => void;
}) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-4">
      <label className="text-xs font-semibold text-gray-300" htmlFor="review-profile">Review profile</label>
      <select id="review-profile" value={profile} onChange={event => setProfile(event.target.value as ReportReviewProfile)} disabled={!canReview || pending} className="field mt-2 w-full">
        <option value="external_cti">External CTI report</option>
        <option value="internal_ir">Internal IR report</option>
      </select>
      <button type="button" onClick={onStart} disabled={!canReview || pending} className="primary-action mt-3 w-full disabled:opacity-40">
        {pending ? 'Starting…' : 'Start deterministic review'}
      </button>
      {!canReview && <div className="mt-3"><PermissionNotice permission="review_reports" action="start a report review" compact /></div>}
    </div>
  );
}

function ReviewOverview({ review }: { review: ReportReviewAssessment }) {
  const readiness = review.readiness;
  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <OverviewMetric label="Required gates reviewed" value={`${readiness.reviewed_gate_count}/${readiness.required_gate_count}`} tone={readiness.reviewed_gate_count === readiness.required_gate_count ? 'good' : 'default'} />
      <OverviewMetric label="Accepted claims" value={String(readiness.accepted_claim_count)} tone={readiness.accepted_claim_count > 0 ? 'good' : 'warn'} />
      <OverviewMetric label="Promotion blockers" value={String(readiness.blockers.length)} tone={readiness.blockers.length === 0 ? 'good' : 'warn'} />
      <OverviewMetric
        label="Source coverage"
        value={review.coverage_complete === false ? (review.coverage_exception_reason ? 'Exception recorded' : 'Incomplete') : 'Complete'}
        tone={review.coverage_complete === false ? 'warn' : 'good'}
      />
      <div className="rounded border border-gray-800 bg-gray-950/60 p-3 text-[11px] leading-5 text-gray-500 md:col-span-2 xl:col-span-4">
        <div className="flex flex-wrap gap-x-5 gap-y-1 font-mono">
          <span>policy {review.policy_version || 'server policy'}</span>
          <span>source {shortChecksum(review.source_checksum)}</span>
          <span>analysis {shortChecksum(review.analysis_checksum)}</span>
          {typeof review.analyzed_char_count === 'number' && typeof review.source_char_count === 'number' && <span>coverage {review.analyzed_char_count}/{review.source_char_count} chars</span>}
        </div>
      </div>
      {readiness.blockers.length > 0 && (
        <div className="rounded border border-amber-800/60 bg-amber-950/20 p-3 md:col-span-2 xl:col-span-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-amber-200">Readiness blockers</h3>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-5 text-amber-100/80">
            {readiness.blockers.map((blocker, index) => <li key={`${blocker}-${index}`}>{blocker}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

function GateEditor({ definition, gate, draft, evidenceOptions, profile, editable, pending, validation, onDraft, onSave }: {
  definition: (typeof GATES)[number];
  gate?: ReportReviewGate;
  draft: GateDraft;
  evidenceOptions: ReportReviewEvidenceRef[];
  profile: ReportReviewProfile;
  editable: boolean;
  pending: boolean;
  validation: string;
  onDraft: (draft: GateDraft) => void;
  onSave: () => void;
}) {
  const machineEvidence = gate?.machine_evidence_refs ?? gate?.machine_evidence ?? [];
  const verdictReasonCodes = gate?.allowed_reason_codes_by_verdict?.[draft.verdict];
  const reasonCodes = verdictReasonCodes
    ?? (gate?.allowed_reason_codes?.length ? gate.allowed_reason_codes : definition.reasonCodes);
  const allowNotApplicable = definition.key === 'actor_identification' || (definition.key === 'publication_date' && profile === 'internal_ir');
  return (
    <article className="overflow-hidden rounded border border-gray-800 bg-gray-950/45">
      <div className="flex items-start gap-3 border-b border-gray-800 p-3">
        <span aria-hidden="true" className="flex h-9 w-9 shrink-0 items-center justify-center rounded border border-cyan-800 bg-cyan-950/30 text-sm font-bold text-cyan-200">{definition.number}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="text-sm font-semibold text-white">{gate?.title || definition.title}</h4>
            {gate?.required !== false && <span className="rounded border border-gray-700 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-gray-500">Required</span>}
          </div>
          <p className="mt-1 text-xs leading-5 text-gray-400">{gate?.question || definition.question}</p>
        </div>
      </div>
      <div className="grid lg:grid-cols-2">
        <section aria-label={`${definition.title} machine finding`} className="border-b border-gray-800 p-4 lg:border-b-0 lg:border-r">
          <div className="flex items-center justify-between gap-2">
            <h5 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Machine finding · advisory</h5>
            <VerdictBadge verdict={gate?.machine_verdict ?? 'not_run'} kind="machine" />
          </div>
          <p className="mt-3 text-xs leading-5 text-gray-400">{machineSummary(gate)}</p>
          {machineEvidence.length > 0 && (
            <div className="mt-3 space-y-2">
              <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">Machine evidence references</div>
              {machineEvidence.map((ref, index) => <EvidenceCard key={evidenceKey(ref, index)} evidence={ref} />)}
            </div>
          )}
        </section>
        <fieldset disabled={!editable || pending} className="p-4 disabled:opacity-70">
          <legend className="sr-only">{definition.title} analyst decision</legend>
          <div className="flex items-center justify-between gap-2">
            <h5 className="text-[10px] font-semibold uppercase tracking-wide text-gray-500">Analyst decision · authoritative</h5>
            <VerdictBadge verdict={gate?.analyst_verdict ?? 'pending'} kind="analyst" />
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-xs text-gray-400">
              <span>Verdict</span>
              <select value={draft.verdict} onChange={event => {
                const verdict = event.target.value as ReportReviewAnalystVerdict;
                onDraft({ ...draft, verdict, reasonCode: defaultReasonCode(definition.key, verdict) });
              }} className="field w-full">
                <option value="pending">Pending</option>
                {ANALYST_VERDICTS.filter(option => option.value !== 'not_applicable' || allowNotApplicable).map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select>
            </label>
            <label className="space-y-1 text-xs text-gray-400">
              <span>Reason code</span>
              <select value={draft.reasonCode} onChange={event => onDraft({ ...draft, reasonCode: normalizeReasonCode(event.target.value) })} className="field w-full font-mono text-xs">
                <option value="">Choose reason</option>
                {reasonCodes.map(code => <option key={code} value={code}>{humanize(code)}</option>)}
              </select>
            </label>
          </div>
          <label className="mt-3 block space-y-1 text-xs text-gray-400">
            <span>Analyst rationale</span>
            <textarea value={draft.rationale} onChange={event => onDraft({ ...draft, rationale: event.target.value })} placeholder="Explain what was checked and why the evidence supports this decision." className="field h-20 w-full resize-y text-xs" />
          </label>
          {evidenceOptions.length > 0 && (
            <div className="mt-3">
              <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">Cite stored evidence references</div>
              <div className="mt-2 space-y-2">
                {evidenceOptions.map((ref, index) => {
                  const key = evidenceKey(ref, index);
                  const checked = draft.selectedEvidence.includes(key);
                  return (
                    <label key={key} className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-2 text-xs text-gray-400">
                      <input type="checkbox" className="mt-1" checked={checked} onChange={() => onDraft({ ...draft, selectedEvidence: checked ? draft.selectedEvidence.filter(value => value !== key) : [...draft.selectedEvidence, key] })} />
                      <span>{evidenceText(ref)}</span>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <span className={`text-[11px] ${validation ? 'text-amber-300' : 'text-gray-600'}`}>{validation || analystReviewMetadata(gate)}</span>
            <button type="button" onClick={onSave} disabled={!editable || pending || Boolean(validation)} className="secondary-action disabled:opacity-40">Save analyst decision</button>
          </div>
        </fieldset>
      </div>
    </article>
  );
}

function ClaimEditor({ claim, rationale, editable, pending, onRationale, onDecision }: {
  claim: ReportReviewClaim;
  rationale: string;
  editable: boolean;
  pending: boolean;
  onRationale: (value: string) => void;
  onDecision: (status: ReportReviewClaimStatus) => void;
}) {
  const acceptanceBlocker = claimAcceptanceBlocker(claim);
  const statement = claim.statement || claim.claim || claim.title || [claim.subject, claim.predicate || claim.action, claim.object].filter(Boolean).join(' ') || 'Untitled claim';
  return (
    <article className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wide text-gray-500">
            <span>{claim.claim_type}</span>
            {(claim.attack_id || claim.attack_ids?.length) && <span className="font-mono text-cyan-300">{claim.attack_id || claim.attack_ids?.join(', ')}</span>}
            {(claim.actor_id || claim.actor_ids?.length) && <span className="font-mono text-violet-300">{claim.actor_id || claim.actor_ids?.join(', ')}</span>}
            {claim.extraction_method && <span>{claim.extraction_method}</span>}
          </div>
          <p className="mt-2 text-sm leading-6 text-gray-200">{statement}</p>
        </div>
        <ClaimStatusBadge status={claim.status} />
      </div>
      <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_300px]">
        <div className="space-y-2">
          {(claim.evidence_refs ?? []).map((ref, index) => <EvidenceCard key={evidenceKey(ref, index)} evidence={ref} />)}
          {claim.evidence_text && <EvidenceCard evidence={{ excerpt: claim.evidence_text, evidence_start: claim.evidence_start, evidence_end: claim.evidence_end, kind: 'source-offset' }} />}
          {acceptanceBlocker && <div className="rounded border border-amber-900/70 bg-amber-950/20 p-2 text-xs text-amber-200">{acceptanceBlocker} Acceptance is disabled.</div>}
        </div>
        <div>
          <label className="text-xs text-gray-400">
            <span>Decision rationale</span>
            <textarea value={rationale} onChange={event => onRationale(event.target.value)} disabled={!editable || pending} className="field mt-1 h-20 w-full resize-y text-xs disabled:opacity-60" placeholder="Why should this claim be accepted, rejected, or returned for evidence?" />
          </label>
          <div className="mt-2 flex flex-wrap gap-2">
            <button type="button" disabled={!editable || pending || Boolean(acceptanceBlocker) || rationale.trim().length < 8} onClick={() => onDecision('accepted')} className="secondary-action border-emerald-800 text-emerald-200 disabled:opacity-40" title={acceptanceBlocker || undefined}>Accept</button>
            <button type="button" disabled={!editable || pending || rationale.trim().length < 8} onClick={() => onDecision('needs_evidence')} className="secondary-action border-amber-800 text-amber-200 disabled:opacity-40">Needs evidence</button>
            <button type="button" disabled={!editable || pending || rationale.trim().length < 8} onClick={() => onDecision('rejected')} className="secondary-action border-red-900 text-red-200 disabled:opacity-40">Reject</button>
          </div>
          <p className="mt-2 text-[10px] leading-4 text-gray-600">A rationale of at least 8 characters is required. AI suggestions remain suggested until an analyst acts.</p>
        </div>
      </div>
    </article>
  );
}

function ManualClaimForm({ draft, setDraft, sourceText, validation, editable, pending, onCreate }: {
  draft: ManualClaimDraft;
  setDraft: (draft: ManualClaimDraft) => void;
  sourceText: string;
  validation: string;
  editable: boolean;
  pending: boolean;
  onCreate: () => void;
}) {
  const start = Number(draft.evidenceStart);
  const end = Number(draft.evidenceEnd);
  const preview = Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start && end <= sourceText.length
    ? sourceText.slice(start, end)
    : '';
  return (
    <details className="border-t border-gray-800">
      <summary className="cursor-pointer px-4 py-3 text-xs font-semibold text-cyan-200">Add a manual source-bound claim</summary>
      <fieldset disabled={!editable || pending} className="grid gap-3 border-t border-gray-800 bg-cyan-950/5 p-4 md:grid-cols-2 disabled:opacity-60">
        <legend className="sr-only">Manual source-bound claim</legend>
        <p className="text-xs leading-5 text-gray-500 md:col-span-2">
          Use this when deterministic extraction found no usable date or procedure candidate. The server derives evidence from exact stored-source offsets; this form never accepts a pasted excerpt as authority.
        </p>
        <label className="space-y-1 text-xs text-gray-400">Claim type
          <select value={draft.claimType} onChange={event => setDraft({ ...draft, claimType: event.target.value as ReportReviewClaimType })} className="field w-full">
            <option value="procedure">Procedure</option>
            <option value="actor">Actor attribution</option>
            <option value="publication_date">Publication date</option>
            <option value="indicator">Indicator</option>
            <option value="vulnerability">Vulnerability</option>
          </select>
        </label>
        <label className="space-y-1 text-xs text-gray-400">Subject
          <input value={draft.subject} onChange={event => setDraft({ ...draft, subject: event.target.value })} className="field w-full" placeholder="The actor, malware, report, or incident" />
        </label>
        <label className="space-y-1 text-xs text-gray-400">Predicate / action
          <input value={draft.predicate} onChange={event => setDraft({ ...draft, predicate: event.target.value })} className="field w-full" placeholder="executed, exploited, published, attributed…" />
        </label>
        <label className="space-y-1 text-xs text-gray-400">Object / outcome
          <input value={draft.object} onChange={event => setDraft({ ...draft, object: event.target.value })} className="field w-full" placeholder="Specific behavior, target, date, or observable" />
        </label>
        <label className="space-y-1 text-xs text-gray-400 md:col-span-2">Complete claim statement
          <textarea value={draft.statement} onChange={event => setDraft({ ...draft, statement: event.target.value })} className="field h-20 w-full resize-y text-xs" placeholder="Write one precise, falsifiable statement supported by the cited source span." />
        </label>
        {draft.claimType === 'procedure' && <label className="space-y-1 text-xs text-gray-400">ATT&amp;CK technique ID
          <input value={draft.attackId} onChange={event => setDraft({ ...draft, attackId: event.target.value.toUpperCase().trim() })} className="field w-full font-mono" placeholder="T1059.001" />
        </label>}
        {draft.claimType === 'actor' && <>
          <label className="space-y-1 text-xs text-gray-400">Actor identifier
            <input value={draft.actorId} onChange={event => setDraft({ ...draft, actorId: event.target.value.trim() })} className="field w-full font-mono" placeholder="G0000 or exact source-reported actor name" />
          </label>
          <label className="space-y-1 text-xs text-gray-400">Attribution basis
            <select value={draft.attributionBasis} onChange={event => setDraft({ ...draft, attributionBasis: event.target.value as ManualClaimDraft['attributionBasis'] })} className="field w-full">
              <option value="explicit">Explicit attribution</option>
              <option value="source_reported">Source-reported attribution</option>
              <option value="inferred">Analyst inference</option>
              <option value="tooling_overlap_only">Tooling overlap only</option>
              <option value="conflicting">Conflicting attribution</option>
              <option value="none">No actor attribution</option>
            </select>
          </label>
        </>}
        {draft.claimType === 'indicator' && <label className="space-y-1 text-xs text-gray-400">Indicator type
          <select value={draft.indicatorType} onChange={event => setDraft({ ...draft, indicatorType: event.target.value as ManualIndicatorType })} className="field w-full font-mono">
            {INDICATOR_TYPES.map(value => <option key={value} value={value}>{value}</option>)}
          </select>
        </label>}
        <div className="grid grid-cols-2 gap-3 md:col-span-2">
          <label className="space-y-1 text-xs text-gray-400">Evidence start offset
            <input type="number" min="0" max={sourceText.length} value={draft.evidenceStart} onChange={event => setDraft({ ...draft, evidenceStart: event.target.value })} className="field w-full font-mono" />
          </label>
          <label className="space-y-1 text-xs text-gray-400">Evidence end offset
            <input type="number" min="1" max={sourceText.length} value={draft.evidenceEnd} onChange={event => setDraft({ ...draft, evidenceEnd: event.target.value })} className="field w-full font-mono" />
          </label>
        </div>
        <div className="rounded border border-gray-800 bg-black/30 p-3 text-xs leading-5 text-gray-400 md:col-span-2">
          <div className="text-[10px] font-semibold uppercase tracking-wide text-gray-600">Exact stored-source preview</div>
          <div className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-words font-mono">{preview || 'Enter valid offsets to preview the immutable source span.'}</div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 md:col-span-2">
          <span className={`text-[11px] ${validation ? 'text-amber-300' : 'text-gray-600'}`}>{validation || 'The new claim will remain suggested until separately adjudicated.'}</span>
          <button type="button" onClick={onCreate} disabled={!editable || pending || Boolean(validation)} className="secondary-action border-cyan-800 text-cyan-100 disabled:opacity-40">Create suggested claim</button>
        </div>
      </fieldset>
    </details>
  );
}

function CoverageExceptionControl({ review, reason, setReason, editable, pending, onRecord }: {
  review: ReportReviewAssessment;
  reason: string;
  setReason: (reason: string) => void;
  editable: boolean;
  pending: boolean;
  onRecord: () => void;
}) {
  if (review.coverage_exception_reason) {
    return (
      <div className="rounded border border-amber-800/60 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100">
        <div className="font-semibold">Explicit coverage exception recorded</div>
        <div className="mt-1">{review.coverage_exception_reason}</div>
        {(review.coverage_exception_by || review.coverage_exception_at) && <div className="mt-1 text-amber-200/60">{review.coverage_exception_by || 'analyst'} · {formatDate(review.coverage_exception_at)}</div>}
      </div>
    );
  }
  return (
    <div className="grid gap-3 rounded border border-amber-800/60 bg-amber-950/20 p-3 lg:grid-cols-[minmax(0,1fr)_auto]">
      <label className="text-xs leading-5 text-amber-100">
        <span className="font-semibold">Incomplete source coverage exception</span>
        <span className="block text-amber-100/70">Use only when full deterministic coverage is impossible and the residual risk is understood. A second reviewer with promotion authority must grant it. The action is attributed and audited; it does not create or accept claims.</span>
        <textarea value={reason} onChange={event => setReason(event.target.value)} disabled={!editable || pending} className="field mt-2 h-16 w-full resize-y text-xs" placeholder="Explain why incomplete coverage is acceptable and what content remains unreviewed." />
      </label>
      <button type="button" onClick={onRecord} disabled={!editable || pending || reason.trim().length < 30} className="secondary-action self-end border-amber-700 text-amber-100 disabled:opacity-40">Record exception</button>
    </div>
  );
}

function LifecycleActions(props: {
  review: ReportReviewAssessment;
  canReview: boolean;
  canPromote: boolean;
  pending: boolean;
  approvalNote: string;
  setApprovalNote: (value: string) => void;
  reviewDecisionReason: string;
  setReviewDecisionReason: (value: string) => void;
  promotionTargets: ReportReviewPromotionTarget[];
  setPromotionTargets: (value: ReportReviewPromotionTarget[]) => void;
  promotionNote: string;
  setPromotionNote: (value: string) => void;
  revocationReason: string;
  setRevocationReason: (value: string) => void;
  onSubmit: () => void;
  onApprove: () => void;
  onRequestChanges: () => void;
  onReject: () => void;
  onPromote: () => void;
  onRevoke: () => void;
}) {
  const { review } = props;
  return (
    <section aria-labelledby="review-lifecycle-heading" className="rounded border border-emerald-900/60 bg-emerald-950/10 p-4">
      <h3 id="review-lifecycle-heading" className="text-sm font-semibold text-white">Review lifecycle</h3>
      <p className="mt-1 text-xs leading-5 text-gray-500">Every transition uses the visible version token. Server policy and RBAC remain authoritative.</p>
      {['draft', 'changes_requested'].includes(review.state) && (
        <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-gray-400">Submit freezes a complete assessment. Server policy routes promotion-ready work to approval and blocked work to changes requested.</p>
          <button type="button" disabled={!props.canReview || props.pending || !assessmentComplete(review)} onClick={props.onSubmit} className="primary-action disabled:opacity-40">Submit assessment</button>
        </div>
      )}
      {review.state === 'in_review' && (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <label className="text-xs text-gray-400">Approval note
            <textarea value={props.approvalNote} onChange={event => props.setApprovalNote(event.target.value)} disabled={!props.canPromote || props.pending} className="field mt-1 h-16 w-full resize-y text-xs" placeholder="Independent reviewer observations" />
          </label>
          <label className="text-xs text-gray-400">Change or rejection reason
            <textarea value={props.reviewDecisionReason} onChange={event => props.setReviewDecisionReason(event.target.value)} disabled={!props.canPromote || props.pending} className="field mt-1 h-16 w-full resize-y text-xs" placeholder="Required for changes requested or final rejection" />
          </label>
          <div className="flex flex-wrap gap-2 lg:col-span-2 lg:justify-end">
            <button type="button" disabled={!props.canPromote || props.pending || props.reviewDecisionReason.trim().length < 8} onClick={props.onReject} className="secondary-action border-red-900 text-red-200 disabled:opacity-40">Reject revision</button>
            <button type="button" disabled={!props.canPromote || props.pending || props.reviewDecisionReason.trim().length < 8} onClick={props.onRequestChanges} className="secondary-action border-amber-800 text-amber-200 disabled:opacity-40">Request changes</button>
            <button type="button" disabled={!props.canPromote || props.pending} onClick={props.onApprove} className="primary-action disabled:opacity-40">Approve reviewed revision</button>
          </div>
        </div>
      )}
      {review.state === 'approved' && (
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(320px,1fr)_minmax(0,1fr)_auto]">
          <fieldset disabled={!props.canPromote || props.pending} className="rounded border border-gray-800 bg-gray-950/30 p-3 disabled:opacity-60">
            <legend className="px-1 text-xs font-semibold text-gray-300">Promotion targets</legend>
            <p className="mb-2 text-[11px] leading-4 text-gray-500">Canonical intelligence is always written. Select any additional governed consumers for this promotion.</p>
            <div className="space-y-2">
              <label className="flex items-start gap-2 text-xs text-gray-300">
                <input type="checkbox" checked disabled className="mt-0.5" />
                <span><span className="font-medium text-white">Canonical intelligence</span><span className="ml-1 text-[10px] uppercase tracking-wide text-emerald-400">required</span></span>
              </label>
              {OPTIONAL_PROMOTION_TARGETS.map(target => (
                <label key={target.value} className="flex items-start gap-2 text-xs text-gray-300">
                  <input
                    type="checkbox"
                    checked={props.promotionTargets.includes(target.value)}
                    onChange={event => props.setPromotionTargets(event.target.checked
                      ? [...props.promotionTargets, target.value]
                      : props.promotionTargets.filter(value => value !== target.value))}
                    className="mt-0.5"
                  />
                  <span><span className="font-medium text-white">{target.label}</span><span className="block text-[10px] leading-4 text-gray-500">{target.description}</span></span>
                </label>
              ))}
            </div>
          </fieldset>
          <label className="text-xs text-gray-400">Promotion note (optional)
            <textarea value={props.promotionNote} onChange={event => props.setPromotionNote(event.target.value)} disabled={!props.canPromote || props.pending} className="field mt-1 h-16 w-full resize-y text-xs" />
          </label>
          <button type="button" disabled={!props.canPromote || props.pending || !review.readiness.ready} onClick={props.onPromote} className="primary-action self-end disabled:opacity-40">Promote accepted claims</button>
        </div>
      )}
      {review.state === 'promoted' && (
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
          <label className="text-xs text-gray-400">Revocation reason
            <textarea value={props.revocationReason} onChange={event => props.setRevocationReason(event.target.value)} disabled={!props.canPromote || props.pending} className="field mt-1 h-16 w-full resize-y text-xs" placeholder="Required operational reason; revocation remains in history." />
          </label>
          <button type="button" disabled={!props.canPromote || props.pending || props.revocationReason.trim().length < 8} onClick={props.onRevoke} className="secondary-action self-end border-red-800 text-red-200 disabled:opacity-40">Revoke promotion</button>
        </div>
      )}
    </section>
  );
}

function History({ events, loading }: { events: Array<{ id?: string; event_type?: string; action?: string; actor?: string; reviewer?: string; summary?: string; created_at?: string; occurred_at?: string; details?: Record<string, unknown> }>; loading: boolean }) {
  return (
    <details className="rounded border border-gray-800 bg-gray-950/30">
      <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-gray-200">Immutable review history ({events.length})</summary>
      <div className="border-t border-gray-800 p-4">
        {loading && <div className="text-xs text-gray-500">Loading history…</div>}
        {!loading && events.length === 0 && <div className="text-xs text-gray-600">No lifecycle events recorded.</div>}
        <ol className="space-y-3">
          {events.map((event, index) => (
            <li key={event.id || `${event.created_at}-${index}`} className="rounded border border-gray-800 bg-gray-950 p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-gray-200">{event.event_type || event.action || 'review_event'}</span>
                <time className="text-gray-600">{formatDate(event.created_at || event.occurred_at)}</time>
              </div>
              <div className="mt-1 text-gray-500">{event.actor || event.reviewer || 'system'}{event.summary ? ` · ${event.summary}` : ''}</div>
              {event.details && Object.keys(event.details).length > 0 && <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-words rounded bg-black/40 p-2 font-mono text-[10px] text-gray-600">{JSON.stringify(event.details, null, 2)}</pre>}
            </li>
          ))}
        </ol>
      </div>
    </details>
  );
}

function AiAdvisoryReceipt({ advisory }: { advisory: ReportReviewAiAdvisory }) {
  const coverage = advisory.coverage;
  const parts = advisory.parts ?? [];
  return (
    <div role="status" className="mt-3 rounded border border-violet-800/60 bg-violet-950/25 p-2 text-[11px] leading-5 text-violet-100/80">
      <div className="font-semibold">Advisory received · not authoritative</div>
      <div>{[advisory.provider, advisory.model, advisory.prompt_version].filter(Boolean).join(' · ') || advisory.summary || 'Source-bound suggestions were returned for analyst review.'}</div>
      {advisory.suggested_claim_count != null && <div>{advisory.suggested_claim_count} new claim suggestion{advisory.suggested_claim_count === 1 ? '' : 's'} persisted; every suggestion still requires analyst adjudication.</div>}
      {coverage && <div>Source coverage: {coverage.analyzed_char_count ?? '?'} / {coverage.source_char_count ?? '?'} chars{coverage.complete === false ? ' · incomplete' : ''}</div>}
      {!coverage && (advisory.coverage_chars != null || advisory.source_chars != null) && <div>Source coverage: {advisory.coverage_chars ?? '?'} / {advisory.source_chars ?? '?'} chars{advisory.complete_coverage === false ? ' · incomplete' : ''}</div>}
      {(advisory.warnings ?? []).map((warning, index) => <div key={`${warning}-${index}`} className="text-amber-200">{warning}</div>)}
      {parts.length > 0 && (
        <details className="mt-2 border-t border-violet-800/50 pt-2">
          <summary className="cursor-pointer font-semibold">Inspect AI advisory evidence ({parts.length} source chunk{parts.length === 1 ? '' : 's'})</summary>
          <div className="mt-2 space-y-2">
            {parts.map((part, index) => <AiAdvisoryPart key={index} part={part} ordinal={index + 1} />)}
          </div>
        </details>
      )}
    </div>
  );
}

function AiAdvisoryPart({ part, ordinal }: { part: Record<string, unknown>; ordinal: number }) {
  const relevance = recordValue(part.procedure_relevance);
  const actor = recordValue(part.actor_identification);
  const claims = Array.isArray(part.procedure_claims) ? part.procedure_claims.map(recordValue).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
  const dates = Array.isArray(part.publication_date_candidates) ? part.publication_date_candidates.map(recordValue).filter((item): item is Record<string, unknown> => Boolean(item)) : [];
  return (
    <div className="rounded border border-violet-900/60 bg-black/20 p-2">
      <div className="font-semibold">Chunk {ordinal}</div>
      {relevance && <div>Procedure relevance: {String(relevance.verdict || 'inconclusive')} · {String(relevance.rationale || 'No rationale')}</div>}
      {actor && <div>Actor lead: {String(actor.verdict || 'inconclusive')} · basis {String(actor.basis || 'unknown')}{actor.actor_name ? ` · ${String(actor.actor_name)}` : ''}</div>}
      {claims.length > 0 && (
        <ul className="mt-1 list-disc space-y-1 pl-4">
          {claims.map((claim, index) => <li key={index}>{[claim.subject, claim.action, claim.object].filter(Boolean).map(String).join(' · ')}{claim.attack_id ? ` · ${String(claim.attack_id)}` : ''}</li>)}
        </ul>
      )}
      {dates.length > 0 && <div>Publication date candidates: {dates.map(date => String(date.value || '')).filter(Boolean).join(', ')}</div>}
    </div>
  );
}

function EvidenceCard({ evidence }: { evidence: ReportReviewEvidenceRef }) {
  const start = evidence.evidence_start ?? evidence.start;
  const end = evidence.evidence_end ?? evidence.end;
  const path = evidencePath(evidence);
  return (
    <div className="rounded border border-gray-800 bg-black/30 p-2 text-xs leading-5 text-gray-400">
      <div className="flex flex-wrap gap-x-3 text-[10px] uppercase tracking-wide text-gray-600">
        <span>{String(evidence.kind || evidence.type || evidence.source || 'source evidence')}</span>
        {(start != null || end != null) && <span className="font-mono">offset {String(start ?? '?')}–{String(end ?? '?')}</span>}
        {evidence.locator && <span className="font-mono normal-case">{formatLocator(evidence.locator)}</span>}
        {path && <span className="font-mono normal-case">{path}</span>}
      </div>
      <div className="mt-1 whitespace-pre-wrap break-words">{evidenceText(evidence)}</div>
    </div>
  );
}

function VerdictBadge({ verdict, kind }: { verdict: string; kind: 'machine' | 'analyst' }) {
  const good = verdict === 'pass';
  const bad = verdict === 'fail';
  const warning = verdict === 'warning' || verdict === 'needs_information';
  const tone = good ? 'border-emerald-800 text-emerald-200' : bad ? 'border-red-800 text-red-200' : warning ? 'border-amber-800 text-amber-200' : 'border-gray-700 text-gray-400';
  return <span aria-label={`${kind} verdict: ${humanize(verdict)}`} className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${tone}`}>{humanize(verdict)}</span>;
}

function ClaimStatusBadge({ status }: { status: ReportReviewClaimStatus }) {
  const tone = status === 'accepted' ? 'border-emerald-800 text-emerald-200' : status === 'rejected' ? 'border-red-800 text-red-200' : status === 'needs_evidence' ? 'border-amber-800 text-amber-200' : 'border-gray-700 text-gray-400';
  return <span className={`rounded border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${tone}`}>{humanize(status)}</span>;
}

function OverviewMetric({ label, value, tone }: { label: string; value: string; tone: 'default' | 'good' | 'warn' }) {
  const color = tone === 'good' ? 'text-emerald-200' : tone === 'warn' ? 'text-amber-200' : 'text-white';
  return <div className="rounded border border-gray-800 bg-gray-950/60 p-3"><div className={`text-lg font-semibold ${color}`}>{value}</div><div className="text-[10px] uppercase tracking-wide text-gray-600">{label}</div></div>;
}

function blankGateDraft(): GateDraft {
  return { verdict: 'pending', reasonCode: '', rationale: '', selectedEvidence: [] };
}

function blankManualClaim(): ManualClaimDraft {
  return {
    claimType: 'procedure',
    subject: '',
    predicate: '',
    object: '',
    statement: '',
    attackId: '',
    actorId: '',
    indicatorType: 'ipv4',
    attributionBasis: 'source_reported',
    evidenceStart: '',
    evidenceEnd: '',
  };
}

function validateManualClaim(draft: ManualClaimDraft, sourceText: string) {
  if (!sourceText) return 'Stored source text is required.';
  if (!draft.subject.trim() || !draft.predicate.trim() || !draft.object.trim()) return 'Subject, predicate, and object are required.';
  if (draft.statement.trim().length < 16) return 'Write a specific claim statement of at least 16 characters.';
  if (draft.claimType === 'procedure' && !/^T\d{4}(?:\.\d{3})?$/.test(draft.attackId.trim())) return 'A valid ATT&CK technique ID is required for a procedure claim.';
  if (draft.claimType === 'actor' && !draft.actorId.trim()) return 'A stable actor identifier is required for an actor claim.';
  if (draft.claimType === 'publication_date' && !/^\d{4}-\d{2}-\d{2}$/.test(draft.object.trim())) return 'Publication-date claim object must use YYYY-MM-DD.';
  const start = Number(draft.evidenceStart);
  const end = Number(draft.evidenceEnd);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end <= start || end > sourceText.length) return `Evidence offsets must select a valid span within 0–${sourceText.length}.`;
  if (end - start > 2_000) return 'Select an evidence span of 2,000 characters or fewer.';
  if (!sourceText.slice(start, end).trim()) return 'The selected source span is empty.';
  return '';
}

function validateGateDraft(draft: GateDraft, evidence: ReportReviewEvidenceRef[], gateKey: ReportReviewGateKey, claims: ReportReviewClaim[]) {
  if (draft.verdict === 'pending') return 'Choose an analyst verdict.';
  if (!draft.reasonCode.trim()) return 'A reason code is required.';
  if (draft.rationale.trim().length < 8) return 'Add a rationale of at least 8 characters.';
  if (draft.verdict === 'pass') {
    const acceptedType = gateKey === 'publication_date' ? 'publication_date'
      : gateKey === 'actor_identification' ? 'actor'
        : ['procedure_relevance', 'procedure_level_claim'].includes(gateKey) ? 'procedure' : '';
    const acceptedClaimSupportsGate = Boolean(acceptedType && claims.some(claim => claim.status === 'accepted' && claim.claim_type === acceptedType));
    if (evidence.length === 0 && !acceptedClaimSupportsGate) return acceptedType
      ? `Accept a source-bound ${humanize(acceptedType)} claim before passing this gate.`
      : 'A passing decision must cite stored evidence.';
  }
  return '';
}

function assessmentComplete(review: ReportReviewAssessment) {
  const requiredGatesComplete = review.gates.every(gate => gate.required === false || gate.analyst_verdict !== 'pending');
  const allClaimsAdjudicated = review.claims.every(claim => claim.status !== 'suggested');
  return requiredGatesComplete && allClaimsAdjudicated;
}

function defaultReasonCode(gateKey: ReportReviewGateKey, verdict: ReportReviewAnalystVerdict) {
  const byGate: Record<ReportReviewGateKey, Partial<Record<ReportReviewAnalystVerdict, string>>> = {
    source_provenance: { pass: 'source_verified', fail: 'source_mismatch', needs_information: 'insufficient_provenance' },
    publication_date: { pass: 'date_verified', fail: 'date_conflict', needs_information: 'date_unverified', not_applicable: 'internal_record_no_publication' },
    procedure_relevance: { pass: 'procedure_relevant', fail: 'not_security_procedure', needs_information: 'insufficient_procedure_context' },
    procedure_level_claim: { pass: 'source_bound_claims', fail: 'generic_tool_only', needs_information: 'claim_not_source_bound' },
    actor_identification: { pass: 'explicit_attribution', fail: 'tooling_overlap_only', needs_information: 'conflicting_attribution', not_applicable: 'no_actor_claim' },
  };
  if (verdict === 'pending') return '';
  return byGate[gateKey][verdict] || '';
}

function normalizeReasonCode(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80);
}

function uniqueEvidence(refs: ReportReviewEvidenceRef[]) {
  const seen = new Set<string>();
  return refs.filter((ref, index) => {
    const key = evidenceKey(ref, index);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function evidenceKey(ref: ReportReviewEvidenceRef, index = 0) {
  const start = ref.evidence_start ?? ref.start ?? '';
  const end = ref.evidence_end ?? ref.end ?? '';
  const content = firstEvidenceValue(ref.excerpt, ref.quote, ref.value, ref.label) ?? index;
  return String(ref.id || `${ref.kind || ref.type || ref.source || 'evidence'}:${start}:${end}:${evidencePath(ref)}:${formatEvidenceValue(content)}`);
}

function evidenceText(ref: ReportReviewEvidenceRef) {
  const value = firstEvidenceValue(ref.excerpt, ref.quote, ref.value, ref.label, ref.source_url) ?? 'Stored evidence reference';
  return formatEvidenceValue(value).slice(0, 600);
}

function evidencePath(ref: ReportReviewEvidenceRef) {
  const nestedPath = ref.metadata?.path;
  const value = firstEvidenceValue(ref.path, typeof nestedPath === 'string' ? nestedPath : '') ?? '';
  return String(value).slice(0, 300);
}

function firstEvidenceValue(...values: unknown[]) {
  return values.find(value => value != null && (typeof value !== 'string' || value.trim().length > 0));
}

function formatEvidenceValue(value: unknown) {
  if (typeof value === 'string') return value;
  if (value !== null && typeof value === 'object') {
    try { return JSON.stringify(value); } catch { return String(value); }
  }
  return String(value);
}

function formatLocator(locator: string | Record<string, unknown>) {
  if (typeof locator === 'string') return locator.slice(0, 180);
  return JSON.stringify(locator).slice(0, 180);
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function claimHasBoundEvidence(claim: ReportReviewClaim) {
  if ((claim.evidence_refs ?? []).some(ref => ref.evidence_start != null || ref.locator || ref.id)) return true;
  return Boolean(claim.evidence_text && claim.evidence_start != null && claim.evidence_end != null && claim.evidence_end > claim.evidence_start);
}

function claimAcceptanceBlocker(claim: ReportReviewClaim) {
  if (!claim.statement?.trim() && !claim.claim?.trim() && !claim.title?.trim()) return 'The claim has no specific statement.';
  if (!claim.object?.trim()) return 'The claim has no specific object or outcome.';
  if (!claimHasBoundEvidence(claim)) return 'No exact source-bound evidence is attached.';
  if (claim.claim_type === 'procedure') {
    const attackId = claim.attack_id || claim.attack_ids?.[0] || '';
    if (!/^T\d{4}(?:\.\d{3})?$/.test(attackId)) return 'The procedure has no valid ATT&CK or ATLAS technique ID.';
    if (claim.metadata?.llm_verified !== true) return 'The technique ID is not verified in the active local catalog.';
    const action = (claim.predicate || claim.action || '').trim().toLowerCase();
    const statement = claim.statement || claim.claim || '';
    if (!action || (['uses', 'used', 'performed procedure'].includes(action) && statement.length < 30)) return 'The procedure is a generic tool or label mention.';
  }
  if (claim.claim_type === 'actor') {
    const basis = String(claim.metadata?.attribution_basis || '');
    if (!['explicit', 'source_reported'].includes(basis)) return 'Actor attribution is inferred, conflicting, absent, or based only on tooling overlap.';
    if (!(claim.actor_id || claim.actor_ids?.[0])) return 'The actor has no stable identifier or exact source-reported name.';
  }
  if (claim.claim_type === 'publication_date' && !/^\d{4}-\d{2}-\d{2}/.test(String(claim.metadata?.date_candidate || claim.object || ''))) return 'The publication date is not a valid ISO calendar date.';
  return '';
}

function machineSummary(gate?: ReportReviewGate) {
  if (!gate) return 'Preflight has not created this gate finding.';
  if (gate.machine_summary) return gate.machine_summary;
  const details = gate.machine_details;
  if (details) {
    for (const key of ['summary', 'reason', 'message', 'finding']) {
      if (typeof details[key] === 'string' && details[key]) return details[key] as string;
    }
  }
  return gate.machine_verdict === 'not_run' ? 'Run deterministic preflight to calculate this finding.' : `Deterministic evaluator returned ${humanize(gate.machine_verdict)}.`;
}

function analystReviewMetadata(gate?: ReportReviewGate) {
  if (!gate?.reviewed_by) return 'No analyst decision saved.';
  return `Last saved by ${gate.reviewed_by}${gate.reviewed_at ? ` · ${formatDate(gate.reviewed_at)}` : ''}`;
}

function shortChecksum(value?: string) {
  return value ? `${value.slice(0, 12)}…` : 'pending';
}

function humanize(value: string) {
  return value.replace(/_/g, ' ');
}

function formatDate(value?: string | null) {
  if (!value) return 'time unavailable';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function isVersionConflict(message: string) {
  return /\b(409|conflict|version|stale|checksum|changed)\b/i.test(message);
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : 'No review was returned.';
}

function unwrapAssessment(value: ReportReviewAssessment | { assessment?: ReportReviewAssessment; review?: ReportReviewAssessment }): ReportReviewAssessment {
  if ('assessment' in value && value.assessment) return value.assessment;
  if ('review' in value && value.review) return value.review;
  return value as ReportReviewAssessment;
}
