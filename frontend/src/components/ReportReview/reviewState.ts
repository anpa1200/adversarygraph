import type { ReportCollectionItem, ReportReviewAssessment, ReportReviewCollectionSummary, ReportReviewState } from '@/api/client';

export type DisplayReviewState = ReportReviewState | 'unreviewed';

export const REVIEW_STATE_LABELS: Record<DisplayReviewState, string> = {
  unreviewed: 'Unreviewed',
  draft: 'Draft review',
  in_review: 'In review',
  changes_requested: 'Changes requested',
  approved: 'Approved',
  promoted: 'Promoted',
  stale: 'Stale review',
  rejected: 'Rejected',
  revoked: 'Revoked',
};

export function reportReviewSummary(item: ReportCollectionItem): ReportReviewCollectionSummary {
  const nested = item.review_summary ?? item.review;
  const state = item.review_state ?? nested?.state ?? legacyReviewState(item.status);
  const reviewed = numberOrZero(nested?.reviewed_gate_count);
  const required = numberOrZero(nested?.required_gate_count);
  const blockers = Array.isArray(nested?.blockers) ? nested.blockers.filter(Boolean) : [];
  return {
    state,
    ready: Boolean(nested?.ready ?? (state === 'approved' || state === 'promoted')),
    reviewed_gate_count: reviewed,
    required_gate_count: required,
    accepted_claim_count: numberOrZero(nested?.accepted_claim_count),
    blocker_count: numberOrZero(nested?.blocker_count) || blockers.length,
    blockers,
  };
}

export function reviewStateLabel(state: DisplayReviewState) {
  return REVIEW_STATE_LABELS[state];
}

export function isReportReviewAssessment(value: unknown): value is ReportReviewAssessment {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Partial<ReportReviewAssessment>;
  return typeof candidate.session_id === 'string'
    && typeof candidate.profile === 'string'
    && typeof candidate.state === 'string'
    && Number.isInteger(candidate.version)
    && Array.isArray(candidate.gates)
    && Array.isArray(candidate.claims)
    && Boolean(candidate.readiness)
    && typeof candidate.readiness === 'object'
    && !Array.isArray(candidate.readiness);
}

function legacyReviewState(status: string): DisplayReviewState {
  const value = String(status || '').toLowerCase();
  if (value === 'promoted') return 'promoted';
  if (value === 'rejected') return 'rejected';
  if (value === 'reviewing' || value === 'in_review') return 'in_review';
  return 'unreviewed';
}

function numberOrZero(value: unknown) {
  const result = Number(value);
  return Number.isFinite(result) && result > 0 ? result : 0;
}
