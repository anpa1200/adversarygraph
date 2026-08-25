import { REVIEW_STATE_LABELS, type DisplayReviewState } from './reviewState';

export function ReviewStateBadge({ state, compact = false }: { state: DisplayReviewState; compact?: boolean }) {
  return (
    <span
      aria-label={`Report review state: ${REVIEW_STATE_LABELS[state]}`}
      className={`inline-flex items-center gap-1.5 rounded border font-semibold ${compact ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-1 text-xs'} ${stateTone(state)}`}
    >
      <span aria-hidden="true">{stateIcon(state)}</span>
      {REVIEW_STATE_LABELS[state]}
    </span>
  );
}

function stateIcon(state: DisplayReviewState) {
  if (state === 'approved' || state === 'promoted') return '✓';
  if (state === 'changes_requested' || state === 'stale') return '!';
  if (state === 'rejected' || state === 'revoked') return '×';
  if (state === 'in_review') return '◐';
  return '○';
}

function stateTone(state: DisplayReviewState) {
  if (state === 'approved' || state === 'promoted') return 'border-emerald-700 bg-emerald-950/40 text-emerald-200';
  if (state === 'changes_requested' || state === 'stale') return 'border-amber-700 bg-amber-950/40 text-amber-200';
  if (state === 'rejected' || state === 'revoked') return 'border-red-800 bg-red-950/40 text-red-200';
  if (state === 'in_review') return 'border-cyan-700 bg-cyan-950/40 text-cyan-200';
  return 'border-gray-700 bg-gray-950 text-gray-300';
}
