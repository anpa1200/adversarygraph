import type { ThreatHuntPriority, ThreatHuntStatus } from '@/api/client';
import { cn } from '@/utils/cn';

const STATUS_TONES: Record<ThreatHuntStatus, string> = {
  queued: 'border-slate-600 bg-slate-900/70 text-slate-200',
  draft: 'border-gray-700 bg-gray-900 text-gray-300',
  planned: 'border-sky-700/70 bg-sky-950/50 text-sky-200',
  running: 'border-cyan-600/70 bg-cyan-950/50 text-cyan-100',
  review: 'border-amber-600/70 bg-amber-950/50 text-amber-100',
  completed: 'border-emerald-700/70 bg-emerald-950/50 text-emerald-100',
  cancelled: 'border-rose-900/70 bg-rose-950/30 text-rose-300',
  archived: 'border-gray-800 bg-gray-950 text-gray-500',
};

const PRIORITY_TONES: Record<ThreatHuntPriority, string> = {
  'P0 Emergency': 'border-red-500/70 bg-red-950/60 text-red-100',
  'P1 High': 'border-orange-600/70 bg-orange-950/50 text-orange-100',
  'P2 Medium': 'border-amber-700/70 bg-amber-950/40 text-amber-100',
  'P3 Monitor': 'border-sky-800/70 bg-sky-950/35 text-sky-200',
  'P4 Low/Archive': 'border-gray-700 bg-gray-950 text-gray-400',
};

export function HuntStatusPill({ status }: { status: ThreatHuntStatus }) {
  return (
    <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize', STATUS_TONES[status])}>
      {status}
    </span>
  );
}

export function HuntPriorityPill({ priority }: { priority: ThreatHuntPriority }) {
  return (
    <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold', PRIORITY_TONES[priority])}>
      {priority}
    </span>
  );
}
