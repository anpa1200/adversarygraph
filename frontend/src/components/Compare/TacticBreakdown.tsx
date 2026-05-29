/**
 * Per-tactic breakdown table and stacked bar chart.
 * Shows: shared | user-only | APT-only counts per tactic.
 */

import { useMemo } from 'react';
import type { Tactic, TechniqueListItem } from '@/types/attack';

interface Row {
  tactic: string;
  shortname: string;
  shared: number;
  userOnly: number;
  aptOnly: number;
  total: number;
}

interface Props {
  tactics: Tactic[];
  techniquesByTactic: Map<string, TechniqueListItem[]>;
  userIds: Set<string>;
  aptIds: Set<string>;
}

export function TacticBreakdown({ tactics, techniquesByTactic, userIds, aptIds }: Props) {
  const rows: Row[] = useMemo(() => {
    return tactics
      .map(tactic => {
        const techs = techniquesByTactic.get(tactic.shortname) ?? [];
        const shared   = techs.filter(t => userIds.has(t.attack_id) && aptIds.has(t.attack_id)).length;
        const userOnly = techs.filter(t => userIds.has(t.attack_id) && !aptIds.has(t.attack_id)).length;
        const aptOnly  = techs.filter(t => !userIds.has(t.attack_id) && aptIds.has(t.attack_id)).length;
        return { tactic: tactic.name, shortname: tactic.shortname, shared, userOnly, aptOnly, total: shared + userOnly + aptOnly };
      })
      .filter(r => r.total > 0)
      .sort((a, b) => b.total - a.total);
  }, [tactics, techniquesByTactic, userIds, aptIds]);

  if (rows.length === 0) {
    return <div className="text-gray-600 text-xs py-6 text-center">No overlap data yet.</div>;
  }

  const maxTotal = Math.max(...rows.map(r => r.total), 1);

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="grid text-[10px] text-gray-500 font-semibold uppercase tracking-wide"
           style={{ gridTemplateColumns: '130px 1fr 36px 36px 36px' }}>
        <span>Tactic</span>
        <span>Distribution</span>
        <span className="text-center text-[#e94560]">You</span>
        <span className="text-center text-blue-400">APT</span>
        <span className="text-center text-amber-400">Both</span>
      </div>

      {rows.map(row => (
        <div
          key={row.shortname}
          className="grid items-center gap-2"
          style={{ gridTemplateColumns: '130px 1fr 36px 36px 36px' }}
        >
          {/* Tactic name */}
          <div className="text-xs text-gray-300 truncate" title={row.tactic}>
            {row.tactic}
          </div>

          {/* Stacked bar */}
          <div className="h-5 flex rounded overflow-hidden bg-gray-800">
            {row.shared > 0 && (
              <div
                style={{ flex: row.shared, background: '#f59e0b' }}
                title={`${row.shared} shared`}
              />
            )}
            {row.userOnly > 0 && (
              <div
                style={{ flex: row.userOnly, background: '#e94560' }}
                title={`${row.userOnly} your TTPs only`}
              />
            )}
            {row.aptOnly > 0 && (
              <div
                style={{ flex: row.aptOnly, background: '#3b82f6' }}
                title={`${row.aptOnly} APT only`}
              />
            )}
            {/* spacer to reach maxTotal */}
            <div style={{ flex: maxTotal - row.total }} />
          </div>

          {/* Counts */}
          <div className="text-center text-[10px] text-red-400">{row.userOnly + row.shared}</div>
          <div className="text-center text-[10px] text-blue-400">{row.aptOnly  + row.shared}</div>
          <div className="text-center text-[10px] text-amber-400">{row.shared}</div>
        </div>
      ))}
    </div>
  );
}
