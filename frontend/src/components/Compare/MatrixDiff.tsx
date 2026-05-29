/**
 * Compact visual diff of two TTP sets on the ATT&CK matrix.
 *
 * Each column = one tactic.
 * Each strip  = one technique (8 px tall, no text — hover shows name/ID).
 * Colours: red = user only | blue = APT only | amber = shared | dark = neither
 *
 * Uses D3 colour interpolation for the gradient scale used on "score" export.
 */

import { useMemo } from 'react';
import * as d3 from 'd3';
import type { Tactic, TechniqueListItem } from '@/types/attack';

interface Props {
  tactics: Tactic[];
  techniquesByTactic: Map<string, TechniqueListItem[]>;
  userIds: Set<string>;
  aptIds: Set<string>;
  /** If true, hide cells that appear in neither set */
  diffOnly?: boolean;
}

// D3 colour scale used for blending — kept here so it's reusable in Phase 5
const _blendScale = d3
  .scaleLinear<string>()
  .domain([0, 0.5, 1])
  .range(['#1f2937', '#3b82f6', '#e94560'])
  .interpolate(d3.interpolateRgb.gamma(2.2));

function cellColor(id: string, userIds: Set<string>, aptIds: Set<string>): string {
  const u = userIds.has(id);
  const a = aptIds.has(id);
  if (u && a) return '#f59e0b';
  if (u)      return '#e94560';
  if (a)      return '#3b82f6';
  return '#111827';
}

export function MatrixDiff({ tactics, techniquesByTactic, userIds, aptIds, diffOnly = false }: Props) {
  const columns = useMemo(() => {
    return tactics.map(tactic => {
      let techs = techniquesByTactic.get(tactic.shortname) ?? [];
      if (diffOnly) {
        techs = techs.filter(t => userIds.has(t.attack_id) || aptIds.has(t.attack_id));
      }
      return { tactic, techs };
    }).filter(c => c.techs.length > 0);
  }, [tactics, techniquesByTactic, userIds, aptIds, diffOnly]);

  if (columns.length === 0) {
    return (
      <div className="text-center text-gray-600 text-xs py-8">
        No techniques to display. Select TTPs first.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      {/* Legend */}
      <div className="flex gap-4 mb-3 text-[10px] text-gray-400">
        <LegendDot color="#e94560" label="Your TTPs" />
        <LegendDot color="#3b82f6" label="APT group" />
        <LegendDot color="#f59e0b" label="Shared" />
        {!diffOnly && <LegendDot color="#111827" label="Neither" />}
      </div>

      <div className="flex gap-1">
        {columns.map(({ tactic, techs }) => (
          <div key={tactic.shortname} style={{ minWidth: 52 }}>
            {/* Tactic label */}
            <div
              className="text-[8px] text-center text-gray-400 mb-1 leading-tight"
              title={tactic.name}
            >
              {tactic.name.length > 8 ? tactic.name.slice(0, 7) + '…' : tactic.name}
            </div>

            {/* Technique strips */}
            {techs.map(tech => {
              const color = cellColor(tech.attack_id, userIds, aptIds);
              const isActive = color !== '#111827';
              return (
                <div
                  key={tech.attack_id}
                  style={{
                    height: 7,
                    marginBottom: 1,
                    background: color,
                    borderRadius: 1,
                    opacity: isActive ? 1 : 0.25,
                    cursor: 'default',
                  }}
                  title={`${tech.attack_id} — ${tech.name}`}
                />
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1">
      <div style={{ width: 10, height: 10, background: color, borderRadius: 2 }} />
      <span>{label}</span>
    </div>
  );
}
