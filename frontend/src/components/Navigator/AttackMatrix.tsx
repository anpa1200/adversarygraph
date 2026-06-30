/**
 * D3-powered ATT&CK matrix.
 *
 * D3 responsibilities:
 *   - zoom / pan on the outer container (d3-zoom)
 *   - color interpolation for dual-layer blending (d3-interpolate)
 *
 * React responsibilities:
 *   - rendering every cell (avoids SVG foreignObject hacks)
 *   - all click / keyboard events
 */

import { useRef, useEffect, useCallback, useMemo } from 'react';
import * as d3 from 'd3';
import type { Tactic, TechniqueListItem } from '@/types/attack';
import type { MatrixData } from '@/hooks/useAttackMatrix';
import type { ComparisonLayer } from '@/store';

// ── Cell dimensions (px, pre-zoom) ───────────────────────────────────────────
const COL_WIDTH = 138;
const PARENT_CELL_H = 52;
const SUB_CELL_H = 38;
const TACTIC_HEADER_H = 56;
const COL_GAP = 3;

// ── Layer colour system ───────────────────────────────────────────────────────
// Uses D3 colour interpolation so blended colours stay perceptually smooth.

const COLORS = {
  userOnly:    { bg: '#7f1d1d', border: '#e94560', id: '#fca5a5', name: '#fff' },
  overlayOnly: { bg: '#1e3a5f', border: '#3b82f6', id: '#93c5fd', name: '#dbeafe' },
  shared:      { bg: '#78350f', border: '#f59e0b', id: '#fde68a', name: '#fef3c7' },
  none:        { bg: '#1f2937', border: '#374151', id: '#4b5563', name: '#6b7280' },
} as const;

function cellColors(
  id: string,
  selected: Set<string>,
  overlay: Set<string>,
  comparisonLayers: ComparisonLayer[] = []
) {
  const sel = selected.has(id);
  const matchedLayers = comparisonLayers.filter(layer => layer.techniqueIds.includes(id));
  const ov  = overlay.has(id) || matchedLayers.length > 0;
  const layerColors = matchedLayers.map(layer => layer.color);
  if (sel && ov) return layeredColors([COLORS.userOnly.border, ...layerColors], true);
  if (matchedLayers.length > 1) return layeredColors(layerColors, false);
  if (matchedLayers.length === 1 && matchedLayers[0].color.toLowerCase() === '#ffffff') {
    return { bg: 'rgba(255,255,255,0.16)', border: '#ffffff', id: '#ffffff', name: '#f8fafc' };
  }
  if (matchedLayers.length === 1) return { bg: `${matchedLayers[0].color}33`, border: matchedLayers[0].color, id: '#dbeafe', name: '#f8fafc' };
  if (sel)       return COLORS.userOnly;
  if (ov)        return COLORS.overlayOnly;
  return COLORS.none;
}

function layeredColors(colors: string[], shared: boolean) {
  const safeColors = colors.length ? colors : [COLORS.shared.border];
  const stops = safeColors.map((color, index) => {
    const start = Math.round((index / safeColors.length) * 100);
    const end = Math.round(((index + 1) / safeColors.length) * 100);
    return `${color}55 ${start}% ${end}%`;
  }).join(', ');
  return {
    bg: `linear-gradient(135deg, ${stops})`,
    border: shared ? COLORS.shared.border : safeColors[0],
    id: shared ? COLORS.shared.id : '#dbeafe',
    name: shared ? COLORS.shared.name : '#f8fafc',
  };
}

// ── Component props ───────────────────────────────────────────────────────────

interface Props extends Pick<MatrixData, 'tactics' | 'techniquesByTactic' | 'subtechsByParent' | 'parentsWithSubs'> {
  selectedTechniques: Set<string>;
  overlayTechniques:  Set<string>;
  comparisonLayers: ComparisonLayer[];
  coverageTechniques: Set<string>;
  simulationTechniques?: Set<string>;
  simulationMode?: boolean;
  expandedTechniques: Set<string>;
  onToggleTechnique:  (id: string) => void;
  onToggleExpanded:   (id: string) => void;
}

// ── Main component ────────────────────────────────────────────────────────────

export function AttackMatrix({
  tactics,
  techniquesByTactic,
  subtechsByParent,
  parentsWithSubs,
  selectedTechniques,
  overlayTechniques,
  comparisonLayers,
  coverageTechniques,
  simulationTechniques = new Set<string>(),
  simulationMode = false,
  expandedTechniques,
  onToggleTechnique,
  onToggleExpanded,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const innerRef     = useRef<HTMLDivElement>(null);

  // ── D3 zoom setup ───────────────────────────────────────────────────────────
  useEffect(() => {
    const container = containerRef.current;
    const inner     = innerRef.current;
    if (!container || !inner) return;

    const zoom = d3
      .zoom<HTMLDivElement, unknown>()
      .scaleExtent([0.15, 2.5])
      // Prevent zoom hijacking clicks on cells
      .filter((event) => {
        const target = event.target as HTMLElement;
        return !target.closest('[data-matrix-cell]') || event.type !== 'mousedown';
      })
      .on('zoom', (event: d3.D3ZoomEvent<HTMLDivElement, unknown>) => {
        const { x, y, k } = event.transform;
        inner.style.transform = `translate(${x}px,${y}px) scale(${k})`;
      });

    const sel = d3.select(container);
    sel.call(zoom);
    // Start slightly zoomed out so the full matrix is visible
    sel.call(zoom.transform, d3.zoomIdentity.translate(16, 16).scale(0.82));

    // Double-click resets to initial view instead of zooming in
    sel.on('dblclick.zoom', () =>
      sel.transition().duration(400).call(zoom.transform, d3.zoomIdentity.translate(16, 16).scale(0.82))
    );

    return () => {
      sel.on('.zoom', null);
      sel.on('dblclick.zoom', null);
    };
  }, []); // mount-only

  // Memoised stable callbacks so cells don't re-render on zoom
  const handleToggle   = useCallback(onToggleTechnique, [onToggleTechnique]);
  const handleExpanded = useCallback(onToggleExpanded,  [onToggleExpanded]);

  return (
    <div
      ref={containerRef}
      className="w-full h-full overflow-hidden select-none"
      style={{ background: '#0d1117', cursor: 'grab' }}
    >
      {/* transformOrigin top-left so D3 transform coords are intuitive */}
      <div
        ref={innerRef}
        className="flex gap-[3px] p-2"
        style={{ transformOrigin: '0 0', willChange: 'transform' }}
      >
        {tactics.map((tactic) => (
          <TacticColumn
            key={tactic.shortname}
            tactic={tactic}
            techniques={techniquesByTactic.get(tactic.shortname) ?? []}
            subtechsByParent={subtechsByParent}
            parentsWithSubs={parentsWithSubs}
            selectedTechniques={selectedTechniques}
            overlayTechniques={overlayTechniques}
            comparisonLayers={comparisonLayers}
            coverageTechniques={coverageTechniques}
            simulationTechniques={simulationTechniques}
            simulationMode={simulationMode}
            expandedTechniques={expandedTechniques}
            onToggle={handleToggle}
            onToggleExpanded={handleExpanded}
          />
        ))}
      </div>
    </div>
  );
}

// ── Tactic column ─────────────────────────────────────────────────────────────

interface ColumnProps {
  tactic: Tactic;
  techniques: TechniqueListItem[];
  subtechsByParent: Map<string, TechniqueListItem[]>;
  parentsWithSubs: Set<string>;
  selectedTechniques: Set<string>;
  overlayTechniques: Set<string>;
  comparisonLayers: ComparisonLayer[];
  coverageTechniques: Set<string>;
  simulationTechniques: Set<string>;
  simulationMode: boolean;
  expandedTechniques: Set<string>;
  onToggle: (id: string) => void;
  onToggleExpanded: (id: string) => void;
}

function TacticColumn({
  tactic,
  techniques,
  subtechsByParent,
  parentsWithSubs,
  selectedTechniques,
  overlayTechniques,
  comparisonLayers,
  coverageTechniques,
  simulationTechniques,
  simulationMode,
  expandedTechniques,
  onToggle,
  onToggleExpanded,
}: ColumnProps) {
  // Count how many selected/overlay techniques are in this column
  const selectedCount = techniques.filter((t) => selectedTechniques.has(t.attack_id)).length;
  const overlayIds = new Set([...overlayTechniques, ...comparisonLayers.flatMap(layer => layer.techniqueIds)]);
  const overlayCount  = techniques.filter((t) => overlayIds.has(t.attack_id)).length;
  const expandableParents = useMemo(
    () => techniques.filter((tech) => parentsWithSubs.has(tech.attack_id)).map((tech) => tech.attack_id),
    [parentsWithSubs, techniques],
  );
  const expandedCount = expandableParents.filter((id) => expandedTechniques.has(id)).length;
  const allExpanded = expandableParents.length > 0 && expandedCount === expandableParents.length;
  const handleColumnExpansion = useCallback(() => {
    if (!expandableParents.length) return;
    const targetIds = allExpanded
      ? expandableParents.filter((id) => expandedTechniques.has(id))
      : expandableParents.filter((id) => !expandedTechniques.has(id));
    targetIds.forEach(onToggleExpanded);
  }, [allExpanded, expandableParents, expandedTechniques, onToggleExpanded]);

  return (
    <div style={{ width: COL_WIDTH, flexShrink: 0 }}>
      {/* Header */}
      <div
        style={{ height: TACTIC_HEADER_H, background: '#991b1b', borderRadius: 4 }}
        className="flex flex-col items-center justify-center px-2 mb-[3px]"
      >
        <span className="text-white font-bold text-[10px] text-center leading-tight line-clamp-2">
          {tactic.name}
        </span>
        <span className="text-red-300 text-[8px] mt-0.5 font-mono">{tactic.attack_id}</span>
        <div className="flex gap-2 mt-1">
          {selectedCount > 0 && (
            <span className="text-[8px] bg-mitre-accent/40 text-red-200 px-1 rounded">
              {selectedCount}↑
            </span>
          )}
          {overlayCount > 0 && (
            <span className="text-[8px] bg-blue-800/60 text-blue-200 px-1 rounded">
              {overlayCount}↓
            </span>
          )}
        </div>
        {expandableParents.length > 0 && (
          <button
            type="button"
            data-matrix-cell
            onClick={handleColumnExpansion}
            className="mt-1 rounded border border-red-400/20 bg-black/20 px-1.5 py-0.5 text-[8px] text-red-100 hover:border-red-300/60 hover:bg-black/35"
            title={allExpanded ? `Collapse ${expandableParents.length} technique group${expandableParents.length === 1 ? '' : 's'} in ${tactic.name}` : `Expand ${expandableParents.length} technique group${expandableParents.length === 1 ? '' : 's'} in ${tactic.name}`}
          >
            {allExpanded ? 'Minimize' : 'Extend'} subs {expandedCount}/{expandableParents.length}
          </button>
        )}
      </div>

      {/* Technique cells */}
      {techniques.map((tech) => {
        const hasSubs  = parentsWithSubs.has(tech.attack_id);
        const expanded = expandedTechniques.has(tech.attack_id);
        const subs     = subtechsByParent.get(tech.attack_id) ?? [];

        return (
          <div key={tech.attack_id}>
            <ParentCell
              tech={tech}
              hasSubs={hasSubs}
              expanded={expanded}
              selectedTechniques={selectedTechniques}
              overlayTechniques={overlayTechniques}
              comparisonLayers={comparisonLayers}
              covered={coverageTechniques.has(tech.attack_id)}
              simulationAvailable={simulationTechniques.has(tech.attack_id)}
              simulationMode={simulationMode}
              onToggle={onToggle}
              onToggleExpanded={onToggleExpanded}
            />
            {expanded &&
              subs.map((sub) => (
                <SubtechCell
                  key={sub.attack_id}
                  tech={sub}
                  selectedTechniques={selectedTechniques}
                  overlayTechniques={overlayTechniques}
                  comparisonLayers={comparisonLayers}
                  covered={coverageTechniques.has(sub.attack_id)}
                  simulationAvailable={simulationTechniques.has(sub.attack_id)}
                  simulationMode={simulationMode}
                  onToggle={onToggle}
                />
              ))}
          </div>
        );
      })}
    </div>
  );
}

// ── Parent technique cell ─────────────────────────────────────────────────────

interface ParentCellProps {
  tech: TechniqueListItem;
  hasSubs: boolean;
  expanded: boolean;
  selectedTechniques: Set<string>;
  overlayTechniques: Set<string>;
  comparisonLayers: ComparisonLayer[];
  covered: boolean;
  simulationAvailable: boolean;
  simulationMode: boolean;
  onToggle: (id: string) => void;
  onToggleExpanded: (id: string) => void;
}

function ParentCell({
  tech, hasSubs, expanded,
  selectedTechniques, overlayTechniques, comparisonLayers, covered, simulationAvailable, simulationMode,
  onToggle, onToggleExpanded,
}: ParentCellProps) {
  const c = simulationMode && simulationAvailable
    ? { bg: '#064e3b', border: '#22c55e', id: '#bbf7d0', name: '#f0fdf4' }
    : cellColors(tech.attack_id, selectedTechniques, overlayTechniques, comparisonLayers);
  const tags = layerTags(tech.attack_id, comparisonLayers);

  return (
    <div
      data-matrix-cell
      style={{
        height: PARENT_CELL_H,
        background: c.bg,
        borderLeft: `3px solid ${c.border}`,
        borderRadius: 3,
        marginBottom: COL_GAP,
        position: 'relative',
        overflow: 'hidden',
      }}
      className="transition-colors duration-100"
    >
      {/* Clickable technique area */}
      <button
        onClick={() => onToggle(tech.attack_id)}
        style={{ width: hasSubs ? COL_WIDTH - 22 : COL_WIDTH, height: PARENT_CELL_H }}
        className="absolute left-0 top-0 text-left px-1.5 pt-1"
      >
        <div style={{ color: c.id, fontSize: 9, fontFamily: 'monospace', lineHeight: 1 }}>
          {tech.attack_id}
        </div>
        <div
          style={{
            color: c.name,
            fontSize: 10,
            lineHeight: 1.25,
            marginTop: 3,
            overflow: 'hidden',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
          }}
        >
          {tech.name}
        </div>
      </button>

      {/* Sub-technique expand toggle */}
      {hasSubs && (
        <button
          onClick={() => onToggleExpanded(tech.attack_id)}
          style={{
            position: 'absolute',
            right: 0,
            top: 0,
            width: 20,
            height: PARENT_CELL_H,
            color: '#6b7280',
            fontSize: 8,
            background: 'rgba(0,0,0,0.25)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          title={expanded ? 'Collapse sub-techniques' : 'Expand sub-techniques'}
        >
          {expanded ? '▼' : '▶'}
        </button>
      )}
      {covered && <span title="Detection/hunt coverage" className="absolute right-1 bottom-1 w-2 h-2 rounded-full bg-green-500 ring-1 ring-green-300" />}
      {simulationAvailable && !simulationMode && <span title="Attack Simulation available" className="absolute right-1 top-1 text-[11px] leading-none text-red-400">⚑</span>}
      {simulationAvailable && simulationMode && <span title="Click to configure this simulation" className="absolute right-1 top-1 rounded bg-green-950 px-1 text-[8px] font-semibold text-green-200">SIM</span>}
      {tags.length > 0 && <LayerTags tags={tags} />}
    </div>
  );
}

// ── Sub-technique cell ────────────────────────────────────────────────────────

interface SubCellProps {
  tech: TechniqueListItem;
  selectedTechniques: Set<string>;
  overlayTechniques: Set<string>;
  comparisonLayers: ComparisonLayer[];
  covered: boolean;
  simulationAvailable: boolean;
  simulationMode: boolean;
  onToggle: (id: string) => void;
}

function SubtechCell({ tech, selectedTechniques, overlayTechniques, comparisonLayers, covered, simulationAvailable, simulationMode, onToggle }: SubCellProps) {
  const c = simulationMode && simulationAvailable
    ? { bg: '#064e3b', border: '#22c55e', id: '#bbf7d0', name: '#f0fdf4' }
    : cellColors(tech.attack_id, selectedTechniques, overlayTechniques, comparisonLayers);
  const tags = layerTags(tech.attack_id, comparisonLayers);

  return (
    <button
      data-matrix-cell
      onClick={() => onToggle(tech.attack_id)}
      style={{
        height: SUB_CELL_H,
        width: COL_WIDTH - 10,
        marginLeft: 10,
        marginBottom: COL_GAP,
        background: c.bg,
        borderLeft: `2px solid ${c.border}`,
        borderRadius: '0 3px 3px 0',
        textAlign: 'left',
        padding: '2px 6px',
        position: 'relative',
        display: 'block',
        overflow: 'hidden',
      }}
      className="transition-colors duration-100"
    >
      {/* Connector dot */}
      <div
        style={{
          position: 'absolute',
          left: -6,
          top: '50%',
          transform: 'translateY(-50%)',
          width: 4,
          height: 4,
          borderRadius: '50%',
          background: c.border,
        }}
      />
      <div style={{ color: c.id, fontSize: 8, fontFamily: 'monospace', lineHeight: 1 }}>
        {tech.attack_id}
      </div>
      <div
        style={{
          color: c.name,
          fontSize: 9,
          lineHeight: 1.25,
          marginTop: 2,
          overflow: 'hidden',
          whiteSpace: 'nowrap',
          textOverflow: 'ellipsis',
        }}
      >
        {tech.name}
      </div>
      {covered && <span title="Detection/hunt coverage" className="absolute right-1 bottom-1 w-2 h-2 rounded-full bg-green-500 ring-1 ring-green-300" />}
      {simulationAvailable && !simulationMode && <span title="Attack Simulation available" className="absolute right-1 top-1 text-[10px] leading-none text-red-400">⚑</span>}
      {simulationAvailable && simulationMode && <span title="Click to configure this simulation" className="absolute right-1 top-1 rounded bg-green-950 px-1 text-[7px] font-semibold text-green-200">SIM</span>}
      {tags.length > 0 && <LayerTags tags={tags} compact />}
    </button>
  );
}

function layerTags(id: string, layers: ComparisonLayer[]) {
  return layers
    .filter(layer => layer.techniqueIds.includes(id))
    .map(layer => ({ label: layer.name.slice(0, 2).toUpperCase(), color: layer.color, title: layer.name }));
}

function LayerTags({ tags, compact = false }: { tags: Array<{ label: string; color: string; title: string }>; compact?: boolean }) {
  const limit = compact ? 2 : 3;
  return (
    <div className="absolute bottom-1 left-1 flex max-w-[94px] gap-0.5 overflow-hidden">
      {tags.slice(0, limit).map(tag => (
        <span
          key={`${tag.title}-${tag.color}`}
          title={tag.title}
          style={{ backgroundColor: tag.color }}
          className="rounded px-1 text-[7px] font-bold leading-3 text-white shadow"
        >
          {tag.label}
        </span>
      ))}
      {tags.length > limit && <span className="text-[7px] text-white">+{tags.length - limit}</span>}
    </div>
  );
}
