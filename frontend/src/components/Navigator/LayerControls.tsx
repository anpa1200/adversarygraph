/**
 * Toolbar beneath the Navigator header.
 * Handles: colour legend, expand/collapse all, layer stats, exports, clear actions,
 * save/load named layers.
 */

import { useCallback } from 'react';
import type { MatrixData } from '@/hooks/useAttackMatrix';
import type { ComparisonLayer } from '@/store';

interface Props {
  matrixData: MatrixData;
  selectedTechniques: Set<string>;
  overlayTechniques: Set<string>;
  comparisonLayers: ComparisonLayer[];
  expandedTechniques: Set<string>;
  overlayGroupName: string;
  onExpandAll: () => void;
  onCollapseAll: () => void;
  onClearTechniques: () => void;
  onClearOverlay: () => void;
  onRemoveComparisonLayer: (id: string) => void;
  onExportLayer: () => void;
  onExportNavigator: () => void;
  onExportPdf: () => void;
  onImportClick: () => void;
  onImportOverlayClick: () => void;
  onSaveClick: () => void;
  onLoadClick: () => void;
  onLoadOverlayClick: () => void;
}

export function LayerControls({
  matrixData,
  selectedTechniques,
  overlayTechniques,
  comparisonLayers,
  expandedTechniques,
  overlayGroupName,
  onExpandAll,
  onCollapseAll,
  onClearTechniques,
  onClearOverlay,
  onRemoveComparisonLayer,
  onExportLayer,
  onExportNavigator,
  onExportPdf,
  onImportClick,
  onImportOverlayClick,
  onSaveClick,
  onLoadClick,
  onLoadOverlayClick,
}: Props) {
  const { parentsWithSubs } = matrixData;
  const comparisonIds = new Set([...overlayTechniques, ...comparisonLayers.flatMap(layer => layer.techniqueIds)]);
  const sharedCount = [...selectedTechniques].filter((id) => comparisonIds.has(id)).length;

  const handleExpandAll = useCallback(() => {
    onExpandAll();
  }, [onExpandAll]);

  return (
    <div className="flex items-center gap-3 px-4 py-2 bg-gray-900 border-b border-gray-700 text-xs shrink-0 overflow-x-auto">

      {/* ── Colour legend ──────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 shrink-0">
        <LegendDot color="bg-red-700 border-[#e94560]" label="Your TTPs" count={selectedTechniques.size} />
        {overlayTechniques.size > 0 && (
          <>
            <LegendDot color="bg-blue-900 border-blue-500" label={overlayGroupName || 'Overlay'} count={overlayTechniques.size} />
          </>
        )}
        {comparisonLayers.map(layer => (
          <LayerLegend key={layer.id} layer={layer} onRemove={() => onRemoveComparisonLayer(layer.id)} />
        ))}
        {sharedCount > 0 && <LegendDot color="bg-amber-900 border-amber-500" label="Shared" count={sharedCount} />}
      </div>

      <div className="w-px h-4 bg-gray-700 shrink-0" />

      {/* ── Sub-technique controls ─────────────────────────────────────── */}
      {parentsWithSubs.size > 0 && (
        <>
          <button
            onClick={handleExpandAll}
            className="text-gray-400 hover:text-white transition-colors shrink-0"
            title="Expand all sub-techniques"
          >
            Expand all ▶
          </button>
          {expandedTechniques.size > 0 && (
            <button
              onClick={onCollapseAll}
              className="text-gray-400 hover:text-white transition-colors shrink-0"
            >
              Collapse all ▲
            </button>
          )}
          <div className="w-px h-4 bg-gray-700 shrink-0" />
        </>
      )}

      {/* ── Import ────────────────────────────────────────────────────── */}
      <button
        onClick={onImportClick}
        className="text-gray-400 hover:text-white transition-colors shrink-0"
        title="Import an ATT&CK Navigator .json layer"
      >
        ↑ Import layer
      </button>
      <button
        onClick={onImportOverlayClick}
        className="text-blue-400 hover:text-white transition-colors shrink-0"
        title="Import another ATT&CK Navigator .json layer as comparison overlay"
      >
        ⇄ Import compare
      </button>

      <div className="w-px h-4 bg-gray-700 shrink-0" />

      {/* ── Save / Load named layers ───────────────────────────────────── */}
      <button
        onClick={onLoadClick}
        className="text-gray-400 hover:text-white transition-colors shrink-0"
        title="Load a previously saved layer"
      >
        📂 Load layer
      </button>
      <button
        onClick={onLoadOverlayClick}
        className="text-blue-400 hover:text-white transition-colors shrink-0"
        title="Load a saved layer as comparison overlay"
      >
        ⇄ Load compare
      </button>
      {selectedTechniques.size > 0 && (
        <button
          onClick={onSaveClick}
          className="text-gray-400 hover:text-white transition-colors shrink-0"
          title="Save current selection as a named layer"
        >
          ↓ Save layer
        </button>
      )}

      <div className="w-px h-4 bg-gray-700 shrink-0" />

      {/* ── Export actions ─────────────────────────────────────────────── */}
      {selectedTechniques.size > 0 && (
        <>
          <button
            onClick={onExportPdf}
            className="text-gray-400 hover:text-white transition-colors shrink-0"
            title="Download PDF report of current layer"
          >
            ↓ PDF
          </button>
          <button
            onClick={onExportNavigator}
            className="text-gray-400 hover:text-white transition-colors shrink-0"
            title="Export as ATT&CK Navigator JSON layer"
          >
            ↓ Navigator layer
          </button>
          <button
            onClick={onExportLayer}
            className="text-gray-400 hover:text-white transition-colors shrink-0"
            title="Export selected technique IDs as plain JSON"
          >
            ↓ JSON
          </button>
        </>
      )}

      {/* ── Clear actions ──────────────────────────────────────────────── */}
      <div className="ml-auto flex items-center gap-3 shrink-0">
        {(overlayTechniques.size > 0 || comparisonLayers.length > 0) && (
          <button
            onClick={onClearOverlay}
            className="text-blue-400 hover:text-white transition-colors"
          >
            Clear compare
          </button>
        )}
        {selectedTechniques.size > 0 && (
          <button
            onClick={onClearTechniques}
            className="text-red-400 hover:text-white transition-colors"
          >
            Clear my TTPs
          </button>
        )}
        {selectedTechniques.size === 0 && overlayTechniques.size === 0 && comparisonLayers.length === 0 && (
          <span className="text-gray-600">Click cells to select your TTPs</span>
        )}
      </div>
    </div>
  );
}

function LayerLegend({ layer, onRemove }: { layer: ComparisonLayer; onRemove: () => void }) {
  return (
    <span className="flex items-center gap-1.5 text-gray-400">
      <span className="h-3 w-3 rounded-sm border" style={{ backgroundColor: `${layer.color}66`, borderColor: layer.color }} />
      <span title={layer.name}>{layer.name} <span className="text-gray-500">({layer.techniqueIds.length})</span></span>
      <button type="button" onClick={onRemove} className="text-gray-600 hover:text-red-300" title={`Remove ${layer.name}`}>x</button>
    </span>
  );
}

// ── Legend dot ────────────────────────────────────────────────────────────────

function LegendDot({
  color,
  label,
  count,
}: {
  color: string;
  label: string;
  count: number;
}) {
  return (
    <div className="flex items-center gap-1.5">
      <div className={`w-3 h-3 rounded-sm border ${color}`} />
      <span className="text-gray-400">
        {label}
        {count > 0 && <span className="ml-1 text-gray-500">({count})</span>}
      </span>
    </div>
  );
}
