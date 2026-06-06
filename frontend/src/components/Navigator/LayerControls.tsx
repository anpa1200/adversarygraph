/**
 * Toolbar beneath the Navigator header.
 * Handles: colour legend, expand/collapse all, layer stats, exports, clear actions,
 * save/load named layers.
 */

import { useCallback } from 'react';
import type { MatrixData } from '@/hooks/useAttackMatrix';

interface Props {
  matrixData: MatrixData;
  selectedTechniques: Set<string>;
  overlayTechniques: Set<string>;
  expandedTechniques: Set<string>;
  overlayGroupName: string;
  onExpandAll: () => void;
  onCollapseAll: () => void;
  onClearTechniques: () => void;
  onClearOverlay: () => void;
  onExportLayer: () => void;
  onExportNavigator: () => void;
  onImportClick: () => void;
  onSaveClick: () => void;
  onLoadClick: () => void;
}

export function LayerControls({
  matrixData,
  selectedTechniques,
  overlayTechniques,
  expandedTechniques,
  overlayGroupName,
  onExpandAll,
  onCollapseAll,
  onClearTechniques,
  onClearOverlay,
  onExportLayer,
  onExportNavigator,
  onImportClick,
  onSaveClick,
  onLoadClick,
}: Props) {
  const { parentsWithSubs } = matrixData;
  const sharedCount = [...selectedTechniques].filter((id) => overlayTechniques.has(id)).length;

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
            <LegendDot color="bg-amber-900 border-amber-500" label="Shared" count={sharedCount} />
          </>
        )}
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

      <div className="w-px h-4 bg-gray-700 shrink-0" />

      {/* ── Save / Load named layers ───────────────────────────────────── */}
      <button
        onClick={onLoadClick}
        className="text-gray-400 hover:text-white transition-colors shrink-0"
        title="Load a previously saved layer"
      >
        📂 Load layer
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
        {overlayTechniques.size > 0 && (
          <button
            onClick={onClearOverlay}
            className="text-blue-400 hover:text-white transition-colors"
          >
            Clear overlay
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
        {selectedTechniques.size === 0 && overlayTechniques.size === 0 && (
          <span className="text-gray-600">Click cells to select your TTPs</span>
        )}
      </div>
    </div>
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
