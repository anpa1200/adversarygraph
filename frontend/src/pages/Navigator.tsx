import { useState, useEffect, useCallback, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAppStore } from '@/store';
import { aptApi, exportApi } from '@/api/client';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { AttackMatrix } from '@/components/Navigator/AttackMatrix';
import { LayerControls } from '@/components/Navigator/LayerControls';
import { LayerImport } from '@/components/Navigator/LayerImport';
import { SaveLayerModal } from '@/components/Navigator/SaveLayerModal';
import { LoadLayerModal } from '@/components/Navigator/LoadLayerModal';
import { TechniquePanel } from '@/components/Navigator/TechniquePanel';
import { MatrixFilters } from '@/components/Navigator/MatrixFilters';
import { Header } from '@/components/Layout/Header';
import type { TechniqueListItem } from '@/types/attack';

export function Navigator() {
  const {
    domain, version,
    selectedTechniques, overlayTechniques,
    overlayGroupId, overlayGroupName,
    expandedTechniques,
    toggleTechnique, toggleExpanded,
    addTechniques, replaceTechniques, clearTechniques, clearOverlay,
    setOverlayTechniques, expandAll, collapseAll,
  } = useAppStore();

  // ── Panel state ────────────────────────────────────────────────────────────
  const [selectedAttackId, setSelectedAttackId] = useState<string | null>(null);
  const [importOpen, setImportOpen]             = useState(false);
  const [saveOpen,   setSaveOpen]               = useState(false);
  const [loadOpen,   setLoadOpen]               = useState(false);

  // ── Filter state ───────────────────────────────────────────────────────────
  const [search, setSearch]                       = useState('');
  const [platform, setPlatform]                   = useState('');
  const [showOnlySelected, setShowOnlySelected]   = useState(false);
  const [showOnlyOverlay,  setShowOnlyOverlay]     = useState(false);

  // ── Matrix data ────────────────────────────────────────────────────────────
  const matrixData = useAttackMatrix(domain, version);
  const { tactics, techniquesByTactic, subtechsByParent, parentsWithSubs, isLoading, hasData } = matrixData;

  // ── APT overlay sync ───────────────────────────────────────────────────────
  const { data: overlayGroup } = useQuery({
    queryKey: ['overlay-group', overlayGroupId, domain, version],
    queryFn: () => aptApi.group(overlayGroupId!, domain, version ?? undefined),
    enabled: !!overlayGroupId,
    staleTime: 10 * 60 * 1000,
  });

  useEffect(() => {
    if (overlayGroup) setOverlayTechniques(overlayGroup.techniques.map(t => t.attack_id));
  }, [overlayGroup, setOverlayTechniques]);

  // ── Derived platform list ──────────────────────────────────────────────────
  const availablePlatforms = useMemo(() => {
    const all = new Set<string>();
    for (const techs of techniquesByTactic.values())
      techs.forEach(t => t.platforms.forEach(p => all.add(p)));
    return Array.from(all).sort();
  }, [techniquesByTactic]);

  // ── Filtered matrix ────────────────────────────────────────────────────────
  const filteredByTactic = useMemo(() => {
    const term = search.toLowerCase();
    if (!term && !platform && !showOnlySelected && !showOnlyOverlay) return techniquesByTactic;

    const result = new Map<string, TechniqueListItem[]>();
    for (const [tactic, techs] of techniquesByTactic) {
      let filtered = techs;
      if (term)             filtered = filtered.filter(t => t.name.toLowerCase().includes(term) || t.attack_id.toLowerCase().includes(term));
      if (platform)         filtered = filtered.filter(t => t.platforms.includes(platform));
      if (showOnlySelected) filtered = filtered.filter(t => selectedTechniques.has(t.attack_id));
      if (showOnlyOverlay)  filtered = filtered.filter(t => overlayTechniques.has(t.attack_id));
      result.set(tactic, filtered);
    }
    return result;
  }, [techniquesByTactic, search, platform, showOnlySelected, showOnlyOverlay, selectedTechniques, overlayTechniques]);

  // Simplified: toggle + open panel together (detail panel on click)
  const handleToggle = useCallback(
    (id: string) => {
      toggleTechnique(id);
      setSelectedAttackId(id);
    },
    [toggleTechnique]
  );

  // ── Expand all ────────────────────────────────────────────────────────────
  const handleExpandAll = useCallback(() => expandAll(Array.from(parentsWithSubs)), [expandAll, parentsWithSubs]);

  // ── Exports ───────────────────────────────────────────────────────────────
  const exportNavigatorLayer = useCallback(() => {
    downloadJson(buildNavigatorLayer(selectedTechniques, overlayTechniques, domain), 'threatmapper-layer.json');
  }, [selectedTechniques, overlayTechniques, domain]);

  const exportJson = useCallback(() => {
    downloadJson({ techniques: Array.from(selectedTechniques).sort(), domain }, 'my-ttps.json');
  }, [selectedTechniques, domain]);

  const exportLayerPdf = useCallback(async () => {
    const blob = await exportApi.layer(Array.from(selectedTechniques), domain);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'layer-report.pdf'; a.click();
    URL.revokeObjectURL(url);
  }, [selectedTechniques, domain]);

  return (
    <div className="flex flex-col h-full">
      <Header title="ATT&CK Navigator" />

      <LayerControls
        matrixData={matrixData}
        selectedTechniques={selectedTechniques}
        overlayTechniques={overlayTechniques}
        expandedTechniques={expandedTechniques}
        overlayGroupName={overlayGroupName}
        onExpandAll={handleExpandAll}
        onCollapseAll={collapseAll}
        onClearTechniques={clearTechniques}
        onClearOverlay={clearOverlay}
        onExportLayer={exportJson}
        onExportNavigator={exportNavigatorLayer}
        onExportPdf={exportLayerPdf}
        onImportClick={() => setImportOpen(true)}
        onSaveClick={() => setSaveOpen(true)}
        onLoadClick={() => setLoadOpen(true)}
      />

      <MatrixFilters
        search={search}            onSearchChange={setSearch}
        platform={platform}        onPlatformChange={setPlatform}
        availablePlatforms={availablePlatforms}
        showOnlySelected={showOnlySelected}  onToggleSelected={() => setShowOnlySelected(v => !v)}
        showOnlyOverlay={showOnlyOverlay}    onToggleOverlay={() => setShowOnlyOverlay(v => !v)}
        hasOverlay={overlayTechniques.size > 0}
      />

      {/* Main workspace row */}
      <div className="flex flex-1 overflow-hidden">
        {/* Matrix */}
        <div className="flex-1 overflow-hidden relative">
          {isLoading && <LoadingOverlay />}

          {!isLoading && !hasData && <EmptyState />}

          {!isLoading && hasData && (
            <AttackMatrix
              tactics={tactics}
              techniquesByTactic={filteredByTactic}
              subtechsByParent={subtechsByParent}
              parentsWithSubs={parentsWithSubs}
              selectedTechniques={selectedTechniques}
              overlayTechniques={overlayTechniques}
              expandedTechniques={expandedTechniques}
              onToggleTechnique={handleToggle}
              onToggleExpanded={toggleExpanded}
            />
          )}

          {/* Overlay badge */}
          {overlayGroupId && overlayGroupName && (
            <div className="absolute bottom-4 left-4 flex items-center gap-2 bg-blue-900/80 border border-blue-600 text-blue-200 text-xs px-3 py-2 rounded-lg z-20">
              <div className="w-2 h-2 rounded-sm bg-blue-500" />
              Overlay: <span className="font-medium">{overlayGroupName}</span>
              <span className="text-blue-400">({overlayTechniques.size})</span>
              <button onClick={clearOverlay} className="ml-1 text-blue-400 hover:text-white transition-colors">✕</button>
            </div>
          )}
        </div>

        {/* Technique detail panel */}
        {selectedAttackId && (
          <TechniquePanel
            attackId={selectedAttackId}
            onClose={() => setSelectedAttackId(null)}
          />
        )}
      </div>

      {/* Import modal */}
      {importOpen && (
        <LayerImport
          onImport={ids => { addTechniques(ids); }}
          onClose={() => setImportOpen(false)}
        />
      )}

      {/* Save layer modal */}
      {saveOpen && (
        <SaveLayerModal
          techniqueIds={Array.from(selectedTechniques)}
          domain={domain}
          onClose={() => setSaveOpen(false)}
          onSaved={() => {}}
        />
      )}

      {/* Load layer modal */}
      {loadOpen && (
        <LoadLayerModal
          domain={domain}
          onLoad={(ids) => { replaceTechniques(ids); }}
          onClose={() => setLoadOpen(false)}
        />
      )}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function LoadingOverlay() {
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center text-gray-500 z-10">
      <div className="text-3xl mb-3 animate-pulse">⬡</div>
      <p className="text-sm">Loading ATT&CK matrix…</p>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center text-center text-gray-500">
      <div className="text-5xl mb-4">⬡</div>
      <p className="text-lg text-gray-400">No ATT&CK data yet</p>
      <p className="text-sm mt-2 max-w-sm text-gray-600">
        The API downloads and ingests ATT&CK data on first startup. This can take a few minutes.
        Once complete, refresh this page.
      </p>
    </div>
  );
}

function buildNavigatorLayer(
  selectedTechniques: Set<string>,
  overlayTechniques: Set<string>,
  domain: string
) {
  const userIds = Array.from(selectedTechniques);
  return {
    name: 'ThreatMapper Export',
    versions: { attack: '19', navigator: '5.0', layer: '4.5' },
    domain,
    description: `Exported from ThreatMapper. User TTPs: ${userIds.length}`,
    techniques: [
      ...userIds.map(id => ({
        techniqueID: id,
        color: overlayTechniques.has(id) ? '#f59e0b' : '#e94560',
        comment: overlayTechniques.has(id) ? 'Shared with overlay' : 'My TTP',
        enabled: true, score: 1, showSubtechniques: false,
      })),
      ...[...overlayTechniques].filter(id => !selectedTechniques.has(id)).map(id => ({
        techniqueID: id,
        color: '#3b82f6', comment: 'Overlay only',
        enabled: true, score: 1, showSubtechniques: false,
      })),
    ],
    gradient: { colors: ['#ffffff', '#e94560'], minValue: 0, maxValue: 1 },
    legendItems: [
      { color: '#e94560', label: 'My TTP' },
      { color: '#3b82f6', label: 'APT overlay' },
      { color: '#f59e0b', label: 'Shared' },
    ],
    metadata: [],
    hideDisabled: false,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true },
  };
}

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}
