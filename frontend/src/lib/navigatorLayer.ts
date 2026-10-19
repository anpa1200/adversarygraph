export interface NavigatorTechnique {
  techniqueID: string;
  enabled?: boolean;
  [key: string]: unknown;
}
export interface NavigatorLayer {
  name?: string;
  domain?: string;
  techniques?: NavigatorTechnique[];
  [key: string]: unknown;
}

export function buildNavigatorLayer(
  selectedTechniques: Set<string>,
  overlayTechniques: Set<string>,
  domain: string,
  attackVersion: string | null,
  source: NavigatorLayer | null = null
) {
  const userIds = Array.from(selectedTechniques);
  const layer = {
    name: 'AdversaryGraph Export',
    versions: {
      ...(domain !== 'atlas' && attackVersion ? { attack: attackVersion.split('.')[0] } : {}),
      navigator: '5.0', layer: '4.5',
    },
    domain,
    description: `Exported from AdversaryGraph. User TTPs: ${userIds.length}`,
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
      { color: '#3b82f6', label: 'Group-profile overlay' },
      { color: '#f59e0b', label: 'Shared' },
    ],
    metadata: [],
    hideDisabled: false,
    layout: { layout: 'side', aggregateFunction: 'average', showID: true, showName: true },
  };
  const imported = (source?.techniques ?? []).filter(item => item.enabled === false || selectedTechniques.has(item.techniqueID.toUpperCase()));
  const importedIds = new Set(imported.map(item => item.techniqueID.toUpperCase()));
  return {
    ...layer,
    ...source,
    versions: layer.versions,
    domain,
    techniques: [...imported, ...layer.techniques.filter(item => !importedIds.has(item.techniqueID))],
  };
}
