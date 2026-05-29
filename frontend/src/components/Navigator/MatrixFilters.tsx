/**
 * Search + platform filter bar shown above the matrix.
 */

interface Props {
  search: string;
  onSearchChange: (v: string) => void;
  platform: string;
  onPlatformChange: (v: string) => void;
  availablePlatforms: string[];
  showOnlySelected: boolean;
  onToggleSelected: () => void;
  showOnlyOverlay: boolean;
  onToggleOverlay: () => void;
  hasOverlay: boolean;
}

export function MatrixFilters({
  search, onSearchChange,
  platform, onPlatformChange,
  availablePlatforms,
  showOnlySelected, onToggleSelected,
  showOnlyOverlay, onToggleOverlay,
  hasOverlay,
}: Props) {
  return (
    <div className="flex items-center gap-2 px-4 py-1.5 bg-gray-900/80 border-b border-gray-800 text-xs shrink-0">
      {/* Search */}
      <input
        type="text"
        value={search}
        onChange={e => onSearchChange(e.target.value)}
        placeholder="Search techniques… (name or ID)"
        className="bg-gray-800 text-gray-300 text-xs px-3 py-1.5 rounded border border-gray-700 focus:border-mitre-accent outline-none w-56 placeholder-gray-600"
      />

      {/* Platform filter */}
      {availablePlatforms.length > 0 && (
        <select
          value={platform}
          onChange={e => onPlatformChange(e.target.value)}
          className="bg-gray-800 text-gray-300 text-xs px-2 py-1.5 rounded border border-gray-700 focus:border-mitre-accent outline-none"
        >
          <option value="">All platforms</option>
          {availablePlatforms.map(p => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      )}

      {/* Toggle filters */}
      <FilterToggle
        active={showOnlySelected}
        color="bg-mitre-accent/20 text-red-300 border-mitre-accent/40"
        onClick={onToggleSelected}
      >
        My TTPs only
      </FilterToggle>

      {hasOverlay && (
        <FilterToggle
          active={showOnlyOverlay}
          color="bg-blue-900/30 text-blue-300 border-blue-700/40"
          onClick={onToggleOverlay}
        >
          Overlay only
        </FilterToggle>
      )}

      {(search || platform || showOnlySelected || showOnlyOverlay) && (
        <button
          onClick={() => {
            onSearchChange('');
            onPlatformChange('');
            if (showOnlySelected) onToggleSelected();
            if (showOnlyOverlay)  onToggleOverlay();
          }}
          className="text-gray-500 hover:text-gray-300 transition-colors ml-1"
        >
          Clear filters
        </button>
      )}
    </div>
  );
}

function FilterToggle({
  active, color, onClick, children,
}: {
  active: boolean; color: string; onClick: () => void; children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-2.5 py-1 rounded border transition-colors ${
        active ? color : 'border-gray-700 text-gray-500 hover:text-gray-300'
      }`}
    >
      {children}
    </button>
  );
}
