import { useState, useMemo } from 'react';
import { useQuery, useQueries } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '@/store';
import { aptApi } from '@/api/client';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { Header } from '@/components/Layout/Header';
import type { GroupDetail, Tactic, TechniqueListItem } from '@/types/attack';

// ── Constants ──────────────────────────────────────────────────────────────────
const GROUP_COLORS = ['#e94560', '#3b82f6', '#22c55e', '#a855f7', '#f59e0b', '#ec4899'];
const MAX_GROUPS = 6;
type Tab        = 'overlap' | 'matrix' | 'techniques';
type TechFilter = 'all' | 'shared' | 'exclusive';
type LoadedGroup = GroupDetail & { color: string };

// ── Pure utilities ─────────────────────────────────────────────────────────────
function getIds(g: GroupDetail): Set<string> {
  return new Set(g.techniques.map(t => t.attack_id));
}

function jaccard(a: Set<string>, b: Set<string>): number {
  let inter = 0;
  a.forEach(id => { if (b.has(id)) inter++; });
  const union = a.size + b.size - inter;
  return union === 0 ? 0 : inter / union;
}

// ── Main page ──────────────────────────────────────────────────────────────────
export function GroupCompare() {
  const { domain, version, setOverlayGroup } = useAppStore();
  const navigate = useNavigate();

  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [search,      setSearch]      = useState('');
  const [tab,         setTab]         = useState<Tab>('overlap');
  const [techFilter,  setTechFilter]  = useState<TechFilter>('all');
  const [techSort,    setTechSort]    = useState('id');
  const [sortDir,     setSortDir]     = useState<1 | -1>(1);

  // ── Data ──────────────────────────────────────────────────────────────────────
  const { data: groups = [], isLoading: groupsLoading } = useQuery({
    queryKey: ['apt-groups', domain, version, search],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined, search: search || undefined }),
    staleTime: 10 * 60 * 1000,
  });

  const detailResults = useQueries({
    queries: selectedIds.map(id => ({
      queryKey: ['grp-cmp-detail', id, domain, version],
      queryFn:  () => aptApi.group(id, domain, version ?? undefined),
      staleTime: 10 * 60 * 1000,
    })),
  });

  const { tactics, techniquesByTactic, isLoading: matrixLoading } = useAttackMatrix(domain, version);

  const loadedGroups = useMemo<LoadedGroup[]>(() =>
    detailResults
      .map((q, i) => q.data ? { ...q.data, color: GROUP_COLORS[i] } : null)
      .filter(Boolean) as LoadedGroup[]
  , [detailResults]);

  const anyLoading = detailResults.some(q => q.isLoading);

  // ── Technique table data ───────────────────────────────────────────────────
  const techDetails = useMemo(() => {
    const map = new Map<string, { id: string; name: string; tactic: string }>();
    for (const g of loadedGroups)
      for (const t of g.techniques)
        if (!map.has(t.attack_id))
          map.set(t.attack_id, { id: t.attack_id, name: t.name, tactic: t.tactics?.[0] ?? '' });
    return map;
  }, [loadedGroups]);

  const filteredTechs = useMemo(() => {
    let items = Array.from(techDetails.values());
    if (techFilter === 'shared')
      items = items.filter(t => loadedGroups.filter(g => getIds(g).has(t.id)).length >= 2);
    else if (techFilter === 'exclusive')
      items = items.filter(t => loadedGroups.filter(g => getIds(g).has(t.id)).length === 1);

    if (techSort === 'id') {
      items.sort((a, b) => sortDir * a.id.localeCompare(b.id));
    } else {
      const tgt = loadedGroups.find(g => g.attack_id === techSort);
      if (tgt) {
        const ids = getIds(tgt);
        items.sort((a, b) => sortDir * ((ids.has(b.id) ? 1 : 0) - (ids.has(a.id) ? 1 : 0)));
      }
    }
    return items;
  }, [techDetails, techFilter, techSort, sortDir, loadedGroups]);

  // ── Handlers ──────────────────────────────────────────────────────────────────
  function toggleGroup(id: string) {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id)
        : prev.length < MAX_GROUPS ? [...prev, id] : prev
    );
  }

  function handleSortTech(col: string) {
    if (techSort === col) setSortDir(d => (d === 1 ? -1 : 1));
    else { setTechSort(col); setSortDir(1); }
  }

  function overlayAndNavigate(g: LoadedGroup) {
    setOverlayGroup(g.attack_id, g.name);
    navigate('/navigator');
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      <Header title="Group vs Group" />

      <div className="flex flex-1 overflow-hidden">

        {/* ── Left: group selector ──────────────────────────────────────────── */}
        <div className="w-72 shrink-0 border-r border-gray-700 flex flex-col">
          <div className="p-3 border-b border-gray-700">
            <input
              type="text"
              placeholder="Search groups…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none"
            />
            <div className="text-[10px] text-gray-600 mt-1.5">
              {selectedIds.length}/{MAX_GROUPS} selected · click to add/remove
            </div>
          </div>

          {/* Selected group chips */}
          {selectedIds.length > 0 && (
            <div className="p-3 border-b border-gray-800 space-y-1.5 shrink-0">
              {selectedIds.map((id, i) => {
                const loaded = loadedGroups.find(g => g.attack_id === id);
                const label  = loaded?.name ?? groups.find(g => g.attack_id === id)?.name ?? id;
                return (
                  <div key={id}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded"
                    style={{ background: `${GROUP_COLORS[i]}18`, border: `1px solid ${GROUP_COLORS[i]}35` }}
                  >
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ background: GROUP_COLORS[i] }} />
                    <span className="text-xs text-white flex-1 truncate font-medium">{label}</span>
                    <button
                      onClick={() => { if (loaded) overlayAndNavigate(loaded); }}
                      title="Overlay on Navigator"
                      disabled={!loaded}
                      className="text-[10px] text-gray-600 hover:text-blue-300 transition-colors px-1 shrink-0 disabled:opacity-30"
                    >⊕</button>
                    <button
                      onClick={() => setSelectedIds(prev => prev.filter(x => x !== id))}
                      className="text-[10px] text-gray-600 hover:text-red-400 transition-colors shrink-0"
                    >✕</button>
                  </div>
                );
              })}
            </div>
          )}

          {/* Group list */}
          <div className="flex-1 overflow-y-auto">
            {groupsLoading
              ? <div className="p-4 text-gray-500 text-xs">Loading…</div>
              : groups.map(g => {
                const isSel = selectedIds.includes(g.attack_id);
                const idx   = selectedIds.indexOf(g.attack_id);
                return (
                  <button
                    key={g.attack_id}
                    onClick={() => toggleGroup(g.attack_id)}
                    disabled={!isSel && selectedIds.length >= MAX_GROUPS}
                    className={`w-full text-left px-4 py-2.5 border-b border-gray-800 transition-colors
                      ${isSel ? 'bg-gray-800/50' : 'hover:bg-gray-800/30 disabled:opacity-40'}`}
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full shrink-0" style={{
                        background: isSel ? GROUP_COLORS[idx] : 'transparent',
                        border: isSel ? 'none' : '1px solid #4b5563',
                      }} />
                      <span className={`text-xs flex-1 ${isSel ? 'text-white font-medium' : 'text-gray-300'}`}>
                        {g.name}
                      </span>
                      <span className="text-gray-600 font-mono text-[9px]">{g.attack_id}</span>
                    </div>
                    <div className="text-gray-600 text-[10px] mt-0.5 ml-4">{g.technique_count} techniques</div>
                  </button>
                );
              })
            }
          </div>
        </div>

        {/* ── Right: comparison ─────────────────────────────────────────────── */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {selectedIds.length < 2 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-gray-600">
              <div className="text-5xl mb-4">⬡</div>
              <p className="text-gray-400 mb-1.5">Select 2–{MAX_GROUPS} APT groups to compare</p>
              <p className="text-gray-600 text-xs">Search and click groups on the left</p>
            </div>
          ) : (
            <>
              {/* Tab bar */}
              <div className="flex items-center gap-6 px-6 border-b border-gray-700 shrink-0">
                {([
                  ['overlap',    `Overlap Matrix`],
                  ['matrix',     'Combined Matrix'],
                  ['techniques', `Technique Table (${techDetails.size})`],
                ] as [Tab, string][]).map(([id, label]) => (
                  <button key={id} onClick={() => setTab(id)}
                    className={`py-3 border-b-2 text-sm transition-colors whitespace-nowrap ${
                      tab === id
                        ? 'border-mitre-accent text-white'
                        : 'border-transparent text-gray-500 hover:text-gray-300'
                    }`}
                  >{label}</button>
                ))}
                {anyLoading && (
                  <span className="text-[10px] text-gray-600 ml-auto pb-1 animate-pulse">Loading group data…</span>
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-6">
                {tab === 'overlap' && (
                  <OverlapMatrix groups={loadedGroups} />
                )}
                {tab === 'matrix' && (
                  <CombinedMatrix
                    groups={loadedGroups}
                    tactics={tactics}
                    techniquesByTactic={techniquesByTactic}
                    isLoading={matrixLoading}
                  />
                )}
                {tab === 'techniques' && (
                  <TechniqueTableView
                    groups={loadedGroups}
                    techs={filteredTechs}
                    allCount={techDetails.size}
                    techFilter={techFilter}
                    setTechFilter={setTechFilter}
                    techSort={techSort}
                    onSort={handleSortTech}
                    sortDir={sortDir}
                  />
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Overlap Matrix ─────────────────────────────────────────────────────────────
function OverlapMatrix({ groups }: { groups: LoadedGroup[] }) {
  if (groups.length < 2)
    return <div className="text-gray-600 text-sm text-center py-12">Waiting for group data…</div>;

  const sets = groups.map(getIds);

  function simBg(v: number): string {
    if (v >= 0.5) return '#7f1d1d';
    if (v >= 0.25) return '#78350f';
    if (v > 0) return '#1e3a5f';
    return 'transparent';
  }

  return (
    <div className="space-y-8">
      {/* N×N similarity table */}
      <div>
        <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-4">
          Jaccard Similarity Matrix
        </div>
        <div className="overflow-x-auto">
          <table className="text-xs border-collapse">
            <thead>
              <tr>
                <th className="w-36 p-2" />
                {groups.map((g, i) => (
                  <th key={g.attack_id} className="p-2 text-center" style={{ color: GROUP_COLORS[i] }}>
                    <div className="font-medium max-w-[90px] truncate">{g.name}</div>
                    <div className="text-gray-600 font-mono text-[9px] font-normal">{g.attack_id}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {groups.map((row, ri) => (
                <tr key={row.attack_id}>
                  <td className="p-2 text-right pr-4">
                    <div className="font-medium" style={{ color: GROUP_COLORS[ri] }}>{row.name}</div>
                    <div className="text-gray-600 font-mono text-[9px]">{sets[ri].size} TTPs</div>
                  </td>
                  {groups.map((_, ci) => {
                    const isDiag = ri === ci;
                    const score  = isDiag ? 1 : jaccard(sets[ri], sets[ci]);
                    const pct    = Math.round(score * 100);
                    return (
                      <td key={ci}
                        className="p-3 text-center rounded"
                        style={{ background: isDiag ? '#1f2937' : simBg(score) }}
                      >
                        <span className={`font-mono font-bold text-sm ${
                          isDiag ? 'text-gray-600' : pct > 0 ? 'text-white' : 'text-gray-800'
                        }`}>
                          {pct}%
                        </span>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pairwise shared technique cards */}
      <div>
        <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-4">
          Pairwise Shared Techniques
        </div>
        <div className="space-y-3">
          {groups.flatMap((a, i) =>
            groups.slice(i + 1).map((b, j) => {
              const aIdx   = i;
              const bIdx   = i + 1 + j;
              const aIds   = sets[aIdx];
              const bIds   = sets[bIdx];
              const shared = [...aIds].filter(id => bIds.has(id));
              const score  = jaccard(aIds, bIds);
              return (
                <div key={`${a.attack_id}-${b.attack_id}`}
                  className="bg-gray-800/60 rounded-lg p-4 border border-gray-700/60"
                >
                  <div className="flex items-center gap-3 mb-3 flex-wrap">
                    <span className="font-semibold text-sm" style={{ color: a.color }}>{a.name}</span>
                    <span className="text-gray-600 text-xs">×</span>
                    <span className="font-semibold text-sm" style={{ color: b.color }}>{b.name}</span>
                    <div className="ml-auto flex items-center gap-3 shrink-0">
                      <span className="text-xs font-mono bg-gray-700/80 text-white px-2 py-0.5 rounded">
                        {Math.round(score * 100)}% Jaccard
                      </span>
                      <span className="text-xs text-amber-400 font-medium">{shared.length} shared</span>
                    </div>
                  </div>
                  {shared.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {shared.slice(0, 40).map(id => (
                        <span key={id}
                          className="text-[10px] font-mono bg-amber-900/20 text-amber-400 border border-amber-900/30 px-1.5 py-0.5 rounded"
                        >{id}</span>
                      ))}
                      {shared.length > 40 && (
                        <span className="text-[10px] text-gray-600">+{shared.length - 40} more</span>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-gray-600">No shared techniques.</p>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

// ── Combined ATT&CK Matrix ─────────────────────────────────────────────────────
function CombinedMatrix({
  groups, tactics, techniquesByTactic, isLoading,
}: {
  groups: LoadedGroup[];
  tactics: Tactic[];
  techniquesByTactic: Map<string, TechniqueListItem[]>;
  isLoading: boolean;
}) {
  if (isLoading || !tactics.length)
    return (
      <div className="flex items-center justify-center h-40 text-gray-500 text-sm">
        Loading ATT&CK matrix…
      </div>
    );

  if (groups.length < 2)
    return <div className="text-gray-600 text-sm text-center py-12">Waiting for group data…</div>;

  const sets = groups.map(getIds);

  const columns = tactics
    .map(tactic => {
      const techs = techniquesByTactic.get(tactic.shortname) ?? [];
      const relevant = techs.filter(t => sets.some(s => s.has(t.attack_id)));
      return { tactic, techs: relevant };
    })
    .filter(c => c.techs.length > 0);

  return (
    <div>
      {/* Legend */}
      <div className="flex gap-4 mb-5 flex-wrap">
        {groups.map((g, i) => (
          <div key={g.attack_id} className="flex items-center gap-1.5 text-xs" style={{ color: g.color }}>
            <span className="w-3 h-3 rounded-sm shrink-0" style={{ background: g.color }} />
            {g.name}
            <span className="text-gray-600 font-mono text-[9px]">({sets[i].size})</span>
          </div>
        ))}
        <div className="flex items-center gap-1.5 text-xs text-gray-600 ml-auto">
          <span className="w-3 h-3 rounded-sm bg-gray-800 border border-gray-700" />
          Not used
        </div>
      </div>

      <div className="overflow-x-auto">
        <div className="flex gap-1" style={{ width: 'max-content' }}>
          {columns.map(({ tactic, techs }) => (
            <div key={tactic.shortname} style={{ width: 100, flexShrink: 0 }}>
              {/* Tactic header */}
              <div className="rounded-t bg-red-900/70 border border-red-900/50 px-1.5 py-2 mb-0.5 text-center min-h-[48px] flex flex-col items-center justify-center">
                <div className="text-white text-[8px] font-bold leading-tight text-center line-clamp-2">
                  {tactic.name}
                </div>
                <div className="text-red-300 text-[7px] font-mono mt-0.5">{tactic.attack_id}</div>
              </div>

              {/* Techniques */}
              {techs.map(tech => {
                const usedBy = sets.map(s => s.has(tech.attack_id));
                const sharedCount = usedBy.filter(Boolean).length;
                return (
                  <div
                    key={tech.attack_id}
                    title={`${tech.attack_id}: ${tech.name}`}
                    className="rounded bg-gray-800/80 border border-gray-700/40 px-1.5 pt-1 pb-1.5 mb-0.5"
                  >
                    <div className="font-mono text-[8px] text-gray-500 mb-1 leading-none">{tech.attack_id}</div>
                    <div className="flex gap-0.5">
                      {groups.map((g, i) => (
                        <span
                          key={g.attack_id}
                          className="rounded-sm"
                          style={{
                            width: 10, height: 10,
                            background: usedBy[i] ? g.color : '#1f2937',
                            opacity: usedBy[i] ? 1 : 0.4,
                            flexShrink: 0,
                          }}
                          title={usedBy[i] ? `Used by ${g.name}` : `Not in ${g.name}`}
                        />
                      ))}
                      {sharedCount >= 2 && (
                        <span className="text-[7px] text-amber-400 ml-0.5 font-bold leading-[10px]">
                          {sharedCount}×
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Technique Table ────────────────────────────────────────────────────────────
function TechniqueTableView({
  groups, techs, allCount,
  techFilter, setTechFilter,
  techSort, onSort, sortDir,
}: {
  groups: LoadedGroup[];
  techs: { id: string; name: string; tactic: string }[];
  allCount: number;
  techFilter: TechFilter;
  setTechFilter: (f: TechFilter) => void;
  techSort: string;
  onSort: (col: string) => void;
  sortDir: 1 | -1;
}) {
  const sets = groups.map(getIds);

  const sharedCount    = Array.from(new Set(groups.flatMap(g => g.techniques.map(t => t.attack_id))))
    .filter(id => sets.filter(s => s.has(id)).length >= 2).length;
  const exclusiveCount = Array.from(new Set(groups.flatMap(g => g.techniques.map(t => t.attack_id))))
    .filter(id => sets.filter(s => s.has(id)).length === 1).length;

  function SortIcon({ col }: { col: string }) {
    if (techSort !== col) return <span className="text-gray-700"> ↕</span>;
    return <span className="text-mitre-accent">{sortDir === 1 ? ' ↑' : ' ↓'}</span>;
  }

  return (
    <div>
      {/* Filter bar */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <div className="flex gap-1 bg-gray-800 rounded p-0.5">
          {([
            ['all',       `All (${allCount})`],
            ['shared',    `Shared 2+ (${sharedCount})`],
            ['exclusive', `Exclusive (${exclusiveCount})`],
          ] as [TechFilter, string][]).map(([f, label]) => (
            <button key={f} onClick={() => setTechFilter(f)}
              className={`text-xs px-3 py-1 rounded transition-colors ${
                techFilter === f ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'
              }`}
            >{label}</button>
          ))}
        </div>
        <span className="text-[10px] text-gray-600 ml-auto">
          {techs.length} technique{techs.length !== 1 ? 's' : ''} · click column header to sort
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="border-b border-gray-700">
              <th
                className="text-left py-2 pr-3 text-gray-500 font-semibold w-20 cursor-pointer hover:text-gray-300"
                onClick={() => onSort('id')}
              >
                ID <SortIcon col="id" />
              </th>
              <th className="text-left py-2 pr-3 text-gray-500 font-semibold">Name</th>
              <th className="text-left py-2 pr-3 text-gray-500 font-semibold w-28">Tactic</th>
              {groups.map((g, i) => (
                <th
                  key={g.attack_id}
                  className="text-center py-2 px-2 font-semibold w-16 cursor-pointer hover:opacity-80 transition-opacity"
                  style={{ color: GROUP_COLORS[i] }}
                  onClick={() => onSort(g.attack_id)}
                  title={`Sort by ${g.name}`}
                >
                  <div className="truncate max-w-[56px] text-[10px]">{g.name}</div>
                  <div className="font-mono text-[8px] opacity-60 font-normal">{g.attack_id}</div>
                  <SortIcon col={g.attack_id} />
                </th>
              ))}
              <th className="text-center py-2 px-2 text-gray-500 font-semibold w-12">Count</th>
            </tr>
          </thead>
          <tbody>
            {techs.map(t => {
              const usedBy   = sets.map(s => s.has(t.id));
              const useCount = usedBy.filter(Boolean).length;
              return (
                <tr key={t.id} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
                  <td className="py-1.5 pr-3 font-mono text-blue-400">{t.id}</td>
                  <td className="py-1.5 pr-3 text-gray-300">{t.name}</td>
                  <td className="py-1.5 pr-3 text-gray-500 text-[10px]">{t.tactic}</td>
                  {groups.map((g, i) => (
                    <td key={g.attack_id} className="py-1.5 px-2 text-center">
                      {usedBy[i]
                        ? <span className="font-bold text-sm" style={{ color: g.color }}>✓</span>
                        : <span className="text-gray-800">·</span>
                      }
                    </td>
                  ))}
                  <td className="py-1.5 px-2 text-center">
                    <span className={`text-xs font-bold ${
                      useCount >= 2 ? 'text-amber-400' : 'text-gray-600'
                    }`}>
                      {useCount}/{groups.length}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {techs.length === 0 && (
          <div className="text-center text-gray-600 py-8 text-sm">
            No techniques match the current filter.
          </div>
        )}
      </div>
    </div>
  );
}
