import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { iocApi, sectorApi } from '@/api/client';
import type { ActorRelevance } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { useAppStore } from '@/store';
import { safeHref } from '@/utils/url';

const windows = [
  { label: 'Quarter', days: 90 },
  { label: 'Year', days: 365 },
  { label: '2 Years', days: 730 },
];

export function SectorIntel() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { replaceTechniques, setOverlayGroup } = useAppStore();
  const [selectedSectors, setSelectedSectors] = useState<string[]>([]);
  const [selectedRegions, setSelectedRegions] = useState<string[]>([]);
  const [technologies, setTechnologies] = useState<string[]>([]);
  const [days, setDays] = useState(365);

  const sources = useQuery({ queryKey: ['sector-sources'], queryFn: sectorApi.sources });
  const sectors = useQuery({ queryKey: ['sector-options'], queryFn: sectorApi.sectors });
  const regions = useQuery({ queryKey: ['sector-regions'], queryFn: sectorApi.regions });
  const technologyOptions = useQuery({ queryKey: ['sector-technologies'], queryFn: sectorApi.technologies });
  const relevance = useQuery({
    queryKey: ['sector-relevance', selectedSectors.join(','), selectedRegions.join(','), technologies.join(','), days],
    queryFn: () => sectorApi.relevance({ sectors: selectedSectors, regions: selectedRegions, technologies, days, limit: 30 }),
    enabled: selectedSectors.length > 0,
  });
  const actorIds = (relevance.data ?? []).map(actor => actor.actor_attack_id);
  const iocCounts = useQuery({
    queryKey: ['sector-actor-ioc-counts', actorIds.join(',')],
    queryFn: () => iocApi.actorCounts(actorIds, 180, false),
    enabled: actorIds.length > 0,
  });
  const sync = useMutation({
    mutationFn: sectorApi.syncMispGalaxy,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sector-sources'] });
      qc.invalidateQueries({ queryKey: ['sector-options'] });
      qc.invalidateQueries({ queryKey: ['sector-relevance'] });
    },
  });

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Header title="Sector Intelligence" />
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="grid xl:grid-cols-[420px_1fr] gap-5">
            <Panel title="Client Context">
              <div className="space-y-4 p-4">
                <MultiChoiceDropdown
                  label="Sectors"
                  placeholder="Select sectors"
                  selected={selectedSectors}
                  onChange={setSelectedSectors}
                  options={(sectors.data ?? []).map(item => ({
                    id: item.id,
                    label: item.label,
                    meta: item.actor_count ? `${item.actor_count}` : '',
                  }))}
                />
                <MultiChoiceDropdown
                  label="Regions / Geography"
                  placeholder="Any region"
                  selected={selectedRegions}
                  onChange={setSelectedRegions}
                  options={(regions.data ?? []).map(item => ({
                    id: item.id,
                    label: item.label,
                    meta: item.actor_count ? `${item.actor_count}` : '',
                  }))}
                  allowEmpty
                />
                <MultiChoiceDropdown
                  label="Technologies / Environment"
                  placeholder="Any technology"
                  selected={technologies}
                  onChange={setTechnologies}
                  options={(technologyOptions.data ?? []).map(item => ({ id: item.id, label: item.label }))}
                  allowEmpty
                />
                <div>
                  <span className="label">Activity Window</span>
                  <div className="grid grid-cols-3 gap-2">
                    {windows.map(item => (
                      <button
                        key={item.days}
                        onClick={() => setDays(item.days)}
                        className={`rounded border px-3 py-2 text-xs font-semibold ${days === item.days ? 'border-mitre-accent bg-mitre-accent/20 text-mitre-accent' : 'border-gray-700 text-gray-400 hover:text-white'}`}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-500">
                  Results are hard-filtered by selected sectors, optional regions, and selected technology/environment TTP matches. Ranking then uses recency and TTP depth.
                </div>
              </div>
            </Panel>

            <Panel title="Intel Sync">
              <div className="p-4 space-y-4">
                <p className="text-sm text-gray-400">
                  Sync MISP Galaxy threat-actor metadata into the local database. This adds evidence-backed actor sector, victim geography, origin, motivation, refs, and alias observations.
                </p>
                <button onClick={() => sync.mutate()} disabled={sync.isPending} className="primary">
                  {sync.isPending ? 'Syncing...' : 'Sync MISP Galaxy'}
                </button>
                {sync.data && (
                  <div className="rounded border border-green-900 bg-green-950/30 p-3 text-xs text-green-300">
                    Synced {sync.data.actors} actors, matched {sync.data.matched} to ATT&amp;CK groups, stored {sync.data.observations} observations.
                  </div>
                )}
                {sync.error && <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">{String(sync.error)}</div>}
                <div className="grid md:grid-cols-2 gap-3">
                  {(sources.data ?? []).map(source => (
                    <div key={source.source_id} className="rounded border border-gray-800 bg-gray-950 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <b className="text-sm text-white">{source.label}</b>
                        <span className={`rounded px-2 py-1 text-[10px] ${source.sync_status === 'ok' ? 'bg-green-950 text-green-400' : source.sync_status === 'error' ? 'bg-red-950 text-red-400' : 'bg-gray-800 text-gray-500'}`}>{source.sync_status}</span>
                      </div>
                      <p className="mt-2 truncate text-xs text-gray-500">{source.url}</p>
                      <p className="mt-1 text-[10px] text-gray-600">Last sync: {source.last_synced_at ?? 'never'}</p>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          </section>

          <Panel title={`Relevant Actors for ${selectedSectors.join(', ') || 'selected sectors'}${selectedRegions.length ? ` / ${selectedRegions.join(', ')}` : ''}${technologies.length ? ` / ${technologies.join(', ')}` : ''}`}>
            {relevance.isLoading ? (
              <div className="p-4 text-sm text-gray-500">Scoring actors...</div>
            ) : relevance.data?.length ? (
              <div className="divide-y divide-gray-800">
                {relevance.data.map(actor => (
                  <ActorRow
                    key={actor.actor_attack_id}
                    actor={actor}
                    iocCount={iocCounts.data?.[actor.actor_attack_id] ?? 0}
                    onOpenActor={() => navigate(`/apt?group=${actor.actor_attack_id}&tab=overview`)}
                    onOpenTtps={() => navigate(`/apt?group=${actor.actor_attack_id}&tab=techniques`)}
                    onOpenIocs={() => navigate(`/apt?group=${actor.actor_attack_id}&tab=iocs`)}
                    onShowMatrix={() => {
                      setOverlayGroup(actor.actor_attack_id, actor.actor_name);
                      replaceTechniques(actor.techniques.map(item => item.attack_id));
                      navigate('/navigator');
                    }}
                  />
                ))}
              </div>
            ) : (
              <div className="p-4 text-sm text-gray-500">
                No ranked actors match the selected filters. Remove a region or technology filter, run MISP Galaxy sync, or choose broader sectors such as private sector, government, finance, telecom, energy, or technology.
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function MultiChoiceDropdown({
  label,
  placeholder,
  selected,
  options,
  onChange,
  allowEmpty = false,
}: {
  label: string;
  placeholder: string;
  selected: string[];
  options: Array<{ id: string; label: string; meta?: string }>;
  onChange: (values: string[]) => void;
  allowEmpty?: boolean;
}) {
  const [search, setSearch] = useState('');
  const selectedSet = new Set(selected);
  const sortedOptions = [...options].sort((left, right) => left.label.localeCompare(right.label, undefined, { sensitivity: 'base' }));
  const normalizedSearch = search.trim().toLowerCase();
  const visibleOptions = normalizedSearch
    ? sortedOptions.filter(item => [item.label, item.id, item.meta ?? ''].some(value => value.toLowerCase().includes(normalizedSearch)))
    : sortedOptions;
  const labels = new Map(sortedOptions.map(item => [item.id, item.label]));
  const display = selected.length
    ? selected.map(item => labels.get(item) ?? item).join(', ')
    : placeholder;

  const toggle = (id: string) => {
    if (selectedSet.has(id)) {
      const next = selected.filter(item => item !== id);
      if (next.length || allowEmpty) onChange(next);
      return;
    }
    onChange([...selected, id]);
  };

  return (
    <div>
      <span className="label">{label}</span>
      <details className="group relative">
        <summary className="field flex cursor-pointer list-none items-center justify-between gap-3">
          <span className={`truncate ${selected.length ? 'text-gray-100' : 'text-gray-500'}`}>{display}</span>
          <span className="text-xs text-gray-500 group-open:rotate-180">v</span>
        </summary>
        <div className="absolute z-20 mt-1 w-full rounded border border-gray-700 bg-gray-950 shadow-xl">
          <div className="border-b border-gray-800 p-2">
            <input
              type="search"
              value={search}
              onChange={event => setSearch(event.target.value)}
              placeholder={`Search ${label.toLowerCase()}...`}
              className="w-full rounded border border-gray-700 bg-gray-900 px-2 py-2 text-xs text-gray-200 outline-none placeholder:text-gray-600 focus:border-mitre-accent"
            />
          </div>
          <div className="max-h-64 overflow-y-auto p-2">
            {visibleOptions.length ? visibleOptions.map(item => (
              <label key={item.id} className="flex cursor-pointer items-center justify-between gap-3 rounded px-2 py-2 text-xs text-gray-300 hover:bg-gray-800">
                <span className="flex min-w-0 items-center gap-2">
                  <input
                    type="checkbox"
                    checked={selectedSet.has(item.id)}
                    onChange={() => toggle(item.id)}
                    className="h-3.5 w-3.5 accent-mitre-accent"
                  />
                  <span className="truncate">{item.label}</span>
                </span>
                {item.meta && <span className="shrink-0 text-[10px] text-gray-600">{item.meta}</span>}
              </label>
            )) : (
              <div className="px-2 py-3 text-xs text-gray-600">{options.length ? 'No matching options' : 'No options loaded'}</div>
            )}
          </div>
          <div className="flex items-center justify-between border-t border-gray-800 px-2 py-2">
            <span className="text-[10px] text-gray-600">{selected.length} selected</span>
            <button
              type="button"
              disabled={!allowEmpty}
              onClick={() => allowEmpty && onChange([])}
              className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-400 enabled:hover:border-mitre-accent enabled:hover:text-mitre-accent disabled:opacity-40"
            >
              Clear
            </button>
          </div>
        </div>
      </details>
      {selected.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {selected.map(item => (
            <button
              key={item}
              type="button"
              onClick={() => {
                const next = selected.filter(value => value !== item);
                if (next.length || allowEmpty) onChange(next);
              }}
              className="rounded border border-mitre-accent/40 bg-mitre-accent/10 px-2 py-1 text-[10px] text-mitre-accent"
            >
              {labels.get(item) ?? item} x
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function ActorRow({
  actor,
  iocCount,
  onOpenActor,
  onOpenTtps,
  onOpenIocs,
  onShowMatrix,
}: {
  actor: ActorRelevance;
  iocCount: number;
  onOpenActor: () => void;
  onOpenTtps: () => void;
  onOpenIocs: () => void;
  onShowMatrix: () => void;
}) {
  const [showTtps, setShowTtps] = useState(false);
  return (
    <div className="grid gap-4 p-4 lg:grid-cols-[240px_1fr_320px]">
      <div>
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-1 text-[10px] font-bold ${badge(actor.relevance)}`}>{actor.score}</span>
          <b className="text-white">{actor.actor_name}</b>
        </div>
        <div className="mt-1 font-mono text-xs text-mitre-accent">{actor.actor_attack_id}</div>
        <div className="mt-2 text-[10px] text-gray-600">
          {actor.technique_count} TTPs · {actor.campaign_count} campaigns · {actor.recent_campaign_count} recent
        </div>
        {actor.last_activity && <div className="mt-1 text-[10px] text-gray-500">Last activity: {actor.last_activity}</div>}
        <div className="mt-3 flex flex-wrap gap-2">
          <button onClick={onOpenActor} className="secondary-action">Actor info</button>
          <button onClick={onOpenTtps} className="secondary-action">TTP info</button>
          <button onClick={onOpenIocs} className="secondary-action">IOCs ({iocCount})</button>
          <button onClick={onShowMatrix} className="primary-action">Show on matrix</button>
        </div>
      </div>
      <div>
        <div className="flex flex-wrap gap-1">
          {actor.aliases.slice(0, 8).map(alias => <span key={alias} className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-500">{alias}</span>)}
        </div>
        <ul className="mt-3 space-y-1 text-xs text-gray-400">
          {actor.reasons.map(reason => <li key={reason}>• {reason}</li>)}
        </ul>
        <div className="mt-3">
          <button onClick={() => setShowTtps(value => !value)} className="text-xs text-mitre-accent hover:underline">
            {showTtps ? 'Hide relevant TTPs' : `Show relevant TTPs (${actor.techniques.length})`}
          </button>
          {showTtps && (
            <div className="mt-2 grid gap-1 sm:grid-cols-2 xl:grid-cols-3">
              {actor.techniques.slice(0, 36).map(tech => (
                <a
                  key={tech.attack_id}
                  href={`/navigator?technique=${encodeURIComponent(tech.attack_id)}`}
                  className="rounded border border-gray-800 bg-gray-950 px-2 py-1.5 hover:border-mitre-accent"
                >
                  <span className="block font-mono text-[10px] text-mitre-accent">{tech.attack_id}</span>
                  <span className="block truncate text-[11px] text-gray-300">{tech.name}</span>
                  {tech.tactics.length > 0 && <span className="block truncate text-[10px] text-gray-600">{tech.tactics.join(', ')}</span>}
                </a>
              ))}
              {actor.techniques.length > 36 && <span className="text-[10px] text-gray-600">+ {actor.techniques.length - 36} more techniques in actor profile</span>}
            </div>
          )}
        </div>
      </div>
      <div className="space-y-2">
        {actor.evidence.slice(0, 4).map((item, idx) => (
          <a key={`${item.type}-${idx}`} href={safeHref(item.url)} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 bg-gray-950 p-2 hover:border-mitre-accent">
            <div className="flex items-center justify-between gap-2">
              <b className="text-[11px] text-gray-300">{item.type}: {item.value}</b>
              <span className="text-[10px] text-gray-600">{item.confidence}</span>
            </div>
            <p className="mt-1 text-[10px] text-gray-500">{item.evidence}</p>
          </a>
        ))}
      </div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function badge(level: string) {
  if (level === 'high') return 'bg-red-950 text-red-300';
  if (level === 'medium') return 'bg-amber-950 text-amber-300';
  return 'bg-gray-800 text-gray-400';
}
