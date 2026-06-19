import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { aptApi, iocApi, syncApi, type IOCLibraryItem } from '@/api/client';
import { useAppStore } from '@/store';
import type { GroupListItem } from '@/types/attack';

type FeedKind = 'custom-json' | 'custom-csv' | 'custom-txt';

const sortOptions = [
  ['last_seen_desc', 'Last seen newest'],
  ['last_seen_asc', 'Last seen oldest'],
  ['actor_asc', 'Group / attacker A-Z'],
  ['actor_desc', 'Group / attacker Z-A'],
  ['type_asc', 'Type A-Z'],
  ['type_desc', 'Type Z-A'],
  ['value_asc', 'Indicator A-Z'],
  ['source_asc', 'Source A-Z'],
  ['confidence_desc', 'Confidence high first'],
];

export function IOCLibrary() {
  const qc = useQueryClient();
  const { domain, version } = useAppStore();
  const [search, setSearch] = useState('');
  const [type, setType] = useState('');
  const [source, setSource] = useState('');
  const [actorIds, setActorIds] = useState<string[]>([]);
  const [actorSearch, setActorSearch] = useState('');
  const [sort, setSort] = useState('last_seen_desc');
  const [offset, setOffset] = useState(0);
  const [feedLabel, setFeedLabel] = useState('');
  const [feedUrl, setFeedUrl] = useState('');
  const [feedKind, setFeedKind] = useState<FeedKind>('custom-json');
  const [mispUrl, setMispUrl] = useState('');
  const [taxiiUrl, setTaxiiUrl] = useState('');
  const [taxiiToken, setTaxiiToken] = useState('');
  const [taxiiUsername, setTaxiiUsername] = useState('');
  const [taxiiPassword, setTaxiiPassword] = useState('');
  const [aiEnrichIocs, setAiEnrichIocs] = useState(false);
  const [aiProvider, setAiProvider] = useState<'local' | 'claude' | 'openai' | 'gemini'>('local');
  const limit = 100;

  const sources = useQuery({ queryKey: ['ioc-sources'], queryFn: iocApi.sources });
  const groups = useQuery({
    queryKey: ['ioc-library-groups', domain, version],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined }),
  });
  const library = useQuery({
    queryKey: ['ioc-library', search, type, source, actorIds, sort, offset],
    queryFn: () => iocApi.library({ search, type, source, actor: actorIds, sort, limit, offset }),
  });

  const typeOptions = useMemo(() => {
    const fromRows = new Set((library.data?.items ?? []).map(item => item.type).filter(Boolean));
    ['domain', 'ip:port', 'ipv4', 'ipv6', 'md5', 'sha1', 'sha256', 'url', 'malware-family'].forEach(item => fromRows.add(item));
    return Array.from(fromRows).sort((a, b) => a.localeCompare(b));
  }, [library.data?.items]);

  const createSource = useMutation({
    mutationFn: iocApi.createSource,
    onSuccess: () => {
      setFeedLabel('');
      setFeedUrl('');
      setMispUrl('');
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const iocSyncOptions = () => ({ ai_enrich: aiEnrichIocs, ai_provider: aiProvider });
  const syncAll = useMutation({
    mutationFn: () => syncApi.ioc(7, iocSyncOptions()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const syncThreatFox = useMutation({
    mutationFn: () => iocApi.syncThreatFox(7, iocSyncOptions()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const syncMalpedia = useMutation({
    mutationFn: iocApi.syncMalpedia,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const syncOtx = useMutation({
    mutationFn: () => iocApi.syncOtx('subscribed', iocSyncOptions()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const enrichIocTtps = useMutation({
    mutationFn: () => iocApi.enrichIocTtps({ ...iocSyncOptions(), limit: 20000 }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const importStix = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      return iocApi.importStix(JSON.parse(text), { source_label: file.name });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const importTaxii = useMutation({
    mutationFn: () => iocApi.importTaxii({
      objects_url: taxiiUrl,
      token: taxiiToken,
      username: taxiiUsername,
      password: taxiiPassword,
      source_label: 'TAXII IOC Import',
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ioc-library'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });

  const total = library.data?.total ?? 0;
  const rows = library.data?.items ?? [];
  const maxPage = Math.max(0, Math.floor(Math.max(0, total - 1) / limit) * limit);
  const selectedGroups = useMemo(
    () => actorIds.map(id => groups.data?.find(group => group.attack_id === id)).filter(Boolean) as GroupListItem[],
    [actorIds, groups.data],
  );

  const resetFilters = () => {
    setSearch('');
    setType('');
    setSource('');
    setActorIds([]);
    setActorSearch('');
    setSort('last_seen_desc');
    setOffset(0);
  };

  const setFilter = (fn: () => void) => {
    fn();
    setOffset(0);
  };

  const openEnrichment = (indicator: string) => {
    window.open(`/virustotal?indicator=${encodeURIComponent(indicator)}`, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="IOC Library" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="grid items-start gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Search and filter IOCs">
              <div className="flex flex-wrap gap-3 p-4">
                <input
                  value={search}
                  onChange={event => setFilter(() => setSearch(event.target.value))}
                  placeholder="Search IOC, description, malware, campaign..."
                  className="field min-w-[280px] flex-1"
                />
                <select value={type} onChange={event => setFilter(() => setType(event.target.value))} className="field w-40">
                  <option value="">All types</option>
                  {typeOptions.map(item => <option key={item} value={item}>{item}</option>)}
                </select>
                <select value={source} onChange={event => setFilter(() => setSource(event.target.value))} className="field w-44">
                  <option value="">All sources</option>
                  {(sources.data ?? []).map(item => <option key={item.source_id} value={item.source_id}>{item.label}</option>)}
                </select>
                <GroupMultiSelect
                  groups={groups.data ?? []}
                  selectedIds={actorIds}
                  search={actorSearch}
                  loading={groups.isLoading}
                  onSearchChange={setActorSearch}
                  onChange={ids => setFilter(() => setActorIds(ids))}
                />
                <select value={sort} onChange={event => setFilter(() => setSort(event.target.value))} className="field w-48">
                  {sortOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
                <button onClick={resetFilters} className="secondary-action min-h-10">Reset</button>
              </div>
            </Panel>

            <Panel title="Sync and connect sources">
              <div className="space-y-3 p-4">
                <div className="flex flex-wrap gap-2">
                  <button onClick={() => syncAll.mutate()} disabled={syncAll.isPending} className="primary-action">
                    {syncAll.isPending ? 'Syncing...' : 'Sync all'}
                  </button>
                  <a
                    href={iocApi.stixExportUrl({ search, type, source, actor: actorIds, sort, limit: 5000 })}
                    className="secondary-action"
                  >
                    Export STIX
                  </a>
                  <label className="secondary-action cursor-pointer">
                    {importStix.isPending ? 'Importing...' : 'Import STIX'}
                    <input
                      type="file"
                      accept=".json,.stix,application/json,application/stix+json"
                      className="hidden"
                      disabled={importStix.isPending}
                      onChange={event => {
                        const file = event.currentTarget.files?.[0];
                        if (file) importStix.mutate(file);
                        event.currentTarget.value = '';
                      }}
                    />
                  </label>
                  <button onClick={() => syncThreatFox.mutate()} disabled={syncThreatFox.isPending} className="secondary-action">
                    ThreatFox
                  </button>
                  <button onClick={() => syncMalpedia.mutate()} disabled={syncMalpedia.isPending} className="secondary-action">
                    Malpedia
                  </button>
                  <button onClick={() => syncOtx.mutate()} disabled={syncOtx.isPending} className="secondary-action">
                    OTX
                  </button>
                  <button onClick={() => enrichIocTtps.mutate()} disabled={enrichIocTtps.isPending} className="secondary-action">
                    {enrichIocTtps.isPending ? 'Enriching...' : 'Enrich IOC TTPs'}
                  </button>
                </div>
                <div className="grid gap-2 rounded border border-gray-800 bg-gray-950 p-3">
                  <label className="flex items-start gap-2 text-xs text-gray-300">
                    <input
                      type="checkbox"
                      checked={aiEnrichIocs}
                      onChange={event => setAiEnrichIocs(event.target.checked)}
                      className="mt-0.5"
                    />
                    <span>Use AI as last fallback when synced IOCs have no strict report or enrichment-platform TTP mapping.</span>
                  </label>
                  <select value={aiProvider} onChange={event => setAiProvider(event.target.value as typeof aiProvider)} className="field">
                    <option value="local">Local LLM</option>
                    <option value="claude">Claude</option>
                    <option value="openai">OpenAI</option>
                    <option value="gemini">Gemini</option>
                    <option value="minimax">MiniMax</option>
                  </select>
                </div>
                <SourceStatus mutation={syncAll} label="All IOC sources" />
                <SourceStatus mutation={syncThreatFox} label="ThreatFox" />
                <SourceStatus mutation={syncMalpedia} label="Malpedia" />
                <SourceStatus mutation={syncOtx} label="OTX" />
                <SourceStatus mutation={enrichIocTtps} label="IOC-to-TTP enrichment" />
                <SourceStatus mutation={importStix} label="STIX import" />
                <div className="grid gap-2">
                  <input value={feedLabel} onChange={event => setFeedLabel(event.target.value)} placeholder="Feed label" className="field" />
                  <input value={feedUrl} onChange={event => setFeedUrl(event.target.value)} placeholder="https://example.local/iocs.json|csv|txt" className="field" />
                  <div className="grid grid-cols-[1fr_auto] gap-2">
                    <select value={feedKind} onChange={event => setFeedKind(event.target.value as FeedKind)} className="field">
                      <option value="custom-json">JSON</option>
                      <option value="custom-csv">CSV</option>
                      <option value="custom-txt">TXT</option>
                    </select>
                    <button
                      onClick={() => createSource.mutate({ label: feedLabel, url: feedUrl, kind: feedKind })}
                      disabled={!feedLabel.trim() || !feedUrl.trim() || createSource.isPending}
                      className="primary-action disabled:opacity-40"
                    >
                      Add feed
                    </button>
                  </div>
                </div>
                <div className="rounded border border-gray-800 bg-gray-950 p-3">
                  <div className="mb-2 text-xs font-semibold text-gray-200">Connect MISP export</div>
                  <div className="grid gap-2">
                    <input
                      value={mispUrl}
                      onChange={event => setMispUrl(event.target.value)}
                      placeholder="MISP JSON export URL or local gateway URL"
                      className="field"
                    />
                    <button
                      onClick={() => createSource.mutate({ label: 'MISP IOC Export', url: mispUrl, kind: 'custom-json', source_id: 'custom-misp-export' })}
                      disabled={!mispUrl.trim() || createSource.isPending}
                      className="secondary-action disabled:opacity-40"
                    >
                      Connect MISP JSON
                    </button>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-gray-600">
                    Use a MISP event or attribute JSON export URL. Records are parsed as a custom JSON IOC feed.
                  </p>
                </div>
                <div className="rounded border border-gray-800 bg-gray-950 p-3">
                  <div className="mb-2 text-xs font-semibold text-gray-200">Pull TAXII collection</div>
                  <div className="grid gap-2">
                    <input
                      value={taxiiUrl}
                      onChange={event => setTaxiiUrl(event.target.value)}
                      placeholder="https://taxii.example/api2/collections/{id}/objects/"
                      className="field"
                    />
                    <input
                      value={taxiiToken}
                      onChange={event => setTaxiiToken(event.target.value)}
                      placeholder="Bearer token (optional)"
                      className="field"
                    />
                    <div className="grid grid-cols-2 gap-2">
                      <input value={taxiiUsername} onChange={event => setTaxiiUsername(event.target.value)} placeholder="Username" className="field" />
                      <input value={taxiiPassword} onChange={event => setTaxiiPassword(event.target.value)} placeholder="Password" type="password" className="field" />
                    </div>
                    <button
                      onClick={() => importTaxii.mutate()}
                      disabled={!taxiiUrl.trim() || importTaxii.isPending}
                      className="secondary-action disabled:opacity-40"
                    >
                      {importTaxii.isPending ? 'Pulling TAXII...' : 'Pull TAXII STIX'}
                    </button>
                  </div>
                  <p className="mt-2 text-[10px] leading-relaxed text-gray-600">
                    Provide the TAXII 2.1 collection objects URL. Returned STIX indicators and observed-data are imported into the IOC Library.
                  </p>
                </div>
                {createSource.error && <ErrorText error={createSource.error} />}
                {importTaxii.error && <ErrorText error={importTaxii.error} />}
                <ImportResult result={importStix.data} />
                <ImportResult result={importTaxii.data} />
              </div>
            </Panel>
          </section>

          {selectedGroups.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {selectedGroups.map(group => (
                <button
                  key={group.attack_id}
                  onClick={() => setFilter(() => setActorIds(actorIds.filter(id => id !== group.attack_id)))}
                  className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-2 py-1 text-xs text-mitre-accent hover:bg-mitre-accent/20"
                  title="Remove group filter"
                >
                  {group.name} <span className="font-mono text-[10px]">{group.attack_id}</span> x
                </button>
              ))}
            </div>
          )}

          <Panel title={`IOC records (${total})`}>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1180px] text-left text-xs">
                <thead className="bg-gray-950 text-[10px] uppercase text-gray-500">
                  <tr>
                    <th className="p-3">Type</th>
                    <th className="p-3">Indicator</th>
                    <th className="p-3">Group / attacker</th>
                    <th className="p-3">Context</th>
                    <th className="p-3">Freshness</th>
                    <th className="p-3">Source</th>
                    <th className="p-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {library.isLoading ? (
                    <tr><td colSpan={7} className="p-6 text-center text-gray-500">Loading IOC library...</td></tr>
                  ) : rows.length ? rows.map(item => (
                    <IOCRow
                      key={item.id}
                      item={item}
                      onEnrichment={() => openEnrichment(item.value)}
                    />
                  )) : (
                    <tr><td colSpan={7} className="p-6 text-center text-gray-500">No IOC records match the current filters.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-gray-800 px-4 py-3 text-xs text-gray-500">
              <span>Showing {rows.length ? offset + 1 : 0}-{Math.min(offset + rows.length, total)} of {total}</span>
              <div className="flex gap-2">
                <button onClick={() => setOffset(Math.max(0, offset - limit))} disabled={offset <= 0} className="secondary-action disabled:opacity-40">Previous</button>
                <button onClick={() => setOffset(Math.min(maxPage, offset + limit))} disabled={offset + limit >= total} className="secondary-action disabled:opacity-40">Next</button>
              </div>
            </div>
          </Panel>

        </div>
      </div>
    </div>
  );
}

function IOCRow({ item, onEnrichment }: {
  item: IOCLibraryItem;
  onEnrichment: () => void;
}) {
  const navigate = useNavigate();
  return (
    <tr className="align-top hover:bg-gray-900/70">
      <td className="p-3">
        <span className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-300">{item.type}</span>
        <div className="mt-2 text-[10px] text-gray-600">conf {item.confidence}</div>
      </td>
      <td className="max-w-md p-3">
        <div className="break-all font-mono text-gray-200">{item.value}</div>
        {item.description && <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-gray-500">{item.description}</p>}
        {item.tags.length > 0 && <div className="mt-2 flex flex-wrap gap-1">{item.tags.slice(0, 8).map(tag => <Chip key={tag}>{tag}</Chip>)}</div>}
      </td>
      <td className="p-3">
        {item.actors.length ? (
          <div className="space-y-1">
            {item.actors.slice(0, 4).map(actor => (
              <button
                key={`${actor.actor_attack_id}-${actor.actor_name}`}
                onClick={() => navigate(`/apt?group=${actor.actor_attack_id}&tab=iocs`)}
                className="block text-left text-xs text-gray-300 hover:text-mitre-accent"
              >
                <span className="font-semibold">{actor.actor_name || actor.actor_attack_id}</span>
                <span className="ml-2 font-mono text-[10px] text-mitre-accent">{actor.actor_attack_id}</span>
              </button>
            ))}
            {item.actor_count > 4 && <div className="text-[10px] text-gray-600">+{item.actor_count - 4} more</div>}
          </div>
        ) : <span className="text-xs text-gray-600">Unmapped</span>}
      </td>
      <td className="p-3">
        <div className="space-y-1 text-xs text-gray-400">
          {item.malware_family && <div>Malware: {item.malware_family}</div>}
          {item.campaign && <div>Campaign: {item.campaign}</div>}
          {item.technique_ids.length > 0 && (
            <div className="flex max-w-xs flex-wrap gap-1 pt-1">
              {item.technique_ids.slice(0, 8).map(id => <Chip key={id} accent>{id}</Chip>)}
            </div>
          )}
          {!item.malware_family && !item.campaign && !item.technique_ids.length && <span className="text-gray-600">No extra context</span>}
        </div>
      </td>
      <td className="p-3 text-xs text-gray-500">
        <div>Last: {item.last_seen || '-'}</div>
        <div>First: {item.first_seen || '-'}</div>
        <div className="mt-1 uppercase">{item.tlp}</div>
      </td>
      <td className="max-w-44 p-3">
        <div className="font-mono text-xs text-gray-300">{item.source}</div>
        {item.source_url && <a href={item.source_url} target="_blank" rel="noreferrer" className="mt-1 block truncate text-[10px] text-blue-400 hover:underline">{item.source_url}</a>}
      </td>
      <td className="p-3">
        <div className="flex flex-col gap-2">
          <button onClick={onEnrichment} className="primary-action">
            Enrichment
          </button>
        </div>
      </td>
    </tr>
  );
}

function GroupMultiSelect({
  groups,
  selectedIds,
  search,
  loading,
  onSearchChange,
  onChange,
}: {
  groups: GroupListItem[];
  selectedIds: string[];
  search: string;
  loading: boolean;
  onSearchChange: (value: string) => void;
  onChange: (ids: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const selected = new Set(selectedIds);
  const normalizedSearch = search.trim().toLowerCase();
  const visibleGroups = useMemo(() => {
    const ordered = [...groups].sort((a, b) => a.name.localeCompare(b.name));
    if (!normalizedSearch) return ordered.slice(0, 80);
    return ordered.filter(group => {
      const aliases = group.aliases.join(' ').toLowerCase();
      return (
        group.name.toLowerCase().includes(normalizedSearch) ||
        group.attack_id.toLowerCase().includes(normalizedSearch) ||
        aliases.includes(normalizedSearch)
      );
    }).slice(0, 80);
  }, [groups, normalizedSearch]);

  const toggle = (id: string) => {
    onChange(selected.has(id) ? selectedIds.filter(item => item !== id) : [...selectedIds, id]);
  };

  return (
    <div className="relative w-72 shrink-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="field flex h-10 w-full items-center justify-between gap-3 text-left"
      >
        <span className={`truncate ${selectedIds.length ? 'text-gray-200' : 'text-gray-500'}`}>
          {selectedIds.length ? `${selectedIds.length} selected groups` : 'Choose groups / attackers'}
        </span>
        <span className="text-gray-500">{open ? '^' : 'v'}</span>
      </button>
      {open && (
        <div className="absolute left-0 top-12 z-30 w-[420px] overflow-hidden rounded-md border border-gray-700 bg-gray-950 shadow-xl">
          <div className="border-b border-gray-800 p-2">
            <input
              value={search}
              onChange={event => onSearchChange(event.target.value)}
              placeholder="Search by group, ID, or alias..."
              className="field h-9 w-full"
              autoFocus
            />
          </div>
          <div className="max-h-[420px] min-h-[340px] overflow-y-auto p-1">
            {loading ? (
              <div className="p-3 text-xs text-gray-500">Loading groups...</div>
            ) : visibleGroups.length ? visibleGroups.map(group => (
              <label
                key={group.attack_id}
                className="flex cursor-pointer items-center gap-2 rounded px-2 py-2 text-xs hover:bg-gray-900"
              >
                <input
                  type="checkbox"
                  checked={selected.has(group.attack_id)}
                  onChange={() => toggle(group.attack_id)}
                  className="h-4 w-4 shrink-0"
                />
                <span className="min-w-0 flex-1">
                  <span className="flex items-center gap-2">
                    <span className="truncate font-semibold text-gray-200">{group.name}</span>
                    <span className="shrink-0 font-mono text-[10px] text-mitre-accent">{group.attack_id}</span>
                  </span>
                  {group.aliases.length > 0 && (
                    <span className="block truncate text-[10px] text-gray-600">{group.aliases.slice(0, 4).join(', ')}</span>
                  )}
                </span>
              </label>
            )) : (
              <div className="p-3 text-xs text-gray-500">No groups match this search.</div>
            )}
          </div>
          <div className="flex items-center justify-between border-t border-gray-800 bg-gray-950 p-2">
            <span className="text-[10px] text-gray-600">{selectedIds.length} selected</span>
            <div className="flex gap-2">
              <button type="button" onClick={() => onChange([])} className="secondary-action">Clear</button>
              <button type="button" onClick={() => setOpen(false)} className="primary-action">Apply</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SourceStatus({ mutation, label }: { mutation: { data?: unknown; error: unknown; isPending: boolean }; label: string }) {
  if (mutation.isPending) return <div className="text-[10px] text-gray-500">{label}: running...</div>;
  if (mutation.error) return <ErrorText error={mutation.error} />;
  if (!mutation.data) return null;
  return <div className="rounded border border-green-900 bg-green-950/30 p-2 text-[10px] text-green-300">{label}: sync complete.</div>;
}

function ImportResult({ result }: { result?: { inserted: number; updated: number; actor_links: number; items_seen: number; source: string } }) {
  if (!result) return null;
  return (
    <div className="rounded border border-green-900 bg-green-950/30 p-2 text-[10px] text-green-300">
      {result.source}: saw {result.items_seen}, inserted {result.inserted}, updated {result.updated}, linked {result.actor_links}.
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/60"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function Chip({ children, accent = false }: { children: React.ReactNode; accent?: boolean }) {
  return <span className={accent ? 'rounded bg-purple-950/40 px-1.5 py-0.5 font-mono text-[10px] text-purple-300' : 'rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400'}>{children}</span>;
}

function ErrorText({ error }: { error: unknown }) {
  return <div className="rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">{errorMessage(error)}</div>;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
