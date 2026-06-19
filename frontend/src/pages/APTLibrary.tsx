import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useAppStore } from '@/store';
import { aptApi, iocApi, operationsApi } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { TechniqueModal } from '@/components/TechniqueModal';
import type { CampaignListItem } from '@/types/attack';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { getActorReports } from '@/config/intelligence';
import { ReportReferences } from '@/components/ReportReferences';

type GroupTab = 'overview' | 'techniques' | 'campaigns' | 'reports' | 'iocs';

export function APTLibrary() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { domain, version, addTechniques, replaceTechniques, setOverlayGroup } = useAppStore();
  const [search, setSearch] = useState('');
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [groupTab, setGroupTab] = useState<GroupTab>('overview');
  const [expandedCampaign, setExpandedCampaign] = useState<string | null>(null);
  const [techModalId, setTechModalId] = useState<string | null>(null);
  const [params] = useSearchParams();
  useEffect(() => {
    const id = params.get('group');
    const tab = params.get('tab') as GroupTab | null;
    if (id) setSelectedGroupId(id);
    if (tab && ['overview', 'techniques', 'campaigns', 'reports', 'iocs'].includes(tab)) setGroupTab(tab);
  }, [params]);

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ['apt-groups', domain, version, search],
    queryFn: () =>
      aptApi.groups({ domain, version: version ?? undefined, search: search || undefined }),
  });
  const groupIds = groups.map(group => group.attack_id).join(',');
  const { data: groupIocCounts = {} } = useQuery({
    queryKey: ['actor-ioc-counts', groupIds, 180, true],
    queryFn: () => iocApi.actorCounts(groups.map(group => group.attack_id), 180, true),
    enabled: groups.length > 0,
  });

  const { data: groupDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['apt-group', selectedGroupId, domain, version],
    queryFn: () => aptApi.group(selectedGroupId!, domain, version ?? undefined),
    enabled: !!selectedGroupId,
  });

  // DB 1: campaigns attributed to the selected group
  const { data: campaigns = [], isLoading: campaignsLoading } = useQuery({
    queryKey: ['apt-campaigns', selectedGroupId, domain, version],
    queryFn: () =>
      aptApi.campaigns({ domain, version: version ?? undefined, group_id: selectedGroupId! }),
    enabled: !!selectedGroupId && groupTab === 'campaigns',
  });

  const { data: campaignDetail } = useQuery({
    queryKey: ['campaign-detail', expandedCampaign, domain, version],
    queryFn: () => aptApi.campaign(expandedCampaign!, domain, version ?? undefined),
    enabled: !!expandedCampaign,
  });
  const { data: reports = [] } = useQuery({ queryKey: ['actor-reports', selectedGroupId], queryFn: () => getActorReports(selectedGroupId!), enabled: !!selectedGroupId });
  const { data: iocSummary } = useQuery({
    queryKey: ['actor-ioc-summary', selectedGroupId],
    queryFn: () => iocApi.actorSummary(selectedGroupId!, 180),
    enabled: !!selectedGroupId,
  });
  const { data: actorIocs = [], isLoading: iocsLoading } = useQuery({
    queryKey: ['actor-iocs', selectedGroupId],
    queryFn: () => iocApi.actor(selectedGroupId!, { days: 180, active_only: true, limit: 250 }),
    enabled: !!selectedGroupId && groupTab === 'iocs',
  });
  const { data: iocSources = [] } = useQuery({
    queryKey: ['ioc-sources'],
    queryFn: iocApi.sources,
    enabled: groupTab === 'iocs',
  });
  const syncThreatFox = useMutation({
    mutationFn: () => iocApi.syncThreatFox(7),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actor-iocs'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const enrichActorOtx = useMutation({
    mutationFn: () => iocApi.enrichActorOtx(selectedGroupId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actor-iocs', selectedGroupId] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary', selectedGroupId] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const uploadReportIocs = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append('file', file);
      form.append('actor_attack_id', selectedGroupId ?? '');
      form.append('actor_name', groupDetail?.name ?? '');
      return iocApi.uploadReport(form);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actor-iocs', selectedGroupId] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary', selectedGroupId] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    },
  });
  const createIocSource = useMutation({
    mutationFn: iocApi.createSource,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ioc-sources'] }),
  });
  const syncIocSource = useMutation({
    mutationFn: (sourceId: string) => iocApi.syncSource(sourceId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actor-iocs'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const trackActor = useMutation({ mutationFn: () => operationsApi.trackActor({ actor_id: groupDetail!.attack_id, actor_name: groupDetail!.name, snapshot: { technique_ids: groupDetail!.techniques.map(item => item.attack_id), captured_at: new Date().toISOString() } }) });

  return (
    <div className="flex flex-col h-full">
      <TechniqueModal attackId={techModalId} onClose={() => setTechModalId(null)} />
      <Header title="ATT&CK Group Library" />
      <div className="flex flex-1 overflow-hidden">

        {/* Group list */}
        <div className="w-72 border-r border-gray-700 flex flex-col shrink-0">
          <div className="p-3 border-b border-gray-700">
            <input
              type="text"
              placeholder="Search groups..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-gray-800 text-sm text-gray-200 px-3 py-2 rounded border border-gray-600 focus:border-mitre-accent outline-none"
            />
          </div>

          <div className="flex-1 overflow-y-auto">
            {isLoading ? (
              <div className="p-4 text-gray-400 text-sm">Loading groups...</div>
            ) : (
              groups.map((group) => (
                <button
                  key={group.attack_id}
                  onClick={() => { setSelectedGroupId(group.attack_id); setGroupTab('overview'); setExpandedCampaign(null); }}
                  className={`w-full text-left px-4 py-3 border-b border-gray-800 hover:bg-gray-800 transition-colors ${
                    selectedGroupId === group.attack_id ? 'bg-gray-800 border-l-2 border-l-mitre-accent' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-white">{group.name}</span>
                    <span className="text-xs text-gray-500">{group.attack_id}</span>
                  </div>
                  <div className="text-xs text-gray-400 mt-0.5">
                    {group.technique_count} techniques
                    {` · ${groupIocCounts[group.attack_id] ?? 0} current IOCs`}
                    {group.aliases.length > 0 && ` · ${group.aliases.slice(0, 2).join(', ')}`}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Group detail */}
        <div className="flex-1 overflow-y-auto p-6">
          {!selectedGroupId && (
            <div className="flex items-center justify-center h-48 text-gray-500">
              Select a group to view its TTP profile
            </div>
          )}

          {selectedGroupId && (detailLoading) && (
            <div className="text-gray-400">Loading...</div>
          )}

          {groupDetail && !detailLoading && (
            <div>
              {/* Header */}
              <div className="grid xl:grid-cols-[1fr_auto] gap-4 mb-4">
                <div className="min-w-0">
                  <h2 className="text-xl font-bold text-white">{groupDetail.name}</h2>
                  <div className="flex gap-2 mt-1 flex-wrap">
                    <span className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded font-mono">
                      {groupDetail.attack_id}
                    </span>
                    {groupDetail.aliases.map((alias) => (
                      <span key={alias} className="text-xs text-gray-400 bg-gray-800 px-2 py-0.5 rounded">
                        {alias}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex max-w-full shrink-0 flex-wrap items-start justify-start gap-2 xl:max-w-[720px] xl:justify-end">
                  <button
                    onClick={() => replaceTechniques(groupDetail.techniques.map((t) => t.attack_id))}
                    className="actor-header-action bg-gray-700 text-white hover:bg-gray-600"
                    title="Replace your current TTP selection with this group's techniques"
                  >
                    Load as my TTPs
                  </button>
                  <button onClick={() => navigator.clipboard.writeText(`${location.origin}/apt?group=${groupDetail.attack_id}`)}
                    className="actor-header-action border border-gray-700 text-gray-400 hover:border-gray-500 hover:text-white">Copy link</button>
                  <button onClick={() => trackActor.mutate()} className="actor-header-action border border-purple-800 text-purple-300 hover:border-purple-500">
                    {trackActor.isSuccess ? 'Snapshot tracked' : 'Track changes'}
                  </button>
                  <button
                    onClick={() => addTechniques(groupDetail.techniques.map((t) => t.attack_id))}
                    className="actor-header-action border border-gray-700 text-gray-400 hover:border-gray-500 hover:text-white"
                    title="Merge this group's techniques into your existing selection"
                  >
                    + Merge into TTPs
                  </button>
                  <button
                    onClick={() => setOverlayGroup(groupDetail.attack_id, groupDetail.name)}
                    className="actor-header-action bg-mitre-accent text-white hover:bg-red-600"
                  >
                    Overlay on Navigator
                  </button>
                  <a
                    href={groupDetail.url}
                    target="_blank"
                    rel="noreferrer"
                    className="actor-header-action border border-gray-600 text-gray-400 hover:border-gray-500 hover:text-white"
                  >
                    ATT&CK ↗
                  </a>
                </div>
              </div>

              {groupDetail.description && (
                <div className="text-sm text-gray-400 mb-5 leading-relaxed max-w-6xl">
                  <AttackText text={groupDetail.description} />
                </div>
              )}

              {/* Tabs */}
              <div className="mb-5 flex flex-wrap gap-2 border-b border-gray-800 pb-3">
                {([
                  ['overview', 'Overview'],
                  ['techniques', `Techniques (${groupDetail.technique_count})`],
                  ['campaigns',  `Campaigns (${groupDetail.campaign_count})`],
                  ['reports', `CTI / IR Reports (${reports.length})`],
                  ['iocs', `IOCs (${iocSummary?.count ?? 0})`],
                ] as [GroupTab, string][]).map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setGroupTab(id)}
                    className={`actor-tab-button ${
                      groupTab === id
                        ? 'border-mitre-accent bg-mitre-accent/15 text-white'
                        : 'border-gray-800 bg-gray-950/50 text-gray-400 hover:border-gray-600 hover:text-white'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {/* ── Overview tab ──────────────────────────────────────────── */}
              {groupTab === 'overview' && (
                <div className="grid xl:grid-cols-[1fr_360px] gap-5">
                  <div className="space-y-5">
                    <InfoPanel title="Actor Profile">
                      <div className="grid md:grid-cols-2 gap-3">
                        <Info label="ATT&CK ID" value={groupDetail.attack_id} mono />
                        <Info label="STIX ID" value={groupDetail.stix_id} mono />
                        <Info label="Domain" value={groupDetail.domain} />
                        <Info label="ATT&CK object version" value={groupDetail.attack_version || '-'} />
                        <Info label="Created" value={fmtDate(groupDetail.created)} />
                        <Info label="Modified" value={fmtDate(groupDetail.modified)} />
                        <Info label="Mapped techniques" value={String(groupDetail.technique_count)} />
                        <Info label="Named campaigns" value={String(groupDetail.campaign_count)} />
                      </div>
                    </InfoPanel>

                    {groupDetail.aliases.length > 0 && (
                      <InfoPanel title="Known Aliases">
                        <div className="flex flex-wrap gap-2">
                          {groupDetail.aliases.map(alias => <span key={alias} className="rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-300">{alias}</span>)}
                        </div>
                      </InfoPanel>
                    )}

                    <InfoPanel title="Technique Usage Evidence">
                      <div className="space-y-3">
                        {groupDetail.techniques.filter(item => item.use_description).slice(0, 12).map(tech => (
                          <div key={tech.attack_id} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                            <div className="flex items-center gap-2">
                              <button onClick={() => setTechModalId(tech.attack_id)} className="font-mono text-xs text-mitre-accent hover:underline">{tech.attack_id}</button>
                              <span className="text-sm text-white">{tech.name}</span>
                            </div>
                            <div className="mt-2 text-xs leading-relaxed text-gray-400"><AttackText text={tech.use_description} /></div>
                            {tech.references.length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {tech.references.slice(0, 4).map((ref, idx) => (
                                  <span key={`${tech.attack_id}-${idx}`} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{ref.source_name}</span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                        {groupDetail.techniques.every(item => !item.use_description) && <p className="text-xs text-gray-500">No technique usage descriptions are present for this actor in the selected ATT&CK version.</p>}
                      </div>
                    </InfoPanel>
                  </div>

                  <div className="space-y-5">
                    <InfoPanel title="Tactic Coverage">
                      <StatList items={groupDetail.tactic_counts} />
                    </InfoPanel>
                    <InfoPanel title="Observed Platforms">
                      <StatList items={groupDetail.platform_counts} />
                    </InfoPanel>
                    {groupDetail.contributors.length > 0 && (
                      <InfoPanel title="ATT&CK Contributors">
                        <div className="space-y-1">
                          {groupDetail.contributors.map(item => <div key={item} className="text-xs text-gray-400">{item}</div>)}
                        </div>
                      </InfoPanel>
                    )}
                    <InfoPanel title="External References">
                      <div className="space-y-2">
                        {groupDetail.external_references.map((ref, idx) => (
                          ref.url ? (
                            <a key={`${ref.source_name}-${idx}`} href={ref.url} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 p-2 text-xs hover:border-gray-600">
                              <span className="block text-gray-300">{ref.source_name || 'reference'}</span>
                              {ref.description && <span className="block text-gray-500 mt-1 line-clamp-2"><AttackText text={ref.description} /></span>}
                            </a>
                          ) : (
                            <div key={`${ref.source_name}-${idx}`} className="rounded border border-gray-800 p-2 text-xs text-gray-400">{ref.source_name}</div>
                          )
                        ))}
                        {groupDetail.external_references.length === 0 && <p className="text-xs text-gray-500">No external references stored for this actor.</p>}
                      </div>
                    </InfoPanel>
                    <InfoPanel title="Technique Source Names">
                      <div className="flex flex-wrap gap-1.5">
                        {groupDetail.source_names.slice(0, 30).map(item => <span key={item} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{item}</span>)}
                        {groupDetail.source_names.length === 0 && <span className="text-xs text-gray-500">No source names available.</span>}
                      </div>
                    </InfoPanel>
                  </div>
                </div>
              )}

              {/* ── Techniques tab ─────────────────────────────────────────── */}
              {groupTab === 'techniques' && (
                <div className="space-y-2">
                  {groupDetail.techniques.map((tech) => (
                    <div
                      key={tech.attack_id}
                      className="rounded border border-gray-800 p-3 hover:bg-gray-800/50 transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <button
                          onClick={() => setTechModalId(tech.attack_id)}
                          className="font-mono text-xs text-mitre-accent pt-0.5 shrink-0 w-20 text-left hover:underline hover:text-red-400 transition-colors"
                          title="View technique details"
                        >
                          {tech.attack_id}
                        </button>
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-white">{tech.name}</div>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            {tech.tactics.map((t) => (
                              <span key={t} className="text-[10px] bg-gray-700 text-gray-300 px-1.5 rounded">
                                {t}
                              </span>
                            ))}
                            {tech.platforms.slice(0, 4).map((p) => (
                              <span key={p} className="text-[10px] bg-gray-900 text-gray-500 px-1.5 rounded">
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>
                        {tech.is_subtechnique && (
                          <span className="text-[10px] text-gray-500 pt-0.5 shrink-0">sub</span>
                        )}
                      </div>
                      {tech.use_description && (
                        <div className="mt-2 pl-[92px] text-xs leading-relaxed text-gray-500"><AttackText text={tech.use_description} /></div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* ── Campaigns tab (DB 1) ───────────────────────────────────── */}
              {groupTab === 'campaigns' && (
                <div>
                  {campaignsLoading ? (
                    <div className="text-gray-400 text-sm">Loading campaigns...</div>
                  ) : campaigns.length === 0 ? (
                    <div className="text-gray-500 text-sm py-4">
                      No named campaigns attributed to {groupDetail.name} in this ATT&CK version.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <p className="text-xs text-gray-500 mb-3">
                        Named operations/attacks from MITRE ATT&CK attributed to this group.
                        Each has its own technique mapping.
                      </p>
                      {campaigns.map((c) => (
                        <CampaignCard
                          key={c.attack_id}
                          campaign={c}
                          expanded={expandedCampaign === c.attack_id}
                          detail={expandedCampaign === c.attack_id ? campaignDetail ?? null : null}
                          onToggle={() =>
                            setExpandedCampaign(
                              expandedCampaign === c.attack_id ? null : c.attack_id
                            )
                          }
                          onAddTTPs={() => {
                            if (campaignDetail && expandedCampaign === c.attack_id) {
                              addTechniques(campaignDetail.techniques.map(t => t.attack_id));
                            }
                          }}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )}
              {groupTab === 'reports' && <ReportReferences reports={reports} limit={60} />}
              {groupTab === 'iocs' && (
                <ActorIOCs
                  actorId={groupDetail.attack_id}
                  actorName={groupDetail.name}
                  items={actorIocs}
                  loading={iocsLoading}
                  summary={iocSummary ?? null}
                  syncing={syncThreatFox.isPending}
                  syncResult={syncThreatFox.data ?? null}
                  sources={iocSources}
                  sourceSyncingId={syncIocSource.variables ?? ''}
                  sourceSyncResult={syncIocSource.data ?? null}
                  sourceCreateError={errorMessage(createIocSource.error)}
                  sourceSyncError={errorMessage(syncIocSource.error)}
                  syncError={errorMessage(syncThreatFox.error)}
                  enriching={enrichActorOtx.isPending}
                  enrichResult={enrichActorOtx.data ?? null}
                  enrichError={errorMessage(enrichActorOtx.error)}
                  uploadingReport={uploadReportIocs.isPending}
                  reportResult={uploadReportIocs.data ?? null}
                  reportError={errorMessage(uploadReportIocs.error)}
                  onSync={() => syncThreatFox.mutate()}
                  onEnrichActor={() => enrichActorOtx.mutate()}
                  onUploadReport={(file) => uploadReportIocs.mutate(file)}
                  onAddSource={(payload) => createIocSource.mutate(payload)}
                  onSyncSource={(sourceId) => syncIocSource.mutate(sourceId)}
                  onAddTechniques={(ids) => addTechniques(ids)}
                  onShowTechniques={(ids) => {
                    replaceTechniques(ids);
                    navigate('/navigator');
                  }}
                  onOpenDetail={(id) => navigate(`/ioc-library/${id}`)}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function errorMessage(error: unknown) {
  if (!error) return '';
  if (typeof error === 'object' && error !== null && 'response' in error) {
    const response = (error as { response?: { data?: { detail?: string } } }).response;
    if (response?.data?.detail) return response.data.detail;
  }
  return error instanceof Error ? error.message : String(error);
}

function ActorIOCs({
  actorId,
  actorName,
  items,
  loading,
  summary,
  syncing,
  syncResult,
  sources,
  sourceSyncingId,
  sourceSyncResult,
  sourceCreateError,
  sourceSyncError,
  syncError,
  enriching,
  enrichResult,
  enrichError,
  uploadingReport,
  reportResult,
  reportError,
  onSync,
  onEnrichActor,
  onUploadReport,
  onAddSource,
  onSyncSource,
  onAddTechniques,
  onShowTechniques,
  onOpenDetail,
}: {
  actorId: string;
  actorName: string;
  items: import('@/api/client').IOCItem[];
  loading: boolean;
  summary: import('@/api/client').IOCSummary | null;
  syncing: boolean;
  syncResult: {source: string; days: number; inserted: number; updated: number; actor_links: number} | null;
  sources: import('@/api/client').IOCSourceStatus[];
  sourceSyncingId: string;
  sourceSyncResult: {source: string; days: null; inserted: number; updated: number; actor_links: number} | null;
  sourceCreateError: string;
  sourceSyncError: string;
  syncError: string;
  enriching: boolean;
  enrichResult: {
    source: string;
    actor_attack_id: string;
    actor_name: string;
    inserted: number;
    updated: number;
    actor_links: number;
    searched_aliases: number;
    pulses: number;
    matched_pulses: number;
  } | null;
  enrichError: string;
  uploadingReport: boolean;
  reportResult: {
    filename: string;
    extracted: number;
    imported: {source: string; days: null; inserted: number; updated: number; actor_links: number};
    preview: import('@/api/client').IOCItem[];
  } | null;
  reportError: string;
  onSync: () => void;
  onEnrichActor: () => void;
  onUploadReport: (file: File) => void;
  onAddSource: (payload: {label: string; url: string; kind: 'custom-json' | 'custom-csv' | 'custom-txt'}) => void;
  onSyncSource: (sourceId: string) => void;
  onAddTechniques: (ids: string[]) => void;
  onShowTechniques: (ids: string[]) => void;
  onOpenDetail: (id: number) => void;
}) {
  const [feedLabel, setFeedLabel] = useState('');
  const [feedUrl, setFeedUrl] = useState('');
  const [feedKind, setFeedKind] = useState<'custom-json' | 'custom-csv' | 'custom-txt'>('custom-json');
  const customSources = sources.filter(source => source.kind.startsWith('custom-'));
  const iocTechniqueIds = Array.from(new Set(items.flatMap(item => item.technique_ids ?? []))).sort();
  const openEnrichment = (indicator: string) => {
    window.open(`/virustotal?indicator=${encodeURIComponent(indicator)}`, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 xl:grid-cols-[1fr_auto]">
        <div className="rounded border border-gray-800 bg-gray-900/50 p-4">
          <h3 className="text-sm font-semibold text-white">Current Actor IOCs</h3>
          <p className="mt-2 text-xs leading-relaxed text-gray-500">
            Source-backed observables mapped to {actorName}. ThreatFox links are created only when IOC metadata
            contains this actor name or one of its aliases. Manual report imports can add direct actor mappings.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {Object.entries(summary?.by_type ?? {}).map(([type, count]) => (
              <span key={type} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-[10px] text-gray-400">
                {type}: {count}
              </span>
            ))}
            {Object.entries(summary?.techniques ?? {}).slice(0, 12).map(([techniqueId, count]) => (
              <span key={techniqueId} className="rounded border border-purple-900 bg-purple-950/30 px-2 py-1 font-mono text-[10px] text-purple-300">
                {techniqueId}: {count}
              </span>
            ))}
            {!summary?.count && <span className="text-xs text-gray-600">No active IOCs stored for this actor.</span>}
          </div>
        </div>
        <div className="rounded border border-gray-800 bg-gray-900/50 p-4 xl:w-80">
          <div className="flex flex-wrap gap-2">
            <button onClick={onSync} disabled={syncing} className="primary-action">
              {syncing ? 'Syncing...' : 'Sync ThreatFox'}
            </button>
            <button onClick={onEnrichActor} disabled={enriching} className="secondary-action">
              {enriching ? 'Enriching...' : 'Enrich actor'}
            </button>
            <a href={iocApi.actorCsvUrl(actorId, 180, true)} className="secondary-action">
              Export CSV
            </a>
            <button
              onClick={() => onAddTechniques(iocTechniqueIds)}
              disabled={!iocTechniqueIds.length}
              className="secondary-action disabled:opacity-40"
            >
              Add IOC TTPs
            </button>
            <button
              onClick={() => onShowTechniques(iocTechniqueIds)}
              disabled={!iocTechniqueIds.length}
              className="secondary-action disabled:opacity-40"
            >
              Show IOC TTPs
            </button>
          </div>
          {syncResult && (
            <div className="mt-3 rounded border border-green-900 bg-green-950/30 p-2 text-[10px] text-green-300">
              Synced {syncResult.inserted} new, updated {syncResult.updated}, linked {syncResult.actor_links}.
            </div>
          )}
          {syncError && (
            <div className="mt-3 rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">
              {syncError}
              {syncError.includes('THREATFOX_AUTH_KEY') && (
                <div className="mt-1 text-red-200">
                  Add THREATFOX_AUTH_KEY to .env, restart the API container, then run Sync ThreatFox again.
                </div>
              )}
            </div>
          )}
          {enrichResult && (
            <div className="mt-3 rounded border border-green-900 bg-green-950/30 p-2 text-[10px] text-green-300">
              Enriched {enrichResult.actor_name}: {enrichResult.inserted} new, {enrichResult.updated} updated, {enrichResult.actor_links} links from {enrichResult.matched_pulses} matched OTX pulses.
            </div>
          )}
          {enrichError && (
            <div className="mt-3 rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">
              {enrichError}
            </div>
          )}
        </div>
      </div>

      <div className="rounded border border-gray-800 bg-gray-900/50 p-4">
        <h3 className="text-sm font-semibold text-white">Extract IOCs From Report</h3>
        <p className="mt-2 text-xs text-gray-500">
          Upload PDF, DOCX, or TXT. AdversaryGraph extracts common IOCs and maps them to {actorName}.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <label className="secondary-action cursor-pointer">
            {uploadingReport ? 'Importing...' : 'Upload report'}
            <input
              type="file"
              accept=".pdf,.docx,.txt,text/plain,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
              className="hidden"
              disabled={uploadingReport}
              onChange={event => {
                const file = event.currentTarget.files?.[0];
                if (file) onUploadReport(file);
                event.currentTarget.value = '';
              }}
            />
          </label>
          {reportResult && (
            <span className="text-xs text-green-300">
              Extracted {reportResult.extracted}; imported {reportResult.imported.inserted} new, {reportResult.imported.updated} updated, {reportResult.imported.actor_links} links.
            </span>
          )}
        </div>
        {reportError && <div className="mt-2 rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">{reportError}</div>}
        {reportResult?.preview?.length ? (
          <div className="mt-3 flex max-h-24 flex-wrap gap-1 overflow-y-auto">
            {reportResult.preview.slice(0, 20).map(item => (
              <span key={`${item.type}-${item.value}`} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 font-mono text-[10px] text-gray-400">
                {item.type}: {item.value}
              </span>
            ))}
          </div>
        ) : null}
      </div>

      <div className="rounded border border-gray-800 bg-gray-900/50 p-4">
        <h3 className="text-sm font-semibold text-white">Custom / Personal IOC Feeds</h3>
        <p className="mt-2 text-xs text-gray-500">
          Add a private JSON, CSV, or TXT IOC feed. JSON/CSV records can include actor_attack_id, actor_name,
          malware_family, campaign, first_seen, last_seen, confidence, tags, and source_url.
        </p>
        <div className="mt-3 grid gap-2 lg:grid-cols-[180px_1fr_140px_auto]">
          <input
            value={feedLabel}
            onChange={event => setFeedLabel(event.target.value)}
            placeholder="Feed label"
            className="field"
          />
          <input
            value={feedUrl}
            onChange={event => setFeedUrl(event.target.value)}
            placeholder="https://example.local/iocs.json"
            className="field"
          />
          <select value={feedKind} onChange={event => setFeedKind(event.target.value as typeof feedKind)} className="field">
            <option value="custom-json">JSON</option>
            <option value="custom-csv">CSV</option>
            <option value="custom-txt">TXT</option>
          </select>
          <button
            type="button"
            onClick={() => {
              onAddSource({ label: feedLabel, url: feedUrl, kind: feedKind });
              setFeedLabel('');
              setFeedUrl('');
            }}
            disabled={!feedLabel.trim() || !feedUrl.trim()}
            className="primary-action disabled:opacity-40"
          >
            Add Feed
          </button>
        </div>
        {sourceCreateError && <div className="mt-2 rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">{sourceCreateError}</div>}
        {sourceSyncError && <div className="mt-2 rounded border border-red-900 bg-red-950/30 p-2 text-[10px] text-red-300">{sourceSyncError}</div>}
        {sourceSyncResult && (
          <div className="mt-2 rounded border border-green-900 bg-green-950/30 p-2 text-[10px] text-green-300">
            Synced {sourceSyncResult.source}: {sourceSyncResult.inserted} new, {sourceSyncResult.updated} updated, {sourceSyncResult.actor_links} linked.
          </div>
        )}
        <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {customSources.map(source => (
            <div key={source.source_id} className="rounded border border-gray-800 bg-gray-950 p-3">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="truncate text-xs font-semibold text-gray-200">{source.label}</div>
                  <div className="mt-1 truncate text-[10px] text-gray-600">{source.url}</div>
                  <div className="mt-1 text-[10px] text-gray-500">{source.kind.replace('custom-', '').toUpperCase()} · {source.sync_status}</div>
                  {source.sync_error && <div className="mt-1 line-clamp-2 text-[10px] text-red-300">{source.sync_error}</div>}
                </div>
                <button
                  type="button"
                  onClick={() => onSyncSource(source.source_id)}
                  disabled={sourceSyncingId === source.source_id}
                  className="secondary-action"
                >
                  {sourceSyncingId === source.source_id ? 'Syncing' : 'Sync'}
                </button>
              </div>
            </div>
          ))}
          {!customSources.length && <div className="text-xs text-gray-600">No custom feeds configured.</div>}
        </div>
      </div>

      <div className="overflow-hidden rounded border border-gray-800">
        <div className="grid grid-cols-[140px_1fr_110px_110px_120px_160px] gap-3 border-b border-gray-800 bg-gray-950 px-3 py-2 text-[10px] uppercase text-gray-500">
          <span>Type</span>
          <span>Indicator</span>
          <span>Malware</span>
          <span>Last Seen</span>
          <span>Source</span>
          <span>Actions</span>
        </div>
        {loading ? (
          <div className="p-4 text-sm text-gray-500">Loading actor IOCs...</div>
        ) : items.length ? (
          <div className="divide-y divide-gray-800">
            {items.map(item => (
              <div key={`${item.id}-${item.type}-${item.value}-${item.source}`} className="grid grid-cols-[140px_1fr_110px_110px_120px_160px] gap-3 px-3 py-3 text-xs">
                <div>
                  <span className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-300">{item.type}</span>
                  <div className="mt-2 text-[10px] text-gray-600">conf {item.confidence}</div>
                </div>
                <div className="min-w-0">
                  <button
                    type="button"
                    onClick={() => onOpenDetail(item.id)}
                    className="break-all text-left font-mono text-gray-200 hover:text-mitre-accent hover:underline"
                    title="Open IOC enrichment detail"
                  >
                    {item.value}
                  </button>
                  {item.evidence && <div className="mt-1 text-[10px] text-gray-600">{item.evidence}</div>}
                  {item.tags.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {item.tags.slice(0, 6).map(tag => (
                        <span key={tag} className="rounded bg-gray-900 px-1.5 py-0.5 text-[10px] text-gray-500">{tag}</span>
                      ))}
                    </div>
                  )}
                  {(item.technique_ids ?? []).length > 0 && (
                    <div className="mt-2 flex flex-wrap items-center gap-1">
                      {(item.technique_ids ?? []).slice(0, 10).map(techniqueId => (
                        <button
                          key={techniqueId}
                          type="button"
                          onClick={() => onShowTechniques([techniqueId])}
                          className="rounded border border-purple-900 bg-purple-950/30 px-1.5 py-0.5 font-mono text-[10px] text-purple-300 hover:border-purple-500"
                          title="Show this IOC-linked TTP on the matrix"
                        >
                          {techniqueId}
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => onAddTechniques(item.technique_ids ?? [])}
                        className="rounded border border-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400 hover:border-gray-600 hover:text-white"
                      >
                        Add
                      </button>
                      <button
                        type="button"
                        onClick={() => onShowTechniques(item.technique_ids ?? [])}
                        className="rounded border border-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400 hover:border-gray-600 hover:text-white"
                      >
                        Matrix
                      </button>
                    </div>
                  )}
                </div>
                <div className="truncate text-gray-400" title={item.malware_family}>{item.malware_family || '-'}</div>
                <div className="font-mono text-[10px] text-gray-500">{(item.last_seen || item.first_seen || '-').slice(0, 10)}</div>
                <div>
                  {item.source_url ? (
                    <a href={item.source_url} target="_blank" rel="noreferrer" className="text-mitre-accent hover:underline">
                      {item.source}
                    </a>
                  ) : (
                    <span className="text-gray-500">{item.source}</span>
                  )}
                  <div className="mt-1 text-[10px] uppercase text-gray-600">{item.tlp}</div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" onClick={() => openEnrichment(item.value)} className="primary-action">
                    Enrichment
                  </button>
                  <button type="button" onClick={() => onOpenDetail(item.id)} className="secondary-action">
                    Open detail
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="p-4 text-sm text-gray-500">
            No current IOCs are mapped to this actor yet. Sync ThreatFox or import report/MISP/OpenCTI IOCs with direct actor attribution.
          </div>
        )}
      </div>
    </div>
  );
}

function InfoPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-4"><h3 className="text-sm font-semibold text-white mb-3">{title}</h3>{children}</section>;
}

function Info({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div><div className={`mt-1 text-xs text-gray-300 break-words ${mono ? 'font-mono' : ''}`}>{value || '-'}</div></div>;
}

function StatList({ items }: { items: Array<{ name: string; count: number }> }) {
  if (!items.length) return <p className="text-xs text-gray-500">No data available.</p>;
  const max = Math.max(...items.map(item => item.count), 1);
  return <div className="space-y-2">{items.slice(0, 12).map(item => <div key={item.name}><div className="flex justify-between gap-3 text-xs"><span className="text-gray-300">{item.name}</span><span className="font-mono text-gray-500">{item.count}</span></div><div className="mt-1 h-1.5 rounded bg-gray-800"><div className="h-1.5 rounded bg-mitre-accent" style={{ width: `${Math.max(8, (item.count / max) * 100)}%` }} /></div></div>)}</div>;
}

function fmtDate(value: string) {
  if (!value) return '-';
  return value.slice(0, 10);
}

function AttackText({ text }: { text: string }) {
  const parts = parseAttackText(text);
  return <>{parts.map((part, idx) => {
    if (part.kind === 'link') {
      return <a key={idx} href={part.url} target="_blank" rel="noreferrer" className="text-mitre-accent hover:underline">{part.text}</a>;
    }
    if (part.kind === 'citation') {
      return <span key={idx} className="mx-1 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{part.text}</span>;
    }
    return <span key={idx}>{part.text}</span>;
  })}</>;
}

function parseAttackText(text: string): Array<{ kind: 'text'; text: string } | { kind: 'link'; text: string; url: string } | { kind: 'citation'; text: string }> {
  const parts: Array<{ kind: 'text'; text: string } | { kind: 'link'; text: string; url: string } | { kind: 'citation'; text: string }> = [];
  const re = /\[([^\]]+)\]\((https?:\/\/[^)]+)\)|\(Citation:\s*([^)]+)\)/g;
  let last = 0;
  for (const match of text.matchAll(re)) {
    if (match.index > last) parts.push({ kind: 'text', text: text.slice(last, match.index) });
    if (match[1] && match[2]) parts.push({ kind: 'link', text: match[1], url: match[2] });
    else if (match[3]) parts.push({ kind: 'citation', text: match[3] });
    last = match.index + match[0].length;
  }
  if (last < text.length) parts.push({ kind: 'text', text: text.slice(last) });
  return parts;
}

// ── Campaign card (expandable) ────────────────────────────────────────────────

function CampaignCard({
  campaign, expanded, detail, onToggle, onAddTTPs,
}: {
  campaign: CampaignListItem;
  expanded: boolean;
  detail: import('@/types/attack').CampaignDetail | null;
  onToggle: () => void;
  onAddTTPs: () => void;
}) {
  const dateRange = [campaign.first_seen, campaign.last_seen]
    .filter(Boolean)
    .map(d => d!.slice(0, 10))
    .join(' → ');

  return (
    <div className="border border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-start gap-3 p-4 hover:bg-gray-800/60 transition-colors text-left"
      >
        <span className="text-gray-500 mt-0.5 shrink-0">{expanded ? '▾' : '▸'}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-purple-400">{campaign.attack_id}</span>
            <span className="text-sm font-medium text-white">{campaign.name}</span>
          </div>
          <div className="flex items-center gap-3 mt-1">
            {dateRange && (
              <span className="text-[10px] text-gray-500">{dateRange}</span>
            )}
            <span className="text-[10px] text-gray-500">
              {campaign.technique_count} techniques
            </span>
          </div>
        </div>
        <span className="text-[10px] font-mono text-gray-600 shrink-0 pt-0.5">
          {campaign.group_names.join(', ')}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-gray-700 px-4 pb-4 pt-3 bg-gray-900/40">
          {!detail ? (
            <div className="text-xs text-gray-500">Loading...</div>
          ) : (
            <>
              {detail.description && (
                <p className="text-xs text-gray-400 mb-3 leading-relaxed line-clamp-3">
                  <AttackText text={detail.description} />
                </p>
              )}
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-gray-500">
                  {detail.techniques.length} techniques in this campaign
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={onAddTTPs}
                    className="text-[10px] bg-gray-700 hover:bg-gray-600 text-white px-2 py-1 rounded transition-colors"
                  >
                    Add to my TTPs
                  </button>
                  {detail.url && (
                    <a
                      href={detail.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[10px] text-gray-400 hover:text-white border border-gray-700 px-2 py-1 rounded transition-colors"
                    >
                      ATT&CK ↗
                    </a>
                  )}
                </div>
              </div>
              <div className="space-y-1 max-h-56 overflow-y-auto">
                {detail.techniques.map((t) => (
                  <div key={t.attack_id} className="flex items-center gap-2 py-1">
                    <span className="font-mono text-[10px] text-purple-400 w-16 shrink-0">{t.attack_id}</span>
                    <span className="text-xs text-gray-300 flex-1">{t.name}</span>
                    <span className="text-[10px] bg-gray-800 text-gray-500 px-1.5 rounded shrink-0">
                      {t.tactics?.[0] ?? ''}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
