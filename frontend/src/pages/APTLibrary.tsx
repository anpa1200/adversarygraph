import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAppStore } from '@/store';
import { aptApi, operationsApi } from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { TechniqueModal } from '@/components/TechniqueModal';
import type { CampaignListItem } from '@/types/attack';
import { useSearchParams } from 'react-router-dom';
import { getActorReports } from '@/config/intelligence';
import { ReportReferences } from '@/components/ReportReferences';
import { useMutation } from '@tanstack/react-query';

type GroupTab = 'overview' | 'techniques' | 'campaigns' | 'reports';

export function APTLibrary() {
  const { domain, version, addTechniques, replaceTechniques, setOverlayGroup } = useAppStore();
  const [search, setSearch] = useState('');
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [groupTab, setGroupTab] = useState<GroupTab>('overview');
  const [expandedCampaign, setExpandedCampaign] = useState<string | null>(null);
  const [techModalId, setTechModalId] = useState<string | null>(null);
  const [params] = useSearchParams();
  useEffect(() => { const id = params.get('group'); if (id) setSelectedGroupId(id); }, [params]);

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ['apt-groups', domain, version, search],
    queryFn: () =>
      aptApi.groups({ domain, version: version ?? undefined, search: search || undefined }),
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
                <div className="flex gap-2 shrink-0 flex-wrap justify-start xl:justify-end">
                  <button
                    onClick={() => replaceTechniques(groupDetail.techniques.map((t) => t.attack_id))}
                    className="text-xs bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded transition-colors"
                    title="Replace your current TTP selection with this group's techniques"
                  >
                    Load as my TTPs
                  </button>
                  <button onClick={() => navigator.clipboard.writeText(`${location.origin}/apt?group=${groupDetail.attack_id}`)}
                    className="text-xs text-gray-400 border border-gray-700 px-3 py-1.5 rounded">Copy link</button>
                  <button onClick={() => trackActor.mutate()} className="text-xs text-purple-300 border border-purple-800 px-3 py-1.5 rounded">
                    {trackActor.isSuccess ? 'Snapshot tracked' : 'Track changes'}
                  </button>
                  <button
                    onClick={() => addTechniques(groupDetail.techniques.map((t) => t.attack_id))}
                    className="text-xs text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-3 py-1.5 rounded transition-colors"
                    title="Merge this group's techniques into your existing selection"
                  >
                    + Merge into TTPs
                  </button>
                  <button
                    onClick={() => setOverlayGroup(groupDetail.attack_id, groupDetail.name)}
                    className="text-xs bg-mitre-accent hover:bg-red-600 text-white px-3 py-1.5 rounded transition-colors"
                  >
                    Overlay on Navigator
                  </button>
                  <a
                    href={groupDetail.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-gray-400 hover:text-white border border-gray-600 px-3 py-1.5 rounded transition-colors"
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
              <div className="flex gap-5 text-xs border-b border-gray-800 mb-5">
                {([
                  ['overview', 'Overview'],
                  ['techniques', `Techniques (${groupDetail.technique_count})`],
                  ['campaigns',  `Campaigns (${groupDetail.campaign_count})`],
                  ['reports', `CTI / IR Reports (${reports.length})`],
                ] as [GroupTab, string][]).map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setGroupTab(id)}
                    className={`pb-2 border-b-2 transition-colors ${
                      groupTab === id
                        ? 'border-mitre-accent text-white'
                        : 'border-transparent text-gray-500 hover:text-gray-300'
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
            </div>
          )}
        </div>
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
