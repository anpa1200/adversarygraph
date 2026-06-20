import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '@/store';
import { aptApi, analyzeApi, reportsApi, exportApi } from '@/api/client';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { MatrixDiff } from '@/components/Compare/MatrixDiff';
import { TacticBreakdown } from '@/components/Compare/TacticBreakdown';
import { Header } from '@/components/Layout/Header';
import { TechniqueModal } from '@/components/TechniqueModal';
import type { CampaignResult, CompareResult, OverlapExplanationRequest, ReportSession, TechniqueUsage } from '@/types/attack';

type CompareMode = 'groups' | 'campaigns' | 'reports';
type DetailTab   = 'overview' | 'tactic' | 'matrix' | 'gap' | 'explain';

export function Compare() {
  const { domain, version, selectedTechniques, setOverlayGroup } = useAppStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [techModalId, setTechModalId] = useState<string | null>(null);

  // ── Mode switcher ───────────────────────────────────────────────────────────
  const [mode, setMode] = useState<CompareMode>('groups');

  // ── Groups mode state ───────────────────────────────────────────────────────
  const [groupResults,  setGroupResults]  = useState<CompareResult[]>([]);
  const [activeGroup,   setActiveGroup]   = useState<CompareResult | null>(null);
  const [tab,           setTab]           = useState<DetailTab>('overview');
  const [groupSearch,   setGroupSearch]   = useState('');
  const [diffOnly,      setDiffOnly]      = useState(false);
  const [exporting,     setExporting]     = useState(false);
  const [explanation,   setExplanation]   = useState('');

  // ── Campaigns mode state ────────────────────────────────────────────────────
  const [campaignResults,  setCampaignResults]  = useState<CampaignResult[]>([]);
  const [activeCampaign,   setActiveCampaign]   = useState<CampaignResult | null>(null);
  const [campaignSearch,   setCampaignSearch]   = useState('');

  // ── Reports mode state ──────────────────────────────────────────────────────
  const [selectedReport,   setSelectedReport]   = useState<ReportSession | null>(null);
  const [reportMatches,    setReportMatches]     = useState<CompareResult[]>([]);
  const [activeReportMatch, setActiveReportMatch] = useState<CompareResult | null>(null);
  const [reportSearch,     setReportSearch]     = useState('');

  // Matrix data (groups mode visual diff)
  const { tactics, techniquesByTactic } = useAttackMatrix(domain, version);

  // Group-profile detail for visual diff
  const { data: groupDetail } = useQuery({
    queryKey: ['compare-group-detail', activeGroup?.group_attack_id, domain, version],
    queryFn: () => aptApi.group(activeGroup!.group_attack_id, domain, version ?? undefined),
    enabled: !!activeGroup,
    staleTime: 10 * 60 * 1000,
  });

  const aptIds = useMemo(
    () => new Set(groupDetail?.techniques.map(t => t.attack_id) ?? []),
    [groupDetail]
  );

  // Campaign detail for expanded selected campaign
  const { data: activeCampaignDetail } = useQuery({
    queryKey: ['compare-campaign-detail', activeCampaign?.campaign_attack_id, domain, version],
    queryFn: () => aptApi.campaign(activeCampaign!.campaign_attack_id, domain, version ?? undefined),
    enabled: !!activeCampaign && mode === 'campaigns',
    staleTime: 10 * 60 * 1000,
  });

  const { data: activeReportResult } = useQuery({
    queryKey: ['compare-report-result', selectedReport?.session_id],
    queryFn: () => analyzeApi.getResult(selectedReport!.session_id),
    enabled: !!selectedReport && mode === 'reports',
    staleTime: 60_000,
  });

  const { data: activeReportGroupDetail } = useQuery({
    queryKey: ['compare-report-group-detail', activeReportMatch?.group_attack_id, domain, version],
    queryFn: () => aptApi.group(activeReportMatch!.group_attack_id, domain, version ?? undefined),
    enabled: !!activeReportMatch && mode === 'reports',
    staleTime: 10 * 60 * 1000,
  });

  // DB 2 — stored report sessions
  const { data: reportSessions = [], isLoading: sessionsLoading } = useQuery({
    queryKey: ['report-sessions'],
    queryFn: () => reportsApi.list(50, 0),
    enabled: mode === 'reports',
    staleTime: 60_000,
  });

  // Mutations
  const compareGroupsMutation = useMutation({
    mutationFn: () =>
      aptApi.compare({
        technique_ids: Array.from(selectedTechniques),
        domain,
        version: version ?? undefined,
        top_n: 30,
      }),
    onSuccess: data => { setGroupResults(data); setActiveGroup(data[0] ?? null); },
  });

  const compareCampaignsMutation = useMutation({
    mutationFn: () =>
      aptApi.compareCampaigns({
        technique_ids: Array.from(selectedTechniques),
        domain,
        version: version ?? undefined,
        top_n: 50,
      }),
    onSuccess: data => { setCampaignResults(data); setActiveCampaign(data[0] ?? null); },
  });

  const compareReportMutation = useMutation({
    mutationFn: (sessionId: string) => reportsApi.compare(sessionId, 20),
    onSuccess: data => { setReportMatches(data); setActiveReportMatch(data[0] ?? null); },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (sessionId: string) => reportsApi.remove(sessionId),
    onSuccess: (_data, sessionId) => {
      queryClient.invalidateQueries({ queryKey: ['report-sessions'] });
      if (selectedReport?.session_id === sessionId) {
        setSelectedReport(null);
        setReportMatches([]);
        setActiveReportMatch(null);
      }
    },
  });

  const explainOverlapMutation = useMutation({
    mutationFn: (payload: OverlapExplanationRequest) =>
      aptApi.explainOverlap(payload, { domain, version: version ?? undefined }),
    onSuccess: data => setExplanation(data.markdown),
  });

  // PDF export (groups mode)
  const exportPdf = async () => {
    if (!activeGroup) return;
    setExporting(true);
    try {
      const fd = new FormData();
      fd.append('provider', 'claude');
      fd.append('domain', domain);
      fd.append('text',
        `TTP Comparison: User vs ${activeGroup.group_name}\n` +
        `Similarity: ${Math.round(activeGroup.similarity * 100)}%\n` +
        `Shared techniques: ${activeGroup.shared_techniques.join(', ')}`
      );
      const resp = await analyzeApi.submit(fd).catch(() => null);
      if (resp) {
        const pdfResp = await fetch(`/api/export/analysis/${resp.session_id}`);
        if (pdfResp.ok) {
          const blob = await pdfResp.blob();
          const url  = URL.createObjectURL(blob);
          const a    = document.createElement('a');
          a.href = url; a.download = `compare-${activeGroup.group_attack_id}.pdf`; a.click();
          URL.revokeObjectURL(url);
        }
      }
    } finally { setExporting(false); }
  };

  // Filtered lists
  const filteredGroupResults = groupResults.filter(r =>
    !groupSearch || r.group_name.toLowerCase().includes(groupSearch.toLowerCase()) ||
                    r.group_attack_id.toLowerCase().includes(groupSearch.toLowerCase())
  );

  const filteredCampaignResults = campaignResults.filter(r =>
    !campaignSearch || r.campaign_name.toLowerCase().includes(campaignSearch.toLowerCase()) ||
                       r.campaign_attack_id.toLowerCase().includes(campaignSearch.toLowerCase())
  );

  const filteredReportMatches = reportMatches.filter(r =>
    !reportSearch || r.group_name.toLowerCase().includes(reportSearch.toLowerCase()) ||
                     r.group_attack_id.toLowerCase().includes(reportSearch.toLowerCase())
  );

  const canRun = selectedTechniques.size > 0;

  const buildTacticDistribution = (
    subjectAIds: Set<string>,
    subjectBIds: Set<string>,
    sharedIds: Set<string>,
  ): OverlapExplanationRequest['tactic_distribution'] => {
    const distribution: OverlapExplanationRequest['tactic_distribution'] = {};
    tactics.forEach(tactic => {
      const techniqueIds = (techniquesByTactic.get(tactic.shortname) ?? []).map(item => item.attack_id);
      const subjectA = techniqueIds.filter(id => subjectAIds.has(id)).length;
      const subjectB = techniqueIds.filter(id => subjectBIds.has(id)).length;
      const shared = techniqueIds.filter(id => sharedIds.has(id)).length;
      if (subjectA || subjectB || shared) {
        distribution[tactic.shortname] = { subject_a: subjectA, subject_b: subjectB, shared };
      }
    });
    return distribution;
  };

  const explainGroupOverlap = () => {
    if (!activeGroup || !groupDetail) return;
    const subjectAIds = new Set(Array.from(selectedTechniques));
    const subjectBIds = new Set(groupDetail.techniques.map(item => item.attack_id));
    const sharedIds = new Set(activeGroup.shared_techniques);
    explainOverlapMutation.mutate({
      subject_a: { name: 'Current Navigator layer', type: 'layer' },
      subject_b: { name: activeGroup.group_name, type: 'actor' },
      shared_techniques: activeGroup.shared_techniques,
      unique_to_a: Array.from(subjectAIds).filter(id => !sharedIds.has(id)),
      unique_to_b: Array.from(subjectBIds).filter(id => !sharedIds.has(id)),
      tactic_distribution: buildTacticDistribution(subjectAIds, subjectBIds, sharedIds),
      overlap_score: activeGroup.similarity,
    });
  };

  const explainCampaignOverlap = () => {
    if (!activeCampaign || !activeCampaignDetail) return;
    const subjectAIds = new Set(Array.from(selectedTechniques));
    const subjectBIds = new Set(activeCampaignDetail.techniques.map(item => item.attack_id));
    const sharedIds = new Set(activeCampaign.shared_techniques);
    explainOverlapMutation.mutate({
      subject_a: { name: 'Current Navigator layer', type: 'layer' },
      subject_b: { name: activeCampaign.campaign_name, type: 'campaign' },
      shared_techniques: activeCampaign.shared_techniques,
      unique_to_a: Array.from(subjectAIds).filter(id => !sharedIds.has(id)),
      unique_to_b: Array.from(subjectBIds).filter(id => !sharedIds.has(id)),
      tactic_distribution: buildTacticDistribution(subjectAIds, subjectBIds, sharedIds),
      overlap_score: activeCampaign.similarity,
    });
  };

  const explainReportOverlap = () => {
    if (!selectedReport || !activeReportMatch || !activeReportResult || !activeReportGroupDetail) return;
    const subjectAIds = new Set(activeReportResult.techniques.map(item => item.attack_id));
    const subjectBIds = new Set(activeReportGroupDetail.techniques.map((item: TechniqueUsage) => item.attack_id));
    const sharedIds = new Set(activeReportMatch.shared_techniques);
    explainOverlapMutation.mutate({
      subject_a: { name: selectedReport.name || selectedReport.filename || selectedReport.session_id.slice(0, 8), type: 'report' },
      subject_b: { name: activeReportMatch.group_name, type: 'actor' },
      shared_techniques: activeReportMatch.shared_techniques,
      unique_to_a: Array.from(subjectAIds).filter(id => !sharedIds.has(id)),
      unique_to_b: Array.from(subjectBIds).filter(id => !sharedIds.has(id)),
      tactic_distribution: buildTacticDistribution(subjectAIds, subjectBIds, sharedIds),
      overlap_score: activeReportMatch.similarity,
    });
  };

  return (
    <div className="flex flex-col h-full">
      <TechniqueModal attackId={techModalId} onClose={() => setTechModalId(null)} />
      <Header title="Group & Campaign Similarity" />

      {/* ── My TTPs summary + mode switcher bar ────────────────────────────── */}
      <div className="flex items-center gap-4 px-6 py-3 bg-gray-900 border-b border-gray-700 shrink-0 flex-wrap gap-y-2">
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-white">{selectedTechniques.size}</span>
          <span className="text-sm text-gray-400">
            {selectedTechniques.size === 1 ? 'technique' : 'techniques'} selected
          </span>
        </div>

        {selectedTechniques.size > 0 && (
          <div className="flex flex-wrap gap-1 flex-1 overflow-hidden max-h-8 min-w-0">
            {Array.from(selectedTechniques).slice(0, 18).map(id => (
              <span key={id} className="text-[10px] font-mono bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{id}</span>
            ))}
            {selectedTechniques.size > 18 && (
              <span className="text-[10px] text-gray-600">+{selectedTechniques.size - 18} more</span>
            )}
          </div>
        )}

        {/* Mode switcher */}
        <div className="ml-auto flex items-center gap-1 shrink-0 bg-gray-800 rounded p-0.5">
          {([
            ['groups',    'Groups (DB 1)'],
            ['campaigns', 'Campaigns (DB 1)'],
            ['reports',   'Reports (DB 2)'],
          ] as [CompareMode, string][]).map(([m, label]) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`text-xs px-3 py-1 rounded transition-colors ${
                mode === m ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Run button */}
        {mode !== 'reports' && (
          <div className="flex items-center gap-2 shrink-0">
            {!canRun && (
              <button
                onClick={() => navigate('/navigator')}
                className="text-xs text-gray-400 hover:text-white border border-gray-700 px-3 py-1.5 rounded transition-colors"
              >
                ← Select TTPs in Navigator
              </button>
            )}
            <button
              onClick={() => mode === 'groups' ? compareGroupsMutation.mutate() : compareCampaignsMutation.mutate()}
              disabled={!canRun || compareGroupsMutation.isPending || compareCampaignsMutation.isPending}
              className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-4 py-1.5 rounded font-medium transition-colors"
            >
              {(compareGroupsMutation.isPending || compareCampaignsMutation.isPending)
                ? 'Comparing…'
                : mode === 'groups'
                  ? 'Compare vs Groups'
                  : 'Compare vs Campaigns'
              }
            </button>
          </div>
        )}
      </div>

      {/* ── Mode: Groups ──────────────────────────────────────────────────── */}
      {mode === 'groups' && (
        groupResults.length === 0 ? (
          <EmptyState canRun={canRun} onRun={() => compareGroupsMutation.mutate()} isPending={compareGroupsMutation.isPending} />
        ) : (
          <div className="flex flex-1 overflow-hidden">
            {/* Rankings */}
            <div className="w-72 shrink-0 border-r border-gray-700 flex flex-col">
              <div className="p-3 border-b border-gray-800">
                <input
                  type="text" placeholder="Filter groups…"
                  value={groupSearch} onChange={e => setGroupSearch(e.target.value)}
                  className="w-full bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none"
                />
                <div className="text-[10px] text-gray-600 mt-1.5">
                  {filteredGroupResults.length} / {groupResults.length} · Jaccard similarity
                </div>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredGroupResults.map((r, i) => (
                  <button
                    key={r.group_attack_id}
                    onClick={() => { setActiveGroup(r); setTab('overview'); setExplanation(''); }}
                    className={`w-full text-left px-4 py-3 border-b border-gray-800 transition-colors ${
                      activeGroup?.group_attack_id === r.group_attack_id
                        ? 'bg-gray-800 border-l-2 border-l-mitre-accent' : 'hover:bg-gray-800/60'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-[10px] text-gray-600 w-5">#{i + 1}</span>
                      <div className="flex-1 bg-gray-700 rounded-full h-1.5 overflow-hidden">
                        <div className="h-1.5 rounded-full" style={{
                          width: `${r.similarity * 100}%`,
                          background: r.similarity > 0.5 ? '#e94560' : r.similarity > 0.25 ? '#f59e0b' : '#3b82f6',
                        }} />
                      </div>
                      <span className="text-[10px] font-mono text-gray-300">{Math.round(r.similarity * 100)}%</span>
                    </div>
                    <div className="text-sm font-medium text-white ml-7">{r.group_name}</div>
                    <div className="text-[10px] text-gray-500 ml-7">{r.group_attack_id} · {r.shared_count} shared</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Group detail */}
            {activeGroup && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-800 shrink-0">
                  <div className="flex items-start justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-white">{activeGroup.group_name}</h2>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="font-mono text-xs text-gray-500">{activeGroup.group_attack_id}</span>
                        <SimilarityBadge value={activeGroup.similarity} />
                        <span className="text-xs text-gray-400">
                          {activeGroup.shared_count} shared · {selectedTechniques.size} your TTPs
                          {groupDetail && ` · ${groupDetail.technique_count} in group`}
                        </span>
                      </div>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      <button
                        onClick={() => { setOverlayGroup(activeGroup.group_attack_id, activeGroup.group_name); navigate('/navigator'); }}
                        className="text-xs bg-blue-900/40 hover:bg-blue-800/60 border border-blue-700 text-blue-300 px-3 py-1.5 rounded transition-colors"
                      >
                        Overlay in Navigator
                      </button>
                      <button onClick={exportPdf} disabled={exporting}
                        className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-3 py-1.5 rounded transition-colors disabled:opacity-50"
                      >
                        {exporting ? 'Exporting…' : '↓ PDF Report'}
                      </button>
                    </div>
                  </div>
                  <div className="flex gap-5 mt-4 text-xs border-b border-gray-800 pb-0">
                    {([
                      ['overview', 'Overview'],
                      ['tactic',   'Tactic Breakdown'],
                      ['matrix',   'Visual Diff'],
                      ['gap',      'Gap Analysis'],
                      ['explain',  'Explanation'],
                    ] as [DetailTab, string][]).map(([id, label]) => (
                      <button key={id} onClick={() => setTab(id)}
                        className={`pb-2 border-b-2 transition-colors ${tab === id ? 'border-mitre-accent text-white' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
                      >{label}</button>
                    ))}
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto p-6">
                  {tab === 'overview' && <OverviewTab result={activeGroup} userIds={selectedTechniques} onTechClick={setTechModalId} />}
                  {tab === 'tactic' && (
                    <TacticBreakdown tactics={tactics} techniquesByTactic={techniquesByTactic} userIds={selectedTechniques} aptIds={aptIds} />
                  )}
                  {tab === 'matrix' && (
                    <div>
                      <div className="flex items-center gap-3 mb-4">
                        <button onClick={() => setDiffOnly(v => !v)}
                          className={`text-xs px-3 py-1 rounded border transition-colors ${diffOnly ? 'bg-mitre-accent/20 border-mitre-accent text-red-300' : 'border-gray-700 text-gray-500'}`}
                        >Diff only</button>
                      </div>
                      <MatrixDiff tactics={tactics} techniquesByTactic={techniquesByTactic} userIds={selectedTechniques} aptIds={aptIds} diffOnly={diffOnly} />
                    </div>
                  )}
                  {tab === 'gap' && (
                    <GapAnalysis result={activeGroup} groupDetail={groupDetail ?? null} userIds={selectedTechniques} onTechClick={setTechModalId} />
                  )}
                  {tab === 'explain' && (
                    <ExplanationPanel
                      markdown={explanation}
                      isPending={explainOverlapMutation.isPending}
                      onGenerate={explainGroupOverlap}
                      disabled={!groupDetail}
                    />
                  )}
                </div>
              </div>
            )}
          </div>
        )
      )}

      {/* ── Mode: Campaigns (DB 1) ─────────────────────────────────────────── */}
      {mode === 'campaigns' && (
        campaignResults.length === 0 ? (
          <EmptyState canRun={canRun} onRun={() => compareCampaignsMutation.mutate()} isPending={compareCampaignsMutation.isPending} label="Compare your TTPs against MITRE named campaigns (operations)." />
        ) : (
          <div className="flex flex-1 overflow-hidden">
            {/* Campaign rankings */}
            <div className="w-80 shrink-0 border-r border-gray-700 flex flex-col">
              <div className="p-3 border-b border-gray-800">
                <input
                  type="text" placeholder="Filter campaigns…"
                  value={campaignSearch} onChange={e => setCampaignSearch(e.target.value)}
                  className="w-full bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none"
                />
                <div className="text-[10px] text-gray-600 mt-1.5">
                  {filteredCampaignResults.length} / {campaignResults.length} campaigns · Jaccard similarity
                </div>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredCampaignResults.map((r, i) => (
                  <button
                    key={r.campaign_attack_id}
                    onClick={() => { setActiveCampaign(r); setExplanation(''); }}
                    className={`w-full text-left px-4 py-3 border-b border-gray-800 transition-colors ${
                      activeCampaign?.campaign_attack_id === r.campaign_attack_id
                        ? 'bg-gray-800 border-l-2 border-l-purple-500' : 'hover:bg-gray-800/60'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-[10px] text-gray-600 w-5">#{i + 1}</span>
                      <div className="flex-1 bg-gray-700 rounded-full h-1.5 overflow-hidden">
                        <div className="h-1.5 rounded-full" style={{
                          width: `${r.similarity * 100}%`,
                          background: r.similarity > 0.5 ? '#a855f7' : r.similarity > 0.25 ? '#f59e0b' : '#3b82f6',
                        }} />
                      </div>
                      <span className="text-[10px] font-mono text-gray-300">{Math.round(r.similarity * 100)}%</span>
                    </div>
                    <div className="text-sm font-medium text-white ml-7">{r.campaign_name}</div>
                    <div className="text-[10px] text-gray-500 ml-7">
                      {r.campaign_attack_id} · {r.shared_count} shared
                      {r.group_names.length > 0 && ` · ${r.group_names.slice(0, 2).join(', ')}`}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Campaign detail */}
            {activeCampaign && (
              <div className="flex-1 overflow-y-auto p-6">
                <div className="mb-4">
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs text-purple-400">{activeCampaign.campaign_attack_id}</span>
                        <h2 className="text-xl font-bold text-white">{activeCampaign.campaign_name}</h2>
                        <SimilarityBadge value={activeCampaign.similarity} />
                      </div>
                      {activeCampaign.group_names.length > 0 && (
                        <div className="text-xs text-gray-400 mt-1">
                          Attributed to: {activeCampaign.group_names.join(', ')}
                        </div>
                      )}
                      {(activeCampaign.first_seen || activeCampaign.last_seen) && (
                        <div className="text-xs text-gray-500 mt-0.5">
                          {[activeCampaign.first_seen, activeCampaign.last_seen].filter(Boolean).map(d => d!.slice(0, 10)).join(' → ')}
                        </div>
                      )}
                    </div>
                  </div>

                  {activeCampaignDetail?.description && (
                    <p className="text-sm text-gray-400 mb-4 leading-relaxed line-clamp-3">
                      {activeCampaignDetail.description}
                    </p>
                  )}

                  <div className="grid grid-cols-3 gap-4 mb-6">
                    <StatCard value={`${Math.round(activeCampaign.similarity * 100)}%`} label="Jaccard similarity" color="text-purple-400" />
                    <StatCard value={String(activeCampaign.shared_count)} label="Shared techniques" color="text-amber-400" />
                    <StatCard value={String(activeCampaignDetail?.techniques.length ?? '—')} label="Total in campaign" color="text-blue-400" />
                  </div>
                  <ExplanationPanel
                    markdown={explanation}
                    isPending={explainOverlapMutation.isPending}
                    onGenerate={explainCampaignOverlap}
                    disabled={!activeCampaignDetail}
                    compact
                  />
                </div>

                {/* Shared techniques */}
                {activeCampaign.shared_techniques.length > 0 && (
                  <div className="mb-6">
                    <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
                      Shared techniques ({activeCampaign.shared_techniques.length})
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {activeCampaign.shared_techniques.map(id => (
                        <button key={id} onClick={() => setTechModalId(id)}
                          className="text-xs font-mono bg-purple-900/30 text-purple-300 border border-purple-800/50 px-2 py-0.5 rounded hover:bg-purple-800/40 hover:text-purple-200 transition-colors"
                        >{id}</button>
                      ))}
                    </div>
                  </div>
                )}

                {/* All campaign techniques */}
                {activeCampaignDetail && (
                  <div>
                    <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
                      All campaign techniques ({activeCampaignDetail.techniques.length})
                    </div>
                    <div className="space-y-1 max-h-96 overflow-y-auto">
                      {activeCampaignDetail.techniques.map(t => {
                        const isShared = activeCampaign.shared_techniques.includes(t.attack_id);
                        return (
                          <div key={t.attack_id}
                            className={`flex items-center gap-3 py-1.5 px-3 rounded transition-colors ${isShared ? 'bg-purple-900/20' : 'hover:bg-gray-800/60'}`}
                          >
                            <span className={`font-mono text-xs w-20 shrink-0 ${isShared ? 'text-purple-400' : 'text-gray-500'}`}>{t.attack_id}</span>
                            <span className="text-sm text-gray-300 flex-1">{t.name}</span>
                            <span className="text-[10px] bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded shrink-0">{t.tactics?.[0] ?? ''}</span>
                            {isShared && <span className="text-[10px] text-purple-500 shrink-0">✓ shared</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      )}

      {/* ── Mode: Reports (DB 2) ──────────────────────────────────────────── */}
      {mode === 'reports' && (
        <div className="flex flex-1 overflow-hidden">
          {/* Stored sessions list */}
          <div className="w-80 shrink-0 border-r border-gray-700 flex flex-col">
            <div className="p-3 border-b border-gray-800">
              <div className="text-xs text-gray-400 font-medium mb-1">DB 2 — Stored Report Sessions</div>
              <div className="text-[10px] text-gray-600">
                Click a report to compare its TTP mapping against known group profiles.
              </div>
            </div>
            <div className="flex-1 overflow-y-auto">
              {sessionsLoading ? (
                <div className="p-4 text-gray-500 text-sm">Loading sessions…</div>
              ) : reportSessions.length === 0 ? (
                <div className="p-4 text-gray-600 text-sm">
                  No completed reports yet.{' '}
                  <button onClick={() => navigate('/analyze')} className="text-mitre-accent hover:underline">
                    Analyze a report →
                  </button>
                </div>
              ) : (
                reportSessions.map(s => (
                  <div
                    key={s.session_id}
                    className={`border-b border-gray-800 transition-colors ${
                      selectedReport?.session_id === s.session_id
                        ? 'bg-gray-800 border-l-2 border-l-green-500' : 'hover:bg-gray-800/60'
                    }`}
                  >
                    {/* Clickable session body */}
                    <button
                      onClick={() => {
                        setSelectedReport(s);
                        setReportMatches([]);
                        setActiveReportMatch(null);
                        setExplanation('');
                        compareReportMutation.mutate(s.session_id);
                      }}
                      className="w-full text-left px-4 pt-3 pb-1"
                    >
                      <div className="text-sm font-medium text-white truncate">
                        {s.name || s.filename || `Session ${s.session_id.slice(0, 8)}`}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        <span className="text-[10px] text-gray-500">{s.technique_count} techniques</span>
                        <span className="text-[10px] text-gray-600">{s.domain}</span>
                        <span className="text-[10px] text-gray-600">{s.created_at.slice(0, 10)}</span>
                      </div>
                      <div className="text-[10px] text-gray-600">{s.provider} · {s.model}</div>
                    </button>
                    {/* Action buttons */}
                    <div className="flex items-center gap-2 px-4 pb-2 pt-1">
                      <a
                        href={exportApi.analysisUrl(s.session_id)}
                        download={`analysis-${s.session_id.slice(0, 8)}.pdf`}
                        onClick={e => e.stopPropagation()}
                        className="text-[10px] text-gray-400 hover:text-white border border-gray-700 hover:border-gray-500 px-2 py-0.5 rounded transition-colors"
                      >
                        ↓ PDF
                      </a>
                      <button
                        onClick={e => {
                          e.stopPropagation();
                          if (window.confirm('Delete this report session?')) {
                            deleteReportMutation.mutate(s.session_id);
                          }
                        }}
                        className="text-[10px] text-red-500 hover:text-red-300 border border-red-900 hover:border-red-700 px-2 py-0.5 rounded transition-colors"
                      >
                        ✕ Remove
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Report group-similarity results */}
          <div className="flex flex-1 overflow-hidden">
            {!selectedReport ? (
              <div className="flex-1 flex items-center justify-center text-gray-600">
                <div className="text-center">
                  <div className="text-4xl mb-3">📋</div>
                  <p>Select a report to review group profiles with overlapping TTPs.</p>
                </div>
              </div>
            ) : compareReportMutation.isPending ? (
              <div className="flex-1 flex items-center justify-center text-gray-500">
                Comparing report against group profiles…
              </div>
            ) : reportMatches.length === 0 ? (
              <div className="flex-1 flex items-center justify-center text-gray-600">
                No matches found for this report.
              </div>
            ) : (
              <>
                {/* Match rankings */}
                <div className="w-72 shrink-0 border-r border-gray-700 flex flex-col">
                  <div className="p-3 border-b border-gray-800">
                    <input
                      type="text" placeholder="Filter groups…"
                      value={reportSearch} onChange={e => setReportSearch(e.target.value)}
                      className="w-full bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none"
                    />
                    <div className="text-[10px] text-gray-600 mt-1.5">
                      {filteredReportMatches.length} / {reportMatches.length} group profiles
                    </div>
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    {filteredReportMatches.map((r, i) => (
                      <button
                        key={r.group_attack_id}
                        onClick={() => { setActiveReportMatch(r); setExplanation(''); }}
                        className={`w-full text-left px-4 py-3 border-b border-gray-800 transition-colors ${
                          activeReportMatch?.group_attack_id === r.group_attack_id
                            ? 'bg-gray-800 border-l-2 border-l-green-500' : 'hover:bg-gray-800/60'
                        }`}
                      >
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="text-[10px] text-gray-600 w-5">#{i + 1}</span>
                          <div className="flex-1 bg-gray-700 rounded-full h-1.5 overflow-hidden">
                            <div className="h-1.5 rounded-full" style={{
                              width: `${r.similarity * 100}%`,
                              background: r.similarity > 0.5 ? '#22c55e' : r.similarity > 0.25 ? '#f59e0b' : '#3b82f6',
                            }} />
                          </div>
                          <span className="text-[10px] font-mono text-gray-300">{Math.round(r.similarity * 100)}%</span>
                        </div>
                        <div className="text-sm font-medium text-white ml-7">{r.group_name}</div>
                        <div className="text-[10px] text-gray-500 ml-7">{r.group_attack_id} · {r.shared_count} shared</div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Selected match detail */}
                {activeReportMatch && (
                  <div className="flex-1 overflow-y-auto p-6">
                    <div className="mb-2">
                      <div className="text-xs text-gray-500 mb-1">
                        Report: <span className="text-gray-300">{selectedReport.name || selectedReport.filename || selectedReport.session_id.slice(0, 8)}</span>
                        {' '}vs Group Profile
                      </div>
                      <h2 className="text-xl font-bold text-white">{activeReportMatch.group_name}</h2>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="font-mono text-xs text-gray-500">{activeReportMatch.group_attack_id}</span>
                        <SimilarityBadge value={activeReportMatch.similarity} />
                        <span className="text-xs text-gray-400">{activeReportMatch.shared_count} shared</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-4 my-5">
                      <StatCard value={`${Math.round(activeReportMatch.similarity * 100)}%`} label="Jaccard similarity" color="text-green-400" />
                      <StatCard value={String(activeReportMatch.shared_count)} label="Shared techniques" color="text-amber-400" />
                      <StatCard value={String(selectedReport.technique_count)} label="Report techniques" color="text-blue-400" />
                    </div>
                    {activeReportMatch.shared_techniques.length > 0 && (
                      <div>
                        <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
                          Shared techniques ({activeReportMatch.shared_techniques.length})
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {activeReportMatch.shared_techniques.map(id => (
                            <button key={id} onClick={() => setTechModalId(id)}
                              className="text-xs font-mono bg-green-900/20 text-green-400 border border-green-900/30 px-2 py-0.5 rounded hover:bg-green-800/30 hover:text-green-300 transition-colors"
                            >{id}</button>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="mt-6">
                      <ExplanationPanel
                        markdown={explanation}
                        isPending={explainOverlapMutation.isPending}
                        onGenerate={explainReportOverlap}
                        disabled={!activeReportResult || !activeReportGroupDetail}
                      />
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function EmptyState({
  canRun, onRun, isPending, label,
}: {
  canRun: boolean; onRun: () => void; isPending: boolean; label?: string;
}) {
  const navigate = useNavigate();
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-gray-600">
      <div className="text-5xl mb-5">◈</div>
      {canRun ? (
        <>
          <p className="text-gray-400 mb-4">{label ?? 'Run comparison to rank group profiles against your TTP selection.'}</p>
          <button onClick={onRun} disabled={isPending}
            className="bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-6 py-2 rounded font-medium text-sm transition-colors"
          >
            {isPending ? 'Comparing…' : 'Run comparison'}
          </button>
        </>
      ) : (
        <>
          <p className="text-gray-500 mb-4">Select techniques in the Navigator first.</p>
          <button onClick={() => navigate('/navigator')}
            className="border border-gray-600 hover:border-gray-400 text-gray-400 hover:text-white px-4 py-2 rounded text-sm transition-colors"
          >
            Go to Navigator →
          </button>
        </>
      )}
    </div>
  );
}

function OverviewTab({ result, userIds, onTechClick }: { result: CompareResult; userIds: Set<string>; onTechClick: (id: string) => void }) {
  const onlyInUser = Array.from(userIds).filter(id => !result.shared_techniques.includes(id));
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <StatCard value={`${Math.round(result.similarity * 100)}%`} label="Jaccard similarity" color="text-mitre-accent" />
        <StatCard value={String(result.shared_count)} label="Shared techniques" color="text-amber-400" />
        <StatCard value={String(onlyInUser.length)} label="Your TTPs not in group" color="text-blue-400" />
      </div>
      {result.shared_techniques.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Shared techniques ({result.shared_techniques.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {result.shared_techniques.map(id => (
              <button key={id} onClick={() => onTechClick(id)}
                className="text-xs font-mono bg-amber-900/30 text-amber-400 border border-amber-800/50 px-2 py-0.5 rounded hover:bg-amber-800/40 hover:text-amber-300 transition-colors"
              >{id}</button>
            ))}
          </div>
        </div>
      )}
      {onlyInUser.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Your TTPs not in this group ({onlyInUser.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {onlyInUser.map(id => (
              <button key={id} onClick={() => onTechClick(id)}
                className="text-xs font-mono bg-red-900/20 text-red-400 border border-red-900/30 px-2 py-0.5 rounded hover:bg-red-800/30 hover:text-red-300 transition-colors"
              >{id}</button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GapAnalysis({
  result, groupDetail, userIds, onTechClick,
}: {
  result: CompareResult;
  groupDetail: { techniques: Array<{ attack_id: string; name: string; tactics: string[]; is_subtechnique: boolean; use_description: string }> } | null;
  userIds: Set<string>;
  onTechClick: (id: string) => void;
}) {
  if (!groupDetail) return <div className="text-gray-600 text-sm">Loading group details…</div>;
  const gapTechs = groupDetail.techniques.filter(t => !userIds.has(t.attack_id));
  return (
    <div className="space-y-6">
      <div className="bg-gray-800 rounded-lg p-4">
        <div className="text-sm font-medium text-white mb-1">Coverage Summary</div>
        <p className="text-xs text-gray-400">
          You cover <span className="text-amber-400 font-medium">{result.shared_count}</span> of{' '}
          <span className="text-white font-medium">{groupDetail.techniques.length}</span> techniques
          used by {result.group_name} ({Math.round((result.shared_count / Math.max(groupDetail.techniques.length, 1)) * 100)}% coverage).
          There are <span className="text-blue-400 font-medium">{gapTechs.length}</span> techniques not in your selection.
        </p>
      </div>
      {gapTechs.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Techniques in {result.group_name}'s profile not in your layer ({gapTechs.length})
          </div>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {gapTechs.map(t => (
              <div key={t.attack_id} className="flex items-center gap-3 py-1.5 px-3 rounded hover:bg-gray-800/60 transition-colors">
                <button onClick={() => onTechClick(t.attack_id)}
                  className="font-mono text-xs text-blue-400 w-20 shrink-0 text-left hover:underline hover:text-blue-300 transition-colors"
                >{t.attack_id}</button>
                <span className="text-sm text-gray-300 flex-1">{t.name}</span>
                <span className="text-[10px] bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded shrink-0">{t.tactics?.[0] || ''}</span>
                {t.is_subtechnique && <span className="text-[10px] text-gray-600 shrink-0">sub</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ExplanationPanel({
  markdown,
  isPending,
  onGenerate,
  disabled,
  compact = false,
}: {
  markdown: string;
  isPending: boolean;
  onGenerate: () => void;
  disabled?: boolean;
  compact?: boolean;
}) {
  return (
    <div className={`rounded border border-gray-800 bg-gray-900/50 ${compact ? 'mb-6 p-3' : 'p-4'}`}>
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-semibold text-white">Auditable overlap explanation</div>
          <p className="text-xs text-gray-500">
            Generates a caveated Jaccard explanation with shared techniques, tactic coverage, limitations, and next steps.
          </p>
        </div>
        <button
          onClick={onGenerate}
          disabled={disabled || isPending}
          className="shrink-0 rounded bg-mitre-accent px-3 py-2 text-xs font-semibold text-white transition-colors hover:bg-red-600 disabled:opacity-40"
        >
          {isPending ? 'Generating...' : markdown ? 'Regenerate' : 'Generate'}
        </button>
      </div>
      {markdown ? (
        <pre className="max-h-[560px] overflow-auto whitespace-pre-wrap rounded border border-gray-800 bg-gray-950 p-4 text-xs leading-relaxed text-gray-300">
          {markdown}
        </pre>
      ) : (
        <div className="rounded border border-dashed border-gray-800 bg-gray-950/50 p-6 text-center text-sm text-gray-600">
          No explanation generated yet.
        </div>
      )}
    </div>
  );
}

function StatCard({ value, label, color }: { value: string; label: string; color: string }) {
  return (
    <div className="bg-gray-800 rounded-lg p-4 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 mt-1">{label}</div>
    </div>
  );
}

function SimilarityBadge({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const cls = pct >= 50 ? 'bg-red-900/40 text-red-300 border-red-800'
    : pct >= 25 ? 'bg-amber-900/40 text-amber-300 border-amber-800'
    : 'bg-blue-900/40 text-blue-300 border-blue-800';
  return <span className={`text-xs px-2 py-0.5 rounded border ${cls}`}>{pct}% similarity</span>;
}
