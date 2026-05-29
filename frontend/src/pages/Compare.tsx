import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '@/store';
import { aptApi, analyzeApi } from '@/api/client';
import { useAttackMatrix } from '@/hooks/useAttackMatrix';
import { MatrixDiff } from '@/components/Compare/MatrixDiff';
import { TacticBreakdown } from '@/components/Compare/TacticBreakdown';
import { Header } from '@/components/Layout/Header';
import type { CompareResult } from '@/types/attack';

type DetailTab = 'overview' | 'tactic' | 'matrix' | 'gap';

export function Compare() {
  const { domain, version, selectedTechniques, setOverlayGroup } = useAppStore();
  const navigate = useNavigate();

  const [results,     setResults]     = useState<CompareResult[]>([]);
  const [activeGroup, setActiveGroup] = useState<CompareResult | null>(null);
  const [tab,         setTab]         = useState<DetailTab>('overview');
  const [search,      setSearch]      = useState('');
  const [diffOnly,    setDiffOnly]    = useState(false);
  const [exporting,   setExporting]   = useState(false);

  // Matrix data for the visual diff
  const { tactics, techniquesByTactic } = useAttackMatrix(domain, version);

  // APT techniques for the selected group (for visual diff)
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

  // Jaccard comparison
  const compareMutation = useMutation({
    mutationFn: () =>
      aptApi.compare({
        technique_ids: Array.from(selectedTechniques),
        domain,
        version: version ?? undefined,
        top_n: 30,
      }),
    onSuccess: data => { setResults(data); setActiveGroup(data[0] ?? null); },
  });

  // PDF export for current selection + top match
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
        const pdfResp = await fetch(`/api/export/analysis/${resp.session_id}`, { method: 'POST' });
        if (pdfResp.ok) {
          const blob = await pdfResp.blob();
          const url  = URL.createObjectURL(blob);
          const a    = document.createElement('a');
          a.href = url;
          a.download = `compare-${activeGroup.group_attack_id}.pdf`;
          a.click();
          URL.revokeObjectURL(url);
        }
      }
    } finally { setExporting(false); }
  };

  // Filter rankings by search
  const filteredResults = results.filter(r =>
    !search || r.group_name.toLowerCase().includes(search.toLowerCase()) ||
               r.group_attack_id.toLowerCase().includes(search.toLowerCase())
  );

  const canRun = selectedTechniques.size > 0;

  return (
    <div className="flex flex-col h-full">
      <Header title="APT Comparison" />

      {/* ── My TTPs summary bar ───────────────────────────────────────────── */}
      <div className="flex items-center gap-4 px-6 py-3 bg-gray-900 border-b border-gray-700 shrink-0">
        <div className="flex items-center gap-2">
          <span className="text-2xl font-bold text-white">{selectedTechniques.size}</span>
          <span className="text-sm text-gray-400">
            {selectedTechniques.size === 1 ? 'technique' : 'techniques'} selected
          </span>
        </div>

        {selectedTechniques.size > 0 && (
          <div className="flex flex-wrap gap-1 flex-1 overflow-hidden max-h-8">
            {Array.from(selectedTechniques).slice(0, 18).map(id => (
              <span key={id} className="text-[10px] font-mono bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{id}</span>
            ))}
            {selectedTechniques.size > 18 && (
              <span className="text-[10px] text-gray-600">+{selectedTechniques.size - 18} more</span>
            )}
          </div>
        )}

        <div className="ml-auto flex items-center gap-2 shrink-0">
          {!canRun && (
            <button
              onClick={() => navigate('/navigator')}
              className="text-xs text-gray-400 hover:text-white border border-gray-700 px-3 py-1.5 rounded transition-colors"
            >
              ← Select TTPs in Navigator
            </button>
          )}
          <button
            onClick={() => compareMutation.mutate()}
            disabled={!canRun || compareMutation.isPending}
            className="text-xs bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-4 py-1.5 rounded font-medium transition-colors"
          >
            {compareMutation.isPending ? 'Comparing…' : 'Compare against all APT groups'}
          </button>
        </div>
      </div>

      {/* ── Main workspace ────────────────────────────────────────────────── */}
      {results.length === 0 ? (
        <EmptyState canRun={canRun} onRun={() => compareMutation.mutate()} isPending={compareMutation.isPending} />
      ) : (
        <div className="flex flex-1 overflow-hidden">

          {/* Rankings panel */}
          <div className="w-72 shrink-0 border-r border-gray-700 flex flex-col">
            <div className="p-3 border-b border-gray-800">
              <input
                type="text"
                placeholder="Filter groups…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full bg-gray-800 text-xs text-gray-200 px-3 py-2 rounded border border-gray-700 focus:border-mitre-accent outline-none"
              />
              <div className="text-[10px] text-gray-600 mt-1.5">
                {filteredResults.length} / {results.length} groups · sorted by Jaccard similarity
              </div>
            </div>

            <div className="flex-1 overflow-y-auto">
              {filteredResults.map((r, i) => (
                <button
                  key={r.group_attack_id}
                  onClick={() => { setActiveGroup(r); setTab('overview'); }}
                  className={`w-full text-left px-4 py-3 border-b border-gray-800 transition-colors ${
                    activeGroup?.group_attack_id === r.group_attack_id
                      ? 'bg-gray-800 border-l-2 border-l-mitre-accent'
                      : 'hover:bg-gray-800/60'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <span className="text-[10px] text-gray-600 w-5">#{i + 1}</span>
                    <div className="flex-1 bg-gray-700 rounded-full h-1.5 overflow-hidden">
                      <div
                        className="h-1.5 rounded-full"
                        style={{
                          width: `${r.similarity * 100}%`,
                          background: r.similarity > 0.5 ? '#e94560' : r.similarity > 0.25 ? '#f59e0b' : '#3b82f6',
                        }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-gray-300">
                      {Math.round(r.similarity * 100)}%
                    </span>
                  </div>
                  <div className="text-sm font-medium text-white ml-7">{r.group_name}</div>
                  <div className="text-[10px] text-gray-500 ml-7">
                    {r.group_attack_id} · {r.shared_count} shared
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Detail panel */}
          {activeGroup && (
            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Group header */}
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
                    <button
                      onClick={exportPdf}
                      disabled={exporting}
                      className="text-xs bg-gray-700 hover:bg-gray-600 text-gray-300 px-3 py-1.5 rounded transition-colors disabled:opacity-50"
                    >
                      {exporting ? 'Exporting…' : '↓ PDF Report'}
                    </button>
                  </div>
                </div>

                {/* Tabs */}
                <div className="flex gap-5 mt-4 text-xs border-b border-gray-800 pb-0">
                  {([
                    ['overview', 'Overview'],
                    ['tactic',   'Tactic Breakdown'],
                    ['matrix',   'Visual Diff'],
                    ['gap',      'Gap Analysis'],
                  ] as [DetailTab, string][]).map(([id, label]) => (
                    <button
                      key={id}
                      onClick={() => setTab(id)}
                      className={`pb-2 border-b-2 transition-colors ${
                        tab === id
                          ? 'border-mitre-accent text-white'
                          : 'border-transparent text-gray-500 hover:text-gray-300'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Tab content */}
              <div className="flex-1 overflow-y-auto p-6">

                {tab === 'overview' && (
                  <OverviewTab result={activeGroup} userIds={selectedTechniques} />
                )}

                {tab === 'tactic' && (
                  <TacticBreakdown
                    tactics={tactics}
                    techniquesByTactic={techniquesByTactic}
                    userIds={selectedTechniques}
                    aptIds={aptIds}
                  />
                )}

                {tab === 'matrix' && (
                  <div>
                    <div className="flex items-center gap-3 mb-4">
                      <button
                        onClick={() => setDiffOnly(v => !v)}
                        className={`text-xs px-3 py-1 rounded border transition-colors ${
                          diffOnly
                            ? 'bg-mitre-accent/20 border-mitre-accent text-red-300'
                            : 'border-gray-700 text-gray-500'
                        }`}
                      >
                        Diff only
                      </button>
                    </div>
                    <MatrixDiff
                      tactics={tactics}
                      techniquesByTactic={techniquesByTactic}
                      userIds={selectedTechniques}
                      aptIds={aptIds}
                      diffOnly={diffOnly}
                    />
                  </div>
                )}

                {tab === 'gap' && (
                  <GapAnalysis
                    result={activeGroup}
                    groupDetail={groupDetail ?? null}
                    userIds={selectedTechniques}
                  />
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function EmptyState({ canRun, onRun, isPending }: { canRun: boolean; onRun: () => void; isPending: boolean }) {
  const navigate = useNavigate();
  return (
    <div className="flex-1 flex flex-col items-center justify-center text-gray-600">
      <div className="text-5xl mb-5">◈</div>
      {canRun ? (
        <>
          <p className="text-gray-400 mb-4">Run comparison to rank all APT groups against your TTP selection.</p>
          <button
            onClick={onRun}
            disabled={isPending}
            className="bg-mitre-accent hover:bg-red-600 disabled:opacity-40 text-white px-6 py-2 rounded font-medium text-sm transition-colors"
          >
            {isPending ? 'Comparing…' : 'Run comparison'}
          </button>
        </>
      ) : (
        <>
          <p className="text-gray-500 mb-4">Select techniques in the Navigator first.</p>
          <button
            onClick={() => navigate('/navigator')}
            className="border border-gray-600 hover:border-gray-400 text-gray-400 hover:text-white px-4 py-2 rounded text-sm transition-colors"
          >
            Go to Navigator →
          </button>
        </>
      )}
    </div>
  );
}

function OverviewTab({ result, userIds }: { result: CompareResult; userIds: Set<string> }) {
  const onlyInUser = Array.from(userIds).filter(id => !result.shared_techniques.includes(id));
  return (
    <div className="space-y-6">
      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard value={`${Math.round(result.similarity * 100)}%`} label="Jaccard similarity" color="text-mitre-accent" />
        <StatCard value={String(result.shared_count)} label="Shared techniques" color="text-amber-400" />
        <StatCard value={String(onlyInUser.length)} label="Your TTPs not in group" color="text-blue-400" />
      </div>

      {/* Shared techniques */}
      {result.shared_techniques.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Shared techniques ({result.shared_techniques.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {result.shared_techniques.map(id => (
              <span key={id} className="text-xs font-mono bg-amber-900/30 text-amber-400 border border-amber-800/50 px-2 py-0.5 rounded">
                {id}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Unique to user */}
      {onlyInUser.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Your TTPs not observed in this group ({onlyInUser.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {onlyInUser.map(id => (
              <span key={id} className="text-xs font-mono bg-red-900/20 text-red-400 border border-red-900/30 px-2 py-0.5 rounded">
                {id}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function GapAnalysis({
  result, groupDetail, userIds,
}: {
  result: CompareResult;
  groupDetail: { techniques: Array<{ attack_id: string; name: string; tactic: string; is_subtechnique: boolean }> } | null;
  userIds: Set<string>;
}) {
  if (!groupDetail) return <div className="text-gray-600 text-sm">Loading group details…</div>;

  const gapTechs = groupDetail.techniques.filter(t => !userIds.has(t.attack_id));
  const coveredByTactic = new Map<string, { gap: number; covered: number }>();
  for (const t of groupDetail.techniques) {
    const tactic = t.tactic || 'unknown';
    if (!coveredByTactic.has(tactic)) coveredByTactic.set(tactic, { gap: 0, covered: 0 });
    const entry = coveredByTactic.get(tactic)!;
    userIds.has(t.attack_id) ? entry.covered++ : entry.gap++;
  }

  return (
    <div className="space-y-6">
      <div className="bg-gray-800 rounded-lg p-4">
        <div className="text-sm font-medium text-white mb-1">Coverage Summary</div>
        <p className="text-xs text-gray-400">
          You cover <span className="text-amber-400 font-medium">{result.shared_count}</span> of{' '}
          <span className="text-white font-medium">{groupDetail.techniques.length}</span> techniques
          used by {result.group_name} ({Math.round((result.shared_count / Math.max(groupDetail.techniques.length, 1)) * 100)}% coverage).
          There are <span className="text-blue-400 font-medium">{gapTechs.length}</span> techniques in their profile not in your selection.
        </p>
      </div>

      {gapTechs.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide mb-3">
            Techniques in {result.group_name}'s profile not yet in your layer ({gapTechs.length})
          </div>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {gapTechs.map(t => (
              <div key={t.attack_id} className="flex items-center gap-3 py-1.5 px-3 rounded hover:bg-gray-800/60 transition-colors">
                <span className="font-mono text-xs text-blue-400 w-20 shrink-0">{t.attack_id}</span>
                <span className="text-sm text-gray-300 flex-1">{t.name}</span>
                <span className="text-[10px] bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded shrink-0">{t.tactic}</span>
                {t.is_subtechnique && <span className="text-[10px] text-gray-600 shrink-0">sub</span>}
              </div>
            ))}
          </div>
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
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${cls}`}>
      {pct}% similarity
    </span>
  );
}
