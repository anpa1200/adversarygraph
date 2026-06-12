import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { aptApi, attackApi } from '@/api/client';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';

export function InvestigationReport() {
  const { domain, version, selectedTechniques, coverageTechniques, techniqueAssessments } = useAppStore();
  const ids = [...selectedTechniques].sort();
  const { data: techniques = [] } = useQuery({ queryKey: ['report-techniques', domain, version], queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }) });
  const { data: matches = [] } = useQuery({ queryKey: ['report-matches', domain, version, ids.join(',')], queryFn: () => aptApi.compare({ technique_ids: ids, domain, version: version ?? undefined, top_n: 10 }), enabled: ids.length > 0 });
  const rows = useMemo(() => ids.map(id => ({ id, name: techniques.find(item => item.attack_id === id)?.name ?? id, assessment: techniqueAssessments[id] ?? {}, covered: coverageTechniques.has(id) })), [coverageTechniques, ids, techniqueAssessments, techniques]);

  const exportReport = () => {
    const text = [
      'ThreatMapper Investigation Report', `Generated: ${new Date().toISOString()}`, `Domain: ${domain}`, `Selected techniques: ${rows.length}`, `Covered techniques: ${rows.filter(row => row.covered).length}`, '',
      'Top behavior-overlap hypotheses:', ...matches.map((item, index) => `${index + 1}. ${item.group_name} (${item.group_attack_id}) — ${Math.round(item.similarity * 100)}% Jaccard overlap; ${item.shared_count} shared`), '',
      'Technique evidence:', ...rows.flatMap(row => [`${row.id} — ${row.name}`, `  Coverage: ${row.covered ? 'yes' : 'no'} | Mapping: ${row.assessment.mapping ?? 'weak'} | Confidence: ${row.assessment.confidence ?? 'low'} | Maturity: ${row.assessment.maturity ?? 'none'}`, `  Evidence: ${row.assessment.evidence ?? 'Not recorded'}`, `  Source: ${row.assessment.source ?? 'Not recorded'}`, `  Notes: ${row.assessment.notes ?? 'Not recorded'}`, '']),
      'Analytic caution: TTP overlap supports hypothesis generation and prioritization; it is not definitive attribution evidence.',
    ].join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'threatmapper-investigation-report.txt'; anchor.click(); URL.revokeObjectURL(url);
  };

  return <div className="flex flex-col h-full"><Header title="Investigation Report" /><div className="flex-1 overflow-y-auto p-6"><div className="max-w-6xl mx-auto">
    <div className="flex items-start justify-between mb-6"><div><h1 className="text-xl font-bold text-white">Evidence-backed ATT&amp;CK investigation</h1><p className="text-sm text-gray-500 mt-1">{rows.length} techniques · {rows.filter(row => row.covered).length} covered · {Object.keys(techniqueAssessments).length} assessed</p></div><button onClick={exportReport} disabled={!rows.length} className="bg-mitre-accent text-white text-xs px-4 py-2 rounded disabled:opacity-40">Export report</button></div>
    {!rows.length ? <p className="text-gray-500">Select techniques or load a workspace to generate an investigation report.</p> : <div className="grid lg:grid-cols-3 gap-5">
      <section className="lg:col-span-2 rounded border border-gray-800 bg-gray-900/50 p-3"><h2 className="text-sm font-semibold text-white mb-2">Technique evidence</h2>{rows.map(row => <div key={row.id} className="border-t border-gray-800 py-3"><div className="flex justify-between"><b className="text-sm text-gray-200"><span className="font-mono text-mitre-accent mr-2">{row.id}</span>{row.name}</b><span className={`text-[10px] ${row.covered ? 'text-green-400' : 'text-amber-500'}`}>{row.covered ? 'covered' : 'gap'}</span></div><p className="text-[10px] text-gray-500 mt-1">{row.assessment.mapping ?? 'weak'} mapping · {row.assessment.confidence ?? 'low'} confidence · {row.assessment.maturity ?? 'none'} maturity</p>{row.assessment.evidence && <p className="text-xs text-gray-400 mt-1">{row.assessment.evidence}</p>}</div>)}</section>
      <section className="rounded border border-gray-800 bg-gray-900/50 p-3"><h2 className="text-sm font-semibold text-white mb-2">Behavior-overlap hypotheses</h2>{matches.map((item, index) => <div key={item.group_attack_id} className="border-t border-gray-800 py-3"><b className="text-xs text-gray-300">{index + 1}. {item.group_name}</b><p className="text-[10px] text-gray-500">{Math.round(item.similarity * 100)}% Jaccard · {item.shared_count} shared</p></div>)}</section>
    </div>}
  </div></div></div>;
}

