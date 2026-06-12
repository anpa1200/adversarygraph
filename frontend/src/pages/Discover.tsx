import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { aptApi, attackApi } from '@/api/client';
import { loadReportIndex } from '@/config/intelligence';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';

export function Discover() {
  const { domain, version, selectedTechniques, coverageTechniques, workspaces } = useAppStore();
  const navigate = useNavigate();
  const { data: groups = [] } = useQuery({ queryKey: ['discover-groups', domain, version], queryFn: () => aptApi.groups({ domain, version: version ?? undefined }) });
  const { data: techniques = [] } = useQuery({ queryKey: ['discover-techniques', domain, version], queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }) });
  const { data: reports } = useQuery({ queryKey: ['report-index'], queryFn: loadReportIndex });
  const uniqueReports = useMemo(() => {
    const seen = new Set<string>(); return Object.values(reports?.byTechnique ?? {}).flat().filter(item => !seen.has(item.url) && seen.add(item.url));
  }, [reports]);
  const recent = [...uniqueReports].filter(item => item.date).sort((a, b) => b.date.localeCompare(a.date)).slice(0, 10);
  const trending = Object.entries(reports?.byTechnique ?? {}).map(([id, refs]) => ({ id, count: new Set(refs.map(item => item.url)).size, name: techniques.find(item => item.attack_id === id)?.name ?? id })).sort((a, b) => b.count - a.count).slice(0, 12);

  return <div className="flex flex-col h-full"><Header title="Discover Intelligence" /><div className="flex-1 overflow-y-auto p-6">
    <div className="max-w-7xl mx-auto">
      <p className="text-sm text-gray-400 max-w-3xl mb-6">Start with an actor, behavior, report, AI analysis, or detection gap. ThreatMapper connects live ATT&amp;CK data, private analysis, and the shared 1200km research ecosystem.</p>
      <div className="grid md:grid-cols-4 gap-3 mb-7">
        <Start title="Investigate actor" text="Profiles, campaigns, reports, aliases, and behavior." onClick={() => navigate('/apt')} />
        <Start title="Analyze report with AI" text="Extract ATT&CK evidence using your configured LLM." onClick={() => navigate('/analyze')} />
        <Start title="Compare behavior" text="Rank group, campaign, and stored-report overlap." onClick={() => navigate('/compare')} />
        <Start title="Review coverage" text="Prioritize selected techniques without coverage." onClick={() => navigate('/navigator')} />
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-3 mb-7">
        <Metric label="Actors" value={groups.length} /><Metric label="Techniques" value={techniques.length} /><Metric label="Public reports" value={uniqueReports.length} />
        <Metric label="Selected TTPs" value={selectedTechniques.size} /><Metric label="Covered TTPs" value={coverageTechniques.size} /><Metric label="Workspaces" value={workspaces.length} />
      </div>
      <div className="grid lg:grid-cols-2 gap-5">
        <Panel title="Most-referenced techniques">{trending.map(item => <button key={item.id} onClick={() => navigate(`/navigator?technique=${item.id}`)} className="result flex-row items-center justify-between"><span><b>{item.id}</b><small>{item.name}</small></span><small>{item.count} reports</small></button>)}</Panel>
        <Panel title="Recent public intelligence">{recent.map(item => <a key={item.url} href={item.url} target="_blank" rel="noreferrer" className="result"><b>{item.title}</b><small>{item.date} · {item.publisher}</small></a>)}</Panel>
        <Panel title="1200km ecosystem">{[
          ['CTI Analyst Field Manual','https://1200km.com/cti-analyst-field-manual/'],['Israel Threat Actors CTI','https://1200km.com/israel-government-threat-actors-cti/'],['Anomaly Detection Atlas','https://1200km.com/anomaly-detection-atlas/'],['ITDR Handbook','https://1200km.com/ITDR/'],['Medium Research','https://medium.com/@1200km']
        ].map(([label,url]) => <a key={url} href={url} target="_blank" rel="noreferrer" className="result"><b>{label} ↗</b></a>)}</Panel>
        <Panel title="Private platform capabilities"><div className="grid grid-cols-2 gap-2 p-2">{['AI report extraction','Private report library','Campaign comparison','Saved server layers','LLM technique assistant','Automated ATT&CK sync','PDF exports','API workflows'].map(item => <span key={item} className="rounded border border-purple-900/50 bg-purple-950/20 p-2 text-xs text-purple-300">{item}</span>)}</div></Panel>
      </div>
    </div>
  </div></div>;
}
function Start({ title, text, onClick }: { title: string; text: string; onClick: () => void }) { return <button onClick={onClick} className="rounded-lg border border-gray-700 bg-gray-900 p-4 text-left hover:border-mitre-accent"><b className="block text-white">{title}</b><span className="block text-xs text-gray-500 mt-1">{text}</span></button>; }
function Metric({ label, value }: { label: string; value: number }) { return <div className="rounded border border-gray-800 bg-gray-900 p-3"><b className="block text-xl text-white">{value}</b><span className="text-[10px] text-gray-500">{label}</span></div>; }
function Panel({ title, children }: { title: string; children: React.ReactNode }) { return <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-3"><h2 className="text-sm font-semibold text-white px-2 py-1">{title}</h2>{children}</section>; }

