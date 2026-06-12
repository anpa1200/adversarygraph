import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { aptApi, attackApi } from '@/api/client';
import { loadReportIndex, type ReportReference } from '@/config/intelligence';
import { useAppStore } from '@/store';

export function GlobalSearch() {
  const { domain, version } = useAppStore();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [reports, setReports] = useState<ReportReference[]>([]);
  const input = useRef<HTMLInputElement>(null);
  const { data: groups = [] } = useQuery({ queryKey: ['global-groups', domain, version], queryFn: () => aptApi.groups({ domain, version: version ?? undefined }), enabled: open });
  const { data: techniques = [] } = useQuery({ queryKey: ['global-techniques', domain, version], queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }), enabled: open });

  useEffect(() => { loadReportIndex().then(index => {
    const seen = new Set<string>(); setReports(Object.values(index.byTechnique).flat().filter(report => !seen.has(report.url) && seen.add(report.url)));
  }).catch(() => {}); }, []);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); setOpen(value => !value); }
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('keydown', handler); return () => window.removeEventListener('keydown', handler);
  }, []);
  useEffect(() => { if (open) setTimeout(() => input.current?.focus(), 0); }, [open]);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return { groups: [], techniques: [], reports: [] };
    return {
      groups: groups.filter(item => item.attack_id.toLowerCase().includes(q) || item.name.toLowerCase().includes(q) || item.aliases.some(alias => alias.toLowerCase().includes(q))).slice(0, 7),
      techniques: techniques.filter(item => item.attack_id.toLowerCase().includes(q) || item.name.toLowerCase().includes(q)).slice(0, 8),
      reports: reports.filter(item => item.title.toLowerCase().includes(q) || item.publisher.toLowerCase().includes(q) || item.context.toLowerCase().includes(q)).slice(0, 7),
    };
  }, [groups, query, reports, techniques]);

  return <>
    <button onClick={() => setOpen(true)} className="w-full flex items-center justify-between px-3 py-2 rounded border border-gray-700 bg-gray-800/60 text-xs text-gray-400 hover:text-white">
      <span>Search intelligence</span><span className="text-gray-600">Ctrl K</span>
    </button>
    {open && <div className="fixed inset-0 z-[80] bg-black/70 p-8" onClick={() => setOpen(false)}>
      <div className="max-w-3xl mx-auto rounded-lg border border-gray-700 bg-gray-900 shadow-2xl overflow-hidden" onClick={event => event.stopPropagation()}>
        <input ref={input} value={query} onChange={event => setQuery(event.target.value)} placeholder="Search actor, alias, TTP, report, publisher, or evidence..."
          className="w-full bg-gray-950 border-b border-gray-700 px-5 py-4 text-base text-white outline-none focus:border-mitre-accent" />
        <div className="max-h-[70vh] overflow-y-auto p-4 space-y-5">
          <Results title="Threat actors">{results.groups.map(item => <button key={item.attack_id} onClick={() => { navigate(`/apt?group=${item.attack_id}`); setOpen(false); }} className="result"><b>{item.name}</b><small>{item.attack_id} · {item.aliases.slice(0, 3).join(', ')}</small></button>)}</Results>
          <Results title="Techniques">{results.techniques.map(item => <button key={item.attack_id} onClick={() => { navigate(`/navigator?technique=${item.attack_id}`); setOpen(false); }} className="result"><b>{item.name}</b><small>{item.attack_id} · {item.tactics.join(', ')}</small></button>)}</Results>
          <Results title="CTI / IR reports">{results.reports.map(item => <a key={item.url} href={item.url} target="_blank" rel="noreferrer" className="result"><b>{item.title}</b><small>{item.publisher} · {item.match_basis}</small></a>)}</Results>
          {!query && <p className="text-sm text-gray-500">Search across live ATT&amp;CK data and the shared 1200km CTI/IR report index.</p>}
        </div>
      </div>
    </div>}
  </>;
}

function Results({ title, children }: { title: string; children: React.ReactNode }) {
  return <section><h2 className="text-[10px] uppercase tracking-wide text-gray-500 mb-1">{title}</h2><div className="space-y-1">{children}</div></section>;
}

