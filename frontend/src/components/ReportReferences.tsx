import { useMemo, useState } from 'react';
import type { ReportReference } from '@/config/intelligence';

export function ReportReferences({ reports, limit = 30 }: { reports: ReportReference[]; limit?: number }) {
  const [filter, setFilter] = useState<'all' | 'direct' | 'primary' | 'recent'>('all');
  const filtered = useMemo(() => reports.filter(report => {
    if (filter === 'direct') return report.match_basis.toLowerCase().includes('direct');
    if (filter === 'primary') return /cisa|fbi|mitre|microsoft|google|mandiant|checkpoint|eset/i.test(report.publisher);
    if (filter === 'recent') return report.date >= '2024-01-01';
    return true;
  }), [filter, reports]);

  if (!reports.length) return <p className="text-xs text-gray-600">No correlated CTI/IR reports indexed.</p>;
  return <div className="space-y-2">
    <div className="flex gap-1 flex-wrap">
      {(['all', 'direct', 'primary', 'recent'] as const).map(value => <button key={value} onClick={() => setFilter(value)}
        className={`px-2 py-1 rounded border text-[10px] capitalize ${filter === value ? 'border-blue-600 text-blue-300 bg-blue-950/40' : 'border-gray-700 text-gray-500'}`}>{value}</button>)}
      <span className="text-[10px] text-gray-600 self-center ml-1">{filtered.length} shown</span>
    </div>
    {filtered.slice(0, limit).map(report => <a key={report.url} href={report.url} target="_blank" rel="noreferrer"
      className="block rounded border border-gray-800 bg-gray-900/40 px-3 py-2 hover:border-gray-600">
      <span className="block text-xs text-gray-300">{report.title} ↗</span>
      <span className="block text-[10px] text-gray-600 mt-0.5">{report.publisher}{report.date ? ` · ${report.date}` : ''}{report.reliability ? ` · Reliability ${report.reliability}` : ''}</span>
      <span className="block text-[10px] text-blue-500/80 mt-0.5">{report.match_basis}</span>
      {report.context && <span className="block text-[10px] text-gray-600 mt-0.5 line-clamp-2">{report.context}</span>}
    </a>)}
  </div>;
}

