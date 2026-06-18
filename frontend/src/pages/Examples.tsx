import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { loadDfirReportIndex, type DfirExampleReport } from '@/config/intelligence';

type Filter = 'all' | 'with-ttps' | 'with-actors' | 'recent';

export function Examples() {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const { data, isLoading, error } = useQuery({
    queryKey: ['dfir-examples'],
    queryFn: loadDfirReportIndex,
  });

  const reports = useMemo(() => data?.reports ?? [], [data?.reports]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return reports.filter(report => {
      if (filter === 'with-ttps' && report.techniques.length === 0) return false;
      if (filter === 'with-actors' && report.actors.length === 0) return false;
      if (filter === 'recent' && report.date < '2024-01-01') return false;
      if (!needle) return true;
      return [
        report.title,
        report.date,
        report.url,
        ...report.tags,
        ...report.techniques,
        ...report.actors,
      ].join(' ').toLowerCase().includes(needle);
    });
  }, [reports, query, filter]);

  return (
    <div className="flex flex-col h-full">
      <Header title="DFIR Examples" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-7xl mx-auto space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="grid lg:grid-cols-[1fr_auto] gap-4 items-start">
              <div>
                <h2 className="text-base font-semibold text-white">Indexed Public DFIR Report Examples</h2>
                <p className="mt-2 text-sm text-gray-400 max-w-4xl">
                  Linked metadata from The DFIR Report public pages. AdversaryGraph stores report titles, URLs, dates, tags, ATT&CK IDs, and actor mappings only; full report text and images stay on the source site.
                </p>
                {data?.license_note && <p className="mt-2 text-xs text-gray-500">{data.license_note}</p>}
              </div>
              <div className="grid grid-cols-3 gap-2 min-w-[300px]">
                <Metric label="Reports" value={data?.report_count ?? 0} />
                <Metric label="TTPs" value={data?.technique_count ?? 0} />
                <Metric label="Actors" value={data?.actor_count ?? 0} />
              </div>
            </div>
          </section>

          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="flex flex-wrap gap-2 items-center">
              <input
                value={query}
                onChange={event => setQuery(event.target.value)}
                placeholder="Search title, TTP, actor, tag..."
                className="min-w-[280px] flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent"
              />
              {(['all', 'with-ttps', 'with-actors', 'recent'] as const).map(item => (
                <button
                  key={item}
                  onClick={() => setFilter(item)}
                  className={`rounded border px-3 py-2 text-xs capitalize ${filter === item ? 'border-mitre-accent bg-mitre-accent/10 text-white' : 'border-gray-700 text-gray-500 hover:text-gray-300'}`}
                >
                  {item.replace('-', ' ')}
                </button>
              ))}
              <span className="text-xs text-gray-500">{filtered.length} shown</span>
            </div>
          </section>

          {isLoading && <div className="text-sm text-gray-500">Loading examples...</div>}
          {error && <div className="text-sm text-red-400">{String(error)}</div>}

          <div className="grid xl:grid-cols-2 gap-3">
            {filtered.map(report => (
              <article
                key={report.url}
                className="rounded-lg border border-gray-800 bg-gray-900/50 p-4"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="text-sm font-semibold text-white">{report.title}</h3>
                    <p className="mt-1 text-[10px] text-gray-500">{report.date || 'undated'} · The DFIR Report</p>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <button
                      onClick={() => openPdfWorkflow(report)}
                      className="rounded border border-mitre-accent px-2 py-1 text-[10px] text-mitre-accent hover:bg-mitre-accent/10"
                      title="Open the original report so you can save it as PDF for local AI analysis"
                    >
                      PDF workflow
                    </button>
                    <a
                      href={report.url}
                      target="_blank"
                      rel="noreferrer"
                      className="rounded border border-gray-700 px-2 py-1 text-[10px] text-gray-400 hover:text-white hover:border-gray-500"
                    >
                      Open ↗
                    </a>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {report.techniques.slice(0, 16).map(ttp => (
                    <span key={ttp} className="rounded bg-red-950/40 px-1.5 py-0.5 text-[10px] font-mono text-red-300">{ttp}</span>
                  ))}
                  {report.techniques.length > 16 && <span className="text-[10px] text-gray-600">+{report.techniques.length - 16} TTPs</span>}
                </div>
                {report.actors.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {report.actors.map(actor => (
                      <span key={actor} className="rounded bg-purple-950/40 px-1.5 py-0.5 text-[10px] font-mono text-purple-300">{actor}</span>
                    ))}
                  </div>
                )}
                {report.tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {report.tags.slice(0, 8).map(tag => (
                      <span key={tag} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-500">{tag}</span>
                    ))}
                  </div>
                )}
              </article>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div className="rounded border border-gray-800 bg-gray-950/50 p-3"><b className="block text-lg text-white">{value}</b><span className="text-[10px] text-gray-500">{label}</span></div>;
}

function openPdfWorkflow(report: DfirExampleReport) {
  window.open(report.url, '_blank', 'noopener,noreferrer');
  const payload = [
    `DFIR Report PDF workflow`,
    ``,
    `Title: ${report.title}`,
    `Source URL: ${report.url}`,
    `Date: ${report.date || 'undated'}`,
    ``,
    `How to create the PDF for local AI Analysis:`,
    `1. Use the opened original DFIR Report tab.`,
    `2. Press Ctrl+P.`,
    `3. Select "Save to PDF".`,
    `4. Upload the saved PDF in AdversaryGraph > AI Analysis.`,
    ``,
    `Indexed TTPs: ${report.techniques.join(', ') || 'none indexed'}`,
    `Indexed actors: ${report.actors.join(', ') || 'none indexed'}`,
    ``,
    `Copyright note: this workflow does not mirror the report inside AdversaryGraph. The PDF is created from the original source page by the user for local analysis.`,
    ``,
  ].join('\n');
  const blob = new Blob([payload], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${slug(report.title)}-pdf-workflow.txt`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 80) || 'dfir-example';
}
