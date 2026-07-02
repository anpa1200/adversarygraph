import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Header } from '@/components/Layout/Header';
import { statisticsApi, type StatPoint, type StatWidget } from '@/api/client';
import { useAppStore } from '@/store';

const DATASETS = [
  { id: 'actors', label: 'Groups / actors', detail: 'Actor TTP coverage and recurring behaviors.' },
  { id: 'reports', label: 'Reports', detail: 'Stored AI report extraction and TTP frequency.' },
  { id: 'sectors', label: 'Sectors', detail: 'Sector pack confidence, actor mentions, and TTP categories.' },
  { id: 'ttps', label: 'TTPs', detail: 'Technique, sub-technique, and tactic distribution.' },
  { id: 'cves', label: 'CVEs', detail: 'CVSS severity, KEV, weakness, and CVE-to-TTP usage.' },
  { id: 'iocs', label: 'IOCs', detail: 'IOC type, source, actor, and technique relationships.' },
];

const COLORS = ['#fb7185', '#38bdf8', '#34d399', '#fbbf24', '#a78bfa', '#f472b6', '#22d3ee', '#f97316'];

export function Statistics() {
  const { domain } = useAppStore();
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string[]>(DATASETS.map(item => item.id));
  const [limit, setLimit] = useState(15);

  const query = useQuery({
    queryKey: ['statistics-overview', domain, selected, limit],
    queryFn: () => statisticsApi.overview({ domain, include: selected, limit }),
    enabled: selected.length > 0,
  });

  const data = query.data;
  const widgets = data?.widgets ?? [];
  const totals = data?.totals ?? [];
  const selectedSet = useMemo(() => new Set(selected), [selected]);

  const toggleDataset = (id: string) => {
    setSelected(current => {
      if (current.includes(id)) return current.filter(item => item !== id);
      return [...current, id];
    });
  };

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Statistics" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-6">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Statistical analysis workspace</h2>
                <p className="mt-2 max-w-4xl text-sm leading-6 text-sky-100/80">
                  Compare actor behavior, report extraction, sector relevance, ATT&amp;CK usage, CVE relationships,
                  and IOC coverage. Add or remove datasets with checkboxes to build the statistical view you need.
                </p>
              </div>
              <div className="rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-400">
                Domain: <span className="font-mono text-gray-100">{domain}</span>
              </div>
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_260px]">
            <Panel title="Add Data To Statistical Analysis">
              <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
                {DATASETS.map(item => (
                  <label
                    key={item.id}
                    className={`flex cursor-pointer gap-3 rounded-lg border p-3 transition-colors ${
                      selectedSet.has(item.id)
                        ? 'border-mitre-accent bg-mitre-accent/10'
                        : 'border-gray-800 bg-gray-950/60 hover:border-gray-600'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={selectedSet.has(item.id)}
                      onChange={() => toggleDataset(item.id)}
                      className="mt-1 h-4 w-4 accent-mitre-accent"
                    />
                    <span>
                      <b className="block text-sm text-white">{item.label}</b>
                      <span className="mt-1 block text-xs leading-5 text-gray-500">{item.detail}</span>
                    </span>
                  </label>
                ))}
              </div>
            </Panel>

            <Panel title="Analysis Controls">
              <div className="space-y-4 p-4">
                <label className="block text-xs text-gray-400">
                  Rows per widget
                  <select value={limit} onChange={event => setLimit(Number(event.target.value))} className="field mt-2 w-full">
                    {[10, 15, 25, 50].map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => query.refetch()}
                  disabled={query.isFetching || selected.length === 0}
                  className="primary-action w-full disabled:opacity-40"
                >
                  {query.isFetching ? 'Refreshing...' : 'Refresh statistics'}
                </button>
                <button
                  type="button"
                  onClick={() => setSelected(DATASETS.map(item => item.id))}
                  className="secondary-action w-full"
                >
                  Select all datasets
                </button>
                <button
                  type="button"
                  onClick={() => setSelected([])}
                  className="secondary-action w-full"
                >
                  Clear selection
                </button>
              </div>
            </Panel>
          </section>

          {selected.length === 0 && (
            <section className="rounded-lg border border-amber-500/40 bg-amber-950/20 p-5 text-sm text-amber-100">
              Select at least one dataset to run statistical analysis.
            </section>
          )}

          {query.error && (
            <section className="rounded-lg border border-red-500/50 bg-red-950/30 p-4 text-sm text-red-100">
              Statistics request failed: {query.error instanceof Error ? query.error.message : 'unknown error'}
            </section>
          )}

          <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
            {totals.map(total => <TotalCard key={`${total.label}-${total.value}`} point={total} />)}
            {query.isLoading && <TotalCard point={{ label: 'Loading', value: 0, id: '', secondary: '', category: '', detail: 'Collecting statistics' }} />}
          </section>

          <section className="grid gap-5 xl:grid-cols-2">
            {widgets.map(widget => (
              <WidgetCard key={widget.id} widget={widget} onNavigate={navigateToPoint(navigate, widget)} />
            ))}
            {!query.isLoading && selected.length > 0 && widgets.length === 0 && (
              <Panel title="No Statistics Returned">
                <p className="p-4 text-sm text-gray-500">
                  The selected datasets are empty or not synced yet. Open Feeds Management to sync ATT&amp;CK, IOC, and CVE sources.
                </p>
              </Panel>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function navigateToPoint(navigate: ReturnType<typeof useNavigate>, widget: StatWidget) {
  return (point: StatPoint) => {
    if (!point.id) return;
    if (point.id.startsWith('T')) navigate(`/navigator?technique=${encodeURIComponent(point.id)}`);
    else if (point.id.startsWith('G')) navigate(`/apt?group=${encodeURIComponent(point.id)}`);
    else if (point.id.startsWith('CVE-')) navigate(`/cve?search=${encodeURIComponent(point.id)}`);
    else if (widget.id.includes('cwe')) navigate(`/cve?search=${encodeURIComponent(point.id)}`);
  };
}

function TotalCard({ point }: { point: StatPoint }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className="text-2xl font-semibold text-white">{formatNumber(point.value)}</div>
      <div className="mt-1 text-xs text-gray-500">{point.label}</div>
      {point.detail && <div className="mt-2 text-[11px] leading-4 text-gray-600">{point.detail}</div>}
    </div>
  );
}

function WidgetCard({ widget, onNavigate }: { widget: StatWidget; onNavigate: (point: StatPoint) => void }) {
  return (
    <Panel title={widget.title} badge={widget.dataset}>
      <div className="border-b border-gray-800 px-4 py-3 text-xs leading-5 text-gray-500">{widget.description}</div>
      {widget.points.length === 0 ? (
        <p className="p-4 text-sm text-gray-500">No data available for this statistic.</p>
      ) : widget.kind === 'pie' ? (
        <PieWidget points={widget.points} onNavigate={onNavigate} />
      ) : widget.kind === 'bar' ? (
        <BarWidget points={widget.points} onNavigate={onNavigate} />
      ) : (
        <TableWidget points={widget.points} onNavigate={onNavigate} />
      )}
    </Panel>
  );
}

function BarWidget({ points, onNavigate }: { points: StatPoint[]; onNavigate: (point: StatPoint) => void }) {
  const chartData = points.map(point => ({ ...point, short: point.id || compactLabel(point.label) }));
  return (
    <div className="p-4">
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 8, right: 12, bottom: 42, left: 0 }}>
            <XAxis dataKey="short" tick={{ fill: '#94a3b8', fontSize: 10 }} angle={-35} textAnchor="end" interval={0} height={62} />
            <YAxis tick={{ fill: '#94a3b8', fontSize: 10 }} width={42} />
            <Tooltip content={<ChartTooltip />} />
            <Bar
              dataKey="value"
              radius={[3, 3, 0, 0]}
              onClick={(data) => {
                const point = (data as { payload?: StatPoint }).payload ?? (data as unknown as StatPoint);
                onNavigate(point);
              }}
            >
              {chartData.map((_, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <TableWidget points={points.slice(0, 8)} onNavigate={onNavigate} compact />
    </div>
  );
}

function PieWidget({ points, onNavigate }: { points: StatPoint[]; onNavigate: (point: StatPoint) => void }) {
  return (
    <div className="grid gap-4 p-4 lg:grid-cols-[220px_1fr]">
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={points}
              dataKey="value"
              nameKey="label"
              outerRadius={88}
              innerRadius={42}
              paddingAngle={2}
              onClick={(data) => onNavigate(data as unknown as StatPoint)}
            >
              {points.map((_, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <TableWidget points={points} onNavigate={onNavigate} compact />
    </div>
  );
}

function TableWidget({ points, onNavigate, compact = false }: { points: StatPoint[]; onNavigate: (point: StatPoint) => void; compact?: boolean }) {
  return (
    <div className={compact ? 'max-h-72 overflow-y-auto' : 'max-h-[420px] overflow-y-auto'}>
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-gray-950 text-gray-500">
          <tr>
            <th className="px-3 py-2">Item</th>
            <th className="px-3 py-2">Context</th>
            <th className="px-3 py-2 text-right">Count</th>
          </tr>
        </thead>
        <tbody>
          {points.map((point, index) => (
            <tr key={`${point.id}-${point.label}-${index}`} className="border-t border-gray-900">
              <td className="px-3 py-2">
                <button
                  type="button"
                  onClick={() => onNavigate(point)}
                  className={`text-left ${point.id ? 'text-sky-300 hover:text-mitre-accent' : 'text-gray-200'}`}
                >
                  <span className="block font-semibold">{point.id || point.label}</span>
                  {point.id && <span className="block text-[11px] text-gray-500">{point.label}</span>}
                </button>
              </td>
              <td className="px-3 py-2 text-gray-500">{point.secondary || point.category || point.detail || '-'}</td>
              <td className="px-3 py-2 text-right font-mono text-white">{formatNumber(point.value)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Panel({ title, badge, children }: { title: string; badge?: string; children: ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="flex items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
        {badge && <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[10px] uppercase text-gray-500">{badge}</span>}
      </div>
      {children}
    </section>
  );
}

function ChartTooltip({ active, payload }: { active?: boolean; payload?: Array<{ payload: StatPoint }> }) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;
  return (
    <div className="rounded border border-gray-700 bg-gray-950 p-3 text-xs shadow-xl">
      <div className="font-semibold text-white">{point.id || point.label}</div>
      {point.id && <div className="mt-1 text-gray-400">{point.label}</div>}
      <div className="mt-2 font-mono text-mitre-accent">{formatNumber(point.value)}</div>
      {(point.secondary || point.category) && <div className="mt-1 text-gray-500">{point.secondary || point.category}</div>}
    </div>
  );
}

function compactLabel(value: string) {
  if (value.length <= 16) return value;
  return `${value.slice(0, 13)}...`;
}

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}
