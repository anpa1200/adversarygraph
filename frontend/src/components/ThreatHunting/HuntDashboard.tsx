import { useMemo } from 'react';
import type { ColumnDef } from '@tanstack/react-table';

import type {
  ThreatHunt,
  ThreatHuntPriority,
  ThreatHuntStats,
  ThreatHuntStatus,
  ThreatHuntTemplate,
} from '@/api/client';
import { DataTable } from '@/components/ui/data-table';
import { HuntPriorityPill, HuntStatusPill } from './HuntStatusPill';

export interface HuntFilters {
  q: string;
  status: '' | ThreatHuntStatus;
  priority: '' | ThreatHuntPriority;
  technique: string;
}

const STATUS_OPTIONS: ThreatHuntStatus[] = ['queued', 'draft', 'planned', 'running', 'review', 'completed', 'cancelled', 'archived'];
const PRIORITY_OPTIONS: ThreatHuntPriority[] = ['P0 Emergency', 'P1 High', 'P2 Medium', 'P3 Monitor', 'P4 Low/Archive'];

export function HuntDashboard({
  stats,
  hunts,
  templates,
  filters,
  onFiltersChange,
  onOpenHunt,
  onCreate,
  onUseTemplate,
  loading,
  error,
}: {
  stats?: ThreatHuntStats;
  hunts: ThreatHunt[];
  templates: ThreatHuntTemplate[];
  filters: HuntFilters;
  onFiltersChange: (filters: HuntFilters) => void;
  onOpenHunt: (id: string) => void;
  onCreate: () => void;
  onUseTemplate: (id: string) => void;
  loading: boolean;
  error: string;
}) {
  const columns = useMemo<ColumnDef<ThreatHunt>[]>(() => [
    {
      accessorKey: 'title',
      header: 'Hunt',
      cell: ({ row }) => (
        <button
          type="button"
          className="min-w-[260px] rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          onClick={event => {
            event.stopPropagation();
            onOpenHunt(row.original.id);
          }}
        >
          <b className="block text-sm text-white">{row.original.title}</b>
          <span className="mt-1 block line-clamp-2 max-w-xl text-[11px] leading-4 text-gray-500">{row.original.hypothesis}</span>
        </button>
      ),
    },
    { accessorKey: 'status', header: 'Status', cell: ({ row }) => <HuntStatusPill status={row.original.status} /> },
    { accessorKey: 'priority', header: 'Priority', cell: ({ row }) => <HuntPriorityPill priority={row.original.priority} /> },
    {
      id: 'techniques',
      header: 'ATT&CK',
      cell: ({ row }) => (
        <div className="flex max-w-[220px] flex-wrap gap-1">
          {row.original.technique_ids.slice(0, 3).map(id => <span key={id} className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-[10px] text-cyan-200">{id}</span>)}
          {row.original.technique_ids.length > 3 && <span className="text-[10px] text-gray-600">+{row.original.technique_ids.length - 3}</span>}
          {!row.original.technique_ids.length && <span className="text-gray-600">Not mapped</span>}
        </div>
      ),
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: ({ row }) => row.original.owner || <span className="text-gray-600">Unassigned</span>,
    },
    {
      accessorKey: 'updated_at',
      header: 'Updated',
      cell: ({ row }) => <span className="whitespace-nowrap text-gray-500">{formatDate(row.original.updated_at)}</span>,
    },
  ], [onOpenHunt]);

  return (
    <main className="flex-1 px-6 py-6">
      <div className="mx-auto max-w-[1500px] space-y-5">
        <section className="rounded-lg border border-cyan-500/35 bg-cyan-950/15 p-5">
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_520px]">
            <div>
              <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-200">Hypothesis-driven operations</p>
              <h1 className="mt-3 text-2xl font-semibold text-white">Turn intelligence leads into reviewable threat hunts.</h1>
              <p className="mt-3 max-w-4xl text-sm leading-6 text-cyan-100/75">
                Define the question, scope the telemetry, preserve the query and evidence, review findings, and record an explicit outcome.
                AdversaryGraph manages the hunt record; queries run only in your approved telemetry tools.
              </p>
              <div className="mt-4 flex flex-wrap gap-2">
                <button type="button" onClick={onCreate} className="primary min-h-10 px-4 text-sm">Create threat hunt</button>
                <a href="/query-library" className="secondary-action inline-flex min-h-10 items-center px-4 text-xs">Browse query library</a>
                <a href="/help#threat-hunting" className="secondary-action inline-flex min-h-10 items-center px-4 text-xs">Open hunting guide</a>
              </div>
            </div>
            <div className="grid gap-2 text-xs sm:grid-cols-5 xl:grid-cols-5">
              {[
                ['1', 'Hypothesis'],
                ['2', 'Scope'],
                ['3', 'Query'],
                ['4', 'Findings'],
                ['5', 'Outcome'],
              ].map(([step, label]) => (
                <div key={step} className="rounded border border-cyan-500/20 bg-gray-950/50 p-3 text-center">
                  <span className="mx-auto block w-fit rounded bg-cyan-500/15 px-2 py-1 font-mono text-cyan-100">{step}</span>
                  <b className="mt-2 block text-white">{label}</b>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section aria-label="Threat hunting metrics" className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          <Metric label="All hunts" value={stats?.total_hunts ?? 0} detail="Recorded plans" />
          <Metric label="Active" value={stats?.active_hunts ?? 0} detail="Planned, running, review" tone="cyan" />
          <Metric label="Awaiting review" value={stats?.by_status.review ?? 0} detail="Needs analyst decision" tone="amber" />
          <Metric label="Completed" value={stats?.completed_hunts ?? 0} detail="Outcome recorded" tone="green" />
          <Metric label="High findings" value={stats?.high_priority_findings ?? 0} detail={`${stats?.total_findings ?? 0} total findings`} tone="red" />
        </section>

        <Panel title="Hunt queue">
          <div className="grid gap-2 border-b border-gray-800 p-4 lg:grid-cols-[minmax(240px,1fr)_180px_190px_170px_auto]">
            <label className="text-xs text-gray-500">
              Search
              <input
                className="field mt-1"
                value={filters.q}
                onChange={event => onFiltersChange({ ...filters, q: event.target.value })}
                placeholder="Title or hypothesis"
              />
            </label>
            <label className="text-xs text-gray-500">
              Status
              <select className="field mt-1" value={filters.status} onChange={event => onFiltersChange({ ...filters, status: event.target.value as HuntFilters['status'] })}>
                <option value="">All statuses</option>
                {STATUS_OPTIONS.map(value => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label className="text-xs text-gray-500">
              Priority
              <select className="field mt-1" value={filters.priority} onChange={event => onFiltersChange({ ...filters, priority: event.target.value as HuntFilters['priority'] })}>
                <option value="">All priorities</option>
                {PRIORITY_OPTIONS.map(value => <option key={value} value={value}>{value}</option>)}
              </select>
            </label>
            <label className="text-xs text-gray-500">
              ATT&amp;CK technique
              <input
                className="field mt-1 font-mono uppercase"
                value={filters.technique}
                onChange={event => onFiltersChange({ ...filters, technique: event.target.value.toUpperCase() })}
                placeholder="T1059.001"
              />
            </label>
            <button
              type="button"
              onClick={() => onFiltersChange({ q: '', status: '', priority: '', technique: '' })}
              className="secondary-action self-end px-3 py-2 text-xs"
            >
              Clear filters
            </button>
          </div>

          {error && <div role="alert" className="m-4 rounded border border-red-700/60 bg-red-950/30 p-3 text-sm text-red-200">{error}</div>}
          {filters.technique && !/^T\d{4}(?:\.\d{3})?$/.test(filters.technique) && (
            <p className="px-4 pt-3 text-xs text-amber-300">Enter an ATT&amp;CK technique such as T1059.001.</p>
          )}
          <div className="p-4">
            <DataTable
              data={hunts}
              columns={columns}
              onRowClick={row => onOpenHunt(row.id)}
              empty={loading ? 'Loading threat hunts…' : 'No hunts match these filters. Create a hunt or start from a template.'}
            />
          </div>
        </Panel>

        <Panel title="Start from a reviewed template">
          <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-3">
            {templates.slice(0, 6).map(template => (
              <button
                type="button"
                key={template.id}
                onClick={() => onUseTemplate(template.id)}
                className="rounded border border-gray-800 bg-gray-950/60 p-4 text-left transition-colors hover:border-cyan-700 hover:bg-gray-900"
              >
                <b className="text-sm text-white">{template.title}</b>
                <p className="mt-2 line-clamp-3 text-xs leading-5 text-gray-500">{template.hypothesis}</p>
                <div className="mt-3 flex flex-wrap gap-1">
                  {template.technique_ids.map(id => <span key={id} className="rounded bg-cyan-950 px-2 py-1 font-mono text-[10px] text-cyan-200">{id}</span>)}
                </div>
              </button>
            ))}
            {!templates.length && !loading && <p className="text-sm text-gray-600">No templates are available.</p>}
          </div>
        </Panel>
      </div>
    </main>
  );
}

function Metric({ label, value, detail, tone = 'default' }: { label: string; value: number; detail: string; tone?: 'default' | 'cyan' | 'amber' | 'green' | 'red' }) {
  const color = {
    default: 'text-white',
    cyan: 'text-cyan-200',
    amber: 'text-amber-200',
    green: 'text-emerald-200',
    red: 'text-red-200',
  }[tone];
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
      <div className={`text-2xl font-semibold ${color}`}>{value}</div>
      <div className="mt-1 text-xs font-semibold text-gray-300">{label}</div>
      <div className="mt-1 text-[11px] text-gray-600">{detail}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/50">
      <h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
}
