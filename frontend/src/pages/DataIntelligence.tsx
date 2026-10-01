import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import type React from 'react';
import { Header } from '@/components/Layout/Header';
import { observabilityApi, type PlatformArchitectureSnapshot } from '@/api/client';

const format = (value: number | null | undefined) =>
  value == null ? 'unavailable' : value.toLocaleString();

const percent = (part: number | null, total: number | null) =>
  part == null || total == null || total === 0 ? null : Math.min(100, Math.round((part / total) * 100));

export function DataIntelligence() {
  const query = useQuery({
    queryKey: ['platform-data-logic'],
    queryFn: () => observabilityApi.architecture(60),
    refetchInterval: 30000,
  });
  const snapshot = query.data;

  return (
    <>
      <Header title="Data Logic & AI Grounding" />
      <div className="flex-1 overflow-y-auto p-4 md:p-6">
        <div className="mx-auto max-w-[1500px] space-y-5">
          <section className="overflow-hidden rounded-xl border border-cyan-500/30 bg-gradient-to-br from-cyan-950/35 via-gray-950 to-fuchsia-950/20 p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="max-w-4xl">
                <p className="text-[11px] font-semibold uppercase tracking-[0.24em] text-cyan-300">Live intelligence supply chain</p>
                <h1 className="mt-2 text-2xl font-bold text-white md:text-3xl">From feeds to governed AI assistance</h1>
                <p className="mt-3 text-sm leading-6 text-gray-300">
                  This dashboard explains and measures how AdversaryGraph collects IOC and CVE intelligence,
                  normalizes and tags it, builds cross-source relationships, reconciles the RAG corpus, exposes
                  bounded MCP tools, and produces citation-bound AI suggestions for human review.
                </p>
              </div>
              <div className="flex gap-2">
                <Link className="secondary-action" to="/observability">Runtime architecture</Link>
                <Link className="secondary-action" to="/feeds">Manage feeds</Link>
              </div>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              <Metric label="IOC records" value={format(snapshot?.streams.ioc.records)} detail={`${format(snapshot?.streams.ioc.enabled)} enabled feeds`} />
              <Metric label="CVE records" value={format(snapshot?.streams.cve.records)} detail={`${format(snapshot?.streams.cve.known_exploited)} known exploited`} />
              <Metric label="RAG documents" value={format(snapshot?.data_logic.rag.documents)} detail={`${format(snapshot?.data_logic.rag.chunks)} chunks`} />
              <Metric label="Cross-links" value={format(totalCorrelations(snapshot))} detail="IOC, CVE, actor, ATT&CK" />
              <Metric label="AI providers" value={format(snapshot?.data_logic.ai.configured_count)} detail="configured endpoints / credentials" />
            </div>
          </section>

          {query.isError && (
            <div className="rounded border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-200">
              Data-logic telemetry is unavailable. {query.error instanceof Error ? query.error.message : ''}
            </div>
          )}

          <Pipeline snapshot={snapshot} />

          <section className="grid gap-5 xl:grid-cols-2">
            <Panel title="IOC and CVE enrichment coverage" subtitle="Measured from normalized database fields—not inferred from feed names.">
              <div className="space-y-4">
                <Coverage label="IOCs with normalized tags" value={snapshot?.data_logic.coverage.ioc_tagged ?? null} total={snapshot?.streams.ioc.records ?? null} />
                <Coverage label="IOCs mapped to ATT&CK techniques" value={snapshot?.data_logic.coverage.ioc_ttp_tagged ?? null} total={snapshot?.streams.ioc.records ?? null} />
                <Coverage label="CVEs with normalized tags" value={snapshot?.data_logic.coverage.cve_tagged ?? null} total={snapshot?.streams.cve.records ?? null} />
                <Coverage label="CVEs with CWE weakness classes" value={snapshot?.data_logic.coverage.cve_cwe ?? null} total={snapshot?.streams.cve.records ?? null} />
                <Coverage label="CVEs with CPE product matches" value={snapshot?.data_logic.coverage.cve_cpe ?? null} total={snapshot?.streams.cve.records ?? null} />
              </div>
              <div className="mt-5 grid gap-2 sm:grid-cols-2">
                {snapshot?.correlations.map(item => (
                  <div key={item.id} className="rounded-lg border border-gray-800 bg-black/20 p-3">
                    <div className="text-lg font-semibold text-white">{format(item.count)}</div>
                    <div className="text-xs text-gray-400">{item.label}</div>
                    <div className="mt-1 text-[10px] uppercase tracking-wide text-cyan-400">{item.status}</div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="RAG corpus state" subtitle="Only active, sanitized, policy-visible documents are eligible for retrieval.">
              <div className="grid gap-3 sm:grid-cols-3">
                <SmallMetric label="Documents" value={format(snapshot?.data_logic.rag.documents)} />
                <SmallMetric label="Chunks" value={format(snapshot?.data_logic.rag.chunks)} />
                <SmallMetric label="AI assistance records" value={format(snapshot?.data_logic.rag.assistance_records)} />
              </div>
              <div className="mt-4 max-h-64 overflow-y-auto rounded-lg border border-gray-800">
                {(snapshot?.data_logic.rag.source_types ?? []).map(source => (
                  <div key={source.source_type} className="flex items-center justify-between border-b border-gray-800 px-3 py-2 last:border-0">
                    <span className="font-mono text-xs text-cyan-200">{source.source_type}</span>
                    <span className="text-sm font-semibold text-white">{format(source.documents)}</span>
                  </div>
                ))}
              </div>
              <LatestRun run={snapshot?.data_logic.rag.latest_run ?? null} />
            </Panel>
          </section>

          <section className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
            <Panel title="MCP trust boundary" subtitle="The MCP server is a governed API facade, not direct database or shell access.">
              <div className="grid gap-3 sm:grid-cols-2">
                <SmallMetric label="Transport" value={snapshot?.data_logic.mcp.transport ?? '—'} />
                <SmallMetric label="Tools" value={format(snapshot?.data_logic.mcp.tool_count)} />
              </div>
              <ol className="mt-4 space-y-2 text-sm text-gray-300">
                {(snapshot?.data_logic.mcp.api_operations ?? []).map((operation, index) => (
                  <li key={operation} className="flex gap-3 rounded border border-gray-800 bg-black/20 p-3">
                    <span className="font-mono text-cyan-300">0{index + 1}</span><span>{operation}</span>
                  </li>
                ))}
              </ol>
              <p className="mt-4 rounded border border-emerald-500/25 bg-emerald-950/20 p-3 text-xs leading-5 text-emerald-100">
                Advisory only · allowlisted endpoints · bounded inputs and responses · no database credentials · API authorization, TLP, tenant, citation, and audit policy remain authoritative.
              </p>
            </Panel>

            <Panel title="AI assistant provider and grounding flow" subtitle="Configured does not mean every request is permitted; provider policy is evaluated per operation.">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(snapshot?.data_logic.ai.providers ?? []).map(provider => (
                  <div key={provider.id} className={`rounded-lg border p-3 ${provider.configured ? 'border-emerald-500/30 bg-emerald-950/15' : 'border-gray-800 bg-black/20'}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-semibold text-white">{provider.label}</span>
                      <span className={provider.configured ? 'text-emerald-300' : 'text-gray-600'}>●</span>
                    </div>
                    <div className="mt-1 truncate font-mono text-[11px] text-gray-400" title={provider.model}>{provider.model}</div>
                    <div className="mt-2 text-[10px] uppercase tracking-wide text-gray-500">{provider.status.replace(/_/g, ' ')}</div>
                  </div>
                ))}
              </div>
              <div className="mt-4 grid gap-2 md:grid-cols-5">
                {['Scope request', 'Retrieve governed evidence', 'Build cited context', 'Validate structured output', 'Human accepts or rejects'].map((step, index) => (
                  <div key={step} className="relative rounded border border-fuchsia-500/25 bg-fuchsia-950/15 p-3 text-xs text-gray-200">
                    <span className="block font-mono text-fuchsia-300">AI-{index + 1}</span>
                    <span className="mt-1 block">{step}</span>
                  </div>
                ))}
              </div>
            </Panel>
          </section>

          <Panel title="Evidence and safety boundaries" subtitle="Operational transparency prevents architecture diagrams from becoming unsupported security claims.">
            <div className="grid gap-3 md:grid-cols-2">
              {(snapshot?.data_logic.boundaries ?? []).map(boundary => (
                <div key={boundary} className="rounded-lg border border-amber-500/25 bg-amber-950/15 p-3 text-sm leading-6 text-amber-100">
                  {boundary}
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-gray-500">
              Snapshot generated {snapshot ? new Date(snapshot.generated_at).toLocaleString() : 'while loading'}.
              Live values refresh every 30 seconds.
            </p>
          </Panel>
        </div>
      </div>
    </>
  );
}

function Pipeline({ snapshot }: { snapshot?: PlatformArchitectureSnapshot }) {
  return (
    <Panel title="End-to-end data path" subtitle="Each arrow represents a controlled transformation; raw inputs never become AI evidence merely because they were ingested.">
      <div className="overflow-x-auto pb-2">
        <div className="grid min-w-[1180px] grid-cols-8 gap-2">
          {(snapshot?.data_logic.stages ?? []).map((stage, index) => (
            <div key={stage.id} className="relative rounded-lg border border-cyan-500/25 bg-cyan-950/15 p-3">
              <div className="font-mono text-[10px] uppercase tracking-wider text-cyan-400">{String(index + 1).padStart(2, '0')}</div>
              <h3 className="mt-1 text-sm font-semibold text-white">{stage.label}</h3>
              <p className="mt-2 text-[11px] leading-5 text-gray-400">{stage.detail}</p>
              {index < 7 && <span className="absolute -right-2.5 top-1/2 z-10 text-cyan-500">→</span>}
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}

function Coverage({ label, value, total }: { label: string; value: number | null; total: number | null }) {
  const ratio = percent(value, total);
  return (
    <div>
      <div className="mb-1 flex items-end justify-between gap-3 text-xs">
        <span className="text-gray-300">{label}</span>
        <span className="font-mono text-gray-400">{format(value)} / {format(total)}{ratio == null ? '' : ` · ${ratio}%`}</span>
      </div>
      <div className="h-2 overflow-hidden rounded bg-gray-900">
        <div className="h-full rounded bg-gradient-to-r from-cyan-500 to-fuchsia-500" style={{ width: `${ratio ?? 0}%` }} />
      </div>
    </div>
  );
}

function LatestRun({ run }: { run: PlatformArchitectureSnapshot['data_logic']['rag']['latest_run'] }) {
  if (!run) return <p className="mt-4 text-xs text-gray-500">No RAG reconciliation run is recorded.</p>;
  return (
    <div className="mt-4 rounded-lg border border-gray-800 bg-black/20 p-3 text-xs">
      <div className="flex items-center justify-between">
        <span className="font-semibold text-white">Latest reconciliation</span>
        <span className={run.status === 'completed' ? 'text-emerald-300' : run.status === 'failed' ? 'text-red-300' : 'text-amber-300'}>{run.status}</span>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2 text-gray-400 sm:grid-cols-4">
        <span>Seen {format(run.documents_seen)}</span><span>Created {format(run.documents_created)}</span>
        <span>Updated {format(run.documents_updated)}</span><span>Chunks {format(run.chunks_created)}</span>
      </div>
    </div>
  );
}

function totalCorrelations(snapshot?: PlatformArchitectureSnapshot) {
  return snapshot?.correlations.reduce((sum, item) => sum + (item.count ?? 0), 0) ?? null;
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="rounded-lg border border-white/10 bg-black/25 p-3"><div className="text-2xl font-bold text-white">{value}</div><div className="mt-1 text-xs font-semibold uppercase tracking-wide text-cyan-300">{label}</div><div className="mt-1 text-[11px] text-gray-500">{detail}</div></div>;
}

function SmallMetric({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg border border-gray-800 bg-black/20 p-3"><div className="text-lg font-semibold text-white">{value}</div><div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div></div>;
}

function Panel({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return <section className="rounded-xl border border-gray-800 bg-gray-950/55 p-4"><h2 className="text-lg font-semibold text-white">{title}</h2><p className="mt-1 text-xs leading-5 text-gray-500">{subtitle}</p><div className="mt-4">{children}</div></section>;
}
