import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { iocApi, type IOCDetail as IOCDetailType } from '@/api/client';
import { useAppStore } from '@/store';

export function IOCDetail() {
  const navigate = useNavigate();
  const { id = '' } = useParams();
  const { domain, addTechniques, replaceTechniques } = useAppStore();
  const numericId = Number(id);
  const detail = useQuery({
    queryKey: ['ioc-detail', numericId, domain],
    queryFn: () => iocApi.detail(numericId, domain),
    enabled: Number.isFinite(numericId) && numericId > 0,
  });
  const item = detail.data;
  const techniqueIds = useMemo(() => item?.techniques.map(technique => technique.attack_id) ?? [], [item]);

  const showOnMatrix = () => {
    replaceTechniques(techniqueIds);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="IOC Enrichment Detail" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          {detail.isLoading && <Panel title="Loading">Loading IOC detail...</Panel>}
          {detail.error && <Panel title="Error"><ErrorBox error={detail.error} /></Panel>}
          {item && (
            <>
              <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="mb-2 flex flex-wrap items-center gap-2">
                      <span className="rounded bg-gray-800 px-2 py-1 font-mono text-[10px] text-gray-300">{item.type}</span>
                      <span className="rounded bg-gray-800 px-2 py-1 text-[10px] uppercase text-gray-400">{item.tlp}</span>
                      <span className="rounded bg-gray-800 px-2 py-1 text-[10px] text-gray-400">confidence {item.confidence}</span>
                    </div>
                    <h2 className="break-all font-mono text-xl font-semibold text-white">{item.value}</h2>
                    {item.description && <p className="mt-3 max-w-4xl text-sm leading-relaxed text-gray-400">{item.description}</p>}
                    <div className="mt-3 flex flex-wrap gap-2">
                      <ClickableValue value={item.value} label="Lookup" />
                      {item.source_url && <ClickableValue value={item.source_url} label="Source report" />}
                      <button onClick={() => navigate('/ioc-library')} className="secondary-action">Back to IOC Library</button>
                    </div>
                  </div>
                  <div className="grid min-w-[240px] gap-2 text-xs text-gray-400">
                    <Metric label="Source" value={item.source_details.label || item.source} />
                    <Metric label="First seen" value={item.first_seen || '-'} />
                    <Metric label="Last seen" value={item.last_seen || '-'} />
                    <Metric label="Updated" value={item.updated_at || '-'} />
                  </div>
                </div>
              </section>

              <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
                <Panel title={`Mapped ATT&CK TTPs (${item.techniques.length})`}>
                  {item.techniques.length > 0 ? (
                    <div className="space-y-3">
                      <div className="flex flex-wrap gap-2">
                        <button onClick={() => addTechniques(techniqueIds)} className="primary-action">Add to My TTPs</button>
                        <button onClick={showOnMatrix} className="secondary-action">Show on matrix</button>
                      </div>
                      {item.techniques.map(technique => (
                        <TechniqueCard key={technique.attack_id} technique={technique} />
                      ))}
                    </div>
                  ) : (
                    <Empty text="No TTP mappings are stored for this IOC yet." />
                  )}
                </Panel>

                <Panel title={`Actors / Groups (${item.actors.length})`}>
                  {item.actors.length > 0 ? (
                    <div className="space-y-2">
                      {item.actors.map(actor => (
                        <button
                          key={`${actor.actor_attack_id}-${actor.actor_name}-${actor.source}`}
                          onClick={() => navigate(`/apt?group=${actor.actor_attack_id}&tab=iocs`)}
                          className="w-full rounded border border-gray-800 bg-gray-950/50 p-3 text-left hover:border-mitre-accent/60"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-semibold text-white">{actor.actor_name || actor.actor_attack_id}</span>
                            <span className="font-mono text-[10px] text-mitre-accent">{actor.actor_attack_id}</span>
                          </div>
                          <div className="mt-1 text-[10px] text-gray-500">{actor.relationship} · confidence {actor.confidence} · {actor.source}</div>
                          {actor.evidence && <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-gray-400">{actor.evidence}</p>}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <Empty text="No actor link is stored for this IOC." />
                  )}
                </Panel>
              </section>

              <Panel title={`Enrichment Sources (${item.enrichments.length})`}>
                <div className="grid gap-4 lg:grid-cols-2">
                  {item.enrichments.map((section, index) => (
                    <EnrichmentSection key={`${section.source}-${section.label}-${index}`} section={section} />
                  ))}
                </div>
              </Panel>

              <Panel title="Raw Source / Enrichment JSON">
                <pre className="max-h-[480px] overflow-auto rounded bg-gray-950 p-4 text-xs leading-relaxed text-gray-300">
                  {JSON.stringify(item.raw, null, 2)}
                </pre>
              </Panel>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function TechniqueCard({ technique }: { technique: IOCDetailType['techniques'][number] }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <a href={`/navigator?technique=${technique.attack_id}`} className="font-mono text-sm text-mitre-accent hover:underline">{technique.attack_id}</a>
        <span className="text-sm font-semibold text-white">{technique.name || 'Technique'}</span>
        {technique.url && <a href={technique.url} target="_blank" rel="noreferrer" className="text-[10px] text-blue-400 hover:underline">ATT&CK ↗</a>}
      </div>
      {technique.tactics.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {technique.tactics.map(tactic => <Chip key={tactic}>{tactic}</Chip>)}
        </div>
      )}
      {technique.evidence.length > 0 && (
        <div className="mt-3 space-y-2">
          {technique.evidence.map((row, index) => (
            <div key={index} className="rounded bg-gray-900 p-2 text-xs text-gray-400">
              <div className="mb-1 font-mono text-[10px] text-gray-500">{row.priority || 'evidence'} · {row.source || 'source'}</div>
              <p>{row.evidence || 'No evidence text stored.'}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function EnrichmentSection({ section }: { section: IOCDetailType['enrichments'][number] }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-white">{section.label}</h3>
          <p className="font-mono text-[10px] text-gray-500">{section.source} · {section.kind}{section.status ? ` · ${section.status}` : ''}</p>
        </div>
        {section.url && <ClickableValue value={section.url} label="Open source" />}
      </div>
      <div className="space-y-1">
        {section.values.length ? section.values.map((row, index) => (
          <div key={`${row.key}-${index}`} className="grid gap-2 rounded border border-gray-900 bg-gray-900/60 p-2 text-xs md:grid-cols-[180px_minmax(0,1fr)]">
            <div className="break-all font-mono text-[10px] text-gray-500">{row.key}</div>
            <ClickableValue value={row.value} />
          </div>
        )) : <Empty text="No scalar enrichment values were stored for this source." />}
      </div>
    </div>
  );
}

function ClickableValue({ value, label }: { value: string; label?: string }) {
  const trimmed = String(value || '').trim();
  if (!trimmed) return <span className="text-gray-600">-</span>;
  if (/^https?:\/\//i.test(trimmed)) {
    return <a href={trimmed} target="_blank" rel="noreferrer" className="break-all text-blue-400 hover:underline">{label || trimmed}</a>;
  }
  if (/^T\d{4}(?:\.\d{3})?$/i.test(trimmed)) {
    return <a href={`/navigator?technique=${trimmed.toUpperCase()}`} className="break-all font-mono text-mitre-accent hover:underline">{label || trimmed.toUpperCase()}</a>;
  }
  if (/^G\d{4}$/i.test(trimmed)) {
    return <a href={`/apt?group=${trimmed.toUpperCase()}`} className="break-all font-mono text-mitre-accent hover:underline">{label || trimmed.toUpperCase()}</a>;
  }
  if (trimmed.includes(', ')) {
    return (
      <span className="flex flex-wrap gap-1">
        {trimmed.split(', ').filter(Boolean).slice(0, 40).map(part => <ClickableValue key={part} value={part} />)}
      </span>
    );
  }
  return <a href={`/ioc-library?search=${encodeURIComponent(trimmed)}`} className="break-all text-gray-300 hover:text-mitre-accent hover:underline">{label || trimmed}</a>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
      <div className="text-[10px] uppercase text-gray-600">{label}</div>
      <div className="mt-1 break-all text-gray-300">{value}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Chip({ children }: { children: ReactNode }) {
  return <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{children}</span>;
}

function Empty({ text }: { text: string }) {
  return <p className="text-sm text-gray-600">{text}</p>;
}

function ErrorBox({ error }: { error: unknown }) {
  return (
    <div className="rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}
