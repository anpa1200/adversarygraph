import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { emb3dApi } from '@/api/client';
import type { Emb3dAssetReportItem, Emb3dThreat } from '@/api/client';

export function Emb3d() {
  const [selectedAssetId, setSelectedAssetId] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const reportQuery = useQuery({
    queryKey: ['emb3d-asset-report'],
    queryFn: () => emb3dApi.report({ limit: 300 }),
  });
  const catalogQuery = useQuery({
    queryKey: ['emb3d-catalog'],
    queryFn: emb3dApi.catalog,
  });

  const assets = useMemo(() => reportQuery.data?.assets ?? [], [reportQuery.data?.assets]);
  const selectedAsset = useMemo(() => {
    if (!assets.length) return null;
    return assets.find(asset => asset.asset_id === selectedAssetId) ?? assets[0];
  }, [assets, selectedAssetId]);
  const visibleThreats = useMemo(() => {
    const threats = selectedAsset?.threats ?? [];
    if (categoryFilter === 'all') return threats;
    return threats.filter(threat => threat.category === categoryFilter);
  }, [categoryFilter, selectedAsset?.threats]);

  const loading = reportQuery.isLoading || catalogQuery.isLoading;
  const error = reportQuery.error || catalogQuery.error;

  return (
    <div className="flex h-full flex-col">
      <Header title="EMB3D" />
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="border-b border-gray-800 px-6 py-5">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-gray-500">Embedded Device Threat Modeling</p>
              <h1 className="mt-1 text-2xl font-semibold text-white">MITRE EMB3D Asset Assessment</h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-400">
                Saved asset-registry entries are mapped to EMB3D properties, threats, and mitigations using the MITRE STIX bundle.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <a
                href="https://emb3d.mitre.org/"
                target="_blank"
                rel="noreferrer"
                className="secondary-action"
              >
                MITRE EMB3D
              </a>
              <button type="button" onClick={() => reportQuery.refetch()} className="primary-action">
                Refresh
              </button>
            </div>
          </div>
        </div>

        {loading && <div className="p-6 text-sm text-gray-400">Loading EMB3D catalog and asset report...</div>}
        {error && <div className="m-6 rounded border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-200">{error instanceof Error ? error.message : 'EMB3D assessment failed'}</div>}

        {!loading && !error && (
          <div className="grid min-h-0 grid-cols-1 xl:grid-cols-[360px_minmax(0,1fr)]">
            <aside className="border-r border-gray-800 p-4">
              <div className="grid grid-cols-2 gap-3">
                <Metric label="Assets" value={reportQuery.data?.asset_count ?? 0} />
                <Metric label="Threats" value={reportQuery.data?.threat_count ?? 0} />
                <Metric label="Properties" value={reportQuery.data?.property_count ?? 0} />
                <Metric label="Mitigations" value={reportQuery.data?.mitigation_count ?? 0} />
              </div>

              <section className="mt-5">
                <div className="mb-2 flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-white">Assets</h2>
                  <span className="text-xs text-gray-500">v{reportQuery.data?.version ?? catalogQuery.data?.version}</span>
                </div>
                <div className="space-y-2">
                  {assets.map(asset => (
                    <button
                      key={asset.asset_id}
                      type="button"
                      onClick={() => setSelectedAssetId(asset.asset_id)}
                      className={`w-full rounded border px-3 py-2 text-left text-xs ${
                        selectedAsset?.asset_id === asset.asset_id
                          ? 'border-mitre-accent bg-mitre-accent/15 text-white'
                          : 'border-gray-800 bg-gray-950/60 text-gray-400 hover:border-gray-700 hover:text-gray-200'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-semibold">{asset.name}</span>
                        <span className="shrink-0 rounded bg-black/30 px-2 py-0.5 font-mono">{asset.threat_count}</span>
                      </div>
                      <div className="mt-1 truncate text-[11px] text-gray-500">{asset.asset_type} · {asset.exposure} · {asset.criticality}</div>
                    </button>
                  ))}
                  {!assets.length && (
                    <div className="rounded border border-gray-800 bg-gray-950/60 p-3 text-xs leading-5 text-gray-500">
                      No saved assets yet. Upload an inventory in Asset Surface, then return here.
                    </div>
                  )}
                </div>
              </section>
            </aside>

            <main className="min-w-0 p-6">
              {!selectedAsset ? (
                <div className="rounded border border-gray-800 bg-gray-950/60 p-6 text-sm text-gray-400">No EMB3D asset assessment available.</div>
              ) : (
                <AssetDetail
                  asset={selectedAsset}
                  visibleThreats={visibleThreats}
                  categoryFilter={categoryFilter}
                  setCategoryFilter={setCategoryFilter}
                  categories={Object.keys(reportQuery.data?.category_counts ?? {})}
                />
              )}

              <div className="mt-6 grid grid-cols-1 gap-4 xl:grid-cols-3">
                <RankedList title="Top Threats" rows={(reportQuery.data?.top_threats ?? []).map(item => ({
                  id: item.id,
                  name: item.name,
                  count: item.affected_assets,
                  meta: item.category,
                }))} />
                <RankedList title="Top Properties" rows={(reportQuery.data?.top_properties ?? []).map(item => ({
                  id: item.id,
                  name: item.name,
                  count: item.matched_assets,
                  meta: item.category,
                }))} />
                <RankedList title="Top Mitigations" rows={(reportQuery.data?.top_mitigations ?? []).map(item => ({
                  id: item.id,
                  name: item.name,
                  count: item.recommended_for_threats,
                  meta: item.maturity,
                }))} />
              </div>
            </main>
          </div>
        )}
      </div>
    </div>
  );
}

function AssetDetail({
  asset,
  visibleThreats,
  categoryFilter,
  setCategoryFilter,
  categories,
}: {
  asset: Emb3dAssetReportItem;
  visibleThreats: Emb3dThreat[];
  categoryFilter: string;
  setCategoryFilter: (value: string) => void;
  categories: string[];
}) {
  return (
    <div className="space-y-5">
      <section className="rounded border border-gray-800 bg-gray-950/60 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-white">{asset.name}</h2>
            <p className="mt-1 text-sm text-gray-500">{asset.inventory_asset_id} · {asset.asset_type} · {asset.environment}</p>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge>{asset.exposure}</Badge>
            <Badge>{asset.criticality}</Badge>
            <Badge>{asset.risk_level}</Badge>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Metric label="Properties" value={asset.properties.length} />
          <Metric label="Threats" value={asset.threat_count} />
          <Metric label="Mitigations" value={asset.mitigation_count} />
          <Metric label="Risk" value={asset.risk_score} />
        </div>
      </section>

      <section className="rounded border border-gray-800 bg-gray-950/60 p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-white">Mapped Properties</h3>
          <select className="field w-56" value={categoryFilter} onChange={event => setCategoryFilter(event.target.value)}>
            <option value="all">All threat categories</option>
            {categories.map(category => <option key={category} value={category}>{category}</option>)}
          </select>
        </div>
        <div className="grid grid-cols-1 gap-2 lg:grid-cols-2">
          {asset.properties.map(property => (
            <div key={property.id} className="rounded border border-gray-800 bg-black/20 p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-mitre-accent">{property.id}</span>
                <span className="text-xs text-gray-500">{property.confidence}%</span>
              </div>
              <p className="mt-1 text-sm font-medium text-gray-200">{property.name}</p>
              <p className="mt-1 text-xs text-gray-500">{property.category} · {property.threat_count} threats</p>
              <ul className="mt-2 space-y-1 text-xs text-gray-500">
                {property.evidence.map(item => <li key={item}>{item}</li>)}
              </ul>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded border border-gray-800 bg-gray-950/60 p-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white">Applicable Threats</h3>
          <span className="text-xs text-gray-500">{visibleThreats.length} shown</span>
        </div>
        <div className="space-y-3">
          {visibleThreats.map(threat => (
            <details key={threat.id} className="rounded border border-gray-800 bg-black/20 p-3">
              <summary className="cursor-pointer list-none">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-mono text-xs text-mitre-accent">{threat.id}</div>
                    <div className="mt-1 text-sm font-semibold text-white">{threat.name}</div>
                    <div className="mt-1 text-xs text-gray-500">{threat.category} · {threat.maturity || 'maturity unknown'}</div>
                  </div>
                  <span className="rounded bg-gray-900 px-2 py-1 text-xs text-gray-400">{threat.mitigations.length} mitigations</span>
                </div>
              </summary>
              <p className="mt-3 text-sm leading-6 text-gray-400">{threat.description}</p>
              <div className="mt-3 flex flex-wrap gap-1">
                {threat.cwes.map(cwe => <Badge key={cwe}>{cwe}</Badge>)}
                {threat.properties.map(property => <Badge key={property.id}>{property.id}</Badge>)}
              </div>
              <div className="mt-3 space-y-2">
                {threat.mitigations.slice(0, 6).map(mitigation => (
                  <div key={mitigation.id} className="rounded border border-gray-800 bg-gray-950 p-2">
                    <div className="text-xs font-semibold text-gray-200">{mitigation.id} · {mitigation.name}</div>
                    <div className="mt-1 text-xs uppercase tracking-wide text-gray-600">{mitigation.maturity}</div>
                  </div>
                ))}
              </div>
            </details>
          ))}
        </div>
      </section>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-800 bg-black/20 p-3">
      <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-white">{value}</div>
    </div>
  );
}

function Badge({ children }: { children: string | number }) {
  return <span className="rounded border border-gray-700 bg-gray-900 px-2 py-0.5 text-xs text-gray-400">{children}</span>;
}

function RankedList({ title, rows }: { title: string; rows: Array<{ id: string; name: string; count: number; meta: string }> }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-950/60 p-4">
      <h3 className="mb-3 text-sm font-semibold text-white">{title}</h3>
      <div className="space-y-2">
        {rows.slice(0, 8).map(row => (
          <div key={row.id} className="flex items-start justify-between gap-3 rounded border border-gray-800 bg-black/20 p-2 text-xs">
            <div className="min-w-0">
              <div className="font-mono text-mitre-accent">{row.id}</div>
              <div className="mt-1 truncate text-gray-300">{row.name}</div>
              <div className="mt-1 truncate text-gray-600">{row.meta}</div>
            </div>
            <span className="shrink-0 rounded bg-gray-900 px-2 py-1 text-gray-400">{row.count}</span>
          </div>
        ))}
        {!rows.length && <div className="text-xs text-gray-500">No rows yet.</div>}
      </div>
    </section>
  );
}
