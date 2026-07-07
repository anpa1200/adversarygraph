import { useMemo } from 'react';
import type React from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { threatRadarApi, type ThreatSpaceAsset } from '@/api/client';

type AlertRow = Record<string, unknown> & {
  id?: string;
  title?: string;
  description?: string;
  priority?: string;
  severity?: string;
  status?: string;
  score?: number;
  signal_id?: string;
  asset_id?: string;
  asset_uuid?: string;
  asset_name?: string;
  match_type?: string;
  matched_terms?: unknown[];
  matches?: unknown[];
  last_seen?: string;
};

export function ThreatRadarAssets() {
  const [params, setParams] = useSearchParams();
  const selectedSpaceId = params.get('space_id') || '';
  const selectedAssetId = params.get('asset_id') || '';
  const spaces = useQuery({ queryKey: ['threat-radar-spaces'], queryFn: threatRadarApi.spaces });
  const firstSpaceId = selectedSpaceId || spaces.data?.[0]?.id || '';
  const detail = useQuery({
    queryKey: ['threat-radar-space', firstSpaceId],
    queryFn: () => threatRadarApi.spaceDetail(firstSpaceId),
    enabled: Boolean(firstSpaceId),
  });
  const alerts = useQuery({
    queryKey: ['threat-radar-space-asset-alerts', firstSpaceId],
    queryFn: () => threatRadarApi.alerts(firstSpaceId, { limit: 500 }),
    enabled: Boolean(firstSpaceId),
  });
  const assets = useMemo(() => sortAssets(detail.data?.assets ?? []), [detail.data?.assets]);
  const selectedAsset = assets.find(asset => asset.id === selectedAssetId) ?? assets[0] ?? null;
  const selectedAssetContext = useMemo(
    () => selectedAsset ? buildAssetContext(selectedAsset, (alerts.data ?? []) as AlertRow[]) : emptyAssetContext(),
    [alerts.data, selectedAsset],
  );

  const setSpace = (spaceId: string) => {
    const next = new URLSearchParams(params);
    next.set('space_id', spaceId);
    next.delete('asset_id');
    setParams(next);
  };
  const setAsset = (assetId: string) => {
    const next = new URLSearchParams(params);
    next.set('space_id', firstSpaceId);
    next.set('asset_id', assetId);
    setParams(next);
  };

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Threat Radar Asset Inventory" />
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">Parsed company asset inventory</h2>
                <p className="mt-2 max-w-4xl text-sm leading-6 text-sky-100/80">
                  This page presents the normalized inventory stored in the selected Threat Radar company space.
                  Assets are parsed into strict fields so CVE, actor, IOC, sector, supply-chain, and product-security signals can be matched.
                </p>
              </div>
              <a className="secondary-action inline-flex min-h-10 items-center px-4" href="/threat-radar">Back to Threat Radar</a>
            </div>
          </section>

          <section className="grid gap-4 lg:grid-cols-[minmax(360px,520px)_minmax(0,1fr)]">
            <div className="space-y-4">
              <Panel title="Company Space">
                <div className="space-y-3 p-4">
                  <label className="block text-xs text-gray-400">
                    Space
                    <select className="field mt-1 w-full" value={firstSpaceId} onChange={event => setSpace(event.target.value)}>
                      <option value="">Select space</option>
                      {(spaces.data ?? []).map(space => <option key={space.id} value={space.id}>{space.name}</option>)}
                    </select>
                  </label>
                  {detail.data?.space && (
                    <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-400">
                      <b className="text-white">{detail.data.space.name}</b>
                      <p>{detail.data.space.description || 'No description recorded.'}</p>
                      <p className="mt-2">{detail.data.space.owner || 'No owner'} · {detail.data.space.sector || 'no sector'} · {detail.data.space.region || 'no region'}</p>
                    </div>
                  )}
                  <a className="secondary-action flex min-h-9 items-center justify-center text-xs" href={`/asset-surface?space_id=${encodeURIComponent(firstSpaceId)}`}>
                    Upload more inventory files
                  </a>
                </div>
              </Panel>

              <Panel title="Parsed Assets">
                <div className="border-b border-gray-800 px-4 py-3 text-xs text-gray-500">
                  {assets.length} uploaded and parsed assets. Select one to open its asset intelligence page.
                </div>
                <div className="max-h-[720px] overflow-auto">
                  <table className="w-full min-w-[760px] text-left text-sm">
                    <thead className="sticky top-0 z-10 bg-gray-950 text-xs uppercase text-gray-500">
                      <tr><th className="p-3">Asset</th><th>Exposure</th><th>Products</th><th>Technologies</th><th>Alerts</th></tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {assets.map(asset => {
                        const context = buildAssetContext(asset, (alerts.data ?? []) as AlertRow[]);
                        return (
                          <tr key={asset.id} className={`align-top hover:bg-gray-900/60 ${selectedAsset?.id === asset.id ? 'bg-mitre-accent/10' : ''}`}>
                            <td className="p-3">
                              <button onClick={() => setAsset(asset.id)} className="text-left font-semibold text-mitre-accent hover:underline">
                                {asset.name}
                              </button>
                              <p className="mt-1 text-xs text-gray-500">{asset.asset_id} · {asset.asset_type} · {asset.environment}</p>
                            </td>
                            <td className="py-3 text-xs text-gray-400">{asset.exposure}<p className="text-gray-600">{asset.criticality}</p></td>
                            <td className="py-3"><TagList tags={asset.products.slice(0, 3)} /></td>
                            <td className="py-3"><TagList tags={asset.technologies.slice(0, 4)} /></td>
                            <td className="py-3 pr-3">
                              <span className={`rounded border px-2 py-1 text-xs ${context.alerts.length ? 'border-red-500/40 bg-red-950/30 text-red-100' : 'border-gray-700 bg-gray-950 text-gray-400'}`}>
                                {context.alerts.length}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {!assets.length && <p className="p-4 text-sm text-gray-500">No assets stored in this company space yet.</p>}
                </div>
              </Panel>
            </div>

            <div className="space-y-4">
              <section className="grid gap-3 md:grid-cols-4">
                <Metric label="Assets" value={assets.length} />
                <Metric label="Critical/high" value={assets.filter(asset => ['critical', 'high'].includes(asset.criticality)).length} />
                <Metric label="Internet/external" value={assets.filter(asset => ['internet', 'external', 'third-party'].includes(asset.exposure)).length} />
                <Metric label="Products" value={new Set(assets.flatMap(asset => asset.products)).size} />
              </section>

              {detail.isLoading && <Panel title="Loading"><p className="p-4 text-sm text-gray-500">Loading parsed inventory...</p></Panel>}
              {!detail.isLoading && selectedAsset && <AssetDetail asset={selectedAsset} context={selectedAssetContext} alertsLoading={alerts.isLoading} />}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function AssetDetail({ asset, context, alertsLoading }: { asset: ThreatSpaceAsset; context: ReturnType<typeof buildAssetContext>; alertsLoading: boolean }) {
  return (
    <Panel title={`Asset Intelligence: ${asset.name}`}>
      <div className="space-y-4 p-4 text-sm">
        <p className="leading-6 text-gray-300">{describeAsset(asset)}</p>
        <section className="grid gap-3 md:grid-cols-3">
          <Fact label="Inventory ID" value={asset.asset_id} />
          <Fact label="Owner" value={asset.owner || '-'} />
          <Fact label="Type" value={asset.asset_type || '-'} />
          <Fact label="Environment" value={asset.environment || '-'} />
          <Fact label="Exposure" value={asset.exposure || '-'} />
          <Fact label="Criticality" value={asset.criticality || '-'} />
        </section>
        <section className="grid gap-4 lg:grid-cols-2">
          <Info title="Products" tags={asset.products} />
          <Info title="Components" tags={asset.components} />
          <Info title="Technologies" tags={asset.technologies} />
          <Info title="Network Identity" tags={[...asset.domains, ...asset.ip_addresses]} />
        </section>
        <Info title="Labels / Tags" tags={asset.tags} />

        <section className="grid gap-3 md:grid-cols-4">
          <Metric label="Relevant alerts" value={context.alerts.length} />
          <Metric label="Relevant CVEs" value={context.cves.length} />
          <Metric label="Relevant TTPs" value={context.ttps.length} />
          <Metric label="Relevant IOCs" value={context.iocs.length} />
        </section>

        <section className="grid gap-4 xl:grid-cols-3">
          <LinkedInfo title="Relevant CVEs" values={context.cves} type="cve" empty="No CVE match yet." />
          <LinkedInfo title="Relevant TTPs" values={context.ttps} type="ttp" empty="No TTP match yet." />
          <LinkedInfo title="Relevant IOCs" values={context.iocs} type="ioc" empty="No IOC match yet." />
        </section>

        <Panel title="Matching Alerts">
          {alertsLoading && <p className="p-4 text-sm text-gray-500">Loading alert context...</p>}
          {!alertsLoading && !context.alerts.length && <p className="p-4 text-sm text-gray-500">No feed detections currently match this asset.</p>}
          {!alertsLoading && context.alerts.length > 0 && (
            <div className="max-h-[420px] overflow-y-auto">
              {context.alerts.map(alert => (
                <div key={String(alert.id)} className="border-b border-gray-800 p-3 last:border-b-0">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      {alert.signal_id ? (
                        <a className="font-semibold text-mitre-accent hover:underline" href={`/threat-radar?space_id=${encodeURIComponent(asset.space_id)}&signal_id=${encodeURIComponent(String(alert.signal_id))}`}>
                          {String(alert.title || 'Matched alert')}
                        </a>
                      ) : (
                        <b className="text-white">{String(alert.title || 'Matched alert')}</b>
                      )}
                      <p className="mt-1 text-xs leading-5 text-gray-500">{String(alert.description || '')}</p>
                    </div>
                    <span className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300">{String(alert.priority || alert.severity || 'priority unknown')}</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {collectEvidenceValues(alert).slice(0, 16).map(item => <EntityTag key={`${item.type}:${item.value}`} value={item.value} type={item.type} />)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <details className="rounded border border-gray-800 bg-gray-950 p-3">
          <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-400">Raw normalized metadata</summary>
          <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap text-xs text-gray-400">{JSON.stringify(asset.metadata, null, 2)}</pre>
        </details>
      </div>
    </Panel>
  );
}

function describeAsset(asset: ThreatSpaceAsset) {
  const products = asset.products.slice(0, 4).join(', ') || 'no mapped product';
  const components = asset.components.slice(0, 4).join(', ') || 'no mapped component';
  const technologies = asset.technologies.slice(0, 5).join(', ') || 'no mapped technology';
  const network = [...asset.domains, ...asset.ip_addresses].slice(0, 5).join(', ') || 'no endpoint recorded';
  return `${asset.name} is a ${asset.criticality || 'unknown'} ${asset.asset_type || 'asset'} owned by ${asset.owner || 'an unspecified owner'}. It runs in ${asset.environment || 'unknown'} with ${asset.exposure || 'unknown'} exposure. Product context: ${products}. Component context: ${components}. Technology context: ${technologies}. Network identity: ${network}.`;
}

function sortAssets(assets: ThreatSpaceAsset[]) {
  const criticality = new Map([['critical', 5], ['high', 4], ['medium', 3], ['low', 2], ['unknown', 1]]);
  const exposure = new Map([['internet', 5], ['external', 4], ['third-party', 4], ['customer', 3], ['internal', 2], ['unknown', 1]]);
  return [...assets].sort((a, b) => (
    (criticality.get(b.criticality) ?? 0) - (criticality.get(a.criticality) ?? 0)
    || (exposure.get(b.exposure) ?? 0) - (exposure.get(a.exposure) ?? 0)
    || a.name.localeCompare(b.name)
  ));
}

function emptyAssetContext() {
  return { alerts: [] as AlertRow[], cves: [] as string[], ttps: [] as string[], iocs: [] as string[] };
}

function buildAssetContext(asset: ThreatSpaceAsset, alerts: AlertRow[]) {
  const assetKeys = new Set([
    asset.id,
    asset.asset_id,
    asset.name,
    ...asset.products,
    ...asset.components,
    ...asset.technologies,
    ...asset.domains,
    ...asset.ip_addresses,
  ].map(item => String(item || '').toLowerCase()).filter(Boolean));

  const matchedAlerts = alerts.filter(alert => {
    if (String(alert.asset_uuid || '').toLowerCase() === asset.id.toLowerCase()) return true;
    if (String(alert.asset_id || '').toLowerCase() === asset.asset_id.toLowerCase()) return true;
    if (String(alert.asset_name || '').toLowerCase() === asset.name.toLowerCase()) return true;
    const matches = Array.isArray(alert.matches) ? alert.matches : [];
    return matches.some(match => {
      if (!match || typeof match !== 'object') return false;
      const record = match as Record<string, unknown>;
      return ['asset_id', 'asset_uuid', 'inventory_entity', 'signal_entity'].some(key => assetKeys.has(String(record[key] || '').toLowerCase()));
    });
  });

  const evidence = matchedAlerts.flatMap(collectEvidenceValues);
  return {
    alerts: matchedAlerts,
    cves: unique(evidence.filter(item => item.type === 'cve').map(item => item.value)),
    ttps: unique(evidence.filter(item => item.type === 'ttp').map(item => item.value)),
    iocs: unique(evidence.filter(item => item.type === 'ioc').map(item => item.value)),
  };
}

function collectEvidenceValues(row: AlertRow): Array<{ value: string; type: string }> {
  const out: Array<{ value: string; type: string }> = [];
  const add = (raw: unknown, fallback = 'tag') => {
    const value = String(raw || '').trim();
    if (!value || value === '-') return;
    const type = inferEntityType(value, fallback);
    if (!out.some(item => item.value.toLowerCase() === value.toLowerCase() && item.type === type)) out.push({ value, type });
  };
  (row.matched_terms || []).forEach(item => add(item));
  ['cve_ids', 'technique_ids', 'actors', 'iocs', 'tags'].forEach(key => {
    const value = row[key];
    if (Array.isArray(value)) {
      value.forEach(item => typeof item === 'object' && item ? add((item as Record<string, unknown>).value ?? (item as Record<string, unknown>).id ?? JSON.stringify(item)) : add(item));
    }
  });
  const matches = Array.isArray(row.matches) ? row.matches : [];
  matches.forEach(match => {
    if (!match || typeof match !== 'object') return;
    const record = match as Record<string, unknown>;
    add(record.signal_entity);
    add(record.inventory_entity, 'asset');
  });
  return out;
}

function inferEntityType(value: string, fallback: string) {
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return 'cve';
  if (/^T\d{4}(?:\.\d{3})?$/i.test(value)) return 'ttp';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes('@') || /^[a-f0-9]{32,}$/i.test(value)) return 'ioc';
  return fallback;
}

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/30"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function Metric({ label, value }: { label: string; value: number }) {
  return <div className="rounded border border-gray-800 bg-gray-950 px-3 py-2"><div className="text-xl font-semibold text-white">{value}</div><div className="text-[11px] text-gray-500">{label}</div></div>;
}

function Fact({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-gray-800 bg-gray-950 p-3"><div className="text-xs uppercase text-gray-500">{label}</div><div className="mt-1 break-words text-white">{value}</div></div>;
}

function Info({ title, tags }: { title: string; tags: string[] }) {
  return <section><h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3><TagList tags={tags} /></section>;
}

function LinkedInfo({ title, values, type, empty }: { title: string; values: string[]; type: string; empty: string }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-950 p-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      {values.length ? <div className="flex flex-wrap gap-1">{values.map(value => <EntityTag key={value} value={value} type={type} />)}</div> : <p className="text-xs text-gray-500">{empty}</p>}
    </section>
  );
}

function EntityTag({ value, type }: { value: string; type: string }) {
  const href = entityHref(value, type);
  const className = 'rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400 hover:border-mitre-accent hover:text-mitre-accent';
  return href ? <a className={className} href={href}>{value}</a> : <span className="rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400">{value}</span>;
}

function entityHref(value: string, type: string) {
  const encoded = encodeURIComponent(value);
  if (type === 'cve') return `/cve-library?search=${encoded}`;
  if (type === 'ttp') return `/navigator?technique=${encoded}`;
  if (type === 'ioc') return `/ioc-library?search=${encoded}`;
  return '';
}

function TagList({ tags }: { tags: string[] }) {
  if (!tags.length) return <p className="text-xs text-gray-500">No values recorded.</p>;
  return <div className="flex flex-wrap gap-1">{tags.map(tag => <span key={tag} className="rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400">{tag}</span>)}</div>;
}
