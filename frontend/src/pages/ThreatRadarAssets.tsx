import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import type React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import {
  threatRadarApi,
  type ThreatAssetIntelligence,
  type ThreatAssetScan,
  type ThreatHuntAIProviderId,
  type ThreatSpaceAsset,
} from '@/api/client';

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
  const route = useParams<{ spaceId?: string; assetId?: string }>();
  if (route.spaceId && route.assetId) {
    return <ThreatRadarAssetPage spaceId={route.spaceId} assetId={route.assetId} />;
  }
  return <ThreatRadarAssetRegistry />;
}

function ThreatRadarAssetRegistry() {
  const [params, setParams] = useSearchParams();
  const selectedSpaceId = params.get('space_id') || '';
  const selectedAssetId = params.get('asset_id') || '';
  const [search, setSearch] = useState('');
  const [criticalityFilter, setCriticalityFilter] = useState('');
  const [exposureFilter, setExposureFilter] = useState('');
  const deferredSearch = useDeferredValue(search);
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
  const assetList = useQuery({
    queryKey: ['threat-radar-space-assets', firstSpaceId, deferredSearch, criticalityFilter, exposureFilter],
    queryFn: () => threatRadarApi.spaceAssets(firstSpaceId, {
      q: deferredSearch,
      criticality: criticalityFilter,
      exposure: exposureFilter,
      limit: 500,
    }),
    enabled: Boolean(firstSpaceId),
  });
  const assets = useMemo(
    () => sortAssets(assetList.data?.items ?? detail.data?.assets ?? []),
    [assetList.data?.items, detail.data?.assets],
  );
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
                <div className="space-y-3 border-b border-gray-800 p-4">
                  <label className="block text-xs text-gray-400">
                    Search saved assets
                    <input
                      className="field mt-1 w-full"
                      type="search"
                      value={search}
                      onChange={event => setSearch(event.target.value)}
                      placeholder="Name, inventory ID, owner, IP, domain, product…"
                    />
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    <label className="text-xs text-gray-400">
                      Criticality
                      <select className="field mt-1 w-full" value={criticalityFilter} onChange={event => setCriticalityFilter(event.target.value)}>
                        <option value="">All</option>
                        {['critical', 'high', 'medium', 'low', 'unknown'].map(value => <option key={value} value={value}>{value}</option>)}
                      </select>
                    </label>
                    <label className="text-xs text-gray-400">
                      Exposure
                      <select className="field mt-1 w-full" value={exposureFilter} onChange={event => setExposureFilter(event.target.value)}>
                        <option value="">All</option>
                        {['internet', 'external', 'third-party', 'customer', 'internal', 'unknown'].map(value => <option key={value} value={value}>{value}</option>)}
                      </select>
                    </label>
                  </div>
                  <div className="flex items-center justify-between gap-3 text-xs text-gray-500">
                    <span>{assetList.data?.total ?? assets.length} saved assets · {assets.length} shown</span>
                    {(search || criticalityFilter || exposureFilter) && (
                      <button className="text-mitre-accent hover:underline" onClick={() => {
                        setSearch('');
                        setCriticalityFilter('');
                        setExposureFilter('');
                      }}>
                        Clear filters
                      </button>
                    )}
                  </div>
                </div>
                <div className="max-h-[720px] overflow-auto">
                  <div className="divide-y divide-gray-800">
                    {assets.map(asset => {
                      const context = buildAssetContext(asset, (alerts.data ?? []) as AlertRow[]);
                      return (
                        <Link
                          key={asset.id}
                          to={`/threat-radar/assets/${encodeURIComponent(asset.space_id)}/${encodeURIComponent(asset.id)}`}
                          className={`block p-4 transition hover:bg-gray-900/70 focus-visible:outline focus-visible:outline-2 focus-visible:outline-mitre-accent ${selectedAsset?.id === asset.id ? 'bg-mitre-accent/10' : ''}`}
                        >
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <h3 className="break-words font-semibold text-mitre-accent">{asset.name}</h3>
                              <p className="mt-1 break-all text-xs text-gray-500">{asset.asset_id}</p>
                            </div>
                            <span className={`shrink-0 rounded border px-2 py-1 text-[11px] ${context.alerts.length ? 'border-red-500/40 bg-red-950/30 text-red-100' : 'border-gray-700 text-gray-400'}`}>
                              {context.alerts.length} alerts
                            </span>
                          </div>
                          <div className="mt-3 flex flex-wrap gap-1 text-[11px]">
                            <span className={`rounded border px-2 py-1 ${riskTone(asset.criticality)}`}>{asset.criticality}</span>
                            <span className="rounded border border-gray-700 px-2 py-1 text-gray-400">{asset.exposure}</span>
                            <span className="rounded border border-gray-700 px-2 py-1 text-gray-400">{asset.asset_type}</span>
                            <span className="rounded border border-gray-700 px-2 py-1 text-gray-400">{asset.environment}</span>
                          </div>
                          <p className="mt-3 line-clamp-2 text-xs leading-5 text-gray-500">
                            {[...asset.products, ...asset.technologies, ...asset.domains, ...asset.ip_addresses].slice(0, 8).join(' · ') || 'No product or network identity recorded.'}
                          </p>
                        </Link>
                      );
                    })}
                  </div>
                  {assetList.isLoading && <p className="p-4 text-sm text-gray-500">Loading saved assets…</p>}
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

function ThreatRadarAssetPage({ spaceId, assetId }: { spaceId: string; assetId: string }) {
  const intelligence = useQuery({
    queryKey: ['threat-radar-asset-intelligence', spaceId, assetId],
    queryFn: () => threatRadarApi.assetIntelligence(spaceId, assetId),
  });
  const data = intelligence.data;

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Threat Radar Asset Intelligence" />
      <div className="flex-1 overflow-y-auto px-4 py-5 sm:px-6">
        <div className="mx-auto max-w-[1500px] space-y-5">
          <nav aria-label="Asset breadcrumbs" className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
            <Link className="hover:text-mitre-accent" to="/threat-radar">Threat Radar</Link>
            <span aria-hidden="true">/</span>
            <Link
              className="hover:text-mitre-accent"
              to={`/threat-radar/assets?space_id=${encodeURIComponent(spaceId)}`}
            >
              Assets
            </Link>
            {data?.asset.name && <><span aria-hidden="true">/</span><span className="text-gray-300">{data.asset.name}</span></>}
          </nav>

          {intelligence.isLoading && (
            <Panel title="Loading asset intelligence">
              <p className="p-5 text-sm text-gray-500">Correlating the saved asset with current CVE, IOC, ATT&CK, signal, and assessment evidence…</p>
            </Panel>
          )}
          {intelligence.isError && (
            <div role="alert" className="rounded border border-red-500/40 bg-red-950/30 p-4 text-sm text-red-100">
              {apiErrorMessage(intelligence.error)}
            </div>
          )}
          {data && <ServerAssetDetail intelligence={data} />}
        </div>
      </div>
    </div>
  );
}

function ServerAssetDetail({ intelligence }: { intelligence: ThreatAssetIntelligence }) {
  const { asset, summary } = intelligence;
  return (
    <>
      <section className="rounded-lg border border-gray-800 bg-gradient-to-br from-gray-900/80 to-gray-950 p-5">
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded border border-sky-500/30 bg-sky-950/30 px-2 py-1 text-[11px] uppercase tracking-wide text-sky-300">
                {asset.asset_type || 'asset'}
              </span>
              <span className={`rounded border px-2 py-1 text-[11px] uppercase tracking-wide ${riskTone(summary.risk_level)}`}>
                {summary.risk_level} · {summary.risk_score}/100
              </span>
              <span className="rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400">{asset.environment}</span>
              <span className="rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400">{asset.exposure}</span>
            </div>
            <h1 className="mt-3 break-words text-2xl font-semibold text-white sm:text-3xl">{asset.name}</h1>
            <p className="mt-2 font-mono text-xs text-gray-500">{asset.asset_id} · {asset.id}</p>
            <p className="mt-4 max-w-4xl text-sm leading-6 text-gray-300">{describeAsset(asset)}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <a className="secondary-action inline-flex min-h-10 items-center px-4" href={`/asset-surface?space_id=${encodeURIComponent(asset.space_id)}`}>
              Update inventory
            </a>
            <a className="secondary-action inline-flex min-h-10 items-center px-4" href="#active-assessment">
              Run assessment
            </a>
          </div>
        </div>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-7">
        <Metric label="Risk score" value={summary.risk_score} />
        <Metric label="CVEs" value={summary.cves} />
        <Metric label="Known exploited" value={summary.known_exploited_cves} />
        <Metric label="ATT&CK TTPs" value={summary.ttps} />
        <Metric label="Relevant IOCs" value={summary.iocs} />
        <Metric label="Alerts" value={summary.alerts} />
        <Metric label="Open services" value={summary.latest_open_services} />
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(340px,.65fr)]">
        <Panel title="Saved Asset Record">
          <div className="space-y-4 p-4">
            <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <Fact label="Owner" value={asset.owner || '-'} />
              <Fact label="Criticality" value={asset.criticality || '-'} />
              <Fact label="Exposure" value={asset.exposure || '-'} />
              <Fact label="Environment" value={asset.environment || '-'} />
              <Fact label="Created" value={formatDate(asset.created_at)} />
              <Fact label="Updated" value={formatDate(asset.updated_at)} />
            </section>
            <section className="grid gap-4 lg:grid-cols-2">
              <Info title="IP addresses" tags={asset.ip_addresses} />
              <Info title="Domains / URLs" tags={asset.domains} />
              <Info title="Products" tags={asset.products} />
              <Info title="Components" tags={asset.components} />
              <Info title="Technologies" tags={asset.technologies} />
              <Info title="Tags" tags={asset.tags} />
            </section>
          </div>
        </Panel>

        <Panel title="Evidence Boundary">
          <div className="space-y-3 p-4 text-xs leading-5 text-amber-100/80">
            <p className="rounded border border-amber-500/30 bg-amber-950/20 p-3">{intelligence.evidence_boundary}</p>
            <p className="text-gray-500">
              Generated {formatDate(intelligence.generated_at)}. Relationships remain analyst-review leads until supported by endpoint, network, scanner, vendor, or incident evidence.
            </p>
          </div>
        </Panel>
      </section>

      <section id="active-assessment" className="scroll-mt-4">
        <AssetScanner key={asset.id} asset={asset} />
      </section>

      <section className="grid gap-5 2xl:grid-cols-2">
        <Panel title={`Relevant CVEs (${intelligence.cves.length})`}>
          <div className="max-h-[680px] divide-y divide-gray-800 overflow-y-auto">
            {!intelligence.cves.length && <EmptyEvidence>No CVE correlation or inventory candidate is currently available.</EmptyEvidence>}
            {intelligence.cves.map(cve => (
              <article key={cve.cve_id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <a className="font-mono font-semibold text-mitre-accent hover:underline" href={`/cve?search=${encodeURIComponent(cve.cve_id)}`}>{cve.cve_id}</a>
                    <p className="mt-1 text-xs text-gray-500">{cve.evidence_level} · {cve.status}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {cve.known_exploited && <span className="rounded bg-red-600 px-2 py-1 text-[11px] font-semibold text-white">CISA KEV</span>}
                    <span className={`rounded border px-2 py-1 text-[11px] uppercase ${severityTone(cve.severity)}`}>
                      {cve.severity || 'unknown'}{cve.score ? ` · ${cve.score}` : ''}
                    </span>
                  </div>
                </div>
                <p className="mt-3 line-clamp-4 text-sm leading-6 text-gray-300">{cve.description || 'The local record has no description.'}</p>
                <EvidenceList evidence={cve.evidence} />
                <p className="mt-2 text-[11px] text-amber-300">Affected version and configuration must be verified.</p>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title={`Relevant ATT&CK techniques (${intelligence.ttps.length})`}>
          <div className="max-h-[680px] divide-y divide-gray-800 overflow-y-auto">
            {!intelligence.ttps.length && <EmptyEvidence>No ATT&CK technique correlation is currently available.</EmptyEvidence>}
            {intelligence.ttps.map(ttp => (
              <article key={ttp.attack_id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <a className="font-mono font-semibold text-mitre-accent hover:underline" href={`/navigator?technique=${encodeURIComponent(ttp.attack_id)}`}>{ttp.attack_id}</a>
                    <h3 className="mt-1 font-semibold text-white">{ttp.name || 'Technique details not present locally'}</h3>
                  </div>
                  <span className="rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400">{ttp.evidence_level}</span>
                </div>
                <p className="mt-3 line-clamp-4 text-sm leading-6 text-gray-300">{ttp.description || 'Open Navigator for the current ATT&CK record.'}</p>
                <TagList tags={ttp.platforms.slice(0, 8)} />
                <EvidenceList evidence={ttp.evidence} />
              </article>
            ))}
          </div>
        </Panel>
      </section>

      <Panel title={`Relevant IOCs (${intelligence.iocs.length})`}>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[920px] text-left text-xs">
            <thead className="bg-gray-950 text-gray-500">
              <tr>
                <th className="p-3">Indicator</th><th>Type</th><th>Evidence</th><th>Source</th><th>Confidence</th><th>Last seen</th><th>Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {!intelligence.iocs.length && <tr><td className="p-4 text-gray-500" colSpan={7}>No exact or correlated IOC is currently available.</td></tr>}
              {intelligence.iocs.map(ioc => (
                <tr key={`${ioc.indicator_type}:${ioc.value}`} className="align-top">
                  <td className="max-w-sm break-all p-3">
                    <a className="font-mono text-mitre-accent hover:underline" href={`/ioc-library?search=${encodeURIComponent(ioc.value)}`}>{ioc.value}</a>
                  </td>
                  <td className="py-3 text-gray-400">{ioc.indicator_type}</td>
                  <td className="py-3"><span className={`rounded border px-2 py-1 ${ioc.evidence_level === 'exact-inventory-identity' ? 'border-red-500/40 text-red-200' : 'border-amber-500/30 text-amber-200'}`}>{ioc.evidence_level}</span></td>
                  <td className="max-w-40 break-words py-3 text-gray-400">{ioc.source_id}</td>
                  <td className="py-3 text-gray-300">{ioc.confidence}%</td>
                  <td className="py-3 text-gray-400">{ioc.last_seen || '-'}</td>
                  <td className="max-w-md py-3 pr-3 text-gray-500">{ioc.note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <section className="grid gap-5 xl:grid-cols-2">
        <Panel title={`Matching Threat Radar Alerts (${intelligence.alerts.length})`}>
          <div className="max-h-[520px] divide-y divide-gray-800 overflow-y-auto">
            {!intelligence.alerts.length && <EmptyEvidence>No current signal alert matches this exact asset record.</EmptyEvidence>}
            {intelligence.alerts.map(alert => (
              <article key={String(alert.id)} className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <a className="font-semibold text-mitre-accent hover:underline" href={String(alert.route || '/threat-radar')}>{String(alert.title || 'Matched alert')}</a>
                  <span className="rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400">{String(alert.priority || alert.severity || 'unknown')}</span>
                </div>
                <p className="mt-2 text-xs leading-5 text-gray-500">{String(alert.description || '')}</p>
              </article>
            ))}
          </div>
        </Panel>

        <Panel title={`Assessment History (${intelligence.recent_scans.length})`}>
          <div className="max-h-[520px] divide-y divide-gray-800 overflow-y-auto">
            {!intelligence.recent_scans.length && <EmptyEvidence>No vulnerability assessment has been run for this asset.</EmptyEvidence>}
            {intelligence.recent_scans.map(scan => (
              <article key={scan.id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="break-all font-mono text-xs text-white">{scan.target}</p>
                    <p className="mt-1 text-xs text-gray-500">{scan.scan_profile} · {formatDate(scan.completed_at || scan.created_at)}</p>
                  </div>
                  <span className={`rounded border px-2 py-1 text-[11px] ${scan.status === 'completed' ? 'border-emerald-500/40 text-emerald-300' : 'border-amber-500/40 text-amber-300'}`}>{scan.status}</span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px] text-gray-400">
                  <span>{scan.open_port_count} open services</span><span>·</span><span>{scan.finding_count} findings/leads</span><span>·</span><span>{scan.risk_level} interpreted risk</span>
                </div>
              </article>
            ))}
          </div>
        </Panel>
      </section>

      <details className="rounded border border-gray-800 bg-gray-950 p-4">
        <summary className="cursor-pointer text-xs font-semibold uppercase tracking-wide text-gray-400">Raw normalized inventory metadata</summary>
        <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-gray-400">{JSON.stringify(asset.metadata, null, 2)}</pre>
      </details>
    </>
  );
}

function EvidenceList({ evidence }: { evidence: ThreatAssetIntelligence['cves'][number]['evidence'] }) {
  if (!evidence.length) return null;
  return (
    <div className="mt-3 flex flex-wrap gap-1">
      {evidence.slice(0, 8).map((item, index) => (
        <span key={`${item.kind}:${item.signal_id || item.scan_id || item.label}:${index}`} className="rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-400">
          {item.kind} · {item.label || item.source}
        </span>
      ))}
    </div>
  );
}

function EmptyEvidence({ children }: { children: React.ReactNode }) {
  return <p className="p-4 text-sm text-gray-500">{children}</p>;
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

        <AssetScanner key={asset.id} asset={asset} />

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

function AssetScanner({ asset }: { asset: ThreatSpaceAsset }) {
  const queryClient = useQueryClient();
  const targets = useMemo(
    () => [
      ...asset.ip_addresses.map(value => ({ value, label: `IP · ${value}` })),
      ...asset.domains.map(value => ({
        value: value.includes('://') ? value : `https://${value}/`,
        label: `URL · ${value}`,
      })),
    ],
    [asset.domains, asset.ip_addresses],
  );
  const [target, setTarget] = useState(targets[0]?.value ?? '');
  const [selectedProviders, setSelectedProviders] = useState<string[]>([]);
  const [runNmap, setRunNmap] = useState(false);
  const [aiAnalyze, setAiAnalyze] = useState(false);
  const [aiProvider, setAiProvider] = useState<ThreatHuntAIProviderId>('local');
  const [authorized, setAuthorized] = useState(false);
  const [cloudAcknowledged, setCloudAcknowledged] = useState(false);
  const providersInitialized = useRef(false);
  const providers = useQuery({
    queryKey: ['threat-radar-asset-scanner-providers'],
    queryFn: threatRadarApi.assetScannerProviders,
  });
  const scans = useQuery({
    queryKey: ['threat-radar-asset-scans', asset.space_id, asset.id],
    queryFn: () => threatRadarApi.assetScans(asset.space_id, asset.id),
  });

  useEffect(() => {
    if (!providers.data || providersInitialized.current) return;
    providersInitialized.current = true;
    setSelectedProviders(providers.data.passive.filter(row => row.enabled).map(row => row.id));
    const preferred = providers.data.ai.find(row => row.default && row.available)
      ?? providers.data.ai.find(row => row.available);
    if (preferred) setAiProvider(preferred.id);
  }, [providers.data]);

  const selectedAi = providers.data?.ai.find(row => row.id === aiProvider);
  const scan = useMutation({
    mutationFn: () => threatRadarApi.createAssetScan(asset.space_id, asset.id, {
      target,
      providers: selectedProviders,
      run_nmap: runNmap,
      ai_analyze: aiAnalyze,
      ai_provider: aiProvider,
      cloud_processing_acknowledged: Boolean(aiAnalyze && selectedAi?.remote && cloudAcknowledged),
      authorization_confirmed: authorized,
      tlp: 'TLP:AMBER',
    }),
    onSuccess: result => {
      queryClient.setQueryData<ThreatAssetScan[]>(
        ['threat-radar-asset-scans', asset.space_id, asset.id],
        previous => [result, ...(previous ?? []).filter(item => item.id !== result.id)],
      );
      queryClient.invalidateQueries({
        queryKey: ['threat-radar-asset-intelligence', asset.space_id, asset.id],
      });
      setAuthorized(false);
    },
  });
  const latest = scan.data ?? scans.data?.[0];
  const canRun = Boolean(
    providers.data?.enabled
    && target
    && authorized
    && !scan.isPending
    && (!aiAnalyze || selectedAi?.available)
    && (!aiAnalyze || !selectedAi?.remote || cloudAcknowledged),
  );

  const toggleProvider = (id: string) => {
    setSelectedProviders(current => (
      current.includes(id) ? current.filter(item => item !== id) : [...current, id]
    ));
  };

  return (
    <Panel title="Authorized Asset Exposure Assessment">
      <div className="space-y-4 p-4">
        <div className="rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs leading-5 text-amber-100/80">
          Targets are restricted to this inventory record. Passive OSINT runs first. The optional active stage uses an
          unprivileged, bounded top-port Nmap service-discovery profile—no NSE vulnerability scripts or exploitation.
        </div>

        {!targets.length ? (
          <p className="text-sm text-gray-500">Add an IP address or domain to this inventory asset before running an assessment.</p>
        ) : (
          <>
            <div className="grid gap-3 lg:grid-cols-2">
              <label className="block text-xs text-gray-400">
                Inventory target
                <select className="field mt-1 w-full" value={target} onChange={event => setTarget(event.target.value)}>
                  {targets.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
                </select>
              </label>
              <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
                <b className="text-white">Assessment boundary</b>
                <p className="mt-1">{providers.data?.nmap.boundary ?? 'Loading scanner policy…'}</p>
              </div>
            </div>

            <fieldset>
              <legend className="text-xs font-semibold uppercase tracking-wide text-gray-500">Passive evidence sources</legend>
              <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                {(providers.data?.passive ?? []).map(provider => (
                  <label key={provider.id} className={`flex min-h-10 items-center gap-2 rounded border px-3 py-2 text-xs ${provider.enabled ? 'border-gray-700 text-gray-300' : 'border-gray-800 text-gray-600'}`}>
                    <input
                      type="checkbox"
                      checked={selectedProviders.includes(provider.id)}
                      disabled={!provider.enabled}
                      onChange={() => toggleProvider(provider.id)}
                    />
                    <span>{provider.label}{!provider.enabled ? ' · not configured' : ''}</span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div className="grid gap-3 lg:grid-cols-2">
              <label className="flex items-start gap-3 rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                <input
                  className="mt-0.5"
                  type="checkbox"
                  checked={runNmap}
                  disabled={!providers.data?.nmap.enabled}
                  onChange={event => setRunNmap(event.target.checked)}
                />
                <span>
                  <b className="text-white">Run safe Nmap discovery</b>
                  <span className="mt-1 block text-gray-500">
                    Top {providers.data?.nmap.top_ports ?? 100} TCP ports, light version detection, bounded timeout.
                  </span>
                </span>
              </label>
              <label className="flex items-start gap-3 rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                <input className="mt-0.5" type="checkbox" checked={aiAnalyze} onChange={event => setAiAnalyze(event.target.checked)} />
                <span>
                  <b className="text-white">Analyze evidence with AI</b>
                  <span className="mt-1 block text-gray-500">Advisory interpretation only; all inferred CVEs require analyst verification.</span>
                </span>
              </label>
            </div>

            {aiAnalyze && (
              <div className="grid gap-3 lg:grid-cols-2">
                <label className="block text-xs text-gray-400">
                  AI provider
                  <select className="field mt-1 w-full" value={aiProvider} onChange={event => {
                    setAiProvider(event.target.value as ThreatHuntAIProviderId);
                    setCloudAcknowledged(false);
                  }}>
                    {(providers.data?.ai ?? []).map(provider => (
                      <option key={provider.id} value={provider.id} disabled={!provider.available}>
                        {provider.label} · {provider.model}{provider.available ? '' : ` · ${provider.status}`}
                      </option>
                    ))}
                  </select>
                </label>
                {selectedAi?.remote && (
                  <label className="flex items-start gap-3 rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-100/80">
                    <input className="mt-0.5" type="checkbox" checked={cloudAcknowledged} onChange={event => setCloudAcknowledged(event.target.checked)} />
                    <span>I explicitly authorize sending this TLP:AMBER assessment evidence to {selectedAi.label} for this request.</span>
                  </label>
                )}
              </div>
            )}

            <label className="flex items-start gap-3 rounded border border-red-500/30 bg-red-950/20 p-3 text-xs text-red-100/90">
              <input className="mt-0.5" type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} />
              <span>I confirm I am authorized to assess this exact inventory asset and target.</span>
            </label>

            <button className="primary-action min-h-10 px-4" disabled={!canRun} onClick={() => scan.mutate()}>
              {scan.isPending ? 'Assessment running…' : 'Run asset assessment'}
            </button>
            {scan.isError && <p role="alert" className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-100">{apiErrorMessage(scan.error)}</p>}
          </>
        )}

        {latest && <AssetScanResult scan={latest} />}
        {!latest && scans.isLoading && <p className="text-xs text-gray-500">Loading assessment history…</p>}
      </div>
    </Panel>
  );
}

function AssetScanResult({ scan }: { scan: ThreatAssetScan }) {
  const analysis = scan.ai_analysis;
  const nmapHosts = Array.isArray(scan.nmap_result.hosts)
    ? scan.nmap_result.hosts as Array<Record<string, unknown>>
    : [];
  const ports = nmapHosts.flatMap(host => (
    Array.isArray(host.ports) ? host.ports as Array<Record<string, unknown>> : []
  ));
  return (
    <section className="space-y-3 rounded border border-gray-800 bg-gray-950 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-semibold text-white">Latest assessment · {scan.target}</h3>
          <p className="mt-1 text-xs text-gray-500">{scan.scan_profile} · requested by {scan.requested_by}</p>
        </div>
        <span className={`rounded border px-2 py-1 text-xs ${scan.status === 'completed' ? 'border-emerald-500/40 text-emerald-300' : scan.status === 'partial' ? 'border-amber-500/40 text-amber-300' : 'border-red-500/40 text-red-300'}`}>
          {scan.status}
        </span>
      </div>
      {scan.error && <p className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-100">{scan.error}</p>}
      {scan.warnings.map(warning => <p key={warning} className="rounded border border-amber-500/30 bg-amber-950/20 p-3 text-xs text-amber-100/80">{warning}</p>)}
      <section className="grid gap-3 md:grid-cols-4">
        <Metric label="Passive lookups" value={scan.passive_results.length} />
        <Metric label="Open services" value={ports.length} />
        <Metric label="Findings / leads" value={scan.findings.length} />
        <Metric label="CVE candidates" value={Array.isArray(analysis.cve_candidates) ? analysis.cve_candidates.length : 0} />
      </section>
      <div className="rounded border border-sky-500/30 bg-sky-950/20 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <b className="text-sm text-white">Assessment interpretation</b>
          <span className="text-xs uppercase text-sky-300">{String(analysis.risk_level || 'unknown')} risk</span>
        </div>
        <p className="mt-2 text-sm leading-6 text-sky-100/80">{String(analysis.summary || 'No interpretation is available.')}</p>
        <p className="mt-2 text-xs text-sky-200/60">{String(analysis.evidence_boundary || '')}</p>
      </div>
      {!!ports.length && (
        <div className="overflow-x-auto rounded border border-gray-800">
          <table className="w-full min-w-[680px] text-left text-xs">
            <thead className="bg-gray-900 text-gray-500"><tr><th className="p-2">Port</th><th>Service</th><th>Product</th><th>Version</th><th>CPE</th></tr></thead>
            <tbody className="divide-y divide-gray-800">
              {ports.map((port, index) => (
                <tr key={`${String(port.protocol)}:${String(port.port)}:${index}`}>
                  <td className="p-2 font-mono text-white">{String(port.protocol)}/{String(port.port)}</td>
                  <td>{String(port.service || '-')}</td>
                  <td>{String(port.product || '-')}</td>
                  <td>{String(port.version || '-')}</td>
                  <td className="max-w-xs break-all">{Array.isArray(port.cpes) ? port.cpes.join(', ') : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {!!scan.findings.length && (
        <div className="grid gap-2 lg:grid-cols-2">
          {scan.findings.slice(0, 20).map((finding, index) => (
            <div key={`${finding.category}:${finding.title}:${index}`} className="rounded border border-gray-800 p-3 text-xs">
              <div className="flex items-start justify-between gap-2">
                <b className="text-white">{finding.title || 'Assessment lead'}</b>
                <span className="uppercase text-gray-500">{finding.severity || 'unknown'}</span>
              </div>
              <p className="mt-1 text-gray-400">{finding.evidence || 'No evidence summary.'}</p>
              {finding.verification_required && <p className="mt-2 text-amber-300">Analyst verification required.</p>}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function apiErrorMessage(error: unknown) {
  if (!error || typeof error !== 'object') return 'Assessment failed.';
  const record = error as { response?: { data?: { detail?: unknown } }; message?: string };
  return String(record.response?.data?.detail || record.message || 'Assessment failed.');
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
  if (type === 'cve') return `/cve?search=${encoded}`;
  if (type === 'ttp') return `/navigator?technique=${encoded}`;
  if (type === 'ioc') return `/ioc-library?search=${encoded}`;
  return '';
}

function riskTone(value: string) {
  if (value === 'critical') return 'border-red-500/50 bg-red-950/40 text-red-200';
  if (value === 'high') return 'border-orange-500/50 bg-orange-950/30 text-orange-200';
  if (value === 'medium') return 'border-amber-500/40 bg-amber-950/20 text-amber-200';
  return 'border-emerald-500/40 bg-emerald-950/20 text-emerald-200';
}

function severityTone(value: string) {
  const normalized = value.toLowerCase();
  if (normalized === 'critical') return 'border-red-500/50 bg-red-950/40 text-red-200';
  if (normalized === 'high') return 'border-orange-500/50 bg-orange-950/30 text-orange-200';
  if (normalized === 'medium') return 'border-amber-500/40 text-amber-200';
  return 'border-gray-700 text-gray-400';
}

function formatDate(value?: string | null) {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function TagList({ tags }: { tags: string[] }) {
  if (!tags.length) return <p className="text-xs text-gray-500">No values recorded.</p>;
  return <div className="flex flex-wrap gap-1">{tags.map(tag => <span key={tag} className="rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400">{tag}</span>)}</div>;
}
