import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  cveApi,
  threatRadarApi,
  type CVESourceStatus,
  type ThreatCompanySpace,
  type ThreatCompanySpaceDetail,
  type ThreatExposureProvider,
  type ThreatRadarSignal,
  type ThreatSpaceAsset,
  type ThreatSpaceMonitor,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useAttackMatrix, type MatrixData } from '@/hooks/useAttackMatrix';
import { useHasPermission } from '@/hooks/useCurrentUser';
import type { TechniqueListItem } from '@/types/attack';
import { safeHref } from '@/utils/url';

const INVENTORY_TEMPLATES = [
  ['Assets', '/templates/threat-radar/asset_inventory_template.csv'],
  ['Products', '/templates/threat-radar/product_inventory_template.csv'],
  ['Components', '/templates/threat-radar/component_inventory_template.csv'],
  ['SBOM dependencies', '/templates/threat-radar/dependency_sbom_inventory_template.csv'],
  ['Exposure', '/templates/threat-radar/product_exposure_inventory_template.csv'],
] as const;

type AlertRow = Record<string, unknown> & {
  id?: string;
  title?: string;
  description?: string;
  priority?: string;
  severity?: string;
  status?: string;
  score?: number;
  signal_id?: string;
  case_id?: string;
  asset_name?: string;
  asset_id?: string;
  asset_uuid?: string;
  match_type?: string;
  matched_terms?: unknown[];
  matches?: unknown[];
  last_seen?: string;
};

export function ThreatRadar() {
  const canManage = useHasPermission('manage_intel');
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const qc = useQueryClient();
  const [selectedSpaceId, setSelectedSpaceId] = useState(searchParams.get('space_id') || '');
  const [selectedSignalId, setSelectedSignalId] = useState(searchParams.get('signal_id') || searchParams.get('signal') || '');
  const [statusFilter, setStatusFilter] = useState('open');
  const [query, setQuery] = useState('* | stats count by priority');
  const [newSpaceName, setNewSpaceName] = useState('My Company Threat Monitor');
  const [newSpaceOwner, setNewSpaceOwner] = useState('Security Team');

  const spaces = useQuery({ queryKey: ['threat-radar-spaces'], queryFn: threatRadarApi.spaces });
  const metrics = useQuery({ queryKey: ['threat-radar-space-metrics'], queryFn: threatRadarApi.spaceMetrics });
  const selectedSpace = useQuery({
    queryKey: ['threat-radar-space', selectedSpaceId],
    queryFn: () => threatRadarApi.spaceDetail(selectedSpaceId),
    enabled: Boolean(selectedSpaceId),
  });
  const alerts = useQuery({
    queryKey: ['threat-radar-alerts', selectedSpaceId, statusFilter],
    queryFn: () => threatRadarApi.alerts(selectedSpaceId, { status: ['all', 'open'].includes(statusFilter) ? undefined : statusFilter, limit: 250 }),
    enabled: Boolean(selectedSpaceId),
  });
  const search = useQuery({
    queryKey: ['threat-radar-search', selectedSpaceId, query],
    queryFn: () => threatRadarApi.searchSpace(selectedSpaceId, { query, timerange: '30d', limit: 100 }),
    enabled: Boolean(selectedSpaceId),
  });
  const signals = useQuery({
    queryKey: ['threat-radar-signals'],
    queryFn: () => threatRadarApi.signals({ limit: 50 }),
  });
  const selectedSignal = useQuery({
    queryKey: ['threat-radar-signal', selectedSignalId],
    queryFn: () => threatRadarApi.signal(selectedSignalId),
    enabled: Boolean(selectedSignalId),
  });
  const cveSources = useQuery({ queryKey: ['cve-sources'], queryFn: cveApi.sources });
  const threatSources = useQuery({ queryKey: ['threat-radar-sources'], queryFn: threatRadarApi.sources });
  const exposureProviders = useQuery({ queryKey: ['threat-radar-exposure-providers'], queryFn: threatRadarApi.exposureProviders });
  const matrixData = useAttackMatrix('enterprise-attack', null);

  const invalidateSpace = () => {
    qc.invalidateQueries({ queryKey: ['threat-radar-spaces'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-space-metrics'] });
    qc.invalidateQueries({ queryKey: ['threat-radar-signals'] });
    if (selectedSpaceId) {
      qc.invalidateQueries({ queryKey: ['threat-radar-space', selectedSpaceId] });
      qc.invalidateQueries({ queryKey: ['threat-radar-alerts', selectedSpaceId] });
      qc.invalidateQueries({ queryKey: ['threat-radar-search', selectedSpaceId] });
    }
  };

  const createSpace = useMutation({
    mutationFn: () => threatRadarApi.createSpace({
      name: newSpaceName.trim() || 'My Company Threat Monitor',
      description: 'Company boundary for asset inventory, feed monitoring, correlation, detections, and analyst triage.',
      owner: newSpaceOwner.trim() || 'Security Team',
      sector: 'technology',
      region: 'global',
      tags: ['company-space', 'asset-monitoring', 'product-security'],
    }),
    onSuccess: space => {
      setSelectedSpaceId(space.id);
      setSearchParams({ space_id: space.id });
      invalidateSpace();
    },
  });

  const createMonitor = useMutation({
    mutationFn: () => threatRadarApi.createSpaceMonitor(selectedSpaceId, {
      name: 'CVE, IOC, actor, exploit, leak, and supply-chain relevance monitor',
      monitor_type: 'asset-feed-relevance',
      cadence: 'continuous',
      enabled: true,
      alert_threshold: 70,
      query: {
        asset_scope: 'all',
        feeds: ['cve', 'kev', 'ioc', 'actor', 'exploit', 'breach', 'leak', 'supply-chain', 'darknet', 'external-exposure'],
      },
    }),
    onSuccess: invalidateSpace,
  });

  const refreshDetections = useMutation({
    mutationFn: async () => {
      const detail = selectedSpace.data;
      if (detail?.monitors.length) {
        for (const monitor of detail.monitors) {
          await threatRadarApi.runSpaceMonitor(selectedSpaceId, monitor.id);
        }
      }
      return threatRadarApi.generateSpaceDashboard(selectedSpaceId);
    },
    onSuccess: invalidateSpace,
  });

  const updateAlert = useMutation({
    mutationFn: ({ alertId, status }: { alertId: string; status: string }) =>
      threatRadarApi.updateAlertStatus(selectedSpaceId, alertId, { status }),
    onSuccess: invalidateSpace,
  });

  useEffect(() => {
    const nextParams = new URLSearchParams(searchParams);
    let paramsChanged = false;
    let spaceId = searchParams.get('space_id') || '';
    if (!spaceId && spaces.data?.length) {
      spaceId = spaces.data[0].id;
      nextParams.set('space_id', spaceId);
      paramsChanged = true;
    }

    const canonicalSignalId = searchParams.get('signal_id') || '';
    const legacySignalId = searchParams.get('signal') || '';
    const signalId = canonicalSignalId || legacySignalId;
    if (!canonicalSignalId && legacySignalId) {
      nextParams.set('signal_id', legacySignalId);
      nextParams.delete('signal');
      paramsChanged = true;
    }

    if (spaceId && spaceId !== selectedSpaceId) setSelectedSpaceId(spaceId);
    if (signalId && signalId !== selectedSignalId) setSelectedSignalId(signalId);
    if (paramsChanged) setSearchParams(nextParams, { replace: true });
  }, [searchParams, selectedSignalId, selectedSpaceId, setSearchParams, spaces.data]);

  const selectedDetail = selectedSpace.data ?? null;
  const rawAlertRows = useMemo(() => (alerts.data ?? []) as AlertRow[], [alerts.data]);
  const alertRows = useMemo(() => filterAlertRows(rawAlertRows, statusFilter), [rawAlertRows, statusFilter]);
  const monitorRows = useMemo(() => selectedDetail?.monitors ?? [], [selectedDetail?.monitors]);
  const assetRows = useMemo(() => selectedDetail?.assets ?? [], [selectedDetail?.assets]);
  const summary = useMemo(() => buildSummary(alertRows, assetRows, monitorRows), [alertRows, assetRows, monitorRows]);
  const assetTtpCoverage = useMemo(() => buildAssetTtpCoverage(assetRows, rawAlertRows), [assetRows, rawAlertRows]);
  const feedCoverage = useMemo(
    () => buildFeedCoverage(cveSources.data ?? [], threatSources.data ?? [], exposureProviders.data ?? []),
    [cveSources.data, exposureProviders.data, threatSources.data],
  );

  const openSignal = (signalId: string) => {
    setSelectedSignalId(signalId);
    setSearchParams({ ...(selectedSpaceId ? { space_id: selectedSpaceId } : {}), signal_id: signalId });
  };

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Threat Monitor" />
      <main className="flex-1 overflow-y-auto px-6 py-6">
        <div className="mx-auto max-w-[1500px] space-y-5">
          <Declaration />

          <SetupPanel
            canManage={canManage}
            spaces={spaces.data ?? []}
            selectedSpaceId={selectedSpaceId}
            setSelectedSpaceId={id => {
              setSelectedSpaceId(id);
              setSearchParams(id ? { space_id: id } : {});
            }}
            newSpaceName={newSpaceName}
            setNewSpaceName={setNewSpaceName}
            newSpaceOwner={newSpaceOwner}
            setNewSpaceOwner={setNewSpaceOwner}
            onCreate={() => createSpace.mutate()}
            createPending={createSpace.isPending}
            onUpload={() => navigate(`/asset-surface?${new URLSearchParams({ space_id: selectedSpaceId }).toString()}`)}
            onCreateMonitor={() => createMonitor.mutate()}
            createMonitorPending={createMonitor.isPending}
            onRefresh={() => refreshDetections.mutate()}
            refreshPending={refreshDetections.isPending}
            assetCount={assetRows.length}
            monitorCount={monitorRows.length}
            metrics={metrics.data ?? {}}
          />

          <StatusStrip summary={summary} feedCoverage={feedCoverage} />
          <AssetTtpMatrixWidget matrixData={matrixData} coverage={assetTtpCoverage} selectedSpaceId={selectedSpaceId} />
          <AlertCenter
            canManage={canManage}
            selectedSpaceId={selectedSpaceId}
            loading={alerts.isLoading || selectedSpace.isLoading}
            rows={alertRows}
            statusFilter={statusFilter}
            setStatusFilter={setStatusFilter}
            onOpenSignal={openSignal}
            onUpdateAlert={(alertId, status) => updateAlert.mutate({ alertId, status })}
            updatePending={updateAlert.isPending}
          />

          <details className="rounded-lg border border-gray-800 bg-gray-900/40">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white">Inventory and feed status</summary>
            <section className="grid gap-5 border-t border-gray-800 p-4 2xl:grid-cols-[minmax(0,1fr)_460px]">
              <InventoryPanel detail={selectedDetail} loading={selectedSpace.isLoading} />
              <FeedPanel cveSources={cveSources.data ?? []} threatSources={threatSources.data ?? []} exposureProviders={exposureProviders.data ?? []} />
            </section>
          </details>

          <details className="rounded-lg border border-gray-800 bg-gray-900/40">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white">Advanced search and evidence</summary>
            <section className="grid gap-5 border-t border-gray-800 p-4 2xl:grid-cols-[minmax(0,1fr)_460px]">
              <QueryPanel query={query} setQuery={setQuery} result={search.data ?? null} loading={search.isLoading} />
              <SignalInspector signal={selectedSignal.data ?? null} loading={selectedSignal.isLoading} recentSignals={signals.data ?? []} onSelect={openSignal} />
            </section>
          </details>
        </div>
      </main>
    </div>
  );
}

function Declaration() {
  return (
    <section className="rounded-lg border border-sky-500/40 bg-sky-950/20 p-5">
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_520px]">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-sky-200">Threat Monitor</p>
          <h1 className="mt-3 text-2xl font-semibold text-white">Upload assets. Check feeds. Get alerts.</h1>
          <p className="mt-3 max-w-4xl text-sm leading-6 text-sky-100/80">
            This module compares your inventory with CVE, IOC, actor, exploit, leak, breach, supply-chain, and exposure feeds.
          </p>
        </div>
        <div className="grid gap-2 text-xs sm:grid-cols-3">
          {[
            ['1', 'Choose space', 'Your company or lab boundary.'],
            ['2', 'Upload assets', 'Assets, products, SBOM, exposure.'],
            ['3', 'Run monitor', 'Relevant matches become alerts.'],
          ].map(([step, title, text]) => (
            <div key={step} className="rounded border border-sky-500/25 bg-gray-950/50 p-3">
              <span className="rounded bg-sky-500/20 px-2 py-1 font-mono text-sky-100">{step}</span>
              <b className="ml-2 text-white">{title}</b>
              <p className="mt-2 leading-5 text-sky-100/70">{text}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function SetupPanel({
  canManage,
  spaces,
  selectedSpaceId,
  setSelectedSpaceId,
  newSpaceName,
  setNewSpaceName,
  newSpaceOwner,
  setNewSpaceOwner,
  onCreate,
  createPending,
  onUpload,
  onCreateMonitor,
  createMonitorPending,
  onRefresh,
  refreshPending,
  assetCount,
  monitorCount,
  metrics,
}: {
  canManage: boolean;
  spaces: ThreatCompanySpace[];
  selectedSpaceId: string;
  setSelectedSpaceId: (id: string) => void;
  newSpaceName: string;
  setNewSpaceName: (value: string) => void;
  newSpaceOwner: string;
  setNewSpaceOwner: (value: string) => void;
  onCreate: () => void;
  createPending: boolean;
  onUpload: () => void;
  onCreateMonitor: () => void;
  createMonitorPending: boolean;
  onRefresh: () => void;
  refreshPending: boolean;
  assetCount: number;
  monitorCount: number;
  metrics: Record<string, number>;
}) {
  return (
    <Panel title="Start Here">
      {!canManage&&<div className="border-b border-gray-800 p-4"><PermissionNotice permission="manage_intel" action="create spaces, upload inventory, run monitors, or change alert status" compact /></div>}
      <div className="grid gap-4 p-4 xl:grid-cols-[minmax(260px,360px)_minmax(0,1fr)_minmax(260px,360px)]">
        <div className="space-y-3">
          <label className="block text-xs text-gray-400">
            1. Choose company space
            <select className="field mt-1 w-full" value={selectedSpaceId} onChange={event => setSelectedSpaceId(event.target.value)}>
              <option value="">Select company space</option>
              {spaces.map(space => <option key={space.id} value={space.id}>{space.name}</option>)}
            </select>
          </label>
          {canManage&&<details className="rounded border border-gray-800 bg-gray-950">
            <summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-gray-300">Create new space</summary>
            <div className="space-y-3 border-t border-gray-800 p-3">
              <label className="block text-xs text-gray-400">Name<input className="field mt-1 w-full" value={newSpaceName} onChange={event => setNewSpaceName(event.target.value)} /></label>
              <label className="block text-xs text-gray-400">Owner<input className="field mt-1 w-full" value={newSpaceOwner} onChange={event => setNewSpaceOwner(event.target.value)} /></label>
              <button className="primary-action min-h-10 w-full" disabled={createPending} onClick={onCreate}>
                {createPending ? 'Creating...' : 'Create space'}
              </button>
            </div>
          </details>}
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <ActionStep
            number="2"
            title="Upload inventory"
            description={`${assetCount} assets loaded`}
            primary="Upload files"
            disabled={!canManage || !selectedSpaceId}
            onPrimary={onUpload}
            secondaryHref={`/threat-radar/assets?space_id=${encodeURIComponent(selectedSpaceId)}`}
            secondary="View inventory"
          />
          <ActionStep
            number="3"
            title="Create monitor"
            description={`${monitorCount} monitors configured`}
            primary={createMonitorPending ? 'Adding...' : 'Add monitor'}
            disabled={!canManage || !selectedSpaceId || createMonitorPending}
            onPrimary={onCreateMonitor}
          />
          <ActionStep
            number="4"
            title="Check feeds"
            description="Generate matching alerts"
            primary={refreshPending ? 'Checking...' : 'Run now'}
            disabled={!canManage || !selectedSpaceId || refreshPending}
            onPrimary={onRefresh}
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <Metric label="Spaces" value={metrics.spaces ?? spaces.length} />
          <Metric label="Assets" value={assetCount} />
          <Metric label="Rules" value={metrics.rules ?? 0} />
          <Metric label="Alerts" value={metrics.alerts ?? 0} tone={(metrics.alerts ?? 0) > 0 ? 'bad' : 'neutral'} />
        </div>
      </div>
      <div className="flex flex-wrap gap-2 border-t border-gray-800 px-4 py-3">
        <span className="text-xs text-gray-500">CSV templates:</span>
        {INVENTORY_TEMPLATES.map(([label, href]) => (
          <a key={href} className="text-xs text-mitre-accent hover:underline" href={href} download>{label}</a>
        ))}
      </div>
    </Panel>
  );
}

function ActionStep({
  number,
  title,
  description,
  primary,
  disabled,
  onPrimary,
  secondaryHref,
  secondary,
}: {
  number: string;
  title: string;
  description: string;
  primary: string;
  disabled: boolean;
  onPrimary: () => void;
  secondaryHref?: string;
  secondary?: string;
}) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className="flex items-center gap-2">
        <span className="rounded bg-mitre-accent/20 px-2 py-1 font-mono text-xs text-mitre-accent">{number}</span>
        <b className="text-sm text-white">{title}</b>
      </div>
      <p className="mt-2 text-xs text-gray-500">{description}</p>
      <button className="primary-action mt-3 min-h-9 w-full text-xs" disabled={disabled} onClick={onPrimary}>{primary}</button>
      {secondaryHref && secondary && (
        <a className="secondary-action mt-2 flex min-h-9 w-full items-center justify-center text-xs" href={secondaryHref}>{secondary}</a>
      )}
    </div>
  );
}

function StatusStrip({ summary, feedCoverage }: { summary: ReturnType<typeof buildSummary>; feedCoverage: ReturnType<typeof buildFeedCoverage> }) {
  return (
    <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      <MetricCard title="Alerts" value={summary.openAlerts} detail={`${summary.highPriority} high priority`} tone={summary.openAlerts ? 'bad' : 'neutral'} />
      <MetricCard title="Assets" value={summary.assets} detail={`${summary.internetFacing} internet-facing`} />
      <MetricCard title="Feeds" value={feedCoverage.ready} detail={`${feedCoverage.total} sources`} tone={feedCoverage.ready ? 'good' : 'warn'} />
      <MetricCard title="Monitors" value={summary.enabledMonitors} detail={`${summary.alertingMonitors} alerting`} tone={summary.alertingMonitors ? 'warn' : 'neutral'} />
    </section>
  );
}

function AssetTtpMatrixWidget({
  matrixData,
  coverage,
  selectedSpaceId,
}: {
  matrixData: MatrixData;
  coverage: ReturnType<typeof buildAssetTtpCoverage>;
  selectedSpaceId: string;
}) {
  const relevantCount = coverage.byTechnique.size;
  const hasInventory = coverage.assetCount > 0;
  const maxScore = Math.max(...Array.from(coverage.byTechnique.values()).map(item => item.score), 1);
  const techniqueNameById = buildTechniqueNameLookup(matrixData);

  return (
    <Panel title="Dashboard: ATT&CK Matrix for Asset-Relevant TTPs">
      <div className="space-y-4 p-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-sm leading-6 text-gray-300">
              This matrix highlights ATT&CK techniques mapped to the selected company space from parsed asset inventory,
              asset-surface TTP candidates, and feed alerts that matched assets.
            </p>
            <p className="mt-1 text-xs text-gray-500">
              Click any highlighted technique to open the full Navigator page. Use the asset inventory page to inspect the exact asset, CVE, IOC, and alert context.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-2 text-center">
            <Metric label="Relevant TTPs" value={relevantCount} tone={relevantCount ? 'warn' : 'neutral'} />
            <Metric label="Mapped assets" value={coverage.assetCount} />
            <Metric label="Alert-backed" value={coverage.alertBackedCount} tone={coverage.alertBackedCount ? 'bad' : 'neutral'} />
          </div>
        </div>

        {!selectedSpaceId && <p className="rounded border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">Select or create a company space to build the asset TTP matrix.</p>}
        {selectedSpaceId && !hasInventory && <p className="rounded border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">Upload inventory first. Asset-surface analysis will add TTP candidates that appear here.</p>}
        {selectedSpaceId && hasInventory && !matrixData.hasData && <p className="rounded border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">Loading ATT&CK tactics and techniques...</p>}
        {selectedSpaceId && hasInventory && matrixData.hasData && relevantCount === 0 && (
          <p className="rounded border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">
            No asset-relevant ATT&CK techniques have been mapped yet. Run asset analysis or feed monitoring to produce TTP evidence.
          </p>
        )}

        {selectedSpaceId && hasInventory && matrixData.hasData && relevantCount > 0 && (
          <>
            <div className="flex flex-wrap gap-2 text-[11px] text-gray-400">
              <span className="rounded border border-red-500/40 bg-red-950/40 px-2 py-1 text-red-100">alert-backed</span>
              <span className="rounded border border-sky-500/40 bg-sky-950/40 px-2 py-1 text-sky-100">asset-surface candidate</span>
              <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1">number = matched assets + alerts</span>
            </div>
            <div className="overflow-x-auto rounded border border-gray-800 bg-gray-950/60">
              <div
                className="grid min-w-[1400px] gap-2 p-3"
                style={{ gridTemplateColumns: `repeat(${matrixData.tactics.length}, minmax(150px, 1fr))` }}
              >
                {matrixData.tactics.map(tactic => (
                  <AssetTacticColumn
                    key={tactic.attack_id}
                    tacticName={tactic.name}
                    tacticShortname={tactic.shortname}
                    techniques={matrixData.techniquesByTactic.get(tactic.shortname) ?? []}
                    subtechsByParent={matrixData.subtechsByParent}
                    coverage={coverage}
                    maxScore={maxScore}
                  />
                ))}
              </div>
            </div>
            <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_360px]">
              <div className="rounded border border-gray-800 bg-gray-950 p-3">
                <b className="text-xs uppercase tracking-wide text-gray-500">Top asset-relevant techniques</b>
                <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {coverage.topTechniques.slice(0, 12).map(item => (
                    <a key={item.id} className="rounded border border-gray-800 bg-gray-900/60 p-3 hover:border-mitre-accent" href={`/navigator?technique=${encodeURIComponent(item.id)}`}>
                      <div className="flex items-center justify-between gap-3">
                        <b className="font-mono text-sm text-mitre-accent">{item.id}</b>
                        <span className="rounded border border-gray-700 px-2 py-0.5 text-[11px] text-gray-400">{item.score}</span>
                      </div>
                      <p className="mt-2 text-xs text-gray-400">{techniqueNameById.get(item.id) || (item.name !== item.id ? item.name : item.id)}</p>
                      <p className="mt-1 text-[11px] text-gray-600">{item.assets.size} assets · {item.alerts} alerts</p>
                    </a>
                  ))}
                </div>
              </div>
              <div className="rounded border border-gray-800 bg-gray-950 p-3">
                <b className="text-xs uppercase tracking-wide text-gray-500">Source logic</b>
                <ul className="mt-3 space-y-2 text-xs leading-5 text-gray-400">
                  <li>Asset inventory contributes TTP candidates from `metadata.ttp_candidates`, `technique_ids`, and normalized TTP tags.</li>
                  <li>Alerts contribute TTPs only when they are attached to an inventory asset or asset match.</li>
                  <li>Sub-techniques are shown under their parent technique when ATT&CK provides that relationship.</li>
                </ul>
              </div>
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

function AssetTacticColumn({
  tacticName,
  tacticShortname,
  techniques,
  subtechsByParent,
  coverage,
  maxScore,
}: {
  tacticName: string;
  tacticShortname: string;
  techniques: TechniqueListItem[];
  subtechsByParent: Map<string, TechniqueListItem[]>;
  coverage: ReturnType<typeof buildAssetTtpCoverage>;
  maxScore: number;
}) {
  const cells = techniques.flatMap(technique => {
    const parentCoverage = coverage.byTechnique.get(technique.attack_id);
    const relevantSubs = (subtechsByParent.get(technique.attack_id) ?? []).filter(sub => coverage.byTechnique.has(sub.attack_id));
    if (!parentCoverage && !relevantSubs.length) return [];
    return [{ technique, parentCoverage, relevantSubs }];
  });

  return (
    <section className="min-h-[220px] rounded border border-gray-800 bg-gray-900/60">
      <header className="sticky top-0 border-b border-gray-800 bg-gray-950 px-2 py-2">
        <h3 className="line-clamp-2 text-xs font-semibold text-white">{tacticName}</h3>
        <p className="mt-1 text-[10px] text-gray-600">{tacticShortname} · {cells.length} relevant</p>
      </header>
      <div className="max-h-[480px] space-y-2 overflow-y-auto p-2">
        {cells.map(({ technique, parentCoverage, relevantSubs }) => (
          <AssetTechniqueCell
            key={technique.attack_id}
            technique={technique}
            coverageItem={parentCoverage}
            relevantSubs={relevantSubs}
            coverage={coverage}
            maxScore={maxScore}
          />
        ))}
        {!cells.length && <p className="p-2 text-[11px] text-gray-700">No mapped TTPs</p>}
      </div>
    </section>
  );
}

function AssetTechniqueCell({
  technique,
  coverageItem,
  relevantSubs,
  coverage,
  maxScore,
}: {
  technique: TechniqueListItem;
  coverageItem?: AssetTtpCoverageItem;
  relevantSubs: TechniqueListItem[];
  coverage: ReturnType<typeof buildAssetTtpCoverage>;
  maxScore: number;
}) {
  const score = coverageItem?.score ?? relevantSubs.reduce((sum, sub) => sum + (coverage.byTechnique.get(sub.attack_id)?.score ?? 0), 0);
  const alertBacked = Boolean(coverageItem?.alerts) || relevantSubs.some(sub => (coverage.byTechnique.get(sub.attack_id)?.alerts ?? 0) > 0);
  const opacity = Math.min(1, Math.max(0.25, score / maxScore));
  const border = alertBacked ? 'border-red-500/50' : 'border-sky-500/40';
  const background = alertBacked ? `rgba(127, 29, 29, ${0.25 + opacity * 0.35})` : `rgba(12, 74, 110, ${0.22 + opacity * 0.32})`;
  const displayName = coverageItem?.name && coverageItem.name !== coverageItem.id ? coverageItem.name : technique.name;

  return (
    <div className={`rounded border ${border} p-2`} style={{ background }}>
      <a className="font-mono text-[11px] font-semibold text-white hover:text-mitre-accent" href={`/navigator?technique=${encodeURIComponent(technique.attack_id)}`}>
        {technique.attack_id}
      </a>
      <p className="mt-1 line-clamp-2 text-[11px] leading-4 text-gray-200">{displayName}</p>
      <p className="mt-1 text-[10px] text-gray-400">
        {coverageItem ? `${coverageItem.assets.size} assets · ${coverageItem.alerts} alerts` : `${relevantSubs.length} sub-techniques`}
      </p>
      {coverageItem && coverageItem.assets.size > 0 && (
        <p className="mt-1 line-clamp-2 text-[10px] text-gray-500">{Array.from(coverageItem.assets).slice(0, 3).join(', ')}</p>
      )}
      {relevantSubs.length > 0 && (
        <div className="mt-2 space-y-1">
          {relevantSubs.map(sub => {
            const subCoverage = coverage.byTechnique.get(sub.attack_id);
            return (
              <a key={sub.attack_id} className="block rounded border border-gray-700/80 bg-gray-950/70 px-2 py-1 hover:border-mitre-accent" href={`/navigator?technique=${encodeURIComponent(sub.attack_id)}`}>
                <span className="font-mono text-[10px] text-mitre-accent">{sub.attack_id}</span>
                <span className="ml-2 text-[10px] text-gray-400">{subCoverage?.assets.size ?? 0} assets · {subCoverage?.alerts ?? 0} alerts</span>
              </a>
            );
          })}
        </div>
      )}
    </div>
  );
}

function AlertCenter({
  canManage,
  selectedSpaceId,
  loading,
  rows,
  statusFilter,
  setStatusFilter,
  onOpenSignal,
  onUpdateAlert,
  updatePending,
}: {
  canManage: boolean;
  selectedSpaceId: string;
  loading: boolean;
  rows: AlertRow[];
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  onOpenSignal: (signalId: string) => void;
  onUpdateAlert: (alertId: string, status: string) => void;
  updatePending: boolean;
}) {
  return (
    <Panel title="Alerts">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 p-4">
        <div>
          <p className="text-sm text-gray-300">Relevant feed matches for your assets appear here.</p>
          <p className="mt-1 text-xs text-gray-500">Open an alert to see the source signal, affected asset, and matched evidence.</p>
        </div>
        <select className="field min-w-40" value={statusFilter} onChange={event => setStatusFilter(event.target.value)}>
          <option value="open">Open</option>
          <option value="new">New</option>
          <option value="triaged">Triaged</option>
          <option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option>
          <option value="all">All</option>
        </select>
      </div>
      {!selectedSpaceId && <p className="p-4 text-sm text-gray-500">Select or create a company space first.</p>}
      {loading && <p className="p-4 text-sm text-gray-500">Loading detections...</p>}
      {!loading && selectedSpaceId && !rows.length && (
        <div className="p-6 text-sm text-gray-400">
          <b className="text-white">No alerts yet.</b>
          <p className="mt-2">Upload inventory, add a monitor, then run monitoring.</p>
        </div>
      )}
      {rows.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="bg-gray-950 text-xs uppercase text-gray-500">
              <tr>
                <th className="p-3">Detection</th>
                <th>Priority</th>
                <th>Asset / match</th>
                <th>Evidence tags</th>
                <th>Status</th>
                <th className="pr-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {rows.map(row => (
                <tr key={String(row.id)} className="align-top hover:bg-gray-900/60">
                  <td className="max-w-md p-3">
                    <button className="text-left font-semibold text-mitre-accent hover:underline" onClick={() => row.signal_id && onOpenSignal(String(row.signal_id))}>
                      {String(row.title || 'Detection')}
                    </button>
                    <p className="mt-1 line-clamp-2 text-xs leading-5 text-gray-500">{String(row.description || '')}</p>
                    <p className="mt-1 text-[11px] text-gray-600">{formatDate(row.last_seen)}</p>
                  </td>
                  <td className="py-3">
                    <StatusPill value={String(row.priority || row.severity || 'P3')} />
                    <p className="mt-2 font-mono text-xs text-gray-500">score {String(row.score ?? '-')}</p>
                  </td>
                  <td className="py-3 text-xs text-gray-300">
                    <p className="font-semibold text-white">{String(row.asset_name || 'inventory match')}</p>
                    <p className="mt-1 text-gray-500">{String(row.match_type || 'match')}</p>
                    {row.asset_uuid && <a className="mt-2 inline-block text-mitre-accent hover:underline" href={`/threat-radar/assets/${encodeURIComponent(String(row.space_id || selectedSpaceId))}/${encodeURIComponent(String(row.asset_uuid))}`}>Open asset</a>}
                  </td>
                  <td className="max-w-sm py-3">
                    <EvidenceTags row={row} />
                  </td>
                  <td className="py-3">
                    <StatusPill value={String(row.status || 'new')} />
                  </td>
                  <td className="pr-3 py-3">
                    <div className="flex flex-col gap-2">
                      {row.signal_id && <button className="secondary-action min-h-8 text-xs" onClick={() => onOpenSignal(String(row.signal_id))}>Open signal</button>}
                      {canManage&&row.id && <button className="secondary-action min-h-8 text-xs" disabled={updatePending} onClick={() => onUpdateAlert(String(row.id), 'investigating')}>Investigate</button>}
                      {canManage&&row.id && <button className="secondary-action min-h-8 text-xs" disabled={updatePending} onClick={() => onUpdateAlert(String(row.id), 'resolved')}>Resolve</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function QueryPanel({ query, setQuery, result, loading }: { query: string; setQuery: (value: string) => void; result: { rows?: Record<string, unknown>[]; points?: Array<{ label: string; value: number }>; errors?: string[] } | null; loading: boolean }) {
  const rows = result?.rows ?? [];
  const points = result?.points ?? [];
  return (
    <Panel title="Detection Search">
      <div className="space-y-4 p-4">
        <label className="block text-xs text-gray-400">
          Query detections
          <textarea className="field mt-1 min-h-20 w-full font-mono text-xs" value={query} onChange={event => setQuery(event.target.value)} />
        </label>
        <div className="flex flex-wrap gap-2">
          {['severity:critical OR severity:high', 'match_type:technology', 'match_type:supply-chain', 'cve:* | stats count by priority'].map(example => (
            <button key={example} className="rounded border border-gray-700 px-2 py-1 font-mono text-[11px] text-gray-300 hover:border-mitre-accent" onClick={() => setQuery(example)}>
              {example}
            </button>
          ))}
        </div>
        {loading && <p className="text-sm text-gray-500">Searching detections...</p>}
        {Boolean(result?.errors?.length) && <p className="rounded border border-amber-500/40 bg-amber-950/20 p-3 text-xs text-amber-100">{result?.errors?.join(' · ')}</p>}
        <div className="grid gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
          <div className="rounded border border-gray-800 bg-gray-950 p-3">
            <b className="text-xs uppercase tracking-wide text-gray-500">Grouped result</b>
            <div className="mt-3 space-y-2">
              {points.slice(0, 12).map(point => <Bar key={point.label} label={point.label} value={point.value} max={Math.max(...points.map(item => item.value), 1)} />)}
              {!points.length && <p className="text-sm text-gray-500">No grouped result.</p>}
            </div>
          </div>
          <div className="max-h-80 overflow-auto rounded border border-gray-800">
            {rows.slice(0, 30).map((row, index) => (
              <div key={String(row.id ?? index)} className="border-b border-gray-800 p-3 last:border-b-0">
                <b className="text-sm text-white">{String(row.title || row.event_type || 'Detection result')}</b>
                <p className="mt-1 text-xs text-gray-500">{String(row.description || row.searchable || '')}</p>
                <EvidenceTags row={row as AlertRow} />
              </div>
            ))}
            {!rows.length && <p className="p-4 text-sm text-gray-500">No matching rows.</p>}
          </div>
        </div>
      </div>
    </Panel>
  );
}

function SignalInspector({ signal, loading, recentSignals, onSelect }: { signal: ThreatRadarSignal | null; loading: boolean; recentSignals: ThreatRadarSignal[]; onSelect: (id: string) => void }) {
  return (
    <Panel title="Source Signal">
      {loading && <p className="p-4 text-sm text-gray-500">Loading signal...</p>}
      {!loading && signal && (
        <div className="space-y-4 p-4">
          <div>
            <StatusPill value={signal.severity} />
            <h3 className="mt-3 text-lg font-semibold text-white">{signal.title}</h3>
            <p className="mt-2 text-sm leading-6 text-gray-300">{signal.description}</p>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <Metric label="Confidence" value={signal.confidence} />
            <Metric label="Score" value={signal.score?.score ?? 0} tone={(signal.score?.score ?? 0) >= 70 ? 'bad' : 'neutral'} />
          </div>
          <TagLinks values={signal.cve_ids} type="cve" />
          <TagLinks values={signal.technique_ids} type="ttp" />
          <TagLinks values={signal.actors} type="actor" />
          <TagList tags={signal.tags} />
          {safeHref(signal.source_url) && <a className="secondary-action inline-flex min-h-9 items-center" href={safeHref(signal.source_url)} target="_blank" rel="noreferrer">Open source</a>}
        </div>
      )}
      {!loading && !signal && (
        <div className="space-y-3 p-4">
          <p className="text-sm text-gray-500">Select a detection or recent signal to inspect the source evidence.</p>
          {recentSignals.slice(0, 8).map(item => (
            <button key={item.id} className="block w-full rounded border border-gray-800 bg-gray-950 p-3 text-left hover:border-mitre-accent" onClick={() => onSelect(item.id)}>
              <b className="text-sm text-white">{item.title}</b>
              <p className="mt-1 text-xs text-gray-500">{item.signal_type} · {item.severity} · confidence {item.confidence}</p>
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}

function InventoryPanel({ detail, loading }: { detail: ThreatCompanySpaceDetail | null; loading: boolean }) {
  if (loading) return <Panel title="Inventory Coverage"><p className="p-4 text-sm text-gray-500">Loading inventory...</p></Panel>;
  if (!detail) return <Panel title="Inventory Coverage"><p className="p-4 text-sm text-gray-500">Select a company space first.</p></Panel>;
  return (
    <Panel title="Inventory Coverage">
      <div className="border-b border-gray-800 px-4 py-3 text-xs text-gray-500">
        {detail.assets.length} parsed assets. Click an asset to open its generated asset intelligence page.
      </div>
      <div className="max-h-[520px] overflow-auto">
        <table className="w-full min-w-[820px] text-left text-sm">
          <thead className="sticky top-0 z-10 bg-gray-950 text-xs uppercase text-gray-500"><tr><th className="p-3">Asset</th><th>Exposure</th><th>Products</th><th>Technologies</th><th>Owner</th></tr></thead>
          <tbody className="divide-y divide-gray-800">
            {detail.assets.map(asset => (
              <tr key={asset.id} className="align-top hover:bg-gray-900/60">
                <td className="p-3">
                  <a className="font-semibold text-mitre-accent hover:underline" href={`/threat-radar/assets/${encodeURIComponent(asset.space_id)}/${encodeURIComponent(asset.id)}`}>{asset.name}</a>
                  <p className="mt-1 text-xs text-gray-500">{asset.asset_id} · {asset.asset_type} · {asset.environment}</p>
                </td>
                <td className="py-3"><StatusPill value={`${asset.exposure || 'unknown'} / ${asset.criticality || 'unknown'}`} /></td>
                <td className="py-3"><TagList tags={asset.products.slice(0, 5)} /></td>
                <td className="py-3"><TagList tags={asset.technologies.slice(0, 6)} /></td>
                <td className="py-3 pr-3 text-xs text-gray-400">{asset.owner || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!detail.assets.length && <p className="p-4 text-sm text-gray-500">No inventory loaded yet.</p>}
      </div>
    </Panel>
  );
}

function FeedPanel({ cveSources, threatSources, exposureProviders }: { cveSources: CVESourceStatus[]; threatSources: Array<{ id: string; name: string; source_type: string; enabled: boolean; url: string }>; exposureProviders: ThreatExposureProvider[] }) {
  return (
    <Panel title="Feed Coverage">
      <div className="max-h-[520px] overflow-y-auto">
        <FeedGroup title="CVE / vulnerability feeds" rows={cveSources.map(item => ({
          id: item.source_id,
          title: item.label,
          detail: item.kind,
          status: item.enabled ? item.sync_status || 'enabled' : 'disabled',
          url: item.url,
        }))} />
        <FeedGroup title="Threat signal sources" rows={threatSources.map(item => ({
          id: item.id,
          title: item.name,
          detail: item.source_type,
          status: item.enabled ? 'enabled' : 'disabled',
          url: item.url,
        }))} />
        <FeedGroup title="Exposure / breach / leak providers" rows={exposureProviders.map(item => ({
          id: item.id,
          title: item.label,
          detail: item.category,
          status: item.configured ? 'ready' : 'missing key',
          url: '',
        }))} />
      </div>
    </Panel>
  );
}

function FeedGroup({ title, rows }: { title: string; rows: Array<{ id: string; title: string; detail: string; status: string; url: string }> }) {
  return (
    <div className="border-b border-gray-800 p-4 last:border-b-0">
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      <div className="mt-3 space-y-2">
        {rows.map(row => (
          <div key={row.id} className="rounded border border-gray-800 bg-gray-950 p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <b className="text-xs text-gray-100">{row.title}</b>
                <p className="mt-1 text-[11px] text-gray-500">{row.id} · {row.detail}</p>
              </div>
              <StatusPill value={row.status} />
            </div>
            {safeHref(row.url) && <a className="mt-2 inline-block text-[11px] text-mitre-accent hover:underline" href={safeHref(row.url)} target="_blank" rel="noreferrer">source</a>}
          </div>
        ))}
        {!rows.length && <p className="text-xs text-gray-500">No sources registered.</p>}
      </div>
    </div>
  );
}

function EvidenceTags({ row }: { row: AlertRow }) {
  const values = collectEvidenceValues(row);
  return (
    <div className="mt-2 flex flex-wrap gap-1.5">
      {values.slice(0, 14).map(value => <EntityTag key={`${value.type}:${value.value}`} value={value.value} type={value.type} />)}
      {!values.length && <span className="text-xs text-gray-600">No evidence tags</span>}
    </div>
  );
}

function TagLinks({ values, type }: { values: string[]; type: 'cve' | 'ttp' | 'actor' | 'ioc' }) {
  if (!values.length) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map(value => <EntityTag key={`${type}:${value}`} value={value} type={type} />)}
    </div>
  );
}

function EntityTag({ value, type }: { value: string; type: string }) {
  const href = entityHref(value, type);
  const className = 'rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-300 hover:border-mitre-accent hover:text-mitre-accent';
  return href ? <a className={className} href={href}>{value}</a> : <span className="rounded border border-gray-800 px-2 py-1 text-[11px] text-gray-400">{value}</span>;
}

function TagList({ tags }: { tags: string[] }) {
  if (!tags.length) return <span className="text-xs text-gray-600">-</span>;
  return <div className="mt-2 flex flex-wrap gap-1.5">{tags.slice(0, 12).map(tag => <span key={tag} className="rounded border border-gray-800 px-2 py-1 text-[11px] text-gray-400">{tag}</span>)}</div>;
}

function Metric({ label, value, tone = 'neutral' }: { label: string; value: number | string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }) {
  const color = tone === 'bad' ? 'text-red-200' : tone === 'warn' ? 'text-amber-200' : tone === 'good' ? 'text-emerald-200' : 'text-white';
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className={`text-xl font-semibold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
    </div>
  );
}

function MetricCard({ title, value, detail, tone = 'neutral' }: { title: string; value: number; detail: string; tone?: 'neutral' | 'good' | 'warn' | 'bad' }) {
  const border = tone === 'bad' ? 'border-red-500/40' : tone === 'warn' ? 'border-amber-500/40' : tone === 'good' ? 'border-emerald-500/40' : 'border-gray-800';
  return (
    <div className={`rounded-lg border ${border} bg-gray-950 p-4`}>
      <div className="text-3xl font-semibold text-white">{value}</div>
      <div className="mt-2 text-sm font-semibold text-gray-200">{title}</div>
      <div className="mt-1 text-xs text-gray-500">{detail}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/40">
      <header className="border-b border-gray-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </header>
      {children}
    </section>
  );
}

function StatusPill({ value }: { value: string }) {
  const text = value || 'unknown';
  const lower = text.toLowerCase();
  const tone = lower.includes('critical') || lower.includes('p0') || lower.includes('p1') || lower.includes('alert') || lower.includes('high')
    ? 'border-red-500/40 bg-red-950/40 text-red-100'
    : lower.includes('ready') || lower.includes('ok') || lower.includes('enabled') || lower.includes('complete')
      ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-100'
      : lower.includes('warn') || lower.includes('missing') || lower.includes('medium')
        ? 'border-amber-500/40 bg-amber-950/30 text-amber-100'
        : 'border-gray-700 bg-gray-950 text-gray-300';
  return <span className={`inline-flex rounded border px-2 py-1 text-[11px] ${tone}`}>{text}</span>;
}

function Bar({ label, value, max }: { label: string; value: number; max: number }) {
  return (
    <div>
      <div className="mb-1 flex justify-between gap-2 text-xs">
        <span className="truncate text-gray-300">{label}</span>
        <span className="font-mono text-white">{value}</span>
      </div>
      <div className="h-2 rounded bg-gray-900"><div className="h-2 rounded bg-sky-400" style={{ width: `${Math.max(4, (value / max) * 100)}%` }} /></div>
    </div>
  );
}

type AssetTtpCoverageItem = {
  id: string;
  name: string;
  assets: Set<string>;
  alerts: number;
  sources: Set<string>;
  score: number;
};

function buildSummary(alerts: AlertRow[], assets: ThreatSpaceAsset[], monitors: ThreatSpaceMonitor[]) {
  const open = alerts.filter(alert => !['resolved', 'false_positive', 'suppressed'].includes(String(alert.status || '').toLowerCase()));
  return {
    openAlerts: open.length,
    highPriority: open.filter(alert => /p0|p1|critical|high/i.test(`${alert.priority} ${alert.severity}`)).length,
    assets: assets.length,
    internetFacing: assets.filter(asset => /internet|external|public/i.test(`${asset.exposure} ${asset.tags.join(' ')}`)).length,
    enabledMonitors: monitors.filter(monitor => monitor.enabled).length,
    alertingMonitors: monitors.filter(monitor => /alert|warning/i.test(monitor.last_status || '')).length,
  };
}

function buildAssetTtpCoverage(assets: ThreatSpaceAsset[], alerts: AlertRow[]) {
  const byTechnique = new Map<string, AssetTtpCoverageItem>();
  const assetLookup = buildAssetLookup(assets);
  const add = (ttp: string, assetName: string, source: string, name = '', alertBacked = false) => {
    const id = normalizeTtp(ttp);
    if (!id) return;
    const current = byTechnique.get(id) ?? { id, name: name || id, assets: new Set<string>(), alerts: 0, sources: new Set<string>(), score: 0 };
    if (name && current.name === id) current.name = name;
    if (assetName) current.assets.add(assetName);
    current.sources.add(source);
    if (alertBacked) current.alerts += 1;
    current.score = current.assets.size + current.alerts * 2 + current.sources.size;
    byTechnique.set(id, current);
  };

  assets.forEach(asset => {
    const extracted = extractTtpsFromAsset(asset);
    extracted.forEach(item => add(item.id, asset.name, item.source, item.name, false));
  });

  alerts.forEach(alert => {
    const assetNames = resolveAlertAssets(alert, assetLookup);
    if (!assetNames.length) return;
    const ttps = collectEvidenceValues(alert).filter(item => item.type === 'ttp').map(item => item.value);
    ttps.forEach(ttp => {
      assetNames.forEach(assetName => add(ttp, assetName, 'alert-evidence', '', true));
    });
  });

  const topTechniques = Array.from(byTechnique.values()).sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return {
    assetCount: assets.length,
    byTechnique,
    topTechniques,
    alertBackedCount: topTechniques.filter(item => item.alerts > 0).length,
  };
}

function buildTechniqueNameLookup(matrixData: MatrixData) {
  const lookup = new Map<string, string>();
  matrixData.techniquesByTactic.forEach(techniques => {
    techniques.forEach(technique => lookup.set(technique.attack_id, technique.name));
  });
  matrixData.subtechsByParent.forEach(techniques => {
    techniques.forEach(technique => lookup.set(technique.attack_id, technique.name));
  });
  return lookup;
}

function buildAssetLookup(assets: ThreatSpaceAsset[]) {
  const lookup = new Map<string, string>();
  assets.forEach(asset => {
    [
      asset.id,
      asset.asset_id,
      asset.name,
      ...asset.products,
      ...asset.components,
      ...asset.technologies,
      ...asset.domains,
      ...asset.ip_addresses,
    ].forEach(value => {
      const key = String(value || '').trim().toLowerCase();
      if (key) lookup.set(key, asset.name);
    });
  });
  return lookup;
}

function resolveAlertAssets(alert: AlertRow, assetLookup: Map<string, string>) {
  const names = new Set<string>();
  const add = (raw: unknown) => {
    const value = String(raw || '').trim();
    if (!value) return;
    const mapped = assetLookup.get(value.toLowerCase());
    if (mapped) names.add(mapped);
  };
  add(alert.asset_uuid);
  add(alert.asset_id);
  add(alert.asset_name);
  const matches = Array.isArray(alert.matches) ? alert.matches : [];
  matches.forEach(match => {
    if (!match || typeof match !== 'object') return;
    const record = match as Record<string, unknown>;
    add(record.asset_id);
    add(record.asset_uuid);
    add(record.asset_name);
    add(record.inventory_entity);
    add(record.signal_entity);
  });
  return Array.from(names);
}

function extractTtpsFromAsset(asset: ThreatSpaceAsset) {
  const values: Array<{ id: string; name: string; source: string }> = [];
  const add = (raw: unknown, source: string, name = '') => {
    const id = normalizeTtp(String(raw || ''));
    if (!id) return;
    if (!values.some(item => item.id === id)) values.push({ id, name, source });
  };

  asset.tags.forEach(tag => add(tag, 'asset-tag'));
  extractTtpsFromUnknown(asset.metadata, add);
  inferTtpsFromAssetProfile(asset).forEach(item => add(item.id, item.source, item.name));
  return values;
}

function inferTtpsFromAssetProfile(asset: ThreatSpaceAsset) {
  const text = assetSearchText(asset);
  const exposure = `${asset.exposure} ${asset.environment}`.toLowerCase();
  const hasAny = (...needles: string[]) => needles.some(needle => text.includes(needle));
  const isInternet = /internet|external|public|customer/.test(exposure) || asset.domains.length > 0;
  const hasPort = (...ports: number[]) => ports.some(port => text.includes(`:${port}`) || text.includes(` ${port} `) || text.includes(`tcp/${port}`));
  const out: Array<{ id: string; name: string; source: string }> = [];
  const add = (id: string, name: string, condition: boolean) => {
    if (condition && !out.some(item => item.id === id)) out.push({ id, name, source: 'asset-profile-inference' });
  };

  add('T1595', 'Active Scanning', isInternet);
  add('T1592', 'Gather Victim Host Information', isInternet || hasAny('product', 'firmware', 'version', 'cpe', 'purl'));
  add('T1580', 'Cloud Infrastructure Discovery', hasAny('cloud', 'aws', 'azure', 'gcp', 'kubernetes', 'container', 'ngc'));

  add('T1190', 'Exploit Public-Facing Application', isInternet || hasAny('web', 'api', 'nginx', 'apache', 'http', 'portal', 'redfish', 'bmc'));
  add('T1133', 'External Remote Services', isInternet && hasAny('vpn', 'sso', 'okta', 'citrix', 'rdp', 'ssh', 'remote', 'gateway'));
  add('T1110', 'Brute Force', hasAny('login', 'auth', 'sso', 'vpn', 'ldap', 'kerberos', 'ssh', 'rdp') || hasPort(22, 3389, 389, 443));
  add('T1078', 'Valid Accounts', hasAny('identity', 'auth', 'sso', 'ldap', 'kerberos', 'admin', 'service account', 'ci', 'runner', 'registry'));
  add('T1556', 'Modify Authentication Process', hasAny('identity', 'sso', 'okta', 'ldap', 'kerberos', 'auth gateway'));
  add('T1558', 'Steal or Forge Kerberos Tickets', hasAny('active-directory', 'kerberos', 'ldap', 'domain controller', 'ad-'));
  add('T1021', 'Remote Services', hasAny('ssh', 'rdp', 'smb', 'winrm', 'remote admin') || hasPort(22, 445, 3389, 5900, 5985, 5986));

  add('T1005', 'Data from Local System', hasAny('database', 'postgres', 'mysql', 'redis', 'elastic', 'storage', 'backup', 'artifact', 'registry', 'source'));
  add('T1530', 'Data from Cloud Storage', hasAny('s3', 'blob', 'bucket', 'cloud storage', 'object storage', 'backup'));
  add('T1552', 'Unsecured Credentials', hasAny('ci', 'runner', 'pipeline', 'build', 'secret', 'token', 'key', 'hsm', 'registry', 'backup', 'config'));

  add('T1195', 'Supply Chain Compromise', hasAny('ci', 'cd', 'build', 'runner', 'artifact', 'registry', 'sbom', 'dependency', 'supplier', 'package', 'purl', 'container image'));
  add('T1608', 'Stage Capabilities', hasAny('build', 'release', 'artifact', 'registry', 'signing', 'container image', 'package', 'sbom', 'dependency', 'purl'));
  add('T1059', 'Command and Scripting Interpreter', hasAny('runner', 'build', 'pipeline', 'script', 'shell', 'powershell', 'bash', 'python', 'nodejs'));
  add('T1105', 'Ingress Tool Transfer', hasAny('artifact', 'registry', 'package', 'download', 'update', 'firmware', 'container image', 'ngc'));

  add('T1611', 'Escape to Host', hasAny('container', 'docker', 'kubernetes', 'containerd', 'runtime', 'ngc'));
  add('T1610', 'Deploy Container', hasAny('kubernetes', 'container', 'container image', 'oci', 'registry'));
  add('T1525', 'Implant Internal Image', hasAny('container image', 'oci', 'registry', 'ngc', 'base image'));

  add('T1068', 'Exploitation for Privilege Escalation', hasAny('kernel', 'driver', 'firmware', 'bmc', 'redfish', 'ipmi', 'cuda', 'gpu driver', 'dpu', 'bluefield', 'jetson', 'igx', 'openssl'));
  add('T1542', 'Pre-OS Boot', hasAny('firmware', 'bootloader', 'uefi', 'secure boot', 'bmc', 'dpu firmware', 'nic firmware'));
  add('T1562', 'Impair Defenses', hasAny('edr', 'agent', 'kernel', 'driver', 'firmware', 'bmc', 'management plane'));
  add('T1200', 'Hardware Additions', hasAny('prototype', 'hardware', 'board', 'jetson', 'igx', 'bluefield', 'connectx', 'dpu', 'gpu'));

  add('T1496', 'Resource Hijacking', hasAny('gpu', 'cuda', 'kubernetes', 'cluster', 'container', 'cloud', 'compute'));
  add('T1486', 'Data Encrypted for Impact', hasAny('backup', 'storage', 'database', 'artifact registry', 'source repository'));
  return out;
}

function assetSearchText(asset: ThreatSpaceAsset) {
  return [
    asset.id,
    asset.asset_id,
    asset.name,
    asset.asset_type,
    asset.environment,
    asset.owner,
    asset.criticality,
    asset.exposure,
    ...asset.products,
    ...asset.components,
    ...asset.technologies,
    ...asset.ip_addresses,
    ...asset.domains,
    ...asset.tags,
    flattenUnknown(asset.metadata).join(' '),
  ].join(' ').toLowerCase();
}

function flattenUnknown(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(flattenUnknown);
  if (value && typeof value === 'object') return Object.entries(value as Record<string, unknown>).flatMap(([key, item]) => [key, ...flattenUnknown(item)]);
  if (value === null || value === undefined) return [];
  return [String(value)];
}

function extractTtpsFromUnknown(value: unknown, add: (raw: unknown, source: string, name?: string) => void) {
  if (Array.isArray(value)) {
    value.forEach(item => extractTtpsFromUnknown(item, add));
    return;
  }
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const source = Object.prototype.hasOwnProperty.call(record, 'reason') ? 'asset-surface-candidate' : 'asset-metadata';
    add(record.attack_id, source, String(record.name || ''));
    add(record.technique_id, source, String(record.name || ''));
    add(record.ttp, source, String(record.name || ''));
    add(record.mitre_attack_id, source, String(record.name || ''));
    Object.values(record).forEach(item => extractTtpsFromUnknown(item, add));
    return;
  }
  if (typeof value === 'string') {
    const matches = value.match(/\bT\d{4}(?:\.\d{3})?\b/gi) ?? [];
    matches.forEach(match => add(match, 'asset-metadata'));
  }
}

function normalizeTtp(value: string) {
  const match = value.toUpperCase().match(/\bT\d{4}(?:\.\d{3})?\b/);
  return match?.[0] ?? '';
}

function filterAlertRows(rows: AlertRow[], statusFilter: string) {
  if (statusFilter === 'all') return rows;
  if (statusFilter === 'open') {
    return rows.filter(row => !['resolved', 'false_positive', 'suppressed'].includes(String(row.status || '').toLowerCase()));
  }
  return rows.filter(row => String(row.status || '').toLowerCase() === statusFilter.toLowerCase());
}

function buildFeedCoverage(cveSources: CVESourceStatus[], threatSources: Array<{ enabled: boolean }>, exposureProviders: ThreatExposureProvider[]) {
  const total = cveSources.length + threatSources.length + exposureProviders.length;
  const ready = cveSources.filter(item => item.enabled).length
    + threatSources.filter(item => item.enabled).length
    + exposureProviders.filter(item => item.configured || item.enabled).length;
  return { total, ready };
}

function collectEvidenceValues(row: AlertRow): Array<{ value: string; type: string }> {
  const out: Array<{ value: string; type: string }> = [];
  const add = (raw: unknown, type = 'tag') => {
    const value = String(raw || '').trim();
    if (!value || value === '-') return;
    const inferred = inferEntityType(value, type);
    if (!out.some(item => item.value.toLowerCase() === value.toLowerCase() && item.type === inferred)) {
      out.push({ value, type: inferred });
    }
  };
  (row.matched_terms || []).forEach(item => add(item));
  ['cve_ids', 'technique_ids', 'actors', 'iocs', 'matched_iocs', 'tags'].forEach(key => {
    const value = row[key];
    if (Array.isArray(value)) value.forEach(item => typeof item === 'object' && item ? add((item as Record<string, unknown>).value ?? (item as Record<string, unknown>).id ?? JSON.stringify(item)) : add(item));
  });
  const matches = Array.isArray(row.matches) ? row.matches : [];
  matches.forEach(match => {
    if (!match || typeof match !== 'object') return;
    const record = match as Record<string, unknown>;
    add(record.signal_entity);
    add(record.inventory_entity);
    add(record.asset_id, 'asset');
  });
  return out;
}

function inferEntityType(value: string, fallback: string) {
  if (/^CVE-\d{4}-\d{4,}$/i.test(value)) return 'cve';
  if (/^T\d{4}(?:\.\d{3})?$/i.test(value)) return 'ttp';
  if (/^G\d{4}$/i.test(value) || /^APT\d+/i.test(value)) return 'actor';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes('@') || /^[a-f0-9]{32,}$/i.test(value)) return 'ioc';
  return fallback;
}

function entityHref(value: string, type: string) {
  const encoded = encodeURIComponent(value);
  if (type === 'cve') return `/cve?search=${encoded}`;
  if (type === 'ttp') return `/navigator?technique=${encoded}`;
  if (type === 'actor') return `/apt?search=${encoded}`;
  if (type === 'ioc') return `/ioc-library?search=${encoded}`;
  return '';
}

function formatDate(value: unknown) {
  if (!value) return '';
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}
