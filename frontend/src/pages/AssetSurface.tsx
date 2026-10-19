import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import type { Edge, Node } from '@xyflow/react';
import { useDropzone } from 'react-dropzone';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { EntityGraph } from '@/components/ui/graph';
import { PermissionNotice } from '@/components/PermissionNotice';
import { assetSurfaceApi, layersApi, threatRadarApi } from '@/api/client';
import type { AssetIntelMatch, AssetRegistryItem, AssetSurfaceAnalysisResult, AssetSurfaceAsset, ThreatAssetIntelligence, ThreatCompanySpace, ThreatSpaceAsset } from '@/api/client';
import { IocLink, TtpLink } from '@/utils/ctiLinks';
import { useAppStore } from '@/store';
import { safeInternalHref } from '@/utils/url';
import { useHasPermission } from '@/hooks/useCurrentUser';

type Provider = 'claude' | 'openai' | 'gemini' | 'minimax' | 'local';

const PROVIDERS: { id: Provider; label: string }[] = [
  { id: 'local', label: 'Local' },
  { id: 'claude', label: 'Claude' },
  { id: 'openai', label: 'OpenAI' },
  { id: 'gemini', label: 'Gemini' },
  { id: 'minimax', label: 'MiniMax' },
];

const RETROHUNT_VISIBLE_ROWS = 5;
const RETROHUNT_MAX_RENDERED_ROWS = 100;
const RETROHUNT_ROW_HEIGHT_PX = 112;
const RETROHUNT_HEADER_HEIGHT_PX = 40;

const SAMPLE = `asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags
asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80;443;8443","nginx;nodejs;postgres",internet,critical,"customer-data;pci"
asset-0002,vpn-gateway,remote-access,prod,IT,198.51.100.20,vpn.example.com,"443;500;4500","vpn;sso;mfa",internet,high,"remote-access;identity-edge"
asset-0003,ad-dc-01,identity,prod,IT,10.10.1.10,ad01.corp.local,"53;88;135;389;445","active-directory;windows;kerberos;ldap",internal,critical,"identity;tier-0"
asset-0004,postgres-payments,database,prod,Payments,10.20.5.15,,"5432","postgresql;linux",internal,critical,"database;payments"`;

function linkedRecordId(value: string | null): string {
  const normalized = value?.trim() ?? '';
  return normalized.length <= 128 ? normalized : '';
}

export function AssetSurface() {
  const canManage = useHasPermission('manage_intel');
  const canExport = useHasPermission('export_data');
  const canUploadFiles = useHasPermission('upload_files');
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const linkedAssetId = linkedRecordId(searchParams.get('asset') || searchParams.get('asset_id'));
  const queryClient = useQueryClient();
  const { domain, addComparisonLayer, clearComparisonLayers, clearTechniques } = useAppStore();
  const [provider, setProvider] = useState<Provider>('local');
  const [useAi, setUseAi] = useState(true);
  const [inventoryName, setInventoryName] = useState('External asset inventory');
  const [companySpaceId, setCompanySpaceId] = useState('');
  const [text, setText] = useState(SAMPLE);
  const [files, setFiles] = useState<File[]>([]);
  const [result, setResult] = useState<AssetSurfaceAnalysisResult | null>(null);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState('all');
  const [exposureFilter, setExposureFilter] = useState('all');
  const [graphAssetId, setGraphAssetId] = useState('');

  const casesQuery = useQuery({
    queryKey: ['asset-surface-cases'],
    queryFn: assetSurfaceApi.cases,
  });
  const spacesQuery = useQuery({
    queryKey: ['threat-radar-spaces'],
    queryFn: threatRadarApi.spaces,
  });
  const assetsQuery = useQuery({
    queryKey: ['asset-registry-assets'],
    queryFn: assetSurfaceApi.assets,
  });
  const matchesQuery = useQuery({
    queryKey: ['asset-intel-matches'],
    queryFn: () => assetSurfaceApi.intelMatches({ limit: 100 }),
  });
  const mutation = useMutation({
    mutationFn: (form: FormData) => assetSurfaceApi.analyze(form),
    onSuccess: nextResult => {
      setResult(nextResult);
      setActiveCaseId(nextResult.case_id ?? null);
      queryClient.invalidateQueries({ queryKey: ['asset-surface-cases'] });
      queryClient.invalidateQueries({ queryKey: ['asset-registry-assets'] });
      queryClient.invalidateQueries({ queryKey: ['asset-intel-matches'] });
      queryClient.invalidateQueries({ queryKey: ['threat-radar-spaces'] });
      queryClient.invalidateQueries({ queryKey: ['threat-radar-space-metrics'] });
      if (companySpaceId) {
        queryClient.invalidateQueries({ queryKey: ['threat-radar-space', companySpaceId] });
        queryClient.invalidateQueries({ queryKey: ['threat-radar-space-assets', companySpaceId] });
      }
    },
  });
  const loadCase = useMutation({
    mutationFn: (caseId: string) => assetSurfaceApi.case(caseId),
    onSuccess: savedCase => {
      setResult(savedCase);
      setActiveCaseId(savedCase.case_id ?? null);
      setInventoryName(savedCase.inventory_name || savedCase.case_name || savedCase.filename || 'Asset surface case');
      setFiles([]);
      setText('');
    },
  });
  const deleteCase = useMutation({
    mutationFn: (caseId: string) => assetSurfaceApi.deleteCase(caseId),
    onSuccess: (_data, caseId) => {
      if (activeCaseId === caseId) {
        setResult(null);
        setActiveCaseId(null);
      }
      queryClient.invalidateQueries({ queryKey: ['asset-surface-cases'] });
    },
  });
  const saveLayer = useMutation({
    mutationFn: (ids: string[]) => layersApi.save(`${inventoryName || 'Asset surface'} TTP layer`, ids, domain),
  });
  const retrohunt = useMutation({
    mutationFn: () => assetSurfaceApi.retrohunt(),
    onSuccess: summary => {
      setResult(prev => prev ? { ...prev, retrohunt_summary: summary } : prev);
      queryClient.invalidateQueries({ queryKey: ['asset-intel-matches'] });
      queryClient.invalidateQueries({ queryKey: ['asset-registry-assets'] });
    },
  });

  const onDrop = (nextFiles: File[]) => {
    if (!canManage || !canUploadFiles || !nextFiles.length) return;
    setFiles(nextFiles);
    setText('');
    setInventoryName(nextFiles.length === 1 ? nextFiles[0].name.replace(/\.[^.]+$/, '') : `${nextFiles.length} asset inventory files`);
  };

  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    onDrop,
    disabled: !canManage || !canUploadFiles,
    multiple: true,
    maxFiles: 20,
    accept: {
      'text/csv': ['.csv'],
      'application/json': ['.json'],
      'text/plain': ['.txt', '.tsv', '.log'],
    },
  });

  useEffect(() => {
    const linkedSpaceId = searchParams.get('space_id')?.trim() || '';
    if (linkedSpaceId && linkedSpaceId !== companySpaceId) {
      setCompanySpaceId(linkedSpaceId);
    }
  }, [companySpaceId, searchParams]);

  const filteredAssets = useMemo(() => {
    return (result?.assets ?? []).filter(asset => {
      const riskOk = riskFilter === 'all' || asset.risk_level === riskFilter || asset.ai_risk_level === riskFilter;
      const exposureOk = exposureFilter === 'all' || asset.exposure === exposureFilter;
      return riskOk && exposureOk;
    });
  }, [result?.assets, riskFilter, exposureFilter]);

  const linkedAsset = useMemo(() => (assetsQuery.data ?? []).find(asset => (
    asset.id === linkedAssetId || asset.inventory_asset_id === linkedAssetId
  )), [assetsQuery.data, linkedAssetId]);

  const allTtpIds = useMemo(() => {
    return Array.from(new Set((result?.assets ?? []).flatMap(asset => asset.ttp_candidates.map(ttp => ttp.attack_id.toUpperCase())))).sort();
  }, [result?.assets]);

  const visibleMatches = useMemo(() => {
    const fromResult = result?.intel_matches ?? [];
    return fromResult.length ? fromResult : (matchesQuery.data ?? []);
  }, [matchesQuery.data, result?.intel_matches]);
  const resultCompanySpaceId = result?.company_space_id?.trim() || '';
  const companyAssetsQuery = useQuery({
    queryKey: ['threat-radar-space-assets', resultCompanySpaceId, 'asset-surface-links'],
    queryFn: () => threatRadarApi.spaceAssets(resultCompanySpaceId, { limit: 500 }),
    enabled: Boolean(resultCompanySpaceId),
  });
  const companyAssetByInventoryId = useMemo(
    () => new Map(
      (companyAssetsQuery.data?.items ?? []).map(asset => [asset.asset_id.toLowerCase(), asset]),
    ),
    [companyAssetsQuery.data?.items],
  );

  useEffect(() => {
    const assets = result?.assets ?? [];
    if (!assets.length) {
      setGraphAssetId('');
      return;
    }
    if (!assets.some(asset => asset.asset_id === graphAssetId)) {
      setGraphAssetId(assets[0].asset_id);
    }
  }, [graphAssetId, result?.assets]);

  const graphAsset = useMemo(
    () => (result?.assets ?? []).find(asset => asset.asset_id === graphAssetId),
    [graphAssetId, result?.assets],
  );
  const registryAssetByInventoryId = useMemo(
    () => new Map((assetsQuery.data ?? []).map(asset => [asset.inventory_asset_id.toLowerCase(), asset])),
    [assetsQuery.data],
  );
  const graphRegistryAsset = graphAsset
    ? registryAssetByInventoryId.get(graphAsset.asset_id.toLowerCase())
    : undefined;
  const graphCompanyAsset = graphAsset
    ? companyAssetByInventoryId.get(graphAsset.asset_id.toLowerCase())
    : undefined;

  const run = () => {
    if (!canManage || (files.length > 0 && !canUploadFiles)) return;
    const form = new FormData();
    form.append('provider', provider);
    form.append('use_ai', String(useAi));
    form.append('inventory_name', inventoryName);
    if (companySpaceId) form.append('company_space_id', companySpaceId);
    if (files.length) files.forEach(item => form.append('files', item));
    else form.append('text', text);
    mutation.mutate(form);
  };

  const canRun = canManage && !mutation.isPending && ((files.length > 0 && canUploadFiles) || text.trim().length > 0);
  const addWhiteAssetLayer = (replace = false) => {
    if (!allTtpIds.length) return;
    if (replace) {
      clearTechniques();
      clearComparisonLayers();
    }
    addComparisonLayer({
      name: `${inventoryName || 'Asset inventory'} TTPs`,
      techniqueIds: allTtpIds,
      source: 'asset-surface',
      color: '#ffffff',
    });
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Asset Attack Surface" />
      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-y-auto xl:grid-cols-[400px_minmax(0,1fr)] xl:overflow-hidden">
        <aside className="flex min-h-0 flex-col overflow-y-auto border-r border-gray-700">
          {!canManage&&<section className="border-b border-gray-800 p-4"><PermissionNotice permission="manage_intel" action="analyze inventory, create asset cases, or save server-side layers" compact /></section>}
          <section className="border-b border-gray-800 p-4">
            <label className="label">Inventory Name</label>
            <input disabled={!canManage} className="field" value={inventoryName} onChange={event => setInventoryName(event.target.value)} />
          </section>

          <section className="border-b border-gray-800 p-4">
            <label className="label">Target Company Space</label>
            <select disabled={!canManage} className="field" value={companySpaceId} onChange={event => setCompanySpaceId(event.target.value)}>
              <option value="">No company space - analyze only</option>
              {(spacesQuery.data ?? []).map((space: ThreatCompanySpace) => (
                <option key={space.id} value={space.id}>
                  {space.name} ({space.counts.assets ?? 0} assets)
                </option>
              ))}
            </select>
            <p className="mt-2 text-xs leading-5 text-gray-500">
              Choose a Threat Radar company space to store this upload as private monitored assets. The asset-surface case is still saved normally.
            </p>
          </section>

          <section className="border-b border-gray-800 p-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">AI Provider</div>
            <div className="grid grid-cols-1 gap-1.5">
              {PROVIDERS.map(item => (
                <button
                  key={item.id}
                  type="button"
                  disabled={!canManage}
                  onClick={() => setProvider(item.id)}
                  className={`flex items-center justify-between rounded border px-3 py-2 text-xs ${
                    provider === item.id ? 'border-mitre-accent bg-mitre-accent/20 text-white' : 'border-gray-700 text-gray-500 hover:text-gray-300'
                  }`}
                >
                  <span>{item.label}</span>
                  <span className="text-[10px] opacity-70">server-selected model</span>
                </button>
              ))}
            </div>
            <label className="mt-3 flex items-start gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
              <input disabled={!canManage} type="checkbox" checked={useAi} onChange={event => setUseAi(event.target.checked)} />
              <span>Use AI enrichment for attack paths, control gaps, assumptions, and validation gaps. Baseline scoring still runs without AI.</span>
            </label>
          </section>

          <section className="flex min-h-0 flex-1 flex-col p-4">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">Inventory Input</div>
            <textarea
              disabled={!canManage}
              rows={5}
              value={text}
              onChange={event => {
                setText(event.target.value);
                setFiles([]);
              }}
              className="min-h-0 flex-none resize-none overflow-y-auto rounded border border-gray-700 bg-gray-900 px-3 py-2 font-mono text-xs leading-5 text-gray-200 outline-none focus:border-mitre-accent"
              placeholder="Paste CSV, JSON, hostname/IP list, CMDB export, cloud inventory, or scanner output"
            />
            <div
              {...getRootProps()}
              className={`mt-3 cursor-pointer rounded border-2 border-dashed p-4 text-center text-xs transition-colors ${
                isDragActive ? 'border-mitre-accent bg-mitre-accent/10' : 'border-gray-700 text-gray-600 hover:border-gray-500'
              }`}
            >
              <input {...getInputProps()} />
              {files.length ? (
                <span className="text-gray-300">{files.length} inventory file{files.length === 1 ? '' : 's'} selected</span>
              ) : (
                <span>Drop one or more CSV / JSON / TXT inventories or click</span>
              )}
            </div>
            {!canUploadFiles && <div className="mt-3"><PermissionNotice permission="upload_files" action="upload asset inventory files" compact /></div>}
            {files.length > 0 && (
              <div className="mt-3 max-h-28 overflow-y-auto rounded border border-gray-800 bg-gray-950 p-2 text-xs text-gray-400">
                {files.map(item => (
                  <div key={`${item.name}-${item.size}`} className="flex items-center justify-between gap-3 border-b border-gray-900 py-1 last:border-b-0">
                    <span className="truncate">{item.name}</span>
                    <span className="shrink-0 text-gray-600">{Math.ceil(item.size / 1024)} KB</span>
                  </div>
                ))}
              </div>
            )}
            <button type="button" disabled={!canManage || !canUploadFiles} onClick={open} className="secondary-action mt-3 min-h-10 w-full disabled:opacity-40">
              Upload inventory files
            </button>
            <button type="button" disabled={!canManage || !canRun} onClick={run} className="primary mt-4 disabled:opacity-50">
              {mutation.isPending ? 'Building matrix...' : 'Analyze Attack Surface'}
            </button>
            {mutation.error && (
              <div className="mt-3 rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">
                {String(mutation.error)}
              </div>
            )}
          </section>

          <section className="min-h-0 border-t border-gray-800 p-4">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-xs font-semibold uppercase tracking-wide text-gray-500">Saved Cases</div>
              <span className="text-[10px] text-gray-600">{casesQuery.data?.length ?? 0}</span>
            </div>
            <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
              {(casesQuery.data ?? []).map(item => (
                <div
                  key={item.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => {
                    loadCase.mutate(item.id);
                  }}
                  onKeyDown={event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      loadCase.mutate(item.id);
                    }
                  }}
                  className={`w-full rounded border p-2 text-left text-xs ${
                    activeCaseId === item.id
                      ? 'border-mitre-accent bg-mitre-accent/10'
                      : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <b className="block truncate text-gray-200">{item.name}</b>
                      <span className="mt-1 block text-[10px] text-gray-600">{new Date(item.created_at).toLocaleString()}</span>
                    </div>
                    {canManage&&<button
                      type="button"
                      onClick={event => {
                        event.stopPropagation();
                        deleteCase.mutate(item.id);
                      }}
                      disabled={deleteCase.isPending}
                      className="text-[10px] text-gray-600 hover:text-red-300 disabled:opacity-40"
                    >
                      delete
                    </button>}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1 text-[10px]">
                    <Chip>{item.asset_count} assets</Chip>
                    <Chip>{item.technique_ids.length} TTPs</Chip>
                    <Chip>{item.high_or_critical_count} high/critical</Chip>
                  </div>
                </div>
              ))}
              {casesQuery.isLoading && (
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-600">
                  Loading saved asset-surface cases...
                </div>
              )}
              {casesQuery.error && (
                <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">
                  {String(casesQuery.error)}
                </div>
              )}
              {!casesQuery.isLoading && !casesQuery.data?.length && (
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-600">
                  Completed asset analyses will be saved as cases.
                </div>
              )}
              {loadCase.error && <div className="rounded border border-red-900 bg-red-950/30 p-3 text-xs text-red-300">{String(loadCase.error)}</div>}
            </div>
          </section>
        </aside>

        <main className="min-h-0 overflow-y-auto p-4 lg:p-6">
          {linkedAssetId && (
            <LinkedRegistryAsset
              asset={linkedAsset}
              assetId={linkedAssetId}
              error={assetsQuery.error}
              loading={assetsQuery.isLoading}
            />
          )}
          {!result ? (
            <EmptyState />
          ) : (
            <div className="mx-auto max-w-7xl space-y-5">
              <section className="flex flex-wrap items-center justify-between gap-3 rounded border border-gray-800 bg-gray-950 p-4">
                <div>
                  <div className="text-sm font-semibold text-white">Attack Surface TTP Layer</div>
                  <p className="mt-1 text-xs text-gray-500">{allTtpIds.length} unique ATT&amp;CK candidates mapped from inventory exposure and AI context.</p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" disabled={!allTtpIds.length} onClick={() => addWhiteAssetLayer(false)} className="secondary-action disabled:opacity-40">Add White Layer</button>
                  <button type="button" disabled={!allTtpIds.length} onClick={() => { addWhiteAssetLayer(true); navigate('/navigator'); }} className="primary-action disabled:opacity-40">Open Matrix</button>
                  {canManage&&<button type="button" disabled={!allTtpIds.length || saveLayer.isPending} onClick={() => saveLayer.mutate(allTtpIds)} className="secondary-action disabled:opacity-40">
                    {saveLayer.isPending ? 'Saving...' : 'Save Layer'}
                  </button>}
                  {canExport&&<button type="button" onClick={() => downloadJson(result, `${slug(inventoryName || 'asset-surface')}-matrix.json`)} className="secondary-action">Export JSON</button>}
                </div>
                {saveLayer.data && <div className="w-full text-xs text-green-400">Saved layer: {saveLayer.data.name}</div>}
                {saveLayer.error && <div className="w-full text-xs text-red-300">{String(saveLayer.error)}</div>}
              </section>

              <section className="grid gap-3 lg:grid-cols-4">
                <Metric label="Assets" value={result.asset_count} />
                <Metric label="Internet Facing" value={result.exposure_counts.internet ?? 0} />
                <Metric label="High / Critical" value={(result.risk_counts.high ?? 0) + (result.risk_counts.critical ?? 0)} />
                <Metric label="Provider" value={result.provider ?? 'baseline'} compact />
              </section>

              <section className="grid gap-3 lg:grid-cols-5">
                <Metric label="Saved Registry Assets" value={assetsQuery.data?.length ?? result.registry_summary?.asset_ids?.length ?? 0} />
                <Metric label="Created / Updated" value={`${result.registry_summary?.created ?? 0} / ${result.registry_summary?.updated ?? 0}`} compact />
                <Metric label="Space Assets Synced" value={result.company_space_assets_synced ?? 0} />
                <Metric label="Retrohunt Matches" value={result.retrohunt_summary?.matches_created ?? visibleMatches.length ?? 0} />
                <div className="rounded border border-gray-800 bg-gray-950 p-4">
                  <button type="button" disabled={retrohunt.isPending} onClick={() => retrohunt.mutate()} className="primary-action w-full disabled:opacity-40">
                    {retrohunt.isPending ? 'Retrohunting...' : 'Retrohunt Saved Assets'}
                  </button>
                  <p className="mt-2 text-[11px] leading-5 text-gray-500">
                    Rechecks saved assets against current CVEs, actor techniques, and report intake.
                  </p>
                </div>
              </section>

              <Panel title="Asset Inventory Intelligence Graph">
                <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
                  <div className="max-w-3xl">
                    <p className="text-xs leading-5 text-gray-400">
                      Select an analyzed asset to view its observed attack surface and the CVE, IOC, ATT&amp;CK technique,
                      and threat-group leads already correlated by Threat Radar. Dashed relationships are hypotheses for
                      analyst validation; inventory addresses and exposure fields are observations, not proof of compromise.
                    </p>
                  </div>
                  <label className="min-w-[260px] text-xs text-gray-500">
                    Asset
                    <select className="field mt-1" value={graphAssetId} onChange={event => setGraphAssetId(event.target.value)}>
                      {result.assets.map(asset => (
                        <option key={asset.asset_id} value={asset.asset_id}>{asset.asset} · {asset.asset_id}</option>
                      ))}
                    </select>
                  </label>
                </div>
                {graphAsset ? (
                  <AssetInventoryIntelligenceGraph
                    asset={graphAsset}
                    companyAsset={graphCompanyAsset}
                    companySpaceId={resultCompanySpaceId}
                    registryAsset={graphRegistryAsset}
                  />
                ) : (
                  <div className="rounded border border-gray-800 bg-gray-950 p-4 text-xs text-gray-500">No analyzed asset is available for graphing.</div>
                )}
              </Panel>

              <Panel title="Asset Retrohunt Matches">
                <AssetIntelMatches matches={visibleMatches} loading={matchesQuery.isLoading || retrohunt.isPending} />
                {retrohunt.data && (
                  <div className="mt-3 text-xs text-green-400">
                    Retrohunt checked {retrohunt.data.assets_checked ?? 0} assets and created {retrohunt.data.matches_created ?? 0} matches.
                  </div>
                )}
                {retrohunt.error && <div className="mt-3 text-xs text-red-300">{String(retrohunt.error)}</div>}
              </Panel>

              <Panel title="Executive Summary">
                <p className="text-sm leading-6 text-gray-300">{result.summary}</p>
                <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                  {Object.entries(result.exposure_counts).map(([key, value]) => <Chip key={key}>{key}: {value}</Chip>)}
                  {Object.entries(result.risk_counts).map(([key, value]) => <Chip key={key}>{key}: {value}</Chip>)}
                </div>
              </Panel>

              <section className="grid gap-5 xl:grid-cols-[1fr_360px]">
                <Panel title="Attack Surface Matrix">
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <select className="field max-w-[180px]" value={riskFilter} onChange={event => setRiskFilter(event.target.value)}>
                      <option value="all">All risk</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                    <select className="field max-w-[180px]" value={exposureFilter} onChange={event => setExposureFilter(event.target.value)}>
                      <option value="all">All exposure</option>
                      <option value="internet">Internet</option>
                      <option value="internal">Internal</option>
                      <option value="third-party">Third-party</option>
                      <option value="unknown">Unknown</option>
                    </select>
                    <span className="text-xs text-gray-500">{filteredAssets.length} rows</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[1100px] text-left text-xs">
                      <thead className="border-b border-gray-800 text-gray-500">
                        <tr>
                          <th className="py-2 pr-3">Asset</th>
                          <th className="py-2 pr-3">Risk</th>
                          <th className="py-2 pr-3">Exposure</th>
                          <th className="py-2 pr-3">Entry Points</th>
                          <th className="py-2 pr-3">TTPs</th>
                          <th className="py-2 pr-3">Priority Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {filteredAssets.map(asset => {
                          const companyAsset = companyAssetByInventoryId.get(asset.asset_id.toLowerCase());
                          return (
                            <AssetRow
                              key={asset.asset_id}
                              asset={asset}
                              companySpaceId={resultCompanySpaceId}
                              companyAssetId={companyAsset?.id}
                              companyAssetLoading={companyAssetsQuery.isLoading}
                              onShowGraph={() => setGraphAssetId(asset.asset_id)}
                              selectedForGraph={graphAssetId === asset.asset_id}
                            />
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <div className="space-y-5">
                  <Panel title="Top Risks">
                    <div className="space-y-2">
                      {result.top_risks.slice(0, 6).map(asset => (
                        <div key={asset.asset_id} className="rounded border border-gray-800 bg-gray-950 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <b className="text-sm text-white">{asset.asset}</b>
                            <RiskBadge level={asset.risk_level} score={asset.risk_score} />
                          </div>
                          <p className="mt-2 text-xs leading-5 text-gray-500">{asset.attack_surface.join(', ')}</p>
                        </div>
                      ))}
                    </div>
                  </Panel>
                  <Panel title="Validation Gaps">
                    <List items={result.validation_gaps.length ? result.validation_gaps : ['Validate inventory with active scanner, cloud inventory, DNS, EDR, and firewall telemetry.']} />
                  </Panel>
                  <Panel title="Cross-Asset Findings">
                    <List items={result.cross_asset_findings.length ? result.cross_asset_findings : result.recommended_workflow} />
                  </Panel>
                  <Panel title="Assumptions">
                    <List items={result.assumptions.length ? result.assumptions : ['No AI assumptions returned. Treat inventory fields as unverified until scanner, CMDB, cloud, identity, and network telemetry confirm them.']} />
                  </Panel>
                </div>
              </section>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

function LinkedRegistryAsset({
  asset,
  assetId,
  error,
  loading,
}: {
  asset?: AssetRegistryItem;
  assetId: string;
  error: unknown;
  loading: boolean;
}) {
  if (loading) {
    return <section className="mx-auto mb-5 max-w-7xl rounded border border-cyan-900/70 bg-cyan-950/20 p-4 text-sm text-cyan-200">Loading linked registry asset...</section>;
  }
  if (error) {
    return <section className="mx-auto mb-5 max-w-7xl rounded border border-red-900 bg-red-950/30 p-4 text-sm text-red-300">Could not load linked registry asset: {String(error)}</section>;
  }
  if (!asset) {
    return (
      <section className="mx-auto mb-5 max-w-7xl rounded border border-yellow-800 bg-yellow-950/20 p-4 text-sm text-yellow-200">
        Registry asset <span className="font-mono">{assetId}</span> was not found in the active asset result. It may have been removed or excluded by the registry result limit.
      </section>
    );
  }

  return (
    <section className="mx-auto mb-5 max-w-7xl rounded border border-cyan-800/70 bg-cyan-950/10 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-wide text-cyan-400">Linked asset registry record</div>
          <h2 className="mt-1 text-lg font-semibold text-white">{asset.name}</h2>
          <div className="mt-1 font-mono text-[11px] text-gray-500">{asset.inventory_asset_id || asset.id}</div>
        </div>
        <RiskBadge level={asset.risk_level} score={asset.risk_score} />
      </div>
      <div className="mt-4 grid gap-3 text-xs sm:grid-cols-2 xl:grid-cols-5">
        <RegistryField label="Type" value={asset.asset_type || 'unknown'} />
        <RegistryField label="Environment" value={asset.environment || 'unknown'} />
        <RegistryField label="Owner" value={asset.owner || 'unassigned'} />
        <RegistryField label="Exposure" value={asset.exposure || 'unknown'} />
        <RegistryField label="Criticality" value={asset.criticality || 'unknown'} />
      </div>
      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <div>
          <div className="text-[10px] font-semibold uppercase text-gray-500">Observed addresses</div>
          <div className="mt-2 flex flex-wrap gap-2 font-mono text-xs text-cyan-300">
            {[...asset.domains, ...asset.ip_addresses].map(value => (
              <IocLink key={value} value={value} source="AssetSurface" className="hover:underline" />
            ))}
            {!asset.domains.length && !asset.ip_addresses.length && <span className="text-gray-600">None recorded</span>}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-semibold uppercase text-gray-500">Technologies and ports</div>
          <div className="mt-2 flex flex-wrap gap-1">
            {[...asset.technologies, ...asset.products, ...asset.ports.map(port => `port:${port}`)].map(value => <Chip key={value}>{value}</Chip>)}
            {!asset.technologies.length && !asset.products.length && !asset.ports.length && <span className="text-xs text-gray-600">None recorded</span>}
          </div>
        </div>
        <div>
          <div className="text-[10px] font-semibold uppercase text-gray-500">ATT&amp;CK candidates</div>
          <div className="mt-2 flex flex-wrap gap-1">
            {asset.technique_ids.map(techniqueId => (
              <TtpLink key={techniqueId} id={techniqueId} className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 text-[10px] font-semibold text-mitre-accent hover:bg-mitre-accent/20" />
            ))}
            {!asset.technique_ids.length && <span className="text-xs text-gray-600">None recorded</span>}
          </div>
        </div>
      </div>
    </section>
  );
}

function AssetInventoryIntelligenceGraph({
  asset,
  companyAsset,
  companySpaceId,
  registryAsset,
}: {
  asset: AssetSurfaceAsset;
  companyAsset?: ThreatSpaceAsset;
  companySpaceId: string;
  registryAsset?: AssetRegistryItem;
}) {
  const intelligence = useQuery({
    queryKey: ['threat-radar-asset-intelligence', companySpaceId, companyAsset?.id, 'asset-surface-graph'],
    queryFn: () => threatRadarApi.assetIntelligence(companySpaceId, companyAsset!.id),
    enabled: Boolean(companySpaceId && companyAsset?.id),
  });
  const registryMatches = useQuery({
    queryKey: ['asset-intel-matches', registryAsset?.id, 'asset-surface-graph'],
    queryFn: () => assetSurfaceApi.intelMatches({ asset_id: registryAsset!.id, limit: 200 }),
    enabled: Boolean(registryAsset?.id),
  });
  const graph = useMemo(
    () => buildAssetGraph(asset, intelligence.data, registryMatches.data ?? []),
    [asset, intelligence.data, registryMatches.data],
  );
  const threatRadarHref = companySpaceId && companyAsset?.id
    ? `/threat-radar/assets/${encodeURIComponent(companySpaceId)}/${encodeURIComponent(companyAsset.id)}`
    : '';

  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <GraphMetric label="Attack surface" value={graph.counts.attackSurface} />
        <GraphMetric label="CVEs" value={graph.counts.cves} />
        <GraphMetric label="IOCs" value={graph.counts.iocs} />
        <GraphMetric label="TTPs" value={graph.counts.ttps} />
        <GraphMetric label="Groups" value={graph.counts.groups} />
        <GraphMetric label="Graph edges" value={graph.edges.length} />
      </div>
      {(intelligence.isLoading || registryMatches.isLoading) && (
        <div className="rounded border border-cyan-900/60 bg-cyan-950/20 p-3 text-xs text-cyan-200">
          Loading Threat Radar intelligence for {asset.asset}…
        </div>
      )}
      {(intelligence.error || registryMatches.error) && (
        <div className="rounded border border-amber-800 bg-amber-950/20 p-3 text-xs text-amber-200">
          Some correlation sources could not be loaded. The graph still shows the deterministic inventory observations and ATT&amp;CK candidates.
        </div>
      )}
      {!companyAsset && (
        <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-500">
          This asset was not synchronized to a Threat Radar company space. Direct inventory observations, TTP candidates,
          and registry retrohunt matches are shown. Select a company space and rerun the analysis to add Threat Radar CVE,
          IOC, alert, and assessment correlations.
        </div>
      )}
      <div className="h-[620px]">
        <EntityGraph nodes={graph.nodes} edges={graph.edges} />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 text-[11px] text-gray-500">
        <div className="flex flex-wrap gap-2">
          <GraphLegend color="#155e75" label="Observed asset / exposure" />
          <GraphLegend color="#7c2d12" label="CVE candidate" />
          <GraphLegend color="#164e63" label="IOC / observable" />
          <GraphLegend color="#4c1d95" label="ATT&CK candidate" />
          <GraphLegend color="#713f12" label="Threat group lead" />
        </div>
        {threatRadarHref && <Link className="text-mitre-accent hover:underline" to={threatRadarHref}>Open full Threat Radar asset intelligence →</Link>}
      </div>
      <p className="text-[11px] leading-5 text-amber-200/70">
        {intelligence.data?.evidence_boundary
          ?? 'CVE, IOC, TTP, and group relationships are relevance leads. Validate affected versions, reachability, source evidence, and telemetry before treating any relationship as confirmed.'}
      </p>
    </div>
  );
}

type AssetGraphResult = {
  nodes: Node[];
  edges: Edge[];
  counts: { attackSurface: number; cves: number; iocs: number; ttps: number; groups: number };
};

function buildAssetGraph(
  asset: AssetSurfaceAsset,
  intelligence: ThreatAssetIntelligence | undefined,
  matches: AssetIntelMatch[],
): AssetGraphResult {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const rootId = `asset:${asset.asset_id}`;
  const cves = uniqueBy(
    intelligence?.cves ?? matches.filter(match => match.source_type === 'cve').map(match => ({
      cve_id: match.source_id,
      description: match.title,
      severity: match.severity,
      evidence_level: 'registry-retrohunt',
    })),
    row => row.cve_id.toUpperCase(),
  );
  const iocs = uniqueBy(intelligence?.iocs ?? [], row => `${row.indicator_type}:${row.value.toLowerCase()}`);
  const ttps: Array<{ attack_id: string; name: string }> = uniqueBy(
    intelligence?.ttps?.map(ttp => ({ attack_id: ttp.attack_id, name: ttp.name }))
      ?? asset.ttp_candidates.map(ttp => ({ attack_id: ttp.attack_id, name: ttp.name })),
    row => row.attack_id.toUpperCase(),
  );
  const groups = uniqueBy(
    matches.filter(match => match.source_type === 'actor'),
    match => match.source_id.toUpperCase(),
  );
  const attackSurface = unique([
    `Exposure: ${asset.exposure}`,
    ...asset.attack_surface,
    ...asset.likely_entry_points,
    ...asset.ports.map(port => `TCP/${port}`),
  ]);
  const observables = unique([...asset.domains, ...asset.ip_addresses]);

  nodes.push(graphNode(rootId, `ASSET\n${asset.asset}\n${asset.risk_level.toUpperCase()} · ${asset.risk_score}/100`, 0, 240, '#155e75', '#67e8f9', 190));
  addGraphColumn(nodes, edges, rootId, attackSurface.slice(0, 12), {
    idPrefix: 'surface', x: -520, color: '#0f3f46', border: '#2dd4bf', relation: 'observed / candidate surface', dashed: false,
  });
  addGraphColumn(nodes, edges, rootId, observables.slice(0, 12), {
    idPrefix: 'ioc-observed', x: -260, color: '#164e63', border: '#22d3ee', relation: 'inventory identity', dashed: false,
  });
  addGraphColumn(nodes, edges, rootId, cves.slice(0, 12).map(row => `${row.cve_id}\n${row.severity || 'severity unknown'}`), {
    idPrefix: 'cve', x: 260, color: '#4c1d1d', border: '#fb7185', relation: 'may be affected by', dashed: true,
  });
  addGraphColumn(nodes, edges, rootId, iocs.slice(0, 12).map(row => `${row.indicator_type.toUpperCase()}\n${row.value}`), {
    idPrefix: 'ioc', x: 520, color: '#164e63', border: '#22d3ee', relation: 'correlated IOC', dashed: true,
  });
  addGraphColumn(nodes, edges, rootId, ttps.slice(0, 12).map(row => `${row.attack_id}\n${row.name || 'ATT&CK technique'}`), {
    idPrefix: 'ttp', x: 780, color: '#4c1d95', border: '#c084fc', relation: 'technique candidate', dashed: true,
  });
  addGraphColumn(nodes, edges, rootId, groups.slice(0, 10).map(row => `${row.source_id}\n${row.title || 'Threat group'}`), {
    idPrefix: 'group', x: 1040, color: '#713f12', border: '#fbbf24', relation: 'relevance lead', dashed: true,
  });

  return {
    nodes,
    edges,
    counts: {
      attackSurface: attackSurface.length + observables.length,
      cves: cves.length,
      iocs: iocs.length,
      ttps: ttps.length,
      groups: groups.length,
    },
  };
}

function addGraphColumn(
  nodes: Node[],
  edges: Edge[],
  rootId: string,
  labels: string[],
  options: { idPrefix: string; x: number; color: string; border: string; relation: string; dashed: boolean },
) {
  const spacing = 92;
  const startY = 240 - ((labels.length - 1) * spacing) / 2;
  labels.forEach((label, index) => {
    const id = `${options.idPrefix}:${index}:${label.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 80)}`;
    nodes.push(graphNode(id, label, options.x, startY + index * spacing, options.color, options.border));
    edges.push({
      id: `${rootId}->${id}`,
      source: rootId,
      target: id,
      label: options.relation,
      style: { stroke: options.border, strokeDasharray: options.dashed ? '6 5' : undefined, opacity: 0.8 },
      labelStyle: { fill: '#94a3b8', fontSize: 9 },
    });
  });
}

function graphNode(id: string, label: string, x: number, y: number, background: string, border: string, width = 180): Node {
  return {
    id,
    position: { x, y },
    data: { label },
    style: {
      width,
      border: `1px solid ${border}`,
      borderRadius: 8,
      background,
      color: '#f8fafc',
      fontSize: 10,
      lineHeight: 1.35,
      whiteSpace: 'pre-line',
      overflowWrap: 'anywhere',
      padding: 8,
    },
  };
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.map(value => value.trim()).filter(Boolean)));
}

function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  return values.filter(value => {
    const identity = key(value);
    if (seen.has(identity)) return false;
    seen.add(identity);
    return true;
  });
}

function GraphMetric({ label, value }: { label: string; value: number }) {
  return <div className="rounded border border-gray-800 bg-gray-950 p-3"><div className="text-xl font-semibold text-white">{value}</div><div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div></div>;
}

function GraphLegend({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />{label}</span>;
}

function RegistryField({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-3">
      <div className="text-[10px] uppercase text-gray-600">{label}</div>
      <div className="mt-1 text-gray-200">{value}</div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="mx-auto mt-12 max-w-3xl rounded border border-gray-800 bg-gray-950 p-6">
      <h2 className="text-lg font-semibold text-white">Upload an asset inventory to build an attack surface matrix.</h2>
      <p className="mt-3 text-sm leading-6 text-gray-400">
        Supported inputs include CSV/JSON CMDB exports, cloud asset lists, scanner output, and plain hostname/IP lists.
        The module normalizes assets, scores exposure, proposes likely entry points and ATT&CK candidates, and uses AI to
        explain attack paths and validation gaps.
      </p>
    </div>
  );
}

function AssetRow({
  asset,
  companySpaceId,
  companyAssetId,
  companyAssetLoading,
  onShowGraph,
  selectedForGraph,
}: {
  asset: AssetSurfaceAsset;
  companySpaceId: string;
  companyAssetId?: string;
  companyAssetLoading: boolean;
  onShowGraph: () => void;
  selectedForGraph: boolean;
}) {
  const assetHref = companySpaceId && companyAssetId
    ? `/threat-radar/assets/${encodeURIComponent(companySpaceId)}/${encodeURIComponent(companyAssetId)}`
    : '';
  return (
    <>
      <tr className="align-top">
        <td className="py-3 pr-3">
          {assetHref ? (
            <Link className="font-semibold text-white hover:text-mitre-accent hover:underline" to={assetHref}>
              {asset.asset}
            </Link>
          ) : (
            <div className="font-semibold text-white">{asset.asset}</div>
          )}
          <div className="mt-1 text-[11px] text-gray-500">{asset.asset_type} · {asset.environment} · {asset.owner || 'no owner'}</div>
          <div className="mt-1 max-w-[240px] truncate font-mono text-[11px] text-gray-600">
            {[...asset.domains, ...asset.ip_addresses].length ? (
              [...asset.domains, ...asset.ip_addresses].map(value => (
                <IocLink key={value} value={value} source="AssetSurface" className="mr-1 hover:text-cyan-300 hover:underline" />
              ))
            ) : asset.asset_id}
          </div>
          {assetHref && (
            <Link
              className="secondary-action mt-2 inline-flex min-h-8 items-center px-2.5 text-[11px]"
              to={`${assetHref}#active-assessment`}
            >
              Open asset &amp; scan
            </Link>
          )}
          {companySpaceId && !assetHref && (
            <div className="mt-2 text-[10px] text-gray-600">
              {companyAssetLoading ? 'Linking saved company asset…' : 'Company asset link unavailable; rerun this inventory analysis.'}
            </div>
          )}
          <button
            type="button"
            onClick={onShowGraph}
            className={`mt-2 inline-flex min-h-8 items-center rounded border px-2.5 text-[11px] ${selectedForGraph ? 'border-cyan-500 bg-cyan-950/40 text-cyan-200' : 'border-gray-700 text-gray-400 hover:border-cyan-700 hover:text-cyan-200'}`}
          >
            {selectedForGraph ? 'Shown in graph' : 'Show intelligence graph'}
          </button>
        </td>
        <td className="py-3 pr-3"><RiskBadge level={asset.risk_level} score={asset.risk_score} /></td>
        <td className="py-3 pr-3"><Chip>{asset.exposure}</Chip></td>
        <td className="py-3 pr-3 text-gray-400">{asset.likely_entry_points.join(', ')}</td>
        <td className="py-3 pr-3">
          <div className="flex flex-wrap gap-1">
            {asset.ttp_candidates.map(ttp => (
              <TtpLink
                key={`${asset.asset_id}-${ttp.attack_id}`}
                id={ttp.attack_id}
                className="rounded border border-mitre-accent/50 bg-mitre-accent/10 px-1.5 py-0.5 text-[10px] font-semibold text-mitre-accent hover:bg-mitre-accent/20"
                title={ttp.reason}
              >
                {ttp.attack_id}
              </TtpLink>
            ))}
          </div>
        </td>
        <td className="py-3 pr-3 text-gray-400">{asset.priority_actions.slice(0, 2).join(' ')}</td>
      </tr>
      <tr className="border-t-0 align-top">
        <td colSpan={6} className="pb-4 pr-3">
          <div className="grid gap-3 rounded border border-gray-800 bg-gray-950 p-3 text-xs md:grid-cols-3">
            <DetailBlock title="Attack Paths" items={asset.attack_paths?.length ? asset.attack_paths : asset.attack_surface} />
            <DetailBlock title="Control Gaps" items={asset.control_gaps?.length ? asset.control_gaps : ['Validate controls against scanner, CMDB, cloud, identity, and EDR telemetry.']} />
            <DetailBlock title="Detections / Validation" items={(asset.detection_ideas?.length ? asset.detection_ideas : asset.validation_steps) ?? asset.priority_actions} />
          </div>
        </td>
      </tr>
    </>
  );
}

function AssetIntelMatches({ matches, loading }: { matches: AssetIntelMatch[]; loading: boolean }) {
  if (loading && !matches.length) {
    return <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-500">Checking saved assets against current intelligence...</div>;
  }
  if (!matches.length) {
    return (
      <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs leading-5 text-gray-500">
        No saved asset relevance matches yet. Upload assets, then sync CVEs/reports or run Retrohunt Saved Assets.
      </div>
    );
  }
  const renderedMatches = matches.slice(0, RETROHUNT_MAX_RENDERED_ROWS);
  const rowsInViewport = Math.min(RETROHUNT_VISIBLE_ROWS, renderedMatches.length);
  return (
    <>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-[11px] text-gray-500">
        <span>
          Showing {rowsInViewport} row{rowsInViewport === 1 ? '' : 's'} at a time. Scroll for more matches.
        </span>
        <span>
          {renderedMatches.length}{matches.length > renderedMatches.length ? ` of ${matches.length}` : ''} loaded
        </span>
      </div>
      <div
        aria-label={`Asset Retrohunt Matches, ${renderedMatches.length} loaded`}
        className="overflow-auto overscroll-contain rounded border border-gray-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mitre-accent"
        data-testid="asset-retrohunt-scroll"
        role="region"
        style={{ maxHeight: RETROHUNT_HEADER_HEIGHT_PX + (RETROHUNT_VISIBLE_ROWS * RETROHUNT_ROW_HEIGHT_PX) }}
        tabIndex={renderedMatches.length > RETROHUNT_VISIBLE_ROWS ? 0 : undefined}
      >
        <table className="w-full min-w-[900px] text-left text-xs">
          <thead className="sticky top-0 z-10 h-10 border-b border-gray-800 bg-gray-900 text-gray-500">
            <tr>
              <th className="py-2 pr-3">Source</th>
              <th className="py-2 pr-3">Match</th>
              <th className="py-2 pr-3">Score</th>
              <th className="py-2 pr-3">Reason</th>
              <th className="py-2 pr-3">Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {renderedMatches.map(match => (
              <tr key={match.id} className="h-28 align-top">
                <td className="py-3 pr-3">
                  <div className="font-semibold uppercase text-mitre-accent">{match.source_type}</div>
                  <div className="mt-1 font-mono text-[11px] text-gray-500">{match.source_id}</div>
                </td>
                <td className="py-3 pr-3">
                  {safeInternalHref(match.route) ? (
                    <a href={safeInternalHref(match.route)} className="font-semibold text-white hover:text-mitre-accent hover:underline">{match.title || match.source_id}</a>
                  ) : (
                    <span className="font-semibold text-white">{match.title || match.source_id}</span>
                  )}
                  <div className="mt-1 flex flex-wrap gap-1">
                    {match.tags.slice(0, 5).map(tag => <Chip key={`${match.id}-${tag}`}>{tag}</Chip>)}
                  </div>
                </td>
                <td className="py-3 pr-3">
                  <div className="font-bold text-white">{match.relevance_score}</div>
                  <div className="mt-1 text-[11px] text-gray-500">conf {match.confidence}</div>
                </td>
                <td className="max-w-[260px] py-3 pr-3 leading-5 text-gray-400">
                  <p className="line-clamp-3" title={match.reason}>{match.reason}</p>
                </td>
                <td className="max-w-[320px] py-3 pr-3">
                  <ul className="space-y-1 text-gray-500">
                    {match.evidence.slice(0, 3).map((item, index) => (
                      <li key={`${match.id}-e-${index}`} className="line-clamp-1" title={item}>{item}</li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Metric({ label, value, compact = false }: { label: string; value: string | number; compact?: boolean }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950 p-4">
      <div className={`${compact ? 'text-xl' : 'text-3xl'} font-bold text-white`}>{value}</div>
      <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-gray-500">{label}</div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded border border-gray-800 bg-gray-900/60">
      <div className="border-b border-gray-800 px-4 py-3">
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}

function RiskBadge({ level, score }: { level: string; score: number }) {
  const color = level === 'critical'
    ? 'border-red-500 bg-red-950 text-red-300'
    : level === 'high'
      ? 'border-orange-500 bg-orange-950 text-orange-300'
      : level === 'medium'
        ? 'border-yellow-600 bg-yellow-950 text-yellow-300'
        : 'border-green-700 bg-green-950 text-green-300';
  return <span className={`inline-flex rounded border px-2 py-1 text-[11px] font-bold ${color}`}>{level} · {score}</span>;
}

function Chip({ children }: { children: ReactNode }) {
  return <span className="rounded border border-gray-700 bg-gray-950 px-2 py-1 text-[11px] text-gray-300">{children}</span>;
}

function List({ items }: { items: string[] }) {
  return (
    <ul className="space-y-2 text-xs leading-5 text-gray-400">
      {items.map((item, index) => <li key={`${index}-${item}`} className="border-t border-gray-800 pt-2 first:border-t-0 first:pt-0">{item}</li>)}
    </ul>
  );
}

function DetailBlock({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="mb-2 font-semibold uppercase tracking-wide text-gray-500">{title}</div>
      <ul className="space-y-1.5 text-gray-400">
        {items.slice(0, 4).map((item, index) => <li key={`${title}-${index}-${item}`}>{item}</li>)}
      </ul>
    </div>
  );
}

function downloadJson(data: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function slug(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'asset-surface';
}
