import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Header } from '@/components/Layout/Header';
import { iocApi, pipelineApi, sectorApi, syncApi } from '@/api/client';
import type { CollectionSource, IOCSourceStatus } from '@/api/client';

type FeedKind = 'custom-json' | 'custom-csv' | 'custom-txt';
type RuleFeedKind = 'sigma' | 'yara';

const field = 'w-full rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent';
const domainLabels: Record<string, string> = {
  'enterprise-attack': 'Enterprise',
  'mobile-attack': 'Mobile',
  'ics-attack': 'ICS',
  atlas: 'ATLAS',
};

export function FeedsManagement() {
  const qc = useQueryClient();
  const [selectedDomains, setSelectedDomains] = useState<string[]>([]);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [customLabel, setCustomLabel] = useState('');
  const [customUrl, setCustomUrl] = useState('');
  const [customKind, setCustomKind] = useState<FeedKind>('custom-json');
  const [mispUrl, setMispUrl] = useState('');
  const [taxiiUrl, setTaxiiUrl] = useState('');
  const [taxiiToken, setTaxiiToken] = useState('');
  const [taxiiUsername, setTaxiiUsername] = useState('');
  const [taxiiPassword, setTaxiiPassword] = useState('');
  const [ruleName, setRuleName] = useState('');
  const [ruleUrl, setRuleUrl] = useState('');
  const [ruleKind, setRuleKind] = useState<RuleFeedKind>('sigma');
  const [sandboxName, setSandboxName] = useState('');
  const [sandboxUrl, setSandboxUrl] = useState('');
  const [rssName, setRssName] = useState('');
  const [rssUrl, setRssUrl] = useState('');
  const [forceReferences, setForceReferences] = useState(false);
  const [aiEnrichIocs, setAiEnrichIocs] = useState(false);
  const [aiProvider, setAiProvider] = useState<'local' | 'claude' | 'openai' | 'gemini'>('local');

  const syncStatus = useQuery({ queryKey: ['sync-status'], queryFn: syncApi.status });
  const syncTask = useQuery({
    queryKey: ['sync-task', taskId],
    queryFn: () => syncApi.taskStatus(taskId as string),
    enabled: !!taskId,
    refetchInterval: query => {
      const state = query.state.data?.status;
      return state && !['PENDING', 'STARTED', 'RETRY'].includes(state) ? false : 2500;
    },
  });
  const iocSources = useQuery({ queryKey: ['ioc-sources'], queryFn: iocApi.sources });
  const pipelineSources = useQuery({ queryKey: ['pipeline-sources'], queryFn: pipelineApi.sources });
  const pipelineRuns = useQuery({ queryKey: ['pipeline-runs'], queryFn: pipelineApi.runs });
  const sectorSources = useQuery({ queryKey: ['sector-sources'], queryFn: sectorApi.sources });

  const refreshFeeds = () => {
    qc.invalidateQueries({ queryKey: ['sync-status'] });
    qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    qc.invalidateQueries({ queryKey: ['ioc-library'] });
    qc.invalidateQueries({ queryKey: ['pipeline-sources'] });
    qc.invalidateQueries({ queryKey: ['pipeline-runs'] });
    qc.invalidateQueries({ queryKey: ['sector-sources'] });
    qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
    qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
  };

  useEffect(() => {
    const state = syncTask.data?.status;
    if (state && !['PENDING', 'STARTED', 'RETRY'].includes(state)) {
      qc.invalidateQueries({ queryKey: ['sync-status'] });
      qc.invalidateQueries({ queryKey: ['attack-versions'] });
    }
  }, [syncTask.data?.status, qc]);

  const referenceDomains = useMemo(
    () => (syncStatus.data?.domains ?? []).map(item => item.domain),
    [syncStatus.data?.domains],
  );
  const referenceSources = useMemo(() => syncStatus.data?.sources ?? [], [syncStatus.data?.sources]);
  const activeDomains = selectedDomains.length ? selectedDomains : referenceDomains;
  const taskRunning = !!taskId && ['PENDING', 'STARTED', 'RETRY'].includes(syncTask.data?.status ?? 'PENDING');
  const synchronizedContent = useMemo(() => {
    const mitre = referenceSources.find(source => source.id === 'mitre-attack');
    return mitre?.content ?? syncStatus.data?.domains?.[0]?.content ?? [];
  }, [referenceSources, syncStatus.data?.domains]);

  const syncReferences = useMutation({
    mutationFn: () => syncApi.trigger({ source: 'mitre-attack', domains: activeDomains, force: forceReferences }),
    onSuccess: data => {
      setTaskId(data.task_id);
      refreshFeeds();
    },
  });
  const syncDynamicDb = useMutation({
    mutationFn: () => syncApi.dynamicDb({ days: 7, force_attack: forceReferences }),
    onSuccess: refreshFeeds,
  });
  const syncMispGalaxy = useMutation({ mutationFn: sectorApi.syncMispGalaxy, onSuccess: refreshFeeds });
  const iocSyncOptions = () => ({ ai_enrich: aiEnrichIocs, ai_provider: aiProvider });
  const syncAllIocs = useMutation({ mutationFn: () => syncApi.ioc(7, iocSyncOptions()), onSuccess: refreshFeeds });
  const syncThreatFox = useMutation({ mutationFn: () => iocApi.syncThreatFox(7, iocSyncOptions()), onSuccess: refreshFeeds });
  const syncMalpedia = useMutation({ mutationFn: iocApi.syncMalpedia, onSuccess: refreshFeeds });
  const syncOtx = useMutation({ mutationFn: () => iocApi.syncOtx('subscribed', iocSyncOptions()), onSuccess: refreshFeeds });
  const createIocSource = useMutation({
    mutationFn: iocApi.createSource,
    onSuccess: () => {
      setCustomLabel('');
      setCustomUrl('');
      setMispUrl('');
      refreshFeeds();
    },
  });
  const syncIocSource = useMutation({ mutationFn: (sourceId: string) => iocApi.syncSource(sourceId, iocSyncOptions()), onSuccess: refreshFeeds });
  const enrichIocTtps = useMutation({ mutationFn: () => iocApi.enrichIocTtps({ ...iocSyncOptions(), limit: 20000 }), onSuccess: refreshFeeds });
  const importStix = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      return iocApi.importStix(JSON.parse(text), { source_label: file.name });
    },
    onSuccess: refreshFeeds,
  });
  const importTaxii = useMutation({
    mutationFn: () => iocApi.importTaxii({
      objects_url: taxiiUrl,
      token: taxiiToken,
      username: taxiiUsername,
      password: taxiiPassword,
      source_label: 'TAXII IOC Import',
    }),
    onSuccess: refreshFeeds,
  });

  const createRuleFeed = useMutation({
    mutationFn: () => pipelineApi.createSource({
      name: ruleName,
      kind: ruleKind,
      url: ruleUrl,
      enabled: true,
      interval_minutes: 1440,
      config: { limit: 250 },
    }),
    onSuccess: () => {
      setRuleName('');
      setRuleUrl('');
      refreshFeeds();
    },
  });
  const createDefaultRuleFeeds = useMutation({ mutationFn: pipelineApi.createDefaultRuleFeeds, onSuccess: refreshFeeds });
  const createSandboxFeed = useMutation({
    mutationFn: () => pipelineApi.createSource({
      name: sandboxName,
      kind: 'sandbox',
      url: sandboxUrl,
      enabled: true,
      interval_minutes: 1440,
      config: { limit: 100 },
    }),
    onSuccess: () => {
      setSandboxName('');
      setSandboxUrl('');
      refreshFeeds();
    },
  });
  const createRssFeed = useMutation({
    mutationFn: () => pipelineApi.createSource({
      name: rssName,
      kind: 'rss',
      url: rssUrl,
      enabled: true,
      interval_minutes: 60,
      config: {},
    }),
    onSuccess: () => {
      setRssName('');
      setRssUrl('');
      refreshFeeds();
    },
  });
  const runPipelineSource = useMutation({ mutationFn: pipelineApi.runSource, onSuccess: refreshFeeds });

  const collectionSources = pipelineSources.data ?? [];
  const ruleFeeds = collectionSources.filter(source => source.kind === 'sigma' || source.kind === 'yara');
  const sandboxFeeds = collectionSources.filter(source => source.kind === 'sandbox');
  const rssFeeds = collectionSources.filter(source => source.kind === 'rss');

  const toggleDomain = (domain: string) => {
    setSelectedDomains(current =>
      current.includes(domain)
        ? current.filter(item => item !== domain)
        : [...current, domain],
    );
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="Feeds Management" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="grid gap-4 xl:grid-cols-[1fr_420px]">
            <Panel title="Reference and Dynamic Database Sync">
              <div className="space-y-4 p-4">
                <p className="text-sm leading-relaxed text-gray-400">
                  Manage public reference data that powers actor pages, matrices, sector relevance, and IOC enrichment. This includes MITRE ATT&CK, ATLAS, MISP Galaxy actor metadata, Malpedia, ThreatFox, OTX, and custom IOC feeds.
                </p>
                <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                  {(syncStatus.data?.domains ?? []).map(domain => (
                    <button
                      key={domain.domain}
                      onClick={() => toggleDomain(domain.domain)}
                      className={`rounded border p-3 text-left transition-colors ${
                        activeDomains.includes(domain.domain)
                          ? 'border-mitre-accent bg-mitre-accent/10 text-white'
                          : 'border-gray-800 bg-gray-950 text-gray-500 hover:text-gray-300'
                      }`}
                    >
                      <b className="block text-sm">{domainLabels[domain.domain] ?? domain.domain}</b>
                      <span className="text-[10px] text-gray-500">{domain.current_version ?? 'not loaded'} to {domain.latest_version ?? 'unknown'}</span>
                      <div className={domain.needs_update ? 'mt-2 text-[10px] text-amber-300' : 'mt-2 text-[10px] text-green-400'}>
                        {domain.needs_update ? 'Update available' : 'Current'}
                      </div>
                    </button>
                  ))}
                </div>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input type="checkbox" checked={forceReferences} onChange={event => setForceReferences(event.target.checked)} />
                  Force refresh cached reference bundles
                </label>
                <div className="flex flex-wrap gap-2">
                  <button className="primary" disabled={syncReferences.isPending || taskRunning || activeDomains.length === 0} onClick={() => syncReferences.mutate()}>
                    {forceReferences ? 'Force sync selected references' : 'Sync selected references'}
                  </button>
                  <button className="primary" disabled={syncDynamicDb.isPending} onClick={() => syncDynamicDb.mutate()}>
                    {syncDynamicDb.isPending ? 'Syncing...' : 'Sync Local / Dynamic DB'}
                  </button>
                  <button className="secondary-action" disabled={syncMispGalaxy.isPending} onClick={() => syncMispGalaxy.mutate()}>
                    {syncMispGalaxy.isPending ? 'Syncing...' : 'Sync MISP Galaxy'}
                  </button>
                </div>
                {taskId && <div className="rounded border border-gray-800 bg-gray-950 p-2 font-mono text-[10px] text-gray-500">Reference task {taskId.slice(0, 8)} · {syncTask.data?.status ?? 'PENDING'}</div>}
                <MutationStatus label="Reference feeds" mutation={syncReferences} />
                <MutationStatus label="Dynamic DB" mutation={syncDynamicDb} />
                <MutationStatus label="MISP Galaxy" mutation={syncMispGalaxy} />
                {syncDynamicDb.data && (
                  <div className="rounded border border-green-900 bg-green-950/30 p-3 text-xs text-green-300">
                    Local / dynamic DB sync complete. Public references were refreshed while private/custom records were preserved.
                  </div>
                )}
              </div>
            </Panel>

            <Panel title="Configured Source Health">
              <div className="divide-y divide-gray-800">
                <SourceHealth title="IOC sources" rows={(iocSources.data ?? []).map(source => ({
                  id: source.source_id,
                  label: source.label,
                  kind: source.kind,
                  url: source.url,
                  status: source.sync_status,
                  last: source.last_synced_at,
                  error: source.sync_error,
                }))} />
                <SourceHealth title="Sector sources" rows={(sectorSources.data ?? []).map(source => ({
                  id: source.source_id,
                  label: source.label,
                  kind: source.kind,
                  url: source.url,
                  status: source.sync_status,
                  last: source.last_synced_at,
                  error: source.sync_error,
                }))} />
                <SourceHealth title="Pipeline sources" rows={collectionSources.map(source => ({
                  id: source.id,
                  label: source.name,
                  kind: source.kind,
                  url: source.url,
                  status: source.enabled ? 'enabled' : 'disabled',
                  last: source.last_run_at,
                  error: '',
                }))} />
              </div>
            </Panel>
          </section>

          <section className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
            <Panel title="Reference Sources">
              <div className="divide-y divide-gray-800">
                {referenceSources.map(source => (
                  <div key={source.id} className="p-4">
                    <div className="flex items-center justify-between gap-3">
                      <b className="text-sm text-white">{source.label}</b>
                      <StatusPill status={source.status} />
                    </div>
                    <p className="mt-2 text-xs text-gray-500">{source.schedule ?? 'No automated schedule configured'}</p>
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {source.content.map(item => <span key={item} className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-400">{item}</span>)}
                    </div>
                  </div>
                ))}
                {!referenceSources.length && <div className="p-4 text-sm text-gray-600">No reference source metadata returned yet.</div>}
              </div>
            </Panel>

            <Panel title="Domain Status">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-xs uppercase text-gray-500">
                    <tr>
                      <th className="p-3 text-left">Domain</th>
                      <th className="p-3 text-left">Current</th>
                      <th className="p-3 text-left">Latest</th>
                      <th className="p-3 text-left">State</th>
                      <th className="p-3 text-left">Last ingested</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(syncStatus.data?.domains ?? []).map(domain => (
                      <tr key={domain.domain} className="border-t border-gray-800">
                        <td className="p-3 text-white">{domainLabels[domain.domain] ?? domain.domain}</td>
                        <td className="p-3 font-mono text-gray-300">{domain.current_version ?? '-'}</td>
                        <td className="p-3 font-mono text-gray-300">{domain.latest_version ?? '-'}</td>
                        <td className="p-3">
                          <span className={`rounded-full px-2 py-1 text-[10px] ${domain.needs_update ? 'bg-amber-950 text-amber-300' : 'bg-green-950 text-green-400'}`}>
                            {domain.needs_update ? 'update available' : 'current'}
                          </span>
                        </td>
                        <td className="p-3 text-gray-500">{domain.last_ingested ?? '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {syncStatus.isLoading && <div className="p-4 text-sm text-gray-500">Checking references...</div>}
                {syncStatus.error && <div className="p-4 text-sm text-red-400">{String(syncStatus.error)}</div>}
              </div>
            </Panel>
          </section>

          {syncTask.data?.result ? (
            <Panel title="Last Reference Task Result">
              <pre className="m-4 max-h-72 overflow-auto rounded bg-gray-950 p-3 text-xs text-gray-400">{JSON.stringify(syncTask.data.result, null, 2)}</pre>
            </Panel>
          ) : null}

          <Panel title="Synchronized Reference Content">
            <div className="grid gap-2 p-4 sm:grid-cols-2 lg:grid-cols-3">
              {synchronizedContent.map(item => <span key={item} className="rounded border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-300">{item}</span>)}
              {!synchronizedContent.length && <span className="text-sm text-gray-600">No synchronized content metadata yet.</span>}
            </div>
          </Panel>

          <section className="grid gap-4 xl:grid-cols-2">
            <Panel title="IOC Feeds">
              <div className="space-y-4 p-4">
                <p className="text-sm text-gray-400">
                  Connect IOC feeds for indicators, malware context, actor links, source URLs, and TTP mapping.
                </p>
                <div className="flex flex-wrap gap-2">
                  <button className="primary" disabled={syncAllIocs.isPending} onClick={() => syncAllIocs.mutate()}>{syncAllIocs.isPending ? 'Syncing...' : 'Sync all IOC sources'}</button>
                  <button className="secondary-action" disabled={syncThreatFox.isPending} onClick={() => syncThreatFox.mutate()}>ThreatFox</button>
                  <button className="secondary-action" disabled={syncMalpedia.isPending} onClick={() => syncMalpedia.mutate()}>Malpedia</button>
                  <button className="secondary-action" disabled={syncOtx.isPending} onClick={() => syncOtx.mutate()}>OTX</button>
                  <button className="secondary-action" disabled={enrichIocTtps.isPending} onClick={() => enrichIocTtps.mutate()}>
                    {enrichIocTtps.isPending ? 'Enriching...' : 'Enrich local IOC DB to TTPs'}
                  </button>
                  <a className="secondary-action" href={iocApi.stixExportUrl({ limit: 5000 })}>Export STIX</a>
                  <label className="secondary-action cursor-pointer">
                    Import STIX
                    <input
                      type="file"
                      accept=".json,.stix,application/json,application/stix+json"
                      className="hidden"
                      onChange={event => {
                        const file = event.currentTarget.files?.[0];
                        if (file) importStix.mutate(file);
                        event.currentTarget.value = '';
                      }}
                    />
                  </label>
                </div>
                <div className="grid gap-2 rounded border border-gray-800 bg-gray-950 p-3 md:grid-cols-[minmax(0,1fr)_180px]">
                  <label className="flex items-start gap-2 text-xs text-gray-300">
                    <input
                      type="checkbox"
                      checked={aiEnrichIocs}
                      onChange={event => setAiEnrichIocs(event.target.checked)}
                      className="mt-0.5"
                    />
                    <span>
                      Use AI as last fallback for new IOCs without source-backed or enrichment-platform TTP evidence.
                    </span>
                  </label>
                  <select className={field} value={aiProvider} onChange={event => setAiProvider(event.target.value as typeof aiProvider)}>
                    <option value="local">Local LLM</option>
                    <option value="claude">Claude</option>
                    <option value="openai">OpenAI</option>
                    <option value="gemini">Gemini</option>
                    <option value="minimax">MiniMax</option>
                  </select>
                </div>
                <div className="grid gap-2 md:grid-cols-[1fr_1.4fr_140px_auto]">
                  <input className={field} value={customLabel} onChange={event => setCustomLabel(event.target.value)} placeholder="Feed label" />
                  <input className={field} value={customUrl} onChange={event => setCustomUrl(event.target.value)} placeholder="https://example.local/iocs.json|csv|txt" />
                  <select className={field} value={customKind} onChange={event => setCustomKind(event.target.value as FeedKind)}>
                    <option value="custom-json">JSON</option>
                    <option value="custom-csv">CSV</option>
                    <option value="custom-txt">TXT</option>
                  </select>
                  <button className="primary" disabled={!customLabel.trim() || !customUrl.trim() || createIocSource.isPending} onClick={() => createIocSource.mutate({ label: customLabel, url: customUrl, kind: customKind })}>Add</button>
                </div>
                <div className="max-h-64 divide-y divide-gray-800 overflow-y-auto rounded border border-gray-800 bg-gray-950">
                  {(iocSources.data ?? []).map(source => (
                    <IOCSourceRow key={source.source_id} source={source} onSync={() => syncIocSource.mutate(source.source_id)} disabled={syncIocSource.isPending} />
                  ))}
                </div>
                <MutationStatus label="IOC sync" mutation={syncAllIocs} />
                <MutationStatus label="ThreatFox" mutation={syncThreatFox} />
                <MutationStatus label="Malpedia" mutation={syncMalpedia} />
                <MutationStatus label="OTX" mutation={syncOtx} />
                <MutationStatus label="Custom source" mutation={createIocSource} />
                <MutationStatus label="Custom source sync" mutation={syncIocSource} />
                <MutationStatus label="STIX import" mutation={importStix} />
                <MutationStatus label="IOC-to-TTP enrichment" mutation={enrichIocTtps} />
              </div>
            </Panel>

            <Panel title="MISP, TAXII, and STIX">
              <div className="space-y-4 p-4">
                <div className="rounded border border-gray-800 bg-gray-950 p-3">
                  <h3 className="text-sm font-semibold text-white">MISP IOC JSON export</h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-500">
                    Add a MISP event or attribute JSON export URL as a custom IOC source. Use a local gateway when MISP requires authentication headers.
                  </p>
                  <div className="mt-3 grid gap-2 md:grid-cols-[1fr_auto]">
                    <input className={field} value={mispUrl} onChange={event => setMispUrl(event.target.value)} placeholder="MISP JSON export URL or local gateway URL" />
                    <button className="primary" disabled={!mispUrl.trim() || createIocSource.isPending} onClick={() => createIocSource.mutate({ label: 'MISP IOC Export', url: mispUrl, kind: 'custom-json', source_id: 'custom-misp-export' })}>Connect MISP</button>
                  </div>
                </div>
                <div className="rounded border border-gray-800 bg-gray-950 p-3">
                  <h3 className="text-sm font-semibold text-white">TAXII 2.1 collection import</h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-500">
                    Pull STIX indicators and observed-data from a TAXII collection objects endpoint into the IOC Library.
                  </p>
                  <div className="mt-3 grid gap-2">
                    <input className={field} value={taxiiUrl} onChange={event => setTaxiiUrl(event.target.value)} placeholder="https://taxii.example/api2/collections/{id}/objects/" />
                    <input className={field} value={taxiiToken} onChange={event => setTaxiiToken(event.target.value)} placeholder="Bearer token (optional)" />
                    <div className="grid gap-2 md:grid-cols-2">
                      <input className={field} value={taxiiUsername} onChange={event => setTaxiiUsername(event.target.value)} placeholder="Username" />
                      <input className={field} type="password" value={taxiiPassword} onChange={event => setTaxiiPassword(event.target.value)} placeholder="Password" />
                    </div>
                    <button className="primary w-fit" disabled={!taxiiUrl.trim() || importTaxii.isPending} onClick={() => importTaxii.mutate()}>
                      {importTaxii.isPending ? 'Pulling TAXII...' : 'Pull TAXII STIX'}
                    </button>
                  </div>
                </div>
                <div className="rounded border border-gray-800 bg-gray-950 p-3">
                  <h3 className="text-sm font-semibold text-white">Reviewed report import</h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-500">
                    For STIX/TAXII reports, MISP events, and ATLAS objects that should become analyst-reviewed intake, use the Pipeline import workflow.
                  </p>
                  <a href="/pipeline" className="secondary-action mt-3 inline-flex">Open Pipeline Imports</a>
                </div>
                <MutationStatus label="TAXII import" mutation={importTaxii} />
              </div>
            </Panel>
          </section>

          <section className="grid gap-4 xl:grid-cols-2">
            <Panel title="Detection Feeds: Sigma and YARA">
              <div className="space-y-4 p-4">
                <p className="text-sm text-gray-400">
                  Connect raw rule files, URL lists, or GitHub tree URLs. Imported rules keep source links and ATT&CK tags when available.
                </p>
                <div className="flex flex-wrap gap-2">
                  <button className="primary" disabled={createDefaultRuleFeeds.isPending} onClick={() => createDefaultRuleFeeds.mutate()}>
                    {createDefaultRuleFeeds.isPending ? 'Adding...' : 'Add SigmaHQ defaults'}
                  </button>
                </div>
                <div className="grid gap-2 md:grid-cols-[1fr_1.4fr_120px_auto]">
                  <input className={field} value={ruleName} onChange={event => setRuleName(event.target.value)} placeholder="Feed name" />
                  <input className={field} value={ruleUrl} onChange={event => setRuleUrl(event.target.value)} placeholder="Raw rule URL, URL list, or GitHub tree URL" />
                  <select className={field} value={ruleKind} onChange={event => setRuleKind(event.target.value as RuleFeedKind)}>
                    <option value="sigma">Sigma</option>
                    <option value="yara">YARA</option>
                  </select>
                  <button className="primary" disabled={!ruleName.trim() || !ruleUrl.trim() || createRuleFeed.isPending} onClick={() => createRuleFeed.mutate()}>Add</button>
                </div>
                <PipelineSourceList sources={ruleFeeds} run={runPipelineSource} />
                <MutationStatus label="Rule feed" mutation={createRuleFeed} />
                <MutationStatus label="Rule feed sync" mutation={runPipelineSource} />
              </div>
            </Panel>

            <Panel title="Sandbox, RSS, and Intake Feeds">
              <div className="space-y-4 p-4">
                <div>
                  <h3 className="text-sm font-semibold text-white">Sandbox behavior enrichment</h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-500">
                    Connect JSON exports from CAPE, Cuckoo, ANY.RUN-style gateways, or internal sandbox aggregators. Behavior data enriches malware families, signatures, network artifacts, and ATT&CK IDs.
                  </p>
                  <div className="mt-3 grid gap-2 md:grid-cols-[1fr_1.4fr_auto]">
                    <input className={field} value={sandboxName} onChange={event => setSandboxName(event.target.value)} placeholder="Sandbox feed name" />
                    <input className={field} value={sandboxUrl} onChange={event => setSandboxUrl(event.target.value)} placeholder="https://sandbox.local/reports.json" />
                    <button className="primary" disabled={!sandboxName.trim() || !sandboxUrl.trim() || createSandboxFeed.isPending} onClick={() => createSandboxFeed.mutate()}>Add</button>
                  </div>
                </div>
                <PipelineSourceList sources={sandboxFeeds} run={runPipelineSource} />

                <div className="border-t border-gray-800 pt-4">
                  <h3 className="text-sm font-semibold text-white">RSS / Atom collection</h3>
                  <p className="mt-1 text-xs leading-relaxed text-gray-500">
                    Add public or internal report feeds. New items become pending intake and observables for analyst review.
                  </p>
                  <div className="mt-3 grid gap-2 md:grid-cols-[1fr_1.4fr_auto]">
                    <input className={field} value={rssName} onChange={event => setRssName(event.target.value)} placeholder="RSS feed name" />
                    <input className={field} value={rssUrl} onChange={event => setRssUrl(event.target.value)} placeholder="HTTPS RSS / Atom URL" />
                    <button className="primary" disabled={!rssName.trim() || !rssUrl.trim() || createRssFeed.isPending} onClick={() => createRssFeed.mutate()}>Add</button>
                  </div>
                </div>
                <PipelineSourceList sources={rssFeeds} run={runPipelineSource} />
                <MutationStatus label="Sandbox feed" mutation={createSandboxFeed} />
                <MutationStatus label="RSS feed" mutation={createRssFeed} />
              </div>
            </Panel>
          </section>

          <Panel title="Recent Feed Runs">
            <div className="divide-y divide-gray-800">
              {(pipelineRuns.data ?? []).slice(0, 20).map(run => (
                <div key={run.id} className="grid gap-2 p-3 text-xs md:grid-cols-[120px_1fr_140px]">
                  <span className={run.status === 'complete' ? 'text-green-400' : run.status === 'failed' ? 'text-red-300' : 'text-gray-400'}>{run.status}</span>
                  <span className="text-gray-500">{run.items_seen} seen · {run.items_created} intake · {run.observables_created} observables</span>
                  <span className="text-gray-600">{run.completed_at ?? run.started_at}</span>
                  {run.error && <div className="md:col-span-3 text-red-300">{run.error}</div>}
                </div>
              ))}
              {!pipelineRuns.data?.length && <div className="p-4 text-sm text-gray-600">No feed runs yet.</div>}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function IOCSourceRow({ source, onSync, disabled }: { source: IOCSourceStatus; onSync: () => void; disabled: boolean }) {
  const canSync = source.kind.startsWith('custom-');
  return (
    <div className="flex items-center gap-3 p-3">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <b className="text-sm text-gray-200">{source.label}</b>
          <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{source.kind}</span>
          <StatusPill status={source.sync_status} />
        </div>
        <p className="mt-1 truncate text-[10px] text-gray-600">{source.url || 'internal source'}</p>
        {source.last_synced_at && <p className="mt-1 text-[10px] text-gray-700">Last sync: {source.last_synced_at}</p>}
        {source.sync_error && <p className="mt-1 line-clamp-2 text-[10px] text-red-300">{source.sync_error}</p>}
      </div>
      {canSync && <button className="secondary-action" disabled={disabled} onClick={onSync}>Sync</button>}
    </div>
  );
}

function PipelineSourceList({ sources, run }: {
  sources: CollectionSource[];
  run: { mutate: (id: string) => void; isPending: boolean; variables?: string };
}) {
  if (!sources.length) return <div className="rounded border border-gray-800 p-4 text-sm text-gray-600">No sources configured.</div>;
  return (
    <div className="max-h-64 divide-y divide-gray-800 overflow-y-auto rounded border border-gray-800 bg-gray-950">
      {sources.map(source => (
        <div key={source.id} className="flex items-center gap-3 p-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <b className="text-sm text-gray-200">{source.name}</b>
              <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase text-gray-400">{source.kind}</span>
              <StatusPill status={source.enabled ? 'enabled' : 'disabled'} />
            </div>
            <p className="mt-1 truncate text-[10px] text-gray-600">{source.url}</p>
            {source.last_run_at && <p className="mt-1 text-[10px] text-gray-700">Last run: {source.last_run_at}</p>}
          </div>
          <button className="secondary-action" disabled={run.isPending} onClick={() => run.mutate(source.id)}>
            {run.variables === source.id ? 'Syncing' : 'Sync'}
          </button>
        </div>
      ))}
    </div>
  );
}

function SourceHealth({ title, rows }: {
  title: string;
  rows: Array<{ id: string; label: string; kind: string; url: string; status: string; last: string | null; error: string }>;
}) {
  return (
    <div className="p-4">
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      <div className="space-y-2">
        {rows.slice(0, 8).map(row => (
          <div key={`${title}-${row.id}`} className="rounded border border-gray-800 bg-gray-950 p-2">
            <div className="flex items-center justify-between gap-3">
              <div className="min-w-0">
                <b className="block truncate text-xs text-gray-200">{row.label}</b>
                <span className="text-[10px] text-gray-600">{row.kind} · {row.last ?? 'never'}</span>
              </div>
              <StatusPill status={row.status} />
            </div>
            {row.error && <p className="mt-1 line-clamp-2 text-[10px] text-red-300">{row.error}</p>}
          </div>
        ))}
        {!rows.length && <p className="text-xs text-gray-600">No sources configured.</p>}
      </div>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const ok = ['ok', 'active', 'enabled', 'complete'].includes(status);
  const bad = ['error', 'failed', 'disabled'].includes(status);
  return (
    <span className={`rounded px-2 py-1 text-[10px] ${ok ? 'bg-green-950 text-green-400' : bad ? 'bg-red-950 text-red-300' : 'bg-gray-800 text-gray-500'}`}>
      {status || 'unknown'}
    </span>
  );
}

function MutationStatus({ label, mutation }: { label: string; mutation: { data?: unknown; error: unknown; isPending: boolean } }) {
  if (mutation.isPending) return <div className="rounded border border-blue-900 bg-blue-950/30 p-2 text-xs text-blue-200">{label}: running...</div>;
  if (mutation.error) return <div className="rounded border border-red-900 bg-red-950/30 p-2 text-xs text-red-300">{label}: {errorMessage(mutation.error)}</div>;
  if (!mutation.data) return null;
  return <div className="rounded border border-green-900 bg-green-950/30 p-2 text-xs text-green-300">{label}: complete.</div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60"><h2 className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</h2>{children}</section>;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}
