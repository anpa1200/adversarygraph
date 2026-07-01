import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { aptApi, attackApi, iocApi, simulationApi, syncApi, systemApi, type SelfTestResult } from '@/api/client';
import { loadReportIndex } from '@/config/intelligence';
import { useAppStore } from '@/store';
import { Header } from '@/components/Layout/Header';

export function Discover() {
  const {
    domain,
    version,
    selectedTechniques,
    coverageTechniques,
    workspaces,
    clearTechniques,
    saveWorkspace,
  } = useAppStore();
  const navigate = useNavigate();
  const [iocInput, setIocInput] = useState('');
  const [workspaceName, setWorkspaceName] = useState('');
  const [showSelfTestReport, setShowSelfTestReport] = useState(false);
  const { data: groups = [] } = useQuery({
    queryKey: ['discover-groups', domain, version],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined }),
  });
  const { data: techniques = [] } = useQuery({
    queryKey: ['discover-techniques', domain, version],
    queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }),
  });
  const { data: reports } = useQuery({ queryKey: ['report-index'], queryFn: loadReportIndex });
  const { data: simulationCatalog = [] } = useQuery({
    queryKey: ['simulation-catalog'],
    queryFn: simulationApi.catalog,
    staleTime: 5 * 60 * 1000,
  });
  const { data: sources = [] } = useQuery({ queryKey: ['discover-ioc-sources'], queryFn: iocApi.sources });
  const { data: syncStatus } = useQuery({ queryKey: ['discover-sync-status'], queryFn: syncApi.status });
  const selfTest = useMutation({ mutationFn: systemApi.selftest });

  const uniqueReports = useMemo(() => {
    const seen = new Set<string>();
    return Object.values(reports?.byTechnique ?? {})
      .flat()
      .filter(item => !seen.has(item.url) && seen.add(item.url));
  }, [reports]);
  const recent = [...uniqueReports]
    .filter(item => item.date)
    .sort((a, b) => b.date.localeCompare(a.date))
    .slice(0, 10);
  const trending = Object.entries(reports?.byTechnique ?? {})
    .map(([id, refs]) => ({
      id,
      count: new Set(refs.map(item => item.url)).size,
      name: techniques.find(item => item.attack_id === id)?.name ?? id,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 12);
  const simulationByTechnique = useMemo(() => {
    const map = new Map<string, string>();
    for (const item of simulationCatalog) {
      if (!map.has(item.technique_id)) map.set(item.technique_id, item.id);
    }
    return map;
  }, [simulationCatalog]);
  const selectedCount = selectedTechniques.size;
  const missingCoverageCount = Math.max(0, selectedTechniques.size - coverageTechniques.size);
  const enabledSources = sources.filter(source => source.enabled);
  const staleSources = enabledSources.filter(source => source.sync_status && !['ok', 'configured', 'active'].includes(source.sync_status));

  const runIocLookup = () => {
    const value = iocInput.trim();
    if (!value) return;
    navigate(`/ioc-investigation?indicator=${encodeURIComponent(value)}`);
  };
  const runIocSearch = () => {
    const value = iocInput.trim();
    navigate(value ? `/ioc-library?search=${encodeURIComponent(value)}` : '/ioc-library');
  };
  const saveCurrentWorkspace = () => {
    saveWorkspace(workspaceName.trim() || `Discovery workspace ${new Date().toLocaleDateString()}`);
    setWorkspaceName('');
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <Header title="Discover Intelligence" />
      <div data-testid="discover-scroll-region" className="min-h-0 flex-1 overflow-y-auto px-6 pb-6 pt-8">
        <div className="mx-auto max-w-7xl space-y-7">
          <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
            <div>
              <p className="mb-6 max-w-3xl text-sm text-gray-400">
                Start with an actor, behavior, report, IOC, malware sample, asset inventory, sector, feed, detection gap, or AI analysis.
                AdversaryGraph connects live ATT&amp;CK data, IOC enrichment, MalwareGraph analysis, asset attack-surface mapping,
                private analysis, and the shared 1200km research ecosystem.
              </p>
              <div className="grid gap-3 md:grid-cols-4">
                <Start title="Investigate actor" text="Profiles, campaigns, reports, aliases, behavior, and IOCs." onClick={() => navigate('/apt')} />
                <Start title="Analyze report with AI" text="Extract ATT&CK evidence using your configured LLM." onClick={() => navigate('/analyze')} />
                <Start title="Analyze malware" text="Create cases, upload samples, extract IOCs, strings, TTPs, and AI summaries." onClick={() => navigate('/malware-analysis')} />
                <Start title="Map asset surface" text="Upload CMDB, scanner, or cloud inventory and map exposed assets to ATT&CK." onClick={() => navigate('/asset-surface')} />
                <Start title="Attack simulation" text="Choose a TTP, configure an approved target, and prepare validation plans." onClick={() => navigate('/attack-simulation')} />
                <Start title="Evidence graph" text="Trace evidence to claims, behavior, ATT&CK, telemetry, detections, validation, and decisions." onClick={() => navigate('/evidence-graph')} />
                <Start title="Compare behavior" text="Rank group, campaign, and stored-report overlap." onClick={() => navigate('/compare')} />
                <Start title="Review coverage" text="Prioritize selected techniques without coverage." onClick={() => navigate('/navigator')} />
                <Start title="Debug malware" text="Open the decompilation/debug IDE for function stepping and AI explanations." onClick={() => navigate('/malware-debug')} />
                <Start title="Unpack sample" text="Plan static/runtime unpacking and continue into strings, debug, and analysis." onClick={() => navigate('/malware-unpacker')} />
              </div>
            </div>
            <Panel title="IOC quick actions">
              <div className="space-y-3 p-2">
                <input
                  value={iocInput}
                  onChange={event => setIocInput(event.target.value)}
                  onKeyDown={event => {
                    if (event.key === 'Enter') runIocLookup();
                  }}
                  placeholder="IP, domain, URL, hash, malware family..."
                  className="field w-full"
                />
                <div className="grid grid-cols-2 gap-2">
                  <button type="button" onClick={runIocLookup} disabled={!iocInput.trim()} className="primary-action disabled:opacity-40">
                    Investigate
                  </button>
                  <button type="button" onClick={runIocSearch} className="secondary-action">
                    Search library
                  </button>
                </div>
                <ActionLink label="Open IOC Library" detail="Search, sort, enrich, export STIX." onClick={() => navigate('/ioc-library')} />
                <ActionLink label="Open IOC Investigation" detail="Tier 1/2/3 pivots, graph, saved sessions, TTPs, actors, AI summary." onClick={() => navigate('/ioc-investigation')} />
                <ActionLink label="Manage feeds" detail={`${enabledSources.length} enabled sources${staleSources.length ? `, ${staleSources.length} need attention` : ''}.`} onClick={() => navigate('/feeds')} />
              </div>
            </Panel>
          </section>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            <Metric label="Actors" value={groups.length} />
            <Metric label="Techniques" value={techniques.length} />
            <Metric label="Public reports" value={uniqueReports.length} />
            <Metric label="Selected TTPs" value={selectedCount} />
            <Metric label="Covered TTPs" value={coverageTechniques.size} />
            <Metric label="Workspaces" value={workspaces.length} />
          </div>

          <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Action launcher">
              <div className="grid gap-2 p-2 md:grid-cols-2 xl:grid-cols-3">
                <ActionLink label="Sector intelligence" detail="Filter relevant actors by sector, region, technology, and recency." onClick={() => navigate('/sector-intel')} />
                <ActionLink label="Asset attack surface" detail="Normalize inventories, score exposure, map entry points to ATT&CK, and save TTP layers." onClick={() => navigate('/asset-surface')} />
                <ActionLink label="Attack Simulation" detail="Choose a TTP first, then configure target validation and evidence capture." onClick={() => navigate('/attack-simulation')} />
                <ActionLink label="Evidence-to-Detection Graph" detail="Preserve the full reasoning path from evidence through SIEM result and analyst decision." onClick={() => navigate('/evidence-graph')} />
                <ActionLink label="Malware Analysis" detail="Upload malware safely, review first analysis, hashes, files, strings, IOCs, TTPs, and family leads." onClick={() => navigate('/malware-analysis')} />
                <ActionLink label="String Analyzer" detail="Extract strings, commands, URLs, registry keys, APIs, and IOC/TTP leads from samples." onClick={() => navigate('/string-analyzer')} />
                <ActionLink label="Decompilation & Debug IDE" detail="Step through functions, inspect pseudocode/disassembly, and get AI explanations per function." onClick={() => navigate('/malware-debug')} />
                <ActionLink label="Malware Unpacker" detail="Analyze packers, unpack layers, deobfuscate strings/code, and continue into debugger tools." onClick={() => navigate('/malware-unpacker')} />
                <ActionLink label="Dynamic analysis" detail="Review safe runtime workflow output, process/file/registry/network/API events, and AI summaries." onClick={() => navigate('/dynamic-analysis')} />
                <ActionLink label="Group vs Group" detail="Compare two adversaries and their overlapping behavior inside Compare." onClick={() => navigate('/compare?mode=group-vs-group')} />
                <ActionLink label="Detection pipeline" detail="Connect Sigma, YARA, YARA-L, sandbox behavior, and AI rule generation." onClick={() => navigate('/pipeline')} />
                <ActionLink label="DFIR examples" detail="Open downloaded public report examples and mapped TTPs." onClick={() => navigate('/examples')} />
                <ActionLink label="Build report" detail="Create investigation output from selected TTPs and evidence." onClick={() => navigate('/report')} />
                <ActionLink label="Operations" detail="Use operational task views for analyst workflow." onClick={() => navigate('/operations')} />
                <ActionLink label="Troubleshooting" detail="Check deployment, API keys, sync failures, and recovery steps." onClick={() => navigate('/troubleshooting')} />
                <ActionLink label="Feed management" detail="Sync ATT&CK, ATLAS, IOC, MISP, TAXII/STIX, YARA, Sigma, and sandbox feeds." onClick={() => navigate('/feeds')} />
                <ActionLink label="ATT&CK Navigator" detail="Open matrix view for selected, covered, and actor-overlay TTPs." onClick={() => navigate('/navigator')} />
                <button
                  type="button"
                  onClick={() => {
                    setShowSelfTestReport(true);
                    selfTest.mutate();
                  }}
                  disabled={selfTest.isPending}
                  className="rounded border border-gray-800 bg-gray-950/40 p-3 text-left hover:border-mitre-accent hover:bg-gray-900 disabled:cursor-wait disabled:opacity-60"
                >
                  <b className="block text-sm text-white">{selfTest.isPending ? 'Running self-test...' : 'Run self-test'}</b>
                  <span className="mt-1 block text-xs leading-5 text-gray-500">Check API, database, Redis, ATT&CK data, API keys, and IOC sync.</span>
                </button>
              </div>
            </Panel>

            <Panel title="Current investigation actions">
              <div className="space-y-3 p-2">
                <div className="grid grid-cols-2 gap-2">
                  <ContextMetric label="Selected TTPs" value={selectedCount} />
                  <ContextMetric label="Coverage gaps" value={missingCoverageCount} />
                </div>
                <div className="flex gap-2">
                  <button type="button" onClick={() => navigate('/compare')} disabled={!selectedCount} className="secondary-action flex-1 disabled:opacity-40">
                    Compare selected
                  </button>
                  <button type="button" onClick={() => navigate('/navigator')} className="secondary-action flex-1">
                    Show matrix
                  </button>
                </div>
                <input
                  value={workspaceName}
                  onChange={event => setWorkspaceName(event.target.value)}
                  placeholder="Workspace name"
                  className="field w-full"
                />
                <div className="flex gap-2">
                  <button type="button" onClick={saveCurrentWorkspace} className="primary-action flex-1">
                    Save workspace
                  </button>
                  <button type="button" onClick={clearTechniques} disabled={!selectedCount} className="secondary-action flex-1 disabled:opacity-40">
                    Clear TTPs
                  </button>
                </div>
                <p className="text-xs text-gray-500">
                  Reference sync: {syncStatus?.any_updates_needed ? 'updates available' : 'up to date or not checked yet'}.
                </p>
              </div>
            </Panel>
          </section>

          <div className="grid gap-5 lg:grid-cols-2">
            <Panel title="Most-referenced techniques">
              {trending.map(item => (
                <button key={item.id} onClick={() => navigate(`/navigator?technique=${item.id}`)} className="list-row">
                  <span className="min-w-0">
                    <b>{item.id} {simulationByTechnique.has(item.id) && <span title="Attack Simulation available" className="text-red-400">⚑</span>}</b>
                    <small>{item.name}</small>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    {simulationByTechnique.get(item.id) && (
                      <span
                        onClick={(event) => {
                          event.stopPropagation();
                          navigate(`/attack-simulation/${simulationByTechnique.get(item.id)}`);
                        }}
                        className="rounded bg-green-950 px-2 py-1 text-[10px] text-green-300"
                      >
                        Sim
                      </span>
                    )}
                    <small className="text-right">{item.count} reports</small>
                  </span>
                </button>
              ))}
            </Panel>
            <Panel title="Recent public intelligence">
              {recent.map(item => (
                <div key={item.url} className="list-row">
                  <a href={item.url} target="_blank" rel="noreferrer" className="min-w-0 hover:text-mitre-accent">
                    <b>{item.title}</b>
                    <small>{item.date} · {item.publisher}</small>
                  </a>
                  <button
                    type="button"
                    onClick={() => navigate(`/ioc-library?search=${encodeURIComponent(item.title)}`)}
                    className="secondary-action shrink-0"
                  >
                    Search IOCs
                  </button>
                </div>
              ))}
            </Panel>
            <Panel title="1200km ecosystem">
              {[
                ['AdversaryGraph docs', 'https://1200km.com/adversarygraph-docs'],
                ['CTI Analyst Field Manual', 'https://1200km.com/cti-analyst-field-manual/'],
                ['Israel Threat Actors CTI', 'https://1200km.com/israel-government-threat-actors-cti/'],
                ['Anomaly Detection Atlas', 'https://1200km.com/anomaly-detection-atlas/'],
                ['Insider Threat Detection Guide', 'https://1200km.com/insider-threat-detection/'],
                ['Medium Research', 'https://medium.com/@1200km'],
              ].map(([label, url]) => (
                <a key={url} href={url} target="_blank" rel="noreferrer" className="list-row">
                  <span><b>{label} ↗</b></span>
                </a>
              ))}
            </Panel>
            <Panel title="Private platform capabilities">
              <div className="grid grid-cols-2 gap-2 p-2">
                {[
                  'AI report extraction',
                  'Asset attack surface mapping',
                  'MalwareGraph case workflow',
                  'Safe sample upload',
                  'Hash reputation and feed checks',
                  'String analysis',
                  'Decompiler and debugger IDE',
                  'AI function explanations',
                  'Static unpack planning',
                  'Dynamic analysis summaries',
                  'Private report library',
                  'Campaign comparison',
                  'Saved server layers',
                  'LLM technique assistant',
                  'Automated ATT&CK sync',
                  'IOC enrichment',
                  'MISP / TAXII / STIX',
                  'YARA / Sigma feeds',
                  'Sandbox behavior',
                  'PDF exports',
                  'API workflows',
                ].map(item => (
                  <span key={item} className="rounded border border-purple-900/50 bg-purple-950/20 p-2 text-xs text-purple-300">
                    {item}
                  </span>
                ))}
              </div>
            </Panel>
          </div>
        </div>
      </div>
      {showSelfTestReport && (
        <SelfTestReportPopup
          result={selfTest.data}
          error={selfTest.error instanceof Error ? selfTest.error : null}
          loading={selfTest.isPending}
          onClose={() => setShowSelfTestReport(false)}
          onRecheck={() => selfTest.mutate()}
        />
      )}
    </div>
  );
}

function Start({ title, text, onClick }: { title: string; text: string; onClick: () => void }) {
  return (
    <button onClick={onClick} className="rounded-lg border border-gray-700 bg-gray-900 p-4 text-left hover:border-mitre-accent">
      <b className="block text-white">{title}</b>
      <span className="mt-1 block text-xs text-gray-500">{text}</span>
    </button>
  );
}

function ActionLink({ label, detail, onClick }: { label: string; detail: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="rounded border border-gray-800 bg-gray-950/40 p-3 text-left hover:border-mitre-accent hover:bg-gray-900"
    >
      <b className="block text-sm text-white">{label}</b>
      <span className="mt-1 block text-xs leading-5 text-gray-500">{detail}</span>
    </button>
  );
}

function SelfTestReportPopup({
  result,
  error,
  loading,
  onClose,
  onRecheck,
}: {
  result?: SelfTestResult;
  error: Error | null;
  loading: boolean;
  onClose: () => void;
  onRecheck: () => void;
}) {
  const apiCheck = result?.checks.find(check => check.name === 'api_keys');
  const syncCheck = result?.checks.find(check => check.name === 'ioc_sync');
  const providers = getProviderEntries(apiCheck?.details.providers);
  const enabledProviders = providers
      .filter(([, value]) => value.configured)
      .map(([key]) => key);
  const syncDetails = syncCheck?.details as {
    enabled_sources?: number;
    degraded_sources?: number;
    auto_full_sync_on_startup?: boolean;
    startup_sync_days?: number;
    sources?: Array<{
      source_id?: string;
      label?: string;
      kind?: string;
      enabled?: boolean;
      sync_status?: string;
      sync_error?: string;
      last_synced_at?: string | null;
      indicator_count?: number;
    }>;
  } | undefined;
  const sources = syncDetails?.sources ?? [];
  const indicatorCount = syncDetails?.sources?.reduce((sum, source) => sum + Number(source.indicator_count ?? 0), 0) ?? 0;
  const ok = result?.status === 'ok' && !error;
  const degraded = result?.status === 'degraded' && !error;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="flex max-h-[90vh] w-full max-w-5xl flex-col rounded-xl border border-gray-700 bg-gray-950 shadow-2xl">
        <div className={`border-b px-5 py-4 ${ok ? 'border-emerald-500/30 bg-emerald-950/20' : degraded ? 'border-amber-500/40 bg-amber-950/25' : error || result?.status === 'error' ? 'border-red-500/40 bg-red-950/25' : 'border-sky-500/30 bg-sky-950/20'}`}>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Self-test report</h2>
              <p className="mt-1 text-sm text-gray-400">
                {loading ? 'Running platform checks...' : error ? 'Self-test request failed.' : ok ? 'All platform checks passed.' : degraded ? 'Core checks passed, but one or more enabled feeds are degraded.' : 'One or more platform checks returned errors.'}
              </p>
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={onRecheck} disabled={loading} className="secondary-action disabled:opacity-50">
                {loading ? 'Running...' : 'Recheck'}
              </button>
              <button type="button" onClick={onClose} className="secondary-action">Close</button>
            </div>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto p-5">
          {loading && !result && !error ? (
            <div className="rounded border border-sky-500/30 bg-sky-950/20 p-4 text-sm text-sky-100">Self-test is running...</div>
          ) : error ? (
            <div className="rounded border border-red-500/50 bg-red-950/30 p-4 text-sm text-red-100">{error.message}</div>
          ) : result ? (
            <div className="space-y-5">
              <div className="grid gap-3 md:grid-cols-4">
                <ReportMetric label="Overall status" value={result.status.toUpperCase()} tone={ok ? 'ok' : degraded ? 'warning' : 'error'} />
                <ReportMetric label="Checks passed" value={`${result.checks.filter(check => check.status === 'ok').length}/${result.checks.length}`} />
                <ReportMetric label="Runtime" value={`${result.duration_ms} ms`} />
                <ReportMetric label="Version" value={result.version} />
              </div>

              <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <h3 className="text-sm font-semibold text-white">Enabled APIs</h3>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {providers.map(([name, provider]) => (
                    <div key={name} className="flex items-center justify-between rounded border border-gray-800 bg-gray-950/50 px-3 py-2 text-xs">
                      <span>
                        <b className="text-gray-200">{providerLabel(name)}</b>
                        <span className="ml-2 font-mono text-gray-600">{provider.env_var}</span>
                      </span>
                      <span className={provider.configured ? 'text-emerald-300' : 'text-gray-500'}>
                        {provider.configured ? 'enabled' : 'not configured'}
                      </span>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-xs text-gray-500">Enabled: {enabledProviders.length ? enabledProviders.map(providerLabel).join(', ') : 'none'}</p>
              </section>

              <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-white">IOC sync status</h3>
                  <span className="text-xs text-gray-400">
                    {syncDetails?.enabled_sources ?? 0} enabled sources · {syncDetails?.degraded_sources ?? 0} degraded · {indicatorCount.toLocaleString()} indicators
                  </span>
                </div>
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full min-w-[760px] text-left text-xs">
                    <thead className="bg-gray-950 text-[10px] uppercase text-gray-500">
                      <tr>
                        <th className="p-2">Source</th>
                        <th className="p-2">Kind</th>
                        <th className="p-2">Enabled</th>
                        <th className="p-2">Status</th>
                        <th className="p-2">Indicators</th>
                        <th className="p-2">Last sync</th>
                        <th className="p-2">Error</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {sources.map(source => (
                        <tr key={source.source_id ?? source.label}>
                          <td className="p-2 text-gray-200">{source.label ?? source.source_id}</td>
                          <td className="p-2 text-gray-500">{source.kind ?? '-'}</td>
                          <td className="p-2">{source.enabled ? <span className="text-emerald-300">yes</span> : <span className="text-gray-600">no</span>}</td>
                          <td className="p-2 text-gray-300">{source.sync_status || 'not synced'}</td>
                          <td className="p-2 text-gray-300">{Number(source.indicator_count ?? 0).toLocaleString()}</td>
                          <td className="p-2 text-gray-500">{source.last_synced_at ? new Date(source.last_synced_at).toLocaleString() : '-'}</td>
                          <td className="p-2 text-red-300">{source.sync_error || '-'}</td>
                        </tr>
                      ))}
                      {!sources.length && (
                        <tr><td colSpan={7} className="p-3 text-center text-gray-500">No IOC sync source details returned.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-4">
                <h3 className="text-sm font-semibold text-white">All checks</h3>
                <div className="mt-3 space-y-2">
                  {result.checks.map(check => (
                    <details key={check.name} className="rounded border border-gray-800 bg-gray-950/50 p-3" open={check.status !== 'ok'}>
                      <summary className="cursor-pointer text-sm text-gray-200">
                        <span className={checkStatusClass(check.status)}>{checkStatusLabel(check.status)}</span>
                        <span className="ml-2 font-mono">{check.name}</span>
                        <span className="ml-2 text-xs text-gray-500">{check.message}</span>
                      </summary>
                      <pre className="mt-3 max-h-56 overflow-auto rounded bg-black/40 p-3 text-[11px] text-gray-400">{JSON.stringify(check.details, null, 2)}</pre>
                    </details>
                  ))}
                </div>
              </section>
              <p className="text-xs text-gray-600">Checked at: {new Date(result.checked_at).toLocaleString()}</p>
            </div>
          ) : (
            <div className="rounded border border-gray-800 bg-gray-900/50 p-4 text-sm text-gray-400">No self-test result yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function getProviderEntries(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, { configured?: boolean; env_var?: string }>);
}

function providerLabel(name: string) {
  const labels: Record<string, string> = {
    anthropic: 'Claude',
    openai: 'OpenAI',
    gemini: 'Gemini',
    minimax: 'MiniMax',
    local_llm_base_url: 'Local LLM',
    threatfox: 'ThreatFox',
    otx: 'AlienVault OTX',
    virustotal: 'VirusTotal',
  };
  return labels[name] ?? name;
}

function ReportMetric({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: 'neutral' | 'ok' | 'warning' | 'error' }) {
  const valueColor = tone === 'ok' ? 'text-emerald-300' : tone === 'warning' ? 'text-amber-300' : tone === 'error' ? 'text-red-300' : 'text-white';
  return (
    <div className="rounded border border-gray-800 bg-gray-900/70 p-3">
      <b className={`block text-lg ${valueColor}`}>{value}</b>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  );
}

function checkStatusLabel(status: SelfTestResult['checks'][number]['status']) {
  if (status === 'ok') return 'OK';
  if (status === 'degraded' || status === 'warning') return 'WARN';
  return 'FAIL';
}

function checkStatusClass(status: SelfTestResult['checks'][number]['status']) {
  if (status === 'ok') return 'text-emerald-300';
  if (status === 'degraded' || status === 'warning') return 'text-amber-300';
  return 'text-red-300';
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-900 p-3">
      <b className="block text-xl text-white">{value}</b>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  );
}

function ContextMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/40 p-3">
      <b className="block text-lg text-white">{value}</b>
      <span className="text-[10px] text-gray-500">{label}</span>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-3">
      <h2 className="px-2 py-1 text-sm font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}
