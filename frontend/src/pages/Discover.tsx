import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { aptApi, attackApi, iocApi, syncApi, systemApi, type SelfTestResult } from '@/api/client';
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
  const { data: groups = [] } = useQuery({
    queryKey: ['discover-groups', domain, version],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined }),
  });
  const { data: techniques = [] } = useQuery({
    queryKey: ['discover-techniques', domain, version],
    queryFn: () => attackApi.techniques({ domain, version: version ?? undefined }),
  });
  const { data: reports } = useQuery({ queryKey: ['report-index'], queryFn: loadReportIndex });
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
  const selectedCount = selectedTechniques.size;
  const missingCoverageCount = Math.max(0, selectedTechniques.size - coverageTechniques.size);
  const enabledSources = sources.filter(source => source.enabled);
  const staleSources = enabledSources.filter(source => source.sync_status && !['ok', 'configured', 'active'].includes(source.sync_status));

  const runIocLookup = () => {
    const value = iocInput.trim();
    if (!value) return;
    navigate(`/virustotal?indicator=${encodeURIComponent(value)}`);
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
      <div className="min-h-0 flex-1 overflow-y-auto px-6 pb-6 pt-8">
        <div className="mx-auto max-w-7xl space-y-7">
          <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
            <div>
              <p className="mb-6 max-w-3xl text-sm text-gray-400">
                Start with an actor, behavior, report, IOC, sector, feed, detection gap, or AI analysis. AdversaryGraph connects live
                ATT&amp;CK data, IOC enrichment, private analysis, and the shared 1200km research ecosystem.
              </p>
              <div className="grid gap-3 md:grid-cols-4">
                <Start title="Investigate actor" text="Profiles, campaigns, reports, aliases, behavior, and IOCs." onClick={() => navigate('/apt')} />
                <Start title="Analyze report with AI" text="Extract ATT&CK evidence using your configured LLM." onClick={() => navigate('/analyze')} />
                <Start title="Compare behavior" text="Rank group, campaign, and stored-report overlap." onClick={() => navigate('/compare')} />
                <Start title="Review coverage" text="Prioritize selected techniques without coverage." onClick={() => navigate('/navigator')} />
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
                    Enrichment
                  </button>
                  <button type="button" onClick={runIocSearch} className="secondary-action">
                    Search library
                  </button>
                </div>
                <ActionLink label="Open IOC Library" detail="Search, sort, enrich, export STIX." onClick={() => navigate('/ioc-library')} />
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
                <ActionLink label="Group vs Group" detail="Compare two adversaries and their overlapping behavior." onClick={() => navigate('/group-compare')} />
                <ActionLink label="Detection pipeline" detail="Connect Sigma, YARA, YARA-L, sandbox behavior, and AI rule generation." onClick={() => navigate('/pipeline')} />
                <ActionLink label="DFIR examples" detail="Open downloaded public report examples and mapped TTPs." onClick={() => navigate('/examples')} />
                <ActionLink label="Build report" detail="Create investigation output from selected TTPs and evidence." onClick={() => navigate('/report')} />
                <ActionLink label="Operations" detail="Use operational task views for analyst workflow." onClick={() => navigate('/operations')} />
                <ActionLink label="Troubleshooting" detail="Check deployment, API keys, sync failures, and recovery steps." onClick={() => navigate('/troubleshooting')} />
                <ActionLink label="Feed management" detail="Sync ATT&CK, ATLAS, IOC, MISP, TAXII/STIX, YARA, Sigma, and sandbox feeds." onClick={() => navigate('/feeds')} />
                <ActionLink label="ATT&CK Navigator" detail="Open matrix view for selected, covered, and actor-overlay TTPs." onClick={() => navigate('/navigator')} />
                <button
                  type="button"
                  onClick={() => selfTest.mutate()}
                  disabled={selfTest.isPending}
                  className="rounded border border-gray-800 bg-gray-950/40 p-3 text-left hover:border-mitre-accent hover:bg-gray-900 disabled:cursor-wait disabled:opacity-60"
                >
                  <b className="block text-sm text-white">{selfTest.isPending ? 'Running self-test...' : 'Run self-test'}</b>
                  <span className="mt-1 block text-xs leading-5 text-gray-500">Check API, database, Redis, ATT&CK data, API keys, and IOC sync.</span>
                </button>
              </div>
              {(selfTest.data || selfTest.error) && (
                <SelfTestInlineResult result={selfTest.data} error={selfTest.error instanceof Error ? selfTest.error : null} />
              )}
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
                    <b>{item.id}</b>
                    <small>{item.name}</small>
                  </span>
                  <small className="shrink-0 text-right">{item.count} reports</small>
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

function SelfTestInlineResult({ result, error }: { result?: SelfTestResult; error: Error | null }) {
  const apiCheck = result?.checks.find(check => check.name === 'api_keys');
  const syncCheck = result?.checks.find(check => check.name === 'ioc_sync');
  const providers = apiCheck?.details.providers && typeof apiCheck.details.providers === 'object'
    ? Object.entries(apiCheck.details.providers as Record<string, { configured?: boolean }>)
      .filter(([, value]) => value.configured)
      .map(([key]) => key)
    : [];
  const syncDetails = syncCheck?.details as { enabled_sources?: number; sources?: Array<{ indicator_count?: number }> } | undefined;
  const indicatorCount = syncDetails?.sources?.reduce((sum, source) => sum + Number(source.indicator_count ?? 0), 0) ?? 0;
  const ok = result?.status === 'ok' && !error;

  return (
    <div className={`m-2 rounded border p-3 text-xs ${ok ? 'border-emerald-500/40 bg-emerald-950/20 text-emerald-100' : 'border-red-500/50 bg-red-950/30 text-red-100'}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <b>{error ? 'Self-test failed' : ok ? 'Self-test passed' : 'Self-test returned errors'}</b>
        {result && <span className="font-mono opacity-80">{result.duration_ms} ms · v{result.version}</span>}
      </div>
      {error ? (
        <p className="mt-2 opacity-90">{error.message}</p>
      ) : result ? (
        <div className="mt-2 grid gap-2 md:grid-cols-3">
          <span>Checks: {result.checks.filter(check => check.status === 'ok').length}/{result.checks.length} OK</span>
          <span>Enabled APIs: {providers.length ? providers.join(', ') : 'none'}</span>
          <span>IOC sync: {syncDetails?.enabled_sources ?? 0} sources · {indicatorCount.toLocaleString()} IOCs</span>
        </div>
      ) : null}
    </div>
  );
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
