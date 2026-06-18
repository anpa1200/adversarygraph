import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { iocApi, syncApi } from '@/api/client';
import { Header } from '@/components/Layout/Header';

const domainLabels: Record<string, string> = {
  'enterprise-attack': 'Enterprise',
  'mobile-attack': 'Mobile',
  'ics-attack': 'ICS',
  'atlas': 'ATLAS',
};

export function Sync() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<string[]>([]);
  const [force, setForce] = useState(false);
  const [taskId, setTaskId] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ['sync-status'],
    queryFn: syncApi.status,
    refetchInterval: 5 * 60 * 1000,
  });

  const task = useQuery({
    queryKey: ['sync-task', taskId],
    queryFn: () => syncApi.taskStatus(taskId as string),
    enabled: !!taskId,
    refetchInterval: query => {
      const state = query.state.data?.status;
      return state && !['PENDING', 'STARTED', 'RETRY'].includes(state) ? false : 2500;
    },
  });

  useEffect(() => {
    const state = task.data?.status;
    if (state && !['PENDING', 'STARTED', 'RETRY'].includes(state)) {
      qc.invalidateQueries({ queryKey: ['sync-status'] });
      qc.invalidateQueries({ queryKey: ['attack-versions'] });
    }
  }, [task.data?.status, qc]);

  const domains = useMemo(() => status.data?.domains ?? [], [status.data?.domains]);
  const sources = useMemo(() => status.data?.sources ?? [], [status.data?.sources]);
  const activeDomains = selected.length ? selected : domains.map(item => item.domain);
  const taskRunning = !!taskId && ['PENDING', 'STARTED', 'RETRY'].includes(task.data?.status ?? 'PENDING');

  const content = useMemo(() => {
    const mitre = sources.find(source => source.id === 'mitre-attack');
    return mitre?.content ?? domains[0]?.content ?? [];
  }, [sources, domains]);

  const trigger = useMutation({
    mutationFn: () => syncApi.trigger({ source: 'mitre-attack', domains: activeDomains, force }),
    onSuccess: data => {
      setTaskId(data.task_id);
      qc.invalidateQueries({ queryKey: ['sync-status'] });
    },
  });
  const iocSync = useMutation({
    mutationFn: () => syncApi.ioc(7),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
      qc.invalidateQueries({ queryKey: ['actor-iocs'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const malpediaSync = useMutation({
    mutationFn: iocApi.syncMalpedia,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
      qc.invalidateQueries({ queryKey: ['actor-iocs'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });
  const dynamicDbSync = useMutation({
    mutationFn: () => syncApi.dynamicDb({ days: 7, force_attack: force }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sync-status'] });
      qc.invalidateQueries({ queryKey: ['attack-versions'] });
      qc.invalidateQueries({ queryKey: ['sector-sources'] });
      qc.invalidateQueries({ queryKey: ['sector-options'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-counts'] });
      qc.invalidateQueries({ queryKey: ['actor-ioc-summary'] });
      qc.invalidateQueries({ queryKey: ['actor-iocs'] });
      qc.invalidateQueries({ queryKey: ['ioc-sources'] });
    },
  });

  const toggle = (domain: string) => {
    setSelected(current =>
      current.includes(domain)
        ? current.filter(item => item !== domain)
        : [...current, domain],
    );
  };

  return (
    <div className="flex flex-col h-full">
      <Header title="Reference Sync" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="max-w-7xl mx-auto space-y-5">
          <section className="grid lg:grid-cols-[1.2fr_.8fr] gap-5">
            <Panel title="MITRE ATT&CK Synchronization">
              <div className="p-4 space-y-4">
                <p className="text-sm text-gray-400">
                  Synchronize ATT&CK matrices, tactics, techniques, sub-techniques, APT group profiles, campaigns, usage relationships, and references from MITRE STIX bundles.
                </p>
                <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">
                  {domains.map(item => (
                    <button
                      key={item.domain}
                      onClick={() => toggle(item.domain)}
                      className={`rounded border px-3 py-3 text-left transition-colors ${
                        activeDomains.includes(item.domain)
                          ? 'border-mitre-accent bg-mitre-accent/10 text-white'
                          : 'border-gray-700 bg-gray-900 text-gray-500 hover:text-gray-300'
                      }`}
                    >
                      <b className="block text-sm">{domainLabels[item.domain] ?? item.domain}</b>
                      <span className="text-[10px] text-gray-500">{item.current_version ?? 'not ingested'} → {item.latest_version ?? 'unknown'}</span>
                    </button>
                  ))}
                </div>
                <label className="flex items-center gap-2 text-xs text-gray-400">
                  <input type="checkbox" checked={force} onChange={e => setForce(e.target.checked)} />
                  Force refresh latest cached version even when already current
                </label>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => trigger.mutate()}
                    disabled={trigger.isPending || taskRunning || activeDomains.length === 0}
                    className="primary"
                  >
                    {force ? 'Force sync selected' : 'Sync selected'}
                  </button>
                  {trigger.error && <span className="text-xs text-red-400">{String(trigger.error)}</span>}
                  {taskId && <span className="text-xs text-gray-500 font-mono">task {taskId.slice(0, 8)} · {task.data?.status ?? 'PENDING'}</span>}
                </div>
              </div>
            </Panel>

            <Panel title="IOC Intelligence Synchronization">
              <div className="p-4 space-y-4">
                <p className="text-sm text-gray-400">
                  Centrally refresh all IOC and malware-context sources: ThreatFox recent IOCs, Malpedia malware-family actor attributions, AlienVault OTX actor pulses, and every enabled custom JSON, CSV, or TXT IOC feed. Actor IOC counts update after the sync completes.
                </p>
                <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-500">
                  Malpedia adds malware-family records and actor attribution evidence. ThreatFox recent API supports 1-7 days. Larger windows should be handled with ThreatFox exports or custom feeds.
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <button
                    onClick={() => dynamicDbSync.mutate()}
                    disabled={dynamicDbSync.isPending}
                    className="primary"
                  >
                    {dynamicDbSync.isPending ? 'Syncing dynamic DB...' : 'Sync dynamic DB'}
                  </button>
                  <button
                    onClick={() => iocSync.mutate()}
                    disabled={iocSync.isPending}
                    className="primary"
                  >
                    {iocSync.isPending ? 'Syncing IOCs...' : 'Sync all IOC sources'}
                  </button>
                  <button
                    onClick={() => malpediaSync.mutate()}
                    disabled={malpediaSync.isPending}
                    className="secondary-action"
                  >
                    {malpediaSync.isPending ? 'Syncing Malpedia...' : 'Sync Malpedia'}
                  </button>
                  {dynamicDbSync.error && <span className="text-xs text-red-400">{errorMessage(dynamicDbSync.error)}</span>}
                  {iocSync.error && <span className="text-xs text-red-400">{errorMessage(iocSync.error)}</span>}
                  {malpediaSync.error && <span className="text-xs text-red-400">{errorMessage(malpediaSync.error)}</span>}
                </div>
                {dynamicDbSync.data && (
                  <div className="rounded border border-green-900 bg-green-950/30 p-3 text-xs text-green-300">
                    Dynamic DB sync complete. Public ATT&CK/ATLAS, MISP Galaxy, and IOC enrichment sources were refreshed; private/custom DB records are preserved.
                  </div>
                )}
                {malpediaSync.data && (
                  <div className="rounded border border-blue-900 bg-blue-950/30 p-3 text-xs text-blue-200">
                    Malpedia: {malpediaSync.data.families} families, {malpediaSync.data.attributed_families} attributed families, {malpediaSync.data.actor_links} actor links.
                  </div>
                )}
                {iocSync.data && (
                  <div className="rounded border border-green-900 bg-green-950/30 p-3 text-xs text-green-300">
                    Synced IOCs: {iocSync.data.totals.inserted} new, {iocSync.data.totals.updated} updated, {iocSync.data.totals.actor_links} actor links.
                  </div>
                )}
                {iocSync.data?.sources?.length ? (
                  <div className="max-h-44 space-y-2 overflow-y-auto">
                    {iocSync.data.sources.map((source, index) => (
                      <div key={`${String(source.source)}-${index}`} className="rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs">
                        <div className="flex items-center justify-between gap-3">
                          <span className="font-mono text-gray-300">{String(source.source)}</span>
                          <span className={String(source.status) === 'ok' ? 'text-green-400' : 'text-red-300'}>{String(source.status)}</span>
                        </div>
                        {source.error ? <div className="mt-1 text-[10px] text-red-300">{String(source.error)}</div> : null}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </Panel>

            <Panel title="Reference Sources">
              <div className="divide-y divide-gray-800">
                {sources.map(source => (
                  <div key={source.id} className="p-4">
                    <div className="flex items-center justify-between gap-3">
                      <b className="text-sm text-white">{source.label}</b>
                      <span className={`text-[10px] px-2 py-1 rounded-full ${source.status === 'active' ? 'bg-green-950 text-green-400' : 'bg-gray-800 text-gray-500'}`}>{source.status}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-2">{source.schedule ?? 'No automated schedule configured'}</p>
                    <div className="flex flex-wrap gap-1.5 mt-3">
                      {source.content.map(item => <span key={item} className="rounded border border-gray-800 px-2 py-1 text-[10px] text-gray-400">{item}</span>)}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </section>

          <Panel title="Domain Status">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-gray-500 uppercase">
                  <tr>
                    <th className="text-left p-3">Domain</th>
                    <th className="text-left p-3">Current</th>
                    <th className="text-left p-3">Latest</th>
                    <th className="text-left p-3">State</th>
                    <th className="text-left p-3">Last ingested</th>
                  </tr>
                </thead>
                <tbody>
                  {domains.map(item => (
                    <tr key={item.domain} className="border-t border-gray-800">
                      <td className="p-3 text-white">{domainLabels[item.domain] ?? item.domain}</td>
                      <td className="p-3 font-mono text-gray-300">{item.current_version ?? '-'}</td>
                      <td className="p-3 font-mono text-gray-300">{item.latest_version ?? '-'}</td>
                      <td className="p-3">
                        <span className={`rounded-full px-2 py-1 text-[10px] ${item.needs_update ? 'bg-amber-950 text-amber-300' : 'bg-green-950 text-green-400'}`}>
                          {item.needs_update ? 'update available' : 'current'}
                        </span>
                      </td>
                      <td className="p-3 text-gray-500">{item.last_ingested ?? '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {status.isLoading && <div className="p-4 text-sm text-gray-500">Checking references...</div>}
              {status.error && <div className="p-4 text-sm text-red-400">{String(status.error)}</div>}
            </div>
          </Panel>

          {task.data?.result ? (
            <Panel title="Last Task Result">
              <pre className="m-4 max-h-72 overflow-auto rounded bg-gray-950 p-3 text-xs text-gray-400">{JSON.stringify(task.data.result, null, 2)}</pre>
            </Panel>
          ) : null}

          <Panel title="Synchronized Content">
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2 p-4">
              {content.map(item => <span key={item} className="rounded border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-300">{item}</span>)}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/60 overflow-hidden"><h2 className="text-sm font-semibold text-white px-4 py-3 border-b border-gray-800">{title}</h2>{children}</section>;
}

function errorMessage(error: unknown) {
  if (!error) return '';
  if (typeof error === 'object' && error !== null && 'response' in error) {
    const response = (error as { response?: { data?: { detail?: string } } }).response;
    if (response?.data?.detail) return response.data.detail;
  }
  return error instanceof Error ? error.message : String(error);
}
