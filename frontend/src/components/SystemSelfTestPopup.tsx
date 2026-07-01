import { PointerEvent, useEffect, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { systemApi, type SelfTestCheck, type SelfTestResult } from '@/api/client';

type PopupState = 'visible' | 'collapsed' | 'dismissed';
type ProviderDetail = {
  configured?: boolean;
  env_var?: string;
  optional_env_var?: string;
  category?: string;
  auth_mode?: string;
  api_key_configured?: boolean;
  required_for?: string[];
};
type IocSourceDetail = {
  source_id?: string;
  label?: string;
  kind?: string;
  enabled?: boolean;
  sync_status?: string | null;
  sync_error?: string | null;
  last_synced_at?: string | null;
  indicator_count?: number;
};
type CveSourceDetail = Omit<IocSourceDetail, 'indicator_count'>;

const providerLabels: Record<string, string> = {
  anthropic: 'Claude',
  openai: 'OpenAI',
  gemini: 'Gemini',
  minimax: 'MiniMax',
  local_llm_base_url: 'Local LLM',
  threatfox: 'ThreatFox',
  otx: 'AlienVault OTX',
  virustotal: 'VirusTotal',
  urlscan: 'urlscan.io',
  greynoise: 'GreyNoise',
  abuseipdb: 'AbuseIPDB',
  shodan: 'Shodan',
  censys: 'Censys',
  opencti: 'OpenCTI',
};

function summarize(result?: SelfTestResult, error?: Error | null) {
  if (error) {
    return {
      title: 'AdversaryGraph startup problem',
      body: error.message,
      tone: 'error' as const,
    };
  }
  if (!result) {
    return {
      title: 'Running startup self-test',
      body: 'Checking API, database, Redis, storage, ATT&CK data, MalwareGraph, attack labs, API keys, IOC feeds, and CVE Library feed sync state.',
      tone: 'pending' as const,
    };
  }
  if (result.status === 'ok') {
    return {
      title: 'AdversaryGraph self-test passed',
      body: `API, database, Redis, storage, ATT&CK data, MalwareGraph, attack labs, API keys, IOC feeds, and CVE Library feed sync state are ready. Checked in ${result.duration_ms} ms.`,
      tone: 'ok' as const,
    };
  }
  if (result.status === 'degraded') {
    const syncCheck = checkByName(result, 'ioc_sync');
    const cveSyncCheck = checkByName(result, 'cve_sync');
    const syncDetails = asRecord(syncCheck?.details);
    const cveSyncDetails = asRecord(cveSyncCheck?.details);
    const degradedSources = Number(syncDetails.degraded_sources ?? 0);
    const degradedCveSources = Array.isArray(cveSyncDetails.sources)
      ? cveSyncDetails.sources.filter(source => asRecord(source).sync_status === 'error').length
      : 0;
    return {
      title: 'AdversaryGraph self-test degraded',
      body: `Core platform checks passed, but ${degradedSources + degradedCveSources || 'one or more'} feed source${degradedSources + degradedCveSources === 1 ? '' : 's'} need attention. Checked in ${result.duration_ms} ms.`,
      tone: 'warning' as const,
    };
  }
  const failed = result.checks.filter(check => check.status !== 'ok');
  return {
    title: 'AdversaryGraph self-test failed',
    body: failed.map(check => `${check.name}: ${check.message}`).join(' '),
    tone: 'error' as const,
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function checkByName(result: SelfTestResult, name: string): SelfTestCheck | undefined {
  return result.checks.find(check => check.name === name);
}

function configuredProviders(check?: SelfTestCheck) {
  const providers = asRecord(check?.details.providers);
  return Object.entries(providers)
    .map(([name, value]) => ({ name, ...(asRecord(value) as ProviderDetail) }))
    .filter(provider => provider.configured)
    .sort((a, b) => providerLabels[a.name]?.localeCompare(providerLabels[b.name] ?? b.name) ?? a.name.localeCompare(b.name));
}

function enabledSources(check?: SelfTestCheck) {
  const sources = Array.isArray(check?.details.sources) ? check?.details.sources : [];
  return sources
    .map(source => asRecord(source) as IocSourceDetail)
    .filter(source => source.enabled)
    .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
}

function cveSources(check?: SelfTestCheck) {
  const sources = Array.isArray(check?.details.sources) ? check?.details.sources : [];
  return sources
    .map(source => asRecord(source) as CveSourceDetail)
    .filter(source => source.enabled)
    .sort((a, b) => (a.label ?? '').localeCompare(b.label ?? ''));
}

function SelfTestDetails({ result }: { result: SelfTestResult }) {
  const apiCheck = checkByName(result, 'api_keys');
  const syncCheck = checkByName(result, 'ioc_sync');
  const cveSyncCheck = checkByName(result, 'cve_sync');
  const providers = configuredProviders(apiCheck);
  const llmProviders = providers.filter(provider => provider.category === 'llm');
  const feedProviders = providers.filter(provider => provider.category === 'feed');
  const investigationProviders = providers.filter(provider => provider.category === 'investigation');
  const sources = enabledSources(syncCheck);
  const vulnerabilitySources = cveSources(cveSyncCheck);
  const syncDetails = asRecord(syncCheck?.details);
  const cveSyncDetails = asRecord(cveSyncCheck?.details);
  const storedIndicators = sources.reduce((sum, source) => sum + Number(source.indicator_count ?? 0), 0);

  return (
    <div className="space-y-3 text-xs">
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="rounded border border-white/10 bg-black/15 p-2">
          <p className="font-semibold">Enabled LLM APIs</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {llmProviders.length > 0
              ? llmProviders.map(provider => (
                <span key={provider.name} className="rounded bg-emerald-500/15 px-2 py-0.5 text-emerald-100">
                  {providerLabels[provider.name] ?? provider.name}
                </span>
              ))
              : <span className="opacity-70">None configured</span>}
          </div>
        </div>
        <div className="rounded border border-white/10 bg-black/15 p-2">
          <p className="font-semibold">Enabled feed APIs</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {feedProviders.length > 0
              ? feedProviders.map(provider => (
                <span key={provider.name} title={provider.required_for?.join(', ')} className="rounded bg-emerald-500/15 px-2 py-0.5 text-emerald-100">
                  {providerLabels[provider.name] ?? provider.name}
                </span>
              ))
              : <span className="opacity-70">None configured</span>}
          </div>
        </div>
      </div>

      <div className="rounded border border-white/10 bg-black/15 p-2">
        <p className="font-semibold">Enabled investigation APIs</p>
        <div className="mt-2 flex flex-wrap gap-1">
          {investigationProviders.length > 0
            ? investigationProviders.map(provider => (
              <span key={provider.name} title={provider.required_for?.join(', ')} className="rounded bg-sky-500/15 px-2 py-0.5 text-sky-100">
                {providerLabels[provider.name] ?? provider.name}
                {provider.auth_mode && !provider.api_key_configured ? ' · public' : ''}
              </span>
            ))
            : <span className="opacity-70">None configured</span>}
        </div>
      </div>

      <div className="rounded border border-white/10 bg-black/15 p-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="font-semibold">Sync status</p>
          <span className="opacity-80">
            {String(syncDetails.enabled_sources ?? sources.length)} enabled sources · {String(syncDetails.degraded_sources ?? 0)} degraded · {storedIndicators.toLocaleString()} indicators
          </span>
        </div>
        <div className="mt-2 max-h-36 space-y-1 overflow-y-auto pr-1">
          {sources.length > 0 ? sources.map(source => (
            <div key={source.source_id ?? source.label} className="flex items-start justify-between gap-3 rounded bg-black/20 px-2 py-1">
              <div>
                <p className="font-medium">{source.label ?? source.source_id}</p>
                <p className="opacity-70">
                  {source.kind ?? 'feed'} · {Number(source.indicator_count ?? 0).toLocaleString()} IOCs
                  {source.last_synced_at ? ` · ${new Date(source.last_synced_at).toLocaleString()}` : ''}
                </p>
                {source.sync_error && <p className="text-red-200">{source.sync_error}</p>}
              </div>
              <span className={source.sync_status === 'ok' ? 'text-emerald-300' : 'text-amber-200'}>
                {source.sync_status ?? 'not synced'}
              </span>
            </div>
          )) : <p className="opacity-70">No enabled IOC sources found yet.</p>}
        </div>
      </div>

      <div className="rounded border border-white/10 bg-black/15 p-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="font-semibold">CVE Library sync status</p>
          <span className="opacity-80">
            {String(cveSyncDetails.cve_count ?? 0)} CVEs · {String(cveSyncDetails.known_exploited_count ?? 0)} KEV
          </span>
        </div>
        <div className="mt-2 max-h-28 space-y-1 overflow-y-auto pr-1">
          {vulnerabilitySources.length > 0 ? vulnerabilitySources.map(source => (
            <div key={source.source_id ?? source.label} className="flex items-start justify-between gap-3 rounded bg-black/20 px-2 py-1">
              <div>
                <p className="font-medium">{source.label ?? source.source_id}</p>
                <p className="opacity-70">
                  {source.kind ?? 'feed'}
                  {source.last_synced_at ? ` · ${new Date(source.last_synced_at).toLocaleString()}` : ''}
                </p>
                {source.sync_error && <p className="text-red-200">{source.sync_error}</p>}
              </div>
              <span className={source.sync_status === 'ok' ? 'text-emerald-300' : 'text-amber-200'}>
                {source.sync_status ?? 'not synced'}
              </span>
            </div>
          )) : <p className="opacity-70">No CVE sources found yet.</p>}
        </div>
      </div>
    </div>
  );
}

export function SystemSelfTestPopup() {
  const [popupState, setPopupState] = useState<PopupState>('visible');
  const [position, setPosition] = useState<{ x: number; y: number } | null>(null);
  const dragOffset = useRef<{ x: number; y: number } | null>(null);
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ['system-selftest'],
    queryFn: systemApi.selftest,
    retry: 8,
    retryDelay: attempt => Math.min(2000 + attempt * 1500, 8000),
    refetchOnWindowFocus: false,
  });

  useEffect(() => {
    if (query.data?.status === 'ok') {
      queryClient.invalidateQueries({ queryKey: ['tactics'] });
      queryClient.invalidateQueries({ queryKey: ['all-techniques'] });
      queryClient.invalidateQueries({ queryKey: ['discover-groups'] });
      queryClient.invalidateQueries({ queryKey: ['discover-techniques'] });
      queryClient.invalidateQueries({ queryKey: ['sync-status'] });
      const timer = window.setTimeout(() => setPopupState('collapsed'), 7000);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [query.data?.status, queryClient]);

  if (popupState === 'dismissed') return null;

  const error = query.error instanceof Error ? query.error : null;
  const summary = summarize(query.data, error);
  const troubleshootingUrl = `/troubleshooting?${new URLSearchParams({
    error: summary.body,
    url: '/system/selftest',
    ...(error ? {} : { status: query.data?.status === 'ok' ? '200' : query.data?.status === 'degraded' ? 'selftest-degraded' : 'selftest-failed' }),
  }).toString()}`;
  const color =
    summary.tone === 'ok'
      ? 'border-emerald-500/50 bg-emerald-950/90 text-emerald-50'
      : summary.tone === 'warning'
        ? 'border-amber-500/60 bg-amber-950/95 text-amber-50'
      : summary.tone === 'error'
        ? 'border-red-500/60 bg-red-950/95 text-red-50'
        : 'border-sky-500/50 bg-slate-950/95 text-sky-50';

  if (popupState === 'collapsed') {
    const isDegraded = query.data?.status === 'degraded';
    return (
      <button
        type="button"
        onClick={() => setPopupState('visible')}
        className={`fixed bottom-4 right-4 z-50 rounded border px-3 py-2 text-xs font-semibold shadow-lg ${isDegraded ? 'border-amber-500/50 bg-amber-950/90 text-amber-100' : 'border-emerald-500/50 bg-emerald-950/90 text-emerald-100'}`}
      >
        {isDegraded ? 'Self-test Degraded' : 'Self-test OK'}
      </button>
    );
  }

  const panelWidth = typeof window === 'undefined' ? 440 : Math.min(520, window.innerWidth - 24);
  const panelHeight = typeof window === 'undefined' ? 720 : Math.min(720, window.innerHeight - 24);
  const currentPosition = position ?? {
    x: typeof window === 'undefined' ? 16 : Math.max(12, window.innerWidth - panelWidth - 16),
    y: 56,
  };

  function clampPosition(next: { x: number; y: number }) {
    if (typeof window === 'undefined') return next;
    return {
      x: Math.max(8, Math.min(next.x, window.innerWidth - panelWidth - 8)),
      y: Math.max(8, Math.min(next.y, window.innerHeight - 96)),
    };
  }

  function startDrag(event: PointerEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    if (target.closest('button,a')) return;
    dragOffset.current = {
      x: event.clientX - currentPosition.x,
      y: event.clientY - currentPosition.y,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function moveDrag(event: PointerEvent<HTMLDivElement>) {
    if (!dragOffset.current) return;
    setPosition(clampPosition({
      x: event.clientX - dragOffset.current.x,
      y: event.clientY - dragOffset.current.y,
    }));
  }

  function stopDrag(event: PointerEvent<HTMLDivElement>) {
    dragOffset.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }

  return (
    <div
      className={`fixed z-50 flex max-w-[calc(100vw-1rem)] flex-col overflow-hidden rounded-lg border shadow-2xl ${color}`}
      style={{
        left: currentPosition.x,
        top: currentPosition.y,
        width: panelWidth,
        maxHeight: panelHeight,
      }}
    >
      <div
        className="flex cursor-move items-start justify-between gap-3 border-b border-white/10 bg-black/20 p-3"
        onPointerDown={startDrag}
        onPointerMove={moveDrag}
        onPointerUp={stopDrag}
        onPointerCancel={stopDrag}
      >
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold">{summary.title}</p>
          <p className="mt-1 line-clamp-2 text-xs leading-5 opacity-90">{summary.body}</p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            className="rounded border border-white/20 px-2 py-1 text-xs hover:bg-white/10"
            onClick={() => setPopupState('collapsed')}
            aria-label="Minimize self-test popup"
          >
            Minimize
          </button>
          <button
            type="button"
            className="rounded border border-white/20 px-2 py-1 text-xs font-semibold hover:bg-white/10"
            onClick={() => setPopupState('dismissed')}
            aria-label="Dismiss self-test popup"
          >
            Close
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {query.data && (
          <div className="space-y-3">
            <SelfTestDetails result={query.data} />
            {query.data.checks.map(check => (
              <div key={check.name} className="flex gap-2 text-xs">
                <span className={checkStatusClass(check.status)}>
                  {checkStatusLabel(check.status)}
                </span>
                <span className="font-mono">{check.name}</span>
                <span className="opacity-80">{check.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {summary.tone !== 'ok' && (
        <div className="flex shrink-0 flex-wrap gap-2 border-t border-white/10 bg-black/20 p-3">
          <button
            type="button"
            className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10"
            onClick={() => query.refetch()}
          >
            Run Again
          </button>
          <a className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10" href="/feeds">
            Open Feeds
          </a>
          <a className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10" href={troubleshootingUrl}>
            Troubleshooting
          </a>
        </div>
      )}
    </div>
  );
}

function checkStatusLabel(status: SelfTestCheck['status']) {
  if (status === 'ok') return 'OK';
  if (status === 'degraded' || status === 'warning') return 'WARN';
  return 'FAIL';
}

function checkStatusClass(status: SelfTestCheck['status']) {
  if (status === 'ok') return 'text-emerald-300';
  if (status === 'degraded' || status === 'warning') return 'text-amber-200';
  return 'text-red-300';
}
