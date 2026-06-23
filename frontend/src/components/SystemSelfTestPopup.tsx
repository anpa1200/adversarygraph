import { useEffect, useState } from 'react';
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
      body: 'Checking API, database, Redis, ATT&CK data, API keys, and IOC feed sync state.',
      tone: 'pending' as const,
    };
  }
  if (result.status === 'ok') {
    return {
      title: 'AdversaryGraph self-test passed',
      body: `API, database, Redis, ATT&CK data, API keys, and feed sync state are ready. Checked in ${result.duration_ms} ms.`,
      tone: 'ok' as const,
    };
  }
  if (result.status === 'degraded') {
    const syncCheck = checkByName(result, 'ioc_sync');
    const syncDetails = asRecord(syncCheck?.details);
    const degradedSources = Number(syncDetails.degraded_sources ?? 0);
    return {
      title: 'AdversaryGraph self-test degraded',
      body: `Core platform checks passed, but ${degradedSources || 'one or more'} enabled IOC feed source${degradedSources === 1 ? '' : 's'} need attention. Checked in ${result.duration_ms} ms.`,
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

function SelfTestDetails({ result }: { result: SelfTestResult }) {
  const apiCheck = checkByName(result, 'api_keys');
  const syncCheck = checkByName(result, 'ioc_sync');
  const providers = configuredProviders(apiCheck);
  const llmProviders = providers.filter(provider => provider.category === 'llm');
  const feedProviders = providers.filter(provider => provider.category === 'feed');
  const investigationProviders = providers.filter(provider => provider.category === 'investigation');
  const sources = enabledSources(syncCheck);
  const syncDetails = asRecord(syncCheck?.details);
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
    </div>
  );
}

export function SystemSelfTestPopup() {
  const [popupState, setPopupState] = useState<PopupState>('visible');
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

  return (
    <div className={`fixed bottom-4 right-4 z-50 w-[min(440px,calc(100vw-2rem))] rounded-lg border p-4 shadow-2xl ${color}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold">{summary.title}</p>
          <p className="mt-1 text-xs leading-5 opacity-90">{summary.body}</p>
        </div>
        <button
          type="button"
          className="shrink-0 rounded border border-white/20 px-2 py-1 text-xs hover:bg-white/10"
          onClick={() => setPopupState('dismissed')}
          aria-label="Dismiss self-test popup"
        >
          Close
        </button>
      </div>

      {query.data && (
        <div className="mt-3 space-y-3 border-t border-white/10 pt-3">
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

      {summary.tone !== 'ok' && (
        <div className="mt-3 flex gap-2">
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
