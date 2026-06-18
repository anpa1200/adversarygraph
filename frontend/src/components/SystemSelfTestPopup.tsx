import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { systemApi, type SelfTestResult } from '@/api/client';

type PopupState = 'visible' | 'collapsed' | 'dismissed';

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
      body: 'Checking API, database, Redis, and ATT&CK data.',
      tone: 'pending' as const,
    };
  }
  if (result.status === 'ok') {
    return {
      title: 'AdversaryGraph self-test passed',
      body: `API, database, Redis, and ATT&CK data are ready. Checked in ${result.duration_ms} ms.`,
      tone: 'ok' as const,
    };
  }
  const failed = result.checks.filter(check => check.status !== 'ok');
  return {
    title: 'AdversaryGraph self-test failed',
    body: failed.map(check => `${check.name}: ${check.message}`).join(' '),
    tone: 'error' as const,
  };
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
    ...(error ? {} : { status: query.data?.status === 'ok' ? '200' : 'selftest-failed' }),
  }).toString()}`;
  const color =
    summary.tone === 'ok'
      ? 'border-emerald-500/50 bg-emerald-950/90 text-emerald-50'
      : summary.tone === 'error'
        ? 'border-red-500/60 bg-red-950/95 text-red-50'
        : 'border-sky-500/50 bg-slate-950/95 text-sky-50';

  if (popupState === 'collapsed') {
    return (
      <button
        type="button"
        onClick={() => setPopupState('visible')}
        className="fixed bottom-4 right-4 z-50 rounded border border-emerald-500/50 bg-emerald-950/90 px-3 py-2 text-xs font-semibold text-emerald-100 shadow-lg"
      >
        Self-test OK
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
        <div className="mt-3 space-y-1 border-t border-white/10 pt-3">
          {query.data.checks.map(check => (
            <div key={check.name} className="flex gap-2 text-xs">
              <span className={check.status === 'ok' ? 'text-emerald-300' : 'text-red-300'}>
                {check.status === 'ok' ? 'OK' : 'FAIL'}
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
          <a className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10" href="/sync">
            Open Sync
          </a>
          <a className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10" href={troubleshootingUrl}>
            Troubleshooting
          </a>
        </div>
      )}
    </div>
  );
}
