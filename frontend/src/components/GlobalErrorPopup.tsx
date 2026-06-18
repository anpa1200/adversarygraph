import { useEffect, useState } from 'react';
import { systemApi } from '@/api/client';

interface ApiErrorDetail {
  message: string;
  status?: number;
  url?: string;
  retry?: () => Promise<unknown>;
}

type PopupState = 'error' | 'checking' | 'ok';

const providerRequirements = [
  { provider: 'threatfox', envVar: 'THREATFOX_AUTH_KEY', match: ['/ioc/sync/threatfox', 'THREATFOX_AUTH_KEY'] },
  { provider: 'otx', envVar: 'OTX_API_KEY', match: ['/ioc/sync/otx', '/enrich/otx', 'OTX_API_KEY'] },
  { provider: 'virustotal', envVar: 'VIRUSTOTAL_API_KEY', match: ['/ioc/virustotal', 'VIRUSTOTAL_API_KEY'] },
  { provider: 'anthropic', envVar: 'ANTHROPIC_API_KEY', match: ['provider=claude', 'ANTHROPIC_API_KEY'] },
  { provider: 'openai', envVar: 'OPENAI_API_KEY', match: ['provider=openai', 'OPENAI_API_KEY'] },
  { provider: 'gemini', envVar: 'GEMINI_API_KEY', match: ['provider=gemini', 'GEMINI_API_KEY'] },
];

export function GlobalErrorPopup() {
  const [error, setError] = useState<ApiErrorDetail | null>(null);
  const [popupState, setPopupState] = useState<PopupState>('error');

  useEffect(() => {
    const onApiError = (event: Event) => {
      const detail = (event as CustomEvent<ApiErrorDetail>).detail;
      if (detail?.message) {
        setPopupState('error');
        setError(detail);
      }
    };

    window.addEventListener('adversarygraph:api-error', onApiError);
    return () => window.removeEventListener('adversarygraph:api-error', onApiError);
  }, []);

  if (!error) return null;

  const troubleshootingUrl = `/troubleshooting?${new URLSearchParams({
    ...(error.message && { error: error.message }),
    ...(error.status && { status: String(error.status) }),
    ...(error.url && { url: error.url }),
  }).toString()}`;

  const recheck = async () => {
    const originalError = error;
    setPopupState('checking');
    try {
      if (originalError.retry) {
        await originalError.retry();
        setPopupState('ok');
        setError({ message: 'All correct.', status: 200, url: originalError.url });
        return;
      }
      const result = await systemApi.selftest();
      if (result.status === 'ok') {
        const stillMissing = missingRequiredProvider(originalError, result);
        if (stillMissing) {
          setPopupState('error');
          setError({
            message: `${stillMissing.envVar} is still missing. The base deployment is healthy, but this action requires ${stillMissing.envVar}. Add it to .env and restart the API container.`,
            status: originalError.status,
            url: originalError.url,
          });
          return;
        }
        setPopupState('ok');
        setError({ message: 'All correct.', status: 200, url: '/system/selftest' });
      } else {
        const failed = result.checks.filter(check => check.status !== 'ok');
        setPopupState('error');
        setError({
          message: failed.map(check => `${check.name}: ${check.message}`).join(' ') || 'Self-test failed.',
          status: 500,
          url: '/system/selftest',
        });
      }
    } catch (nextError) {
      setPopupState('error');
      setError({
        message: nextError instanceof Error ? nextError.message : 'Self-test request failed.',
        url: '/system/selftest',
      });
    }
  };

  const isOk = popupState === 'ok';
  const isChecking = popupState === 'checking';
  const boxClass = isOk
    ? 'border-emerald-500/60 bg-emerald-950/95 text-emerald-50'
    : 'border-red-500/60 bg-red-950/95 text-red-50';
  const metaClass = isOk ? 'text-emerald-200/80' : 'text-red-200/80';

  return (
    <div className={`fixed top-4 right-4 z-[60] w-[min(460px,calc(100vw-2rem))] rounded-lg border p-4 shadow-2xl ${boxClass}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold">{isOk ? 'All correct.' : 'API request failed'}</p>
          <p className="mt-1 text-xs leading-5 opacity-90">
            {isChecking ? 'Running self-test...' : error.message}
          </p>
          {(error.status || error.url) && (
            <p className={`mt-2 font-mono text-[11px] ${metaClass}`}>
              {error.status ? `HTTP ${error.status}` : 'Network error'}
              {error.url ? ` · ${error.url}` : ''}
            </p>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            {!isOk && (
              <button
                type="button"
                className="rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10 disabled:cursor-wait disabled:opacity-60"
                onClick={recheck}
                disabled={isChecking}
              >
                {isChecking ? 'Checking...' : 'Recheck'}
              </button>
            )}
            {!isOk && (
              <a
                className="inline-flex rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10"
                href={troubleshootingUrl}
                onClick={() => setError(null)}
              >
                Open troubleshooting
              </a>
            )}
          </div>
        </div>
        <button
          type="button"
          className="shrink-0 rounded border border-white/20 px-2 py-1 text-xs hover:bg-white/10"
          onClick={() => setError(null)}
        >
          Close
        </button>
      </div>
    </div>
  );
}

function missingRequiredProvider(error: ApiErrorDetail, result: Awaited<ReturnType<typeof systemApi.selftest>>) {
  const haystack = `${error.url ?? ''} ${error.message ?? ''}`.toLowerCase();
  const apiKeyCheck = result.checks.find(check => check.name === 'api_keys');
  const details = apiKeyCheck?.details as { missing_optional?: string[] } | undefined;
  const missing = new Set((details?.missing_optional ?? []).map(item => String(item).toLowerCase()));
  return providerRequirements.find(requirement =>
    missing.has(requirement.provider) &&
    requirement.match.some(marker => haystack.includes(marker.toLowerCase()))
  );
}
