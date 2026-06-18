import { useEffect, useState } from 'react';

interface ApiErrorDetail {
  message: string;
  status?: number;
  url?: string;
}

export function GlobalErrorPopup() {
  const [error, setError] = useState<ApiErrorDetail | null>(null);

  useEffect(() => {
    const onApiError = (event: Event) => {
      const detail = (event as CustomEvent<ApiErrorDetail>).detail;
      if (detail?.message) setError(detail);
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

  return (
    <div className="fixed top-4 right-4 z-[60] w-[min(460px,calc(100vw-2rem))] rounded-lg border border-red-500/60 bg-red-950/95 p-4 text-red-50 shadow-2xl">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold">API request failed</p>
          <p className="mt-1 text-xs leading-5 opacity-90">{error.message}</p>
          {(error.status || error.url) && (
            <p className="mt-2 font-mono text-[11px] text-red-200/80">
              {error.status ? `HTTP ${error.status}` : 'Network error'}
              {error.url ? ` · ${error.url}` : ''}
            </p>
          )}
          <a
            className="mt-3 inline-flex rounded border border-white/20 px-3 py-1.5 text-xs font-semibold hover:bg-white/10"
            href={troubleshootingUrl}
            onClick={() => setError(null)}
          >
            Open troubleshooting
          </a>
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
