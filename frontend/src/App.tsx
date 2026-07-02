import { lazy, Suspense, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useQuery } from '@tanstack/react-query';
import { authApi, healthApi, type StartupStatus } from '@/api/client';
import { Sidebar } from '@/components/Layout/Sidebar';
import { AppFooter } from '@/components/Layout/AppFooter';
import { Navigator } from '@/pages/Navigator';
import { APTLibrary } from '@/pages/APTLibrary';
import { Analyze } from '@/pages/Analyze';
import { Compare } from '@/pages/Compare';
import { Discover } from '@/pages/Discover';
import { InvestigationReport } from '@/pages/InvestigationReport';
import { Operations } from '@/pages/Operations';
import { Pipeline } from '@/pages/Pipeline';
import { Examples } from '@/pages/Examples';
import { SectorIntel } from '@/pages/SectorIntel';
import { AssetSurface } from '@/pages/AssetSurface';
import { KnowledgeLibrary } from '@/pages/KnowledgeLibrary';
import SectorPacks from '@/pages/SectorPacks';
import RetroHunt from '@/pages/RetroHunt';
import { Troubleshooting } from '@/pages/Troubleshooting';
import { VirusTotalLookup } from '@/pages/VirusTotalLookup';
import { IOCInvestigation } from '@/pages/IOCInvestigation';
import { IOCLibrary } from '@/pages/IOCLibrary';
import { IOCDetail } from '@/pages/IOCDetail';
import { IOCNodeDetail } from '@/pages/IOCNodeDetail';
import { FeedsManagement } from '@/pages/FeedsManagement';
import { MalwareAnalysis } from '@/pages/MalwareAnalysis';
import { StringAnalyzer } from '@/pages/StringAnalyzer';
import { MalwareUnpacker } from '@/pages/MalwareUnpacker';
import { DynamicAnalysis } from '@/pages/DynamicAnalysis';
import { SystemSelfTestPopup } from '@/components/SystemSelfTestPopup';
import { GlobalErrorPopup } from '@/components/GlobalErrorPopup';
import { RoleGate } from '@/components/RoleGate';
import { UIProvider } from '@/components/ui/provider';
import { Login } from '@/pages/Login';
import { AdminUsers } from '@/pages/AdminUsers';
import { AuthGuide } from '@/pages/AuthGuide';
import { Observability } from '@/pages/Observability';
import { EvidenceGraph } from '@/pages/EvidenceGraph';
import { HelpGuide } from '@/pages/HelpGuide';
import { Statistics } from '@/pages/Statistics';

const AttackSimulation = lazy(() => import('@/pages/AttackSimulation').then(module => ({ default: module.AttackSimulation })));
const CVEIntelligence = lazy(() => import('@/pages/CVEIntelligence').then(module => ({ default: module.CVEIntelligence })));
const Debugger = lazy(() => import('@/pages/Debugger').then(module => ({ default: module.Debugger })));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000,
      retry: 2,
    },
  },
});

function AppShell() {
  const status = useQuery({
    queryKey: ['auth-status'],
    queryFn: authApi.status,
    retry: 30,
    retryDelay: attempt => Math.min(1000 + attempt * 1000, 5000),
    staleTime: 5 * 60 * 1000,
    refetchOnWindowFocus: false,
  });
  const me = useQuery({
    queryKey: ['current-user'],
    queryFn: authApi.me,
    retry: false,
    enabled: status.data?.auth_enabled === true,
  });

  if (window.location.pathname === '/auth-guide') {
    return (
      <BrowserRouter>
        <AuthGuide />
      </BrowserRouter>
    );
  }

  if (status.isLoading || status.isError) {
    return <StartupSplash error={status.error instanceof Error ? status.error : null} onRetry={() => status.refetch()} />;
  }

  if (status.data?.auth_enabled && me.isError) {
    return <Login status={status.data} />;
  }

  return (
    <BrowserRouter>
      <div className="app-shell flex overflow-hidden bg-mitre-dark">
        <Sidebar />
        <main className="min-h-0 min-w-0 flex-1 overflow-hidden">
          <div data-testid="app-route-scroll" className="app-route-scroll flex min-h-0 min-w-0 flex-1 flex-col overflow-y-auto overflow-x-hidden overscroll-contain">
            <div className="app-route-content flex min-w-0 flex-1 flex-col">
              <Suspense fallback={<div className="p-6 text-sm text-gray-500">Loading workspace...</div>}>
                <Routes>
                  <Route path="/" element={<Navigate to="/discover" replace />} />
                  <Route path="/discover" element={<Discover />} />
                  <Route path="/navigator" element={<Navigator />} />
                  <Route path="/apt" element={<APTLibrary />} />
                  <Route path="/analyze" element={<Analyze />} />
                  <Route path="/compare" element={<Compare />} />
                  <Route path="/group-compare" element={<Navigate to="/compare?mode=group-vs-group" replace />} />
                  <Route path="/report" element={<InvestigationReport />} />
                  <Route path="/operations" element={<RoleGate require="analyst"><Operations /></RoleGate>} />
                  <Route path="/pipeline" element={<RoleGate require="analyst"><Pipeline /></RoleGate>} />
                  <Route path="/observability" element={<RoleGate require="analyst"><Observability /></RoleGate>} />
                  <Route path="/statistics" element={<RoleGate require="analyst"><Statistics /></RoleGate>} />
                  <Route path="/evidence-graph" element={<RoleGate require="analyst"><EvidenceGraph /></RoleGate>} />
                  <Route path="/admin" element={<RoleGate require="admin"><AdminUsers /></RoleGate>} />
                  <Route path="/auth-guide" element={<AuthGuide />} />
                  <Route path="/help" element={<HelpGuide />} />
                  <Route path="/examples" element={<Examples />} />
                  <Route path="/sector-intel" element={<SectorIntel />} />
                  <Route path="/asset-surface" element={<AssetSurface />} />
                  <Route path="/attack-simulation" element={<RoleGate require="analyst"><AttackSimulation /></RoleGate>} />
                  <Route path="/attack-simulation/:simulationId" element={<RoleGate require="analyst"><AttackSimulation /></RoleGate>} />
                  <Route path="/external-simulation" element={<Navigate to="/attack-simulation" replace />} />
                  <Route path="/sector-packs" element={<SectorPacks />} />
                  <Route path="/knowledge" element={<KnowledgeLibrary />} />
                  <Route path="/retrohunt" element={<RetroHunt />} />
                  <Route path="/ioc-library" element={<IOCLibrary />} />
                  <Route path="/ioc-library/:id" element={<IOCDetail />} />
                  <Route path="/ioc-node" element={<IOCNodeDetail />} />
                  <Route path="/cve" element={<CVEIntelligence />} />
                  <Route path="/feeds" element={<RoleGate require="analyst"><FeedsManagement /></RoleGate>} />
                  <Route path="/malware-analysis" element={<MalwareAnalysis />} />
                  <Route path="/malware-unpacker" element={<MalwareUnpacker />} />
                  <Route path="/string-analyzer" element={<StringAnalyzer />} />
                  <Route path="/malware-debug" element={<Debugger />} />
                  <Route path="/debugger" element={<Debugger />} />
                  <Route path="/dynamic-analysis" element={<DynamicAnalysis />} />
                  <Route path="/troubleshooting" element={<Troubleshooting />} />
                  <Route path="/virustotal" element={<VirusTotalLookup />} />
                  <Route path="/ioc-investigation" element={<IOCInvestigation />} />
                </Routes>
              </Suspense>
            </div>
            <AppFooter />
          </div>
        </main>
        <StartupIngestionIndicator />
        <GlobalErrorPopup />
        <SystemSelfTestPopup />
      </div>
    </BrowserRouter>
  );
}

function StartupIngestionIndicator() {
  const [dismissedKey, setDismissedKey] = useState('');
  const query = useQuery({
    queryKey: ['startup-health'],
    queryFn: healthApi.check,
    retry: false,
    refetchInterval: 5000,
    refetchOnWindowFocus: false,
    staleTime: 0,
  });
  const startup = query.data?.startup;
  const ingestion = startup?.reference_ingestion;
  if (!startup || !ingestion) return null;

  const completedAt = ingestion.completed_at ? new Date(ingestion.completed_at).getTime() : 0;
  const bannerKey = `${ingestion.status}:${ingestion.phase}:${ingestion.started_at ?? ''}:${ingestion.completed_at ?? ''}`;
  if (dismissedKey === bannerKey) return null;

  const showCompleted = ingestion.status === 'complete' && Number.isFinite(completedAt) && Date.now() - completedAt < 30_000;
  if (ingestion.status === 'complete' && !showCompleted) return null;

  const tone = startupIndicatorTone(startup);
  const title = ingestion.status === 'complete'
    ? 'Reference ingestion complete'
    : ingestion.status === 'failed'
      ? 'Reference ingestion failed'
      : 'Reference ingestion running';
  const body = ingestion.error || ingestion.message || startup.message;
  return (
    <div
      className={`fixed bottom-10 right-4 z-50 w-[min(26rem,calc(100vw-2rem))] rounded border px-4 py-3 text-xs shadow-2xl backdrop-blur ${tone.container}`}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-start gap-3">
        <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${tone.dot}`}>
          {ingestion.status === 'running' && <span className={`block h-2.5 w-2.5 animate-ping rounded-full ${tone.dot}`} />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="font-semibold text-white">{title}</p>
            <div className="flex items-center gap-2">
              <span className="rounded bg-black/30 px-2 py-0.5 font-mono uppercase tracking-wide">{ingestion.phase}</span>
              <button
                type="button"
                aria-label="Close startup status banner"
                onClick={() => setDismissedKey(bannerKey)}
                className="rounded border border-white/15 px-1.5 py-0.5 text-[11px] font-semibold text-white/80 hover:border-white/40 hover:bg-white/10 hover:text-white"
              >
                X
              </button>
            </div>
          </div>
          <p className="mt-1 leading-relaxed text-gray-200">{body}</p>
          {ingestion.started_at && ingestion.status === 'running' && (
            <p className="mt-1 text-gray-400">Started {new Date(ingestion.started_at).toLocaleTimeString()} · matrix data may still be incomplete.</p>
          )}
          {ingestion.status === 'failed' && (
            <a href="/troubleshooting" className="mt-2 inline-flex rounded border border-red-300/40 px-2 py-1 font-semibold text-red-100 hover:bg-red-500/10">
              Open troubleshooting
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

function startupIndicatorTone(startup: StartupStatus) {
  if (startup.reference_ingestion.status === 'failed') {
    return {
      container: 'border-red-500/60 bg-red-950/90 text-red-100',
      dot: 'bg-red-400',
    };
  }
  if (startup.reference_ingestion.status === 'complete') {
    return {
      container: 'border-emerald-500/50 bg-emerald-950/90 text-emerald-100',
      dot: 'bg-emerald-400',
    };
  }
  return {
    container: 'border-amber-500/50 bg-amber-950/90 text-amber-100',
    dot: 'bg-amber-300',
  };
}

function StartupSplash({ error, onRetry }: { error: Error | null; onRetry: () => void }) {
  const steps = error
    ? ['Waiting for API container', 'Checking reverse proxy route', 'Retrying auth readiness']
    : ['Starting containers', 'Preparing database and Redis', 'Starting ATT&CK/ATLAS ingestion', 'Checking platform health'];

  return (
    <div className="flex min-h-screen items-center justify-center bg-mitre-dark px-6 text-gray-200">
      <div className="w-full max-w-xl rounded-lg border border-gray-800 bg-gray-950/70 p-8 shadow-2xl">
        <div className="flex items-center gap-4">
          <div className="relative h-14 w-14 shrink-0">
            <div className="absolute inset-0 rounded-full border-2 border-mitre-accent/20" />
            <div className="absolute inset-0 animate-spin rounded-full border-2 border-transparent border-t-mitre-accent" />
            <div className="absolute left-1/2 top-1/2 h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full bg-mitre-accent shadow-[0_0_24px_rgba(255,55,95,0.65)]" />
          </div>
          <div className="min-w-0">
            <p className="text-lg font-semibold text-white">AdversaryGraph is starting</p>
            <p className="mt-1 text-sm text-gray-400">
              Waiting for Docker health checks and API readiness before opening the workspace.
            </p>
          </div>
        </div>

        <div className="mt-6 grid gap-2">
          {steps.map((step, index) => (
            <div key={step} className="flex items-center gap-3 rounded border border-gray-800 bg-gray-900/50 px-3 py-2 text-sm">
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-mitre-accent opacity-60" style={{ animationDelay: `${index * 180}ms` }} />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-mitre-accent" />
              </span>
              <span>{step}</span>
            </div>
          ))}
        </div>

        {error && (
          <div className="mt-5 rounded border border-amber-500/40 bg-amber-950/30 p-3 text-sm text-amber-100">
            <p className="font-semibold">API is not ready yet.</p>
            <p className="mt-1 break-words opacity-90">{error.message}</p>
            <button type="button" onClick={onRetry} className="mt-3 rounded border border-amber-300/40 px-3 py-1.5 text-xs font-semibold hover:bg-amber-300/10">
              Retry now
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <UIProvider>
        <AppShell />
      </UIProvider>
    </QueryClientProvider>
  );
}
