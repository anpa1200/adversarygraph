import { lazy, Suspense, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useQuery } from '@tanstack/react-query';
import { authApi, healthApi, type StartupStatus } from '@/api/client';
import { Sidebar } from '@/components/Layout/Sidebar';
import { AppFooter } from '@/components/Layout/AppFooter';
import { SystemSelfTestPopup } from '@/components/SystemSelfTestPopup';
import { GlobalErrorPopup } from '@/components/GlobalErrorPopup';
import { RoleGate } from '@/components/RoleGate';
import { UIProvider } from '@/components/ui/provider';
import { Login } from '@/pages/Login';
import { AuthGuide } from '@/pages/AuthGuide';

const Discover = lazy(() => import('@/pages/Discover').then(module => ({ default: module.Discover })));
const Navigator = lazy(() => import('@/pages/Navigator').then(module => ({ default: module.Navigator })));
const APTLibrary = lazy(() => import('@/pages/APTLibrary').then(module => ({ default: module.APTLibrary })));
const Analyze = lazy(() => import('@/pages/Analyze').then(module => ({ default: module.Analyze })));
const LinkedReport = lazy(() => import('@/pages/LinkedReport').then(module => ({ default: module.LinkedReport })));
const ReportsResearch = lazy(() => import('@/pages/ReportsResearch').then(module => ({ default: module.ReportsResearch })));
const Compare = lazy(() => import('@/pages/Compare').then(module => ({ default: module.Compare })));
const InvestigationReport = lazy(() => import('@/pages/InvestigationReport').then(module => ({ default: module.InvestigationReport })));
const Operations = lazy(() => import('@/pages/Operations').then(module => ({ default: module.Operations })));
const Pipeline = lazy(() => import('@/pages/Pipeline').then(module => ({ default: module.Pipeline })));
const Observability = lazy(() => import('@/pages/Observability').then(module => ({ default: module.Observability })));
const Statistics = lazy(() => import('@/pages/Statistics').then(module => ({ default: module.Statistics })));
const ThreatRadar = lazy(() => import('@/pages/ThreatRadar').then(module => ({ default: module.ThreatRadar })));
const ThreatRadarAssets = lazy(() => import('@/pages/ThreatRadarAssets').then(module => ({ default: module.ThreatRadarAssets })));
const EvidenceGraph = lazy(() => import('@/pages/EvidenceGraph').then(module => ({ default: module.EvidenceGraph })));
const AdminUsers = lazy(() => import('@/pages/AdminUsers').then(module => ({ default: module.AdminUsers })));
const HelpGuide = lazy(() => import('@/pages/HelpGuide').then(module => ({ default: module.HelpGuide })));
const Examples = lazy(() => import('@/pages/Examples').then(module => ({ default: module.Examples })));
const SectorIntel = lazy(() => import('@/pages/SectorIntel').then(module => ({ default: module.SectorIntel })));
const AssetSurface = lazy(() => import('@/pages/AssetSurface').then(module => ({ default: module.AssetSurface })));
const Emb3d = lazy(() => import('@/pages/Emb3d').then(module => ({ default: module.Emb3d })));
const AttackSimulation = lazy(() => import('@/pages/AttackSimulation').then(module => ({ default: module.AttackSimulation })));
const SectorPacks = lazy(() => import('@/pages/SectorPacks'));
const KnowledgeLibrary = lazy(() => import('@/pages/KnowledgeLibrary').then(module => ({ default: module.KnowledgeLibrary })));
const RetroHunt = lazy(() => import('@/pages/RetroHunt'));
const IOCLibrary = lazy(() => import('@/pages/IOCLibrary').then(module => ({ default: module.IOCLibrary })));
const IOCDetail = lazy(() => import('@/pages/IOCDetail').then(module => ({ default: module.IOCDetail })));
const IOCNodeDetail = lazy(() => import('@/pages/IOCNodeDetail').then(module => ({ default: module.IOCNodeDetail })));
const CVEIntelligence = lazy(() => import('@/pages/CVEIntelligence').then(module => ({ default: module.CVEIntelligence })));
const FeedsManagement = lazy(() => import('@/pages/FeedsManagement').then(module => ({ default: module.FeedsManagement })));
const MalwareAnalysis = lazy(() => import('@/pages/MalwareAnalysis').then(module => ({ default: module.MalwareAnalysis })));
const MalwareUnpacker = lazy(() => import('@/pages/MalwareUnpacker').then(module => ({ default: module.MalwareUnpacker })));
const StringAnalyzer = lazy(() => import('@/pages/StringAnalyzer').then(module => ({ default: module.StringAnalyzer })));
const Debugger = lazy(() => import('@/pages/Debugger').then(module => ({ default: module.Debugger })));
const DynamicAnalysis = lazy(() => import('@/pages/DynamicAnalysis').then(module => ({ default: module.DynamicAnalysis })));
const Troubleshooting = lazy(() => import('@/pages/Troubleshooting').then(module => ({ default: module.Troubleshooting })));
const VirusTotalLookup = lazy(() => import('@/pages/VirusTotalLookup').then(module => ({ default: module.VirusTotalLookup })));
const IOCInvestigation = lazy(() => import('@/pages/IOCInvestigation').then(module => ({ default: module.IOCInvestigation })));
const ThreatHunting = lazy(() => import('@/pages/ThreatHunting').then(module => ({ default: module.ThreatHunting })));
const QueryLibrary = lazy(() => import('@/pages/QueryLibrary').then(module => ({ default: module.QueryLibrary })));

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

  if (status.data?.auth_enabled && me.isLoading) {
    return <SessionSplash />;
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
                  <Route path="/discover" element={<RoleGate module="discover"><Discover /></RoleGate>} />
                  <Route path="/navigator" element={<RoleGate module="navigator"><Navigator /></RoleGate>} />
                  <Route path="/apt" element={<RoleGate module="apt_library"><APTLibrary /></RoleGate>} />
                  <Route path="/analyze" element={<RoleGate module="ai_analysis"><Analyze /></RoleGate>} />
                  <Route path="/analyze/:sessionId/report" element={<RoleGate anyModule={['ai_analysis', 'reports_research', 'investigation']}><LinkedReport /></RoleGate>} />
                  <Route path="/reports-research" element={<RoleGate module="reports_research"><ReportsResearch /></RoleGate>} />
                  <Route path="/compare" element={<RoleGate module="compare"><Compare /></RoleGate>} />
                  <Route path="/group-compare" element={<Navigate to="/compare?mode=group-vs-group" replace />} />
                  <Route path="/report" element={<RoleGate module="investigation" permission="run_analysis"><InvestigationReport /></RoleGate>} />
                  <Route path="/operations" element={<RoleGate module="operations" permission="run_analysis"><Operations /></RoleGate>} />
                  <Route path="/pipeline" element={<RoleGate module="pipeline" permission="run_analysis"><Pipeline /></RoleGate>} />
                  <Route path="/observability" element={<RoleGate module="observability" permission="view_audit"><Observability /></RoleGate>} />
                  <Route path="/statistics" element={<RoleGate module="statistics" permission="run_analysis"><Statistics /></RoleGate>} />
                  <Route path="/threat-radar" element={<RoleGate module="threat_radar" permission="run_analysis"><ThreatRadar /></RoleGate>} />
                  <Route path="/threat-radar/assets" element={<RoleGate module="threat_radar" permission="run_analysis"><ThreatRadarAssets /></RoleGate>} />
                  <Route path="/threat-radar/assets/:spaceId/:assetId" element={<RoleGate module="threat_radar" permission="run_analysis"><ThreatRadarAssets /></RoleGate>} />
                  <Route path="/threat-hunting" element={<RoleGate module="threat_hunting" permission="run_analysis"><ThreatHunting /></RoleGate>} />
                  <Route path="/threat-hunting/new" element={<RoleGate module="threat_hunting" permission="run_analysis"><ThreatHunting /></RoleGate>} />
                  <Route path="/threat-hunting/:huntId" element={<RoleGate module="threat_hunting" permission="run_analysis"><ThreatHunting /></RoleGate>} />
                  <Route path="/query-library" element={<RoleGate module="query_library" permission="run_analysis"><QueryLibrary /></RoleGate>} />
                  <Route path="/evidence-graph" element={<RoleGate module="evidence_graph" permission="run_analysis"><EvidenceGraph /></RoleGate>} />
                  <Route path="/admin" element={<RoleGate module="admin" anyPermission={['manage_users', 'manage_auth', 'view_audit']}><AdminUsers /></RoleGate>} />
                  <Route path="/auth-guide" element={<AuthGuide />} />
                  <Route path="/help" element={<RoleGate module="help"><HelpGuide /></RoleGate>} />
                  <Route path="/examples" element={<RoleGate module="examples"><Examples /></RoleGate>} />
                  <Route path="/sector-intel" element={<RoleGate module="sector_intel"><SectorIntel /></RoleGate>} />
                  <Route path="/asset-surface" element={<RoleGate module="asset_surface" permission="run_analysis"><AssetSurface /></RoleGate>} />
                  <Route path="/emb3d" element={<RoleGate module="emb3d" permission="run_analysis"><Emb3d /></RoleGate>} />
                  <Route path="/attack-simulation" element={<RoleGate module="attack_simulation" permission="run_attack_simulation"><AttackSimulation /></RoleGate>} />
                  <Route path="/attack-simulation/:simulationId" element={<RoleGate module="attack_simulation" permission="run_attack_simulation"><AttackSimulation /></RoleGate>} />
                  <Route path="/external-simulation" element={<Navigate to="/attack-simulation" replace />} />
                  <Route path="/sector-packs" element={<RoleGate module="sector_intel"><SectorPacks /></RoleGate>} />
                  <Route path="/knowledge" element={<RoleGate module="knowledge"><KnowledgeLibrary /></RoleGate>} />
                  <Route path="/retrohunt" element={<RoleGate module="retrohunt"><RetroHunt /></RoleGate>} />
                  <Route path="/ioc-library" element={<RoleGate module="ioc_library"><IOCLibrary /></RoleGate>} />
                  <Route path="/ioc-library/:id" element={<RoleGate module="ioc_library"><IOCDetail /></RoleGate>} />
                  <Route path="/ioc-node" element={<RoleGate module="ioc_library"><IOCNodeDetail /></RoleGate>} />
                  <Route path="/cve" element={<RoleGate module="cve_library"><CVEIntelligence /></RoleGate>} />
                  <Route path="/feeds" element={<RoleGate module="feeds" permission="manage_feeds"><FeedsManagement /></RoleGate>} />
                  <Route path="/malware-analysis" element={<RoleGate module="malware_analysis" permission="run_analysis"><MalwareAnalysis /></RoleGate>} />
                  <Route path="/malware-unpacker" element={<RoleGate module="malware_analysis" permission="run_analysis"><MalwareUnpacker /></RoleGate>} />
                  <Route path="/string-analyzer" element={<RoleGate module="malware_analysis" permission="run_analysis"><StringAnalyzer /></RoleGate>} />
                  <Route path="/malware-debug" element={<RoleGate module="malware_analysis" permission="run_analysis"><Debugger /></RoleGate>} />
                  <Route path="/debugger" element={<RoleGate module="malware_analysis" permission="run_analysis"><Debugger /></RoleGate>} />
                  <Route path="/dynamic-analysis" element={<RoleGate module="malware_analysis" permission="run_analysis"><DynamicAnalysis /></RoleGate>} />
                  <Route path="/troubleshooting" element={<RoleGate module="troubleshooting"><Troubleshooting /></RoleGate>} />
                  <Route path="/virustotal" element={<RoleGate module="virustotal" permission="run_analysis"><VirusTotalLookup /></RoleGate>} />
                  <Route path="/ioc-investigation" element={<RoleGate module="ioc_investigation" permission="run_analysis"><IOCInvestigation /></RoleGate>} />
                  <Route path="*" element={<NotFound />} />
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

function SessionSplash() {
  return (
    <div role="status" className="flex min-h-screen items-center justify-center bg-mitre-dark px-6 text-gray-300">
      <div className="rounded-lg border border-gray-800 bg-gray-950/70 px-8 py-6 text-center shadow-2xl">
        <div className="mx-auto h-8 w-8 animate-spin rounded-full border-2 border-transparent border-t-mitre-accent" />
        <p className="mt-4 text-sm font-semibold text-white">Verifying your session…</p>
        <p className="mt-1 text-xs text-gray-500">Protected workspaces stay closed until access is confirmed.</p>
      </div>
    </div>
  );
}

function NotFound() {
  return (
    <div className="flex min-h-[60vh] items-center justify-center p-8">
      <div className="max-w-md rounded-lg border border-gray-800 bg-gray-950/60 p-8 text-center">
        <h1 className="text-lg font-semibold text-white">Workspace not found</h1>
        <p className="mt-2 text-sm leading-6 text-gray-500">The requested AdversaryGraph route does not exist or the link is no longer current.</p>
        <a href="/discover" className="primary-action mt-5 inline-flex px-4 py-2">Open Discover</a>
      </div>
    </div>
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
