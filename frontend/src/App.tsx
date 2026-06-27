import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Sidebar } from '@/components/Layout/Sidebar';
import { Navigator } from '@/pages/Navigator';
import { APTLibrary } from '@/pages/APTLibrary';
import { Analyze } from '@/pages/Analyze';
import { Compare } from '@/pages/Compare';
import { GroupCompare } from '@/pages/GroupCompare';
import { Discover } from '@/pages/Discover';
import { InvestigationReport } from '@/pages/InvestigationReport';
import { Operations } from '@/pages/Operations';
import { Pipeline } from '@/pages/Pipeline';
import { Examples } from '@/pages/Examples';
import { SectorIntel } from '@/pages/SectorIntel';
import { AssetSurface } from '@/pages/AssetSurface';
import { AttackSimulation } from '@/pages/AttackSimulation';
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
import { Debugger } from '@/pages/Debugger';
import { MalwareUnpacker } from '@/pages/MalwareUnpacker';
import { DynamicAnalysis } from '@/pages/DynamicAnalysis';
import { SystemSelfTestPopup } from '@/components/SystemSelfTestPopup';
import { GlobalErrorPopup } from '@/components/GlobalErrorPopup';
import { RoleGate } from '@/components/RoleGate';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000,
      retry: 2,
    },
  },
});

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <div className="flex h-screen overflow-hidden bg-mitre-dark">
          <Sidebar />
          <main className="flex-1 flex flex-col overflow-hidden">
            <Routes>
              <Route path="/" element={<Navigate to="/discover" replace />} />
              <Route path="/discover" element={<Discover />} />
              <Route path="/navigator" element={<Navigator />} />
              <Route path="/apt" element={<APTLibrary />} />
              <Route path="/analyze" element={<Analyze />} />
              <Route path="/compare" element={<Compare />} />
              <Route path="/group-compare" element={<GroupCompare />} />
              <Route path="/report" element={<InvestigationReport />} />
              <Route path="/operations" element={<RoleGate require="analyst"><Operations /></RoleGate>} />
              <Route path="/pipeline" element={<RoleGate require="analyst"><Pipeline /></RoleGate>} />
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
          </main>
          <GlobalErrorPopup />
          <SystemSelfTestPopup />
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
