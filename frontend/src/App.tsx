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
import { Troubleshooting } from '@/pages/Troubleshooting';
import { VirusTotalLookup } from '@/pages/VirusTotalLookup';
import { IOCInvestigation } from '@/pages/IOCInvestigation';
import { IOCLibrary } from '@/pages/IOCLibrary';
import { IOCDetail } from '@/pages/IOCDetail';
import { IOCNodeDetail } from '@/pages/IOCNodeDetail';
import { FeedsManagement } from '@/pages/FeedsManagement';
import { MalwareAnalysis } from '@/pages/MalwareAnalysis';
import { StringAnalyzer } from '@/pages/StringAnalyzer';
import { SystemSelfTestPopup } from '@/components/SystemSelfTestPopup';
import { GlobalErrorPopup } from '@/components/GlobalErrorPopup';

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
              <Route path="/operations" element={<Operations />} />
              <Route path="/pipeline" element={<Pipeline />} />
              <Route path="/examples" element={<Examples />} />
              <Route path="/sector-intel" element={<SectorIntel />} />
              <Route path="/ioc-library" element={<IOCLibrary />} />
              <Route path="/ioc-library/:id" element={<IOCDetail />} />
              <Route path="/ioc-node" element={<IOCNodeDetail />} />
              <Route path="/feeds" element={<FeedsManagement />} />
              <Route path="/malware-analysis" element={<MalwareAnalysis />} />
              <Route path="/string-analyzer" element={<StringAnalyzer />} />
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
