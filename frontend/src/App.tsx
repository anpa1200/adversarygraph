import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Sidebar } from '@/components/Layout/Sidebar';
import { Navigator } from '@/pages/Navigator';
import { APTLibrary } from '@/pages/APTLibrary';
import { Analyze } from '@/pages/Analyze';
import { Compare } from '@/pages/Compare';

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
              <Route path="/" element={<Navigate to="/navigator" replace />} />
              <Route path="/navigator" element={<Navigator />} />
              <Route path="/apt" element={<APTLibrary />} />
              <Route path="/analyze" element={<Analyze />} />
              <Route path="/compare" element={<Compare />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
