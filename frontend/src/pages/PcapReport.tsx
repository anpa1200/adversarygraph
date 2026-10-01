import { useParams } from 'react-router-dom';
import { PcapSummaryPanel } from '@/components/PcapSummaryPanel';

export function PcapReport() {
  const { analysisId } = useParams();
  if (!analysisId) return <p role="alert">Missing PCAP analysis ID.</p>;
  return <div className="mx-auto w-full max-w-[1280px] p-6"><PcapSummaryPanel analysisId={analysisId} focused /></div>;
}
