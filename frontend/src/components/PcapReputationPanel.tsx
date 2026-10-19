import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { pcapApi } from '@/api/client';
import type { LogPcapAnalysisResult, PcapAnalysisResult } from '@/api/client';
import { useHasPermission } from '@/hooks/useCurrentUser';

const PROVIDERS = ['virustotal', 'threatfox', 'malwarebazaar', 'otx', 'urlscan', 'greynoise', 'abuseipdb', 'shodan', 'censys'];

export function PcapReputationPanel({ result, onUpdated }: { result: LogPcapAnalysisResult; onUpdated: (value: PcapAnalysisResult) => void }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [providers, setProviders] = useState(['virustotal', 'threatfox', 'malwarebazaar']);
  const [consent, setConsent] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [query, setQuery] = useState('');
  const canRun = useHasPermission('run_analysis');
  const canExport = useHasPermission('export_data');
  const assessment = result.pcap_assessment;
  const mutation = useMutation({
    mutationFn: () => pcapApi.enrich(result.analysis_id!, selected, providers),
    onSuccess: data => { onUpdated(data); setConsent(false); },
  });
  if (!assessment) return <p className="p-3 text-xs text-gray-400">Reopen this capture from server history to load its evidence assessment.</p>;
  const items = assessment.items.filter(item => (showAll || item.ioc_candidate || item.roles.includes('exported-object')) && item.value.toLowerCase().includes(query.toLowerCase()));
  return <section className="rounded-lg border border-gray-800 bg-gray-900/50 p-3 text-xs text-gray-300">
    <h2 className="text-sm font-semibold text-white">Evidence-backed IOC assessment</h2>
    <p className="my-2">{assessment.summary}</p>
    <p className="my-2 text-gray-400">Recovered files can be checked without first labelling them malicious. Provider reports do not prove execution or capture-time intent.</p>
    <label className="block my-2"><input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} /> Show other observations (not IOCs)</label>
    <input aria-label="Filter PCAP observations" className="w-full rounded border border-gray-700 bg-gray-950 p-2" placeholder="Filter by address, domain or hash" value={query} onChange={e => setQuery(e.target.value)} />
    <div className="my-2 max-h-96 overflow-auto">
      {items.slice(0, 150).map(item => <div key={item.observable_id} className="border-t border-gray-800 py-3">
        <label className="flex items-start gap-2">
          <input type="checkbox" aria-label={`Select ${item.value}`} checked={selected.includes(item.observable_id)} disabled={!item.enrichment_eligible || (!selected.includes(item.observable_id) && selected.length >= 10) || mutation.isPending}
            onChange={e => setSelected(current => e.target.checked ? [...current, item.observable_id] : current.filter(id => id !== item.observable_id))} />
          <span className="break-all font-mono">{item.value}</span>
        </label>
        <p className="mt-1">{item.type} · {item.classification} · {item.enrichment_status}</p>
        {item.provider_conflict && <p className="text-amber-300">Conflicting provider verdicts — analyst review required.</p>}
        {item.reasons.map((reason, i) => <p key={i} className="text-gray-400">{String(reason.kind)}: {String(reason.rule_id || reason.interpretation || '')}{reason.frame_number ? ` — frame ${reason.frame_number}` : ''}</p>)}
        {item.signals.map(signal => <p key={signal.source} className="mt-1 text-gray-400">{signal.source}: {signal.status} / {signal.verdict}. {signal.basis} {signal.queried_at}</p>)}
        {!item.enrichment_eligible && <p className="text-gray-500">Automatic external disclosure blocked for this target type or scope.</p>}
      </div>)}
      {!items.length && <p className="py-3">No candidates or recovered hashes in this view.</p>}
      {items.length > 150 && <p>Showing 150 of {items.length}; narrow the filter to select other targets.</p>}
    </div>
    <fieldset disabled={mutation.isPending}><legend className="mb-1">Passive providers (up to 3)</legend>
      <div className="flex flex-wrap gap-2">{PROVIDERS.map(provider => <label key={provider}><input type="checkbox" checked={providers.includes(provider)} disabled={!providers.includes(provider) && providers.length >= 3}
        onChange={e => setProviders(current => e.target.checked ? [...current, provider] : current.filter(p => p !== provider))} /> {provider}</label>)}</div>
    </fieldset>
    <label className="block my-3"><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} /> I reviewed the {selected.length} selected targets and authorize their disclosure to these providers. No file upload, full URL disclosure or active scan.</label>
    {result.source_tlp !== 'TLP:CLEAR' && <p className="my-2 text-amber-300">Source marking: {result.source_tlp || 'TLP:AMBER+STRICT'}. External checks require TLP:CLEAR. <a className="underline" href={`/analyze/${result.session_id}/report`}>Review source marking and permissions</a>.</p>}
    <button className="primary-action" disabled={!canRun || !canExport || !consent || !selected.length || !providers.length || result.source_tlp !== 'TLP:CLEAR' || mutation.isPending} onClick={() => mutation.mutate()}>{mutation.isPending ? 'Checking selected targets…' : 'Enrich selected targets'}</button>
    {mutation.isError && <p role="alert" className="mt-2 text-red-400">Reputation request failed; no maliciousness conclusion can be drawn. Check source marking, permissions and provider availability.</p>}
    <p className="mt-2 text-gray-500">Missing credentials, rate limits, no records and zero detections mean unknown, not benign. Existing provider credentials are reused.</p>
  </section>;
}
