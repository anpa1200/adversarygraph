import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { pcapApi, type PcapInvestigationSummary, type PcapSummaryClaim } from '@/api/client';
import { useHasPermission } from '@/hooks/useCurrentUser';

function saveFile(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = name; anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function ClaimList({ claims }: { claims: PcapSummaryClaim[] }) {
  return <ul className="space-y-2">
    {claims.map((claim, index) => {
      const label = claim.value || claim.attack_id;
      const parts = label ? claim.text.split(label) : [claim.text];
      return <li key={index} className="text-[15px] leading-6 text-slate-700">
        {label && parts.length === 1 && <span className="mr-1 break-all font-mono font-semibold text-slate-950">{label} — </span>}
        {parts.map((part, i) => <span key={i}>{i > 0 && <span className="break-all font-mono font-semibold text-slate-950">{label}</span>}{part}</span>)}
      </li>;
    })}
  </ul>;
}

export function PcapReportCard({ summary }: { summary: PcapInvestigationSummary }) {
  const data = summary.structured;
  const omitted = summary.validation_adjustments?.filter(item => item.action === 'optional-claim-omitted').length ?? 0;
  return <article data-testid="pcap-investigation-report" data-analysis-id={summary.analysis_id}
    className="mx-auto w-full max-w-[1100px] rounded-xl border border-slate-300 bg-white p-8 text-slate-900 shadow-lg">
    <header className="mb-5 border-b border-slate-200 pb-4">
      <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-semibold uppercase tracking-wider text-slate-600">
        <span>AdversaryGraph · PCAP investigation</span><span>Analyst review required</span>
      </div>
      <h1 className="mt-3 text-2xl font-bold leading-tight text-slate-950">What happened in this capture?</h1>
      <p className="mt-2 break-all text-sm text-slate-600">{summary.filename}</p>
      {summary.stale && <p role="alert" className="mt-3 rounded bg-amber-100 p-3 font-semibold text-amber-950">Evidence changed after this report. Regenerate before using it.</p>}
    </header>
    <section aria-label="What happened" className="space-y-3 text-[17px] leading-7 text-slate-900">
      {data.what_happened.map((claim, index) => <p key={index}>{claim.text}</p>)}
    </section>
    {data.identities.length > 0 && <section className="mt-5 border-t border-slate-200 pt-4">
      <h2 className="mb-2 text-base font-bold">Who was involved</h2><ClaimList claims={data.identities} />
    </section>}
    {data.iocs.length > 0 && <section className="mt-5 border-t border-slate-200 pt-4">
      <h2 className="mb-2 text-base font-bold">Key indicators and why they matter</h2><ClaimList claims={data.iocs} />
    </section>}
    {data.ttps.length > 0 && <section className="mt-5 border-t border-slate-200 pt-4">
      <h2 className="mb-2 text-base font-bold">Supported technique candidates</h2><ClaimList claims={data.ttps} />
    </section>}
    <section className="mt-5 rounded-lg bg-slate-100 p-4">
      <h2 className="mb-2 text-base font-bold">What remains uncertain</h2><ClaimList claims={data.uncertainties} />
      {data.next_steps.length > 0 && <div className="mt-3"><h2 className="mb-1 text-base font-bold">Next check</h2><ClaimList claims={data.next_steps} /></div>}
    </section>
    <footer className="mt-5 border-t border-slate-200 pt-3 text-xs leading-5 text-slate-600">
      <p>Model: <strong>{summary.model}</strong>{!summary.provider_returned_model && ' (requested alias; returned model ID not recorded)'} · {summary.word_count} claim-text words · {summary.created_at.slice(0, 10)} · {summary.prompt_version}</p>
      <p className="break-all">Capture SHA-256: {summary.capture_sha256}</p>
      <p>Exact citations and reputation coverage are available separately. A downloaded file is not proof of execution.</p>
      {omitted > 0 && <p>{omitted} optional {omitted === 1 ? 'entry was' : 'entries were'} omitted after validation; see the evidence details.</p>}
    </footer>
  </article>;
}

export function PcapSummaryPanel({ analysisId, revision = '', focused = false, onWritten }: { analysisId: string; revision?: string; focused?: boolean; onWritten?: () => void }) {
  const canRun = useHasPermission('run_analysis');
  const canExport = useHasPermission('export_data');
  const queryClient = useQueryClient();
  const [provider, setProvider] = useState('openai');
  const [consent, setConsent] = useState(false);
  const key = ['pcap-summary-preflight', analysisId, revision];
  const preflight = useQuery({ queryKey: key, queryFn: () => pcapApi.summaryPreflight(analysisId), retry: false, staleTime: 0 });
  const selected = preflight.data?.providers?.find(p => p.id === provider);
  const mutation = useMutation({
    mutationFn: () => pcapApi.writeSummary(analysisId, { provider, cloud_processing_acknowledged: consent,
      expected_source_sha256: preflight.data!.source_sha256 }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['pcap-summary-preflight', analysisId] }); onWritten?.(); },
  });
  const summary = preflight.data?.summary;
  return <section className="space-y-4" aria-label="PCAP summary and report writing">
    <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-white">3. Summarise &amp; write the investigation report</h2>
        {!focused && <Link className="secondary-action text-sm" to={`/pcap/${analysisId}/report`}>Open focused report</Link>}
      </div>
      <p className="mt-2 text-sm leading-6 text-gray-300">After packet analysis and IOC enrichment, write a short account of what happened. Detailed evidence remains available separately.</p>
      {preflight.isError && <p role="alert" className="mt-2 text-sm text-red-300">Summary preflight unavailable. Check that the backend supports PCAP report writing.</p>}
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <label className="text-sm text-gray-300">Report model
          <select aria-label="PCAP report model" value={provider} onChange={e => { setProvider(e.target.value); setConsent(false); }} className="ml-2 rounded border border-gray-600 bg-gray-950 p-2 text-white">
            {preflight.data?.providers?.map(p => <option key={p.id} value={p.id} disabled={!p.available}>{p.label} · {p.model}{p.available ? '' : ' · unavailable'}</option>)}
          </select>
        </label>
        {selected?.remote && <label className="flex max-w-xl items-start gap-2 text-sm text-gray-300">
          <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} className="mt-1" />
          I approve sending selected packet metadata, identities, indicators and reputation evidence to {selected.label}. No payload files are sent.
        </label>}
        <button onClick={() => mutation.mutate()} disabled={!canRun || !selected?.available || mutation.isPending || (selected.remote && (!canExport || !consent))}
          className="rounded bg-cyan-700 px-4 py-2 text-sm font-semibold text-white disabled:opacity-40">
          {mutation.isPending ? 'Writing evidence-backed summary…' : 'Write investigation summary'}
        </button>
      </div>
      {selected && !selected.available && <p className="mt-2 text-sm text-amber-300">{selected.reason}</p>}
      {mutation.isError && <p role="alert" className="mt-2 text-sm text-red-300">{mutation.error instanceof Error ? mutation.error.message : 'Summary failed validation or provider request; no new report saved.'}</p>}
      {summary && <div className="mt-3 flex flex-wrap gap-2">
        <button disabled={!canExport} className="secondary-action text-sm" onClick={() => saveFile(`${summary.filename}-summary.md`, summary.content, 'text/markdown')}>Download short report</button>
        <button disabled={!canExport} className="secondary-action text-sm" onClick={() => saveFile(`${summary.filename}-summary-evidence.json`, JSON.stringify(summary, null, 2), 'application/json')}>Download cited evidence</button>
      </div>}
    </div>
    {summary ? <>
      <PcapReportCard summary={summary} />
      <details className="rounded-lg border border-gray-700 p-4 text-sm text-gray-300">
        <summary className="cursor-pointer font-semibold text-white">Evidence, coverage and model provenance</summary>
        <p className="mt-3">Requested: {summary.requested_model}. Provider returned: {summary.provider_returned_model || 'not recorded'}. {summary.generation_seconds} seconds. Tokens: {summary.token_usage?.total_tokens ?? 'unavailable'}.</p>
        {!!summary.validation_adjustments?.length && <div className="mt-4"><h3 className="font-semibold">Server validation adjustments</h3><pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify(summary.validation_adjustments, null, 2)}</pre></div>}
        {Object.entries(summary.structured).map(([section, claims]) => <div key={section} className="mt-4">
          <h3 className="font-semibold">{section.replace(/_/g, ' ')}</h3>
          {claims.map((claim, index) => <div key={index} className="mt-2 border-l-2 border-gray-600 pl-3">
            <p>{claim.text} <span className="text-gray-400">({claim.basis})</span></p>
            {claim.evidence.map((ref, i) => <div key={i} className="mt-1 break-words text-xs leading-5 text-gray-400"><p>{ref.source_id} · {ref.reference}</p><blockquote>{ref.quote}</blockquote></div>)}
          </div>)}
        </div>)}
        <pre className="mt-4 overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(summary.coverage, null, 2)}</pre>
      </details>
    </> : <article data-testid="pcap-summary-empty" data-analysis-id={analysisId} className="mx-auto w-full max-w-[1100px] rounded-xl border border-slate-300 bg-white p-8 text-slate-900 shadow-lg">
      <p className="text-xs font-semibold uppercase tracking-wider text-slate-600">AdversaryGraph · PCAP investigation</p>
      <h1 className="mt-3 text-2xl font-bold">No validated investigation summary is saved</h1>
      <p className="mt-3 break-all text-base">{preflight.data?.filename || analysisId}</p>
      <p className="mt-5 text-[17px] leading-7">Report writing has not completed successfully. This is not a clean-capture verdict. The packet evidence remains available for investigation.</p>
      <p className="mt-4 text-sm text-slate-600">Review the evidence and the report-writing result before retrying. No incident narrative or model result is being substituted here.</p>
      <p className="mt-5 break-all border-t border-slate-200 pt-3 text-xs text-slate-600">Capture SHA-256: {preflight.data?.capture_sha256 || 'Loading capture identity…'}</p>
    </article>}
  </section>;
}
