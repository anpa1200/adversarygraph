import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { CtiInvestigation } from '@/api/client';
import { useHasPermission } from '@/hooks/useCurrentUser';

export function CtiInvestigationPanel({ investigation }: { investigation: CtiInvestigation }) {
  const canExport = useHasPermission('export_data');
  const [query, setQuery] = useState('');
  const [showReferences, setShowReferences] = useState(false);
  const indicators = investigation.indicators.filter(item =>
    (showReferences || item.role !== 'reference') &&
    `${item.value} ${item.indicator_type}`.toLowerCase().includes(query.toLowerCase())
  );
  const download = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(investigation, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `cti-investigation-${investigation.created_at.slice(0, 10)}.json`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <div className="space-y-6 text-sm text-gray-300">
    <div className="flex flex-wrap gap-2">
      {Object.entries(investigation.stages).map(([stage, value]) =>
        <span key={stage} title={value.reason} className={`rounded border px-2 py-1 text-xs ${['failed', 'partial'].includes(value.status) ? 'border-yellow-800 text-yellow-300' : 'border-gray-700 text-gray-300'}`}>
          {stage}: {value.status}
        </span>
      )}
      {canExport && <button onClick={download} className="ml-auto rounded bg-gray-700 px-3 py-1 text-xs text-white">Download evidence JSON</button>}
    </div>
    <p className="text-xs text-gray-400">{investigation.tlp || 'TLP:AMBER+STRICT'} · Analysis: {investigation.status}. Analyst review is pending. Observable candidates and intelligence matches require validation before use.</p>
    {investigation.warnings.length > 0 && <div className="rounded border border-yellow-800/50 bg-yellow-950/20 p-3 text-xs text-yellow-200">
      {investigation.warnings.map((warning, i) => <p key={i} className="mb-1">{warning}</p>)}
    </div>}
    <section>
      <h3 className="mb-3 text-base font-semibold text-white">Technical investigation</h3>
      <div className="space-y-3 leading-7 [&_h1]:text-xl [&_h2]:mt-5 [&_h2]:text-lg [&_h3]:mt-4 [&_h3]:font-semibold [&_p]:mb-3 [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:list-decimal [&_ol]:pl-5 [&_code]:text-cyan-200 [&_pre]:overflow-auto [&_pre]:rounded [&_pre]:bg-gray-950 [&_pre]:p-3 [&_table]:w-full [&_td]:border [&_td]:border-gray-700 [&_td]:p-2 [&_th]:border [&_th]:border-gray-700 [&_th]:p-2 [&_a]:text-cyan-300">
        <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml>{investigation.report || 'Technical synthesis was not completed. Review the retained evidence below.'}</ReactMarkdown>
      </div>
    </section>
    <section>
      <h3 className="mb-3 text-base font-semibold text-white">Source register</h3>
      {investigation.sources.map(source => <div key={source.id} className="mb-2 rounded border border-gray-800 p-3 text-xs">
        <p className="font-medium text-white">[{source.id}] {source.title}</p>
        {source.url && <a href={source.url} target="_blank" rel="noreferrer" className="break-all text-cyan-300">{source.url}</a>}
        <p className="mt-1 text-gray-400">{source.included_chars.toLocaleString()} / {source.original_chars.toLocaleString()} characters included · acquired {source.retrieved_at}</p>
        <p className="mt-1 break-all font-mono text-[10px] text-gray-500">SHA-256: {source.sha256}</p>
      </div>)}
    </section>
    <section>
      <h3 className="mb-3 text-base font-semibold text-white">Observable candidates and enrichment ({indicators.length})</h3>
      <div className="mb-3 flex flex-wrap items-center gap-3 text-xs">
        <input aria-label="Filter observables" placeholder="Filter indicators…" value={query} onChange={e => setQuery(e.target.value)} className="rounded border border-gray-700 bg-gray-900 p-2" />
        <label className="flex items-center gap-2"><input type="checkbox" checked={showReferences} onChange={e => setShowReferences(e.target.checked)} />Include reference links</label>
      </div>
      <p className="mb-3 text-xs text-gray-500">Extraction finds observables, including background infrastructure and filenames. A local match is a dated source claim; no match is unknown.</p>
      {indicators.length === 0 && <p className="text-xs text-gray-500">No candidates match the current filter.</p>}
      {indicators.slice(0, 500).map(item => <details key={`${item.indicator_type}:${item.value}`} className="mb-2 rounded border border-gray-800 p-3 text-xs">
        <summary className="cursor-pointer break-all"><span className="font-mono text-cyan-200">{item.value}</span> <span className="text-gray-500">{item.indicator_type} · {item.role} · local: {item.enrichment.status}{item.registration ? ` · RDAP: ${item.registration.status}` : ''}</span></summary>
        <div className="mt-3 space-y-2">
          {item.evidence.map((evidence, i) => <p key={i} className="whitespace-pre-wrap text-gray-400">[{evidence.source_id}] {evidence.excerpt}</p>)}
          {item.enrichment.matches?.map((match, i) => <p key={i}>Local source: {match.source_id} · {match.malware_family || 'family unknown'} · first seen {match.first_seen || 'unknown'} · last seen {match.last_seen || 'unknown'}</p>)}
          {item.registration && <p>Registration: {item.registration.name || 'unknown'} · {item.registration.country || 'country unknown'} · {item.registration.queried_at}</p>}
          {item.public_intelligence?.map((lookup, i) => <p key={i}>Passive {lookup.source}: {lookup.status} · {lookup.summary || 'No result summary'} · {lookup.queried_at}</p>)}
          <a href={`/ioc-investigation?indicator=${encodeURIComponent(item.value)}`} className="inline-block rounded bg-gray-700 px-2 py-1 text-white">Investigate / enrich</a>
        </div>
      </details>)}
    </section>
    <section className="rounded border border-gray-800 p-3 text-xs text-gray-400">
      <h3 className="mb-2 font-semibold text-gray-200">Coverage and evidence limits</h3>
      {investigation.limitations.map((limit, i) => <p key={i} className="mb-1">{limit}</p>)}
    </section>
  </div>;
}
