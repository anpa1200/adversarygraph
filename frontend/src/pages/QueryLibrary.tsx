import { useDeferredValue, useEffect, useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';

import {
  queryLibraryApi,
  type HuntQueryLibraryItem,
  type IOCQueryBuildResult,
  type ThreatHuntQueryLanguage,
} from '@/api/client';
import { Header } from '@/components/Layout/Header';
import { CodeEditor } from '@/components/ui/code-editor';
import { useHasPermission } from '@/hooks/useCurrentUser';
import { THREAT_HUNT_QUERY_LANGUAGE_OPTIONS } from '@/components/ThreatHunting/queryLanguages';

const LANGUAGES = THREAT_HUNT_QUERY_LANGUAGE_OPTIONS.filter(item => item.value !== 'other');
const EMPTY_FILTERS = { language: '', technique: '', tag: '', source: '', platform: '', ioc_type: '' };

export function QueryLibrary() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const canSync = useHasPermission('manage_feeds');
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search.trim());
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [active, setActive] = useState<HuntQueryLibraryItem | null>(null);
  const [showBuilder, setShowBuilder] = useState(false);
  const [iocText, setIocText] = useState('');
  const [iocTitle, setIocTitle] = useState('IOC match hunt');
  const [iocLanguage, setIocLanguage] = useState<ThreatHuntQueryLanguage>('sigma');
  const [iocTechniques, setIocTechniques] = useState('');
  const [built, setBuilt] = useState<IOCQueryBuildResult | null>(null);
  const [copied, setCopied] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 60;

  useEffect(() => setPage(0), [deferredSearch, filters]);

  const results = useQuery({
    queryKey: ['query-library', deferredSearch, filters, page],
    queryFn: () => queryLibraryApi.search({ q: deferredSearch || undefined, ...nonEmpty(filters), limit: pageSize, offset: page * pageSize }),
  });
  const facets = useQuery({ queryKey: ['query-library-facets'], queryFn: queryLibraryApi.facets });
  const suggestions = useQuery({
    queryKey: ['query-library-autocomplete', deferredSearch],
    queryFn: () => queryLibraryApi.autocomplete(deferredSearch),
    enabled: deferredSearch.length >= 2 && !deferredSearch.includes(' '),
  });
  const sync = useMutation({
    mutationFn: queryLibraryApi.sync,
    onSuccess: async () => {
      await Promise.all([
        qc.invalidateQueries({ queryKey: ['query-library'] }),
        qc.invalidateQueries({ queryKey: ['query-library-facets'] }),
      ]);
    },
  });
  const build = useMutation({
    mutationFn: () => queryLibraryApi.buildFromIoc({
      language: iocLanguage,
      title: iocTitle,
      technique_ids: iocTechniques.split(/[\s,]+/).filter(Boolean),
      observables: parseObservables(iocText),
    }),
    onSuccess: value => setBuilt(value),
  });

  const openInHunt = (item: HuntQueryLibraryItem | IOCQueryBuildResult) => {
    if ('id' in item) {
      navigate('/threat-hunting/new?library=' + encodeURIComponent(item.id) + '&source=query-library&source_ref=' + encodeURIComponent(item.source_url || item.id));
    } else {
      sessionStorage.setItem('adversarygraph:query-library-draft', JSON.stringify(item));
      navigate('/threat-hunting/new?library_draft=session&source=ioc-query-builder');
    }
  };
  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied('Copied');
    window.setTimeout(() => setCopied(''), 1500);
  };

  return (
    <div className="flex min-h-full flex-col">
      <Header title="Hunt Query Library" />
      <main className="flex-1 px-6 py-6">
        <div className="mx-auto max-w-[1580px] space-y-5">
          <section className="overflow-hidden rounded-xl border border-cyan-500/30 bg-gradient-to-br from-cyan-950/25 via-gray-950/70 to-gray-900/50">
            <div className="grid gap-6 p-6 xl:grid-cols-[minmax(0,1fr)_430px]">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-300">Detection engineering workspace</p>
                <h1 className="mt-3 text-2xl font-semibold text-white">Search, review, adapt, and preserve hunt queries.</h1>
                <p className="mt-3 max-w-4xl text-sm leading-6 text-gray-400">
                  Reviewed AdversaryGraph examples and source-backed community rules in Sigma, YARA-L, YARA, KQL, SPL, EQL, Lucene, SQL, and osquery.
                  Every result keeps its provenance, ATT&amp;CK mapping, validation status, and analyst-review boundary.
                </p>
                <div className="mt-5 flex flex-wrap gap-2">
                  <button type="button" className="primary min-h-10 px-4" onClick={() => setShowBuilder(true)}>Build query from IOCs</button>
                  <a className="secondary-action inline-flex min-h-10 items-center px-4" href="/threat-hunting">Open hunt queue</a>
                  {canSync && <button type="button" className="secondary-action min-h-10 px-4" disabled={sync.isPending} onClick={() => sync.mutate()}>{sync.isPending ? 'Indexing…' : 'Index community rules'}</button>}
                </div>
                {sync.data && <p role="status" className="mt-3 text-xs text-emerald-300">Community index updated: {sync.data.created} added, {sync.data.updated} refreshed from {sync.data.seen} feed records.</p>}
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Metric value={facets.data?.total ?? 0} label="Indexed queries" />
                <Metric value={facets.data?.languages.length ?? 0} label="Query formats" />
                <Metric value={facets.data?.techniques.length ?? 0} label="ATT&CK mappings" />
                <Metric value={facets.data?.sources.length ?? 0} label="Provenance sources" />
              </div>
            </div>
          </section>

          <section className="rounded-xl border border-gray-800 bg-gray-900/55">
            <div className="border-b border-gray-800 p-4">
              <div className="relative">
                <label htmlFor="query-library-search" className="sr-only">Search hunt query library</label>
                <input id="query-library-search" className="field min-h-12 pl-11 text-sm" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search behavior or use tag:persistence ttp:T1059.001 lang:yaral" autoComplete="off" />
                <span aria-hidden className="absolute left-4 top-3.5 text-gray-500">⌕</span>
                {suggestions.data?.items.length ? (
                  <div className="absolute left-0 right-0 top-[54px] z-30 grid max-h-64 overflow-y-auto rounded-lg border border-gray-700 bg-gray-950 p-2 shadow-2xl sm:grid-cols-2 lg:grid-cols-3">
                    {suggestions.data.items.map(item => (
                      <button type="button" key={item.type + ':' + item.value} className="flex items-center justify-between rounded px-3 py-2 text-left text-xs text-gray-300 hover:bg-gray-800 hover:text-white" onClick={() => setSearch(item.label)}>
                        <span>{item.label}</span><span className="text-gray-600">{item.count}</span>
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-6">
                <Filter label="Language" value={filters.language} options={facets.data?.languages} onChange={language => setFilters({ ...filters, language })} />
                <Filter label="ATT&CK" value={filters.technique} options={facets.data?.techniques} onChange={technique => setFilters({ ...filters, technique })} />
                <Filter label="Tag" value={filters.tag} options={facets.data?.tags} onChange={tag => setFilters({ ...filters, tag })} />
                <Filter label="Source" value={filters.source} options={facets.data?.sources} onChange={source => setFilters({ ...filters, source })} />
                <Filter label="Platform" value={filters.platform} options={facets.data?.platforms} onChange={platform => setFilters({ ...filters, platform })} />
                <Filter label="IOC type" value={filters.ioc_type} options={facets.data?.ioc_types} onChange={ioc_type => setFilters({ ...filters, ioc_type })} />
              </div>
            </div>
            <div className="flex items-center justify-between border-b border-gray-800 px-4 py-3 text-xs text-gray-500">
              <span>{results.isLoading ? 'Searching…' : (results.data?.total ?? 0) + ' queries'}</span>
              {(search || Object.values(filters).some(Boolean)) && <button type="button" className="text-cyan-300 hover:text-white" onClick={() => { setSearch(''); setFilters(EMPTY_FILTERS); }}>Clear search and filters</button>}
            </div>
            {results.isError && <div role="alert" className="m-4 rounded border border-red-800 bg-red-950/25 p-3 text-sm text-red-200">{errorText(results.error)}</div>}
            <div className="grid gap-3 p-4 md:grid-cols-2 2xl:grid-cols-3">
              {results.data?.items.map(item => <ResultCard key={item.id} item={item} onOpen={() => setActive(item)} />)}
              {!results.isLoading && !results.data?.items.length && <p className="col-span-full py-12 text-center text-sm text-gray-500">No queries match this search. Remove a filter or index additional community rules.</p>}
            </div>
            {(results.data?.total ?? 0) > pageSize && (
              <div className="flex items-center justify-between border-t border-gray-800 px-4 py-3 text-xs text-gray-500">
                <span>Page {page + 1} of {Math.ceil((results.data?.total ?? 0) / pageSize)}</span>
                <div className="flex gap-2">
                  <button type="button" className="secondary-action px-3 py-2" disabled={page === 0 || results.isFetching} onClick={() => setPage(value => Math.max(0, value - 1))}>Previous</button>
                  <button type="button" className="secondary-action px-3 py-2" disabled={(page + 1) * pageSize >= (results.data?.total ?? 0) || results.isFetching} onClick={() => setPage(value => value + 1)}>Next</button>
                </div>
              </div>
            )}
          </section>
        </div>
      </main>
      {active && <QueryDetail item={active} copied={copied} onClose={() => setActive(null)} onCopy={copy} onUse={() => openInHunt(active)} />}
      {showBuilder && (
        <IOCBuilder
          title={iocTitle} setTitle={setIocTitle} language={iocLanguage} setLanguage={setIocLanguage}
          text={iocText} setText={setIocText} techniques={iocTechniques} setTechniques={setIocTechniques}
          result={built} pending={build.isPending} error={errorText(build.error)} copied={copied}
          onBuild={() => build.mutate()} onCopy={copy} onUse={openInHunt} onClose={() => setShowBuilder(false)}
        />
      )}
    </div>
  );
}

function ResultCard({ item, onOpen }: { item: HuntQueryLibraryItem; onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen} className="group rounded-lg border border-gray-800 bg-gray-950/65 p-4 text-left transition hover:border-cyan-700/70 hover:bg-gray-950">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <span className="rounded border border-cyan-900 bg-cyan-950/50 px-2 py-1 font-mono text-[10px] uppercase text-cyan-200">{item.language}</span>
          {item.community && <span className="ml-2 rounded border border-violet-900 bg-violet-950/40 px-2 py-1 text-[10px] text-violet-200">community</span>}
          <h2 className="mt-3 line-clamp-2 text-sm font-semibold leading-5 text-white group-hover:text-cyan-100">{item.title}</h2>
        </div>
        <span className="rounded-full border border-gray-700 px-2 py-1 text-[10px] text-gray-400">{item.quality_score}/100</span>
      </div>
      <p className="mt-2 line-clamp-3 text-xs leading-5 text-gray-500">{item.description}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {item.technique_ids.map(id => <span key={id} className="rounded bg-cyan-950 px-2 py-1 font-mono text-[10px] text-cyan-200">{id}</span>)}
        {item.tags.slice(0, 3).map(tag => <span key={tag} className="rounded bg-gray-800 px-2 py-1 text-[10px] text-gray-400">#{tag}</span>)}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-gray-800 pt-3 text-[10px] text-gray-600">
        <span className="truncate pr-3">{item.source_name}</span><span>{item.validation.valid === false ? 'Needs review' : 'Parsed'}</span>
      </div>
    </button>
  );
}

function QueryDetail({ item, copied, onClose, onCopy, onUse }: { item: HuntQueryLibraryItem; copied: string; onClose: () => void; onCopy: (value: string) => void; onUse: () => void }) {
  return (
    <Modal title={item.title} onClose={onClose}>
      <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto p-5 xl:grid-cols-[minmax(0,1fr)_310px]">
        <div className="min-w-0">
          <CodeEditor value={item.query_text} language={editorLanguage(item.language)} height="560px" readOnly />
          <div className="mt-3 flex gap-2">
            <button type="button" className="primary min-h-10 px-4" onClick={onUse}>Create hunt from query</button>
            <button type="button" className="secondary-action min-h-10 px-4" onClick={() => onCopy(item.query_text)}>{copied || 'Copy query'}</button>
          </div>
        </div>
        <aside className="space-y-4 text-xs">
          <Info label="Language" value={item.language.toUpperCase()} />
          <Info label="Quality / parser status" value={item.quality_score + '/100 · ' + (item.validation.valid === false ? 'parser warnings' : 'parsed')} />
          <Info label="Source" value={item.source_name} />
          <Info label="License" value={item.source_license || 'See upstream source'} />
          {item.source_url && <a className="block rounded border border-gray-700 px-3 py-2 text-cyan-300 hover:border-cyan-600" href={item.source_url} target="_blank" rel="noreferrer">Open original source ↗</a>}
          <div><b className="text-gray-400">ATT&amp;CK techniques</b><div className="mt-2 flex flex-wrap gap-1">{item.technique_ids.map(id => <a key={id} target="_blank" rel="noreferrer" href={'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/'} className="rounded bg-cyan-950 px-2 py-1 font-mono text-cyan-200 hover:bg-cyan-900">{id} ↗</a>)}</div></div>
          <Info label="Data sources" value={item.data_sources.join(', ') || 'Review rule log source'} />
          <Info label="Platforms" value={item.platforms.join(', ') || 'Source-defined'} />
          <Info label="Tags" value={item.tags.map(tag => '#' + tag).join(' ')} />
          <div className="rounded border border-amber-900/60 bg-amber-950/20 p-3 leading-5 text-amber-100/75">Validate syntax, field mappings, exclusions, time windows, and data availability in the destination platform. AdversaryGraph does not execute this query.</div>
        </aside>
      </div>
    </Modal>
  );
}

type BuilderProps = {
  title: string; setTitle: (value: string) => void; language: ThreatHuntQueryLanguage; setLanguage: (value: ThreatHuntQueryLanguage) => void;
  text: string; setText: (value: string) => void; techniques: string; setTechniques: (value: string) => void;
  result: IOCQueryBuildResult | null; pending: boolean; error: string; copied: string; onBuild: () => void;
  onCopy: (value: string) => void; onUse: (item: IOCQueryBuildResult) => void; onClose: () => void;
};

function IOCBuilder(props: BuilderProps) {
  return (
    <Modal title="Build a hunt query from IOCs" onClose={props.onClose}>
      <div className="grid min-h-0 flex-1 gap-5 overflow-y-auto p-5 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="space-y-4">
          <label className="block text-xs text-gray-400">Hunt title<input className="field mt-1" value={props.title} onChange={event => props.setTitle(event.target.value)} /></label>
          <label className="block text-xs text-gray-400">Query format<select className="field mt-1" value={props.language} onChange={event => props.setLanguage(event.target.value as ThreatHuntQueryLanguage)}>{LANGUAGES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
          <label className="block text-xs text-gray-400">IOCs — one per line<textarea className="field mt-1 min-h-52 font-mono text-xs" value={props.text} onChange={event => props.setText(event.target.value)} placeholder={'203.0.113.24\nmalicious.example\nhttps://malicious.example/dropper\n44d88612fea8a8f36de82e1278abb02f'} /></label>
          <p className="text-[11px] leading-5 text-gray-600">IPv4/IPv6, domains, URLs, email, MD5, SHA-1, and SHA-256 are detected locally. Prefix a value with ip:, domain:, or sha256: to override detection.</p>
          <label className="block text-xs text-gray-400">ATT&amp;CK techniques (optional)<input className="field mt-1 font-mono uppercase" value={props.techniques} onChange={event => props.setTechniques(event.target.value.toUpperCase())} placeholder="T1071.001, T1105" /></label>
          <button type="button" className="primary min-h-11 w-full" disabled={props.pending || !props.text.trim()} onClick={props.onBuild}>{props.pending ? 'Building…' : 'Build query'}</button>
          {props.error && <p role="alert" className="rounded border border-red-800 bg-red-950/30 p-3 text-xs text-red-200">{props.error}</p>}
        </div>
        <div className="min-w-0">
          {props.result ? (
            <>
              <CodeEditor value={props.result.query_text} language={editorLanguage(props.result.query_language)} height="500px" readOnly />
              <div className="mt-3 flex flex-wrap gap-2"><button type="button" className="primary min-h-10 px-4" onClick={() => props.onUse(props.result!)}>Create hunt from query</button><button type="button" className="secondary-action min-h-10 px-4" onClick={() => props.onCopy(props.result!.query_text)}>{props.copied || 'Copy query'}</button></div>
              <ul className="mt-4 space-y-1 text-xs text-amber-200/80">{props.result.warnings.map(item => <li key={item}>• {item}</li>)}</ul>
            </>
          ) : <div className="flex min-h-[500px] items-center justify-center rounded border border-dashed border-gray-800 bg-gray-950/40 px-8 text-center text-sm leading-6 text-gray-600">Enter indicators and choose a destination format. The deterministic builder escapes values, groups by IOC type, and creates a reviewable draft without sending data to an LLM.</div>}
        </div>
      </div>
    </Modal>
  );
}

function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4" role="dialog" aria-modal="true" aria-label={title} onMouseDown={event => { if (event.target === event.currentTarget) onClose(); }}>
      <div className="flex max-h-[94vh] w-full max-w-[1500px] flex-col overflow-hidden rounded-xl border border-gray-700 bg-gray-950 shadow-2xl">
        <header className="flex items-center justify-between border-b border-gray-800 px-5 py-4"><div><h2 className="text-sm font-semibold text-white">{title}</h2><p className="mt-1 text-[11px] text-gray-600">Human review required before execution or deployment.</p></div><button type="button" className="secondary-action px-3 py-2" onClick={onClose}>Close</button></header>
        {children}
      </div>
    </div>
  );
}

function Metric({ value, label }: { value: number; label: string }) { return <div className="rounded-lg border border-gray-800 bg-gray-950/55 p-4"><b className="block text-xl text-white">{value.toLocaleString()}</b><span className="mt-1 block text-[11px] text-gray-500">{label}</span></div>; }
function Filter({ label, value, options = [], onChange }: { label: string; value: string; options?: Array<{ value: string; count: number }>; onChange: (value: string) => void }) { return <label className="text-[11px] text-gray-500">{label}<select className="field mt-1 text-xs" value={value} onChange={event => onChange(event.target.value)}><option value="">All</option>{options.slice(0, 200).map(item => <option key={item.value} value={item.value}>{item.value} ({item.count})</option>)}</select></label>; }
function Info({ label, value }: { label: string; value: string }) { return <div><b className="block text-gray-500">{label}</b><span className="mt-1 block break-words leading-5 text-gray-300">{value || '—'}</span></div>; }
function nonEmpty(values: Record<string, string>) { return Object.fromEntries(Object.entries(values).filter(([, value]) => value)); }
function errorText(error: unknown) { return error instanceof Error ? error.message : error ? String(error) : ''; }
function editorLanguage(language: string) { return language === 'sigma' ? 'yaml' : ['yaral', 'yara', 'spl', 'generic'].includes(language) ? 'plaintext' : language; }
function parseObservables(text: string) {
  const known = new Set(['ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'hash', 'text']);
  return text.split(/\r?\n/).map(line => line.trim()).filter(Boolean).slice(0, 200).map(line => {
    const separator = line.indexOf(':');
    const prefix = separator > 0 ? line.slice(0, separator).toLowerCase() : '';
    return known.has(prefix) ? { type: prefix, value: line.slice(separator + 1).trim() } : { value: line };
  }).filter(item => item.value);
}
