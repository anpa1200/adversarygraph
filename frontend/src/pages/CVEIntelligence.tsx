import { useMemo, useState } from 'react';
import type React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { cveApi, type CVEDetail, type CVEItem } from '@/api/client';
import { safeHref } from '@/utils/url';

const severities = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export function CVEIntelligence() {
  const qc = useQueryClient();
  const [searchDraft, setSearchDraft] = useState('');
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const limit = 100;

  const sources = useQuery({ queryKey: ['cve-sources'], queryFn: cveApi.sources });
  const library = useQuery({
    queryKey: ['cve-library', search, severity, kevOnly, offset],
    queryFn: () => cveApi.library({ search, severity, known_exploited: kevOnly ? true : null, limit, offset }),
  });
  const detail = useQuery({
    queryKey: ['cve-detail', selectedCve],
    queryFn: () => cveApi.detail(selectedCve!),
    enabled: Boolean(selectedCve),
  });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['cve-library'] });
    qc.invalidateQueries({ queryKey: ['cve-sources'] });
    if (selectedCve) qc.invalidateQueries({ queryKey: ['cve-detail', selectedCve] });
  };
  const syncAll = useMutation({ mutationFn: () => cveApi.syncAll(7), onSuccess: invalidate });
  const syncNvd = useMutation({ mutationFn: () => cveApi.syncNvd(7), onSuccess: invalidate });
  const enrichMissingCvss = useMutation({ mutationFn: () => cveApi.enrichMissingCvss(20), onSuccess: invalidate });
  const syncKev = useMutation({ mutationFn: cveApi.syncKev, onSuccess: invalidate });
  const correlate = useMutation({ mutationFn: cveApi.correlate, onSuccess: invalidate });

  const total = library.data?.total ?? 0;
  const rows = library.data?.items ?? [];
  const maxPage = Math.max(0, Math.floor(Math.max(0, total - 1) / limit) * limit);
  const stats = useMemo(() => {
    const kev = rows.filter(item => item.known_exploited).length;
    const critical = rows.filter(item => item.cvss.severity === 'CRITICAL').length;
    const high = rows.filter(item => item.cvss.severity === 'HIGH').length;
    return { kev, critical, high };
  }, [rows]);
  const missingCvssOnPage = useMemo(
    () => rows.filter(item => !item.cvss.score).map(item => item.cve_id).slice(0, 10),
    [rows]
  );
  const enrichPageCvss = useMutation({ mutationFn: () => cveApi.syncNvdCveIds(missingCvssOnPage, missingCvssOnPage.length || 1), onSuccess: invalidate });

  const runSearch = () => {
    setSearch(searchDraft.trim());
    setOffset(0);
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="CVE Library" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title="Search CVE Library">
              <div className="space-y-4 p-4">
                <div className="flex flex-wrap gap-3">
                  <input
                    value={searchDraft}
                    onChange={event => setSearchDraft(event.target.value)}
                    onKeyDown={event => { if (event.key === 'Enter') runSearch(); }}
                    placeholder="Search CVE ID, product, weakness, description..."
                    className="field min-w-[320px] flex-1"
                  />
                  <button className="primary-action min-h-10" onClick={runSearch}>Search</button>
                  <select value={severity} onChange={event => { setSeverity(event.target.value); setOffset(0); }} className="field w-40">
                    {severities.map(item => <option key={item || 'all'} value={item}>{item || 'All severity'}</option>)}
                  </select>
                  <label className="flex items-center gap-2 rounded border border-gray-800 bg-gray-950 px-3 text-xs text-gray-300">
                    <input type="checkbox" checked={kevOnly} onChange={event => { setKevOnly(event.target.checked); setOffset(0); }} />
                    CISA KEV only
                  </label>
                </div>
                <div className="grid gap-3 md:grid-cols-4">
                  <Metric label="Results" value={total.toLocaleString()} />
                  <Metric label="Known exploited in page" value={stats.kev.toLocaleString()} tone="bad" />
                  <Metric label="Critical in page" value={stats.critical.toLocaleString()} tone="bad" />
                  <Metric label="High in page" value={stats.high.toLocaleString()} tone="warn" />
                </div>
              </div>
            </Panel>

            <Panel title="Library controls">
              <div className="space-y-3 p-4 text-sm">
                <div className="grid grid-cols-2 gap-2">
                  <button className="primary-action" disabled={syncAll.isPending} onClick={() => syncAll.mutate()}>{syncAll.isPending ? 'Syncing...' : 'Sync NVD + KEV'}</button>
                  <button className="secondary-action" disabled={correlate.isPending} onClick={() => correlate.mutate()}>{correlate.isPending ? 'Correlating...' : 'Refresh correlations'}</button>
                  <button className="secondary-action" disabled={syncNvd.isPending} onClick={() => syncNvd.mutate()}>NVD recent</button>
                  <button className="secondary-action" disabled={syncKev.isPending} onClick={() => syncKev.mutate()}>CISA KEV</button>
                  <button className="secondary-action" disabled={enrichPageCvss.isPending || missingCvssOnPage.length === 0} onClick={() => enrichPageCvss.mutate()}>
                    {enrichPageCvss.isPending ? 'Enriching page...' : 'Enrich visible CVSS'}
                  </button>
                  <button className="secondary-action" disabled={enrichMissingCvss.isPending} onClick={() => enrichMissingCvss.mutate()}>
                    {enrichMissingCvss.isPending ? 'Enriching batch...' : 'Enrich next missing batch'}
                  </button>
                </div>
                {(enrichMissingCvss.data || enrichPageCvss.data) && (
                  <div className="rounded border border-blue-500/40 bg-blue-950/20 p-3 text-xs text-blue-100">
                    NVD enrichment checked {String((enrichMissingCvss.data ?? enrichPageCvss.data)?.missing_selected ?? (enrichPageCvss.data?.requested || 0))} records, fetched {String((enrichMissingCvss.data ?? enrichPageCvss.data)?.fetched ?? 0)}, updated {String((enrichMissingCvss.data ?? enrichPageCvss.data)?.updated ?? 0)}.
                  </div>
                )}
                <div className="rounded border border-amber-500/50 bg-amber-950/20 p-3 text-xs leading-relaxed text-amber-100">
                  Strong links are stored only when source text, imported IOC fields, or analyst data explicitly contain CVE, ATT&CK, IOC, or actor evidence.
                  CVSS is a score field inside the CVE record; KEV entries can have no score until enriched from NVD by CVE ID. Without an NVD API key, enrichment is throttled to avoid 429 rate-limit errors.
                </div>
                <div className="space-y-2">
                  {(sources.data ?? []).map(source => (
                    <div key={source.source_id} className="rounded border border-gray-800 bg-gray-950 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <b className="text-xs text-gray-200">{source.label}</b>
                        <span className={source.sync_status === 'error' ? 'text-xs text-red-300' : 'text-xs text-green-300'}>{source.sync_status}</span>
                      </div>
                      <div className="mt-1 truncate text-[11px] text-gray-500">{source.last_synced_at || 'not synced yet'}</div>
                      {source.sync_error && <div className="mt-2 text-[11px] text-red-300">{source.sync_error}</div>}
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          </section>

          <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <Panel title={`CVE records (${total.toLocaleString()})`}>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-gray-950 text-gray-500">
                    <tr>
                      <th className="px-3 py-2">CVE</th>
                      <th className="px-3 py-2">CVSS</th>
                      <th className="px-3 py-2">Known exploited</th>
                      <th className="px-3 py-2">Description</th>
                      <th className="px-3 py-2">Weakness</th>
                      <th className="px-3 py-2">Modified</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(item => <CVERow key={item.cve_id} item={item} selected={selectedCve === item.cve_id} onSelect={() => setSelectedCve(item.cve_id)} />)}
                    {!rows.length && <tr><td colSpan={6} className="p-6 text-center text-gray-500">{library.isLoading ? 'Loading CVEs...' : 'No CVEs match this filter.'}</td></tr>}
                  </tbody>
                </table>
              </div>
              <div className="flex items-center justify-between border-t border-gray-800 p-3 text-xs text-gray-400">
                <span>Showing {offset + 1}-{Math.min(offset + limit, total)} of {total}</span>
                <div className="flex gap-2">
                  <button className="secondary-action" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</button>
                  <button className="secondary-action" disabled={offset >= maxPage} onClick={() => setOffset(Math.min(maxPage, offset + limit))}>Next</button>
                </div>
              </div>
            </Panel>

            <CveDetailPanel detail={detail.data ?? null} loading={detail.isLoading} />
          </section>
        </div>
      </div>
    </div>
  );
}

function CVERow({ item, selected, onSelect }: { item: CVEItem; selected: boolean; onSelect: () => void }) {
  return (
    <tr onClick={onSelect} className={`cursor-pointer border-t border-gray-800 hover:bg-gray-900 ${selected ? 'bg-mitre-accent/10' : ''}`}>
      <td className="px-3 py-3 align-top"><span className="font-mono text-mitre-accent">{item.cve_id}</span></td>
      <td className="px-3 py-3 align-top"><SeverityBadge severity={item.cvss.severity} score={item.cvss.score} /></td>
      <td className="px-3 py-3 align-top">{item.known_exploited ? <span className="rounded bg-red-900/50 px-2 py-1 text-red-200">KEV</span> : <span className="text-gray-600">no</span>}</td>
      <td className="max-w-xl px-3 py-3 align-top text-gray-300">{item.description || '-'}</td>
      <td className="px-3 py-3 align-top font-mono text-gray-400">{item.cwe_ids.slice(0, 3).join(', ') || '-'}</td>
      <td className="px-3 py-3 align-top text-gray-500">{item.last_modified || '-'}</td>
    </tr>
  );
}

function CveDetailPanel({ detail, loading }: { detail: CVEDetail | null; loading: boolean }) {
  if (loading) return <Panel title="CVE detail"><div className="p-4 text-sm text-gray-500">Loading detail...</div></Panel>;
  if (!detail) return <Panel title="CVE detail"><div className="p-4 text-sm text-gray-500">Select a CVE to review score, references, and strict APT-TTP-IOC-CVE links.</div></Panel>;
  return (
    <Panel title={detail.cve_id}>
      <div className="space-y-4 p-4 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={detail.cvss.severity} score={detail.cvss.score} />
          {detail.known_exploited && <span className="rounded bg-red-900/50 px-2 py-1 text-xs text-red-100">CISA KEV</span>}
          <span className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-400">{detail.vuln_status || 'status unknown'}</span>
        </div>
        <p className="leading-relaxed text-gray-300">{detail.description || 'No description stored.'}</p>
        <InfoGrid items={[
          ['CVSS vector', detail.cvss.vector || '-'],
          ['Published', detail.published || '-'],
          ['Modified', detail.last_modified || '-'],
          ['KEV due date', detail.kev_due_date || '-'],
        ]} />
        {detail.kev_required_action && <div className="rounded border border-red-800 bg-red-950/20 p-3 text-xs text-red-100">{detail.kev_required_action}</div>}
        <LinkGroup title="ATT&CK technique links" empty="No strict CVE-to-TTP link is stored yet.">
          {detail.techniques.map(link => <Link key={`${link.attack_id}:${link.source}`} to={`/navigator?technique=${encodeURIComponent(link.attack_id)}`} className="block rounded border border-gray-800 p-2 hover:border-mitre-accent">
            <b className="font-mono text-mitre-accent">{link.attack_id}</b> <span className="text-gray-300">{link.name}</span>
            <Evidence link={link} />
          </Link>)}
        </LinkGroup>
        <LinkGroup title="Actor links" empty="No strict CVE-to-actor link is stored yet.">
          {detail.actors.map(link => <Link key={`${link.actor_attack_id}:${link.source}`} to={`/apt?group=${encodeURIComponent(link.actor_attack_id)}`} className="block rounded border border-gray-800 p-2 hover:border-mitre-accent">
            <b className="font-mono text-mitre-accent">{link.actor_attack_id}</b> <span className="text-gray-300">{link.actor_name}</span>
            <Evidence link={link} />
          </Link>)}
        </LinkGroup>
        <LinkGroup title="IOC links" empty="No strict CVE-to-IOC link is stored yet.">
          {detail.iocs.map(link => <Link key={`${link.indicator_id}:${link.source}`} to={`/ioc-library/${link.indicator_id}`} className="block rounded border border-gray-800 p-2 hover:border-mitre-accent">
            <b className="font-mono text-mitre-accent">{link.value}</b> <span className="text-gray-500">{link.type}</span>
            <Evidence link={link} />
          </Link>)}
        </LinkGroup>
        <LinkGroup title="References" empty="No references stored.">
          {detail.references.slice(0, 10).map((ref, index) => {
            const href = safeHref(ref.url || '');
            return href ? <a key={`${href}:${index}`} href={href} target="_blank" rel="noreferrer" className="block truncate rounded border border-gray-800 p-2 text-mitre-accent hover:border-mitre-accent">{ref.source || href}</a> : null;
          })}
        </LinkGroup>
      </div>
    </Panel>
  );
}

function SeverityBadge({ severity, score }: { severity: string; score: string }) {
  const tone = severity === 'CRITICAL' ? 'bg-red-900/60 text-red-100' : severity === 'HIGH' ? 'bg-orange-900/60 text-orange-100' : severity === 'MEDIUM' ? 'bg-amber-900/50 text-amber-100' : 'bg-gray-800 text-gray-300';
  return <span className={`inline-flex rounded px-2 py-1 text-xs font-semibold ${tone}`}>{score ? `${severity || 'SCORED'} ${score}` : 'NO NVD SCORE'}</span>;
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string; tone?: 'default' | 'bad' | 'warn' }) {
  const color = tone === 'bad' ? 'text-red-200' : tone === 'warn' ? 'text-amber-200' : 'text-white';
  return <div className="rounded border border-gray-800 bg-gray-950 p-3"><div className={`text-xl font-semibold ${color}`}>{value}</div><div className="text-xs text-gray-500">{label}</div></div>;
}

function InfoGrid({ items }: { items: Array<[string, string]> }) {
  return <div className="grid gap-2 text-xs">{items.map(([label, value]) => <div key={label} className="rounded border border-gray-800 bg-gray-950 p-2"><div className="text-gray-500">{label}</div><div className="mt-1 break-all font-mono text-gray-300">{value}</div></div>)}</div>;
}

function LinkGroup({ title, empty, children }: { title: string; empty: string; children: React.ReactNode }) {
  const nodes = Array.isArray(children) ? children.filter(Boolean) : children;
  const hasChildren = Array.isArray(nodes) ? nodes.length > 0 : Boolean(nodes);
  return <section><h3 className="mb-2 text-xs font-semibold uppercase text-gray-500">{title}</h3><div className="space-y-2">{hasChildren ? nodes : <div className="rounded border border-gray-800 p-3 text-xs text-gray-600">{empty}</div>}</div></section>;
}

function Evidence({ link }: { link: { relationship: string; confidence: number; evidence: string; source: string } }) {
  return <div className="mt-1 text-[11px] leading-relaxed text-gray-500">{link.relationship} · confidence {link.confidence} · {link.source}<br />{link.evidence}</div>;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="overflow-hidden rounded border border-gray-800 bg-gray-900/40"><div className="border-b border-gray-800 px-4 py-3 text-sm font-semibold text-white">{title}</div>{children}</section>;
}
