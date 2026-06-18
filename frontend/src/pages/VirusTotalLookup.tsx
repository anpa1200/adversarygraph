import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation } from '@tanstack/react-query';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Header } from '@/components/Layout/Header';
import { iocApi, type VirusTotalLookupResult } from '@/api/client';
import { useAppStore } from '@/store';

export function VirusTotalLookup() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { domain, addTechniques, replaceTechniques, setOverlayGroup } = useAppStore();
  const initialIndicator = searchParams.get('indicator') ?? '';
  const [indicator, setIndicator] = useState(initialIndicator);
  const [autoLookupDone, setAutoLookupDone] = useState(false);
  const lookup = useMutation({
    mutationFn: (value: string) => iocApi.virusTotalLookup({ indicator: value, domain }),
  });

  const result = lookup.data ?? null;
  const ttpIds = result?.ttps.map(item => item.attack_id) ?? [];

  useEffect(() => {
    const value = searchParams.get('indicator')?.trim() ?? '';
    if (!value) return;
    setIndicator(value);
    if (!autoLookupDone) {
      setAutoLookupDone(true);
      lookup.mutate(value);
    }
  }, [autoLookupDone, lookup, searchParams]);

  const showOnMatrix = (ids: string[]) => {
    replaceTechniques(ids);
    navigate('/navigator');
  };

  return (
    <div className="flex h-full flex-col">
      <Header title="VirusTotal IOC Lookup" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-7xl space-y-5">
          <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4">
            <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
              <div>
                <h2 className="text-base font-semibold text-white">Check IOC and connect it to ATT&CK context</h2>
                <p className="mt-2 max-w-3xl text-sm text-gray-400">
                  Look up an IP, domain, URL, MD5, SHA1, or SHA256 in VirusTotal. AdversaryGraph shows detection context,
                  extracted ATT&CK IDs, and local actor matches by group name or alias.
                </p>
              </div>
              <a
                href="https://www.virustotal.com/gui/home/search"
                target="_blank"
                rel="noreferrer"
                className="h-fit rounded border border-gray-700 px-3 py-2 text-xs font-semibold text-gray-300 hover:border-gray-500 hover:text-white"
              >
                Open VirusTotal ↗
              </a>
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <input
                value={indicator}
                onChange={event => setIndicator(event.target.value)}
                onKeyDown={event => {
                  if (event.key === 'Enter' && indicator.trim()) lookup.mutate(indicator.trim());
                }}
                placeholder="IP, domain, URL, MD5, SHA1, or SHA256..."
                className="min-w-[320px] flex-1 rounded border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-gray-200 outline-none focus:border-mitre-accent"
              />
              <button
                type="button"
                disabled={!indicator.trim() || lookup.isPending}
                onClick={() => lookup.mutate(indicator.trim())}
                className="rounded bg-mitre-accent px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {lookup.isPending ? 'Checking...' : 'Check IOC'}
              </button>
            </div>
            {lookup.error && (
              <div className="mt-3 rounded border border-red-500/50 bg-red-950/30 p-3 text-sm text-red-100">
                {lookup.error instanceof Error ? lookup.error.message : String(lookup.error)}
              </div>
            )}
          </section>

          {result && (
            <>
              <ResultSummary result={result} />

              <section className="grid gap-4 xl:grid-cols-[1fr_420px]">
                <Panel title={`ATT&CK TTPs (${result.ttps.length})`}>
                  {result.ttps.length > 0 ? (
                    <>
                      <div className="mb-3 flex flex-wrap gap-2">
                        <button onClick={() => addTechniques(ttpIds)} className="primary-action">Add to My TTPs</button>
                        <button onClick={() => showOnMatrix(ttpIds)} className="secondary-action">Show on matrix</button>
                      </div>
                      <div className="space-y-2">
                        {result.ttps.map(ttp => (
                          <div key={ttp.attack_id} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <a href={`/navigator?technique=${ttp.attack_id}`} className="font-mono text-sm text-mitre-accent hover:underline">{ttp.attack_id}</a>
                              <span className="text-sm text-white">{ttp.name || 'Technique from VirusTotal context'}</span>
                            </div>
                            {ttp.tactics.length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1.5">
                                {ttp.tactics.map(tactic => <span key={tactic} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{tactic}</span>)}
                              </div>
                            )}
                            <EvidenceList
                              rows={result.ttp_evidence
                                .filter(row => row.attack_id === ttp.attack_id)
                                .slice(0, 3)
                                .map(row => ({
                                  label: [row.source, row.tactic || row.name].filter(Boolean).join(' / '),
                                  text: row.evidence,
                                }))}
                            />
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <Empty text="No ATT&CK technique IDs were present in the VirusTotal response for this IOC." />
                  )}
                </Panel>

                <Panel title={`Local actor matches (${result.actors.length})`}>
                  {result.actors.length > 0 ? (
                    <div className="space-y-3">
                      {result.actors.map(actor => (
                        <div key={actor.attack_id} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <a href={`/apt?group=${actor.attack_id}`} className="text-sm font-semibold text-white hover:text-mitre-accent">{actor.name}</a>
                              <div className="mt-1 font-mono text-xs text-mitre-accent">{actor.attack_id}</div>
                            </div>
                            <span className="rounded bg-purple-950/40 px-2 py-1 text-[10px] text-purple-300">
                              {actor.technique_ids.length} TTPs
                            </span>
                          </div>
                          {actor.matched_terms.length > 0 && (
                            <div className="mt-2 text-xs text-gray-500">Matched: {actor.matched_terms.join(', ')}</div>
                          )}
                          <EvidenceList
                            rows={actor.evidence.slice(0, 4).map(row => ({
                              label: `${row.source}: ${row.term}`,
                              text: row.evidence,
                            }))}
                          />
                          {actor.aliases.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {actor.aliases.slice(0, 8).map(alias => <span key={alias} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{alias}</span>)}
                            </div>
                          )}
                          <div className="mt-3 flex flex-wrap gap-2">
                            <button onClick={() => navigate(`/apt?group=${actor.attack_id}`)} className="secondary-action">Actor page</button>
                            <button onClick={() => { setOverlayGroup(actor.attack_id, actor.name); navigate('/navigator'); }} className="secondary-action">Overlay actor</button>
                            <button onClick={() => addTechniques(actor.technique_ids)} className="secondary-action">Add actor TTPs</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <Empty text="No local ATT&CK actor profile matched the VirusTotal names, tags, or labels." />
                  )}
                </Panel>
              </section>

              <section className="grid gap-4 xl:grid-cols-2">
                <Panel title={`Detections (${result.detections.length})`}>
                  {result.detections.length > 0 ? (
                    <div className="overflow-hidden rounded border border-gray-800">
                      <table className="w-full text-left text-xs">
                        <thead className="bg-gray-950 text-gray-500">
                          <tr><th className="p-2">Engine</th><th className="p-2">Category</th><th className="p-2">Result</th></tr>
                        </thead>
                        <tbody>
                          {result.detections.map(row => (
                            <tr key={`${row.engine}-${row.result}`} className="border-t border-gray-800">
                              <td className="p-2 text-gray-300">{row.engine}</td>
                              <td className={row.category === 'malicious' ? 'p-2 text-red-300' : 'p-2 text-amber-300'}>{row.category || '-'}</td>
                              <td className="p-2 text-gray-400">{row.result || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <Empty text="No malicious or named engine detections were returned." />}
                </Panel>

                <Panel title="Labels and context">
                  <LabelBlock title="Object names" values={result.names} />
                  <LabelBlock title="Threat names" values={result.threat_names} />
                  <LabelBlock title="Tags" values={result.tags} />
                  <div className="mt-3 grid grid-cols-4 gap-2">
                    <Metric label="YARA" value={Number(result.context.crowdsourced_yara_count ?? 0)} />
                    <Metric label="IDS" value={Number(result.context.crowdsourced_ids_count ?? 0)} />
                    <Metric label="Sigma" value={Number(result.context.sigma_result_count ?? 0)} />
                    <Metric label="Sandbox" value={Number(result.context.sandbox_verdict_count ?? 0)} />
                  </div>
                </Panel>
              </section>

              <section className="grid gap-4 xl:grid-cols-2">
                <Panel title={`Crowdsourced rules (${result.rules.length})`}>
                  {result.rules.length > 0 ? (
                    <div className="space-y-2">
                      {result.rules.map((rule, index) => (
                        <div key={`${rule.type}-${rule.name}-${index}`} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{rule.type}</span>
                            {rule.severity && <span className="rounded bg-amber-950/40 px-1.5 py-0.5 text-[10px] text-amber-300">{rule.severity}</span>}
                            <span className="text-sm font-semibold text-white">{rule.name || 'Unnamed rule'}</span>
                          </div>
                          {rule.source && <div className="mt-1 text-xs text-gray-500">{rule.source}</div>}
                          {rule.description && <p className="mt-2 text-xs leading-relaxed text-gray-400">{rule.description}</p>}
                        </div>
                      ))}
                    </div>
                  ) : <Empty text="No crowdsourced YARA, IDS, or Sigma rule details were returned." />}
                </Panel>

                <Panel title={`Sandbox verdicts (${result.sandbox_verdicts.length})`}>
                  {result.sandbox_verdicts.length > 0 ? (
                    <div className="space-y-2">
                      {result.sandbox_verdicts.map(row => (
                        <div key={row.sandbox} className="rounded border border-gray-800 bg-gray-950/40 p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="text-sm font-semibold text-white">{row.sandbox}</span>
                            {row.category && <span className="rounded bg-red-950/40 px-2 py-1 text-[10px] text-red-300">{row.category}</span>}
                          </div>
                          <div className="mt-2 grid gap-2 text-xs text-gray-400 sm:grid-cols-2">
                            <KeyValue label="Class" value={row.malware_classification} />
                            <KeyValue label="Confidence" value={row.confidence} />
                          </div>
                          {row.malware_names && <div className="mt-2 text-xs text-gray-500">Names: {row.malware_names}</div>}
                        </div>
                      ))}
                    </div>
                  ) : <Empty text="No sandbox verdicts were returned for this IOC." />}
                </Panel>
              </section>

              <section className="grid gap-4 xl:grid-cols-2">
                <Panel title="Network and registration">
                  {Object.keys(result.network ?? {}).length > 0 || result.dns_records.length > 0 || result.resolutions.length > 0 ? (
                    <div className="space-y-4">
                      <div className="grid gap-2 sm:grid-cols-2">
                        {Object.entries(result.network).map(([key, value]) => (
                          <KeyValue key={key} label={key.replace(/_/g, ' ')} value={String(value)} />
                        ))}
                      </div>
                      <TinyTable
                        title={`DNS records (${result.dns_records.length})`}
                        rows={result.dns_records.slice(0, 8).map(row => [row.type, row.value, row.ttl])}
                        headers={['Type', 'Value', 'TTL']}
                      />
                      <TinyTable
                        title={`Resolutions (${result.resolutions.length})`}
                        rows={result.resolutions.slice(0, 8).map(row => [row.host_name, row.ip_address, row.date])}
                        headers={['Host', 'IP', 'Date']}
                      />
                    </div>
                  ) : <Empty text="No DNS, ASN, registration, or resolution metadata was returned." />}
                </Panel>

                <Panel title="WHOIS and VT dates">
                  <div className="mb-4 grid gap-2 sm:grid-cols-2">
                    <KeyValue label="First submission" value={formatDate(result.first_submission_date)} />
                    <KeyValue label="Last submission" value={formatDate(result.last_submission_date)} />
                    <KeyValue label="Last analysis" value={formatDate(result.last_analysis_date)} />
                    <KeyValue label="Last modification" value={formatDate(result.last_modification_date)} />
                    <KeyValue label="Community harmless" value={String(result.total_votes?.harmless ?? 0)} />
                    <KeyValue label="Community malicious" value={String(result.total_votes?.malicious ?? 0)} />
                  </div>
                  {result.whois ? (
                    <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded border border-gray-800 bg-gray-950/50 p-3 text-xs leading-relaxed text-gray-400">{result.whois}</pre>
                  ) : <Empty text="No WHOIS text was returned." />}
                </Panel>
              </section>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ResultSummary({ result }: { result: VirusTotalLookupResult }) {
  const stats = result.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const tone = malicious > 0 ? 'border-red-500/50 bg-red-950/25' : suspicious > 0 ? 'border-amber-500/50 bg-amber-950/25' : 'border-emerald-500/50 bg-emerald-950/20';
  return (
    <section className={`rounded-lg border p-4 ${tone}`}>
      <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-gray-950/60 px-2 py-1 font-mono text-xs text-gray-300">{result.type}</span>
            <h2 className="break-all text-base font-semibold text-white">{result.indicator}</h2>
          </div>
          <p className="mt-2 text-sm text-gray-300">{result.summary}</p>
          <div className="mt-3 flex flex-wrap gap-2 text-xs">
            <a href={result.virustotal_url} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-gray-300 hover:border-gray-500 hover:text-white">VirusTotal report ↗</a>
            {result.permalink && result.permalink !== result.virustotal_url && (
              <a href={result.permalink} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-gray-300 hover:border-gray-500 hover:text-white">Permalink ↗</a>
            )}
          </div>
        </div>
        <div className="grid grid-cols-4 gap-2 lg:min-w-[420px]">
          <Metric label="Malicious" value={malicious} danger />
          <Metric label="Suspicious" value={suspicious} warning />
          <Metric label="Harmless" value={stats.harmless ?? 0} />
          <Metric label="Undetected" value={stats.undetected ?? 0} />
        </div>
      </div>
    </section>
  );
}

function EvidenceList({ rows }: { rows: Array<{ label: string; text: string }> }) {
  if (!rows.length) return null;
  return (
    <div className="mt-3 space-y-1.5">
      {rows.map((row, index) => (
        <div key={`${row.label}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-2">
          {row.label && <div className="mb-1 text-[10px] font-semibold uppercase text-gray-500">{row.label}</div>}
          <div className="text-xs leading-relaxed text-gray-400">{row.text}</div>
        </div>
      ))}
    </div>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <section className="rounded-lg border border-gray-800 bg-gray-900/60 p-4"><h2 className="mb-3 text-base font-semibold text-white">{title}</h2>{children}</section>;
}

function Metric({ label, value, danger, warning }: { label: string; value: number; danger?: boolean; warning?: boolean }) {
  const color = danger ? 'text-red-300' : warning ? 'text-amber-300' : 'text-white';
  return <div className="rounded border border-gray-800 bg-gray-950/50 p-3"><b className={`block text-lg ${color}`}>{value}</b><span className="text-[10px] text-gray-500">{label}</span></div>;
}

function LabelBlock({ title, values }: { title: string; values: string[] }) {
  return (
    <div className="mb-3">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500">{title}</h3>
      {values.length ? (
        <div className="flex flex-wrap gap-1.5">
          {values.slice(0, 32).map(value => <span key={value} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-300">{value}</span>)}
        </div>
      ) : <div className="text-xs text-gray-600">None returned.</div>}
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
      <div className="text-[10px] uppercase text-gray-600">{label}</div>
      <div className="mt-1 break-all text-xs text-gray-300">{value || '-'}</div>
    </div>
  );
}

function TinyTable({ title, headers, rows }: { title: string; headers: string[]; rows: string[][] }) {
  if (!rows.length) return null;
  return (
    <div>
      <h3 className="mb-2 text-xs font-semibold text-gray-400">{title}</h3>
      <div className="overflow-hidden rounded border border-gray-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-950 text-gray-500">
            <tr>{headers.map(header => <th key={header} className="p-2">{header}</th>)}</tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index} className="border-t border-gray-800">
                {row.map((cell, cellIndex) => <td key={cellIndex} className="break-all p-2 text-gray-400">{cell || '-'}</td>)}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatDate(value: number | null) {
  if (!value) return '-';
  return new Date(value * 1000).toISOString().slice(0, 10);
}

function Empty({ text }: { text: string }) {
  return <div className="rounded border border-gray-800 bg-gray-950/40 p-4 text-sm text-gray-500">{text}</div>;
}
