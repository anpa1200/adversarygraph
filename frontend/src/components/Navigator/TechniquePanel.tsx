/**
 * Slide-in right panel shown when an analyst clicks a technique cell.
 * Shows: full description, tactic list, platforms, data sources, detection, groups using it.
 * Also hosts the LLM assistant chat for this specific technique.
 */

import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { attackApi, cveApi, simulationApi } from '@/api/client';
import { loadTechniqueReferenceIndex, techniqueReferenceUrl, getEcosystemLinks } from '@/config/references';
import { useAppStore } from '@/store';
import { LLMChat } from './LLMChat';
import { getTechniqueReports, getTechniqueResources } from '@/config/intelligence';
import { ReportReferences } from '@/components/ReportReferences';
import { safeHref } from '@/utils/url';
import { RelatedCvesPanel } from '@/components/CVE/RelatedCvesPanel';
import { PermissionNotice } from '@/components/PermissionNotice';
import { useHasPermission } from '@/hooks/useCurrentUser';

interface Props {
  attackId: string;
  onClose: () => void;
}

export function TechniquePanel({ attackId, onClose }: Props) {
  const canRunAnalysis = useHasPermission('run_analysis');
  const canRunSimulation = useHasPermission('run_attack_simulation');
  const canExportData = useHasPermission('export_data');
  const { domain, version, selectedTechniques, toggleTechnique, techniqueAssessments, updateTechniqueAssessment } = useAppStore();
  const isSelected = selectedTechniques.has(attackId);

  const { data: tech, isLoading } = useQuery({
    queryKey: ['technique-detail', attackId, domain, version],
    queryFn: () => attackApi.technique(attackId, domain, version ?? undefined),
    staleTime: 30 * 60 * 1000,
  });
  const { data: referenceIndex = {} } = useQuery({
    queryKey: ['ttp-reference-index'],
    queryFn: loadTechniqueReferenceIndex,
    staleTime: 5 * 60 * 1000,
  });
  const techniqueReferences = referenceIndex[attackId] || [];
  const { data: reports = [] } = useQuery({ queryKey: ['technique-reports', attackId], queryFn: () => getTechniqueReports(attackId) });
  const { data: resources = [] } = useQuery({ queryKey: ['technique-resources', attackId], queryFn: () => getTechniqueResources(attackId) });
  const { data: simulationCatalog = [] } = useQuery({
    queryKey: ['simulation-catalog'],
    queryFn: simulationApi.catalog,
    enabled: canRunSimulation,
    staleTime: 5 * 60 * 1000,
  });
  const { data: relatedCves = [], isLoading: relatedCvesLoading } = useQuery({
    queryKey: ['related-cves-technique', attackId],
    queryFn: () => cveApi.relatedToTechnique(attackId, 50),
    staleTime: 5 * 60 * 1000,
  });
  const simulation = simulationCatalog.find(item => item.technique_id === attackId);
  const assessment = techniqueAssessments[attackId] ?? {};

  return (
    <div className="flex flex-col h-full bg-gray-900 border-l border-gray-700 w-[420px] shrink-0">
      {/* Header */}
      <div className="flex items-start justify-between px-4 py-3 border-b border-gray-700">
        <div className="flex-1 min-w-0 mr-3">
          <div className="font-mono text-xs text-mitre-accent">{attackId}</div>
          <div className="text-white font-semibold text-sm mt-0.5 leading-tight">
            {isLoading ? '...' : tech?.name}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => toggleTechnique(attackId)}
            className={`text-xs px-2.5 py-1 rounded transition-colors ${
              isSelected
                ? 'bg-mitre-accent text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            {isSelected ? '✓ In my TTPs' : '+ Add to TTPs'}
          </button>
          <button onClick={() => navigator.clipboard.writeText(`${location.origin}/navigator?technique=${attackId}`)}
            className="text-xs px-2 py-1 rounded bg-gray-700 text-gray-300 hover:bg-gray-600">Link</button>
          {simulation && (
            <a
              href={`/attack-simulation/${simulation.id}`}
              className="rounded bg-green-900 px-2 py-1 text-xs text-green-100 hover:bg-green-800"
            >
              Attack Simulation
            </a>
          )}
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-white transition-colors text-lg leading-none"
          >
            ✕
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="p-6 text-gray-500 text-sm">Loading...</div>
        ) : tech ? (
          <>
            {/* Meta pills */}
            <div className="px-4 pt-4 pb-2 flex flex-wrap gap-1.5">
              {tech.tactics.map(t => (
                <span key={t} className="text-[10px] bg-red-900/40 border border-red-800 text-red-300 px-2 py-0.5 rounded-full">
                  {t}
                </span>
              ))}
              {tech.platforms.map(p => (
                <span key={p} className="text-[10px] bg-gray-800 text-gray-400 px-2 py-0.5 rounded-full">
                  {p}
                </span>
              ))}
            </div>

            {/* Description */}
            {tech.description && (
              <Section title="Description">
                <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">
                  {tech.description}
                </p>
                {safeHref(tech.url) && (
                <a
                  href={safeHref(tech.url)}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-mitre-accent hover:underline mt-2 inline-block"
                >
                  View on ATT&CK ↗
                </a>
                )}
              </Section>
            )}

            <Section title="Detection Logic">
              {tech.detection ? (
                <p className="text-xs text-gray-400 leading-relaxed line-clamp-6">
                  {tech.detection}
                </p>
              ) : <Guidance>Baseline {tech.name} activity and alert on rare, unauthorized, or contextually inconsistent behavior.</Guidance>}
            </Section>

            {tech.telemetry_readiness && (
              <Section title="Telemetry Readiness Score">
                <div className="rounded border border-cyan-900/60 bg-cyan-950/10">
                  <div className="flex items-center justify-between border-b border-cyan-900/50 px-2.5 py-2">
                    <div>
                      <div className="text-xs font-semibold text-cyan-100">{tech.telemetry_readiness.readiness_score}/100</div>
                      <div className="text-[10px] uppercase text-cyan-500">Detection feasibility</div>
                    </div>
                    <span className={`rounded px-2 py-1 text-[10px] font-semibold ${feasibilityClass(tech.telemetry_readiness.detection_feasibility)}`}>
                      {tech.telemetry_readiness.detection_feasibility}
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[520px] text-left text-[10px]">
                      <thead className="bg-gray-950/60 text-gray-500 uppercase">
                        <tr>
                          <th className="px-2 py-1.5 font-semibold">Technique</th>
                          <th className="px-2 py-1.5 font-semibold">Required Data Components</th>
                          <th className="px-2 py-1.5 font-semibold">Available Logs</th>
                          <th className="px-2 py-1.5 font-semibold">Missing Telemetry</th>
                          <th className="px-2 py-1.5 font-semibold">Detection Feasibility</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr className="align-top text-gray-300">
                          <td className="px-2 py-2 font-mono text-cyan-200">{tech.attack_id}<br /><span className="font-sans text-gray-400">{tech.name}</span></td>
                          <td className="px-2 py-2">{renderList(tech.telemetry_readiness.required_data_components)}</td>
                          <td className="px-2 py-2">{renderList(tech.telemetry_readiness.available_logs)}</td>
                          <td className="px-2 py-2">{renderList(tech.telemetry_readiness.missing_telemetry.length ? tech.telemetry_readiness.missing_telemetry : ['None inferred'])}</td>
                          <td className="px-2 py-2">{tech.telemetry_readiness.detection_feasibility}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                  <div className="border-t border-cyan-900/50 px-2.5 py-2">
                    <div className="mb-1 text-[10px] uppercase text-cyan-500">Gap / Next Action</div>
                    {renderList(tech.telemetry_readiness.gaps)}
                  </div>
                </div>
              </Section>
            )}

            <Section title="Mitigation">
              <Guidance>Reduce exposure through least privilege, hardened configuration, restricted execution paths, and control validation against realistic attempts to perform this technique.</Guidance>
            </Section>

            <Section title="Threat Hunting">
              <div className="rounded border border-amber-900/50 bg-amber-950/20 p-2">
                <span className="block text-[10px] uppercase text-amber-500 mb-1">Hunt hypothesis</span>
                <p className="text-xs text-gray-300">If an adversary is using {tech.name}, telemetry should reveal activity inconsistent with the expected user, process, host, workload, or network context.</p>
              </div>
              {canExportData && (
                <button onClick={() => downloadHuntPlan(tech.attack_id, tech.name, tech.tactics, tech.data_sources, resources.map(item => item.url))}
                  className="mt-2 text-xs border border-amber-800 text-amber-400 px-2 py-1 rounded">Export hunt plan</button>
              )}
              {canRunAnalysis && (
                <Link
                  to={`/threat-hunting/new?technique=${encodeURIComponent(tech.attack_id)}&source=navigator&source_ref=${encodeURIComponent(tech.attack_id)}`}
                  className="ml-2 mt-2 inline-flex rounded border border-cyan-800 px-2 py-1 text-xs text-cyan-300 hover:bg-cyan-950/40"
                >
                  Create threat hunt
                </Link>
              )}
              {!canExportData && (
                <div className="mt-2"><PermissionNotice permission="export_data" action="download hunt plans" compact /></div>
              )}
              {!canRunAnalysis && (
                <div className="mt-2"><PermissionNotice permission="run_analysis" action="create threat hunts" compact /></div>
              )}
            </Section>

            <Section title="CVE Crosslinks">
              <RelatedCvesPanel
                title="CVE -> TTP / IOC -> TTP"
                items={relatedCves}
                loading={relatedCvesLoading}
                empty="No strict CVE evidence or CVE-tagged IOC is currently linked to this technique."
              />
            </Section>

            <Section title="Investigation Evidence">
              <div className="grid grid-cols-3 gap-1 mb-2">
                <AssessmentSelect value={assessment.mapping ?? 'weak'} values={['weak','inferred','direct']} onChange={mapping => updateTechniqueAssessment(attackId, { ...assessment, mapping: mapping as typeof assessment.mapping })} />
                <AssessmentSelect value={assessment.confidence ?? 'low'} values={['low','medium','high']} onChange={confidence => updateTechniqueAssessment(attackId, { ...assessment, confidence: confidence as typeof assessment.confidence })} />
                <AssessmentSelect value={assessment.maturity ?? 'none'} values={['none','hunt','draft','pilot','production','retired']} onChange={maturity => updateTechniqueAssessment(attackId, { ...assessment, maturity: maturity as typeof assessment.maturity })} />
              </div>
              <textarea value={assessment.evidence ?? ''} onChange={event => updateTechniqueAssessment(attackId, { ...assessment, evidence: event.target.value })} placeholder="Evidence excerpt supporting this mapping..." className="w-full h-16 bg-gray-800 text-xs text-gray-200 p-2 rounded border border-gray-700 mb-1" />
              <input value={assessment.source ?? ''} onChange={event => updateTechniqueAssessment(attackId, { ...assessment, source: event.target.value })} placeholder="Source URL, report, page, or evidence ID" className="w-full bg-gray-800 text-xs text-gray-200 p-2 rounded border border-gray-700 mb-1" />
              <textarea value={assessment.notes ?? ''} onChange={event => updateTechniqueAssessment(attackId, { ...assessment, notes: event.target.value })} placeholder="Analyst notes and validation details..." className="w-full h-12 bg-gray-800 text-xs text-gray-200 p-2 rounded border border-gray-700" />
            </Section>

            {/* Data sources */}
            {tech.data_sources?.length > 0 && (
              <Section title="Data Sources">
                <div className="flex flex-wrap gap-1">
                  {tech.data_sources.slice(0, 12).map(ds => (
                    <span key={ds} className="text-[10px] bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">
                      {ds}
                    </span>
                  ))}
                </div>
              </Section>
            )}

            {techniqueReferences.length > 0 && (
              <Section title="Anomaly Detection Atlas">
                <div className="space-y-2.5">
                  {techniqueReferences.map(reference => (
                    <a
                      key={`${reference.path}-${reference.anchor}`}
                      href={safeHref(techniqueReferenceUrl(reference))}
                      target="_blank"
                      rel="noreferrer"
                      className="block group"
                    >
                      <span className="block text-[10px] text-gray-500 group-hover:text-gray-400">
                        {reference.label}
                      </span>
                      <span className="block text-xs text-mitre-accent group-hover:underline">
                        {reference.context} ↗
                      </span>
                    </a>
                  ))}
                </div>
              </Section>
            )}

            <Section title="Ecosystem Resources">
              <div className="space-y-2">
                {getEcosystemLinks(attackId).map(link => (
                  <a
                    key={link.url}
                    href={safeHref(link.url)}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center gap-2 group hover:bg-gray-800 rounded px-2 py-1.5 -mx-2 transition-colors"
                  >
                    <span className="text-[10px] text-gray-600 shrink-0">↗</span>
                    <span className="text-xs text-blue-400 group-hover:text-blue-300 group-hover:underline">
                      {link.label}
                    </span>
                  </a>
                ))}
              </div>
            </Section>

            {resources.length > 0 && <Section title="1200km Practical Resources"><div className="space-y-2">{resources.map(item => <a key={item.url} href={safeHref(item.url)} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 px-2 py-1.5 hover:border-gray-600"><small className="block text-[10px] uppercase text-gray-600">{item.kind} · {item.source}</small><span className="text-xs text-blue-400">{item.label} ↗</span></a>)}</div></Section>}
            {reports.length > 0 && <Section title={`Correlated CTI / IR Reports (${reports.length})`}><ReportReferences reports={reports} /></Section>}

            {/* Sub-technique indicator */}
            {tech.is_subtechnique && tech.parent_attack_id && (
              <Section title="Parent Technique">
                <span className="text-xs font-mono text-mitre-accent">{tech.parent_attack_id}</span>
              </Section>
            )}
          </>
        ) : (
          <div className="p-6 text-gray-500 text-sm">Technique not found.</div>
        )}

        {/* LLM Assistant for this technique */}
        <LLMChat
          initialContext={
            tech
              ? `Technique: ${tech.attack_id} — ${tech.name}\nTactics: ${tech.tactics.join(', ')}\nPlatforms: ${tech.platforms.join(', ')}`
              : `Technique: ${attackId}`
          }
          placeholder={`Ask about ${attackId}…`}
        />
      </div>
    </div>
  );
}

function Guidance({ children }: { children: React.ReactNode }) { return <p className="text-xs text-gray-400 leading-relaxed">{children}</p>; }
function renderList(items: string[]) {
  return <ul className="space-y-1">{items.map(item => <li key={item} className="leading-snug">- {item}</li>)}</ul>;
}
function feasibilityClass(value: string) {
  if (value === 'High') return 'bg-green-900/60 text-green-200 border border-green-700';
  if (value === 'Medium') return 'bg-amber-900/60 text-amber-200 border border-amber-700';
  return 'bg-red-900/60 text-red-200 border border-red-700';
}
function AssessmentSelect({ value, values, onChange }: { value: string; values: string[]; onChange: (value: string) => void }) {
  return <select value={value} onChange={event => onChange(event.target.value)} className="bg-gray-800 text-[10px] text-gray-300 px-1 py-1 rounded border border-gray-700">{values.map(item => <option key={item}>{item}</option>)}</select>;
}
function downloadHuntPlan(id: string, name: string, tactics: string[], dataSources: string[], resources: string[]) {
  const text = [`AdversaryGraph Hunt Plan: ${id} ${name}`, '', `Tactics: ${tactics.join(', ')}`, `Telemetry: ${dataSources.join(', ') || 'Define environment-specific telemetry'}`, '', `Hypothesis: If an adversary is using ${name}, telemetry should reveal activity inconsistent with expected context.`, '', 'Resources:', ...resources.map(item => `- ${item}`)].join('\n');
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${id}-hunt-plan.txt`; anchor.click(); URL.revokeObjectURL(url);
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-4 py-3 border-t border-gray-800">
      <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">{title}</div>
      {children}
    </div>
  );
}
