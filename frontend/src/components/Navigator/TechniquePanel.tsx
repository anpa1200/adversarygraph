/**
 * Slide-in right panel shown when an analyst clicks a technique cell.
 * Shows: full description, tactic list, platforms, data sources, detection, groups using it.
 * Also hosts the LLM assistant chat for this specific technique.
 */

import { useQuery } from '@tanstack/react-query';
import { attackApi } from '@/api/client';
import { loadTechniqueReferenceIndex, techniqueReferenceUrl, getEcosystemLinks } from '@/config/references';
import { useAppStore } from '@/store';
import { LLMChat } from './LLMChat';
import { getTechniqueReports, getTechniqueResources } from '@/config/intelligence';
import { ReportReferences } from '@/components/ReportReferences';

interface Props {
  attackId: string;
  onClose: () => void;
}

export function TechniquePanel({ attackId, onClose }: Props) {
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
                <a
                  href={tech.url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-mitre-accent hover:underline mt-2 inline-block"
                >
                  View on ATT&CK ↗
                </a>
              </Section>
            )}

            <Section title="Detection Logic">
              {tech.detection ? (
                <p className="text-xs text-gray-400 leading-relaxed line-clamp-6">
                  {tech.detection}
                </p>
              ) : <Guidance>Baseline {tech.name} activity and alert on rare, unauthorized, or contextually inconsistent behavior.</Guidance>}
            </Section>

            <Section title="Mitigation">
              <Guidance>Reduce exposure through least privilege, hardened configuration, restricted execution paths, and control validation against realistic attempts to perform this technique.</Guidance>
            </Section>

            <Section title="Threat Hunting">
              <div className="rounded border border-amber-900/50 bg-amber-950/20 p-2">
                <span className="block text-[10px] uppercase text-amber-500 mb-1">Hunt hypothesis</span>
                <p className="text-xs text-gray-300">If an adversary is using {tech.name}, telemetry should reveal activity inconsistent with the expected user, process, host, workload, or network context.</p>
              </div>
              <button onClick={() => downloadHuntPlan(tech.attack_id, tech.name, tech.tactics, tech.data_sources, resources.map(item => item.url))}
                className="mt-2 text-xs border border-amber-800 text-amber-400 px-2 py-1 rounded">Export hunt plan</button>
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
                      href={techniqueReferenceUrl(reference)}
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
                    href={link.url}
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

            {resources.length > 0 && <Section title="1200km Practical Resources"><div className="space-y-2">{resources.map(item => <a key={item.url} href={item.url} target="_blank" rel="noreferrer" className="block rounded border border-gray-800 px-2 py-1.5 hover:border-gray-600"><small className="block text-[10px] uppercase text-gray-600">{item.kind} · {item.source}</small><span className="text-xs text-blue-400">{item.label} ↗</span></a>)}</div></Section>}
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
function AssessmentSelect({ value, values, onChange }: { value: string; values: string[]; onChange: (value: string) => void }) {
  return <select value={value} onChange={event => onChange(event.target.value)} className="bg-gray-800 text-[10px] text-gray-300 px-1 py-1 rounded border border-gray-700">{values.map(item => <option key={item}>{item}</option>)}</select>;
}
function downloadHuntPlan(id: string, name: string, tactics: string[], dataSources: string[], resources: string[]) {
  const text = [`ThreatMapper Hunt Plan: ${id} ${name}`, '', `Tactics: ${tactics.join(', ')}`, `Telemetry: ${dataSources.join(', ') || 'Define environment-specific telemetry'}`, '', `Hypothesis: If an adversary is using ${name}, telemetry should reveal activity inconsistent with expected context.`, '', 'Resources:', ...resources.map(item => `- ${item}`)].join('\n');
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
