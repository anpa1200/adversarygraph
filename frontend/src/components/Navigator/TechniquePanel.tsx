/**
 * Slide-in right panel shown when an analyst clicks a technique cell.
 * Shows: full description, tactic list, platforms, data sources, detection, groups using it.
 * Also hosts the LLM assistant chat for this specific technique.
 */

import { useQuery } from '@tanstack/react-query';
import { attackApi, aptApi } from '@/api/client';
import { useAppStore } from '@/store';
import { LLMChat } from './LLMChat';

interface Props {
  attackId: string;
  onClose: () => void;
}

export function TechniquePanel({ attackId, onClose }: Props) {
  const { domain, version, selectedTechniques, toggleTechnique } = useAppStore();
  const isSelected = selectedTechniques.has(attackId);

  const { data: tech, isLoading } = useQuery({
    queryKey: ['technique-detail', attackId, domain, version],
    queryFn: () => attackApi.technique(attackId, domain, version ?? undefined),
    staleTime: 30 * 60 * 1000,
  });

  // Find which groups use this technique
  const { data: groups = [] } = useQuery({
    queryKey: ['apt-groups', domain, version],
    queryFn: () => aptApi.groups({ domain, version: version ?? undefined }),
    staleTime: 10 * 60 * 1000,
  });

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
                <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap line-clamp-12">
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

            {/* Detection */}
            {tech.detection && (
              <Section title="Detection">
                <p className="text-xs text-gray-400 leading-relaxed line-clamp-6">
                  {tech.detection}
                </p>
              </Section>
            )}

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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-4 py-3 border-t border-gray-800">
      <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">{title}</div>
      {children}
    </div>
  );
}
