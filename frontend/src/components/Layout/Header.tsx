import { useAppStore } from '@/store';
import type { Domain } from '@/types/attack';
import { DOMAIN_LABELS } from '@/types/attack';

const DOMAINS: Domain[] = ['enterprise-attack', 'mobile-attack', 'ics-attack'];

export function Header({ title }: { title: string }) {
  const { domain, setDomain, selectedTechniques, clearTechniques } = useAppStore();

  return (
    <header className="flex items-center justify-between px-6 py-3 bg-mitre-navy border-b border-gray-700 shrink-0">
      <h1 className="text-base font-semibold text-white">{title}</h1>

      <div className="flex items-center gap-4">
        {/* Domain picker */}
        <div className="flex gap-1 bg-gray-800 rounded-lg p-1">
          {DOMAINS.map((d) => (
            <button
              key={d}
              onClick={() => setDomain(d)}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                domain === d
                  ? 'bg-mitre-accent text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {DOMAIN_LABELS[d]}
            </button>
          ))}
        </div>

        {/* TTP counter badge */}
        {selectedTechniques.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs bg-mitre-accent/20 text-mitre-accent px-2 py-1 rounded-full">
              {selectedTechniques.size} TTPs selected
            </span>
            <button
              onClick={clearTechniques}
              className="text-xs text-gray-500 hover:text-red-400 transition-colors"
            >
              Clear
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
