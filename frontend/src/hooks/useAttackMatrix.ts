import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { attackApi } from '@/api/client';
import type { Tactic, TechniqueListItem } from '@/types/attack';

export interface MatrixData {
  tactics: Tactic[];
  // Parent techniques (not sub-techniques) for each tactic shortname
  techniquesByTactic: Map<string, TechniqueListItem[]>;
  // Sub-techniques for each parent attack_id
  subtechsByParent: Map<string, TechniqueListItem[]>;
  // Set of parent IDs that have at least one sub-technique
  parentsWithSubs: Set<string>;
  isLoading: boolean;
  hasData: boolean;
}

export function useAttackMatrix(domain: string, version: string | null): MatrixData {
  const { data: tactics = [], isLoading: tacticsLoading } = useQuery({
    queryKey: ['tactics', domain, version],
    queryFn: () => attackApi.tactics(domain, version ?? undefined),
    staleTime: 10 * 60 * 1000,
  });

  // Fetch ALL techniques including sub-techniques in one request
  const { data: allTechniques = [], isLoading: techLoading } = useQuery({
    queryKey: ['all-techniques', domain, version],
    queryFn: () =>
      attackApi.techniques({
        domain,
        version: version ?? undefined,
        subtechniques: true,
      }),
    staleTime: 10 * 60 * 1000,
    enabled: tactics.length > 0,
  });

  const techniquesByTactic = useMemo(() => {
    const map = new Map<string, TechniqueListItem[]>();
    for (const tactic of tactics) {
      map.set(tactic.shortname, []);
    }
    // Only parent techniques in tactic columns
    for (const tech of allTechniques) {
      if (tech.is_subtechnique) continue;
      for (const tacticShortname of tech.tactics) {
        const list = map.get(tacticShortname);
        if (list) list.push(tech);
      }
    }
    // Sort each column by attack_id
    for (const list of map.values()) {
      list.sort((a, b) => a.attack_id.localeCompare(b.attack_id));
    }
    return map;
  }, [tactics, allTechniques]);

  const subtechsByParent = useMemo(() => {
    const map = new Map<string, TechniqueListItem[]>();
    for (const tech of allTechniques) {
      if (!tech.is_subtechnique || !tech.parent_attack_id) continue;
      const list = map.get(tech.parent_attack_id) ?? [];
      list.push(tech);
      map.set(tech.parent_attack_id, list);
    }
    // Sort sub-techniques by attack_id
    for (const list of map.values()) {
      list.sort((a, b) => a.attack_id.localeCompare(b.attack_id));
    }
    return map;
  }, [allTechniques]);

  const parentsWithSubs = useMemo(
    () => new Set(subtechsByParent.keys()),
    [subtechsByParent]
  );

  return {
    tactics,
    techniquesByTactic,
    subtechsByParent,
    parentsWithSubs,
    isLoading: tacticsLoading || techLoading,
    hasData: tactics.length > 0,
  };
}
