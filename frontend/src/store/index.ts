import { create } from 'zustand';
import type { Domain } from '@/types/attack';

interface AppState {
  // Active domain across all views
  domain: Domain;
  setDomain: (d: Domain) => void;

  // Active ATT&CK version (null = latest)
  version: string | null;
  setVersion: (v: string | null) => void;

  // ── User TTP layer ──────────────────────────────────────────────────────
  selectedTechniques: Set<string>;
  toggleTechnique: (id: string) => void;
  addTechniques: (ids: string[]) => void;
  replaceTechniques: (ids: string[]) => void;
  clearTechniques: () => void;

  // ── Group-profile overlay layer ─────────────────────────────────────────
  overlayGroupId: string | null;
  overlayGroupName: string;
  setOverlayGroup: (id: string | null, name?: string) => void;

  overlayTechniques: Set<string>;
  setOverlayTechniques: (ids: string[]) => void;
  clearOverlay: () => void;
  comparisonLayers: ComparisonLayer[];
  addComparisonLayer: (layer: Omit<ComparisonLayer, 'id' | 'color'> & { color?: string }) => void;
  removeComparisonLayer: (id: string) => void;
  clearComparisonLayers: () => void;

  // ── Sub-technique expansion ─────────────────────────────────────────────
  expandedTechniques: Set<string>;
  toggleExpanded: (id: string) => void;
  expandAll: (parentIds: string[]) => void;
  collapseAll: () => void;

  coverageTechniques: Set<string>;
  setCoverageTechniques: (ids: string[]) => void;
  clearCoverage: () => void;
  techniqueAssessments: Record<string, TechniqueAssessment>;
  updateTechniqueAssessment: (id: string, assessment: TechniqueAssessment) => void;
  workspaces: InvestigationWorkspace[];
  saveWorkspace: (name: string) => void;
  loadWorkspace: (id: string) => void;
  deleteWorkspace: (id: string) => void;
}

export interface TechniqueAssessment {
  evidence?: string;
  source?: string;
  confidence?: 'low' | 'medium' | 'high';
  mapping?: 'direct' | 'inferred' | 'weak';
  notes?: string;
  maturity?: 'none' | 'hunt' | 'draft' | 'pilot' | 'production' | 'retired';
}

export interface InvestigationWorkspace {
  id: string;
  name: string;
  domain: Domain;
  selectedTechniques: string[];
  coverageTechniques: string[];
  overlayGroupId: string | null;
  overlayGroupName: string;
  techniqueAssessments: Record<string, TechniqueAssessment>;
  updatedAt: string;
}

export interface ComparisonLayer {
  id: string;
  name: string;
  techniqueIds: string[];
  color: string;
  source?: string;
}

const COMPARISON_COLORS = ['#3b82f6', '#22c55e', '#a855f7', '#f59e0b', '#06b6d4', '#ec4899', '#84cc16', '#f97316'];

// NOTE: techniqueAssessments (free-text analyst notes) are stored unencrypted
// in localStorage. This is acceptable for a self-hosted single-operator
// deployment but should be moved server-side if the instance is shared.
const STORAGE_KEY = 'adversarygraph-docker-workbench-v1';
const saved = (() => {
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}'); } catch { return {}; }
})();
const persist = (state: Partial<AppState>) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    coverageTechniques: [...(state.coverageTechniques ?? [])],
    techniqueAssessments: state.techniqueAssessments ?? {},
    workspaces: state.workspaces ?? [],
  }));
};

export const useAppStore = create<AppState>((set, get) => ({
  domain: 'enterprise-attack',
  setDomain: (domain) => set({ domain }),

  version: null,
  setVersion: (version) => set({ version }),

  // User TTPs
  selectedTechniques: new Set(),
  toggleTechnique: (id) =>
    set((s) => {
      const next = new Set(s.selectedTechniques);
      next.has(id) ? next.delete(id) : next.add(id);
      return { selectedTechniques: next };
    }),
  addTechniques: (ids) =>
    set((s) => {
      const next = new Set(s.selectedTechniques);
      ids.forEach((id) => next.add(id));
      return { selectedTechniques: next };
    }),
  replaceTechniques: (ids) =>
    set({ selectedTechniques: new Set(ids) }),
  clearTechniques: () => set({ selectedTechniques: new Set() }),

  // Group-profile overlay
  overlayGroupId: null,
  overlayGroupName: '',
  setOverlayGroup: (id, name = '') =>
    set({ overlayGroupId: id, overlayGroupName: name }),

  overlayTechniques: new Set(),
  setOverlayTechniques: (ids) =>
    set({ overlayTechniques: new Set(ids) }),
  clearOverlay: () =>
    set({ overlayGroupId: null, overlayGroupName: '', overlayTechniques: new Set() }),
  comparisonLayers: [],
  addComparisonLayer: (layer) =>
    set((state) => {
      const color = layer.color ?? COMPARISON_COLORS[state.comparisonLayers.length % COMPARISON_COLORS.length];
      const nextLayer: ComparisonLayer = {
        id: crypto.randomUUID(),
        name: layer.name.trim() || `Comparison layer ${state.comparisonLayers.length + 1}`,
        techniqueIds: Array.from(new Set(layer.techniqueIds.map(id => id.toUpperCase()))).sort(),
        color,
        source: layer.source,
      };
      return { comparisonLayers: [...state.comparisonLayers, nextLayer] };
    }),
  removeComparisonLayer: (id) =>
    set((state) => ({ comparisonLayers: state.comparisonLayers.filter(layer => layer.id !== id) })),
  clearComparisonLayers: () =>
    set({ comparisonLayers: [] }),

  // Sub-technique expansion
  expandedTechniques: new Set(),
  toggleExpanded: (id) =>
    set((s) => {
      const next = new Set(s.expandedTechniques);
      next.has(id) ? next.delete(id) : next.add(id);
      return { expandedTechniques: next };
    }),
  expandAll: (parentIds) =>
    set({ expandedTechniques: new Set(parentIds) }),
  collapseAll: () =>
    set({ expandedTechniques: new Set() }),

  coverageTechniques: new Set(saved.coverageTechniques ?? []),
  setCoverageTechniques: (ids) => set(() => {
    const next = new Set(ids); setTimeout(() => persist({ ...get(), coverageTechniques: next }), 0); return { coverageTechniques: next };
  }),
  clearCoverage: () => set(() => {
    const next = new Set<string>(); setTimeout(() => persist({ ...get(), coverageTechniques: next }), 0); return { coverageTechniques: next };
  }),
  techniqueAssessments: saved.techniqueAssessments ?? {},
  updateTechniqueAssessment: (id, assessment) => set(state => {
    const techniqueAssessments = { ...state.techniqueAssessments, [id]: assessment };
    const coverageTechniques = new Set(state.coverageTechniques);
    assessment.maturity && !['none', 'retired'].includes(assessment.maturity) ? coverageTechniques.add(id) : coverageTechniques.delete(id);
    setTimeout(() => persist({ ...get(), techniqueAssessments, coverageTechniques }), 0);
    return { techniqueAssessments, coverageTechniques };
  }),
  workspaces: saved.workspaces ?? [],
  saveWorkspace: (name) => set(state => {
    const workspace: InvestigationWorkspace = {
      id: crypto.randomUUID(), name: name.trim() || 'Untitled investigation', domain: state.domain,
      selectedTechniques: [...state.selectedTechniques], coverageTechniques: [...state.coverageTechniques],
      overlayGroupId: state.overlayGroupId, overlayGroupName: state.overlayGroupName,
      techniqueAssessments: state.techniqueAssessments, updatedAt: new Date().toISOString(),
    };
    const workspaces = [workspace, ...state.workspaces];
    setTimeout(() => persist({ ...get(), workspaces }), 0); return { workspaces };
  }),
  loadWorkspace: (id) => set(state => {
    const workspace = state.workspaces.find(item => item.id === id);
    return workspace ? {
      domain: workspace.domain, selectedTechniques: new Set(workspace.selectedTechniques),
      coverageTechniques: new Set(workspace.coverageTechniques), overlayGroupId: workspace.overlayGroupId,
      overlayGroupName: workspace.overlayGroupName, techniqueAssessments: workspace.techniqueAssessments,
    } : {};
  }),
  deleteWorkspace: (id) => set(state => {
    const workspaces = state.workspaces.filter(item => item.id !== id);
    setTimeout(() => persist({ ...get(), workspaces }), 0); return { workspaces };
  }),
}));
