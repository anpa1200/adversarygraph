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
  clearTechniques: () => void;

  // ── APT overlay layer ───────────────────────────────────────────────────
  overlayGroupId: string | null;
  overlayGroupName: string;
  setOverlayGroup: (id: string | null, name?: string) => void;

  overlayTechniques: Set<string>;
  setOverlayTechniques: (ids: string[]) => void;
  clearOverlay: () => void;

  // ── Sub-technique expansion ─────────────────────────────────────────────
  expandedTechniques: Set<string>;
  toggleExpanded: (id: string) => void;
  expandAll: (parentIds: string[]) => void;
  collapseAll: () => void;
}

export const useAppStore = create<AppState>((set) => ({
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
  clearTechniques: () => set({ selectedTechniques: new Set() }),

  // APT overlay
  overlayGroupId: null,
  overlayGroupName: '',
  setOverlayGroup: (id, name = '') =>
    set({ overlayGroupId: id, overlayGroupName: name }),

  overlayTechniques: new Set(),
  setOverlayTechniques: (ids) =>
    set({ overlayTechniques: new Set(ids) }),
  clearOverlay: () =>
    set({ overlayGroupId: null, overlayGroupName: '', overlayTechniques: new Set() }),

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
}));
