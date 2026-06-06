import axios from 'axios';
import type {
  AttackVersion,
  CampaignDetail,
  CampaignListItem,
  CampaignResult,
  CompareResult,
  GroupDetail,
  GroupListItem,
  ReportSession,
  Tactic,
  TechniqueDetail,
  TechniqueListItem,
} from '@/types/attack';

const http = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
});

// ── ATT&CK ───────────────────────────────────────────────────────────────────

export const attackApi = {
  versions: (): Promise<AttackVersion[]> =>
    http.get('/attack/versions').then(r => r.data),

  tactics: (domain: string, version?: string): Promise<Tactic[]> =>
    http.get('/attack/tactics', { params: { domain, ...(version && { version }) } }).then(r => r.data),

  techniques: (params: {
    domain: string; version?: string; tactic?: string;
    platform?: string; subtechniques?: boolean; search?: string;
  }): Promise<TechniqueListItem[]> =>
    http.get('/attack/techniques', { params }).then(r => r.data),

  technique: (id: string, domain: string, version?: string): Promise<TechniqueDetail> =>
    http.get(`/attack/techniques/${id}`, { params: { domain, ...(version && { version }) } }).then(r => r.data),
};

// ── APT Groups ────────────────────────────────────────────────────────────────

export const aptApi = {
  groups: (params: { domain: string; version?: string; search?: string }): Promise<GroupListItem[]> =>
    http.get('/apt/groups', { params }).then(r => r.data),

  group: (id: string, domain: string, version?: string): Promise<GroupDetail> =>
    http.get(`/apt/groups/${id}`, { params: { domain, ...(version && { version }) } }).then(r => r.data),

  // Body uses CompareRequest wrapper {technique_ids: [...]}
  compare: (params: { technique_ids: string[]; domain: string; version?: string; top_n?: number }): Promise<CompareResult[]> =>
    http.post('/apt/compare', { technique_ids: params.technique_ids }, {
      params: { domain: params.domain, version: params.version, top_n: params.top_n },
    }).then(r => r.data),

  // ── DB 1: Campaigns ──────────────────────────────────────────────────────

  campaigns: (params: {
    domain: string; version?: string; group_id?: string; search?: string;
  }): Promise<CampaignListItem[]> =>
    http.get('/apt/campaigns', { params }).then(r => r.data),

  campaign: (id: string, domain: string, version?: string): Promise<CampaignDetail> =>
    http.get(`/apt/campaigns/${id}`, { params: { domain, ...(version && { version }) } }).then(r => r.data),

  compareCampaigns: (params: {
    technique_ids: string[]; domain: string; version?: string; top_n?: number;
  }): Promise<CampaignResult[]> =>
    http.post('/apt/campaigns/compare', { technique_ids: params.technique_ids }, {
      params: { domain: params.domain, version: params.version, top_n: params.top_n },
    }).then(r => r.data),
};

// ── DB 2: Report sessions ─────────────────────────────────────────────────────

export const reportsApi = {
  list: (limit = 50, offset = 0): Promise<ReportSession[]> =>
    http.get('/analyze/sessions', { params: { limit, offset } }).then(r => r.data),

  compare: (sessionId: string, topN = 10): Promise<CompareResult[]> =>
    http.post(`/analyze/sessions/${sessionId}/compare`, null, {
      params: { top_n: topN },
    }).then(r => r.data),
};

// ── Analysis ──────────────────────────────────────────────────────────────────

export interface AnalysisResult {
  session_id: string;
  provider: string;
  model: string;
  summary: string;
  techniques: Array<{ attack_id: string; name: string; tactic: string; confidence: number; evidence: string }>;
  apt_matches: Array<{ group_attack_id: string; group_name: string; similarity: number; shared_count: number; shared_techniques: string[] }>;
  apt_hints: string[];
}

export const analyzeApi = {
  /** Non-streaming: returns full result */
  submit: (formData: FormData): Promise<AnalysisResult> =>
    http.post('/analyze', formData, { headers: { 'Content-Type': 'multipart/form-data' } }).then(r => r.data),

  /** Streaming: returns a native EventSource-compatible fetch stream */
  stream: (formData: FormData): Promise<Response> =>
    fetch('/api/analyze/stream', { method: 'POST', body: formData }),

  /** Single-turn chat with SSE streaming */
  chat: (payload: { message: string; provider: string; model?: string; context?: string }): Promise<Response> =>
    fetch('/api/analyze/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),

  getResult: (sessionId: string): Promise<AnalysisResult> =>
    http.get(`/analyze/${sessionId}`).then(r => r.data),
};

// ── Saved Layers ──────────────────────────────────────────────────────────────

export interface SavedLayer {
  id: string;
  name: string;
  domain: string;
  technique_count: number;
  created_at: string;
  updated_at: string;
  technique_ids?: string[];
}

export const layersApi = {
  list: (domain?: string): Promise<SavedLayer[]> =>
    http.get('/layers', { params: domain ? { domain } : {} }).then(r => r.data),

  save: (name: string, technique_ids: string[], domain: string): Promise<SavedLayer> =>
    http.post('/layers', { name, technique_ids, domain }).then(r => r.data),

  load: (id: string): Promise<SavedLayer & { technique_ids: string[] }> =>
    http.get(`/layers/${id}`).then(r => r.data),

  remove: (id: string): Promise<void> =>
    http.delete(`/layers/${id}`).then(() => {}),
};

// ── Health ────────────────────────────────────────────────────────────────────

export const healthApi = {
  check: (): Promise<{ status: string }> =>
    http.get('/health').then(r => r.data),
};

// ── MITRE Sync ────────────────────────────────────────────────────────────────

export interface DomainStatus {
  domain: string;
  current_version: string | null;
  latest_version: string | null;
  needs_update: boolean;
  last_ingested: string | null;
}

export const syncApi = {
  status: (): Promise<{ domains: DomainStatus[]; any_updates_needed: boolean }> =>
    http.get('/sync/status').then(r => r.data),

  trigger: (): Promise<{ task_id: string; status: string }> =>
    http.post('/sync/trigger').then(r => r.data),

  taskStatus: (taskId: string): Promise<{ status: string; result: unknown }> =>
    http.get(`/sync/task/${taskId}`).then(r => r.data),
};

// ── Export ────────────────────────────────────────────────────────────────────

export const exportApi = {
  analysisUrl: (sessionId: string) => `/api/export/analysis/${sessionId}`,

  layer: (techniqueIds: string[], domain: string): Promise<Blob> =>
    http.post(
      '/export/layer',
      { technique_ids: techniqueIds, domain },
      { responseType: 'blob' },
    ).then(r => r.data as Blob),
};
