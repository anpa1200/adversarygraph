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

// ── ATT&CK Group Profiles ────────────────────────────────────────────────────

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

  remove: (sessionId: string): Promise<void> =>
    http.delete(`/analyze/sessions/${sessionId}`).then(() => {}),
};

// ── Analysis ──────────────────────────────────────────────────────────────────

export interface AnalysisResult {
  session_id: string;
  provider: string;
  model: string;
  summary: string;
  techniques: Array<{
    attack_id: string;
    name: string;
    tactic: string;
    confidence: number;
    evidence: string;
    review_status?: 'suggested' | 'accepted' | 'rejected' | 'needs-evidence';
    evidence_start?: number | null;
    evidence_end?: number | null;
    evidence_source?: string;
  }>;
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

  updateTechniqueReview: (
    sessionId: string,
    attackId: string,
    body: {
      review_status: 'suggested' | 'accepted' | 'rejected' | 'needs-evidence';
      evidence?: string;
      review_note?: string;
      reviewer?: string;
    },
  ): Promise<AnalysisResult['techniques'][number]> =>
    http.patch(`/analyze/sessions/${sessionId}/techniques/${attackId}/review`, body).then(r => r.data),
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
  source: string;
  domain: string;
  current_version: string | null;
  latest_version: string | null;
  needs_update: boolean;
  last_ingested: string | null;
  content: string[];
}

export interface SyncSource {
  id: string;
  label: string;
  status: string;
  content: string[];
  domains: string[];
  schedule: string | null;
}

export const syncApi = {
  status: (): Promise<{ sources: SyncSource[]; domains: DomainStatus[]; any_updates_needed: boolean }> =>
    http.get('/sync/status').then(r => r.data),

  trigger: (payload?: { source?: string; domains?: string[]; force?: boolean }): Promise<{
    task_id: string;
    status: string;
    source: string;
    domains: string[];
    force: boolean;
  }> =>
    http.post('/sync/trigger', payload ?? {}).then(r => r.data),

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

// ── Operational Intelligence ──────────────────────────────────────────────────

export interface Investigation {
  id: string; name: string; description: string; status: string; domain: string;
  actor_ids: string[]; technique_ids: string[]; report_ids: string[];
  evidence_nodes: Array<Record<string, unknown>>; evidence_edges: Array<Record<string, unknown>>;
  timeline: Array<Record<string, unknown>>; created_at: string; updated_at: string;
}
export interface IntakeRecord {
  id: string; title: string; url: string; publisher: string; status: string; summary: string;
  source_reliability: string; actor_ids: string[]; technique_ids: string[];
  indicators: Array<Record<string, unknown>>; analyst_notes: string; created_at: string; updated_at: string;
}
export interface DetectionCandidate {
  id: string; title: string; technique_id: string; status: string; owner: string;
  telemetry: string[]; query_language: string; query: string; validation_notes: string;
  source_refs: string[]; created_at: string; updated_at: string;
}
export interface TrackedActor {
  id: string; actor_id: string; actor_name: string; last_snapshot: Record<string, unknown>;
  change_log: Array<Record<string, unknown>>; created_at: string; updated_at: string;
}
const operations = '/operations';
export const operationsApi = {
  investigations: (): Promise<Investigation[]> => http.get(`${operations}/investigations`).then(r => r.data),
  createInvestigation: (body: Omit<Investigation, 'id' | 'created_at' | 'updated_at'>): Promise<Investigation> => http.post(`${operations}/investigations`, body).then(r => r.data),
  updateInvestigation: (id: string, body: Omit<Investigation, 'id' | 'created_at' | 'updated_at'>): Promise<Investigation> => http.put(`${operations}/investigations/${id}`, body).then(r => r.data),
  removeInvestigation: (id: string): Promise<void> => http.delete(`${operations}/investigations/${id}`).then(() => {}),
  intake: (): Promise<IntakeRecord[]> => http.get(`${operations}/intake`).then(r => r.data),
  createIntake: (body: Omit<IntakeRecord, 'id' | 'created_at' | 'updated_at'>): Promise<IntakeRecord> => http.post(`${operations}/intake`, body).then(r => r.data),
  updateIntake: (id: string, body: Omit<IntakeRecord, 'id' | 'created_at' | 'updated_at'>): Promise<IntakeRecord> => http.put(`${operations}/intake/${id}`, body).then(r => r.data),
  removeIntake: (id: string): Promise<void> => http.delete(`${operations}/intake/${id}`).then(() => {}),
  detections: (): Promise<DetectionCandidate[]> => http.get(`${operations}/detections`).then(r => r.data),
  createDetection: (body: Omit<DetectionCandidate, 'id' | 'created_at' | 'updated_at'>): Promise<DetectionCandidate> => http.post(`${operations}/detections`, body).then(r => r.data),
  updateDetection: (id: string, body: Omit<DetectionCandidate, 'id' | 'created_at' | 'updated_at'>): Promise<DetectionCandidate> => http.put(`${operations}/detections/${id}`, body).then(r => r.data),
  removeDetection: (id: string): Promise<void> => http.delete(`${operations}/detections/${id}`).then(() => {}),
  trackedActors: (): Promise<TrackedActor[]> => http.get(`${operations}/tracked-actors`).then(r => r.data),
  trackActor: (body: { actor_id: string; actor_name: string; snapshot: Record<string, unknown> }): Promise<TrackedActor> => http.post(`${operations}/tracked-actors`, body).then(r => r.data),
  removeTrackedActor: (id: string): Promise<void> => http.delete(`${operations}/tracked-actors/${id}`).then(() => {}),
};

// ── Collection, Enrichment, and Detection Pipeline ───────────────────────────

export interface CollectionSource {
  id: string; name: string; kind: 'rss' | 'taxii' | 'misp' | 'atlas'; url: string; enabled: boolean;
  interval_minutes: number; config: Record<string, unknown>; last_run_at: string | null; created_at: string; updated_at: string;
}
export interface CollectionRun {
  id: string; source_id: string | null; status: string; items_seen: number; items_created: number;
  observables_created: number; error: string; started_at: string; completed_at: string | null;
}
export interface Observable {
  id: string; type: string; value: string; normalized_value: string; status: string; confidence: number;
  tags: string[]; source_refs: string[]; first_seen_at: string; last_seen_at: string;
}
export interface DetectionVersion {
  id: string; title: string; technique_id: string; format: string; content: string;
  validation: { valid: boolean; errors: string[]; warnings: string[] }; created_by: string; created_at: string;
}
export interface AuditEvent {
  id: string; actor: string; action: string; object_type: string; object_id: string;
  details: Record<string, unknown>; created_at: string;
}
const pipeline = '/pipeline';
export const pipelineApi = {
  me: (): Promise<{name: string; roles: string[]}> => http.get(`${pipeline}/me`).then(r => r.data),
  sources: (): Promise<CollectionSource[]> => http.get(`${pipeline}/sources`).then(r => r.data),
  createSource: (body: Omit<CollectionSource, 'id'|'last_run_at'|'created_at'|'updated_at'>): Promise<CollectionSource> => http.post(`${pipeline}/sources`, body).then(r => r.data),
  runSource: (id: string): Promise<CollectionRun> => http.post(`${pipeline}/sources/${id}/run`).then(r => r.data),
  runs: (): Promise<CollectionRun[]> => http.get(`${pipeline}/runs`).then(r => r.data),
  observables: (): Promise<Observable[]> => http.get(`${pipeline}/observables`).then(r => r.data),
  createObservable: (body: {type:string;value:string;status:string;confidence:number;tags:string[];source_refs:string[]}): Promise<Observable> => http.post(`${pipeline}/observables`, body).then(r => r.data),
  enrich: (id: string): Promise<Record<string, unknown>> => http.post(`${pipeline}/observables/${id}/enrich`).then(r => r.data),
  generate: (body: {title:string;technique_id:string;format:string;telemetry:string[]}): Promise<DetectionVersion> => http.post(`${pipeline}/detections/generate`, body).then(r => r.data),
  validate: (format: string, content: string): Promise<{valid:boolean;errors:string[];warnings:string[]}> => http.post(`${pipeline}/detections/validate`, {format,content}).then(r => r.data),
  versions: (): Promise<DetectionVersion[]> => http.get(`${pipeline}/detections/versions`).then(r => r.data),
  audit: (): Promise<AuditEvent[]> => http.get(`${pipeline}/audit`).then(r => r.data),
  importJson: (kind: 'stix'|'misp'|'atlas', body: Record<string, unknown>): Promise<Record<string, unknown>> => http.post(`${pipeline}/import/${kind}`, body).then(r => r.data),
};
