export interface ReportReference {
  title: string;
  publisher: string;
  url: string;
  date: string;
  source_id: string;
  reliability: string;
  match_basis: string;
  context: string;
}

export interface TechniqueResource {
  label: string;
  url: string;
  kind: string;
  source: string;
}

interface ReportIndex {
  generated: string;
  byTechnique: Record<string, ReportReference[]>;
  byActor: Record<string, ReportReference[]>;
}

export interface DfirExampleReport {
  title: string;
  url: string;
  date: string;
  tags: string[];
  techniques: string[];
  actors: string[];
}

export interface DfirReportIndex extends ReportIndex {
  source: string;
  supplemental_source?: string;
  license_note: string;
  report_count: number;
  technique_count: number;
  actor_count: number;
  reports: DfirExampleReport[];
}

let reportCache: ReportIndex | null = null;
let dfirCache: DfirReportIndex | null = null;
let resourceCache: Record<string, TechniqueResource[]> | null = null;

export async function loadReportIndex(): Promise<ReportIndex> {
  if (reportCache) return reportCache;
  const response = await fetch('/report-reference-index.json');
  if (!response.ok) throw new Error(`Unable to load report index: HTTP ${response.status}`);
  reportCache = await response.json() as ReportIndex;
  try {
    reportCache = mergeReportIndexes(reportCache, await loadDfirReportIndex());
  } catch {
    // Supplemental external indexes are optional.
  }
  return reportCache;
}

export async function loadDfirReportIndex(): Promise<DfirReportIndex> {
  if (dfirCache) return dfirCache;
  const response = await fetch('/dfir-report-reference-index.json');
  if (!response.ok) throw new Error(`Unable to load DFIR report index: HTTP ${response.status}`);
  dfirCache = await response.json() as DfirReportIndex;
  return dfirCache;
}

function mergeReportIndexes(base: ReportIndex, extra: ReportIndex): ReportIndex {
  return {
    generated: [base.generated, extra.generated].filter(Boolean).join(' + '),
    byTechnique: mergeBuckets(base.byTechnique, extra.byTechnique),
    byActor: mergeBuckets(base.byActor, extra.byActor),
  };
}

function mergeBuckets(
  base: Record<string, ReportReference[]>,
  extra: Record<string, ReportReference[]>,
): Record<string, ReportReference[]> {
  const merged: Record<string, ReportReference[]> = { ...base };
  for (const [key, reports] of Object.entries(extra ?? {})) {
    const seen = new Set((merged[key] ?? []).map(report => report.url));
    merged[key] = [...(merged[key] ?? [])];
    for (const report of reports) {
      if (seen.has(report.url)) continue;
      seen.add(report.url);
      merged[key].push(report);
    }
  }
  return merged;
}

export async function getTechniqueReports(id: string): Promise<ReportReference[]> {
  const index = await loadReportIndex();
  const base = id.split('.')[0];
  const seen = new Set<string>();
  return [...(index.byTechnique[id] ?? []), ...(index.byTechnique[base] ?? [])].filter(report => {
    if (seen.has(report.url)) return false;
    seen.add(report.url);
    return true;
  });
}

export async function getActorReports(id: string): Promise<ReportReference[]> {
  return (await loadReportIndex()).byActor[id] ?? [];
}

export async function getTechniqueResources(id: string): Promise<TechniqueResource[]> {
  if (!resourceCache) {
    const response = await fetch('/technique-resource-index.json');
    if (!response.ok) throw new Error(`Unable to load resource index: HTTP ${response.status}`);
    resourceCache = await response.json() as Record<string, TechniqueResource[]>;
  }
  return resourceCache[id] ?? resourceCache[id.split('.')[0]] ?? [];
}
