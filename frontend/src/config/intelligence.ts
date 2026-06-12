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

let reportCache: ReportIndex | null = null;
let resourceCache: Record<string, TechniqueResource[]> | null = null;

export async function loadReportIndex(): Promise<ReportIndex> {
  if (reportCache) return reportCache;
  const response = await fetch('/report-reference-index.json');
  if (!response.ok) throw new Error(`Unable to load report index: HTTP ${response.status}`);
  reportCache = await response.json() as ReportIndex;
  return reportCache;
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

