const configuredBaseUrl =
  (import.meta as ImportMeta & { env?: Record<string, string> }).env?.VITE_REFERENCE_URL ||
  'http://localhost:3001/anomaly-detection-atlas';

export const REFERENCE_BASE_URL = configuredBaseUrl.replace(/\/$/, '');

export interface TechniqueReference {
  label: string;
  path: string;
  anchor: string;
  context: string;
}

export type TechniqueReferenceIndex = Record<string, TechniqueReference[]>;

export async function loadTechniqueReferenceIndex(): Promise<TechniqueReferenceIndex> {
  const response = await fetch(`${REFERENCE_BASE_URL}/ttp-reference-index.json`);
  if (!response.ok) throw new Error('Unable to load the TTP reference index');
  return response.json();
}

export function techniqueReferenceUrl(reference: TechniqueReference): string {
  return `${REFERENCE_BASE_URL}/${reference.path}/#${reference.anchor}`;
}
