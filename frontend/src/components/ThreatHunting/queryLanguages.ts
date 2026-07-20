import type { ThreatHuntQueryLanguage } from '@/api/client';

export const THREAT_HUNT_QUERY_LANGUAGE_OPTIONS: ReadonlyArray<{
  value: ThreatHuntQueryLanguage;
  label: string;
}> = [
  { value: 'generic', label: 'Generic / pseudocode' },
  { value: 'sigma', label: 'Sigma' },
  { value: 'kql', label: 'Microsoft KQL' },
  { value: 'spl', label: 'Splunk SPL' },
  { value: 'eql', label: 'Elastic EQL' },
  { value: 'lucene', label: 'Lucene' },
  { value: 'sql', label: 'SQL' },
  { value: 'osquery', label: 'osquery SQL' },
  { value: 'yara', label: 'YARA' },
  { value: 'yaral', label: 'YARA-L 2.0 (Google SecOps UDM)' },
  { value: 'other', label: 'Other' },
];

export const THREAT_HUNT_QUERY_LANGUAGES = THREAT_HUNT_QUERY_LANGUAGE_OPTIONS.map(option => option.value);

export function queryLanguageLabel(value: ThreatHuntQueryLanguage) {
  return THREAT_HUNT_QUERY_LANGUAGE_OPTIONS.find(option => option.value === value)?.label ?? value;
}
