export interface AttackVersion {
  domain: string;
  version: string;
  is_latest: boolean;
}

export interface Tactic {
  attack_id: string;     // TA0001
  name: string;
  shortname: string;     // initial-access
  description: string;
  url: string;
  domain: string;
  technique_count: number;
}

export interface TechniqueListItem {
  attack_id: string;     // T1566 | T1566.001
  name: string;
  is_subtechnique: boolean;
  parent_attack_id: string | null;
  tactics: string[];     // shortnames
  platforms: string[];
  domain: string;
}

export interface TechniqueDetail extends TechniqueListItem {
  stix_id: string;
  description: string;
  url: string;
  data_sources: string[];
  detection: string;
}

export interface GroupListItem {
  attack_id: string;     // G0001
  name: string;
  aliases: string[];
  domain: string;
  technique_count: number;
}

export interface TechniqueUsage {
  attack_id: string;
  name: string;
  tactics: string[];
  platforms: string[];
  is_subtechnique: boolean;
  use_description: string;
}

export interface GroupDetail extends GroupListItem {
  description: string;
  url: string;
  techniques: TechniqueUsage[];
}

export interface CompareResult {
  group_attack_id: string;
  group_name: string;
  similarity: number;
  shared_count: number;
  shared_techniques: string[];
}

export type Domain = 'enterprise-attack' | 'mobile-attack' | 'ics-attack';

export const DOMAIN_LABELS: Record<Domain, string> = {
  'enterprise-attack': 'Enterprise',
  'mobile-attack': 'Mobile',
  'ics-attack': 'ICS',
};
