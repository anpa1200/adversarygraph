import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('campaign citations open the referenced ATT&CK campaign without a group selection', async ({ page }) => {
  await page.route('**/api/apt/campaigns/C0042**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      attack_id: 'C0042',
      name: 'Operation Deep Link',
      description: 'A campaign opened directly from a cited RAG source.',
      url: 'https://attack.mitre.org/campaigns/C0042/',
      first_seen: '2026-01-01T00:00:00Z',
      last_seen: '2026-02-01T00:00:00Z',
      domain: 'enterprise-attack',
      technique_count: 1,
      group_names: ['Example Actor'],
      techniques: [{
        attack_id: 'T1595',
        name: 'Active Scanning',
        tactics: ['reconnaissance'],
        platforms: ['Linux'],
        is_subtechnique: false,
        use_description: 'The campaign scanned exposed services.',
      }],
    }),
  }));

  await page.goto('/apt?campaign=C0042');

  await expect(page.getByText('Linked ATT&CK campaign')).toBeVisible();
  await expect(page.getByText('Operation Deep Link')).toBeVisible();
  await expect(page.getByText('A campaign opened directly from a cited RAG source.')).toBeVisible();
});

test('knowledge citations open the referenced article modal', async ({ page }) => {
  const article = {
    id: 42,
    category: 'research',
    external_id: 'research-42',
    title: 'Deep-linked threat research',
    summary: 'A stored research article.',
    tags: ['rag', 'research'],
    meta: {},
    source_file: 'research-42.md',
    published_at: '2026-07-01T00:00:00Z',
  };
  await page.route('**/api/knowledge/stats', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ total: 1, by_category: { research: 1 } }),
  }));
  await page.route('**/api/knowledge/articles?**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([article]),
  }));
  await page.route('**/api/knowledge/articles/42', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ ...article, body: '# Cited evidence\n\nThis is the referenced article body.' }),
  }));

  await page.goto('/knowledge?article=42');

  const modal = page.locator('.fixed.inset-0');
  await expect(modal.getByRole('heading', { name: 'Deep-linked threat research' })).toBeVisible();
  await expect(modal.getByRole('heading', { name: 'Cited evidence' })).toBeVisible();
});

test('legacy threat signal citations canonicalize and open the source signal', async ({ page }) => {
  const signalId = 'signal-deep-link';
  await page.route('**/api/threat-radar/spaces', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/threat-radar/signals?**', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route(`**/api/threat-radar/signals/${signalId}`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      id: signalId,
      title: 'Referenced supply-chain signal',
      signal_type: 'supply_chain_compromise_claim',
      description: 'Signal selected through a legacy RAG citation.',
      status: 'new',
      source_name: 'Example Research',
      source_url: 'https://example.test/research',
      tlp: 'TLP:CLEAR',
      legal_sensitive: false,
      confidence: 80,
      severity: 'high',
      cve_ids: [],
      technique_ids: ['T1195'],
      iocs: [],
      actors: [],
      sectors: ['technology'],
      tags: ['supply-chain'],
      raw_metadata: {},
      created_by: 'test',
      product_mappings: [],
      recommended_actions: [],
    }),
  }));
  await page.route('**/api/threat-radar/sources', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/threat-radar/exposure/providers', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));

  await page.goto(`/threat-radar?signal=${signalId}`);

  await expect(page).toHaveURL(new RegExp(`signal_id=${signalId}`));
  await expect(page).not.toHaveURL(/[?&]signal=/);
  await page.getByText('Advanced search and evidence').click();
  await expect(page.getByRole('heading', { name: 'Referenced supply-chain signal' })).toBeVisible();
});

test('evidence citations select the referenced graph node', async ({ page }) => {
  const nodeId = '11111111-1111-4111-8111-111111111111';
  const node = {
    id: nodeId,
    node_type: 'evidence',
    title: 'Referenced endpoint evidence',
    description: 'The exact graph node selected by its citation route.',
    source_type: 'analyst_note',
    source_ref: 'note:42',
    raw_excerpt: 'Observed process and network evidence.',
    normalized_summary: '',
    statement: '',
    claim_type: '',
    behavior_description: '',
    framework: 'attack',
    technique_id: 'T1059.001',
    technique_name: 'PowerShell',
    tactic: 'execution',
    mapping_rationale: '',
    data_source: 'Process',
    data_component: 'Process Creation',
    required_fields: [],
    example_sources: [],
    availability_status: 'available',
    gap_description: '',
    detection_hypothesis: '',
    detection_type: '',
    severity: 'high',
    status: 'active',
    rule_format: '',
    rule_body: '',
    test_status: 'not_tested',
    deployment_status: 'draft',
    scenario_type: '',
    forwarding_status: 'not_sent',
    detection_matched: false,
    decision: '',
    rationale: '',
    confidence: 85,
    review_status: 'analyst_reviewed',
    ai_generated: false,
    metadata_json: {},
    created_at: '2026-07-01T00:00:00Z',
    updated_at: '2026-07-01T00:00:00Z',
  };
  await page.route('**/api/evidence-graph?**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ nodes: [node], edges: [], grouped_paths: [], warnings: [] }),
  }));
  await page.route('**/api/evidence-graph/gaps', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ gaps: [] }) }));
  await page.route('**/api/evidence-graph/paths**', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ paths: [], warnings: [] }) }));

  await page.goto(`/evidence-graph?node=${nodeId}`);

  await expect(page.getByRole('heading', { name: 'Referenced endpoint evidence' })).toBeVisible();
  await expect(page.getByText('The exact graph node selected by its citation route.')).toBeVisible();
});

test('asset citations render the referenced registry record without an open case', async ({ page }) => {
  const assetId = '22222222-2222-4222-8222-222222222222';
  await page.route('**/api/asset-surface/cases', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/threat-radar/spaces', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/asset-surface/intel-matches**', route => route.fulfill({ status: 200, contentType: 'application/json', body: '[]' }));
  await page.route('**/api/asset-surface/assets', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([{
      id: assetId,
      fingerprint: 'asset-fingerprint',
      inventory_asset_id: 'asset-prod-web-01',
      name: 'Production customer portal',
      asset_type: 'web-app',
      environment: 'production',
      owner: 'Digital',
      exposure: 'internet',
      criticality: 'critical',
      ip_addresses: ['203.0.113.10'],
      domains: ['portal.example.test'],
      ports: [443],
      technologies: ['nginx'],
      products: ['customer-portal'],
      suppliers: [],
      dependencies: [],
      technique_ids: ['T1190'],
      tags: ['customer-data'],
      labels: {},
      risk_score: 91,
      risk_level: 'critical',
      source_case_id: null,
      source_inventory_name: 'Production inventory',
      first_seen_at: '2026-07-01T00:00:00Z',
      last_seen_at: '2026-07-18T00:00:00Z',
    }]),
  }));

  await page.goto(`/asset-surface?asset=${assetId}`);

  await expect(page.getByText('Linked asset registry record')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Production customer portal' })).toBeVisible();
  await expect(page.getByText('portal.example.test')).toBeVisible();
  await expect(page.getByText('T1190')).toBeVisible();
});
