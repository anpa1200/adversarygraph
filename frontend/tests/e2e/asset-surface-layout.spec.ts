import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('Asset Retrohunt Matches shows five rows in a dedicated scroll region', async ({ page }) => {
  const caseId = '11111111-1111-4111-8111-111111111111';
  const matches = Array.from({ length: 12 }, (_, index) => ({
    id: `match-${index + 1}`,
    asset_id: `asset-${index + 1}`,
    source_type: index % 2 ? 'cve' : 'actor',
    source_id: index % 2 ? `CVE-2026-${String(index + 1).padStart(4, '0')}` : `G${String(index + 1).padStart(4, '0')}`,
    title: `Retrohunt match ${index + 1}`,
    relationship: 'relevant-to',
    relevance_score: 90 - index,
    confidence: 85,
    severity: 'high',
    route: '',
    reason: 'The saved asset labels overlap current intelligence and require analyst validation.',
    evidence: [
      'Exact inventory label overlap.',
      'Related ATT&CK technique candidate.',
      'Source freshness must be reviewed.',
    ],
    tags: ['tag:retrohunt', `asset:asset-${index + 1}`, 'ttp:T1190'],
    status: 'active',
    created_at: '2026-07-24T10:00:00Z',
    updated_at: '2026-07-24T10:00:00Z',
  }));
  const result = {
    case_id: caseId,
    case_name: 'Retrohunt UI fixture',
    provider: 'baseline',
    model: null,
    filename: 'asset_inventory.csv',
    inventory_name: 'Retrohunt UI fixture',
    asset_count: 0,
    summary: 'Layout regression fixture.',
    exposure_counts: {},
    risk_counts: {},
    assets: [],
    top_risks: [],
    recommended_workflow: [],
    cross_asset_findings: [],
    assumptions: [],
    validation_gaps: [],
    registry_summary: { created: 0, updated: 0, asset_ids: [] },
    retrohunt_summary: { assets_checked: 12, matches_created: 12 },
    intel_matches: matches,
    company_space_assets_synced: 0,
    raw_ai_response: '',
  };

  await page.route('**/api/asset-surface/cases', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([{
      id: caseId,
      name: 'Retrohunt UI fixture',
      filename: 'asset_inventory.csv',
      provider: 'baseline',
      model: '',
      use_ai: false,
      asset_count: 0,
      technique_ids: [],
      high_or_critical_count: 0,
      summary: 'Layout regression fixture.',
      created_at: '2026-07-24T10:00:00Z',
      updated_at: '2026-07-24T10:00:00Z',
    }]),
  }));
  await page.route(`**/api/asset-surface/cases/${caseId}`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(result),
  }));
  await page.route('**/api/asset-surface/assets', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route('**/api/asset-surface/intel-matches**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(matches),
  }));
  await page.route('**/api/threat-radar/spaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));

  await page.goto('/asset-surface');
  const inventoryInput = page.getByPlaceholder('Paste CSV, JSON, hostname/IP list, CMDB export, cloud inventory, or scanner output');
  await expect(inventoryInput).toHaveAttribute('rows', '5');
  await inventoryInput.fill(Array.from({ length: 12 }, (_, index) => `asset-${index + 1}`).join('\n'));
  const inventoryDimensions = await inventoryInput.evaluate(element => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
  }));
  expect(inventoryDimensions.scrollHeight).toBeGreaterThan(inventoryDimensions.clientHeight);

  await page.getByRole('button', { name: /Retrohunt UI fixture/ }).click();

  await expect(page.getByText('Showing 5 rows at a time. Scroll for more matches.')).toBeVisible();
  const scrollRegion = page.getByTestId('asset-retrohunt-scroll');
  await expect(scrollRegion).toBeVisible();
  await expect(scrollRegion.getByRole('row')).toHaveCount(13);

  const dimensions = await scrollRegion.evaluate(element => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
  }));
  expect(dimensions.clientHeight).toBeLessThanOrEqual(600);
  expect(dimensions.scrollHeight).toBeGreaterThan(dimensions.clientHeight);

  await scrollRegion.evaluate(element => {
    element.scrollTop = element.scrollHeight;
  });
  await expect.poll(() => scrollRegion.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
});

test('a company-synced matrix asset links directly to its active assessment', async ({ page }) => {
  const caseId = '21111111-1111-4111-8111-111111111111';
  const spaceId = '22222222-2222-4222-8222-222222222222';
  const companyAssetId = '23333333-3333-4333-8333-333333333333';
  const surfaceAsset = {
    asset_id: '1200km-web-001',
    asset: '1200km.com security research website',
    asset_type: 'web-app',
    environment: 'prod',
    owner: 'Andrey Pautov',
    exposure: 'internet',
    criticality: 'high',
    ip_addresses: [],
    domains: ['1200km.com'],
    ports: [80, 443],
    technologies: ['static-html'],
    products: ['1200km research'],
    suppliers: [],
    dependencies: [],
    risk_score: 71,
    risk_level: 'high',
    attack_surface: ['web application/API surface'],
    likely_entry_points: ['HTTPS on TCP/443'],
    attack_paths: ['internet-facing exposure'],
    ttp_candidates: [{ attack_id: 'T1190', name: 'Exploit Public-Facing Application', reason: 'Internet-facing web application.' }],
    control_gaps: ['Validate WAF and CDN controls.'],
    validation_steps: ['Run authorized service discovery.'],
    detection_ideas: ['Monitor abnormal 4xx/5xx bursts.'],
    priority_actions: ['Validate external exposure.'],
    evidence: ['Inventory domain: 1200km.com'],
  };
  const companyAsset = {
    id: companyAssetId,
    space_id: spaceId,
    asset_id: surfaceAsset.asset_id,
    name: surfaceAsset.asset,
    asset_type: surfaceAsset.asset_type,
    environment: surfaceAsset.environment,
    owner: surfaceAsset.owner,
    criticality: surfaceAsset.criticality,
    exposure: surfaceAsset.exposure,
    products: surfaceAsset.products,
    components: [],
    technologies: surfaceAsset.technologies,
    ip_addresses: [],
    domains: surfaceAsset.domains,
    tags: [],
    metadata: {},
  };

  await page.route('**/api/asset-surface/cases', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([{
      id: caseId,
      name: '1200km inventory',
      filename: 'asset_inventory.csv',
      provider: 'baseline',
      model: '',
      use_ai: false,
      asset_count: 1,
      technique_ids: ['T1190'],
      high_or_critical_count: 1,
      summary: 'Company-linked asset fixture.',
      created_at: '2026-07-24T10:00:00Z',
      updated_at: '2026-07-24T10:00:00Z',
    }]),
  }));
  await page.route(`**/api/asset-surface/cases/${caseId}`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      case_id: caseId,
      case_name: '1200km inventory',
      provider: 'baseline',
      model: null,
      filename: 'asset_inventory.csv',
      inventory_name: '1200km inventory',
      asset_count: 1,
      summary: 'Company-linked asset fixture.',
      exposure_counts: { internet: 1 },
      risk_counts: { high: 1 },
      assets: [surfaceAsset],
      top_risks: [surfaceAsset],
      recommended_workflow: [],
      cross_asset_findings: [],
      assumptions: [],
      validation_gaps: [],
      registry_summary: { created: 1, updated: 0, asset_ids: ['registry-asset-1'] },
      retrohunt_summary: { assets_checked: 1, matches_created: 0 },
      intel_matches: [],
      company_space_id: spaceId,
      company_space_assets_synced: 1,
      raw_ai_response: '',
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      space: { id: spaceId, name: 'My Company', slug: 'my-company' },
      items: [companyAsset],
      total: 1,
      limit: 500,
      offset: 0,
      filters: {},
    }),
  }));
  await page.route('**/api/asset-surface/assets', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route('**/api/asset-surface/intel-matches**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route('**/api/threat-radar/spaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([{
      id: spaceId,
      name: 'My Company',
      slug: 'my-company',
      counts: { assets: 1 },
    }]),
  }));

  await page.goto('/asset-surface');
  await page.getByRole('button', { name: /1200km inventory/ }).click();

  const assetLink = page.getByRole('link', { name: surfaceAsset.asset }).first();
  await expect(assetLink).toHaveAttribute(
    'href',
    `/threat-radar/assets/${spaceId}/${companyAssetId}`,
  );
  await expect(page.getByRole('link', { name: 'Open asset & scan' })).toHaveAttribute(
    'href',
    `/threat-radar/assets/${spaceId}/${companyAssetId}#active-assessment`,
  );
});
