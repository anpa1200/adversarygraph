import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('company-space inventory supports manual add, field editing, and upload handoff', async ({ page }) => {
  const spaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const assetId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  let asset = {
    id: assetId,
    space_id: spaceId,
    asset_id: '1200KM-WEB-001',
    name: '1200km.com research website',
    asset_type: 'web-app',
    environment: 'prod',
    owner: 'Andrey Pautov',
    criticality: 'medium',
    exposure: 'internet',
    products: ['1200km research'],
    components: ['static site'],
    technologies: ['github-pages', 'pagefind'],
    ip_addresses: [],
    domains: ['1200km.com'],
    tags: ['public-research'],
    metadata: { ports: [80, 443] },
    created_at: '2026-07-24T10:00:00Z',
    updated_at: '2026-07-24T10:00:00Z',
  };
  let updateBody: Record<string, unknown> | null = null;
  let createBody: Record<string, unknown> | null = null;
  const space = {
    id: spaceId,
    name: 'My Company Threat Monitor',
    slug: 'my-company-threat-monitor',
    description: 'Company inventory.',
    owner: 'Security Team',
    sector: 'technology',
    region: 'global',
    tags: [],
    settings: {},
    counts: { assets: 1 },
    created_by: 'Local Analyst',
  };

  await page.route('**/api/threat-radar/spaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([space]),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ space, assets: [asset], dashboards: [], monitors: [], ai_steps: [] }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/alerts?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route('**/api/threat-radar/asset-scanner/providers', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      enabled: true,
      nmap: {
        enabled: true,
        profile: 'safe-service-discovery',
        top_ports: 100,
        timeout_seconds: 120,
        permission: 'run_attack_simulation',
        boundary: 'Unprivileged bounded service discovery.',
      },
      web: {
        enabled: true,
        profile: 'safe-root-http-posture',
        timeout_seconds: 15,
        permission: 'run_attack_simulation',
        boundary: 'Root HTTP(S) response headers only.',
      },
      passive: [],
      ai: [],
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}/scans?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      space: { id: spaceId, name: space.name, slug: space.slug },
      items: [asset],
      total: 1,
      limit: 500,
      offset: 0,
      filters: {},
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}`, async route => {
    updateBody = route.request().postDataJSON();
    asset = { ...asset, ...(updateBody as Partial<typeof asset>), updated_at: '2026-07-24T11:00:00Z' };
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(asset),
    });
  });
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets`, async route => {
    createBody = route.request().postDataJSON();
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        ...asset,
        ...(createBody as Partial<typeof asset>),
        id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      }),
    });
  });

  await page.goto(`/threat-radar/assets?space_id=${spaceId}&asset_id=${assetId}`);
  const uploadLink = page.getByRole('link', { name: 'Upload & analyze inventory' });
  await expect(uploadLink).toHaveAttribute('href', `/asset-surface?space_id=${spaceId}`);

  await page.getByRole('button', { name: 'Edit asset' }).first().click();
  await expect(page.getByRole('heading', { name: 'Edit 1200km.com research website' })).toBeVisible();
  await expect(page.getByLabel('Inventory ID')).toHaveAttribute('readonly', '');
  await page.getByLabel('Owner').fill('Security Engineering');
  await page.getByLabel('Technologies').fill('GitHub Pages\nPagefind\nStatic HTML');
  await page.getByRole('button', { name: 'Save asset changes' }).click();
  await expect.poll(() => updateBody).not.toBeNull();
  expect(updateBody).toMatchObject({
    asset_id: '1200KM-WEB-001',
    owner: 'Security Engineering',
    technologies: ['GitHub Pages', 'Pagefind', 'Static HTML'],
    metadata: { ports: [80, 443] },
  });

  await page.getByRole('button', { name: 'Add asset manually' }).click();
  await expect(page.getByRole('heading', { name: 'Add company asset' })).toBeVisible();
  await page.getByLabel('Inventory ID').fill('1200KM-LAB-002');
  await page.getByLabel('Name *').fill('Private validation host');
  await page.getByLabel('IP addresses').fill('10.0.0.120');
  await page.getByRole('button', { name: 'Add asset to company space' }).click();
  await expect.poll(() => createBody).not.toBeNull();
  expect(createBody).toMatchObject({
    asset_id: '1200KM-LAB-002',
    name: 'Private validation host',
    ip_addresses: ['10.0.0.120'],
  });
});

test('inventory asset assessment requires authorization and renders evidence', async ({ page }) => {
  const spaceId = '11111111-1111-4111-8111-111111111111';
  const assetId = '22222222-2222-4222-8222-222222222222';
  let requestBody: Record<string, unknown> | null = null;
  const asset = {
    id: assetId,
    space_id: spaceId,
    asset_id: 'edge-001',
    name: 'Customer edge gateway',
    asset_type: 'server',
    environment: 'production',
    owner: 'Platform Security',
    criticality: 'high',
    exposure: 'internet',
    products: ['edge-gateway'],
    components: ['admin-ui'],
    technologies: ['nginx'],
    ip_addresses: ['192.0.2.10'],
    domains: ['edge.example.test'],
    tags: ['customer-facing'],
    metadata: {},
  };
  const completedScan = {
    id: '33333333-3333-4333-8333-333333333333',
    space_id: spaceId,
    asset_id: assetId,
    target: '192.0.2.10',
    target_host: '192.0.2.10',
    target_type: 'ip',
    status: 'completed',
    scan_profile: 'safe-service-discovery',
    requested_providers: ['local-db', 'shodan', 'censys'],
    passive_results: [
      { source: 'shodan', status: 'ok', summary: 'Shodan returned one open port.' },
      { source: 'censys', status: 'ok', summary: 'Censys returned one service.' },
    ],
    nmap_requested: true,
    nmap_result: {
      status: 'ok',
      open_port_count: 1,
      hosts: [{
        ports: [{
          protocol: 'tcp',
          port: 443,
          service: 'https',
          product: 'nginx',
          version: '1.24',
          cpes: ['cpe:/a:nginx:nginx:1.24'],
        }],
      }],
    },
    web_probe_requested: true,
    web_probe_result: {
      status: 'ok',
      profile: 'safe-root-http-posture',
      summary: 'Safe web posture checks inspected one endpoint.',
      probes: [{ url: 'https://192.0.2.10/', status: 'observed', status_code: 200 }],
      findings: [],
    },
    inventory_update: {
      requested: true,
      changed: true,
      observed_count: 5,
      added: {
        ip_addresses: ['198.51.100.42'],
        domains: ['edge-observed.example.test'],
        ports: [443],
        technologies: ['nginx'],
        cpes: ['cpe:/a:nginx:nginx:1.24'],
      },
    },
    findings: [{
      category: 'open-service',
      severity: 'informational',
      title: 'Open tcp/443',
      evidence: 'nginx 1.24',
      source: 'nmap',
      status: 'observed',
      verification_required: false,
    }, {
      category: 'local-cve-candidate',
      severity: 'high',
      title: 'CVE-2026-12345 may apply',
      evidence: 'Detected CPE: cpe:/a:nginx:nginx:1.24',
      source: 'local-cve-library',
      status: 'candidate',
      verification_required: true,
    }],
    ai_requested: false,
    ai_provider: '',
    ai_model: '',
    ai_analysis: {
      provider: 'deterministic',
      risk_level: 'high',
      summary: 'Two passive sources returned data; one open service and one CVE candidate require review.',
      evidence_boundary: 'A service banner and CPE match do not prove a vulnerability.',
      cve_candidates: [{ cve_id: 'CVE-2026-12345', verification_required: true }],
    },
    authorization_confirmed: true,
    warnings: [],
    error: '',
    requested_by: 'Local Analyst',
  };

  await page.route('**/api/threat-radar/spaces', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([{
      id: spaceId,
      name: 'Product Security',
      slug: 'product-security',
      description: 'Authorized asset inventory.',
      owner: 'PSIRT',
      sector: 'technology',
      region: 'global',
      tags: [],
      settings: {},
      counts: { assets: 1 },
      created_by: 'Local Analyst',
    }]),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      space: {
        id: spaceId,
        name: 'Product Security',
        slug: 'product-security',
        description: 'Authorized asset inventory.',
        owner: 'PSIRT',
        sector: 'technology',
        region: 'global',
        tags: [],
        settings: {},
        counts: { assets: 1 },
        created_by: 'Local Analyst',
      },
      assets: [asset],
      dashboards: [],
      monitors: [],
      ai_steps: [],
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/alerts?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route('**/api/threat-radar/asset-scanner/providers', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      enabled: true,
      nmap: {
        enabled: true,
        profile: 'safe-service-discovery',
        top_ports: 100,
        timeout_seconds: 120,
        permission: 'run_attack_simulation',
        boundary: 'Unprivileged TCP connect and light service detection only. No NSE scripts or exploitation.',
      },
      web: {
        enabled: true,
        profile: 'safe-root-http-posture',
        timeout_seconds: 15,
        permission: 'run_attack_simulation',
        boundary: 'Root HTTP(S) response headers only.',
      },
      passive: [
        { id: 'local-db', label: 'AdversaryGraph IOC Library', configured: true, enabled: true, mode: 'passive' },
        { id: 'shodan', label: 'Shodan', configured: true, enabled: true, mode: 'passive' },
        { id: 'censys', label: 'Censys', configured: true, enabled: true, mode: 'passive' },
      ],
      ai: [{
        id: 'local',
        label: 'Local',
        model: 'llama3.1:8b',
        configured: true,
        available: true,
        status: 'ready',
        reason: 'Ready.',
        remote: false,
        requires_acknowledgement: false,
        default: true,
      }],
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}/scans?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}/scans`, async route => {
    requestBody = route.request().postDataJSON();
    return route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify(completedScan),
    });
  });

  await page.goto(`/threat-radar/assets?space_id=${spaceId}&asset_id=${assetId}`);
  await expect(page.getByRole('heading', { name: 'Authorized Asset Exposure Assessment' })).toBeVisible();
  const runButton = page.getByRole('button', { name: 'Run asset assessment' });
  await expect(runButton).toBeDisabled();
  await page.getByRole('checkbox', { name: /Run safe Nmap discovery/ }).check();
  await page.getByRole('checkbox', { name: /Run safe web posture checks/ }).check();
  await page.getByRole('checkbox', { name: /I confirm I am authorized/ }).check();
  await expect(runButton).toBeEnabled();
  await runButton.click();

  await expect(page.getByText('Latest assessment · 192.0.2.10')).toBeVisible();
  await expect(page.getByText('CVE-2026-12345 may apply')).toBeVisible();
  await expect(page.getByText('Analyst verification required.')).toBeVisible();
  await expect(page.getByRole('cell', { name: 'tcp/443' })).toBeVisible();
  await expect(page.getByText('Company inventory updated')).toBeVisible();
  await expect(page.getByText('Safe web posture · ok')).toBeVisible();
  await expect(page.getByText('edge-observed.example.test')).toBeVisible();
  expect(requestBody).toMatchObject({
    target: '192.0.2.10',
    run_nmap: true,
    run_web_probe: true,
    update_inventory: true,
    authorization_confirmed: true,
  });
});

test('saved asset opens a dedicated evidence-labelled intelligence page', async ({ page }) => {
  const spaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const assetId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const asset = {
    id: assetId,
    space_id: spaceId,
    asset_id: 'edge-prod-01',
    name: 'Production edge appliance',
    asset_type: 'appliance',
    environment: 'production',
    owner: 'Platform Security',
    criticality: 'critical',
    exposure: 'internet',
    products: ['EdgeShield'],
    components: ['Management API'],
    technologies: ['nginx'],
    ip_addresses: ['192.0.2.44'],
    domains: ['edge.example.test'],
    tags: ['customer-facing'],
    metadata: {},
    created_at: '2026-07-20T08:00:00Z',
    updated_at: '2026-07-24T08:00:00Z',
  };

  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}/intelligence`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      space: { id: spaceId, name: 'Product Security', slug: 'product-security' },
      asset,
      summary: {
        risk_score: 87,
        risk_level: 'critical',
        alerts: 1,
        cves: 1,
        known_exploited_cves: 1,
        ttps: 1,
        iocs: 1,
        direct_ioc_matches: 1,
        assessments: 1,
        latest_open_services: 1,
        last_assessed_at: '2026-07-24T09:00:00Z',
      },
      cves: [{
        cve_id: 'CVE-2026-45678',
        description: 'A source-backed test vulnerability affecting the management interface.',
        severity: 'CRITICAL',
        score: '9.8',
        known_exploited: true,
        references: [],
        status: 'correlated',
        evidence_level: 'source-backed-correlation',
        evidence: [{ kind: 'matched-signal', label: 'Vendor exploitation report', source: 'Vendor advisory' }],
        verification_required: true,
      }],
      ttps: [{
        attack_id: 'T1190',
        name: 'Exploit Public-Facing Application',
        description: 'Adversaries may exploit a weakness in an internet-facing system.',
        url: 'https://attack.mitre.org/techniques/T1190/',
        platforms: ['Network Devices'],
        data_sources: [],
        evidence_level: 'source-backed-correlation',
        evidence: [{ kind: 'matched-signal', label: 'Vendor exploitation report', source: 'Vendor advisory' }],
        verification_required: true,
      }],
      iocs: [{
        id: '44',
        value: '192.0.2.44',
        indicator_type: 'ip',
        source_id: 'threat-feed',
        source_url: 'https://example.test/feed',
        confidence: 90,
        last_seen: '2026-07-24',
        malware_family: '',
        campaign: '',
        technique_ids: ['T1190'],
        status: 'exact-match',
        evidence_level: 'exact-inventory-identity',
        matched_on: ['192.0.2.44'],
        verification_required: true,
        note: 'Validate freshness and ownership before escalation.',
      }],
      alerts: [{
        id: 'alert-1',
        title: 'Asset exposure match: Production edge appliance',
        description: 'Vendor exploitation report matches the saved product.',
        priority: 'P1 High',
        route: '/threat-radar?tab=detail&signal_id=signal-1',
      }],
      recent_scans: [{
        id: 'scan-1',
        target: '192.0.2.44',
        status: 'completed',
        scan_profile: 'safe-service-discovery',
        nmap_requested: true,
        open_port_count: 1,
        finding_count: 2,
        ai_requested: false,
        ai_provider: '',
        risk_level: 'high',
        requested_by: 'Local Analyst',
        completed_at: '2026-07-24T09:00:00Z',
      }],
      evidence_boundary: 'Correlations are investigation leads and do not prove compromise.',
      generated_at: '2026-07-24T09:05:00Z',
    }),
  }));
  await page.route('**/api/threat-radar/asset-scanner/providers', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      enabled: true,
      nmap: {
        enabled: true,
        profile: 'safe-service-discovery',
        top_ports: 100,
        timeout_seconds: 120,
        permission: 'run_attack_simulation',
        boundary: 'Unprivileged bounded service discovery.',
      },
      web: {
        enabled: true,
        profile: 'safe-root-http-posture',
        timeout_seconds: 15,
        permission: 'run_attack_simulation',
        boundary: 'Root HTTP(S) response headers only.',
      },
      passive: [{ id: 'local-db', label: 'AdversaryGraph IOC Library', configured: true, enabled: true, mode: 'passive' }],
      ai: [],
    }),
  }));
  await page.route(`**/api/threat-radar/spaces/${spaceId}/assets/${assetId}/scans?**`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '[]',
  }));

  await page.goto(`/threat-radar/assets/${spaceId}/${assetId}`);

  await expect(page.getByRole('heading', { name: 'Production edge appliance' })).toBeVisible();
  await expect(page.getByText('CVE-2026-45678')).toBeVisible();
  await expect(page.getByText('Exploit Public-Facing Application')).toBeVisible();
  await expect(page.getByText('exact-inventory-identity')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Authorized Asset Exposure Assessment' })).toBeVisible();
  await expect(page.getByText('Correlations are investigation leads and do not prove compromise.')).toBeVisible();
});
