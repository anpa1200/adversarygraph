import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

const sidebarSectionOrder = [
  'Workspace',
  'Intelligence',
  'Analyze & Investigate',
  'Hunt & Validate',
  'Operations',
  'Platform',
  'Learn & Support',
];

const sidebarLinkOrder = [
  'Discover',
  'Threat Radar',
  'Reports / Research',
  'ATT&CK Group Library',
  'Sector Intel',
  'Knowledge Library',
  'IOC Library',
  'CVE Library',
  'RetroHunt Signals',
  'AI Analysis',
  'Navigator',
  'Compare',
  'IOC Investigation',
  'Malware Analysis',
  'VirusTotal Lookup',
  'Asset Surface',
  'EMB3D',
  'Evidence Graph',
  'Threat Hunting',
  'Query Library',
  'Attack Simulation',
  'Investigation',
  'Operations',
  'Pipeline',
  'Statistics',
  'Feeds Management',
  'Observability',
  'Admin Panel',
  'DFIR Examples',
  'Reference Book',
  'Help / Local Guide',
  'Troubleshooting',
];

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('discover workspace renders with mocked platform health', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/discover');
  await expect(page.getByRole('heading', { name: 'Discover Intelligence' })).toBeVisible();
  await expect(page.getByText('Attack Simulation').first()).toBeVisible();
  await expect(page.getByText('CVE Library').first()).toBeVisible();

  const routeScroll = page.getByTestId('app-route-scroll');
  await expect(routeScroll).toBeVisible();
  await expect.poll(async () => routeScroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBeTruthy();

  const discoverScroll = page.getByTestId('discover-scroll-region');
  await expect(discoverScroll).toBeVisible();
  await routeScroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
  await expect.poll(async () => routeScroll.evaluate(node => node.scrollTop > 0)).toBeTruthy();
  await expect(page.getByText('Recent public intelligence')).toBeVisible();

  const sidebarScroll = page.getByTestId('sidebar-primary-nav');
  await expect(sidebarScroll).toBeVisible();
  await expect.poll(async () => sidebarScroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBeTruthy();
  await expect(sidebarScroll.getByRole('heading', { level: 2 })).toHaveText(sidebarSectionOrder);
  await expect.poll(async () => sidebarScroll.getByRole('link').evaluateAll(
    links => links.map(link => link.getAttribute('title')),
  )).toEqual(sidebarLinkOrder);

  await page.goto('/threat-hunting/hunt-1');
  await expect(page.getByTestId('sidebar-primary-nav').locator('a[href="/threat-hunting"]'))
    .toHaveAttribute('aria-current', 'page');
});

test('sidebar omits workflow sections with no viewer-visible destinations', async ({ page }) => {
  await page.route('**/api/auth/status', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      auth_enabled: true,
      native_login_enabled: true,
      user_count: 1,
      bootstrap_configured: false,
      bootstrap_required: false,
    }),
  }));
  await page.route('**/api/auth/me', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      auth_enabled: true,
      name: 'Viewer',
      username: 'viewer',
      role: 'viewer',
      roles: ['viewer'],
      permissions: ['read'],
    }),
  }));

  await page.goto('/discover');

  const sidebar = page.getByTestId('sidebar-primary-nav');
  await expect(sidebar.getByRole('heading', { level: 2 })).toHaveText([
    'Workspace',
    'Intelligence',
    'Analyze & Investigate',
    'Learn & Support',
  ]);
  await expect(page.getByTestId('sidebar-section-hunt-validate')).toHaveCount(0);
  await expect(page.getByTestId('sidebar-section-operations')).toHaveCount(0);
  await expect(page.getByTestId('sidebar-section-platform')).toHaveCount(0);
});

test('attack simulation matrix and saved-flow history render', async ({ page }) => {
  await page.goto('/attack-simulation');
  await expect(page.getByRole('heading', { name: 'Attack Simulation' })).toBeVisible();
  await expect(page.getByText('Choose a TTP from the ATT&CK matrix')).toBeVisible();
  await expect(page.getByText('Attack Simulation available')).toBeVisible();
  await page.goto('/attack-simulation/sim-t1595-http-fingerprint#ai-attack-assistant');
  await expect(page.getByText('AI Attack Assistant')).toBeVisible();
  await expect(page.getByText('Previous Attack Flows')).toBeVisible();
  await expect(page.getByText('APT29-style identity chain').first()).toBeVisible();
  const fallback = page.getByRole('checkbox', { name: 'Allow unauthenticated HTTP fallback', exact: true });
  await expect(fallback).not.toBeChecked();
  await page.getByLabel('SIEM authentication type').selectOption('bearer');
  await expect(fallback).toBeDisabled();
  await expect(fallback).not.toBeChecked();
});

test('cve library renders searchable records', async ({ page }) => {
  await page.goto('/cve');
  await expect(page.getByRole('heading', { name: 'CVE Library' })).toBeVisible();
  await expect(page.getByText('Search CVE Library')).toBeVisible();
  await expect(page.getByText('CVE-2026-0001')).toBeVisible();
});

test('corrupt local workspace storage cannot crash the application', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('adversarygraph-docker-workbench-v1', JSON.stringify({
      coverageTechniques: { not: 'an array' },
      techniqueAssessments: ['invalid'],
      workspaces: { not: 'an array' },
    }));
  });
  await page.goto('/discover');
  await expect(page.getByRole('heading', { name: 'Discover Intelligence' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Workspaces (0)' })).toBeVisible();
});

test('unknown routes render a recoverable not-found workspace', async ({ page }) => {
  await page.goto('/route-that-does-not-exist');
  await expect(page.getByRole('heading', { name: 'Workspace not found' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open Discover' })).toHaveAttribute('href', '/discover');
});

test('taxonomy readiness warning identifies the real cause and can be repaired', async ({ page }) => {
  let normalized = false;
  await page.route('**/api/system/selftest', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(normalized ? {
      status: 'ok',
      duration_ms: 13,
      checks: [{ name: 'taxonomy_normalized', status: 'ok', message: 'Taxonomy check passed.' }],
    } : {
      status: 'degraded',
      duration_ms: 12,
      checks: [{
        name: 'taxonomy_normalized',
        status: 'warning',
        message: 'Some sampled rows still contain raw unnamespaced tags.',
      }],
    }),
  }));
  await page.route('**/api/system/taxonomy/normalize', route => {
    normalized = true;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ rows_changed: 1, tables: { ioc_indicators: { changed: 1 } } }),
    });
  });

  await page.goto('/discover');
  await expect(page.getByText(/1 readiness check needs attention: taxonomy_normalized/)).toBeVisible();
  await expect(page.getByText(/feed source needs attention/)).toHaveCount(0);
  await page.getByRole('button', { name: 'Normalize Taxonomy' }).click();
  await expect(page.getByText('AdversaryGraph self-test passed')).toBeVisible();
});

test('API-controlled report links reject script and data schemes', async ({ page }) => {
  const sessionId = '11111111-1111-4111-8111-111111111111';
  await page.route(`**/api/analyze/sessions/${sessionId}/linked-report`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      session_id: sessionId,
      name: 'Untrusted link regression',
      provider: 'local',
      model: 'llama3.1:8b',
      domain: 'enterprise-attack',
      tlp: 'TLP:AMBER+STRICT',
      created_at: '2026-07-18T00:00:00Z',
      source_text: 'Untrusted Entity',
      source_text_available: true,
      source_note: '',
      summary: 'Link schemes are constrained at render time.',
      techniques: [],
      apt_matches: [],
      entities: [{ id: 'entity-1', type: 'other', value: 'Untrusted Entity', label: 'Untrusted Entity', aliases: [], route: 'javascript:alert(1)' }],
      report_images: [
        { url: 'data:text/html,<script>alert(1)</script>', alt: 'unsafe', caption: '' },
        { url: 'https://images.example.test/report-diagram.png', alt: 'safe external diagram', caption: 'Architecture diagram' },
      ],
      report_intake: { url: 'javascript:alert(1)', publisher: 'Untrusted source' },
    }),
  }));

  await page.goto(`/analyze/${sessionId}/report`);
  await expect(page.getByText('Untrusted link regression', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Source report' })).toHaveCount(0);
  await expect(page.locator('img[alt="unsafe"]')).toHaveCount(0);
  await expect(page.locator('img[alt="safe external diagram"]')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Open original image: safe external diagram' })).toHaveAttribute('href', 'https://images.example.test/report-diagram.png');
  await expect(page.getByText('External images are listed as references')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Untrusted Entity' })).toHaveAttribute('href', '/discover');
  await expect(page.locator('a[href^="javascript:"], a[href^="data:"]')).toHaveCount(0);
});

test('auditor permission opens observability without an analyst role', async ({ page }) => {
  await page.route('**/api/auth/status', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ auth_enabled: true, native_login_enabled: true, user_count: 1, bootstrap_configured: false, bootstrap_required: false }),
  }));
  await page.route('**/api/auth/me', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ auth_enabled: true, name: 'Audit User', roles: ['auditor', 'viewer'], permissions: ['read', 'view_audit'] }),
  }));

  await page.goto('/observability');
  await expect(page.getByText('Operational telemetry boundary')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Observability' })).toBeVisible();
  await expect(page.getByText('Access unavailable')).toHaveCount(0);
});
