import { expect, test, type Page } from '@playwright/test';

import { mockApi } from './support/mock-api';

const allPermissions = [
  'read',
  'run_analysis',
  'manage_intel',
  'manage_detections',
  'run_attack_simulation',
  'manage_feeds',
  'forward_siem',
  'upload_files',
  'export_data',
  'manage_users',
  'manage_auth',
  'view_audit',
];

async function authenticate(page: Page, role: string, permissions: string[], modules?: string[]) {
  await page.route('**/api/auth/status', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      auth_enabled: true,
      native_login_enabled: true,
      user_count: 3,
      bootstrap_configured: false,
      bootstrap_required: false,
      roles: ['viewer', 'auditor', 'threat_intel', 'detection_engineer', 'admin'],
      permissions: allPermissions,
      role_permissions: {},
      password_policy: { min_length: 12 },
      sso_mode: 'proxy',
    }),
  }));
  await page.route('**/api/auth/me', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      auth_enabled: true,
      name: `${role} test user`,
      username: `${role}-test`,
      role,
      roles: [role],
      permissions,
      ...(modules ? { modules } : {}),
    }),
  }));
}

test('SOC Tier 1 module claim limits navigation and direct frontend routes', async ({ page }) => {
  await authenticate(
    page,
    'viewer',
    ['read', 'run_analysis', 'upload_files', 'export_data'],
    ['discover', 'reports_research', 'knowledge', 'ioc_library', 'ioc_investigation', 'virustotal', 'investigation', 'examples', 'help', 'troubleshooting'],
  );

  await page.goto('/discover');
  await expect(page.getByRole('link', { name: 'IOC Investigation' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Reports / Research' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Threat Radar' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Feeds Management' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Admin Panel' })).toHaveCount(0);

  await page.goto('/navigator');
  await expect(page.getByText('Access unavailable')).toBeVisible();
});

async function mockPermissionWorkspaces(page: Page) {
  const emptyPaths = [
    '/operations/investigations',
    '/operations/intake',
    '/operations/detections',
    '/operations/tracked-actors',
    '/pipeline/sources',
    '/pipeline/runs',
    '/pipeline/observables',
    '/pipeline/sandbox/behaviors',
    '/pipeline/detections/versions',
    '/pipeline/audit',
    '/auth/groups',
    '/auth/users',
    '/auth/sessions',
    '/auth/audit',
  ];
  for (const path of emptyPaths) {
    await page.route(`**/api${path}`, route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: '[]',
    }));
  }
}

test.beforeEach(async ({ page }) => {
  await mockApi(page);
  await mockPermissionWorkspaces(page);
});

test('administrator can validate and create a named user', async ({ page }) => {
  await authenticate(page, 'admin', allPermissions, ['admin']);
  let submitted: Record<string, unknown> | undefined;
  await page.route('**/api/auth/users', async route => {
    if (route.request().method() !== 'POST') {
      await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
      return;
    }
    submitted = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      status: 201,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 'created-user',
        username: submitted.username,
        display_name: submitted.display_name,
        role: submitted.role,
        permissions: submitted.permissions,
        effective_permissions: ['read'],
        effective_modules: [],
        group_ids: submitted.group_ids,
        groups: [],
        auth_provider: 'local',
        mfa_enabled: false,
        enabled: true,
        last_login_at: null,
        created_at: '2026-07-24T00:00:00Z',
        updated_at: '2026-07-24T00:00:00Z',
      }),
    });
  });

  await page.goto('/admin');
  const create = page.getByRole('button', { name: 'Create user' });
  await expect(create).toBeEnabled();
  await create.click();
  await expect(page.getByRole('alert')).toContainText('Enter a username');
  await expect(page.getByRole('alert')).toContainText('Use at least 12 characters');

  await page.locator('input[name="username"]').fill('tier1.analyst');
  await page.locator('input[name="display_name"]').fill('Tier 1 Analyst');
  await page.locator('input[name="password"]').fill('valid-password-2026');
  await create.click();

  await expect.poll(() => submitted?.username).toBe('tier1.analyst');
  expect(submitted?.display_name).toBe('Tier 1 Analyst');
  expect(submitted?.role).toBe('viewer');
  await expect(page.locator('input[name="username"]')).toHaveValue('');
});

test('threat-intelligence role can manage intel and feeds but not detections', async ({ page }) => {
  await authenticate(page, 'threat_intel', ['read', 'run_analysis', 'manage_intel', 'manage_feeds', 'upload_files', 'export_data']);

  await page.goto('/pipeline');
  await expect(page.getByRole('heading', { name: 'Intelligence Pipeline' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add RSS' })).toBeVisible();
  await page.getByRole('button', { name: 'detections', exact: true }).click();
  await expect(page.getByTestId('permission-notice-manage_detections')).toBeVisible();
  await expect(page.getByRole('button', { name: /Generate/ })).toHaveCount(0);

  await page.goto('/operations');
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toBeVisible();
});

test('detection engineer gets detection actions and read-only intelligence workflows', async ({ page }) => {
  await authenticate(page, 'detection_engineer', ['read', 'run_analysis', 'manage_detections', 'run_attack_simulation', 'forward_siem', 'export_data']);

  await page.goto('/operations');
  await expect(page.getByRole('heading', { name: 'Operational Intelligence' })).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_intel')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'detections', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_detections')).toHaveCount(0);
});

test('viewer keeps read views but protected workspaces and navigation stay closed', async ({ page }) => {
  await authenticate(page, 'viewer', ['read']);

  await page.goto('/pipeline');
  await expect(page.getByText('Access unavailable')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Pipeline' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Statistics' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Evidence Graph' })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'IOC Investigation' })).toHaveCount(0);

  await page.goto('/cve');
  await expect(page.getByRole('heading', { name: 'CVE Library' })).toBeVisible();
  await expect(page.getByText('CVE-2026-0001')).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_feeds')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sync NVD + KEV' })).toHaveCount(0);

  await page.goto('/discover');
  await expect(page.getByRole('button', { name: /Threat Hunting/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Attack Simulation/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Open IOC Investigation/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Feed management|Manage feeds/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Operations/ })).toHaveCount(0);

  await page.goto('/reports-research');
  await expect(page.getByRole('link', { name: 'Report intake' })).toHaveCount(0);
});

test('analyst sees analysis handoffs but not feed or simulation actions', async ({ page }) => {
  await authenticate(page, 'analyst', ['read', 'run_analysis', 'manage_intel', 'upload_files', 'export_data']);
  await page.route('**/api/system/selftest', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      status: 'degraded',
      duration_ms: 18,
      checked_at: '2026-07-18T12:00:00Z',
      version: '6.0.0',
      checks: [{ name: 'taxonomy_normalized', status: 'warning', message: 'Raw tags require normalization.', details: {} }],
    }),
  }));

  await page.goto('/discover');
  await expect(page.getByText('AdversaryGraph self-test degraded')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open Feeds' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Dismiss self-test popup' }).click();
  await expect(page.getByRole('button', { name: 'Open Threat Hunting' })).toBeVisible();
  await expect(page.getByRole('button', { name: /Attack Simulation/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Feed management|Manage feeds/ })).toHaveCount(0);

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await expect(page.getByRole('link', { name: /Open Attack Simulation/ })).toHaveCount(0);
  await expect(page.getByText(/Attack Simulation handoff requires/)).toBeVisible();

  await page.goto('/reports-research');
  await expect(page.getByRole('link', { name: 'Report intake' })).toHaveCount(2);
});

test('intel manager can review and update the authoritative stored report TLP', async ({ page }) => {
  const sessionId = '11111111-1111-4111-8111-111111111111';
  let patchPayload: Record<string, unknown> | null = null;
  await authenticate(page, 'threat_intel', ['read', 'run_analysis', 'manage_intel', 'manage_feeds', 'upload_files', 'export_data']);
  await page.route(`**/api/analyze/sessions/${sessionId}/linked-report`, async route => {
    if (route.request().method() === 'PATCH') patchPayload = route.request().postDataJSON();
    await route.fallback();
  });

  await page.goto(`/analyze/${sessionId}/report`);
  await expect(page.getByLabel('Stored report TLP')).toContainText('TLP:AMBER+STRICT');
  await page.getByRole('button', { name: 'Edit', exact: true }).click();

  const tlp = page.getByLabel('Report TLP', { exact: true });
  await expect(tlp.locator('option')).toHaveText(['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']);
  await expect(tlp).toHaveValue('TLP:AMBER+STRICT');
  await tlp.selectOption('TLP:RED');
  await page.getByRole('button', { name: 'Save changes' }).click();

  await expect.poll(() => patchPayload?.tlp).toBe('TLP:RED');
  await expect(page.getByLabel('Stored report TLP')).toContainText('TLP:RED');
  await expect(page.getByLabel('Report TLP', { exact: true })).toHaveCount(0);
});

test('viewer sees the authoritative report TLP without edit controls', async ({ page }) => {
  const sessionId = '11111111-1111-4111-8111-111111111111';
  let patchRequests = 0;
  await authenticate(page, 'viewer', ['read']);
  await page.route(`**/api/analyze/sessions/${sessionId}/linked-report`, async route => {
    if (route.request().method() === 'PATCH') patchRequests += 1;
    await route.fallback();
  });

  await page.goto(`/analyze/${sessionId}/report`);
  await expect(page.getByLabel('Stored report TLP')).toContainText('TLP:AMBER+STRICT');
  await expect(page.getByRole('button', { name: 'Edit', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Report TLP', { exact: true })).toHaveCount(0);
  await expect(page.getByTestId('permission-notice-manage_intel')).toBeVisible();
  expect(patchRequests).toBe(0);
});

test('auditor can inspect admin audit without user or session administration', async ({ page }) => {
  const requested: string[] = [];
  page.on('request', request => {
    const pathname = new URL(request.url()).pathname;
    if (['/api/auth/users', '/api/auth/sessions', '/api/auth/audit'].includes(pathname)) requested.push(pathname);
  });
  await authenticate(page, 'auditor', ['read', 'view_audit', 'export_data']);

  await page.goto('/admin');
  await expect(page.getByRole('heading', { name: 'Admin Panel' })).toBeVisible();
  await expect(page.getByText('Auth audit trail')).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_users').first()).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_auth')).toBeVisible();
  await expect.poll(() => requested).toContain('/api/auth/audit');
  expect(requested).not.toContain('/api/auth/users');
  expect(requested).not.toContain('/api/auth/sessions');
});

test('explicit extra permission opens exact actions independently of role name', async ({ page }) => {
  await authenticate(page, 'viewer', ['read', 'run_analysis', 'manage_detections']);

  await page.goto('/operations');
  await expect(page.getByText('Access unavailable')).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Operations' })).toBeVisible();
  await expect(page.getByTestId('permission-notice-manage_intel')).toBeVisible();
  await page.getByRole('button', { name: 'detections', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Create', exact: true })).toBeVisible();
});
