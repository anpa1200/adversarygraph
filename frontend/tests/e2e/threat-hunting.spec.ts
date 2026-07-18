import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('threat hunting dashboard exposes metrics, queue, templates, and scope boundary', async ({ page }) => {
  await page.goto('/threat-hunting');

  await expect(page.getByRole('heading', { name: 'Threat Hunting', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Turn intelligence leads into reviewable threat hunts.' })).toBeVisible();
  await expect(page.getByText('AdversaryGraph manages the hunt record; queries run only in your approved telemetry tools.')).toBeVisible();
  await expect(page.getByText('Awaiting review')).toBeVisible();
  await expect(page.getByText('Suspicious encoded PowerShell execution').first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Threat Hunting' })).toBeVisible();

  await page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).last().click();
  await expect(page).toHaveURL(/\/threat-hunting\/new\?template=powershell-encoded-execution/);
  await expect(page.getByLabel('Hunt title')).toHaveValue('Suspicious encoded PowerShell execution');
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001, T1027');

  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/threat-hunting\/hunt-new$/);
  await expect(page.getByText('draft', { exact: true }).first()).toBeVisible();
});

test('hunt workspace supports query copy, finding review, outcome, lifecycle, and archive', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/threat-hunting/hunt-1');

  await expect(page.getByRole('heading', { name: 'Suspicious encoded PowerShell execution' })).toBeVisible();
  await expect(page.getByText('It does not execute queries against a SIEM or endpoint platform.')).toBeVisible();

  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByText('Query syntax and field names must be validated in the destination platform.')).toBeVisible();
  await expect(page.getByText('Append-only query history')).toBeVisible();
  await expect(page.getByText(/sha256:64b9d5f2f4c1/)).toBeVisible();
  await page.getByRole('button', { name: 'Copy query' }).click();
  await expect(page.getByRole('button', { name: 'Query copied' })).toBeVisible();

  await page.getByRole('tab', { name: /Findings/ }).click();
  await expect(page.getByText('Encoded PowerShell spawned by spreadsheet process')).toBeVisible();
  await page.getByRole('button', { name: 'Add finding' }).click();
  await page.getByLabel('Finding title').fill('Rare child process on host-02');
  await page.getByLabel('Summary').fill('A second endpoint showed related command-line behavior during the scoped period.');
  await page.getByRole('button', { name: 'Save finding' }).click();
  await expect(page.getByText('Rare child process on host-02')).toBeVisible();
  await expect(page.getByText('query v1').last()).toBeVisible();
  await page.getByLabel('Status for Rare child process on host-02').selectOption('reviewed');

  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await page.getByLabel('Reviewed disposition').selectOption('telemetry_gap');
  await page.getByLabel('Result summary').fill('The scoped query returned relevant events, but missing endpoint coverage prevents a complete conclusion.');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await page.getByRole('button', { name: 'Complete hunt' }).click();
  await expect(page.getByText('completed', { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel('Reviewed disposition')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);

  await page.getByRole('button', { name: 'Archive hunt' }).click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  await expect(page.getByText('archived', { exact: true }).first()).toBeVisible();
});

test('navigator deep link preloads ATT&CK and source context without claiming execution', async ({ page }) => {
  await page.goto('/threat-hunting/new?technique=T1059.001&source=navigator&source_ref=T1059.001');

  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001');
  await expect(page.getByLabel('Creation source')).toHaveValue('manual');
  await expect(page.getByLabel('Tags')).toHaveValue('context:navigator, context-ref:T1059.001');
  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByRole('button', { name: 'Copy query' })).toBeDisabled();
  await expect(page.getByText('AdversaryGraph does not claim this query was executed.')).toBeVisible();
});

test('does not request hunt data until analyst access is resolved', async ({ page }) => {
  let releaseAuth: () => void = () => undefined;
  const authBarrier = new Promise<void>(resolve => {
    releaseAuth = resolve;
  });
  let huntRequests = 0;

  await page.route('**/api/auth/me', async route => {
    await authBarrier;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ auth_enabled: true, name: 'Authorized Analyst', roles: ['analyst'], permissions: ['read'] }),
    });
  });
  await page.route('**/api/threat-hunting/**', async route => {
    huntRequests += 1;
    await route.fallback();
  });

  await page.goto('/threat-hunting');
  await expect(page.getByText('Verifying access…')).toBeVisible();
  expect(huntRequests).toBe(0);

  releaseAuth();
  await expect(page.getByRole('heading', { name: 'Turn intelligence leads into reviewable threat hunts.' })).toBeVisible();
  expect(huntRequests).toBeGreaterThan(0);
});

test('failed terminal transition keeps the hunt editable and server-confirmed', async ({ page }) => {
  let rejectNextPatch = true;
  await page.route('**/api/threat-hunting/hunts/hunt-1', async route => {
    if (route.request().method() === 'PATCH' && rejectNextPatch) {
      rejectNextPatch = false;
      await route.fulfill({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Concurrent review prevented completion' }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await page.getByLabel('Reviewed disposition').selectOption('suspicious');
  await page.getByLabel('Result summary').fill('Reviewed evidence supports escalation, but the server must remain authoritative for completion.');
  await page.getByRole('button', { name: 'Complete hunt' }).click();

  await expect(page.getByRole('alert')).toContainText('Concurrent review prevented completion');
  await expect(page.getByText('review', { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel('Reviewed disposition')).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeVisible();
});

test('finding input survives API failure, then supports correction and archive', async ({ page }) => {
  let rejectNextCreate = true;
  await page.route('**/api/threat-hunting/hunts/hunt-1/findings', async route => {
    if (route.request().method() === 'POST' && rejectNextCreate) {
      rejectNextCreate = false;
      await route.fulfill({
        status: 422,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Evidence reference failed server validation' }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: /Findings/ }).click();
  await page.getByRole('button', { name: 'Add finding' }).click();
  await page.getByLabel('Finding title').fill('Finding retained across failure');
  await page.getByLabel('Summary').fill('This analyst-entered evidence must remain available after an API rejection.');
  await page.getByRole('button', { name: 'Save finding' }).click();

  await expect(page.getByRole('alert')).toContainText('Evidence reference failed server validation');
  await expect(page.getByLabel('Finding title')).toHaveValue('Finding retained across failure');
  await expect(page.getByRole('button', { name: 'Save finding' })).toBeVisible();

  await page.getByRole('button', { name: 'Close form' }).click();
  await page.getByRole('button', { name: 'Edit finding' }).click();
  await page.getByLabel('Summary').fill('Peer review established a benign explanation for the observed process chain.');
  await page.getByLabel('Verdict').selectOption('benign');
  await page.getByRole('button', { name: 'Save corrections' }).click();
  await expect(page.getByText('Peer review established a benign explanation for the observed process chain.')).toBeVisible();
  await expect(page.getByText('Benign explanation', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Archive finding' }).click();
  await page.getByRole('button', { name: 'Confirm archive' }).click();
  await expect(page.getByText('Encoded PowerShell spawned by spreadsheet process')).toHaveCount(0);
});

test('classification and lifecycle controls expose only backend-valid actions', async ({ page }) => {
  await page.goto('/threat-hunting/hunt-1');

  await expect(page.getByLabel('TLP').locator('option')).toHaveText(['TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']);
  await expect(page.getByRole('button', { name: 'Return to running' })).toBeVisible();
  await page.getByRole('button', { name: 'Return to running' }).click();
  await expect(page.getByText('running', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send to review' })).toBeVisible();
});

test('hunt queue can be opened with the keyboard', async ({ page }) => {
  await page.goto('/threat-hunting');

  const huntButton = page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).first();
  await huntButton.focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/threat-hunting\/hunt-1$/);
});
