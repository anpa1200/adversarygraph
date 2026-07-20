import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('query library searches, preserves provenance, and hands a query into a hunt', async ({ page }) => {
  await page.goto('/query-library');

  await expect(page.getByRole('heading', { name: 'Search, review, adapt, and preserve hunt queries.' })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText('Encoded PowerShell execution — Sigma')).toBeVisible();
  await page.getByLabel('Search hunt query library').fill('T1059');
  await expect(page.getByRole('button', { name: /technique:T1059.001/ })).toBeVisible();
  await page.getByText('Encoded PowerShell execution — Sigma').click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('link', { name: 'T1059.001 ↗' })).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/001/');
  await expect(page.getByRole('link', { name: 'Open original source ↗' })).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/001/');
  await page.getByRole('button', { name: 'Create hunt from query' }).click();

  await expect(page).toHaveURL(/\/threat-hunting\/new\?library=query-library-1/);
  await expect(page.getByLabel('Hunt title')).toHaveValue('Encoded PowerShell execution');
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001');
  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByLabel('Query language')).toHaveValue('sigma');
  await expect(page.getByTestId('code-editor')).toContainText('Encoded PowerShell execution');
});

test('IOC builder generates YARA-L locally and can open a hunt draft', async ({ page }) => {
  await page.goto('/query-library');
  await page.getByRole('button', { name: 'Build query from IOCs' }).click();
  await page.getByLabel('Query format').selectOption('yaral');
  await page.getByLabel('IOCs — one per line').fill('203.0.113.10\nmalicious.example');
  await page.getByLabel('ATT&CK techniques (optional)').fill('T1071.001');
  await page.getByRole('button', { name: 'Build query', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('ag_ioc_match');
  await expect(page.getByText('Validate field mappings before execution.')).toBeVisible();
  await page.getByRole('button', { name: 'Create hunt from query' }).click();
  await expect(page).toHaveURL(/library_draft=session/);
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1071.001');
  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByLabel('Query language')).toHaveValue('yaral');
});
