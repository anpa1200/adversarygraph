import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

const linkedSessionId = '33333333-3333-4333-8333-333333333333';

const mutableIntake = {
  id: '44444444-4444-4444-8444-444444444444',
  analysis_session_id: null,
  title: 'Standalone source intake',
  url: 'https://example.test/report',
  publisher: 'Example Research',
  status: 'pending',
  summary: 'A source awaiting analyst review.',
  source_reliability: 'unknown',
  actor_ids: ['G0001'],
  technique_ids: ['T1059.001'],
  indicators: [{ type: 'domain', value: 'example.test' }],
  analyst_notes: 'Verify publication metadata.',
  tags: ['server-managed'],
  provenance: { ingestion: 'operations' },
  asset_retrohunt: { status: 'deferred' },
  created_at: '2026-08-20T08:00:00Z',
  updated_at: '2026-08-20T08:00:00Z',
};

const linkedIntake = {
  ...mutableIntake,
  id: '55555555-5555-4555-8555-555555555555',
  analysis_session_id: linkedSessionId,
  title: 'Linked analyzed report',
  status: 'promoted',
  provenance: { analysis_session_id: linkedSessionId },
};

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('uses the IntakeBody PUT contract and keeps linked analysis intake read-only', async ({ page }) => {
  let updatePayload: Record<string, unknown> | undefined;

  await page.route('**/api/operations/investigations', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([]),
  }));
  await page.route('**/api/operations/intake', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify([mutableIntake, linkedIntake]),
  }));
  await page.route(`**/api/operations/intake/${mutableIntake.id}`, async route => {
    updatePayload = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ...mutableIntake, ...updatePayload }),
    });
  });

  await page.goto('/operations');
  await page.getByRole('button', { name: 'intake' }).click();

  const mutablePanel = page.locator('section').filter({ has: page.getByRole('heading', { name: mutableIntake.title }) });
  const linkedPanel = page.locator('section').filter({ has: page.getByRole('heading', { name: linkedIntake.title }) });
  const statusSelect = mutablePanel.getByLabel('Status');

  await expect(statusSelect.locator('option')).toHaveText([
    'pending',
    'stored',
    'analyzed',
    'under review',
    'reviewed',
    'rejected',
    'revoked',
  ]);
  await statusSelect.selectOption('under_review');

  await expect.poll(() => updatePayload?.status).toBe('under_review');
  expect(Object.keys(updatePayload ?? {}).sort()).toEqual([
    'actor_ids',
    'analyst_notes',
    'indicators',
    'publisher',
    'source_reliability',
    'status',
    'summary',
    'technique_ids',
    'title',
    'url',
  ]);
  expect(updatePayload).not.toHaveProperty('analysis_session_id');
  expect(updatePayload).not.toHaveProperty('asset_retrohunt');
  expect(updatePayload).not.toHaveProperty('provenance');
  expect(updatePayload).not.toHaveProperty('tags');

  await expect(linkedPanel.getByText(/cannot be edited or deleted from Operations/)).toBeVisible();
  await expect(linkedPanel.getByRole('combobox')).toHaveCount(0);
  await expect(linkedPanel.getByRole('button', { name: /delete/i })).toHaveCount(0);
  await expect(linkedPanel.getByRole('link', { name: 'Open linked report' })).toHaveAttribute('href', `/analyze/${linkedSessionId}/report`);
});
