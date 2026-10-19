import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

const investigation = {
  schema_version: 'cti-investigation-v1', status: 'partial', created_at: '2026-10-14T08:00:00Z',
  report: '## Attack sequence\nThe source reports PowerShell execution [S002]. Attribution remains unknown.',
  sources: [{ id: 'S002', title: 'Vendor incident report', url: 'https://vendor.example/blog/report', sha256: 'a'.repeat(64), included_sha256: 'a'.repeat(64), original_chars: 5000, included_chars: 5000, retrieved_at: '2026-10-14T08:00:00Z' }],
  stages: { acquisition: { status: 'complete' }, extraction: { status: 'complete', analyzed_chars: 5000, source_chars: 5000 }, enrichment: { status: 'complete' }, registration: { status: 'skipped' }, review: { status: 'pending' } },
  indicators: [{ value: 'evil.example', indicator_type: 'domain', role: 'candidate', confidence: 50,
    evidence: [{ source_id: 'S002', start: 10, end: 22, excerpt: 'Observed evil[.]example in the vendor report.', source_url: 'https://vendor.example/blog/report' }],
    enrichment: { status: 'no_match', queried_at: '2026-10-14T08:00:00Z', matches: [] } }],
  warnings: ['One reference could not be retrieved.'], limitations: ['No match means unknown, not benign.'],
};
const result = { session_id: 'cti-investigation-test', provider: 'openai', model: 'gpt-4.1', summary: 'Source reports PowerShell execution.', techniques: [], apt_matches: [], apt_hints: [], investigation };

test.beforeEach(async ({ page }) => {
  page.on('pageerror', error => console.error('UI error:', error.message));
  await mockApi(page);
  await page.route('**/api/analyze/sessions?*', route => route.fulfill({status: 200, contentType: 'application/json', body: '[]'}));
});

test('defaults to deep investigation and displays source-bound IOCs, gaps and enrichment', async ({ page }) => {
  let body = '';
  await page.route('**/api/analyze/investigate/stream', async route => {
    body = route.request().postData() || '';
    await route.fulfill({ status: 200, contentType: 'text/event-stream', body:
      `data: ${JSON.stringify({ type: 'progress', stage: 'acquisition', message: 'Retrieving report' })}\n\n` +
      `data: ${JSON.stringify({ type: 'result', data: result })}\n\n` });
  });
  await page.goto('/analyze');
  await expect(page.getByLabel('Deep CTI investigation', { exact: true })).toBeChecked();
  await page.getByText('Sources and enrichment options', { exact: true }).click();
  await page.getByLabel('Passive threat intelligence lookups', { exact: true }).check();
  await page.getByPlaceholder('Paste incident report, investigation notes, IOC list, threat intel blog…').fill('Assignment referring to https://vendor.example/blog/report');
  await page.getByRole('button', { name: /Analyse with AI/i }).click();
  await expect(page.getByRole('heading', { name: 'Technical investigation', exact: true })).toBeVisible();
  await expect(page.getByText('One reference could not be retrieved.', { exact: true })).toBeVisible();
  await expect(page.getByText('[S002] Vendor incident report', { exact: true })).toBeVisible();
  await expect(page.getByText('evil.example', { exact: true })).toBeVisible();
  await expect(page.getByText('review: pending', { exact: true })).toBeVisible();
  await page.getByText('evil.example', { exact: true }).click();
  await expect(page.getByText('[S002] Observed evil[.]example in the vendor report.', { exact: true })).toBeVisible();
  expect(body).toContain('name="follow_references"');
  expect(body).toContain('name="external_enrichment"');
  await expect(page.getByRole('button', { name: 'Download evidence JSON' })).toBeVisible();
});

test('quick mapping remains available without reference acquisition options', async ({ page }) => {
  await page.goto('/analyze');
  await page.getByLabel('Deep CTI investigation', { exact: true }).uncheck();
  await expect(page.getByLabel('Retrieve up to 3 public report links')).toHaveCount(0);
  await expect(page.getByLabel('Reference report URLs')).toHaveCount(0);
});

test('loads an existing source for deep investigation without automatically submitting it', async ({ page }) => {
  const id = '424a3785-27f5-41ea-8421-d560e6321e97';
  const source = 'Stored original report source with campaign evidence.';
  let submissions = 0;
  await page.route(`**/api/analyze/sessions/${id}/linked-report`, route => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({source_text: source})}));
  await page.route('**/api/analyze/investigate/stream', route => { submissions++; return route.abort(); });
  await page.goto(`/analyze?source_session=${id}`);
  await expect(page.getByPlaceholder('Paste incident report, investigation notes, IOC list, threat intel blog…')).toHaveValue(source);
  await expect(page.getByLabel('Deep CTI investigation', { exact: true })).toBeChecked();
  expect(submissions).toBe(0);
});
