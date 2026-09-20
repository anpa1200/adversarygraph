import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('second-layer summary uses a saved report, survives reload, and exports separately', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({ json: {
    auth_enabled: false, name: 'Test', roles: ['admin'], permissions: ['read', 'run_analysis', 'manage_intel', 'export_data'],
  } }));
  const report = { id: 'full-report-1', type: 'investigation-report', label: 'Full fixture report', content: '# Full report\n\nOriginal evidence.', created_at: '2026-09-20T00:00:00Z' };
  const workspace = { id: '11111111-1111-4111-8111-111111111111', name: 'Story fixture', description: '', domain: 'enterprise-attack', status: 'active', actor_ids: [], technique_ids: [], report_ids: [], evidence_nodes: [report], evidence_edges: [], timeline: [] };
  await page.route('**/api/operations/investigations', route => route.fulfill({ json: [workspace] }));
  await page.route('**/summaries/summary-1', route => route.fulfill({ json: { stale: false, status: 'snapshot-current' } }));
  let request: Record<string, unknown> | undefined;
  await page.route(`**/api/operations/investigations/${workspace.id}/summary`, async route => {
    request = route.request().postDataJSON();
    const summary = { id: 'summary-1', type: 'investigation-summary', label: 'Investigation summary — Tell the story',
      content: '# Investigation summary\n\n## What happened\n\nRepeated callbacks were reported. [S0001]\n\n## Unknowns\n\nInitial access is not established.',
      created_at: '2026-09-20T01:00:00Z', report_id: report.id, model: 'test-only', status: 'analyst-review-required' };
    workspace.evidence_nodes.push(summary);
    await route.fulfill({ json: summary });
  });
  await page.goto('/report');
  await expect(page.getByRole('button', { name: 'Tell the story', exact: true }).first()).toBeEnabled();
  await page.getByRole('button', { name: 'Tell the story', exact: true }).first().click();
  await expect.poll(() => request).toEqual({ report_id: report.id, provider: 'local' });
  await expect(page.getByText('Second-layer summary saved separately', { exact: false })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What happened', exact: true })).toBeVisible();
  expect(workspace.evidence_nodes[0].content).toBe(report.content);
  await page.reload();
  await expect(page.getByRole('option', { name: 'Investigation summary — Tell the story' })).toHaveCount(1);
  const summaryOption = page.getByRole('option', { name: 'Investigation summary — Tell the story' });
  await summaryOption.locator('..').selectOption('summary-1');
  await expect(page.getByRole('heading', { name: 'What happened', exact: true })).toBeVisible();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'MD', exact: true }).click();
  expect((await download).suggestedFilename()).toContain('.md');
});

test('no full report means no second-layer generation', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/operations/investigations', route => route.fulfill({ json: [] }));
  await page.goto('/report');
  await expect(page.getByRole('button', { name: 'Tell the story', exact: true }).first()).toBeDisabled();
  await expect(page.getByText('Save a full report first.', { exact: false })).toBeVisible();
});
