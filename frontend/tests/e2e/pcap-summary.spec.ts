import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('focused PCAP summary requires consent and displays readable sourced report and actual model', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({ json: { auth_enabled: false, name: 'Test', roles: ['admin'], permissions: ['read', 'run_analysis', 'export_data'] } }));
  const id = '11111111-1111-4111-8111-111111111111';
  const claim = { text: 'A workstation downloaded a file; execution is not established.', basis: 'observed', evidence: [{ source_id: 'S0001', quote: 'A synthetic packet fact.', reference: '/api/pcap/analyses/fixture' }] };
  const summary = { analysis_id: id, filename: 'readable-test.pcap', model: 'provider-returned-snapshot', requested_model: 'configured-alias', provider_returned_model: 'provider-returned-snapshot', word_count: 22, prompt_version: 'pcap-investigation-summary-v1', created_at: '2026-09-22T00:00:00Z', capture_sha256: 'a'.repeat(64), content: '# Short report\n\nSynthetic test.', generation_seconds: 1, token_usage: { total_tokens: 100 }, coverage: {}, stale: false,
    structured: { what_happened: [claim], identities: [], iocs: [], ttps: [], uncertainties: [{ ...claim, text: 'Endpoint execution is not visible in these packets.' }], next_steps: [] } };
  let generated = false; let calls = 0;
  await page.route(`**/api/pcap/analyses/${id}/summary/preflight`, route => route.fulfill({ json: { analysis_id: id, filename: summary.filename, capture_sha256: summary.capture_sha256, source_sha256: 'b'.repeat(64), summary: generated ? summary : null,
    providers: [{ id: 'openai', label: 'OpenAI', remote: true, available: true, model: 'configured-alias' }] } }));
  await page.route(`**/api/pcap/analyses/${id}/summary`, async route => {
    calls++; generated = true;
    expect(route.request().postDataJSON()).toEqual({ provider: 'openai', cloud_processing_acknowledged: true, expected_source_sha256: 'b'.repeat(64) });
    await route.fulfill({ json: summary });
  });
  await page.goto(`/pcap/${id}/report`);
  const generate = page.getByRole('button', { name: 'Write investigation summary', exact: true });
  await expect(generate).toBeDisabled(); expect(calls).toBe(0);
  await expect(page.getByTestId('pcap-summary-empty')).toContainText('readable-test.pcap');
  await expect(page.getByTestId('pcap-summary-empty')).toContainText('not a clean-capture verdict');
  await page.getByRole('checkbox', { name: /I approve sending selected packet metadata/ }).check();
  await generate.click();
  const card = page.getByTestId('pcap-investigation-report');
  await expect(card).toBeVisible(); await expect(card).toHaveAttribute('data-analysis-id', id);
  await expect(card).toContainText('provider-returned-snapshot');
  await expect(card).not.toContainText('Packet behavior findings');
  const overflow = await card.evaluate(el => el.scrollWidth > el.clientWidth);
  expect(overflow).toBeFalsy(); expect(calls).toBe(1);
  await page.getByText('Evidence, coverage and model provenance', { exact: true }).click();
  await expect(page.getByText('A synthetic packet fact.', { exact: true }).first()).toBeVisible();
});
