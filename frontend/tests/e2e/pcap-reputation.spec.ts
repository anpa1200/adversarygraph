import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('PCAP enrichment requires explicit selection and consent and refreshes the report', async ({ page }, testInfo) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({ json: { auth_enabled: false, name: 'Test analyst', roles: ['admin'], permissions: ['read', 'run_analysis', 'export_data', 'upload_files'] } }));
  await page.route('**/api/analyze/sessions?**', route => route.fulfill({ json: [] }));
  const id = '11111111-1111-4111-8111-111111111111';
  const hash = 'b'.repeat(64);
  const fixture = {
    analysis_id: id, session_id: '22222222-2222-4222-8222-222222222222', status: 'completed', filename: 'safe-control.pcap',
    source_tlp: 'TLP:CLEAR', artifact_download_available: true, semantic_sha256: 'a'.repeat(64),
    analyzer_manifest: { profile_id: 'synthetic-test' }, summary: 'Synthetic control, not an incident.', report: 'Initial report', techniques: [], apt_matches: [],
    assessment: { policy_version: 'pcap-assessment-v1', assessment_sha256: hash, counts: { observed: 2 }, ioc_candidate_count: 0, summary: '2 observations; no IOC candidates.', limitations: [],
      items: [
        { observable_id: 'hash1', type: 'sha256', value: hash, roles: ['exported-object'], classification: 'observed', ioc_candidate: false, enrichment_eligible: true, enrichment_status: 'not-requested', reasons: [], signals: [] },
        { observable_id: 'resolver', type: 'ipv4', value: '8.8.8.8', roles: ['network-endpoint'], classification: 'observed', ioc_candidate: false, enrichment_eligible: true, enrichment_status: 'not-requested', reasons: [], signals: [] },
      ] },
    result: { semantic_sha256: 'a'.repeat(64), capture: { source_sha256: hash, packet_count: 12, duration_seconds: 1 }, endpoints: [], flows: [], identities: [], findings: [], attack_candidates: [], coverage: {},
      artifacts: [{ artifact_id: 'artifact1', filename: 'control.bin', sha256: hash, size_bytes: 4, evidence: [] }],
      observables: [{ observable_id: 'hash1', type: 'sha256', value: hash, roles: ['exported-object'], evidence: [] }, { observable_id: 'resolver', type: 'ipv4', value: '8.8.8.8', roles: ['network-endpoint'], evidence: [] }] },
  };
  await page.route('**/api/pcap/analyses?**', route => route.fulfill({ json: { items: [{ ...fixture, finding_count: 0, observable_count: 2, technique_count: 0 }], limit: 50, offset: 0 } }));
  await page.route(`**/api/pcap/analyses/${id}`, route => route.fulfill({ json: fixture }));
  let requests = 0;
  await page.route(`**/api/pcap/analyses/${id}/enrich`, async route => {
    requests++;
    expect(route.request().postDataJSON()).toEqual({ observable_ids: ['hash1'], providers: ['virustotal', 'threatfox', 'malwarebazaar'], consent: true });
    await route.fulfill({ json: { ...fixture, report: 'Updated report: direct provider match, not proof of execution.', assessment: { ...fixture.assessment, ioc_candidate_count: 1,
      summary: '1 provider-reported malicious candidate, requiring analyst review.', items: [{ ...fixture.assessment.items[0], classification: 'provider-reported-malicious', ioc_candidate: true, enrichment_status: 'checked', signals: [{ source: 'virustotal', status: 'ok', verdict: 'provider-reported-malicious', basis: '8 malicious engine reports', queried_at: '2026-09-22T00:00:00Z' }] }, fixture.assessment.items[1]] } } });
  });
  await page.route(`**/api/pcap/analyses/${id}/artifacts/artifact1/download`, route => route.fulfill({ body: 'test', contentType: 'application/octet-stream' }));
  await page.goto('/analyze');
  await page.getByRole('button', { name: 'Log / PCAP', exact: true }).click();
  await page.getByRole('button', { name: /safe-control.pcap/ }).click();
  await expect(page.getByRole('heading', { name: 'IOC candidates for review (0)' })).toBeVisible();
  expect(requests).toBe(0);
  const enrich = page.getByRole('button', { name: 'Enrich selected targets', exact: true });
  await expect(enrich).toBeDisabled();
  await page.getByRole('checkbox', { name: `Select ${hash}`, exact: true }).check();
  await expect(enrich).toBeDisabled();
  await page.getByRole('checkbox', { name: /I reviewed the 1 selected targets/ }).check();
  await enrich.click();
  await expect(page.getByText('Updated report: direct provider match, not proof of execution.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'IOC candidates for review (1)' })).toBeVisible();
  expect(requests).toBe(1);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download verified bytes' }).click();
  expect((await download).suggestedFilename()).toBe(`${hash}.bin`);
  const closeNotice = page.getByRole('button', { name: 'Close', exact: true });
  if (await closeNotice.isVisible()) await closeNotice.click();
  await page.getByRole('heading', { name: 'Evidence-backed IOC assessment', exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: testInfo.outputPath('pcap-evidence-assessment.png'), fullPage: true });
});
