import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('zero-TTP PCAP can save a report without promoting victim identities or dropping malicious hashes', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({ json: { auth_enabled: false, name: 'Test', roles: ['admin'], permissions: ['read', 'run_analysis', 'manage_intel', 'export_data'] } }));
  const hash = 'a'.repeat(64);
  const workspace = { id: '11111111-1111-4111-8111-111111111111', name: 'Zero TTP quality fixture', description: '', domain: 'enterprise-attack', status: 'active', tlp: 'TLP:AMBER+STRICT', actor_ids: [], technique_ids: [], report_ids: [], evidence_edges: [], timeline: [], evidence_nodes: [
    { id: 'user', type: 'identity', identity_type: 'account', value: 'matthew.jones', ip_addresses: ['10.0.0.8'] },
    { id: 'raw', type: 'log-pcap-analysis', observables: [{ type: 'domain', value: 'ordinary.invalid' }] },
    { id: 'file', type: 'file-artifact', sha256: hash, value: hash, size_bytes: 100, ioc_candidate: false },
    { id: 'ioc', type: 'pcap-observable', ioc_type: 'sha256', value: hash, ioc_candidate: true, description: 'Direct provider-reported-malicious exact hash; not proof of execution.', provider_signals: [{ source: 'fixture', verdict: 'provider-reported-malicious' }] },
  ] as Record<string, unknown>[] };
  await page.route('**/api/operations/investigations', route => route.fulfill({ json: [workspace] }));
  let saved: Record<string, any> | undefined;
  await page.route(`**/api/operations/investigations/${workspace.id}`, async route => {
    saved = route.request().postDataJSON();
    Object.assign(workspace, saved);
    await route.fulfill({ json: workspace });
  });
  await page.goto('/report');
  await page.getByRole('button', { name: 'Generate locally from selected sections', exact: true }).click();
  await expect.poll(() => saved).toBeTruthy();
  expect(saved).not.toHaveProperty('tlp');
  const report = saved?.evidence_nodes.find((n: Record<string, unknown>) => n.type === 'investigation-report').content;
  const iocs = report.split('### IOC List')[1].split('### Identities')[0];
  expect(iocs).toContain(hash);
  expect(iocs).not.toContain('matthew.jones');
  expect(iocs).not.toContain('ordinary.invalid');
  expect(report).toContain('matthew.jones');
  expect(report).toContain('provider-reported-malicious');
  await expect(page.getByRole('button', { name: 'Tell the story', exact: true }).first()).toBeEnabled();
});
