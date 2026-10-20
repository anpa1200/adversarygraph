import { expect, test, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { mockApi } from './support/mock-api';

async function catalog(page: Page) {
  await mockApi(page);
  const wrongRequests: string[] = [];
  await page.route('**/api/cve/related/technique/**', route => route.fulfill({ json: [] }));
  await page.route('**/api/attack/**', async route => {
    const url = new URL(route.request().url());
    const domain = url.searchParams.get('domain') ?? 'enterprise-attack';
    const ics = domain === 'ics-attack';
    const row = { attack_id: ics ? 'T1701' : 'T1699', name: ics ? 'Execution through API' : 'Direct Prompt Injection',
      tactics: ['execution'], platforms: ics ? ['Windows'] : ['Linux'], domain, is_subtechnique: false, parent_attack_id: null,
      description: 'Official catalog test technique', data_sources: [], detection: '', stix_id: 'attack-pattern--test' };
    let json: unknown;
    if (url.pathname.endsWith('/versions')) json = ['enterprise-attack', 'ics-attack'].map(domain => ({ domain, version: '20.0', is_latest: true }));
    else if (url.pathname.endsWith('/tactics')) json = [{ attack_id: ics ? 'TA0104' : 'TA0002', shortname: 'execution', name: 'Execution', domain }];
    else if (url.pathname.endsWith('/techniques')) json = [row];
    else {
      if (!url.pathname.endsWith('/' + row.attack_id)) {
        wrongRequests.push(url.toString());
        return route.fulfill({ status: 404, json: { detail: 'Technique not found' } });
      }
      json = row;
    }
    return route.fulfill({ json });
  });
  return wrongRequests;
}

test('domain switch never requests the previous technique in ICS and restores selections and annotations', async ({ page }) => {
  const wrongRequests = await catalog(page);
  await page.goto('/navigator');
  await page.getByPlaceholder('Search techniques… (name or ID)').fill('T1699');
  await page.getByText('T1699', { exact: true }).first().click();
  await expect(page.getByText('Direct Prompt Injection', { exact: true }).last()).toBeVisible();
  await page.locator('select').first().selectOption('Linux');
  await page.getByTitle('Import an ATT&CK Navigator .json layer').click();
  const source = { name: 'Reviewed', domain: 'enterprise-attack', techniques: [{ techniqueID: 'T1699', tactic: 'execution', score: 73, comment: 'Preserve this evidence', enabled: true }] };
  await page.locator('input[type=file]').setInputFiles({ name: 'reviewed.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(source)) });
  await page.getByRole('button', { name: /^Import \(1\)$/ }).click();
  await page.locator('header').getByRole('button', { name: 'ICS', exact: true }).click();
  await expect(page.getByText('T1701', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('T1699', { exact: true })).toHaveCount(0);
  await expect(page.getByPlaceholder('Search techniques… (name or ID)')).toHaveValue('');
  await expect(page.locator('select').first()).toHaveValue('');
  await expect(page.getByText('1 TTPs selected', { exact: true })).toHaveCount(0);
  await page.getByText('T1701', { exact: true }).first().click();
  await page.locator('header').getByRole('button', { name: 'Enterprise', exact: true }).click();
  await expect(page.getByText('1 TTPs selected', { exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByTitle('Export as ATT&CK Navigator JSON layer').click();
  const download = await downloadPromise;
  const exported = JSON.parse(await readFile((await download.path())!, 'utf8'));
  expect(exported.domain).toBe('enterprise-attack');
  expect(exported.techniques).toEqual(source.techniques);
  expect(wrongRequests).toEqual([]);
});

test('domain and version in a technique deep link select the correct catalog', async ({ page, context }) => {
  const wrongRequests = await catalog(page);
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/navigator?technique=T1701&domain=ics-attack&version=20.0');
  await expect(page.getByText('Execution through API', { exact: true }).last()).toBeVisible();
  await page.getByRole('button', { name: 'Link', exact: true }).click();
  const link = new URL(await page.evaluate(() => navigator.clipboard.readText()));
  expect(link.searchParams.get('domain')).toBe('ics-attack');
  expect(link.searchParams.get('version')).toBe('20.0');
  expect(link.searchParams.get('technique')).toBe('T1701');
  expect(wrongRequests).toEqual([]);
});
