import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { buildNavigatorLayer } from '../../src/lib/navigatorLayer';
import { mockApi } from './support/mock-api';

for (const domain of ['enterprise-attack', 'mobile-attack', 'ics-attack']) {
  test(`${domain} v20 Navigator annotations survive JSON reopening`, () => {
    const source = { name: 'Reviewed layer', domain, metadata: [{ name: 'source', value: 'analyst' }], techniques: [
      { techniqueID: 'T9999', tactic: 'execution', score: 42, comment: 'execution evidence', enabled: true },
      { techniqueID: 'T9999', tactic: 'persistence', score: 17, comment: 'persistence evidence', enabled: true },
      { techniqueID: 'T9998', enabled: false, comment: 'historical annotation' },
    ] };
    const layer = buildNavigatorLayer(new Set(['T9999']), new Set(['T9997']), domain, '20.0', source);
    const reopened = JSON.parse(JSON.stringify(layer));
    expect(reopened.versions).toEqual({ attack: '20', navigator: '5.0', layer: '4.5' });
    expect(reopened.techniques.slice(0, 3)).toEqual(source.techniques);
    expect(reopened.metadata).toEqual(source.metadata);
    expect(reopened.techniques.filter((row: {techniqueID: string}) => row.techniqueID === 'T9997')).toHaveLength(1);
  });
}
test('ATLAS export keeps its independent version boundary', () => {
  expect(buildNavigatorLayer(new Set(['AML.T0001']), new Set(), 'atlas', 'abc123').versions).not.toHaveProperty('attack');
});

test('Navigator browser import and download preserve v20 source annotations', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/attack/versions', route => route.fulfill({ json: [{ domain: 'enterprise-attack', version: '20.0', is_latest: true }] }));
  await page.goto('/navigator');
  await page.getByTitle('Import an ATT&CK Navigator .json layer').click();
  const source = { name: 'Browser v20 layer', domain: 'enterprise-attack', versions: {attack: '20', layer: '4.5'}, techniques: [
    { techniqueID: 'T1595', tactic: 'reconnaissance', score: 73, comment: 'reviewed evidence', enabled: true },
  ] };
  await page.locator('input[type=file]').setInputFiles({ name: 'v20.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(source)) });
  await page.getByRole('button', { name: /^Import \(1\)$/ }).click();
  const downloadPromise = page.waitForEvent('download');
  await page.getByTitle('Export as ATT&CK Navigator JSON layer').click();
  const download = await downloadPromise;
  const saved = JSON.parse(await readFile((await download.path())!, 'utf8'));
  expect(saved.versions.attack).toBe('20');
  expect(saved.techniques).toEqual(source.techniques);
});
