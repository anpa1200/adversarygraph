import { expect, test, type Page } from '@playwright/test';

import { mockApi } from './support/mock-api';

const capture = process.env.CAPTURE_RELEASE_SCREENSHOTS === '1';
const outputDir = '../docs/assets/adversarygraph-v6';

test.describe('v6 release screenshots', () => {
  test.skip(!capture, 'Set CAPTURE_RELEASE_SCREENSHOTS=1 to create release assets.');
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1200 });
    await mockApi(page);
  });

  test('capture Discover workspace', async ({ page }) => {
    await page.goto('/discover');
    await expect(page.getByRole('heading', { name: 'Discover Intelligence' })).toBeVisible();
    await expect(page.getByText('Attack Simulation').first()).toBeVisible();
    await dismissTransientUi(page);
    await page.screenshot({ path: `${outputDir}/01-discover-workspace.png`, fullPage: true });
  });

  test('capture Attack Simulation matrix', async ({ page }) => {
    await page.goto('/attack-simulation');
    await expect(page.getByRole('heading', { name: 'Attack Simulation' })).toBeVisible();
    await expect(page.getByText('Attack Simulation available')).toBeVisible();
    await dismissTransientUi(page);
    await page.screenshot({ path: `${outputDir}/02-attack-simulation-matrix.png`, fullPage: true });
  });

  test('capture Attack Assistant and saved flow evidence', async ({ page }) => {
    await page.goto('/attack-simulation/sim-t1595-http-fingerprint#ai-attack-assistant');
    await expect(page.getByText('AI Attack Assistant')).toBeVisible();
    await expect(page.getByText('Previous Attack Flows')).toBeVisible();
    await expect(page.getByText('APT29-style identity chain').first()).toBeVisible();
    await dismissTransientUi(page);
    await page.screenshot({ path: `${outputDir}/03-attack-assistant-evidence.png`, fullPage: true });
  });

  test('capture CVE Library evidence review', async ({ page }) => {
    await page.goto('/cve');
    await expect(page.getByRole('heading', { name: 'CVE Library' })).toBeVisible();
    await expect(page.getByText('CVE-2026-0001')).toBeVisible();
    await dismissTransientUi(page);
    await page.screenshot({ path: `${outputDir}/04-cve-library.png`, fullPage: true });
  });
});

async function dismissTransientUi(page: Page) {
  const close = page.getByRole('button', { name: 'Dismiss self-test popup' });
  if (await close.waitFor({ state: 'visible', timeout: 5_000 }).then(() => true).catch(() => false)) {
    await close.evaluate(node => node.closest('.fixed')?.remove());
  }
}
