import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('discover workspace renders with mocked platform health', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/discover');
  await expect(page.getByRole('heading', { name: 'Discover Intelligence' })).toBeVisible();
  await expect(page.getByText('Attack Simulation').first()).toBeVisible();
  await expect(page.getByText('CVE Library').first()).toBeVisible();

  const routeScroll = page.getByTestId('app-route-scroll');
  await expect(routeScroll).toBeVisible();
  await expect.poll(async () => routeScroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBeTruthy();

  const discoverScroll = page.getByTestId('discover-scroll-region');
  await expect(discoverScroll).toBeVisible();
  await routeScroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
  await expect.poll(async () => routeScroll.evaluate(node => node.scrollTop > 0)).toBeTruthy();
  await expect(page.getByText('Recent public intelligence')).toBeVisible();

  const sidebarScroll = page.getByTestId('sidebar-primary-nav');
  await expect(sidebarScroll).toBeVisible();
  await expect.poll(async () => sidebarScroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBeTruthy();
});

test('attack simulation matrix and saved-flow history render', async ({ page }) => {
  await page.goto('/attack-simulation');
  await expect(page.getByRole('heading', { name: 'Attack Simulation' })).toBeVisible();
  await expect(page.getByText('Choose a TTP from the ATT&CK matrix')).toBeVisible();
  await expect(page.getByText('Attack Simulation available')).toBeVisible();
  await page.goto('/attack-simulation/sim-t1595-http-fingerprint#ai-attack-assistant');
  await expect(page.getByText('AI Attack Assistant')).toBeVisible();
  await expect(page.getByText('Previous Attack Flows')).toBeVisible();
  await expect(page.getByText('APT29-style identity chain').first()).toBeVisible();
});

test('cve library renders searchable records', async ({ page }) => {
  await page.goto('/cve');
  await expect(page.getByRole('heading', { name: 'CVE Library' })).toBeVisible();
  await expect(page.getByText('Search CVE Library')).toBeVisible();
  await expect(page.getByText('CVE-2026-0001')).toBeVisible();
});
