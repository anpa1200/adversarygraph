import { expect, test, type Page } from '@playwright/test';

const technique = {
  attack_id: 'T1595',
  name: 'Active Scanning',
  description: 'Probe public targets before an attack.',
  platforms: ['Linux', 'Windows', 'Network'],
  tactics: ['reconnaissance'],
  is_subtechnique: false,
  parent_attack_id: null,
};

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('discover workspace renders with mocked platform health', async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/discover');
  await expect(page.getByRole('heading', { name: 'Discover Intelligence' })).toBeVisible();
  await expect(page.getByText('Attack Simulation').first()).toBeVisible();
  await expect(page.getByText('CVE Library').first()).toBeVisible();

  const discoverScroll = page.getByTestId('discover-scroll-region');
  await expect(discoverScroll).toBeVisible();
  await expect.poll(async () => discoverScroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBeTruthy();
  await discoverScroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
  await expect.poll(async () => discoverScroll.evaluate(node => node.scrollTop > 0)).toBeTruthy();

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

async function mockApi(page: Page) {
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api/, '');
    const json = (body: unknown) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

    if (path === '/auth/status') {
      return json({
        auth_enabled: false,
        native_login_enabled: false,
        user_count: 1,
        bootstrap_configured: false,
        bootstrap_required: false,
        roles: ['viewer', 'analyst', 'admin'],
        permissions: ['read', 'run_attack_simulation', 'forward_siem'],
        role_permissions: {},
      });
    }
    if (path === '/auth/me') {
      return json({ auth_enabled: false, username: 'local', role: 'admin', permissions: ['read', 'run_attack_simulation', 'forward_siem'] });
    }
    if (path === '/system/selftest') {
      return json({
        status: 'ok',
        duration_ms: 12,
        checks: [{ name: 'database', status: 'ok', message: 'Database connection succeeded.' }],
      });
    }
    if (path === '/sync/status') {
      return json({
        enabled_sources: 0,
        degraded_sources: 0,
        total_indicators: 0,
        sources: [],
        cve_sources: [],
        cve_total_records: 1,
        cve_known_exploited: 0,
      });
    }
    if (path === '/apt/groups') return json([]);
    if (path === '/attack/tactics') {
      return json([{ attack_id: 'TA0043', shortname: 'reconnaissance', name: 'Reconnaissance' }]);
    }
    if (path === '/attack/techniques') return json([technique]);
    if (path === '/ioc/sources') return json([]);
    if (path === '/simulation/catalog') {
      return json([
        {
          id: 'sim-t1595-http-fingerprint',
          technique_id: 'T1595',
          name: 'HTTP/TLS service fingerprint plan',
          description: 'Fingerprint a lab web endpoint and collect validation telemetry.',
          category: 'reconnaissance',
          target_types: ['web', 'http'],
          risk_level: 0,
          steps: ['Send safe probe requests.'],
          expected_telemetry: ['access log', 'event_id=AG-WEB-1595'],
        },
      ]);
    }
    if (path === '/simulation/targets') {
      return json([
        {
          id: 'lab-web-01',
          name: 'Lab web server',
          address: 'http://attack-lab-web:8080',
          target_type: 'web',
          environment: 'lab',
          owner: 'AdversaryGraph',
          authorization: 'approved',
          allowed_simulations: ['sim-t1595-http-fingerprint'],
        },
      ]);
    }
    if (path === '/simulation/ai-assistant/scenarios') {
      return json([
        {
          id: 'apt29-identity-chain',
          name: 'APT29-style identity chain',
          difficulty: 'advanced',
          description: 'Identity, PowerShell, and exfiltration telemetry story.',
          technique_ids: ['T1595', 'T1110.001', 'T1078'],
          preconditions: ['SIEM collector configured.'],
          success_criteria: ['Correlated detections appear.'],
          telemetry_sources: ['windows_security', 'sysmon'],
          expected_detections: ['Password spray followed by valid login.'],
          tags: ['identity', 'endpoint'],
        },
      ]);
    }
    if (path === '/simulation/attack-flows') {
      return json([
        {
          id: 'flow-1',
          run_id: 'run-smoke-1',
          mode: 'challenge',
          ai_provider: 'local',
          ai_model: 'deterministic',
          ai_used: false,
          complicated_attack: true,
          actor_profile: 'apt29',
          scenario_id: 'apt29-identity-chain',
          scenario_name: 'APT29-style identity chain',
          summary: 'APT29-style identity chain',
          technique_ids: ['T1595', 'T1110.001', 'T1078'],
          event_count: 12,
          last_delivery_status: 200,
          last_delivery_ok: true,
          last_delivery_error: '',
          created_at: '2026-07-01T00:00:00Z',
          updated_at: '2026-07-01T00:00:00Z',
          attack_plan: { summary: 'APT29-style identity chain', kill_chain: [], validation_note: '' },
          events: [],
          delivery: {},
        },
      ]);
    }
    if (path === '/simulation/siem-destinations') return json([]);
    if (path === '/cve/sources') return json([]);
    if (path === '/cve/library') {
      return json({
        total: 1,
        limit: 100,
        offset: 0,
        items: [
          {
            id: 1,
            cve_id: 'CVE-2026-0001',
            source: 'nvd',
            description: 'Example CVE used for UI smoke coverage.',
            published: '2026-07-01',
            last_modified: '2026-07-01',
            vuln_status: 'Analyzed',
            cvss: { version: '3.1', score: '9.8', severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            cwe_ids: ['CWE-79'],
            cpe_matches: [],
            references: [],
            tags: [],
            known_exploited: false,
            kev_due_date: '',
            kev_required_action: '',
          },
        ],
      });
    }
    return json({});
  });
}
