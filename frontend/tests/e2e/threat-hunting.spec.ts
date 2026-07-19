import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('threat hunting dashboard exposes metrics, queue, templates, and scope boundary', async ({ page }) => {
  await page.goto('/threat-hunting');

  await expect(page.getByRole('heading', { name: 'Threat Hunting', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Turn intelligence leads into reviewable threat hunts.' })).toBeVisible();
  await expect(page.getByText('AdversaryGraph manages the hunt record; queries run only in your approved telemetry tools.')).toBeVisible();
  await expect(page.getByText('Awaiting review')).toBeVisible();
  await expect(page.getByText('Suspicious encoded PowerShell execution').first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'Threat Hunting' })).toBeVisible();

  await page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).last().click();
  await expect(page).toHaveURL(/\/threat-hunting\/new\?template=powershell-encoded-execution/);
  await expect(page.getByLabel('Hunt title')).toHaveValue('Suspicious encoded PowerShell execution');
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001, T1027');

  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/threat-hunting\/hunt-new$/);
  await expect(page.getByText('draft', { exact: true }).first()).toBeVisible();
});

test('hunt workspace supports query copy, finding review, outcome, lifecycle, and archive', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/threat-hunting/hunt-1');

  await expect(page.getByRole('heading', { name: 'Suspicious encoded PowerShell execution' })).toBeVisible();
  await expect(page.getByText('It does not execute queries against a SIEM or endpoint platform.')).toBeVisible();

  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByText('Query syntax and field names must be validated in the destination platform.')).toBeVisible();
  await expect(page.getByText('Append-only query history')).toBeVisible();
  await expect(page.getByText(/sha256:64b9d5f2f4c1/)).toBeVisible();
  await page.getByRole('button', { name: 'Copy query' }).click();
  await expect(page.getByRole('button', { name: 'Query copied' })).toBeVisible();

  await page.getByRole('tab', { name: /Findings/ }).click();
  await expect(page.getByText('Encoded PowerShell spawned by spreadsheet process')).toBeVisible();
  await page.getByRole('button', { name: 'Add finding' }).click();
  await page.getByLabel('Finding title').fill('Rare child process on host-02');
  await page.getByLabel('Summary').fill('A second endpoint showed related command-line behavior during the scoped period.');
  await page.getByRole('button', { name: 'Save finding' }).click();
  await expect(page.getByText('Rare child process on host-02')).toBeVisible();
  await expect(page.getByText('query v1').last()).toBeVisible();
  await page.getByLabel('Status for Rare child process on host-02').selectOption('reviewed');

  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await page.getByLabel('Reviewed disposition').selectOption('telemetry_gap');
  await page.getByLabel('Result summary').fill('The scoped query returned relevant events, but missing endpoint coverage prevents a complete conclusion.');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await page.getByRole('button', { name: 'Complete hunt' }).click();
  await expect(page.getByText('completed', { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel('Reviewed disposition')).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);

  await page.getByRole('button', { name: 'Archive hunt' }).click();
  await page.getByRole('button', { name: 'Confirm' }).click();
  await expect(page.getByText('archived', { exact: true }).first()).toBeVisible();
});

test('navigator deep link preloads ATT&CK and source context without claiming execution', async ({ page }) => {
  await page.goto('/threat-hunting/new?technique=T1059.001&source=navigator&source_ref=T1059.001');

  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001');
  await expect(page.getByLabel('Creation source')).toHaveValue('manual');
  await expect(page.getByLabel('Tags')).toHaveValue('context:navigator, context-ref:T1059.001');
  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByRole('button', { name: 'Copy query' })).toBeDisabled();
  await expect(page.getByText('AdversaryGraph does not claim this query was executed.')).toBeVisible();
});

test('does not request hunt data until analyst access is resolved', async ({ page }) => {
  let releaseAuth: () => void = () => undefined;
  const authBarrier = new Promise<void>(resolve => {
    releaseAuth = resolve;
  });
  let huntRequests = 0;

  await page.route('**/api/auth/status', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ auth_enabled: true, native_login_enabled: true, user_count: 1, bootstrap_configured: false, bootstrap_required: false }),
  }));
  await page.route('**/api/auth/me', async route => {
    await authBarrier;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ auth_enabled: true, name: 'Authorized Analyst', roles: ['analyst'], permissions: ['read', 'run_analysis'] }),
    });
  });
  await page.route('**/api/threat-hunting/**', async route => {
    huntRequests += 1;
    await route.fallback();
  });

  await page.goto('/threat-hunting');
  await expect(page.getByText('Verifying your session…')).toBeVisible();
  expect(huntRequests).toBe(0);

  releaseAuth();
  await expect(page.getByRole('heading', { name: 'Turn intelligence leads into reviewable threat hunts.' })).toBeVisible();
  await expect.poll(() => huntRequests).toBeGreaterThan(0);
});

test('explicit run_analysis permission opens hunts without an analyst role', async ({ page }) => {
  await page.route('**/api/auth/status', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ auth_enabled: true, native_login_enabled: true, user_count: 1, bootstrap_configured: false, bootstrap_required: false }),
  }));
  await page.route('**/api/auth/me', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ auth_enabled: true, name: 'Custom Hunt User', roles: ['viewer'], permissions: ['read', 'run_analysis'] }),
  }));

  await page.goto('/threat-hunting');
  await expect(page.getByRole('heading', { name: 'Turn intelligence leads into reviewable threat hunts.' })).toBeVisible();
  await expect(page.getByText('Access unavailable')).toHaveCount(0);
});

test('failed terminal transition keeps the hunt editable and server-confirmed', async ({ page }) => {
  let rejectNextPatch = true;
  await page.route('**/api/threat-hunting/hunts/hunt-1', async route => {
    if (route.request().method() === 'PATCH' && rejectNextPatch) {
      rejectNextPatch = false;
      await route.fulfill({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Concurrent review prevented completion' }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await page.getByLabel('Reviewed disposition').selectOption('suspicious');
  await page.getByLabel('Result summary').fill('Reviewed evidence supports escalation, but the server must remain authoritative for completion.');
  await page.getByRole('button', { name: 'Complete hunt' }).click();

  await expect(page.getByRole('alert')).toContainText('Concurrent review prevented completion');
  await expect(page.getByText('review', { exact: true }).first()).toBeVisible();
  await expect(page.getByLabel('Reviewed disposition')).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeVisible();
});

test('finding input survives API failure, then supports correction and archive', async ({ page }) => {
  let rejectNextCreate = true;
  await page.route('**/api/threat-hunting/hunts/hunt-1/findings', async route => {
    if (route.request().method() === 'POST' && rejectNextCreate) {
      rejectNextCreate = false;
      await route.fulfill({
        status: 422,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Evidence reference failed server validation' }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: /Findings/ }).click();
  await page.getByRole('button', { name: 'Add finding' }).click();
  await page.getByLabel('Finding title').fill('Finding retained across failure');
  await page.getByLabel('Summary').fill('This analyst-entered evidence must remain available after an API rejection.');
  await page.getByRole('button', { name: 'Save finding' }).click();

  await expect(page.getByRole('alert')).toContainText('Evidence reference failed server validation');
  await expect(page.getByLabel('Finding title')).toHaveValue('Finding retained across failure');
  await expect(page.getByRole('button', { name: 'Save finding' })).toBeVisible();

  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('Discard unsaved finding changes');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: 'Close form' }).click();
  await expect(page.getByLabel('Finding title')).toHaveValue('Finding retained across failure');
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Close form' }).click();
  await page.getByRole('button', { name: 'Edit finding' }).click();
  await page.getByLabel('Summary').fill('Peer review established a benign explanation for the observed process chain.');
  await page.getByLabel('Finding verdict').selectOption('benign');
  await page.getByRole('button', { name: 'Save corrections' }).click();
  await expect(page.getByText('Peer review established a benign explanation for the observed process chain.')).toBeVisible();
  await expect(page.getByText('Benign explanation', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Archive finding' }).click();
  await page.getByRole('button', { name: 'Confirm archive' }).click();
  await expect(page.getByText('Encoded PowerShell spawned by spreadsheet process')).toHaveCount(0);
});

test('classification and lifecycle controls expose only backend-valid actions', async ({ page }) => {
  await page.goto('/threat-hunting/hunt-1');

  await expect(page.getByLabel('TLP').locator('option')).toHaveText(['TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED']);
  await expect(page.getByRole('button', { name: 'Return to running' })).toBeVisible();
  await page.getByRole('button', { name: 'Return to running' }).click();
  await expect(page.getByText('running', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send to review' })).toBeVisible();
});

test('hunt queue can be opened with the keyboard', async ({ page }) => {
  await page.goto('/threat-hunting');

  const huntButton = page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).first();
  await huntButton.focus();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/threat-hunting\/hunt-1$/);
});

test('stored research generates a reviewable hypothesis without creating a hunt', async ({ page }) => {
  const sourceSessionId = '11111111-1111-4111-8111-111111111111';
  let createRequests = 0;
  let createdBody: Record<string, unknown> | null = null;
  let hypothesisBody: Record<string, unknown> | null = null;
  await page.route('**/api/threat-hunting/hunts', async route => {
    if (route.request().method() === 'POST') {
      createRequests += 1;
      createdBody = route.request().postDataJSON();
    }
    await route.fallback();
  });
  await page.route('**/api/threat-hunting/ai/hypotheses', async route => {
    if (route.request().method() === 'POST') hypothesisBody = route.request().postDataJSON();
    await route.fallback();
  });

  await page.goto(`/threat-hunting/new?assistant=hypothesis&source=report&source_session_id=${sourceSessionId}&source_ref=${sourceSessionId}`);

  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByText('AI Assistant · Report-to-hypothesis')).toBeVisible();
  await expect(page.getByLabel('Hypothesis source report')).toHaveValue(sourceSessionId);
  await expect(page.getByLabel('Selected report TLP')).toContainText('TLP:AMBER+STRICT');
  await expect(page.getByText('Selected report is TLP:AMBER+STRICT and is local-only. Remote providers are unavailable for this request.')).toBeVisible();
  await expect(page.getByLabel('Threat hunting AI provider').locator('option[value="openai"]')).toHaveAttribute('disabled', '');
  await expect(page.getByLabel('Hypothesis source report').locator('option', { hasText: 'Unparsed ATLAS research note' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Generate hunt hypotheses' }).click();
  await expect.poll(() => hypothesisBody?.tlp).toBe('TLP:AMBER+STRICT');
  await expect(page.getByRole('heading', { name: 'Suspicious federation trust modification' })).toBeVisible();
  await expect(page.getByText('No telemetry query was executed and no hunt record was created.')).toBeVisible();
  await expect(page.getByText('The actor modified federation trust settings before accessing cloud mailboxes.')).toBeVisible();

  await page.getByRole('button', { name: 'Apply safe fields' }).click();
  expect(createRequests).toBe(0);
  await page.getByRole('button', { name: 'Close' }).click();

  await expect(page.getByLabel('Hunt title')).toHaveValue('Suspicious federation trust modification');
  await expect(page.getByLabel('Hypothesis')).toContainText('If an adversary modified identity federation trust');
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1098, T1078');
  await expect(page.getByLabel('TLP')).toHaveValue('TLP:AMBER');
  expect(createRequests).toBe(0);

  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect.poll(() => createRequests).toBe(1);
  expect(createdBody?.tags).toEqual(expect.arrayContaining([
    'context:report',
    `context-ref:${sourceSessionId}`,
    'ai-assistance:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  ]));
});

test('eligible report collection and linked-report views expose the AI hypothesis handoff', async ({ page }) => {
  const sourceSessionId = '11111111-1111-4111-8111-111111111111';
  await page.goto('/reports-research');

  const collectionCta = page.getByRole('link', { name: 'Create AI hunt hypothesis' });
  await expect(collectionCta).toHaveCount(1);
  await expect(collectionCta).toHaveAttribute('href', new RegExp(`source_session_id=${sourceSessionId}`));
  await page.locator(`a[href="/analyze/${sourceSessionId}/report"]`, { hasText: 'Open linked report' }).click();

  await expect(page).toHaveURL(new RegExp(`/analyze/${sourceSessionId}/report$`));
  const linkedReportCta = page.getByRole('link', { name: 'Create AI hunt hypothesis' });
  await expect(linkedReportCta).toBeVisible();
  await expect(linkedReportCta).toHaveAttribute('href', new RegExp(`source_session_id=${sourceSessionId}`));
});

test('plan assistance merges safe arrays but does not overwrite or auto-save hunt fields', async ({ page }) => {
  let patchRequests = 0;
  await page.route('**/api/threat-hunting/hunts/hunt-1', async route => {
    if (route.request().method() === 'PATCH') patchRequests += 1;
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('button', { name: 'AI assist plan and scope' }).click();
  await page.getByRole('button', { name: 'Assist with plan and scope' }).click();
  await expect(page.getByText('AI suggestions for the plan stage are ready for analyst review.')).toBeVisible();
  await page.getByRole('button', { name: 'Apply safe suggestions' }).click();
  await expect(page.getByText('Suggestions added to the unsaved hunt draft.')).toBeVisible();
  expect(patchRequests).toBe(0);
  await page.getByRole('button', { name: 'Close' }).click();

  await expect(page.getByLabel('Hunt title')).toHaveValue('Suspicious encoded PowerShell execution');
  await expect(page.getByRole('textbox', { name: 'Scope', exact: true })).toHaveValue('Managed Windows endpoints in the finance segment during the last seven days.');
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001, T1027, T1078');
  expect(patchRequests).toBe(0);

  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect.poll(() => patchRequests).toBe(1);
});

test('query assistance preserves existing query text, merges telemetry, and never claims execution', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  let patchRequests = 0;
  await page.route('**/api/threat-hunting/hunts/hunt-1', async route => {
    if (route.request().method() === 'PATCH') patchRequests += 1;
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: 'Query and telemetry' }).click();
  await expect(page.getByText('AdversaryGraph does not claim this query was executed.')).toBeVisible();
  await page.getByRole('button', { name: 'AI assist query' }).click();
  await page.getByRole('button', { name: 'Assist with query and telemetry' }).click();
  await expect(page.getByText('No telemetry query was executed and no hunt or finding record was changed.')).toBeVisible();
  await page.getByRole('button', { name: 'Apply safe suggestions' }).click();
  expect(patchRequests).toBe(0);
  await page.getByRole('button', { name: 'Close' }).click();

  await expect(page.getByLabel('Query language')).toHaveValue('kql');
  await expect(page.getByLabel('Telemetry sources')).toHaveValue('Process creation, PowerShell Script Block Logging, Identity provider audit logs');
  await expect(page.getByLabel('Required fields')).toHaveValue('@timestamp, host.name, process.command_line, operation.name, actor.id, source.ip');
  await page.getByRole('button', { name: 'Copy query' }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('process.name : "powershell.exe"');
  expect(patchRequests).toBe(0);

  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect.poll(() => patchRequests).toBe(1);
});

test('findings and outcome assistance remain editable and cannot auto-review or complete', async ({ page }) => {
  let findingCreates = 0;
  let huntPatches = 0;
  await page.route('**/api/threat-hunting/hunts/hunt-1/findings', async route => {
    if (route.request().method() === 'POST') findingCreates += 1;
    await route.fallback();
  });
  await page.route('**/api/threat-hunting/hunts/hunt-1', async route => {
    if (route.request().method() === 'PATCH') huntPatches += 1;
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('tab', { name: /Findings/ }).click();
  await page.getByRole('button', { name: 'AI assist findings' }).click();
  await page.getByRole('button', { name: 'Assist with findings review' }).click();
  await page.getByRole('button', { name: 'Apply safe suggestions' }).click();
  await page.getByRole('button', { name: 'Open editable draft' }).click();

  await expect(page.getByLabel('Finding title')).toHaveValue('Federation trust update requires validation');
  await expect(page.getByLabel('Finding status')).toHaveValue('new');
  await expect(page.getByLabel('Finding verdict')).toHaveValue('inconclusive');
  await expect(page.getByLabel('Finding TLP')).toHaveValue('TLP:AMBER');
  await expect(page.getByLabel('Finding evidence type')).toHaveValue('analysis');
  await expect(page.getByLabel('Finding evidence reference')).toHaveValue('');
  await expect(page.getByLabel('Finding event time')).toHaveValue('');
  await expect(page.getByLabel('Finding observables')).toHaveValue('');
  expect(findingCreates).toBe(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Close form' }).click();

  await page.getByRole('tab', { name: 'Plan and scope' }).click();
  await expect(page.getByLabel('ATT&CK techniques')).toHaveValue('T1059.001, T1027');
  await expect(page.getByLabel('Tags')).toHaveValue('endpoint, powershell');

  await page.getByRole('tab', { name: 'Outcome and handoff' }).click();
  await page.getByRole('button', { name: 'AI assist outcome and handoff' }).click();
  await page.getByRole('button', { name: 'Assist with outcome and handoff' }).click();
  await page.getByRole('button', { name: 'Apply safe suggestions' }).click();
  await page.getByRole('button', { name: 'Close' }).click();

  await expect(page.getByLabel('Result summary')).toContainText('remaining gaps in historical sign-in retention');
  await expect(page.getByLabel('Reviewed disposition')).toHaveValue('undetermined');
  await expect(page.getByText('review', { exact: true }).first()).toBeVisible();
  expect(huntPatches).toBe(0);
});

test('remote AI requires acknowledgment and restrictive TLP remains local-only', async ({ page }) => {
  await page.route('**/api/analyze/sessions/collection**', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      total: 1,
      limit: 50,
      offset: 0,
      items: [{
        session_id: '11111111-1111-4111-8111-111111111111',
        title: 'Identity provider intrusion research',
        source_url: 'https://example.test/research/identity-intrusion',
        publisher: 'Example Research',
        status: 'completed',
        provider: 'local',
        model: 'llama3.1:8b',
        domain: 'enterprise-attack',
        tlp: 'TLP:AMBER',
        created_at: '2026-07-16T07:00:00Z',
        updated_at: '2026-07-16T07:30:00Z',
        summary: 'The report documents suspicious identity federation changes followed by mailbox access.',
        source_text_available: true,
        counts: { reports: 1, ttps: 2, iocs: 0, cves: 0, threat_actors: 1, sectors: 1, infrastructure: 0 },
        tags: {},
      }],
    }),
  }));
  await page.goto('/threat-hunting/new?assistant=hypothesis');
  await page.getByLabel('Hypothesis source report').selectOption('11111111-1111-4111-8111-111111111111');
  await expect(page.getByLabel('Selected report TLP')).toContainText('TLP:AMBER');
  await page.getByLabel('Threat hunting AI provider').selectOption('openai');

  const generate = page.getByRole('button', { name: 'Generate hunt hypotheses' });
  await expect(generate).toBeDisabled();
  const acknowledgment = page.getByText('I acknowledge that stage-scoped hunt context will be processed by the selected remote AI provider');
  const acknowledgmentCheckbox = page.getByRole('checkbox', { name: /I acknowledge that stage-scoped hunt context/ });
  await expect(acknowledgment).toBeVisible();
  await acknowledgment.click();
  await expect(generate).toBeEnabled();
  await generate.click();
  await expect(page.getByRole('heading', { name: 'Suspicious federation trust modification' })).toBeVisible();
  await expect(acknowledgmentCheckbox).not.toBeChecked();
  await expect(generate).toBeDisabled();
  await page.getByRole('button', { name: 'Close' }).click();

  await page.getByRole('button', { name: 'Generate hypothesis from report / research' }).click();
  await expect(page.getByLabel('Threat hunting AI provider')).toHaveValue('openai');
  await expect(acknowledgmentCheckbox).not.toBeChecked();
  await expect(page.getByRole('button', { name: 'Generate hunt hypotheses' })).toBeDisabled();
  await page.getByRole('button', { name: 'Close' }).click();

  await page.getByLabel('TLP').selectOption('TLP:AMBER+STRICT');
  await page.getByRole('button', { name: 'AI assist plan and scope' }).click();
  await expect(page.getByText('TLP:AMBER+STRICT hunt context is local-only. Remote providers are unavailable for this request.')).toBeVisible();
  await expect(page.getByLabel('Threat hunting AI provider').locator('option[value="openai"]')).toHaveAttribute('disabled', '');
  await expect(page.getByLabel('Threat hunting AI provider')).toHaveValue('local');
});

test('hunt and template navigation protect unsaved analyst input', async ({ page }) => {
  await page.goto('/threat-hunting/new');
  await page.getByLabel('Hunt title').fill('Analyst-authored draft title');
  await page.getByText('Start from a template').click();

  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('Replace the entered hunt fields');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).click();
  await expect(page.getByLabel('Hunt title')).toHaveValue('Analyst-authored draft title');

  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: /Suspicious encoded PowerShell execution/ }).click();
  await expect(page.getByLabel('Hunt title')).toHaveValue('Suspicious encoded PowerShell execution');
  await expect(page.getByText('Unsaved changes')).toBeVisible();
  expect(await page.evaluate(() => {
    const event = new Event('beforeunload', { cancelable: true });
    return !window.dispatchEvent(event);
  })).toBe(true);

  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('Discard unsaved threat-hunt changes');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: /Hunt queue/ }).click();
  await expect(page).toHaveURL(/\/threat-hunting\/new$/);

  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: /Hunt queue/ }).click();
  await expect(page).toHaveURL(/\/threat-hunting$/);
});

test('changing AI request scope invalidates an earlier suggestion', async ({ page }) => {
  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('button', { name: 'AI assist plan and scope' }).click();
  await page.getByRole('button', { name: 'Assist with plan and scope' }).click();
  await expect(page.getByText('AI suggestions for the plan stage are ready for analyst review.')).toBeVisible();

  await page.getByLabel('Threat hunting AI provider').selectOption('openai');
  await expect(page.getByText('AI suggestions for the plan stage are ready for analyst review.')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Assist with plan and scope' })).toBeDisabled();
});

test('report collection pages older sources instead of silently truncating', async ({ page }) => {
  const reportItem = (index: number) => ({
    session_id: `33333333-3333-4333-8333-${String(index).padStart(12, '0')}`,
    title: index === 50 ? 'Older report loaded from page two' : `Paged report ${index + 1}`,
    source_url: '',
    publisher: 'Paging Test',
    status: 'completed',
    provider: 'local',
    model: 'test',
    domain: 'enterprise-attack',
    created_at: '2026-07-18T00:00:00Z',
    updated_at: '2026-07-18T00:00:00Z',
    summary: 'Paged collection regression fixture.',
    source_text_available: true,
    counts: {},
    tags: {},
  });
  await page.route('**/api/analyze/sessions/collection**', route => {
    const url = new URL(route.request().url());
    const offset = Number(url.searchParams.get('offset') || 0);
    const items = offset === 0 ? Array.from({ length: 50 }, (_, index) => reportItem(index)) : [reportItem(50)];
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ total: offset + items.length, limit: 50, offset, items }),
    });
  });

  await page.goto('/reports-research');
  await expect(page.getByText('50 reports loaded.')).toBeVisible();
  await page.getByRole('button', { name: 'Load older reports' }).click();
  await expect(page.getByText('51 reports loaded.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Older report loaded from page two' })).toBeVisible();
});

test('AI request failure preserves analyst focus and supports retry', async ({ page }) => {
  let rejectNext = true;
  await page.route('**/api/threat-hunting/ai/assist', async route => {
    if (rejectNext) {
      rejectNext = false;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Local AI provider is temporarily unavailable; request ag-test-503' }),
      });
      return;
    }
    await route.fallback();
  });

  await page.goto('/threat-hunting/hunt-1');
  await page.getByRole('button', { name: 'AI assist plan and scope' }).click();
  await page.getByLabel('Analyst focus').fill('Preserve this focus across a retry.');
  await page.getByRole('button', { name: 'Assist with plan and scope' }).click();

  await expect(page.getByRole('alert')).toContainText('Local AI provider is temporarily unavailable');
  await expect(page.getByLabel('Analyst focus')).toHaveValue('Preserve this focus across a retry.');
  await page.getByRole('button', { name: 'Assist with plan and scope' }).click();
  await expect(page.getByText('AI suggestions for the plan stage are ready for analyst review.')).toBeVisible();
  await expect(page.getByLabel('Analyst focus')).toHaveValue('Preserve this focus across a retry.');
});
