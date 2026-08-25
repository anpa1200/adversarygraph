import { expect, test } from '@playwright/test';

import { mockApi } from './support/mock-api';

const sessionId = '11111111-1111-4111-8111-111111111111';
const sourceQuote = 'The actor modified federation trust settings';

function assessment(version: number, sourceVerdict: 'pending' | 'pass' = 'pending') {
  const gateDefinitions = [
    ['source_provenance', 'Source provenance', ['source_verified', 'source_mismatch', 'insufficient_provenance']],
    ['publication_date', 'Publication date', ['date_verified', 'date_missing', 'date_unverified']],
    ['procedure_relevance', 'Procedure relevance', ['procedure_relevant', 'insufficient_procedure_context']],
    ['procedure_level_claim', 'Procedure-level claim', ['source_bound_claims', 'claim_not_source_bound']],
    ['actor_identification', 'Actor identification', ['explicit_attribution', 'no_actor_claim', 'tooling_overlap_only']],
  ] as const;
  return {
    id: 'review-1',
    session_id: sessionId,
    revision: 1,
    version,
    policy_version: 'report-review-v1',
    profile: 'external_cti',
    state: 'draft',
    source_checksum: 'a'.repeat(64),
    analysis_checksum: 'b'.repeat(64),
    source_char_count: 78,
    analyzed_char_count: 78,
    coverage_complete: true,
    gates: gateDefinitions.map(([gate_key, title, reasonCodes], index) => ({
      id: `gate-${index + 1}`,
      gate_key,
      ordinal: index + 1,
      title,
      question: `${title} review question`,
      required: true,
      allowed_reason_codes: reasonCodes,
      machine_verdict: 'pass',
      machine_summary: 'Deterministic evidence check completed.',
      machine_evidence: gate_key === 'source_provenance' ? [{
        id: 'source-ref-1',
        kind: 'source_text',
        excerpt: sourceQuote,
        evidence_start: 0,
        evidence_end: sourceQuote.length,
      }] : [],
      analyst_verdict: gate_key === 'source_provenance' ? sourceVerdict : 'pending',
      reason_code: gate_key === 'source_provenance' && sourceVerdict === 'pass' ? 'source_verified' : '',
      rationale: gate_key === 'source_provenance' && sourceVerdict === 'pass' ? 'Verified against the stored source fingerprint.' : '',
      evidence_refs: gate_key === 'source_provenance' && sourceVerdict === 'pass' ? [{
        id: 'source-ref-1',
        kind: 'source_text',
        excerpt: sourceQuote,
        evidence_start: 0,
        evidence_end: sourceQuote.length,
      }] : [],
    })),
    claims: [],
    readiness: {
      ready: false,
      blockers: ['gate_pending:publication_date'],
      accepted_claim_count: 0,
      required_gate_count: 5,
      reviewed_gate_count: sourceVerdict === 'pass' ? 1 : 0,
    },
    active_promotion: null,
  };
}

test.beforeEach(async ({ page }) => {
  await mockApi(page);
});

test('keeps deterministic and AI findings advisory while recording versioned analyst decisions', async ({ page }) => {
  let current = assessment(4);
  let gatePayload: Record<string, unknown> | undefined;
  let aiPayload: Record<string, unknown> | undefined;

  await page.route(`**/api/analyze/sessions/${sessionId}/review`, async route => {
    if (route.request().method() !== 'GET') return route.fallback();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });
  await page.route(`**/api/analyze/sessions/${sessionId}/review/history`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ items: [] }),
  }));
  await page.route(`**/api/analyze/sessions/${sessionId}/review/gates/source_provenance`, async route => {
    gatePayload = route.request().postDataJSON() as Record<string, unknown>;
    current = assessment(5, 'pass');
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });
  await page.route(`**/api/analyze/sessions/${sessionId}/review/ai-assist`, async route => {
    aiPayload = route.request().postDataJSON() as Record<string, unknown>;
    current = { ...current, version: 6 };
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        authoritative: false,
        provider: 'claude',
        model: 'test-model',
        prompt_version: 'report-review-ai-v1',
        complete_coverage: true,
        coverage_chars: 78,
        source_chars: 78,
        suggested_claim_count: 1,
        review_version: 6,
        review: current,
        parts: [],
      }),
    });
  });

  await page.goto(`/analyze/${sessionId}/report`);
  await expect(page.getByRole('heading', { name: 'Deterministic report Review Gate' })).toBeVisible();
  await expect(page.getByText('Machine finding · advisory').first()).toBeVisible();
  await expect(page.getByText('Analyst decision · authoritative').first()).toBeVisible();

  const sourceGate = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Source provenance' }) });
  await sourceGate.getByRole('combobox').first().selectOption('pass');
  await sourceGate.getByRole('textbox', { name: 'Analyst rationale' }).fill('Verified against the canonical stored report and checksum.');
  await sourceGate.getByRole('checkbox').check();
  await sourceGate.getByRole('button', { name: 'Save analyst decision' }).click();

  await expect.poll(() => gatePayload?.expected_version).toBe(4);
  expect(gatePayload?.reason_code).toBe('source_verified');
  expect(gatePayload).not.toHaveProperty('reviewer');
  await expect(page.getByText('Required gates reviewed').locator('..')).toContainText('1/5');

  await page.getByLabel('AI provider').selectOption('claude');
  await expect(page.getByRole('button', { name: 'Ask AI' })).toBeDisabled();
  await page.getByText(/I acknowledge that the stored report text/).click();
  await page.getByRole('button', { name: 'Ask AI' }).click();

  await expect.poll(() => aiPayload?.expected_version).toBe(5);
  expect(aiPayload?.cloud_processing_acknowledged).toBe(true);
  await expect(page.getByText(/1 new claim suggestion persisted/)).toBeVisible();
  await expect(page.getByText('Advisory received · not authoritative')).toBeVisible();
});

test('promotes to canonical intelligence plus selected governed targets', async ({ page }) => {
  let promotionPayload: Record<string, unknown> | undefined;
  let current = {
    ...assessment(12, 'pass'),
    state: 'approved',
    gates: assessment(12, 'pass').gates.map(gate => ({
      ...gate,
      analyst_verdict: 'pass',
      reason_code: gate.allowed_reason_codes[0],
      rationale: 'Independently verified against source-bound evidence.',
    })),
    readiness: {
      ready: true,
      blockers: [],
      accepted_claim_count: 3,
      required_gate_count: 5,
      reviewed_gate_count: 5,
    },
  };

  await page.route(`**/api/analyze/sessions/${sessionId}/review`, async route => {
    if (route.request().method() !== 'GET') return route.fallback();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });
  await page.route(`**/api/analyze/sessions/${sessionId}/review/history`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ items: [] }),
  }));
  await page.route(`**/api/analyze/sessions/${sessionId}/review/promote`, async route => {
    promotionPayload = route.request().postDataJSON() as Record<string, unknown>;
    current = {
      ...current,
      version: 13,
      state: 'promoted',
      active_promotion: {
        id: 'promotion-1',
        status: 'active',
        targets: promotionPayload.targets,
      },
    };
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });

  await page.goto(`/analyze/${sessionId}/report`);
  const lifecycle = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Review lifecycle' }) });
  const canonical = lifecycle.getByRole('checkbox', { name: /Canonical intelligence/ });
  await expect(canonical).toBeChecked();
  await expect(canonical).toBeDisabled();
  await expect(lifecycle.getByText('Knowledge library')).toHaveCount(0);

  await lifecycle.getByRole('checkbox', { name: /RAG retrieval/ }).check();
  await lifecycle.getByRole('checkbox', { name: /Threat hunting/ }).check();
  await lifecycle.getByRole('checkbox', { name: /Trusted exports/ }).check();
  await lifecycle.getByRole('button', { name: 'Promote accepted claims' }).click();

  await expect.poll(() => promotionPayload?.targets).toEqual(['canonical_intelligence', 'rag', 'hunting', 'exports']);
  expect(promotionPayload?.expected_version).toBe(12);
  expect(promotionPayload).not.toHaveProperty('target');
});

test('binds the selected indicator type to a manual source-backed claim', async ({ page }) => {
  let current = assessment(7);
  let claimPayload: Record<string, unknown> | undefined;

  await page.route(`**/api/analyze/sessions/${sessionId}/review`, async route => {
    if (route.request().method() !== 'GET') return route.fallback();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });
  await page.route(`**/api/analyze/sessions/${sessionId}/review/history`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ items: [] }),
  }));
  await page.route(`**/api/analyze/sessions/${sessionId}/review/claims`, async route => {
    claimPayload = route.request().postDataJSON() as Record<string, unknown>;
    current = { ...current, version: 8 };
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });

  await page.goto(`/analyze/${sessionId}/report`);
  const form = page.locator('details').filter({ hasText: 'Add a manual source-bound claim' });
  await form.getByText('Add a manual source-bound claim').click();
  await form.getByLabel('Claim type').selectOption('indicator');
  await form.getByLabel('Indicator type').selectOption('sha256');
  await form.getByLabel('Subject').fill('Stored report');
  await form.getByLabel('Predicate / action').fill('reported');
  await form.getByLabel('Object / outcome').fill('a'.repeat(64));
  await form.getByLabel('Complete claim statement').fill(`The report identifies SHA-256 ${'a'.repeat(64)} as malicious.`);
  await form.getByLabel('Evidence start offset').fill('0');
  await form.getByLabel('Evidence end offset').fill('10');
  await form.getByRole('button', { name: 'Create suggested claim' }).click();

  await expect.poll(() => claimPayload?.metadata).toEqual({ indicator_type: 'sha256' });
  expect(claimPayload?.claim_type).toBe('indicator');
  expect(claimPayload?.expected_version).toBe(7);
});

test('renders canonical evidence fields and deterministic preflight aliases', async ({ page }) => {
  const base = assessment(9);
  const current = {
    ...base,
    gates: base.gates.map((gate, index) => index === 0 ? {
      ...gate,
      machine_evidence: [
        {
          type: 'source_span',
          quote: 'The actor modified federation',
          start: 4,
          end: 31,
          metadata: { path: 'source_text.sections[0]' },
        },
        {
          type: 'metadata',
          path: 'source_metadata.retrieval.url',
          value: 'https://example.test/report',
        },
        {
          type: 'metadata',
          label: 'Retrieval metadata label',
          path: 'source_metadata.retrieval.method',
        },
      ],
    } : gate),
  };

  await page.route(`**/api/analyze/sessions/${sessionId}/review`, async route => {
    if (route.request().method() !== 'GET') return route.fallback();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(current) });
  });
  await page.route(`**/api/analyze/sessions/${sessionId}/review/history`, route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ items: [] }),
  }));

  await page.goto(`/analyze/${sessionId}/report`);
  const sourceGate = page.locator('article').filter({ has: page.getByRole('heading', { name: 'Source provenance' }) });
  const machineEvidence = sourceGate.getByLabel('Source provenance machine finding');

  await expect(machineEvidence.getByText('source_span', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('offset 4–31', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('The actor modified federation', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('source_text.sections[0]', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('source_metadata.retrieval.url', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('https://example.test/report', { exact: true })).toBeVisible();
  await expect(machineEvidence.getByText('Retrieval metadata label', { exact: true })).toBeVisible();
});
