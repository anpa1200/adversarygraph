import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('large PCAP handoff is bounded and actor overlap stays advisory', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({json:{auth_enabled:false,name:'Local test',roles:['admin'],permissions:['read','run_analysis','manage_intel','export_data','upload_files']}}));
  page.on('pageerror', error => { throw error; });
  await page.route('**/api/analyze/sessions?**', route => route.fulfill({json:[]}));
  const analysisId = '11111111-1111-4111-8111-111111111111';
  const sessionId = '22222222-2222-4222-8222-222222222222';
  const hash = 'a'.repeat(64);
  const result = {
    analysis_id: analysisId, session_id: sessionId, status: 'completed',
    filename: 'large-synthetic-control.pcap', source_sha256: hash,
    semantic_sha256: hash, analyzer_manifest: {profile_id: 'synthetic-control'},
    summary: 'Synthetic regression fixture, not an incident.', report: 'Full evidence is retained.',
    techniques: [], apt_matches: [{group_attack_id: 'G0001', group_name: 'Overlap only', similarity: 0.2, shared_count: 1, shared_techniques: []}],
    result: {
      semantic_sha256: hash, capture: {source_sha256: hash, packet_count: 3001, duration_seconds: 1},
      endpoints: [], flows: [], identities: [], artifacts: [], findings: [], attack_candidates: [], coverage: {},
      observables: Array.from({length: 3001}, (_, i) => ({observable_id: `o${i}`, type: 'domain', value: `fixture${i}.invalid`, roles: ['dns-query'], evidence: [{frame_number: i+1}]})),
    },
  };
  const investigation = {id:'33333333-3333-4333-8333-333333333333',name:'Synthetic test',domain:'enterprise-attack',status:'active',actor_ids:[],technique_ids:[],report_ids:[],evidence_nodes:[],evidence_edges:[],timeline:[]};
  await page.route('**/api/pcap/analyses?**', route => route.fulfill({json:{items:[{...result, finding_count:0,observable_count:3001,technique_count:0}],limit:50,offset:0}}));
  await page.route(`**/api/pcap/analyses/${analysisId}`, route => route.fulfill({json:result}));
  await page.route('**/api/operations/investigations', route => route.fulfill({json:[investigation]}));
  let submitted: Record<string, any> | undefined;
  await page.route(`**/api/operations/investigations/${investigation.id}`, async route => {
    submitted = route.request().postDataJSON();
    await route.fulfill({json:{...investigation,...submitted}});
  });
  await page.goto('/analyze');
  await page.getByRole('button',{name:'Log / PCAP',exact:true}).click();
  await page.getByRole('button',{name:/large-synthetic-control.pcap/}).click();
  await page.getByRole('button',{name:'+ Add to investigation',exact:true}).click();
  await page.getByRole('button',{name:'Add to selected investigation',exact:true}).click();
  await expect.poll(()=>submitted).toBeTruthy();
  expect(submitted?.actor_ids).toEqual([]);
  const source = submitted?.evidence_nodes.find((node: Record<string, unknown>)=>node.type==='log-pcap-analysis');
  expect(source.observables).toHaveLength(100);
  expect(source.observable_count).toBe(3001);
  expect(source.observables_truncated).toBe(true);
  expect(source.source_analysis_ref).toBe(`/api/pcap/analyses/${analysisId}`);
  expect(source.source_sha256).toBe(hash);
  expect(source.actor_similarity_leads[0].status).toBe('ttp-overlap-not-attribution');
  expect(JSON.stringify(submitted).length).toBeLessThan(1024*1024);
});
