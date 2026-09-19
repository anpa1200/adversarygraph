import { expect, test } from '@playwright/test';
import { mockApi } from './support/mock-api';

test('saved IOC deep link transfers bounded, source-linked graph without actor attribution', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/auth/me', route => route.fulfill({json:{auth_enabled:false,name:'Local test',roles:['admin'],permissions:['read','run_analysis','manage_intel']}}));
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const nodes = Array.from({length: 140}, (_, i) => ({id:`domain:fixture${i}.invalid`,kind:'relationship',type:'domain',value:`fixture${i}.invalid`,tier:i === 0 ? 0 : 1,sources:['otx'],suspicious:0}));
  const result = {
    session_id:sessionId,artifact:nodes[0].value,artifact_type:'domain',depth:3,
    suspicion_score:10,verdict:'needs review',summary:'Synthetic provider context.',kill_chain:[],techniques:[],
    actors:[{attack_id:'G0006',name:'Synthetic alias lead',source:'alias',confidence:0.3,evidence:'Not attribution'}],
    sources:[{source:'otx',status:'ok',summary:'No malicious detections; metadata includes malicious:false.',relationships:[],technique_ids:[],actors:[],
      raw:{pulse_id:3641916211,last_seen:1735689600,observed_at:1735776000000}}],tier2_sources:[],tier3_sources:[],ai_input:{},ai_error:'',
    relationships:{nodes,edges:nodes.slice(1).map(node=>({source:nodes[0].value,target:node.value,type:'domain',tier:1,evidence_source:'otx',evidence:'Synthetic relation'}))},
  };
  const row = {id:'33333333-3333-4333-8333-333333333333',name:'Synthetic case',domain:'enterprise-attack',status:'active',actor_ids:['G0001'],technique_ids:[],report_ids:[],evidence_nodes:[],evidence_edges:[],timeline:[]};
  result.relationships.edges.push({...result.relationships.edges[0],evidence:'A second distinct source observation'});
  // The session is outside the history page: only its durable deep link can load it.
  await page.route('**/api/ioc/investigations?**', route => route.fulfill({json:[]}));
  await page.route(`**/api/ioc/investigations/${sessionId}`, route => route.fulfill({json:result}));
  await page.route('**/api/operations/investigations', route => route.fulfill({json:[row]}));
  let submitted: Record<string, any> | undefined;
  await page.route(`**/api/operations/investigations/${row.id}`, async route => {
    submitted = route.request().postDataJSON();
    await route.fulfill({json:{...row,...submitted}});
  });
  await page.goto(`/ioc-investigation?session=${sessionId}`);
  await expect(page.getByText('2025-01-01T00:00:00',{exact:true})).toBeVisible();
  await expect(page.getByText('2025-01-02T00:00:00',{exact:true})).toBeVisible();
  await expect(page.getByText(/2085-/)).toHaveCount(0);
  await expect(page.getByText('Provider review signals',{exact:true})).toHaveCount(0);
  await expect(page.getByText('No positive structured verdict',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'+ Add to investigation',exact:true}).click();
  await page.getByRole('button',{name:'Add to selected investigation',exact:true}).click();
  await expect.poll(()=>submitted).toBeTruthy();
  expect(submitted?.actor_ids).toEqual(['G0001']);
  const source = submitted?.evidence_nodes.find((node: Record<string, unknown>)=>node.type==='ioc-investigation');
  expect(source.actor_leads[0].status).toBe('source-lead-not-attribution');
  expect(source.source_analysis_ref).toBe(`/api/ioc/investigations/${sessionId}`);
  expect(source.graph_node_count).toBe(140);
  expect(source.graph_preview_node_count).toBe(120);
  expect(source.graph_preview_truncated).toBe(true);
  const ids = new Set(submitted?.evidence_nodes.map((node: Record<string, unknown>)=>node.id));
  expect(submitted?.evidence_edges).toHaveLength(120);
  expect(new Set(submitted?.evidence_edges.map((edge: Record<string, unknown>)=>edge.id)).size).toBe(120);
  for (const edge of submitted?.evidence_edges ?? []) {
    expect(ids.has(edge.source)).toBe(true);
    expect(ids.has(edge.target)).toBe(true);
    expect(edge.evidence_source).toBe('otx');
  }
});
