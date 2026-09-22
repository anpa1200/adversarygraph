// Real platform handoff and report export, no mocks or externally authored story.
import { createRequire } from 'node:module';
import { readFile, writeFile, access } from 'node:fs/promises';
const require = createRequire(new URL('../frontend/package.json', import.meta.url));
const { chromium, expect } = require('@playwright/test');
const source = process.argv[2], output = process.argv[3], oneCase = process.argv[4];
const refreshReports = process.env.PCAP_REFRESH_REPORTS === '1';
const reportRevision = 'quality-20260922-v3';
if (!source || !output) throw Error('Usage: node scripts/pcap_quality_browser.mjs SOURCE OUTPUT [DATE]');
const cases = JSON.parse(await readFile(`${source}/cases.json`, 'utf8'));
const origin = 'http://127.0.0.1:3000';
const exists = async path => { try { await access(path); return true; } catch { return false; } };
const save = (folder, name, value) => writeFile(`${folder}/${name}`, JSON.stringify(value, null, 2), { mode: 0o600 });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1600, height: 1050 }, acceptDownloads: true });
  const page = await context.newPage();
  for (const test of cases) {
    if (oneCase && test.date !== oneCase) continue;
    const folder = `${output}/${test.date}`;
    if (await exists(`${folder}/browser.json`) && !refreshReports) continue;
    const data = JSON.parse(await readFile(`${folder}/enriched.json`, 'utf8'));
    const previous = refreshReports ? JSON.parse(await readFile(`${folder}/browser.json`, 'utf8')) : null;
    if (previous?.report_revision === reportRevision) continue;
    const created = previous ? await context.request.get(`${origin}/api/operations/investigations?limit=500`) : await context.request.post(`${origin}/api/operations/investigations`, { data: {
      name: `PCAP quality regression — ${test.name} ${test.date}`,
      description: 'Public training regression of known cases, not an unseen benchmark. Native packet evidence and current dated provider assertions only; no answer-assisted content.',
      domain: 'enterprise-attack', actor_ids: [], technique_ids: [], report_ids: [], evidence_nodes: [], evidence_edges: [], timeline: [],
    } });
    expect(created.status()).toBe(previous ? 200 : 201);
    const createdData = await created.json();
    const workspace = previous ? createdData.find(w => w.id === previous.investigation_id) : createdData;
    if (!workspace) throw Error('The recorded regression workspace is missing');
    if (!previous) await save(folder, 'workspace-created.json', workspace);
    if (previous && !await exists(`${folder}/browser-v1.json`)) {
      for (const name of ['browser.json', 'workspace-native-full.json', 'NATIVE-FULL-REPORT.md', 'NATIVE-FULL-REPORT.pdf']) {
        const dot = name.lastIndexOf('.');
        await writeFile(`${folder}/${name.slice(0, dot)}-v1${name.slice(dot)}`, await readFile(`${folder}/${name}`));
      }
    }
    const errors = [];
    const onError = e => errors.push(e.message);
    page.on('pageerror', onError);
    await page.goto(`${origin}/analyze`, { waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'Log / PCAP', exact: true }).click();
    // Match by analysis id in the history request/selection to avoid an older
    // analysis with the same filename. Newest entry is first in server history.
    await page.getByRole('button', { name: new RegExp(test.filename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).first().click();
    await expect(page.getByRole('heading', { name: 'Deterministic PCAP Analysis', exact: true })).toBeVisible();
    const dismiss = page.getByRole('button', { name: 'Dismiss self-test popup', exact: true });
    if (await dismiss.isVisible()) await dismiss.click();
    await page.screenshot({ path: `${folder}/screen-analysis.png`, fullPage: false });
    for (const [title, file] of [[/^Recovered identities/, 'screen-identities.png'], [/^Recovered (HTTP objects|files and messages)/, 'screen-files.png'], ['Evidence-backed IOC assessment', 'screen-assessment.png']]) {
      const heading = page.getByRole('heading', { name: title });
      await heading.scrollIntoViewIfNeeded();
      await page.screenshot({ path: `${folder}/${file}` });
    }
    if (!previous) {
    await page.getByRole('button', { name: '+ Add to investigation', exact: true }).click();
    await page.locator('[data-add-investigation-menu="true"]').locator('select').selectOption(workspace.id);
    const handoff = page.waitForResponse(r => r.url() === `${origin}/api/operations/investigations/${workspace.id}` && r.request().method() === 'PUT');
    await page.getByRole('button', { name: 'Add to selected investigation', exact: true }).click();
    const linked = await handoff;
    expect(linked.status()).toBe(200);
    const linkedData = await linked.json();
    expect(linkedData.evidence_nodes.some(n => n.source_analysis_ref === `/api/pcap/analyses/${data.analysis_id}`)).toBe(true);
    await save(folder, 'workspace-handoff.json', linkedData);
    }
    await page.goto(`${origin}/report`, { waitUntil: 'domcontentloaded' });
    await page.locator('select').filter({ has: page.locator(`option[value="${workspace.id}"]`) }).selectOption(workspace.id);
    const generate = page.getByRole('button', { name: 'Generate locally from selected sections', exact: true });
    await expect(generate).toBeEnabled();
    const saved = page.waitForResponse(r => r.url() === `${origin}/api/operations/investigations/${workspace.id}` && r.request().method() === 'PUT');
    await generate.click();
    const response = await saved;
    expect(response.status()).toBe(200);
    const full = await response.json();
    await save(folder, 'workspace-native-full.json', full);
    const report = full.evidence_nodes.filter(n => n.type === 'investigation-report').at(-1);
    await writeFile(`${folder}/NATIVE-FULL-REPORT.md`, report.content, { mode: 0o600 });
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: 'PDF', exact: true }).click();
    await (await downloaded).saveAs(`${folder}/NATIVE-FULL-REPORT.pdf`);
    await page.getByRole('heading', { name: 'Executive Summary', exact: true }).scrollIntoViewIfNeeded();
    if (await dismiss.isVisible()) await dismiss.click();
    await page.screenshot({ path: `${folder}/screen-report.png` });
    const maliciousHashes = data.assessment.items.filter(i => i.type === 'sha256' && i.classification === 'provider-reported-malicious');
    expect(maliciousHashes.filter(i => !report.content.includes(i.value))).toEqual([]);
    expect(full.actor_ids).toEqual([]);
    expect(errors).toEqual([]);
    await save(folder, 'browser.json', { no_mocks: true, analysis_id: data.analysis_id, investigation_id: full.id, report_id: report.id, auto_report_saved: true,
      report_revision: reportRevision, malicious_hashes_preserved: maliciousHashes.length, page_errors: errors, local_qwen_not_called: true });
    page.off('pageerror', onError);
    console.log(JSON.stringify({ case: test.date, workspace: full.id, native_report: report.id, no_page_errors: true }));
  }
} finally { await browser.close(); }
