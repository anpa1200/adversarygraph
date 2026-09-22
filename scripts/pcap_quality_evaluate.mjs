// Offline evaluation only: answer keys never enter analysis/enrichment prompts.
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const [source, output] = process.argv.slice(2);
if (!source || !output) throw Error('Usage: node scripts/pcap_quality_evaluate.mjs ORIGINAL FINAL');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const optional = async path => { try { return await json(path); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } };
const save = async (path, value) => writeFile(path, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const cases = await json(`${source}/cases.json`), answers = await json(`${source}/answer-review.json`);
const baseline = await json(`${source}/metrics.json`), freeze = await json(`${source}/PRE-ANSWER-FREEZE.json`);
const frozenChanges = [];
for (const [path, expected] of Object.entries(freeze.file_sha256)) {
  if (hash(await readFile(`${source}/${path}`)) !== expected) frozenChanges.push(path);
}
const results = [], providerStatuses = {}, tokens = { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0, successful_stories_with_usage: 0 };
for (const c of cases) {
  const folder = `${output}/${c.date}`, answer = answers[c.date];
  const data = await json(`${folder}/enriched.json`), native = await json(`${folder}/native.json`);
  const browser = await optional(`${folder}/browser.json`), story = await optional(`${folder}/story.json`);
  const reportText = browser ? await readFile(`${folder}/NATIVE-FULL-REPORT.md`, 'utf8') : '';
  const recovery = await optional(`${folder}/recovery-validation.json`);
  const ledger = await json(`${source}/${c.date}/reviewed-ioc-ledger.json`);
  const candidates = data.assessment.items.filter(i => i.ioc_candidate);
  const expected = answer.expected_network;
  const observed = expected.filter(value => data.result.observables.some(o => o.value === value));
  const found = expected.filter(value => candidates.some(i => i.value === value));
  const hashes = answer.expected_hashes.filter(value => data.result.artifacts.some(a => a.sha256 === value));
  const identities = answer.expected_identities.filter(value => data.result.identities.some(i => i.value.toLowerCase() === value.toLowerCase()));
  const knownContext = ledger.filter(i => i.review_disposition === 'shared-service-context-not-ioc');
  const noise = candidates.filter(i => knownContext.some(o => o.type === i.type && o.value === i.value));
  const beforeCandidates = (await json(`${source}/${c.date}/enriched.json`)).assessment.items.filter(i => i.ioc_candidate);
  const baselineHits = expected.filter(value => beforeCandidates.some(i => i.value === value));
  let pdf = { valid: false, error: 'not generated' };
  if (browser) {
    try {
      const extracted = execFileSync('pdftotext', [`${folder}/NATIVE-FULL-REPORT.pdf`, '-'], { encoding: 'utf8', maxBuffer: 5_000_000 });
      pdf = { valid: extracted.includes('Executive Summary'), extracted_characters: extracted.length, missing_published_hashes: hashes.filter(h => !extracted.includes(h)) };
    } catch { pdf = { valid: false, error: 'PDF text validation failed' }; }
  }
  let requests = 0, cacheHits = 0;
  for (const file of await readdir(folder)) {
    if (!/^enrich-\d+\.json$/.test(file)) continue;
    const batch = await json(`${folder}/${file}`);
    requests += batch.enrichment.coverage.provider_lookups_started;
    cacheHits += batch.enrichment.coverage.cache_hits || 0;
  }
  for (const i of data.enrichment.items || []) for (const s of i.signals || []) {
    const key = `${s.source}:${s.status}`; providerStatuses[key] = (providerStatuses[key] || 0) + 1;
  }
  if (story?.token_usage) {
    for (const key of ['prompt_tokens', 'completion_tokens', 'total_tokens']) tokens[key] += story.token_usage[key] || 0;
    tokens.successful_stories_with_usage++;
  }
  const row = {
    date: c.date, name: c.name, source_sha256: c.source_sha256, source_hash_matches: data.source_sha256 === c.source_sha256,
    analysis_id: data.analysis_id, investigation_id: browser?.investigation_id, analyzer_manifest_sha256: data.analyzer_manifest.manifest_sha256,
    packets: data.result.capture.packet_count, analyze_seconds: (await json(`${folder}/native-http.json`)).seconds,
    baseline_analyze_seconds: baseline.cases.find(r => r.date === c.date).analysis_seconds,
    published_hashes: answer.expected_hashes.length, recovered_published_hashes: hashes.length,
    expected_network: expected.length, observed_expected_network: observed.length,
    candidate_expected_network: found.length, baseline_candidate_expected_network: baselineHits.length,
    missing_network_candidates: expected.filter(v => !found.includes(v)),
    total_candidates: candidates.length, initial_candidates: native.assessment.ioc_candidate_count,
    matched_prior_context_rejections: noise.map(i => ({ type: i.type, value: i.value })),
    exact_identity_matches: identities.length, expected_identities: answer.expected_identities.length,
    identity_nonmatches: answer.expected_identities.filter(v => !identities.includes(v)),
    artifact_count: data.result.artifacts.length, downloads_verified: recovery?.filter(r => r.match).length || 0,
    recovery_failures: recovery?.filter(r => !r.match).length || 0, native_full_report: !!browser?.auto_report_saved,
    omitted_malicious_hashes: candidates.filter(i => i.type === 'sha256' && i.classification === 'provider-reported-malicious' && !reportText.includes(i.value)).map(i => i.value),
    pdf, screenshots: (await readdir(folder)).filter(n => n.endsWith('.png')).length,
    page_errors: browser?.page_errors, story_saved: story?.type === 'investigation-summary',
    story_error: story?.detail || null, story_model: story?.model || null, story_tokens: story?.token_usage || null,
    provider_lookups_started: requests, provider_cache_hits: cacheHits, coverage_warnings: data.result.coverage.warnings,
    answer_errata: answer.errata,
  };
  results.push(row);
  const lines = [
    `# ${c.name} (${c.date}) — regression verification`, '',
    'Known public training case, not an unseen trial. The platform was not given the answer key. This comparison was generated after its analysis.', '',
    `- Capture SHA-256: \`${c.source_sha256}\`; source hash matched: ${row.source_hash_matches}.`,
    `- Platform analysis: \`${data.analysis_id}\`; investigation: \`${row.investigation_id || 'pending'}\`.`,
    `- Decode: ${row.analyze_seconds}s (previous ${row.baseline_analyze_seconds}s; single runs under different load).`,
    `- Published comparable hashes recovered: ${hashes.length}/${answer.expected_hashes.length}. Downloaded objects independently checked: ${row.downloads_verified}.`,
    `- Answer-listed network values observed: ${observed.length}/${expected.length}; shortlisted IOC candidates: ${found.length}/${expected.length} (previous native shortlist ${baselineHits.length}).`,
    `- Exact identity strings: ${identities.length}/${answer.expected_identities.length}. Missing exact strings: ${row.identity_nonmatches.join(', ') || 'none'}. FQDN/short-host equivalence and conflicting machine principals require separate review.`,
    `- Native report: ${row.native_full_report}; PDF text parse: ${pdf.valid}; browser errors: ${JSON.stringify(row.page_errors)}.`,
    `- Native story: ${row.story_saved ? `${row.story_model}, saved as analyst-review draft, not semantic proof` : row.story_error || 'not attempted'}.`, '',
    '## Evidence', '',
    '[Native PCAP report](NATIVE-PCAP-REPORT.md) · [Full investigation report](NATIVE-FULL-REPORT.md) · [PDF](NATIVE-FULL-REPORT.pdf) · [Analysis screenshot](screen-analysis.png) · [IOC assessment screenshot](screen-assessment.png) · [Report screenshot](screen-report.png)', '',
    row.story_saved ? '[Native story draft](STORY.md)' : 'No validated native story was saved.', '',
    '## Answer-listed values not shortlisted', '',
    row.missing_network_candidates.join(', ') || 'None in the comparable answer subset.', '',
    'An inventory match is not an IOC verdict. A missed shortlist item is recorded as a recall gap, not silently promoted from the answer. Current provider detections are dated assertions, not capture-time reputation.', '',
    '## Coverage and source limitations', '',
    ...row.coverage_warnings.map(w => `- ${w}`), ...answer.errata.map(e => `- Publisher erratum retained from the original review: ${e}`), '',
    'No endpoint execution, attribution or encrypted command contents are inferred from successful downloads or graph overlap. Full source JSON, enrichment batches, consent/marking calls and download checks are retained alongside this report.', '',
  ];
  await writeFile(`${folder}/VERIFICATION.md`, lines.join('\n'));
}
const sum = key => results.reduce((n, r) => n + r[key], 0);
const totals = Object.fromEntries(['packets', 'analyze_seconds', 'baseline_analyze_seconds', 'published_hashes', 'recovered_published_hashes', 'expected_network', 'observed_expected_network', 'candidate_expected_network', 'baseline_candidate_expected_network', 'total_candidates', 'exact_identity_matches', 'expected_identities', 'downloads_verified', 'provider_lookups_started', 'provider_cache_hits', 'screenshots'].map(k => [k, sum(k)]));
totals.native_reports = results.filter(r => r.native_full_report).length;
totals.valid_pdfs = results.filter(r => r.pdf.valid).length;
totals.native_stories = results.filter(r => r.story_saved).length;
totals.prior_rejected_context_still_shortlisted = results.reduce((n, r) => n + r.matched_prior_context_rejections.length, 0);
await save(`${output}/metrics.json`, { utc: new Date().toISOString(), scope: 'known-case regression, not unseen accuracy', frozen_files_checked: Object.keys(freeze.file_sha256).length, frozen_file_changes: frozenChanges, totals, provider_statuses: providerStatuses, successful_story_tokens: tokens, cases: results });
const table = results.map(r => `| ${r.date} ${r.name} | ${r.recovered_published_hashes}/${r.published_hashes} | ${r.candidate_expected_network}/${r.expected_network} | ${r.exact_identity_matches}/${r.expected_identities} | ${r.analyze_seconds} | ${r.native_full_report ? 'saved' : 'failed'} | ${r.story_saved ? 'saved draft' : 'not saved'} |`).join('\n');
await writeFile(`${output}/SUMMARY.md`, `# Final ten-case PCAP regression\n\nKnown cases previously reviewed against published answers. Not an unseen benchmark and not a claim of 100% investigation accuracy.\n\n| Case | Published hashes | Network shortlist recall | Exact identities | Decode seconds | Native report | Native story |\n|---|---:|---:|---:|---:|---|---|\n${table}\n\n## Aggregate\n\n- ${totals.recovered_published_hashes}/${totals.published_hashes} published comparable file hashes recovered.\n- ${totals.observed_expected_network}/${totals.expected_network} answer-listed network values observed; ${totals.candidate_expected_network}/${totals.expected_network} shortlisted, versus ${totals.baseline_candidate_expected_network}/${totals.expected_network} in the prior native shortlist. The prior agent-curated shortlist was a different process.\n- ${totals.prior_rejected_context_still_shortlisted} previously rejected shared-service values remain shortlisted; this is not a complete false-positive census.\n- ${totals.native_reports}/10 native reports, ${totals.valid_pdfs}/10 text-parseable PDFs, ${totals.native_stories}/10 saved native story drafts. Exact citation/schema binding is not semantic proof.\n- ${totals.downloads_verified} platform artifact downloads independently hash/size verified. ${totals.screenshots} browser screenshots. The local instance is in its existing local/no-login mode; this run does not prove authenticated production access control.\n- ${totals.analyze_seconds.toFixed(3)}s decoder API time versus ${totals.baseline_analyze_seconds.toFixed(3)}s before (${(100*(1-totals.analyze_seconds/totals.baseline_analyze_seconds)).toFixed(1)}% lower). Load, decoder profile and caching differ; not a controlled throughput benchmark.\n- ${totals.provider_lookups_started} provider invocations; ${totals.provider_cache_hits} exact-target cache hits. Status counts and remaining gaps in metrics.json. No payload uploads or active scans.\n- ${Object.keys(freeze.file_sha256).length} original frozen files verified; changes: ${frozenChanges.length}.\n\n## Evidence navigation\n\n${results.map(r => `- [${r.name} verification and evidence](${r.date}/VERIFICATION.md)`).join('\n')}\n\nRaw outputs and intermediate attempts are retained separately. LLM token counts are provider-reported only, limited to recorded responses; they are not the assistant's conversation-token usage. No Qwen run was performed.\n`);
console.log(JSON.stringify(totals, null, 2));
