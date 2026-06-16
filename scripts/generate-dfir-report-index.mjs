#!/usr/bin/env node

import { writeFile, readFile } from 'node:fs/promises';

const REPORTS_URL = 'https://thedfirreport.com/reports/';
const POST_SITEMAP_URL = 'https://thedfirreport.com/post-sitemap.xml';
const OUT = new URL('../frontend/public/dfir-report-reference-index.json', import.meta.url);
const USER_AGENT = 'ThreatMapper external-link indexer (https://1200km.com/)';
const LOCAL_API = process.env.THREATMAPPER_API || 'http://localhost:8000/api';
const DOMAINS = ['enterprise-attack', 'mobile-attack', 'ics-attack'];

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function stripHtml(html) {
  return decodeEntities(html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim());
}

function decodeEntities(text) {
  return text
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&#039;|&#39;|&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#8217;|&rsquo;/g, "'")
    .replace(/&#8216;|&lsquo;/g, "'")
    .replace(/&#8220;|&ldquo;/g, '"')
    .replace(/&#8221;|&rdquo;/g, '"')
    .replace(/&#8211;|&#8212;|&ndash;|&mdash;/g, '-');
}

function attr(html, property) {
  const escaped = property.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<meta[^>]+(?:property|name)=["']${escaped}["'][^>]+content=["']([^"']+)["']`, 'i');
  return decodeEntities(html.match(re)?.[1]?.trim() ?? '');
}

function titleFrom(html) {
  return attr(html, 'og:title')
    .replace(/\s+-\s+The DFIR Report$/i, '')
    || stripHtml(html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1] ?? '')
    || stripHtml(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '').replace(/\s+-\s+The DFIR Report$/i, '');
}

function dateFrom(url, html) {
  const meta = attr(html, 'article:published_time');
  if (meta) return meta.slice(0, 10);
  const match = url.match(/\/(\d{4})\/(\d{2})\/(\d{2})\//);
  return match ? `${match[1]}-${match[2]}-${match[3]}` : '';
}

function tagsFrom(html) {
  const tags = new Set();
  for (const match of html.matchAll(/<a[^>]+rel=["'][^"']*tag[^"']*["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const tag = stripHtml(match[1]);
    if (tag) tags.add(tag);
  }
  return [...tags].sort((a, b) => a.localeCompare(b));
}

function reportUrlsFrom(html) {
  const urls = new Set();
  for (const match of html.matchAll(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>/gi)) {
    const url = new URL(match[1], REPORTS_URL).href.replace(/#.*$/, '');
    if (/^https:\/\/thedfirreport\.com\/\d{4}\/\d{2}\/\d{2}\//.test(url)) urls.add(url);
  }
  return [...urls].sort();
}

function techniqueIds(text) {
  return [...new Set((text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? []))].sort();
}

async function fetchText(url) {
  const response = await fetch(url, { headers: { 'user-agent': USER_AGENT } });
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  return response.text();
}

async function loadGroups() {
  const groups = [];
  for (const domain of DOMAINS) {
    try {
      const response = await fetch(`${LOCAL_API}/apt/groups?domain=${domain}`, {
        headers: { 'user-agent': USER_AGENT },
      });
      if (!response.ok) continue;
      const rows = await response.json();
      for (const row of rows) {
        groups.push({
          attack_id: row.attack_id,
          name: row.name,
          aliases: row.aliases ?? [],
          domain,
        });
      }
    } catch {
      // Actor enrichment is optional; TTP links still work without the local API.
    }
  }
  const seen = new Set();
  return groups.filter(group => {
    const key = `${group.domain}:${group.attack_id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function actorIds(text, groups) {
  const found = new Set(text.match(/\bG\d{4}\b/g) ?? []);
  const lowered = ` ${text.toLowerCase()} `;
  for (const group of groups) {
    for (const alias of [group.name, ...(group.aliases ?? [])]) {
      if (!alias || alias.length < 4) continue;
      const escaped = alias.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (new RegExp(`(^|[^a-z0-9])${escaped}([^a-z0-9]|$)`, 'i').test(lowered)) {
        found.add(group.attack_id);
      }
    }
  }
  return [...found].sort();
}

function ref(report, matchBasis, context) {
  return {
    title: report.title,
    publisher: 'The DFIR Report',
    url: report.url,
    date: report.date,
    source_id: report.source_id,
    reliability: 'B',
    match_basis: matchBasis,
    context,
  };
}

async function main() {
  const reportsHtml = await fetchText(REPORTS_URL);
  const urls = new Set(reportUrlsFrom(reportsHtml));
  try {
    const sitemap = await fetchText(POST_SITEMAP_URL);
    for (const match of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) {
      const url = match[1].replace(/#.*$/, '');
      if (/^https:\/\/thedfirreport\.com\/\d{4}\/\d{2}\/\d{2}\//.test(url)) urls.add(url);
    }
  } catch (error) {
    console.warn(`Could not load post sitemap, using reports page only: ${error.message}`);
  }
  const groups = await loadGroups();
  const byTechnique = {};
  const byActor = {};
  const reports = [];

  const reportUrls = [...urls].sort();
  for (const [index, url] of reportUrls.entries()) {
    await sleep(index === 0 ? 0 : 350);
    const html = await fetchText(url);
    const text = stripHtml(html);
    const report = {
      title: titleFrom(html),
      url,
      date: dateFrom(url, html),
      tags: tagsFrom(html),
      techniques: techniqueIds(text),
      actors: actorIds(`${titleFrom(html)} ${tagsFrom(html).join(' ')} ${text}`, groups),
    };
    report.source_id = `SRC-DFIR-${report.date.replaceAll('-', '') || 'UNDATED'}-${report.url.split('/').filter(Boolean).at(-1).slice(0, 48).toUpperCase().replace(/[^A-Z0-9]+/g, '-')}`;
    reports.push(report);

    for (const technique of report.techniques) {
      byTechnique[technique] ??= [];
      byTechnique[technique].push(ref(
        report,
        'external public DFIR report ATT&CK ID mention',
        `Linked DFIR public report; content remains on the source site. Tags: ${report.tags.slice(0, 6).join(', ') || 'none'}.`,
      ));
    }

    for (const actor of report.actors) {
      byActor[actor] ??= [];
      byActor[actor].push(ref(
        report,
        'external public DFIR report actor/name mention',
        `Linked DFIR public report correlated by actor name, alias, tag, or ATT&CK group ID.`,
      ));
    }
  }

  const output = {
    generated: new Date().toISOString(),
    source: REPORTS_URL,
    supplemental_source: POST_SITEMAP_URL,
    license_note: 'Linked metadata only. The DFIR Report pages are copyrighted; full report text, images, and artifacts are not mirrored.',
    report_count: reports.length,
    technique_count: Object.keys(byTechnique).length,
    actor_count: Object.keys(byActor).length,
    reports: reports.map(report => ({
      title: report.title,
      url: report.url,
      date: report.date,
      tags: report.tags,
      techniques: report.techniques,
      actors: report.actors,
    })),
    byTechnique,
    byActor,
  };

  await writeFile(OUT, `${JSON.stringify(output, null, 2)}\n`);
  console.log(`Wrote ${OUT.pathname}`);
  console.log(`Reports: ${output.report_count}; TTPs: ${output.technique_count}; Actors: ${output.actor_count}`);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
