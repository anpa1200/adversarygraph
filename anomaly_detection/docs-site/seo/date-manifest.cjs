const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_BASE_URL = '/anomaly-detection-atlas/';
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isCalendarDate(value) {
  if (typeof value !== 'string' || !DATE_PATTERN.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function sourceSha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function expectedRouteSources(descriptions, baseUrl = DEFAULT_BASE_URL) {
  if (!isPlainObject(descriptions) || Object.keys(descriptions).length === 0) {
    throw new Error('SEO descriptions must be a non-empty route map');
  }
  if (!baseUrl.startsWith('/') || !baseUrl.endsWith('/')) {
    throw new Error(`Invalid Docusaurus base URL: ${baseUrl}`);
  }

  const expected = {};
  for (const route of Object.keys(descriptions).sort()) {
    if (!route.startsWith(baseUrl) || !route.endsWith('/')) {
      throw new Error(`SEO route must be inside ${baseUrl} and end with a slash: ${route}`);
    }
    if (route === baseUrl) {
      expected[route] = 'src/pages/index.js';
      continue;
    }

    const slug = route.slice(baseUrl.length, -1);
    if (!slug || slug.includes('/') || slug === '.' || slug === '..') {
      throw new Error(`Unsupported document route for the date manifest: ${route}`);
    }
    expected[route] = `docs/${slug}.md`;
  }
  return expected;
}

function validateDateManifest({manifest, descriptions, siteDir, baseUrl = DEFAULT_BASE_URL}) {
  if (!isPlainObject(manifest)) throw new Error('SEO date manifest must be a JSON object');
  if (manifest.schemaVersion !== 1) {
    throw new Error(`Unsupported SEO date manifest schemaVersion: ${manifest.schemaVersion}`);
  }
  if (manifest.dateSemantics !== 'last source change calendar date') {
    throw new Error('SEO date manifest has unsupported date semantics');
  }
  if (!isPlainObject(manifest.routes)) throw new Error('SEO date manifest routes must be an object');

  const expected = expectedRouteSources(descriptions, baseUrl);
  const expectedRoutes = Object.keys(expected).sort();
  const actualRoutes = Object.keys(manifest.routes).sort();
  const missing = expectedRoutes.filter((route) => !actualRoutes.includes(route));
  const extra = actualRoutes.filter((route) => !expectedRoutes.includes(route));
  if (missing.length || extra.length) {
    throw new Error(
      `SEO date manifest route mismatch; missing: ${missing.join(', ') || 'none'}; extra: ${extra.join(', ') || 'none'}`,
    );
  }

  for (const route of expectedRoutes) {
    const record = manifest.routes[route];
    if (!isPlainObject(record)) throw new Error(`SEO date record must be an object for ${route}`);
    if (record.source !== expected[route]) {
      throw new Error(`SEO date source mismatch for ${route}: expected ${expected[route]}, got ${record.source}`);
    }
    if (!isCalendarDate(record.lastModified)) {
      throw new Error(`Malformed or missing lastModified date for ${route}: ${record.lastModified}`);
    }
    if (typeof record.sourceSha256 !== 'string' || !SHA256_PATTERN.test(record.sourceSha256)) {
      throw new Error(`Malformed or missing sourceSha256 for ${route}`);
    }

    const sourceFile = path.join(siteDir, record.source);
    if (!fs.existsSync(sourceFile) || !fs.statSync(sourceFile).isFile()) {
      throw new Error(`Missing route source for ${route}: ${record.source}`);
    }
    const actualSha256 = sourceSha256(sourceFile);
    if (actualSha256 !== record.sourceSha256) {
      throw new Error(
        `Stale SEO date manifest for ${route}; run npm run generate:seo-dates from a full-history checkout`,
      );
    }
  }

  return manifest;
}

function readJson(file, label) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read ${label} at ${file}: ${error.message}`);
  }
}

function loadDateManifest(siteDir, baseUrl = DEFAULT_BASE_URL) {
  const metadata = readJson(path.join(siteDir, 'seo', 'descriptions.json'), 'SEO descriptions');
  if (!isPlainObject(metadata.descriptions)) {
    throw new Error('SEO descriptions file must contain a descriptions object');
  }
  const manifest = readJson(path.join(siteDir, 'seo', 'dates.json'), 'SEO date manifest');
  return validateDateManifest({
    manifest,
    descriptions: metadata.descriptions,
    siteDir,
    baseUrl,
  });
}

function modifiedTime(lastModified) {
  if (!isCalendarDate(lastModified)) throw new Error(`Invalid last-modified date: ${lastModified}`);
  return `${lastModified}T00:00:00.000Z`;
}

module.exports = {
  DEFAULT_BASE_URL,
  expectedRouteSources,
  isCalendarDate,
  loadDateManifest,
  modifiedTime,
  sourceSha256,
  validateDateManifest,
};
