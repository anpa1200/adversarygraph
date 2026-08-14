const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  DEFAULT_BASE_URL,
  loadDateManifest,
  modifiedTime,
  validateDateManifest,
} = require('../seo/date-manifest.cjs');

const siteDir = path.resolve(__dirname, '..');
const descriptions = JSON.parse(
  fs.readFileSync(path.join(siteDir, 'seo', 'descriptions.json'), 'utf8'),
).descriptions;
const current = loadDateManifest(siteDir, DEFAULT_BASE_URL);

function copyManifest() {
  return JSON.parse(JSON.stringify(current));
}

test('the checked-in manifest covers and binds every authored route', () => {
  assert.equal(
    validateDateManifest({manifest: current, descriptions, siteDir, baseUrl: DEFAULT_BASE_URL}),
    current,
  );
});

test('a missing route date fails closed', () => {
  const manifest = copyManifest();
  delete manifest.routes[DEFAULT_BASE_URL];
  assert.throws(
    () => validateDateManifest({manifest, descriptions, siteDir, baseUrl: DEFAULT_BASE_URL}),
    /route mismatch; missing:/,
  );
});

test('a malformed calendar date fails closed', () => {
  const manifest = copyManifest();
  manifest.routes[DEFAULT_BASE_URL].lastModified = '2026-02-31';
  assert.throws(
    () => validateDateManifest({manifest, descriptions, siteDir, baseUrl: DEFAULT_BASE_URL}),
    /Malformed or missing lastModified/,
  );
});

test('a source-content mismatch fails closed', () => {
  const manifest = copyManifest();
  manifest.routes[DEFAULT_BASE_URL].sourceSha256 = '0'.repeat(64);
  assert.throws(
    () => validateDateManifest({manifest, descriptions, siteDir, baseUrl: DEFAULT_BASE_URL}),
    /Stale SEO date manifest/,
  );
});

test('calendar dates become deterministic Open Graph timestamps', () => {
  assert.equal(modifiedTime('2026-08-14'), '2026-08-14T00:00:00.000Z');
  assert.throws(() => modifiedTime('2026-13-14'), /Invalid last-modified date/);
});
