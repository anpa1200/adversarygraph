#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const require = createRequire(import.meta.url);
const {
  DEFAULT_BASE_URL,
  expectedRouteSources,
  isCalendarDate,
  sourceSha256,
  validateDateManifest,
} = require('../seo/date-manifest.cjs');

const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = path.join(siteDir, 'seo', 'dates.json');
const descriptions = JSON.parse(
  fs.readFileSync(path.join(siteDir, 'seo', 'descriptions.json'), 'utf8'),
).descriptions;

let check = false;
const now = new Date();
const localCalendarDate = [
  now.getFullYear(),
  String(now.getMonth() + 1).padStart(2, '0'),
  String(now.getDate()).padStart(2, '0'),
].join('-');
let dirtyDate = process.env.SEO_DATE_MANIFEST_DIRTY_DATE || localCalendarDate;
for (let index = 2; index < process.argv.length; index += 1) {
  const argument = process.argv[index];
  if (argument === '--check') {
    check = true;
  } else if (argument === '--dirty-date') {
    dirtyDate = process.argv[index + 1];
    index += 1;
  } else {
    throw new Error(`Unknown argument: ${argument}`);
  }
}
if (!isCalendarDate(dirtyDate)) throw new Error(`Invalid --dirty-date value: ${dirtyDate}`);

function git(args, cwd = siteDir) {
  return execFileSync('git', args, {cwd, encoding: 'utf8'}).trim();
}

const repositoryRoot = git(['rev-parse', '--show-toplevel']);
if (git(['rev-parse', '--is-shallow-repository']) !== 'false') {
  throw new Error('SEO date manifests must be generated and checked from a full-history Git checkout');
}

const routes = {};
const dirtySources = [];
for (const [route, source] of Object.entries(expectedRouteSources(descriptions, DEFAULT_BASE_URL))) {
  const absoluteSource = path.join(siteDir, source);
  const repositoryPath = path.relative(repositoryRoot, absoluteSource).split(path.sep).join('/');
  if (repositoryPath.startsWith('../') || path.isAbsolute(repositoryPath)) {
    throw new Error(`Route source is outside the repository: ${source}`);
  }
  if (!fs.existsSync(absoluteSource)) throw new Error(`Missing route source for ${route}: ${source}`);

  const status = git(
    ['status', '--porcelain=v1', '--untracked-files=all', '--', repositoryPath],
    repositoryRoot,
  );
  let lastModified;
  if (status) {
    lastModified = dirtyDate;
    dirtySources.push(source);
  } else {
    lastModified = git(['log', '-1', '--format=%cs', '--', repositoryPath], repositoryRoot);
    if (!isCalendarDate(lastModified)) {
      throw new Error(`No valid Git last-modified date for ${route} (${source})`);
    }
  }

  routes[route] = {
    source,
    lastModified,
    sourceSha256: sourceSha256(absoluteSource),
  };
}

const manifest = {
  schemaVersion: 1,
  dateSemantics: 'last source change calendar date',
  routes,
};
validateDateManifest({manifest, descriptions, siteDir, baseUrl: DEFAULT_BASE_URL});
const serialized = `${JSON.stringify(manifest, null, 2)}\n`;

if (dirtySources.length) {
  process.stderr.write(
    `SEO date manifest uses ${dirtyDate} for uncommitted route source(s): ${dirtySources.join(', ')}\n`,
  );
}

if (check) {
  const existing = fs.existsSync(outputPath) ? fs.readFileSync(outputPath, 'utf8') : '';
  if (existing !== serialized) {
    throw new Error('SEO date manifest is stale; run npm run generate:seo-dates from a full-history checkout');
  }
  process.stdout.write(`SEO date manifest is current for ${Object.keys(routes).length} routes.\n`);
} else {
  fs.writeFileSync(outputPath, serialized);
  process.stdout.write(`Wrote ${path.relative(siteDir, outputPath)} for ${Object.keys(routes).length} routes.\n`);
}
