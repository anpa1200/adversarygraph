const fs = require('node:fs');
const path = require('node:path');
const {loadDateManifest, modifiedTime} = require('./seo/date-manifest.cjs');

const SITE_NAME = '1200km — Andrey Pautov Security Research';
const TITLE_SUFFIX = ' | 1200km';

function walk(directory) {
  return fs.readdirSync(directory, {withFileTypes: true}).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(target) : [target];
  });
}

function decodeHtml(value) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

function escapeHtml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function findTag(html, tagName, attributeName, attributeValue) {
  const tags = html.match(new RegExp(`<${tagName}\\b[^>]*>`, 'gi')) || [];
  return tags.find((tag) => {
    const match = tag.match(new RegExp(`\\b${attributeName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
    return match && (match[1] || match[2] || match[3]) === attributeValue;
  });
}

function getAttribute(tag, attributeName) {
  const match = tag?.match(new RegExp(`\\b${attributeName}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return match ? decodeHtml(match[1] || match[2] || match[3]) : undefined;
}

function upsertMeta(html, key, value, attributeName = 'name') {
  const current = findTag(html, 'meta', attributeName, key);
  const replacement = `<meta data-rh="true" ${attributeName}="${escapeHtml(key)}" content="${escapeHtml(value)}">`;
  return current ? html.replace(current, replacement) : html.replace('</head>', `${replacement}</head>`);
}

function breadcrumbJson(canonical, pageTitle, subsiteName, baseUrl) {
  const root = `https://1200km.com${baseUrl}`;
  const items = [
    {'@type': 'ListItem', position: 1, name: '1200km', item: 'https://1200km.com/'},
    {'@type': 'ListItem', position: 2, name: subsiteName, item: root},
  ];
  if (canonical !== root) {
    items.push({'@type': 'ListItem', position: 3, name: pageTitle, item: canonical});
  }
  return JSON.stringify({'@context': 'https://schema.org', '@type': 'BreadcrumbList', itemListElement: items});
}

module.exports = function seoMetadataPlugin(context) {
  const metadataPath = path.join(context.siteDir, 'seo', 'descriptions.json');
  const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
  const dateManifest = loadDateManifest(context.siteDir, context.siteConfig.baseUrl);

  return {
    name: '1200km-seo-metadata',
    async postBuild({outDir}) {
      const seenDescriptions = new Map();
      const seenPaths = new Set();
      const seenDatePaths = new Set();

      for (const file of walk(outDir).filter((entry) => entry.endsWith('.html'))) {
        let html = fs.readFileSync(file, 'utf8');
        const canonicalTag = findTag(html, 'link', 'rel', 'canonical');
        const canonical = getAttribute(canonicalTag, 'href');
        if (!canonical?.startsWith('https://1200km.com/')) continue;

        const pathname = new URL(canonical).pathname;
        if (!pathname.startsWith(context.siteConfig.baseUrl)) continue;
        if (canonical.includes('/404.html')) {
          const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
          if (!titleMatch) throw new Error(`Missing title for ${pathname}`);
          const title = `Page Not Found${TITLE_SUFFIX}`;
          html = html.replace(titleMatch[0], titleMatch[0].replace(titleMatch[1], escapeHtml(title)));
          html = upsertMeta(html, 'og:title', title, 'property');
          html = upsertMeta(html, 'og:site_name', SITE_NAME, 'property');
          html = upsertMeta(html, 'twitter:title', title);
          fs.writeFileSync(file, html);
          continue;
        }
        const description = metadata.descriptions[pathname];
        if (!description) throw new Error(`Missing authored SEO description for ${pathname}`);
        const dateRecord = dateManifest.routes[pathname];
        if (!dateRecord) throw new Error(`Missing SEO date record for ${pathname}`);

        const titleMatch = html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
        if (!titleMatch) throw new Error(`Missing title for ${pathname}`);
        const title = decodeHtml(titleMatch[1].replace(/<[^>]+>/g, '').trim());
        const suffixCount = title.split(TITLE_SUFFIX).length - 1;
        if (!title.endsWith(TITLE_SUFFIX) || suffixCount !== 1) {
          throw new Error(`Title must end with exactly one "${TITLE_SUFFIX}" for ${pathname}: ${title}`);
        }
        const pageTitle = title.slice(0, -TITLE_SUFFIX.length).trim();

        if (description.length < 140 || description.length > 160) {
          throw new Error(`Description length ${description.length} is outside 140–160 for ${pathname}`);
        }
        if (description.toLocaleLowerCase('en').includes(pageTitle.toLocaleLowerCase('en'))) {
          throw new Error(`Description contains the page title verbatim for ${pathname}`);
        }
        if (description.includes('..') || description.includes('…') || /\s$/.test(description)) {
          throw new Error(`Description has a prohibited or truncated ending for ${pathname}`);
        }
        if (seenDescriptions.has(description)) {
          throw new Error(`Duplicate description for ${pathname} and ${seenDescriptions.get(description)}`);
        }
        seenDescriptions.set(description, pathname);
        seenPaths.add(pathname);
        seenDatePaths.add(pathname);

        html = upsertMeta(html, 'description', description);
        html = upsertMeta(html, 'og:title', title, 'property');
        html = upsertMeta(html, 'og:description', description, 'property');
        html = upsertMeta(html, 'og:site_name', SITE_NAME, 'property');
        html = upsertMeta(html, 'twitter:title', title);
        html = upsertMeta(html, 'twitter:description', description);

        const ogImage = getAttribute(findTag(html, 'meta', 'property', 'og:image'), 'content');
        if (!ogImage) throw new Error(`Missing og:image for ${pathname}`);
        html = upsertMeta(html, 'twitter:image', ogImage);

        if (pathname !== context.siteConfig.baseUrl) {
          html = upsertMeta(
            html,
            'article:modified_time',
            modifiedTime(dateRecord.lastModified),
            'property',
          );
        }

        if (!html.includes('"@type":"BreadcrumbList"')) {
          const json = breadcrumbJson(canonical, pageTitle, metadata.subsiteName, context.siteConfig.baseUrl);
          html = html.replace('</head>', `<script type="application/ld+json">${json}</script></head>`);
        }

        fs.writeFileSync(file, html);
      }

      const unused = Object.keys(metadata.descriptions).filter((pathname) => !seenPaths.has(pathname));
      if (unused.length) throw new Error(`Authored SEO descriptions did not match built routes: ${unused.join(', ')}`);
      const unusedDates = Object.keys(dateManifest.routes).filter((pathname) => !seenDatePaths.has(pathname));
      if (unusedDates.length) throw new Error(`SEO dates did not match built routes: ${unusedDates.join(', ')}`);
    },
  };
};
