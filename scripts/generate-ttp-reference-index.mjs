#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const siteDir = path.resolve(process.argv[2] || 'anomaly_detection/docs-site');
const catalogs = [
  {
    label: 'ATT&CK Activities and Log Sources',
    path: 'attack-activity-log-source-catalog',
    file: 'attack-activity-log-source-catalog.md',
  },
  {
    label: 'Basic Detection Rules',
    path: 'attack-basic-detection-rule-catalog',
    file: 'attack-basic-detection-rule-catalog.md',
  },
  {
    label: 'Statistical Anomaly Mappings',
    path: 'attack-statistical-anomaly-mapping',
    file: 'attack-statistical-anomaly-mapping.md',
  },
];

const index = {};

for (const catalog of catalogs) {
  const filePath = path.join(siteDir, 'docs', catalog.file);
  const lines = fs.readFileSync(filePath, 'utf8').split('\n');
  const occurrences = new Map();

  for (let lineNumber = 0; lineNumber < lines.length; lineNumber += 1) {
    const line = lines[lineNumber];
    if (!line.startsWith('|') || line.startsWith('|---')) continue;

    const ids = [
      ...line.matchAll(/https:\/\/attack\.mitre\.org\/techniques\/T(\d{4})(?:\/(\d{3}))?\//g),
    ].map(match => `T${match[1]}${match[2] ? `.${match[2]}` : ''}`);

    for (const attackId of [...new Set(ids)]) {
      const count = (occurrences.get(attackId) || 0) + 1;
      occurrences.set(attackId, count);
      const anchor = `ttp-${attackId.toLowerCase().replace('.', '-')}${count > 1 ? `-${count}` : ''}`;

      if (!line.includes(`<a id="${anchor}"></a>`)) {
        lines[lineNumber] = lines[lineNumber].replace(/^\| /, `| <a id="${anchor}"></a>`);
      }

      const cells = lines[lineNumber].split('|').map(cell => cell.trim()).filter(Boolean);
      const context = cells[0]
        .replace(/<a id="[^"]+"><\/a>/g, '')
        .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
        .replace(/`/g, '')
        .trim();

      index[attackId] ||= [];
      index[attackId].push({
        label: catalog.label,
        path: catalog.path,
        anchor,
        context,
      });
    }
  }

  fs.writeFileSync(filePath, `${lines.join('\n').replace(/\n+$/, '')}\n`);
}

const outputPath = path.join(siteDir, 'static', 'ttp-reference-index.json');
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(index, null, 2)}\n`);

const linkCount = Object.values(index).reduce((total, links) => total + links.length, 0);
console.log(`Generated ${linkCount} paragraph links for ${Object.keys(index).length} ATT&CK techniques`);
