#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const siteDir = path.resolve(process.argv[2] || 'anomaly_detection/docs-site');
const overlayDir = path.resolve(process.argv[3] || 'anomaly_detection/docs-overlay');
const guide = 'threatmapper-integration.md';

fs.copyFileSync(path.join(overlayDir, guide), path.join(siteDir, 'docs', guide));

const sidebarPath = path.join(siteDir, 'sidebars.js');
let sidebar = fs.readFileSync(sidebarPath, 'utf8');
if (!sidebar.includes("'threatmapper-integration'")) {
  sidebar = sidebar.replace(
    'referenceSidebar: [',
    "referenceSidebar: [\n    'threatmapper-integration',",
  );
  fs.writeFileSync(sidebarPath, sidebar);
}

const configPath = path.join(siteDir, 'docusaurus.config.js');
let config = fs.readFileSync(configPath, 'utf8');
if (!config.includes("to: '/threatmapper-integration'")) {
  config = config.replace(
    "items: [\n        { to: '/attack-activity-log-source-catalog'",
    "items: [\n        { to: '/threatmapper-integration', label: 'ThreatMapper Integration', position: 'left' },\n        { to: '/attack-activity-log-source-catalog'",
  );
  fs.writeFileSync(configPath, config);
}

console.log(`Applied ThreatMapper documentation overlay to ${siteDir}`);
