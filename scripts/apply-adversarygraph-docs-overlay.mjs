#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';

const siteDir = path.resolve(process.argv[2] || 'anomaly_detection/docs-site');
const overlayDir = path.resolve(process.argv[3] || 'anomaly_detection/docs-overlay');
const guide = 'adversarygraph-integration.md';

fs.copyFileSync(path.join(overlayDir, guide), path.join(siteDir, 'docs', guide));
fs.cpSync(path.join(overlayDir, 'src'), path.join(siteDir, 'src'), {recursive: true});

const sidebarPath = path.join(siteDir, 'sidebars.js');
let sidebar = fs.readFileSync(sidebarPath, 'utf8');
if (!sidebar.includes("'adversarygraph-integration'")) {
  sidebar = sidebar.replace(
    'referenceSidebar: [',
    "referenceSidebar: [\n    'adversarygraph-integration',",
  );
}
if (!sidebar.includes("'adversarygraph-integration'")) {
  throw new Error(`Unable to add AdversaryGraph guide to ${sidebarPath}`);
}
fs.writeFileSync(sidebarPath, sidebar);

const configPath = path.join(siteDir, 'docusaurus.config.js');
let config = fs.readFileSync(configPath, 'utf8');
config = config.replace(/  onBrokenLinks: '(?:warn|ignore|throw)',/, "  onBrokenLinks: 'throw',");
if (/  onBrokenAnchors: '(?:warn|ignore|throw)',/.test(config)) {
  config = config.replace(
    /  onBrokenAnchors: '(?:warn|ignore|throw)',/,
    "  onBrokenAnchors: 'throw',",
  );
} else {
  config = config.replace(
    "  onBrokenLinks: 'throw',",
    "  onBrokenLinks: 'throw',\n  onBrokenAnchors: 'throw',",
  );
}
config = config.replace(
  /      onBrokenMarkdownLinks: '(?:warn|ignore|throw)',/,
  "      onBrokenMarkdownLinks: 'throw',",
);
if (!config.includes("require('./src/rehype/explicitAnchors')")) {
  config = config.replace(
    "          sidebarPath: require.resolve('./sidebars.js'),",
    "          sidebarPath: require.resolve('./sidebars.js'),\n          rehypePlugins: [[require('./src/rehype/explicitAnchors'), {}]],",
  );
}
if (!config.includes("to: '/adversarygraph-integration'")) {
  config = config.replace(
    "items: [\n        { to: '/attack-activity-log-source-catalog'",
    "items: [\n        { to: '/adversarygraph-integration', label: 'AdversaryGraph Integration', position: 'left' },\n        { to: '/attack-activity-log-source-catalog'",
  );
}

const requiredConfigMarkers = [
  "  onBrokenLinks: 'throw',",
  "  onBrokenAnchors: 'throw',",
  "      onBrokenMarkdownLinks: 'throw',",
  "require('./src/rehype/explicitAnchors')",
  "to: '/adversarygraph-integration'",
];
const missingConfigMarkers = requiredConfigMarkers.filter((marker) => !config.includes(marker));
if (missingConfigMarkers.length > 0) {
  throw new Error(
    `Unable to apply required documentation configuration to ${configPath}: ${missingConfigMarkers.join(', ')}`,
  );
}
fs.writeFileSync(configPath, config);

console.log(`Applied AdversaryGraph documentation overlay to ${siteDir}`);
