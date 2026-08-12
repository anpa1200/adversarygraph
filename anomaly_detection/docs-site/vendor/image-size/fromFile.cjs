'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { imageSize } = require('./index.cjs');

const MAX_SVG_BYTES = 1024 * 1024;

async function imageSizeFromFile(filePath) {
  if (path.extname(filePath).toLowerCase() !== '.svg') {
    throw new TypeError('Only reviewed SVG documentation assets are supported');
  }
  const handle = await fs.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_SVG_BYTES) {
      throw new TypeError('SVG file is empty, non-regular, or exceeds the 1 MiB build limit');
    }
    return imageSize(await handle.readFile());
  } finally {
    await handle.close();
  }
}

module.exports = imageSizeFromFile;
module.exports.imageSizeFromFile = imageSizeFromFile;
module.exports.default = imageSizeFromFile;
