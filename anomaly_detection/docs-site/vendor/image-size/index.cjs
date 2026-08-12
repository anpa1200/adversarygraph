'use strict';

const MAX_SVG_BYTES = 1024 * 1024;
const SVG_PREFIX_BYTES = 64 * 1024;

function positiveNumber(value) {
  if (typeof value !== 'string') return undefined;
  const match = value.trim().match(/^([0-9]+(?:\.[0-9]+)?)(?:px)?$/i);
  if (!match) return undefined;
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function attribute(source, name) {
  const pattern = new RegExp(`\\b${name}\\s*=\\s*(["'])([^"']+)\\1`, 'i');
  return source.match(pattern)?.[2];
}

function imageSize(input) {
  if (!(input instanceof Uint8Array) && !Buffer.isBuffer(input)) {
    throw new TypeError('Expected an image byte buffer');
  }
  if (input.byteLength === 0 || input.byteLength > MAX_SVG_BYTES) {
    throw new TypeError('SVG input is empty or exceeds the 1 MiB build limit');
  }

  const source = Buffer.from(input.buffer, input.byteOffset, Math.min(input.byteLength, SVG_PREFIX_BYTES))
    .toString('utf8');
  const svgPrefix = source.match(
    /^\uFEFF?\s*(?:<\?xml[^>]*>\s*)?(?:<!--[\s\S]*?-->\s*)*<svg\b/i,
  )?.[0];
  if (!svgPrefix) {
    throw new TypeError('Only reviewed SVG documentation assets are supported');
  }
  const svgStart = svgPrefix.toLowerCase().lastIndexOf('<svg');
  const svgEnd = source.indexOf('>', svgStart);
  if (svgEnd < 0) throw new TypeError('Incomplete SVG root element');
  const root = source.slice(svgStart, svgEnd + 1);

  let width = positiveNumber(attribute(root, 'width'));
  let height = positiveNumber(attribute(root, 'height'));
  if (!width || !height) {
    const viewBox = attribute(root, 'viewBox')
      ?.trim()
      .split(/[\s,]+/)
      .map(Number);
    if (viewBox?.length === 4 && viewBox.every(Number.isFinite)) {
      width ||= viewBox[2] > 0 ? viewBox[2] : undefined;
      height ||= viewBox[3] > 0 ? viewBox[3] : undefined;
    }
  }
  if (!width || !height) throw new TypeError('SVG has no positive width/height or viewBox');
  return { width, height, type: 'svg' };
}

module.exports = imageSize;
module.exports.imageSize = imageSize;
module.exports.default = imageSize;
