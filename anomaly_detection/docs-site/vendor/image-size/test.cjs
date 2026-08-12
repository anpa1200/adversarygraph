'use strict';

const assert = require('node:assert/strict');
const { imageSize } = require('./index.cjs');

assert.deepEqual(imageSize(Buffer.from('<svg viewBox="0 0 120 80"></svg>')), {
  width: 120,
  height: 80,
  type: 'svg',
});
assert.throws(() => imageSize(Buffer.from('icns\0\0\0\0')), /Only reviewed SVG/);
assert.throws(
  () => imageSize(Buffer.from('icns<svg viewBox="0 0 120 80"></svg>')),
  /Only reviewed SVG/,
);
assert.throws(() => imageSize(Buffer.from('\0\0\0\0JXL ')), /Only reviewed SVG/);
assert.throws(() => imageSize(Buffer.alloc(1024 * 1024 + 1)), /exceeds/);
console.log('Documentation image-size boundary passed.');
