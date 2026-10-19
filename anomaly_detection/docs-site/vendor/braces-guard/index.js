"use strict";
// Repository-maintained mitigation for CVE-2026-93687. Fail closed before
// upstream recursive walkers. Internal upstream calls remain behind this API.
const upstream = require("./upstream-index");
const MAX_DEPTH = 64, MAX_LENGTH = 4096, MAX_NODES = 10000;
function guard(value) {
  if (typeof value === "string") {
    if (value.length > MAX_LENGTH) throw new RangeError("Brace input exceeds 4096 characters");
    let depth = 0;
    for (const char of value) {
      if (char === "{" && ++depth > MAX_DEPTH) throw new RangeError("Brace nesting exceeds 64 levels");
      if (char === "}") depth = Math.max(0, depth - 1);
    }
  } else if (Array.isArray(value)) {
    if (value.length > MAX_NODES) throw new RangeError("Too many brace patterns");
    for (const pattern of value) {
      if (typeof pattern !== "string") throw new TypeError("Brace pattern must be a string");
      guard(pattern);
    }
  } else if (value && typeof value === "object") {
    const queue = [[value, 0]], seen = new Set();
    while (queue.length) {
      const [node, depth] = queue.pop();
      if (depth > MAX_DEPTH || seen.size >= MAX_NODES || seen.has(node)) throw new RangeError("Unsafe brace AST");
      seen.add(node);
      if (Array.isArray(node.nodes)) for (const child of node.nodes) queue.push([child, depth + 1]);
    }
  }
}
function bounded(fn) { return function(value, ...args) { guard(value); return fn.call(upstream, value, ...args); }; }
const braces = bounded(upstream);
for (const method of ["parse", "compile", "expand", "stringify", "create"]) braces[method] = bounded(upstream[method]);
module.exports = braces;
