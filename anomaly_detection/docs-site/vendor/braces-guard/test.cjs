const assert = require("node:assert/strict");
const braces = require("./index");
assert.deepEqual(braces.expand("docs/{a,b}.md"), ["docs/a.md", "docs/b.md"]);
assert.deepEqual(braces("{a,b}"), ["(a|b)"]);
assert.deepEqual(braces.expand("{1..3}"), ["1", "2", "3"]);
assert.equal(braces.stringify(braces.parse("x/{a,b}")), "x/{a,b}");
for (const method of [braces, braces.parse, braces.create]) {
  assert.throws(() => method("{".repeat(2000) + "a" + "}".repeat(2000)), /nesting/);
  assert.throws(() => method("x".repeat(4097)), /characters/);
}
let ast = {type:"root",nodes:[]}, root = ast;
for(let i=0;i<1000;i++){const child={type:"brace",nodes:[]};ast.nodes.push(child);ast=child;}
for(const method of [braces.compile, braces.expand, braces.stringify]) assert.throws(()=>method(root), /Unsafe/);
const cycle={nodes:[]};cycle.nodes.push(cycle);assert.throws(()=>braces.compile(cycle),/Unsafe/);
console.log("Bounded braces mitigation tests passed");
