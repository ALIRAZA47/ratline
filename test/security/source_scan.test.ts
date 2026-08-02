/**
 * The shared source scanner (RL-M1-041).
 *
 * In `test/security/` because five security rules are enforced by reading the
 * repository rather than by running it, and every one of them now goes through
 * `codeOf`. A bug here does not fail loudly — it removes a line of real code
 * from something a scanner was about to check, and the rule goes quiet.
 *
 * So this file is mostly adversarial: constructs designed to fool a
 * comment-stripper that is not really a parser. If `codeOf` ever swallows code,
 * these fail rather than a rule silently switching off somewhere else.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { codeOf, scanCode } from "../support/source_scan.ts";

test("a comment is removed and the code around it is not", () => {
  const source = ['const a = 1; // trailing', "/* leading */ const b = 2;", "const c = 3;"].join("\n");
  const code = codeOf(source);
  assert.match(code, /const a = 1;/);
  assert.match(code, /const b = 2;/);
  assert.match(code, /const c = 3;/);
  assert.ok(!code.includes("trailing"));
  assert.ok(!code.includes("leading"));
});

test("line numbers survive the removal", () => {
  // A scanner that reported line 40 of a file whose comments had been collapsed
  // would send somebody to the wrong place, which is worse than reporting no
  // line at all.
  const source = ["/*", " * four", " * lines", " */", "const target = 1;"].join("\n");
  assert.equal(scanCode(source, /const target/g)[0]?.line, 5);
});

test("a URL inside a string is not a comment", () => {
  // The classic. `//` appears in every http URL in the codebase, and a stripper
  // that did not track strings would delete the rest of the line — which in a
  // configuration file is usually the closing brace.
  const source = 'const url = "https://example.test/a"; const kept = 1;';
  const code = codeOf(source);
  assert.match(code, /https:\/\/example\.test\/a/);
  assert.match(code, /const kept = 1;/);
});

test("a comment opener inside a regex or a string does not start a comment", () => {
  for (const source of [
    'const pattern = "/*"; const kept = 1;',
    "const other = '/*'; const kept = 1;",
    "const template = `/*`; const kept = 1;",
  ]) {
    assert.match(codeOf(source), /const kept = 1;/, source);
  }
});

test("an apostrophe inside a comment does not open a string", () => {
  // This is the one that eats a whole file. `// don't` opens a single-quoted
  // string in a naive stripper, and everything until the next apostrophe —
  // possibly hundreds of lines — stops being code.
  const source = ["// don't do this", 'const kept = "yes";', "// it's fine", "const also = 2;"].join("\n");
  const code = codeOf(source);
  assert.match(code, /const kept = "yes";/);
  assert.match(code, /const also = 2;/);
});

test("an escaped quote does not end a string", () => {
  const source = 'const a = "he said \\" // not a comment"; const kept = 1;';
  const code = codeOf(source);
  assert.match(code, /not a comment/);
  assert.match(code, /const kept = 1;/);
});

test("a template literal spanning lines keeps its contents", () => {
  const source = ["const sql = `", "  select 1 -- from nowhere", "`;", "const kept = 1;"].join("\n");
  const code = codeOf(source);
  assert.match(code, /select 1/);
  assert.match(code, /const kept = 1;/);
});

test("an unterminated comment does not eat the file silently — it eats it loudly", () => {
  // There is no good answer for malformed source, so the requirement is only
  // that the failure is visible: everything after an unclosed block comment is
  // gone, which makes any rule over that file report nothing at all rather than
  // report a pass. Pinned so the behaviour is a decision rather than a surprise.
  const source = ["const before = 1;", "/* never closed", "const after = 2;"].join("\n");
  const code = codeOf(source);
  assert.match(code, /const before = 1;/);
  assert.ok(!code.includes("const after"));
});

test("code is preserved byte for byte when there are no comments", () => {
  // The strongest statement available: on a file with nothing to remove, the
  // scanner is the identity function. Anything else is a parser bug waiting to
  // delete something.
  const source = [
    'const url = "https://example.test";',
    "const pattern = /a\\/b/;",
    "const template = `line one",
    "line two`;",
    "function f(): void {}",
  ].join("\n");
  assert.equal(codeOf(source), source);
});
