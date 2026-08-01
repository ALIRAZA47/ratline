/**
 * Guards the scaffold itself (RL-M1-001).
 *
 * These assertions exist because the compiler flags they check are the
 * difference between "strict TypeScript" as a claim and as a fact. Loosening
 * `strict`, dropping `noUncheckedIndexedAccess`, or removing
 * `erasableSyntaxOnly` would all typecheck perfectly well and quietly weaken
 * the codebase. This test makes that a build failure instead.
 *
 * It reads tsconfig.json as text and strips comments, because the file is JSONC
 * and there is no JSON parser in the standard library that accepts comments.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Strip `//` line comments that sit outside string literals. */
function stripJsonComments(source: string): string {
  let out = "";
  let inString = false;
  let escaped = false;

  for (let i = 0; i < source.length; i++) {
    const ch = source[i];
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && source[i + 1] === "/") {
      while (i < source.length && source[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    out += ch;
  }
  return out;
}

function readTsconfig(): { compilerOptions: Record<string, unknown> } {
  const raw = readFileSync(join(ROOT, "tsconfig.json"), "utf8");
  return JSON.parse(stripJsonComments(raw)) as { compilerOptions: Record<string, unknown> };
}

test("tsconfig enables the strictness the acceptance names", () => {
  const { compilerOptions } = readTsconfig();
  for (const flag of ["strict", "noUncheckedIndexedAccess", "exactOptionalPropertyTypes"]) {
    assert.equal(compilerOptions[flag], true, `tsconfig must set ${flag}: true`);
  }
});

test("tsconfig stays inside the subset Node can strip", () => {
  const { compilerOptions } = readTsconfig();
  // Without this, an enum or a parameter property compiles here and then fails
  // at runtime under `node --experimental-strip-types`, which is how we run.
  assert.equal(compilerOptions["erasableSyntaxOnly"], true);
  assert.equal(compilerOptions["noEmit"], true, "there is no build step; tsc is a checker only");
});

test("the repository layout matches the plan", () => {
  const required = [
    "src/db/internal",
    "src/db/migrations",
    "src/repo",
    "src/authz",
    "src/api",
    "src/jobs",
    "src/crypto",
    "src/ops",
    "src/web/lib/design",
    "agent/cmd/ratline-agent",
    "agent/cmd/ratline-privd",
    "test/authz",
    "test/security",
    "test/integration",
  ];
  const missing = required.filter((p) => !existsSync(join(ROOT, p)));
  assert.deepEqual(missing, [], `missing directories from docs/PLAN.md §7: ${missing.join(", ")}`);
});

test("the constraint-critical directories document their rule", () => {
  // A developer who opens src/repo/ should learn the AuthzContext rule there,
  // not by reading an ADR they do not know exists.
  const documented = ["src/db/internal", "src/repo", "src/authz", "src/ops", "test/security", "test/authz"];
  const undocumented = documented.filter((p) => !existsSync(join(ROOT, p, "README.md")));
  assert.deepEqual(undocumented, [], `these directories carry a load-bearing rule and need a README`);
});
