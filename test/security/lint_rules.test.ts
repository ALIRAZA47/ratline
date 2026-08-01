/**
 * RL-M1-008 — the forbidden patterns are unwritable, not merely discouraged.
 *
 * Three rules, three fixtures that violate them, one assertion each that the
 * rule fired. This file is acceptance criterion 4, and it is the only thing
 * standing between "we have a lint rule" and "we had a lint rule".
 *
 * How this works, and why it is arranged this way:
 *
 *   - It runs the REAL eslint.config.js. Nothing is overridden, no inline
 *     config is constructed. Delete a rule from that file and these tests go
 *     red; weaken a `files:` scope so src/** stops being covered and the
 *     configuration-parity test goes red. A test that built its own config
 *     would pass forever while the repository went unpoliced.
 *
 *   - The fixtures live in test/fixtures/lint/, which eslint.config.js lists in
 *     its top-level `ignores`, so `npm run lint` does not fail on files whose
 *     entire purpose is to fail lint. They are reached here with `ignore:
 *     false` and explicit paths. The first test asserts that exclusion is
 *     actually in place, because the other direction of that trade — fixtures
 *     that quietly break the build — is how they would end up deleted.
 *
 *   - It also lints files that MUST NOT trip the rules: the repository layer,
 *     the handle itself, and the two tests that legitimately import the handle
 *     and spawn processes. A rule that fires everywhere passes every
 *     "it fires" assertion and is still wrong, because the first person it
 *     inconveniences will turn it off.
 *
 * One ESLint instance and one lintFiles() call for everything, because each
 * call builds a TypeScript program for the whole project and doing that per
 * test would dominate the suite's runtime.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ESLint, type Linter } from "eslint";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const FIXTURES = {
  dbHandle: "test/fixtures/lint/db_handle_import.ts",
  processSpawning: "test/fixtures/lint/process_spawning.ts",
  shellTemplate: "test/fixtures/lint/shell_template_literal.ts",
};

/**
 * Files that import the handle or spawn processes for good reasons. Linted
 * alongside the fixtures so the rules are proved scoped, not just present.
 */
const EXEMPT = [
  "src/repo/organizations.ts",
  "src/db/internal/handle.ts",
  "test/security/scoped_repository.test.ts",
  "test/security/bind_default.test.ts",
];

const RESTRICTED_IMPORTS = "no-restricted-imports";
const SHELL_RULE = "ratline/no-shell-template-literal";

const eslint = new ESLint({ cwd: ROOT, ignore: false });

let pending: Promise<Map<string, ESLint.LintResult>> | null = null;

function lintTargets(): Promise<Map<string, ESLint.LintResult>> {
  pending ??= eslint
    .lintFiles([...Object.values(FIXTURES), ...EXEMPT].map((file) => join(ROOT, file)))
    .then((results) => new Map(results.map((r) => [relative(ROOT, r.filePath), r])));
  return pending;
}

async function messagesFor(file: string, ruleId: string): Promise<Linter.LintMessage[]> {
  const result = (await lintTargets()).get(file);
  assert.ok(result !== undefined, `${file} produced no lint result at all`);
  return result.messages.filter((message) => message.ruleId === ruleId);
}

/**
 * The resolved `no-restricted-imports` entry for a file, as comparable text.
 *
 * `calculateConfigForFile` is typed as returning `any` and its result holds
 * plugin objects, so it is narrowed to the one property this needs rather than
 * serialised whole.
 */
async function importRuleFor(file: string): Promise<string> {
  const config = (await eslint.calculateConfigForFile(join(ROOT, file))) as {
    readonly rules?: Readonly<Record<string, unknown>>;
  };
  return JSON.stringify(config.rules?.[RESTRICTED_IMPORTS] ?? null);
}

// ---------------------------------------------------------------------------
// The fixtures are excluded from the sweep but not from enforcement
// ---------------------------------------------------------------------------

test("the fixtures are excluded from the normal lint run", async () => {
  // Otherwise `npm run lint` fails on purpose-built violations, someone deletes
  // the fixtures to get CI green, and the rules lose the only thing proving
  // they still work.
  const sweeping = new ESLint({ cwd: ROOT });
  for (const fixture of Object.values(FIXTURES)) {
    assert.equal(
      await sweeping.isPathIgnored(join(ROOT, fixture)),
      true,
      `${fixture} must be in eslint.config.js's top-level ignores`,
    );
  }
});

test("the fixtures are governed by the same configuration as src/**", async () => {
  // The fixtures sit under test/, which is exempt from both import bans. They
  // are re-covered by a later block in eslint.config.js, and this asserts that
  // block resolves to exactly what src/** resolves to. Without it, a fixture
  // could be firing a rule that governs nothing but itself.
  const forSource = await importRuleFor("src/boot.ts");
  // calculateConfigForFile normalises severity, so "error" resolves to 2.
  assert.match(forSource, /^\[2,/, "src/** must carry the import bans at error severity");
  assert.match(forSource, /node:child_process/, "src/** must ban the process-spawning module");
  assert.match(forSource, /db\/internal/, "src/** must ban the database handle");
  assert.equal(
    await importRuleFor(FIXTURES.processSpawning),
    forSource,
    "the fixture directory must carry the src/** import configuration verbatim",
  );
});

// ---------------------------------------------------------------------------
// Acceptance 1-3: each rule fires
// ---------------------------------------------------------------------------

/** The quoted subject ESLint reports, e.g. the import source or the callee. */
const subjects = (messages: readonly Linter.LintMessage[]): (string | undefined)[] =>
  messages.map((message) => /['`]([^'`]+)['`]/.exec(message.message)?.[1]);

test("acceptance 1 — importing the raw database handle outside src/repo fails lint", async () => {
  const messages = await messagesFor(FIXTURES.dbHandle, RESTRICTED_IMPORTS);
  assert.deepEqual(
    subjects(messages),
    ["../../../src/db/internal/handle.ts", "../../../src/db/internal/index.ts"],
    "the handle AND its re-export point must both be blocked",
  );
  for (const message of messages) {
    assert.match(message.message, /Only src\/repo\/ may import it/);
  }
});

test("acceptance 2 — importing a process-spawning module in the control plane fails lint", async () => {
  const messages = await messagesFor(FIXTURES.processSpawning, RESTRICTED_IMPORTS);
  assert.deepEqual(
    subjects(messages),
    ["node:child_process", "child_process"],
    "a ban that knew only one of the two specifiers would be one character from useless",
  );
  for (const message of messages) {
    assert.match(message.message, /control plane executes no processes/);
  }
});

test("acceptance 3 — shell construction by template literal fails lint", async () => {
  const messages = await messagesFor(FIXTURES.shellTemplate, SHELL_RULE);
  assert.deepEqual(
    messages.map((m) => m.messageId),
    ["interpolatedArgument", "commandVariable", "shellInvocation", "interpolatedArgument"],
    "every detector in the rule must be covered by the fixture, in file order",
  );
  assert.deepEqual(
    subjects(messages),
    ["execSync", "command", "ssh", "$"],
    "and each must have matched the construction it was aimed at",
  );
});

// ---------------------------------------------------------------------------
// The rules are scoped, not blanket
// ---------------------------------------------------------------------------

test("the code that legitimately reaches the handle or spawns is not blocked", async () => {
  // src/repo/ is what the handle exists for; the handle imports itself's
  // neighbours; and the two security tests below cannot assert what they assert
  // without importing the handle and spawning the real boot path.
  const blocked: string[] = [];
  for (const file of EXEMPT) {
    for (const message of await messagesFor(file, RESTRICTED_IMPORTS)) {
      blocked.push(`${file}:${String(message.line)} ${message.message}`);
    }
  }
  assert.deepEqual(blocked, [], blocked.join("\n"));
});

test("the shell rule does not fire on the codebase as it stands", async () => {
  // The whole tree is linted by `npm run lint` in CI, so this only needs to
  // cover the files loaded here — but it is the assertion that would catch the
  // rule becoming so broad that the next person disables it.
  const findings: string[] = [];
  for (const file of EXEMPT) {
    for (const message of await messagesFor(file, SHELL_RULE)) {
      findings.push(`${file}:${String(message.line)} ${message.message}`);
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});
