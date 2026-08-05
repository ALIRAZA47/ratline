/**
 * The authorization coverage gates cannot be satisfied by nothing (RL-M1-051).
 *
 * Two properties, and both are about the gate reporting confidence it does not
 * have rather than about a coverage shortfall:
 *
 * 1. A file under `src/authz/**` that no test imports FAILS the gate. It used to
 *    be invisible — a coverage report contains only the files that were loaded, so
 *    an unimported file is absent from it rather than reported at 0%, and the
 *    average over what remained came out at 100%.
 * 2. A module with (next to) no branches cannot satisfy the branch gate by having
 *    nothing to cover. `pct()` answers 100 for an empty denominator, so hollowing
 *    out `can.ts` satisfied the gate that guards it.
 *
 * The second one is not shaped the way the task's diagnosis assumed, and the
 * measurement is recorded in `scripts/coverage_gate.ts`: a real module with no
 * conditional in it reports ONE branch, not zero, because V8 counts the module
 * body. A `total === 0` check would have been dead code, so the gate checks the
 * denominator against a floor. Both are tested below — zero because a synthesized
 * report can carry it, the floor because real coverage is what CI runs on.
 *
 * ## Why these drive the gate with synthetic reports
 *
 * The alternative was a fixture file committed under `src/authz/` that no test
 * imports, which is precisely the defect — a permanently unexercised
 * authorization file, kept deliberately, in the directory whose whole claim is
 * that nothing there is unexercised. It would also have to be exempted from the
 * gate to keep the build green, and an exemption list is the mechanism this task
 * exists to remove.
 *
 * So the gate is driven as a function over two inputs it cannot tell apart from
 * the real ones: a coverage report and a list of source paths. The fixture
 * directory holds ordinary files under `test/fixtures/coverage/` so the disk half
 * is real rather than a string literal, and the pattern points there instead of at
 * `src/authz/`.
 *
 * The real gate constants are exercised too — see the last two tests, which assert
 * that GATES still points at the paths the brief names. A gate tested only through
 * a fixture pattern would keep passing after somebody moved `can.ts`.
 *
 * Verified by mutation, recorded on the task: with `src/authz/never_imported.ts`
 * present the suite reported `src/authz/** line coverage: 100%` and passed; with
 * this module in place the same file fails the gate by name.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { globSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  coverageFor,
  evaluateGate,
  GATES,
  pct,
  sourceFilesMatching,
  type CoverageFile,
  type Gate,
} from "../../scripts/coverage_gate.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const FIXTURES = "test/fixtures/coverage";

/** A report entry with everything covered, so only the property under test varies. */
function covered(path: string, lines: number, branches: number): CoverageFile {
  return {
    path: join(ROOT, path),
    totalLineCount: lines,
    coveredLineCount: lines,
    totalBranchCount: branches,
    coveredBranchCount: branches,
  };
}

const LINE_GATE: Gate = {
  label: "fixture line coverage",
  pattern: new RegExp(`^${FIXTURES}/`),
  metric: "lines",
  required: 100,
  minimum: 5,
  why: "the fixture stands in for src/authz/**",
};

const BRANCH_GATE: Gate = {
  label: "fixture branch coverage",
  pattern: new RegExp(`^${FIXTURES}/decides\\.ts$`),
  metric: "branches",
  required: 100,
  minimum: 4,
  why: "the fixture stands in for can.ts",
};

/**
 * The fixture files as they really are on disk.
 *
 * Globbed rather than listed, so the "what exists" half of every test below is
 * the filesystem answering rather than this file asserting. A hand-written list
 * would keep passing after somebody deleted the fixtures, and the property under
 * test is exactly a disagreement between disk and report.
 */
const ON_DISK = globSync(`${FIXTURES}/*.ts`, { cwd: ROOT }).map((p) => join(ROOT, p)).sort();

test("the fixture directory holds the two files the tests below rely on", () => {
  assert.deepEqual(
    ON_DISK.map((p) => p.slice(ROOT.length + 1).split("\\").join("/")),
    [`${FIXTURES}/decides.ts`, `${FIXTURES}/unimported.ts`],
    "the fixtures are the disk half of every assertion here; without them the rest is vacuous",
  );
});

test("acceptance 1: a matching file no test loaded fails the gate", () => {
  // Both files exist on disk. The report contains one, which is what happens when
  // nothing imports the other: it is not reported at 0%, it is not there at all.
  const report = [covered(`${FIXTURES}/decides.ts`, 10, 4)];

  const result = evaluateGate(ROOT, LINE_GATE, report, ON_DISK);

  assert.equal(
    result.failures.length,
    1,
    "an unloaded file must fail the gate rather than be averaged out of existence",
  );
  assert.match(
    result.failures[0] ?? "",
    /never loaded by any test/,
    "the failure must say the file never ran, not that coverage is low — they need different fixes",
  );
  assert.match(
    result.failures[0] ?? "",
    /unimported\.ts/,
    "the failure must name the file; a count leaves the reader to work out which one",
  );
  // The arithmetic over what DID load is still 100%, which is the whole point:
  // the old gate looked only at this number and passed.
  assert.equal(result.actual, 100);
});

test("acceptance 1: the gate passes when every file on disk was loaded", () => {
  const report = [
    covered(`${FIXTURES}/decides.ts`, 10, 4),
    covered(`${FIXTURES}/unimported.ts`, 3, 0),
  ];

  const result = evaluateGate(ROOT, LINE_GATE, report, ON_DISK);

  assert.deepEqual(result.failures, [], "a fully loaded, fully covered set must pass");
});

test("acceptance 2: a hollowed module cannot satisfy the branch gate", () => {
  // What a hollowed-out decision function really reports: loaded, fully covered,
  // and holding the single branch V8 attributes to the module body. 1/1 is 100%
  // and must not read as verified.
  const report = [covered(`${FIXTURES}/decides.ts`, 2, 1)];

  const result = evaluateGate(ROOT, BRANCH_GATE, report, [join(ROOT, FIXTURES, "decides.ts")]);

  assert.equal(result.failures.length, 1);
  assert.match(
    result.failures[0] ?? "",
    /branches total across the files matching this gate is 1, below the floor of 4/,
    "the failure must name the denominator, not report a percentage shortfall — they need different fixes",
  );
  assert.match(
    result.failures[0] ?? "",
    /lower the floor in GATES deliberately/,
    "a legitimate shrink needs a stated way out, or the next person disables the gate instead",
  );
  assert.equal(result.actual, 100, "pct() still answers 100 — the gate stops trusting it");
});

test("acceptance 2: a report claiming zero branches also fails", () => {
  // Not reachable from node's own coverage — a loaded module always reports at
  // least one branch — but reachable from a synthesized or future report, and a
  // percentage of nothing must never read as verified.
  const report = [covered(`${FIXTURES}/decides.ts`, 2, 0)];
  const result = evaluateGate(ROOT, BRANCH_GATE, report, [join(ROOT, FIXTURES, "decides.ts")]);

  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0] ?? "", /zero branches/);
});

test("acceptance 2: a module with branches, all covered, passes the branch gate", () => {
  const report = [covered(`${FIXTURES}/decides.ts`, 10, 6)];
  const result = evaluateGate(ROOT, BRANCH_GATE, report, [join(ROOT, FIXTURES, "decides.ts")]);
  assert.deepEqual(result.failures, [], "real branches, all exercised, is the passing case");
});

test("an uncovered branch still fails the branch gate", () => {
  // The original gate's job, kept under test so the two new checks cannot be
  // mistaken for a replacement of it.
  const report: CoverageFile[] = [
    {
      path: join(ROOT, FIXTURES, "decides.ts"),
      totalLineCount: 10,
      coveredLineCount: 10,
      totalBranchCount: 6,
      coveredBranchCount: 5,
    },
  ];
  const result = evaluateGate(ROOT, BRANCH_GATE, report, [join(ROOT, FIXTURES, "decides.ts")]);

  assert.equal(result.failures.length, 1);
  assert.match(result.failures[0] ?? "", /83\.33% < 100%/);
});

test("a gate matching nothing at all is not measured, and that is a failure", () => {
  const result = evaluateGate(ROOT, BRANCH_GATE, [], []);

  assert.equal(result.actual, null);
  assert.equal(result.failures.length, 1);
  assert.match(
    result.failures[0] ?? "",
    /not measured/,
    "moving the file the gate names must not switch the gate off",
  );
});

test("pct answers 100 for an empty total, and callers must not read that as coverage", () => {
  // Asserted rather than left implicit, because the gate above is built on
  // knowing this and a future simplification of pct() would break it silently.
  assert.equal(pct(0, 0), 100);
  assert.equal(pct(1, 2), 50);
  assert.equal(pct(2, 3), 66.67);
});

test("coverageFor reports the raw totals, not only the percentages", () => {
  const report = [covered(`${FIXTURES}/decides.ts`, 10, 4), covered(`${FIXTURES}/unimported.ts`, 3, 0)];
  const coverage = coverageFor(ROOT, report, LINE_GATE.pattern);

  assert.ok(coverage, "the fixture files match the fixture pattern");
  assert.equal(coverage.totalLines, 13);
  assert.equal(coverage.totalBranches, 4);
  assert.equal(coverage.lines, 100);
});

test("declaration files are excluded from what a gate expects to have run", () => {
  // A .d.ts has no runtime existence, so it can never appear in a coverage report.
  // Requiring it to would fail the gate permanently for a file nothing can execute.
  const matched = sourceFilesMatching(ROOT, [...ON_DISK, join(ROOT, FIXTURES, "types.d.ts")], LINE_GATE.pattern);

  assert.deepEqual(matched, [`${FIXTURES}/decides.ts`, `${FIXTURES}/unimported.ts`]);
});

test("the real gates still name the paths the brief gates", () => {
  // The tests above prove the mechanism against a fixture pattern. This one proves
  // the mechanism is pointed at the right files, which no fixture can.
  const labels = GATES.map((g) => g.label);
  assert.deepEqual(labels, ["can() branch coverage", "src/authz/** line coverage"]);

  const can = GATES.find((g) => g.label === "can() branch coverage");
  const authz = GATES.find((g) => g.label === "src/authz/** line coverage");
  assert.ok(can && authz);

  assert.equal(can.metric, "branches", "brief §6.3 requires BRANCH coverage on the decision function");
  assert.equal(can.required, 100);
  assert.ok(can.pattern.test("src/authz/can.ts"), "the can() gate must match src/authz/can.ts");
  assert.ok(!can.pattern.test("src/authz/roles.ts"), "the can() gate is one file, not the directory");

  // A floor above 1 is the whole of acceptance 2 on the real gate: a hollowed
  // can.ts reports one branch, so a floor of 0 or 1 would let it through.
  assert.ok(can.minimum > 1, "the can() gate's floor must exclude a module with only its own body");
  assert.ok(authz.minimum > 1);

  assert.equal(authz.metric, "lines");
  assert.equal(authz.required, 100);
  assert.ok(authz.pattern.test("src/authz/roles.ts"));
  assert.ok(!authz.pattern.test("src/repo/scope.ts"), "the directory gate must not reach outside src/authz");
});

test("every file really in src/authz is claimed by the directory gate", () => {
  // Guards against the gate's pattern and the directory drifting apart — a
  // vacuous match set is how this class of test rots. Uses the real tree, so it
  // fails if src/authz is renamed without the gate following.
  const authz = GATES.find((g) => g.label === "src/authz/** line coverage");
  assert.ok(authz);

  const real = sourceFilesMatching(
    ROOT,
    [
      join(ROOT, "src/authz/can.ts"),
      join(ROOT, "src/authz/roles.ts"),
      join(ROOT, "src/repo/scope.ts"),
    ],
    authz.pattern,
  );
  assert.deepEqual(real, ["src/authz/can.ts", "src/authz/roles.ts"]);
});
