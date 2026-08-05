/**
 * The coverage gates, and the two ways they could be satisfied by nothing
 * (RL-M1-051).
 *
 * Brief §6.3 requires 100% branch coverage on the decision function and §2.4
 * requires 100% line coverage on `src/authz/**`, both enforced in CI. This module
 * is the enforcement. It lives apart from `ci-metrics.ts` because that file runs
 * the suite at import time, and a gate nobody can call in a test is a gate nobody
 * checks.
 *
 * ## The defect this exists because of
 *
 * The gates read node's coverage report and averaged over whatever it contained.
 * A coverage report only contains files that were LOADED, so a file no test ever
 * imports is not reported at 0% — it is absent. `src/authz/never_imported.ts`,
 * carrying three uncovered branches, was demonstrated present on disk while the
 * run printed `src/authz/** line coverage: 100%`. The gate was not wrong about
 * its arithmetic; it was averaging over a set that silently excluded the only
 * file that mattered.
 *
 * That is harmless today because every authorization file is exercised. It stops
 * being harmless from M5 onward, where an authorization module reachable only
 * from a route that is not yet bound would ship completely unexercised under a
 * green gate — and the gate is the whole reason anybody would trust it.
 *
 * The second way is arithmetic rather than set membership: a percentage over a
 * denominator small enough to mean nothing. `pct()` answers 100 when the total is
 * zero, which is the right answer for "no uncovered lines" and the wrong one for
 * "nothing to cover", so a `can.ts` hollowed out to nothing satisfies a gate
 * demanding that every branch be exercised. The gate's own comment claims renaming
 * can.ts cannot switch its own gate off — true, and emptying it could.
 *
 * ## The empty denominator is not zero, which changes the fix
 *
 * RL-M1-051's diagnosis named `pct(0, 0) === 100` as the mechanism. Measured, it
 * is not reachable: a `src/authz/hollow.ts` containing one `export const` and no
 * conditional at all was loaded by a test and reported by node as **1 of 1
 * branches covered**, because V8 counts the module's own top-level body as a
 * branch. A loaded file's branch total is therefore never 0, and a `total === 0`
 * check alone would have been dead code that looked like a fix.
 *
 * So the denominator is checked against a FLOOR rather than against zero. That is
 * a tripwire, not a proof: it cannot tell a gutted decision function from a
 * legitimately simplified one, and it is not trying to. What it guarantees is that
 * `can.ts` reporting 100% of one branch — the shape a hollowed module really takes
 * — fails instead of passing, and that somebody has to look. The floors sit well
 * below today's figures so ordinary refactoring does not trip them; see GATES.
 *
 * `total === 0` is still checked, because a synthesized or future report can carry
 * it and a percentage of nothing must never read as verified.
 *
 * ## Why these are failures rather than warnings
 *
 * None of them is a coverage shortfall, so none has a percentage to report, and
 * the temptation is to print a note and pass. The reason not to: each state means
 * the gate did not measure the thing it claims to measure, and a gate that cannot
 * tell "verified" from "not looked at" is reporting confidence it does not have.
 * Absent is already treated as a failure for the whole pattern, for exactly this
 * reason. These extend the same rule from "no file matched" down to "one file
 * matched nothing" and "the files matched had almost nothing in them".
 *
 * ## What this does not catch
 *
 * A file that IS loaded but only by a test that imports it and asserts nothing.
 * Coverage cannot see the difference between exercised and asserted, and pretending
 * otherwise would be worse than the honest limit. What it does guarantee is that
 * every authorization file on disk was at least executed by something.
 */

import { relative } from "node:path";

/** One file's counts, as node's `test:coverage` event reports them. */
export type CoverageFile = {
  readonly path: string;
  readonly totalBranchCount: number;
  readonly coveredBranchCount: number;
  readonly totalLineCount: number;
  readonly coveredLineCount: number;
};

/** Which of a file's two denominators a gate is asserting against. */
export type Metric = "lines" | "branches";

export type Gate = {
  readonly label: string;
  /** Tested against repo-relative paths with forward slashes. */
  readonly pattern: RegExp;
  readonly metric: Metric;
  readonly required: number;
  /**
   * Fewest `metric` the matched files must contain for the percentage to mean
   * anything. A floor, not a target — see the module docstring for why this is
   * not simply `> 0`.
   */
  readonly minimum: number;
  readonly why: string;
};

export type GateResult = {
  readonly label: string;
  /** The percentage, or null when the gate measured nothing at all. */
  readonly actual: number | null;
  readonly required: number;
  /** Empty when the gate passed. One sentence per reason when it did not. */
  readonly failures: readonly string[];
};

/**
 * A percentage, rounded to two places.
 *
 * Still answers 100 for an empty total, because that is correct for a file with
 * no branches in it and callers of `metrics.json` read it that way. The gate no
 * longer TRUSTS that answer — see `evaluateGate`, which checks the denominator
 * separately rather than by inspecting the percentage, since 100 is also what a
 * genuinely covered file reports.
 */
export const pct = (covered: number, total: number): number =>
  total === 0 ? 100 : Math.round((covered / total) * 10_000) / 100;

/** Repo-relative, forward-slashed, so one comparison works on either platform. */
function normalize(root: string, path: string): string {
  return relative(root, path).split("\\").join("/");
}

/** Aggregate coverage over the report files whose repo-relative path matches. */
export function coverageFor(
  root: string,
  files: readonly CoverageFile[],
  match: RegExp,
): { lines: number; branches: number; totalLines: number; totalBranches: number } | null {
  const hit = files.filter((f) => match.test(normalize(root, f.path)));
  if (hit.length === 0) return null;
  const sum = (pick: (f: CoverageFile) => number) => hit.reduce((n, f) => n + pick(f), 0);
  const totalLines = sum((f) => f.totalLineCount);
  const totalBranches = sum((f) => f.totalBranchCount);
  return {
    lines: pct(sum((f) => f.coveredLineCount), totalLines),
    branches: pct(sum((f) => f.coveredBranchCount), totalBranches),
    totalLines,
    totalBranches,
  };
}

/**
 * Source files a gate's pattern covers, as they exist on disk.
 *
 * `.d.ts` is dropped: a declaration file has no runtime existence, so it can
 * never appear in a coverage report and requiring it to would fail the gate
 * permanently for a file that cannot be executed by anything.
 */
export function sourceFilesMatching(
  root: string,
  allSourcePaths: readonly string[],
  match: RegExp,
): string[] {
  return allSourcePaths
    .map((p) => normalize(root, p))
    .filter((p) => !p.endsWith(".d.ts"))
    .filter((p) => match.test(p))
    .sort();
}

/**
 * Judge one gate against the report and against what is on disk.
 *
 * The two arguments are deliberately independent: the report says what ran, the
 * disk says what exists, and every defect this module was written for is a
 * disagreement between them.
 */
export function evaluateGate(
  root: string,
  gate: Gate,
  reportFiles: readonly CoverageFile[],
  allSourcePaths: readonly string[],
): GateResult {
  const failures: string[] = [];
  const coverage = coverageFor(root, reportFiles, gate.pattern);
  const onDisk = sourceFilesMatching(root, allSourcePaths, gate.pattern);
  const reported = new Set(
    reportFiles
      .map((f) => normalize(root, f.path))
      .filter((p) => gate.pattern.test(p)),
  );

  // Files that exist and never ran. Named individually — the whole failure of the
  // old gate was that this set was invisible, and a count would leave the reader
  // to work out which file it meant.
  const unloaded = onDisk.filter((p) => !reported.has(p));
  if (unloaded.length > 0) {
    failures.push(
      `${gate.label}: ${String(unloaded.length)} file(s) matching the gate were never loaded ` +
        `by any test, so they are absent from the coverage report rather than reported at 0%: ` +
        `${unloaded.join(", ")}. Import each from a test, or delete it. ${gate.why}`,
    );
  }

  if (coverage === null) {
    // Absent is a failure, not a pass. Renaming or moving can.ts would otherwise
    // switch its own gate off silently, which is the failure mode most likely to
    // go unnoticed for months.
    failures.push(`${gate.label}: not measured — expected ${String(gate.required)}%. ${gate.why}`);
    return { label: gate.label, actual: null, required: gate.required, failures };
  }

  const total = gate.metric === "lines" ? coverage.totalLines : coverage.totalBranches;
  const actual = gate.metric === "lines" ? coverage.lines : coverage.branches;

  // Nothing to cover is not coverage. Checked on the denominator rather than by
  // noticing that the percentage is 100, because a fully covered file reports
  // 100 too and the two must not be confused.
  if (total === 0) {
    failures.push(
      `${gate.label}: the files matching this gate contain zero ${gate.metric}, so 100% is a ` +
        `percentage of nothing rather than a measurement. Emptying the module must not satisfy ` +
        `the gate that guards it. ${gate.why}`,
    );
  } else if (total < gate.minimum) {
    failures.push(
      `${gate.label}: the ${gate.metric} total across the files matching this gate is ` +
        `${String(total)}, below the floor of ${String(gate.minimum)}, so ${String(actual)}% is a ` +
        `percentage of almost nothing. Either the module was emptied — a hollowed can.ts reports ` +
        `100% of the one branch V8 attributes to its module body — or the logic moved somewhere ` +
        `this gate cannot see. If the reduction is real and intended, lower the floor in GATES ` +
        `deliberately. ${gate.why}`,
    );
  } else if (actual < gate.required) {
    failures.push(
      `${gate.label}: ${String(actual)}% < ${String(gate.required)}%. ${gate.why}`,
    );
  }

  return { label: gate.label, actual, required: gate.required, failures };
}

/**
 * The gates themselves (RL-M1-013).
 *
 * These two are gated and nothing else is. A blanket coverage target buys tests
 * written to raise a number; these buy the specific guarantee that every path
 * through the decision function has been exercised, including the ones that deny.
 *
 * The `minimum` figures are floors on the denominator, set well below what the
 * code reports today so that ordinary refactoring does not trip them. Measured on
 * 2026-08-05: can.ts reports 34 branches, and src/authz/** reports 2,458 lines
 * across seven files. A drop past these floors is not necessarily wrong; it is
 * necessarily worth reading.
 */
export const GATES: readonly Gate[] = [
  {
    label: "can() branch coverage",
    pattern: /^src\/authz\/can\.ts$/,
    metric: "branches",
    required: 100,
    minimum: 20,
    why: "every path through the decision function must be exercised, especially the ones that deny (brief §6.3)",
  },
  {
    label: "src/authz/** line coverage",
    pattern: /^src\/authz\//,
    metric: "lines",
    required: 100,
    minimum: 1_000,
    why: "the authorization module is the differentiator; an unexercised line here is an unknown permission outcome (brief §6.3)",
  },
];
