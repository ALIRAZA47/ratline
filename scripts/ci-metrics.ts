#!/usr/bin/env node --experimental-strip-types
/**
 * Runs the test suite and writes the machine-readable signals that
 * `./scripts/tasks render` and the `tasks done` gate consume (RL-M1-002).
 *
 *   .ratline/metrics.json          test counts and coverage, per brief §2.4
 *   .ratline/security-findings.json  open findings by severity
 *
 * It does NOT write .ratline/ci-status.json. That file means "the whole
 * pipeline was green", which only CI can honestly assert — lint and typecheck
 * run as separate steps. Writing it here would let a local run mint its own
 * green light and quietly defeat the done gate.
 *
 * Suites are split by directory so STATUS.md can report them separately:
 *   test/authz/**         the authorization matrix
 *   test/integration/**   real hosts only; excluded here, see --integration
 *   everything else       unit
 *
 * Exit status is non-zero if any test failed, so CI fails the build.
 *
 * Usage:  ./scripts/ci-metrics [--integration]
 */

import { run } from "node:test";
import { existsSync, globSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  coverageFor,
  evaluateGate,
  GATES,
  type CoverageFile,
} from "./coverage_gate.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, ".ratline");
/** Written by test/authz/matrix.test.ts. See readMatrixReport below. */
const MATRIX_REPORT = join(OUT_DIR, "authz-matrix.json");

type Counts = { tests: number; passed: number; failed: number };
type Suite = { passed: number; total: number };

type CoverageTotals = { coveredLinePercent: number; coveredBranchPercent: number };

/**
 * A string from an untyped event payload, or undefined.
 *
 * The stream is typed as Record<string, unknown>, so coercing with String()
 * would render an object as "[object Object]" — a failure named that is a
 * failure nobody can find.
 */
function text(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** One failing test, enough to act on without re-running the suite locally. */
export type Failure = { readonly name: string; readonly file: string; readonly message: string };

async function runSuite(files: string[], coverage: boolean): Promise<{
  counts: Counts;
  perFile: Map<string, Counts>;
  files: CoverageFile[];
  totals: CoverageTotals | null;
  failures: Failure[];
}> {
  if (files.length === 0) {
    return {
      counts: { tests: 0, passed: 0, failed: 0 },
      perFile: new Map(),
      files: [],
      totals: null,
      failures: [],
    };
  }

  let counts: Counts = { tests: 0, passed: 0, failed: 0 };
  /**
   * Counts attributed to the file that produced them (RL-M1-048).
   *
   * This exists so the authorization suite can be reported separately WITHOUT
   * being executed a second time. node:test emits one `test:summary` per file as
   * well as one for the whole run, so the split is already in the stream and the
   * previous version paid for it by re-running the most expensive suite in the
   * project — the 630-cell matrix — purely to obtain a subtotal.
   */
  const perFile = new Map<string, Counts>();
  let covFiles: CoverageFile[] = [];
  let totals: CoverageTotals | null = null;
  const failures: Failure[] = [];

  const stream = run({ files, coverage, concurrency: true });
  stream.on("data", (event: { type: string; data: Record<string, unknown> }) => {
    // WHY a failing test is collected here rather than left to the reporter:
    // this script drains the stream and prints counts, and the first time CI
    // ever ran it reported "374/592 passed" with no indication of which 218
    // failed or why. A count is a signal that something is wrong and no help
    // at all in fixing it — the failure had to be reproduced locally to be
    // read, which defeats the point of running it here.
    if (event.type === "test:fail") {
      const details = event.data["details"] as { error?: { message?: string; cause?: unknown } } | undefined;
      const error = details?.error;
      const cause = error?.cause;
      // The ASSERTION's message when there is one, the wrapper's otherwise.
      // node:test wraps a failed assertion in a generic "test failed" error and
      // puts the useful text on `cause`, so reading only the outer message would
      // print the same sentence for every failure.
      const causeMessage =
        typeof cause === "object" && cause !== null && "message" in cause
          ? text(cause.message)
          : undefined;
      failures.push({
        name: text(event.data["name"]) ?? "unnamed",
        file: relative(ROOT, text(event.data["file"]) ?? "unknown"),
        message: causeMessage ?? error?.message ?? "no message",
      });
    }
  });
  stream.on("data", (event: { type: string; data: Record<string, unknown> }) => {
    if (event.type !== "test:summary") return;
    const c = event.data["counts"] as Counts | undefined;
    if (!c) return;

    // The run-level summary is the one with no file. Every other summary belongs
    // to a file, and adding them up would double-count against this total.
    const file = text(event.data["file"]);
    if (file === undefined) {
      counts = c;
      return;
    }
    perFile.set(relative(ROOT, file), c);
  });
  // Coverage gets its own handler rather than another branch in the one above.
  // Folding it in there is what I did first, and the early `return` for a
  // non-summary event made this branch unreachable: coverage silently stopped
  // being collected, both gates reported "not measured", and the build failed
  // for a reason that had nothing to do with coverage. `tsc` caught it — the
  // comparison narrowed to two string literals that cannot overlap — which is
  // the argument for strict mode earning its keep on a build script.
  stream.on("data", (event: { type: string; data: Record<string, unknown> }) => {
    if (event.type !== "test:coverage") return;
    const summary = event.data["summary"] as
      | { files?: CoverageFile[]; totals?: CoverageTotals }
      | undefined;
    covFiles = summary?.files ?? [];
    totals = summary?.totals ?? null;
  });
  // Drain so the stream completes; failures are reported via counts, and the
  // reporter output is not wanted here.
  stream.resume();
  await new Promise<void>((res, rej) => {
    stream.on("end", () => res());
    stream.on("error", rej);
  });

  return { counts, perFile, files: covFiles, totals, failures };
}

/**
 * Print failing tests by name, for both modes.
 *
 * Named, not counted. Capped so a wholesale breakage does not bury the gate
 * output below it, and the cap says how much it dropped rather than trailing off
 * silently — the first CI run reported "374/592 passed" with no indication of
 * which 218 failed, and the failure had to be reproduced locally to be read.
 */
function reportFailures(failures: Failure[]): void {
  if (failures.length === 0) return;

  const shown = 25;
  console.error(`\n${String(failures.length)} test(s) failed:`);
  for (const failure of failures.slice(0, shown)) {
    console.error(`  ${failure.file} — ${failure.name}`);
    console.error(`      ${failure.message.split("\n")[0] ?? ""}`);
  }
  if (failures.length > shown) {
    console.error(`  ... and ${String(failures.length - shown)} more`);
  }
}

/** Add up the per-file counts whose path is under `directory`. */
function countsUnder(perFile: Map<string, Counts>, directory: string): Counts {
  const prefix = join("test", directory);
  const total: Counts = { tests: 0, passed: 0, failed: 0 };
  for (const [path, counts] of perFile) {
    if (!path.startsWith(prefix)) continue;
    total.tests += counts.tests;
    total.passed += counts.passed;
    total.failed += counts.failed;
  }
  return total;
}

function suiteOf(counts: Counts): Suite {
  return { passed: counts.passed, total: counts.tests };
}

/**
 * The authorization matrix's own result (RL-M1-025).
 *
 * `authz_matrix` counts TEST CASES in test/authz/, which is a dozen-ish. The
 * matrix is 567 cells, and the pass rate STATUS should report is that one.
 *
 * Staleness is handled by deletion rather than by a timestamp: main() removes
 * the file before the suite runs, so a report present afterwards was written by
 * this run and a missing one means the matrix did not execute. There is no
 * arrangement under which yesterday's green matrix is reported as today's —
 * which matters more here than the number itself, because a stale security
 * signal is believed.
 */
function readMatrixReport(): Record<string, unknown> {
  if (!existsSync(MATRIX_REPORT)) {
    return {
      executed: false,
      note:
        "the authorization matrix did not run — most likely no database. " +
        "It is NOT green; it is unknown. Run ./scripts/pg start.",
    };
  }
  return JSON.parse(readFileSync(MATRIX_REPORT, "utf8")) as Record<string, unknown>;
}

/**
 * The integration files, and only those (RL-M1-048).
 *
 * Separate from main() rather than a branch inside it, because the two modes
 * measure different things and share almost nothing: there is no coverage to
 * gate, no matrix report, and no security-findings file. Folding them together
 * with conditionals is how the previous version ended up running the whole suite
 * to obtain four files' worth of result.
 *
 * The counts go to their own file with their own timestamp. metrics.json points
 * at it rather than absorbing it, so nobody can read this run's numbers as
 * belonging to a different run.
 */
async function runIntegrationOnly(files: string[]): Promise<void> {
  if (files.length === 0) {
    // Not a silent success. An empty glob here means the files moved or the
    // pattern rotted, and reporting "0/0 passed" for that is how a suite
    // disappears without anybody noticing.
    console.error("no files under test/integration — nothing was verified.");
    process.exitCode = 1;
    return;
  }

  const result = await runSuite(files, false);

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(
    join(OUT_DIR, "metrics-integration.json"),
    `${JSON.stringify(
      {
        integration: suiteOf(result.counts),
        files: files.length,
        measured_at: new Date().toISOString(),
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  console.log(
    `integration: ${result.counts.passed}/${result.counts.tests} passed ` +
      `across ${files.length} file(s)`,
  );
  console.log(`wrote ${relative(ROOT, join(OUT_DIR, "metrics-integration.json"))}`);

  reportFailures(result.failures);
  if (result.counts.failed > 0) process.exitCode = 1;
}

async function main(): Promise<void> {
  const all = globSync("test/**/*.test.ts", { cwd: ROOT }).map((p) => join(ROOT, p));
  const isAuthz = (p: string) => relative(ROOT, p).startsWith(join("test", "authz"));
  const isIntegration = (p: string) => relative(ROOT, p).startsWith(join("test", "integration"));

  // `--integration` runs the integration files INSTEAD of the rest, not in
  // addition (RL-M1-048). It used to mean "and also", which is why the database
  // job re-ran all ~600 tests the code job had just run, for four extra files'
  // worth of signal.
  //
  // The flag keeps its name because the workflow and anyone's muscle memory use
  // it, and "run the integration tests" is what a person means by it. What
  // changed is that it no longer silently brings the whole suite along.
  if (process.argv.includes("--integration")) {
    await runIntegrationOnly(all.filter(isIntegration));
    return;
  }

  const unitFiles = all.filter((p) => !isAuthz(p) && !isIntegration(p));
  const authzFiles = all.filter(isAuthz);

  // Cleared before the run so its presence afterwards proves this run wrote it.
  rmSync(MATRIX_REPORT, { force: true });

  // ONE run, and the split comes out of it. Coverage has to be measured over
  // unit and authz together — the authorization module is exercised by both, and
  // measuring them separately would understate it — and the per-file counts in
  // the stream give the authz subtotal without executing the matrix twice.
  const main = await runSuite([...unitFiles, ...authzFiles], true);
  const authzCounts = countsUnder(main.perFile, "authz");

  const authzCoverage = coverageFor(ROOT, main.files, /^src\/authz\//);
  const canCoverage = coverageFor(ROOT, main.files, /^src\/authz\/can\.ts$/);

  const unitCounts: Counts = {
    tests: main.counts.tests - authzCounts.tests,
    passed: main.counts.passed - authzCounts.passed,
    failed: main.counts.failed - authzCounts.failed,
  };

  // A guard, not a formality. The subtraction above is only correct if every
  // file's summary was seen; a future node:test that stops emitting per-file
  // summaries would silently make `authz_matrix` read 0/0 and `unit` absorb it,
  // which looks like a passing run with a suite that quietly vanished.
  if (main.counts.tests > 0 && main.perFile.size !== unitFiles.length + authzFiles.length) {
    throw new Error(
      `per-file summaries: got ${main.perFile.size}, expected ` +
        `${unitFiles.length + authzFiles.length}. The unit/authz split is derived from ` +
        `them, so an incomplete set would misreport both suites rather than fail. ` +
        `See countsUnder in this file.`,
    );
  }

  const metrics: Record<string, unknown> = {
    unit: suiteOf(unitCounts),
    measured_at: new Date().toISOString(),
  };
  if (authzFiles.length > 0) metrics["authz_matrix"] = suiteOf(authzCounts);
  metrics["authz_matrix_cells"] = readMatrixReport();
  // Deliberately NOT merged in from the integration run's file. Folding another
  // run's numbers in here would give them this run's timestamp, and a stale
  // integration result presented as fresh is the failure the matrix report
  // avoids by deletion. Two files, two timestamps, no borrowed freshness.
  metrics["integration_note"] =
    "run separately by the database job — see .ratline/metrics-integration.json";
  if (authzCoverage) metrics["authz_coverage_pct"] = authzCoverage.lines;
  if (canCoverage) metrics["can_branch_coverage_pct"] = canCoverage.branches;

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, "metrics.json"), `${JSON.stringify(metrics, null, 2)}\n`, "utf8");

  // Security findings come from the security suite's own results. A failing
  // security test IS an open finding; anything else would be a number we made
  // up. Severity is not yet modelled per-test, so every failure counts as high
  // until annotations exist.
  //
  // This is written unconditionally, including when the count is zero. An
  // earlier version skipped the write on a green run to avoid clobbering, which
  // meant a finding once recorded never cleared: the suite went green and
  // STATUS.md still reported the gate blocked. A stale security signal is worse
  // than no signal, because it is believed.
  const findings = {
    critical: 0,
    high: main.counts.failed,
    medium: 0,
    at: new Date().toISOString(),
    note: "derived from failing tests in test/security and test/authz",
  };
  writeFileSync(
    join(OUT_DIR, "security-findings.json"),
    `${JSON.stringify(findings, null, 2)}\n`,
    "utf8",
  );

  // ---------------------------------------------------------------------------
  // Coverage gates (RL-M1-013)
  //
  // Brief §6.3: "100% branch coverage on this module, enforced in CI." Enforced
  // means the build fails, not that a number appears on a dashboard — an
  // unenforced target drifts down one uncovered branch at a time, and each one
  // looks reasonable on its own.
  //
  // The gates and their judgement live in ./coverage_gate.ts. They moved there
  // when RL-M1-051 found two ways to satisfy them with nothing — a file no test
  // loads is absent from the report rather than reported at 0%, and a percentage
  // over an empty denominator answers 100 — and neither could be tested while the
  // logic sat inside a script that runs the whole suite on import.
  //
  // `sourcePaths` is what makes the first check possible: the report says what
  // ran, this says what exists, and the gate fails on the difference.
  // ---------------------------------------------------------------------------
  const sourcePaths = globSync(["src/**/*.ts", "src/**/*.tsx"], { cwd: ROOT }).map((p) =>
    join(ROOT, p),
  );
  const results = GATES.map((gate) => evaluateGate(ROOT, gate, main.files, sourcePaths));
  const gateFailures = results.flatMap((r) => r.failures);

  const failed = main.counts.failed;
  console.log(
    `tests: ${main.counts.passed}/${main.counts.tests} passed` +
      (main.totals ? `, lines ${main.totals.coveredLinePercent.toFixed(2)}%` : ""),
  );
  console.log(`wrote ${relative(ROOT, join(OUT_DIR, "metrics.json"))}`);

  const matrix = metrics["authz_matrix_cells"] as Record<string, unknown>;
  console.log(
    matrix["executed"] === true
      ? `authorization matrix: ${String(matrix["passed"])}/${String(matrix["cells"])} cells — ${String(matrix["note"])}`
      : `authorization matrix: ${String(matrix["note"])}`,
  );

  for (const result of results) {
    const actual = result.actual === null ? "not measured" : `${String(result.actual)}%`;
    console.log(`${result.label}: ${actual} (require ${String(result.required)}%)`);
  }

  if (gateFailures.length > 0) {
    console.error(`\ncoverage gate failed:`);
    for (const failure of gateFailures) console.error(`  ${failure}`);
  }

  reportFailures(main.failures);

  if (failed > 0) console.error(`${String(failed)} test(s) failed`);
  if (failed > 0 || gateFailures.length > 0) process.exit(1);
}

await main();
