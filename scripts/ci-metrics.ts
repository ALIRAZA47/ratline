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

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, ".ratline");
/** Written by test/authz/matrix.test.ts. See readMatrixReport below. */
const MATRIX_REPORT = join(OUT_DIR, "authz-matrix.json");

type Counts = { tests: number; passed: number; failed: number };
type Suite = { passed: number; total: number };

type CoverageFile = {
  path: string;
  totalBranchCount: number;
  coveredBranchCount: number;
  totalLineCount: number;
  coveredLineCount: number;
};
type CoverageTotals = { coveredLinePercent: number; coveredBranchPercent: number };

const pct = (covered: number, total: number): number =>
  total === 0 ? 100 : Math.round((covered / total) * 10_000) / 100;

/** Aggregate coverage over the files whose repo-relative path matches. */
function coverageFor(files: CoverageFile[], match: RegExp): { lines: number; branches: number } | null {
  const hit = files.filter((f) => match.test(relative(ROOT, f.path)));
  if (hit.length === 0) return null;
  const sum = (pick: (f: CoverageFile) => number) => hit.reduce((n, f) => n + pick(f), 0);
  return {
    lines: pct(sum((f) => f.coveredLineCount), sum((f) => f.totalLineCount)),
    branches: pct(sum((f) => f.coveredBranchCount), sum((f) => f.totalBranchCount)),
  };
}

async function runSuite(files: string[], coverage: boolean): Promise<{
  counts: Counts;
  files: CoverageFile[];
  totals: CoverageTotals | null;
}> {
  if (files.length === 0) {
    return { counts: { tests: 0, passed: 0, failed: 0 }, files: [], totals: null };
  }

  let counts: Counts = { tests: 0, passed: 0, failed: 0 };
  let covFiles: CoverageFile[] = [];
  let totals: CoverageTotals | null = null;

  const stream = run({ files, coverage, concurrency: true });
  stream.on("data", (event: { type: string; data: Record<string, unknown> }) => {
    if (event.type === "test:summary" && event.data["file"] === undefined) {
      const c = event.data["counts"] as Counts | undefined;
      if (c) counts = c;
    }
    if (event.type === "test:coverage") {
      const summary = event.data["summary"] as
        | { files?: CoverageFile[]; totals?: CoverageTotals }
        | undefined;
      covFiles = summary?.files ?? [];
      totals = summary?.totals ?? null;
    }
  });
  // Drain so the stream completes; failures are reported via counts, and the
  // reporter output is not wanted here.
  stream.resume();
  await new Promise<void>((res, rej) => {
    stream.on("end", () => res());
    stream.on("error", rej);
  });

  return { counts, files: covFiles, totals };
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

async function main(): Promise<void> {
  const includeIntegration = process.argv.includes("--integration");

  const all = globSync("test/**/*.test.ts", { cwd: ROOT }).map((p) => join(ROOT, p));
  const isAuthz = (p: string) => relative(ROOT, p).startsWith(join("test", "authz"));
  const isIntegration = (p: string) => relative(ROOT, p).startsWith(join("test", "integration"));

  const unitFiles = all.filter((p) => !isAuthz(p) && !isIntegration(p));
  const authzFiles = all.filter(isAuthz);
  const integrationFiles = includeIntegration ? all.filter(isIntegration) : [];

  // Cleared before the run so its presence afterwards proves this run wrote it.
  rmSync(MATRIX_REPORT, { force: true });

  // Coverage comes from the combined unit + authz run: the authorization module
  // is exercised by both, and measuring them separately would understate it.
  const main = await runSuite([...unitFiles, ...authzFiles], true);
  const authz = authzFiles.length > 0 ? await runSuite(authzFiles, false) : null;
  const integration =
    integrationFiles.length > 0 ? await runSuite(integrationFiles, false) : null;

  const authzCoverage = coverageFor(main.files, /^src[/\\]authz[/\\]/);
  const canCoverage = coverageFor(main.files, /^src[/\\]authz[/\\]can\.ts$/);

  const unitCounts: Counts = {
    tests: main.counts.tests - (authz?.counts.tests ?? 0),
    passed: main.counts.passed - (authz?.counts.passed ?? 0),
    failed: main.counts.failed - (authz?.counts.failed ?? 0),
  };

  const metrics: Record<string, unknown> = {
    unit: suiteOf(unitCounts),
    measured_at: new Date().toISOString(),
  };
  if (authz) metrics["authz_matrix"] = suiteOf(authz.counts);
  metrics["authz_matrix_cells"] = readMatrixReport();
  if (integration) metrics["integration"] = suiteOf(integration.counts);
  else metrics["integration_note"] = "not run — needs a real host, see RISKS.md R-01";
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
  // These two are gated and nothing else is. A blanket coverage target buys
  // tests written to raise a number; these buy the specific guarantee that every
  // path through the decision function has been exercised, including the ones
  // that deny.
  // ---------------------------------------------------------------------------
  const gates: { label: string; actual: number | null; required: number; why: string }[] = [
    {
      label: "can() branch coverage",
      actual: canCoverage?.branches ?? null,
      required: 100,
      why: "every path through the decision function must be exercised, especially the ones that deny (brief §6.3)",
    },
    {
      label: "src/authz/** line coverage",
      actual: authzCoverage?.lines ?? null,
      required: 100,
      why: "the authorization module is the differentiator; an unexercised line here is an unknown permission outcome (brief §6.3)",
    },
  ];

  const gateFailures: string[] = [];
  for (const gate of gates) {
    if (gate.actual === null) {
      // Absent is a failure, not a pass. Renaming or moving can.ts would
      // otherwise switch its own gate off silently, which is the failure mode
      // most likely to go unnoticed for months.
      gateFailures.push(`${gate.label}: not measured — expected ${gate.required}%. ${gate.why}`);
      continue;
    }
    if (gate.actual < gate.required) {
      gateFailures.push(`${gate.label}: ${gate.actual}% < ${gate.required}%. ${gate.why}`);
    }
  }

  const failed = main.counts.failed + (integration?.counts.failed ?? 0);
  console.log(
    `tests: ${main.counts.passed}/${main.counts.tests} passed` +
      (integration ? `, integration ${integration.counts.passed}/${integration.counts.tests}` : "") +
      (main.totals ? `, lines ${main.totals.coveredLinePercent.toFixed(2)}%` : ""),
  );
  console.log(`wrote ${relative(ROOT, join(OUT_DIR, "metrics.json"))}`);

  const matrix = metrics["authz_matrix_cells"] as Record<string, unknown>;
  console.log(
    matrix["executed"] === true
      ? `authorization matrix: ${String(matrix["passed"])}/${String(matrix["cells"])} cells — ${String(matrix["note"])}`
      : `authorization matrix: ${String(matrix["note"])}`,
  );

  for (const gate of gates) {
    const actual = gate.actual === null ? "not measured" : `${gate.actual}%`;
    console.log(`${gate.label}: ${actual} (require ${gate.required}%)`);
  }

  if (gateFailures.length > 0) {
    console.error(`\ncoverage gate failed:`);
    for (const failure of gateFailures) console.error(`  ${failure}`);
  }

  if (failed > 0) console.error(`${failed} test(s) failed`);
  if (failed > 0 || gateFailures.length > 0) process.exit(1);
}

await main();
