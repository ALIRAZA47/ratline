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
import { globSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, ".ratline");

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

async function main(): Promise<void> {
  const includeIntegration = process.argv.includes("--integration");

  const all = globSync("test/**/*.test.ts", { cwd: ROOT }).map((p) => join(ROOT, p));
  const isAuthz = (p: string) => relative(ROOT, p).startsWith(join("test", "authz"));
  const isIntegration = (p: string) => relative(ROOT, p).startsWith(join("test", "integration"));

  const unitFiles = all.filter((p) => !isAuthz(p) && !isIntegration(p));
  const authzFiles = all.filter(isAuthz);
  const integrationFiles = includeIntegration ? all.filter(isIntegration) : [];

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

  const failed = main.counts.failed + (integration?.counts.failed ?? 0);
  console.log(
    `tests: ${main.counts.passed}/${main.counts.tests} passed` +
      (integration ? `, integration ${integration.counts.passed}/${integration.counts.tests}` : "") +
      (main.totals ? `, lines ${main.totals.coveredLinePercent.toFixed(2)}%` : ""),
  );
  console.log(`wrote ${relative(ROOT, join(OUT_DIR, "metrics.json"))}`);

  if (failed > 0) {
    console.error(`${failed} test(s) failed`);
    process.exit(1);
  }
}

await main();
