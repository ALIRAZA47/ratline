/**
 * The authorization matrix harness (RL-M1-025).
 *
 * Brief §6.3 wants "an exhaustive authorization matrix test — every role × every
 * endpoint × own-resource / other-team-resource / nonexistent-resource". The
 * generator (RL-M1-024) says what SHOULD happen for each of those cells. This
 * runs them and says what DOES.
 *
 * ## The awkward part, stated rather than hidden
 *
 * The acceptance asks the harness to be "meaningful even while most endpoints do
 * not yet exist", and right now none of them do: there is no HTTP server. A
 * harness that quietly reported 100% under those conditions would be worse than
 * no harness, because the number would be believed.
 *
 * So every cell records WHICH LAYER verified it, and the layers are not
 * interchangeable:
 *
 *   transport    a real request through the real server, with the real
 *                middleware. The only layer that proves an endpoint is guarded.
 *   decision     a real `can()` call, as the unprivileged `ratline_app` role,
 *                against a real Postgres with real grants and real row-level
 *                security. Proves the permission MODEL is right; proves nothing
 *                about whether a route remembers to consult it.
 *   declaration  the route claims to need no permission, and the claim is
 *                structural rather than executable — there is no decision to
 *                make. Never counted as a passing permission check.
 *
 * The report writes the histogram, so "0 cells verified end to end" is a number
 * in STATUS.md rather than a caveat somebody has to remember. When the server
 * lands, `transport` starts climbing and the gap closes visibly.
 *
 * `transportLayerExists()` below is the tripwire that stops this from becoming a
 * permanent arrangement: the moment `src/api/server.ts` appears, the harness
 * fails until somebody points it at the real thing. §9 lists "TODO: add auth
 * check later" as an anti-pattern; this is that TODO written as a build failure.
 */

import { existsSync } from "node:fs";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import type { MatrixCell } from "../../src/authz/matrix.ts";

export const VERIFICATION_LAYERS = ["transport", "decision", "declaration"] as const;
export type VerificationLayer = (typeof VERIFICATION_LAYERS)[number];

/**
 * What an executor reports back about one cell.
 *
 * A discriminated union rather than an optional field, because the two cases
 * are verified differently and the comparison against `expected` must happen in
 * exactly one place. An executor that returned a bare boolean would be free to
 * decide what "expected" means, which is the second opinion this whole task
 * exists to avoid.
 */
export type CellOutcome =
  | {
      readonly layer: "transport" | "decision";
      readonly actual: "allow" | "deny";
      /** `{allowed, reason}` — compared across subjects to check §6.3's indistinguishability. */
      readonly signature: string;
      readonly detail: string;
    }
  | {
      readonly layer: "declaration";
      readonly satisfied: boolean;
      readonly detail: string;
    };

export type CellExecutor = (cell: MatrixCell) => Promise<CellOutcome>;

export type CellResult = {
  readonly cell: MatrixCell;
  readonly layer: VerificationLayer;
  readonly passed: boolean;
  readonly actual: "allow" | "deny" | null;
  readonly signature: string | null;
  readonly detail: string;
};

/** A one-line description of a failing cell, for a human reading CI output. */
export function describeFailure(result: CellResult): string {
  const { cell } = result;
  return (
    `${cell.roleKey} ${cell.routeKey} [${cell.subject}] ` +
    `expected ${cell.expected}, got ${result.actual ?? "no verdict"} ` +
    `(${result.layer}) — ${cell.because}; ${result.detail}`
  );
}

/**
 * Run every cell.
 *
 * Sequential on purpose. The executor holds one pooled connection and sets a
 * transaction-local tenant on it; running cells concurrently would interleave
 * those and make a failure impossible to attribute. 546 cells against a local
 * Postgres costs a few seconds, which is a fair price for a result that means
 * what it says.
 */
export async function runMatrix(
  cells: readonly MatrixCell[],
  execute: CellExecutor,
): Promise<CellResult[]> {
  const results: CellResult[] = [];
  for (const cell of cells) {
    const outcome = await execute(cell);
    if (outcome.layer === "declaration") {
      results.push({
        cell,
        layer: "declaration",
        passed: outcome.satisfied,
        actual: null,
        signature: null,
        detail: outcome.detail,
      });
      continue;
    }
    // The one place an outcome is compared with an expectation.
    results.push({
      cell,
      layer: outcome.layer,
      passed: outcome.actual === cell.expected,
      actual: outcome.actual,
      signature: outcome.signature,
      detail: outcome.detail,
    });
  }
  return results;
}

export type MatrixReport = {
  readonly executed: boolean;
  readonly cells: number;
  readonly passed: number;
  readonly failed: number;
  readonly routes: number;
  readonly roles: number;
  readonly subjects: number;
  readonly verified_by: Record<VerificationLayer, number>;
  readonly failures: readonly string[];
  readonly note: string;
  readonly at: string;
};

/** How many failures are written out before the list is truncated. */
const MAX_REPORTED_FAILURES = 20;

export function summariseResults(results: readonly CellResult[]): MatrixReport {
  const verifiedBy: Record<VerificationLayer, number> = {
    transport: 0,
    decision: 0,
    declaration: 0,
  };
  for (const result of results) verifiedBy[result.layer] += 1;

  const failures = results.filter((r) => !r.passed);
  const listed = failures.slice(0, MAX_REPORTED_FAILURES).map(describeFailure);
  if (failures.length > listed.length) {
    listed.push(`... and ${failures.length - listed.length} more`);
  }

  return {
    executed: true,
    cells: results.length,
    passed: results.length - failures.length,
    failed: failures.length,
    routes: new Set(results.map((r) => r.cell.routeKey)).size,
    roles: new Set(results.map((r) => r.cell.roleKey)).size,
    subjects: new Set(results.map((r) => r.cell.subject)).size,
    verified_by: verifiedBy,
    failures: listed,
    // Written into the report rather than left to the reader, because the
    // number that matters is the one that is zero.
    note:
      `${verifiedBy.transport} of ${results.length} cells verified end to end through a real request; ` +
      `${verifiedBy.decision} at the decision layer only (can() against real grants and RLS); ` +
      `${verifiedBy.declaration} unguarded routes, checked structurally and never counted as a permission check.`,
    at: new Date().toISOString(),
  };
}

/**
 * Where the report is written for `scripts/ci-metrics` to fold into metrics.json.
 *
 * ci-metrics DELETES this before running the suite and treats its absence as
 * "the matrix did not run". That is the whole staleness story: there is no way
 * for yesterday's green matrix to be reported as today's, because yesterday's
 * file is gone before today's run starts.
 */
export function matrixReportPath(root: string): string {
  return join(root, ".ratline", "authz-matrix.json");
}

export function writeMatrixReport(root: string, report: MatrixReport): void {
  const path = matrixReportPath(root);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(report, null, 2)}\n`, "utf8");
}

/**
 * Has the HTTP layer landed?
 *
 * The tripwire. While this is false, verifying at the decision layer is the
 * strongest thing available and the report says so. Once it is true, decision
 * coverage is no longer sufficient — a route can consult `can()` correctly in
 * the model and still forget to call it — so the harness must be re-pointed at
 * real requests. The test asserting this fails the build until that happens.
 */
export function transportLayerExists(root: string): boolean {
  return existsSync(join(root, "src", "api", "server.ts"));
}
