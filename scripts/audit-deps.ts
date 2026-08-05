#!/usr/bin/env node --experimental-strip-types
/**
 * Run `npm audit` and decide whether the build stops (RL-M1-060).
 *
 * All the judgement lives in ./dependency_audit.ts, which imports nothing and
 * touches nothing — see its docstring for why production and development
 * advisories are treated differently. This file is the part that shells out.
 *
 * Usage:  ./scripts/audit-deps [--json]
 */

import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { blocking, classify, render, type AuditReport } from "./dependency_audit.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * `npm audit --json`, with the exit status deliberately ignored.
 *
 * npm exits non-zero whenever it finds ANYTHING, so a non-zero exit is the normal
 * case here and the JSON on stdout is the answer. What is not tolerated is no
 * parseable report at all: an audit that cannot reach the registry has verified
 * nothing, and reporting that as clean is the stale-green-signal failure
 * ci-metrics.ts avoids by deleting its report before every run.
 */
function audit(args: readonly string[]): AuditReport {
  let out: string;
  try {
    out = execFileSync("npm", ["audit", "--json", ...args], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      // npm writes progress and registry errors to stderr; let them through so a
      // network failure is visible rather than swallowed.
      stdio: ["ignore", "pipe", "inherit"],
    });
  } catch (error: unknown) {
    out = (error as { stdout?: string }).stdout ?? "";
  }

  try {
    return JSON.parse(out) as AuditReport;
  } catch {
    throw new Error(
      "npm audit produced no report, so no dependency was checked. This is a failure, not a " +
        "pass: an audit that cannot reach the registry has verified nothing. Check network " +
        "access and that package-lock.json is present.",
    );
  }
}

function main(): void {
  let findings;
  try {
    findings = classify(audit([]), audit(["--omit=dev"]));
  } catch (error: unknown) {
    console.error(`\n${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }

  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ findings, at: new Date().toISOString() }, null, 2));
  }

  console.log(render(findings));

  const stopped = blocking(findings);
  if (stopped.length > 0) {
    console.error(
      `\ndependency audit failed: ${String(stopped.length)} advisory package(s) in production ` +
        `dependencies — ${stopped.map((f) => f.package).join(", ")}. Each is named above with ` +
        `its fix. A development advisory would have been reported here without failing.`,
    );
    process.exit(1);
  }
}

main();
