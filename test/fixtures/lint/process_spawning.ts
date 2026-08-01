/**
 * FIXTURE — this file MUST fail lint. RL-M1-008, acceptance 4.
 *
 * C2 / ADR 0005: the control plane executes no processes at all. Both
 * specifiers are banned, so both are here — a rule that only knew
 * `node:child_process` would be one character away from useless.
 *
 * Note what these two functions are NOT doing: there is no string
 * interpolation anywhere below. Both calls pass a program and an explicit argv
 * array, which is exactly the shape C2 asks for — and they are still banned,
 * because the control plane's guarantee is that it launches nothing, not that
 * it launches things carefully.
 *
 * Excluded from `npm run lint` by the top-level `ignores`; linted deliberately
 * by test/security/lint_rules.test.ts.
 */

import { execFileSync } from "node:child_process";
import { spawnSync } from "child_process";

export function nodeVersion(): string {
  return execFileSync("node", ["--version"], { encoding: "utf8" }).trim();
}

export function gitStatus(): string {
  return spawnSync("git", ["status", "--porcelain"], { encoding: "utf8" }).stdout;
}
