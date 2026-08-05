/**
 * FIXTURE — stands in for `src/authz/can.ts` in test/toolchain/coverage_gate.test.ts.
 *
 * The coverage gate is judged as a function of two inputs: a coverage report and
 * the source files that exist on disk. This file and its sibling are the disk
 * half. They live here rather than under `src/authz/` deliberately: an
 * unexercised authorization file kept on purpose, in the one directory whose
 * whole claim is that nothing there is unexercised, is the defect RL-M1-051 was
 * filed to remove — and it would need a gate exemption to keep the build green,
 * which is the mechanism the task removes.
 *
 * Nothing imports the code below and nothing needs to. What the test reads is the
 * path, and what the path must be is a real one.
 */

/** A decision with branches, so a branch gate over this file has a denominator. */
export function decides(kind: string): boolean {
  if (kind === "allow") return true;
  if (kind === "deny") return false;
  return false;
}
