/**
 * Scratch database isolation (RL-M1-045).
 *
 * In `test/security/` rather than with the other scaffold checks, and the
 * reason is the point of the file: every security test in this repository is
 * only as meaningful as the isolation underneath it. A scratch database dropped
 * out from under a running test does not only fail that test — it can make one
 * PASS, with assertions running against a database that is half gone or against
 * rows another process seeded. A cross-tenant test that passes because its
 * fixture vanished is the worst possible outcome here, and it is indistinguishable
 * from a real pass.
 *
 * ## What actually happened
 *
 * Roughly one full-suite run in three failed somewhere with `terminating
 * connection due to administrator command` — a message nothing but
 * `drop database ... with (force)` produces. Two test-file PROCESSES had
 * generated the same scratch database name, and one dropped the other's
 * mid-test.
 *
 * The name was `rl_t_${process.hrtime.bigint().toString(36)}_${counter++}`.
 * That clock is monotonic since BOOT and therefore shared between processes,
 * and the counter restarts at zero in each one; `node --test` launches a batch
 * of file processes together, which is exactly the condition that makes a
 * same-nanosecond collision reachable.
 *
 * Two individually correct decisions were jointly a landmine. `with (force)`
 * exists so one leaked connection cannot wedge the drop and leak a database
 * into the next run — right on its own — and it is what turned a collision into
 * terminated connections rather than a harmless "already exists". The naming
 * was the half that was wrong, and it is the half that was fixed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { codeOf } from "../support/source_scan.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

test("a scratch database name carries no process-shared clock", () => {
  // Asserted by reading the source rather than by generating names, because the
  // property is about what the name is DERIVED FROM. A million sampled names
  // would all be distinct within one process and prove nothing about two.
  const source = codeOf(readFileSync(join(ROOT, "test", "support", "db.ts"), "utf8"));
  const naming = /function scratchName\(\)[^}]*}/.exec(source)?.[0] ?? "";
  assert.ok(naming.length > 0, "scratchName has been renamed or removed");
  assert.ok(
    naming.includes("randomUUID"),
    "the name must come from a per-call random source, not a clock every process shares",
  );
  assert.ok(
    !/hrtime|Date\.now|performance\.now/.test(naming),
    "a clock shared between processes puts the collision back",
  );
});

test("the forced drop is still there, because it is the other half of the trade", () => {
  // Removing the force is the WRONG lesson from this. It would trade a loud
  // failure for a silent one: a leaked database surviving into the next run,
  // carrying another test's rows.
  const source = codeOf(readFileSync(join(ROOT, "test", "support", "db.ts"), "utf8"));
  assert.match(source, /drop database if exists .* with \(force\)/);
});
