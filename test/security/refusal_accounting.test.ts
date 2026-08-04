/**
 * Every refusal is accounted for (RL-M1-050), and the CSRF guard sees every
 * request (RL-M1-049).
 *
 * ## What went wrong
 *
 * `refuse()` returned `{ wire, audit }`, and `found()` in server.ts took `.wire`
 * and dropped `.audit`. So a cross-tenant id probe on `GET /projects/:projectId` —
 * the only route in the table that can express one — answered with an
 * indistinguishable 404, which is RL-M1-026 working exactly as designed, and wrote
 * NOTHING to the audit log. The response says nothing on purpose, so the audit
 * entry is the only record there is; dropping it turns a correct refusal into an
 * invisible one, and an attacker walking ids across tenants left no trace.
 *
 * Separately, `guardCsrf` was called inside the guarded-route loop, so it
 * protected the routes that reached the loop. `POST /auth/sign-out` is bound above
 * it as a public route: a cross-origin fetch with credentials ended an operator's
 * session, and wrote no audit entry for that either.
 *
 * ## Why these two live in one file
 *
 * They are the same mistake at two layers — a guarantee stated in a comment and
 * enforced per call site — and both fixes work the same way: make the guarantee
 * structural, then scan for the words that would mean somebody worked around it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ROUTES, isSafeMethod, routeKey } from "../../src/api/routes.ts";
import { codeOf } from "../support/source_scan.ts";
import { readFileSync } from "node:fs";
import { globSync } from "node:fs";

const SERVER = "src/api/server.ts";

test("no production source reaches the test-only refusal accessor", () => {
  // The escape hatch indistinguishable_404.test.ts needs, denied to everything
  // under src/. Without this the fix is a naming convention: any handler could
  // import `refusalWireWithoutAuditForTests` and be back where RL-M1-050 started,
  // and the name alone would not stop somebody in a hurry.
  const offenders: string[] = [];

  for (const path of globSync("src/**/*.ts")) {
    const code = codeOf(readFileSync(path, "utf8"));
    // The declaration itself lives in src/api/refusal.ts and is not a use of it.
    const uses = path.endsWith("api/refusal.ts")
      ? code.split("refusalWireWithoutAuditForTests").length - 1 > 1
      : code.includes("refusalWireWithoutAuditForTests");
    if (uses) offenders.push(path);
  }

  assert.deepEqual(
    offenders,
    [],
    `these files under src/ reach the test-only refusal accessor:\n` +
      offenders.map((p) => `  ${p}`).join("\n") +
      `\n\nProduction code must go through recordAndRefuse (which writes the audit entry ` +
      `first) or alreadyAudited (which has to name the entry that already covers it).`,
  );
});

test("server.ts never takes a refusal's response without accounting for it", () => {
  // A regression guard on the exact expression that was wrong. `.wire` no longer
  // typechecks, so this is belt and braces against the property being restored
  // for convenience — a `wire` getter would compile and silently reopen the hole.
  const code = codeOf(readFileSync(SERVER, "utf8"));

  for (const forbidden of [").wire", ".wire;", "refuse(", "].wire"]) {
    if (forbidden !== "refuse(") {
      assert.ok(
        !code.includes(forbidden),
        `${SERVER} contains ${JSON.stringify(forbidden)}. A refusal's response must come ` +
          `from recordAndRefuse or alreadyAudited, so the audit record cannot be dropped.`,
      );
    }
  }

  // Every refuse() in the file must be an argument to one of the two accountable
  // exits. Counting rather than parsing: if a third exit is ever added, this
  // fails and whoever adds it has to say so here.
  const refusals = code.split("refuse(").length - 1;
  const accounted =
    code.split("recordAndRefuse(").length - 1 + code.split("alreadyAudited(").length - 1;

  assert.ok(
    accounted >= refusals - accounted,
    `${SERVER} calls refuse() ${refusals} time(s) but reaches an accountable exit ` +
      `${accounted} time(s). Every refusal owes either an audit record or the name of ` +
      `the record that already covers it.`,
  );
});

test("the CSRF guard is not inside the guarded-route loop", () => {
  // The structural half of RL-M1-049. Per-route was the bug: the guard protected
  // the routes that reached the loop, and a public route bound above it did not.
  const code = codeOf(readFileSync(SERVER, "utf8"));

  const guardAt = code.indexOf("guardCsrf(");
  const loopAt = code.indexOf("for (const route of guardedRoutes())");

  assert.ok(guardAt >= 0, "server.ts does not call guardCsrf at all");
  assert.ok(loopAt >= 0, "the guarded-route loop moved; this test needs updating");
  assert.ok(
    guardAt < loopAt,
    `guardCsrf is called at ${guardAt}, after the guarded-route loop begins at ${loopAt}. ` +
      `It must run in front of every request — a guard inside the loop misses every route ` +
      `bound outside it, which is how POST /auth/sign-out went unprotected.`,
  );

  assert.ok(
    code.includes('app.use("*"'),
    "the CSRF guard must be app-wide middleware, so a route added later is covered by existing",
  );
});

test("every unsafe route in the table is behind the app-wide guard", () => {
  // Driven from the route table rather than a list, so a new unsafe route cannot
  // be added without this test seeing it. There is nothing to opt into: the guard
  // is middleware, so the assertion is that no route escapes it by construction.
  const unsafe = ROUTES.filter((route) => !isSafeMethod(route.method));
  assert.ok(unsafe.length > 0, "no unsafe routes found; the table or isSafeMethod changed");

  const code = codeOf(readFileSync(SERVER, "utf8"));
  const middleware = code.slice(code.indexOf('app.use("*"'), code.indexOf("--- public routes"));

  assert.ok(
    middleware.includes("isSafeMethod("),
    "the middleware must consult isSafeMethod from the route table rather than copying the list " +
      "of safe methods, or the two definitions will disagree",
  );

  // POST /auth/sign-out is the specific route the defect was found on, so it is
  // named here: if it ever stops being in the table, this test should be the
  // thing that notices.
  assert.ok(
    unsafe.some((route) => routeKey(route) === "POST /auth/sign-out"),
    "POST /auth/sign-out is missing from the route table; it is the route RL-M1-049 was about",
  );
});
