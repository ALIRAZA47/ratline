/**
 * The authorization matrix generator (RL-M1-024).
 *
 * Brief §6.3: "The matrix is generated from the route table so a new endpoint
 * without matrix coverage fails CI."
 *
 * The property worth testing is not that the generator produces cells — it is
 * that a route CANNOT escape it. So most of what follows adds a route and
 * asserts the matrix noticed, or malforms the table and asserts generation
 * refuses rather than producing something that looks exhaustive.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateMatrix,
  MATRIX_SUBJECTS,
  MatrixGenerationError,
  summariseMatrix,
  uncoveredRoutes,
} from "../../src/authz/matrix.ts";
import { ALL_DEFAULT_ROLES } from "../../src/authz/roles.ts";
import {
  guardedRoutes,
  isSafeMethod,
  publicRoutes,
  ROUTES,
  routeKey,
  validateRoutes,
  type Route,
} from "../../src/api/routes.ts";

// ---------------------------------------------------------------------------
// The route table's own integrity
// ---------------------------------------------------------------------------

test("the committed route table is well formed", () => {
  assert.deepEqual(validateRoutes(), [], "a malformed table would make the matrix exhaustive over the wrong set");
  assert.ok(ROUTES.length > 0);
});

test("every route names an action the catalogue declares, or says why it does not", () => {
  // The type system already enforces the first half. This covers the second,
  // which types cannot: that an unguarded route carries a real argument rather
  // than an empty string someone typed to make the compiler stop.
  for (const route of publicRoutes()) {
    assert.ok(
      route.publicReason.trim().length > 30,
      `${routeKey(route)}: an unguarded route needs a reason worth reading, got "${route.publicReason}"`,
    );
  }
  assert.ok(guardedRoutes().length > publicRoutes().length, "most routes should require a permission");
});

test("the secret name/value split survives into the routes", () => {
  // §6.3 makes these separate actions; a route table that guarded both with the
  // same one would quietly undo that, and no test of the catalogue would notice.
  const list = ROUTES.find((r) => r.path === "/environments/:environmentId/secrets" && r.method === "GET");
  const reveal = ROUTES.find((r) => r.path.endsWith("/value"));
  assert.equal(list?.requires, "secret.read_name");
  assert.equal(reveal?.requires, "secret.read_value");
});

test("only GET is treated as safe", () => {
  // A safe method needs no CSRF token (RL-M1-021). Treating POST as safe would
  // exempt exactly the requests that change things.
  assert.equal(isSafeMethod("GET"), true);
  for (const method of ["POST", "PUT", "PATCH", "DELETE"] as const) {
    assert.equal(isSafeMethod(method), false, `${method} must not be exempt from CSRF`);
  }
});

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

test("the matrix covers every route, every role and every subject", () => {
  const cells = generateMatrix();
  const summary = summariseMatrix(cells);

  assert.equal(summary.routes, ROUTES.length);
  assert.equal(summary.roles, ALL_DEFAULT_ROLES.length);
  assert.equal(summary.cells, ROUTES.length * ALL_DEFAULT_ROLES.length * MATRIX_SUBJECTS.length);
  assert.deepEqual(uncoveredRoutes(cells), []);

  // Both outcomes are represented. A matrix that only ever expects one is a
  // matrix that would pass against a system with no permission model at all.
  assert.ok(summary.expectedAllow > 0);
  assert.ok(summary.expectedDeny > 0);
});

test("a route added to the table appears in the matrix without anything else changing", () => {
  // The acceptance criterion, stated directly: coverage follows declaration.
  const extra: Route = {
    method: "DELETE",
    path: "/projects/:projectId/danger",
    summary: "A route nobody has written a test for",
    scope: "path-node",
    scopeParam: "projectId",
    requires: "project.delete",
  };
  const cells = generateMatrix([...ROUTES, extra]);
  assert.deepEqual(uncoveredRoutes(cells, [...ROUTES, extra]), []);
  assert.equal(
    cells.filter((c) => c.routeKey === routeKey(extra)).length,
    ALL_DEFAULT_ROLES.length * MATRIX_SUBJECTS.length,
  );
});

test("another tenant's resource is denied to every role, including Owner", () => {
  // The IDOR row. Its independence from the role is the point: an Owner is an
  // Owner of THEIR organization, and no role reaches across the boundary.
  const cells = generateMatrix();
  const foreign = cells.filter((c) => c.subject === "other-tenant" && c.action !== null);
  assert.ok(foreign.length > 0);
  for (const cell of foreign) {
    assert.equal(
      cell.expected,
      "deny",
      `${cell.roleKey} on ${cell.routeKey} against another tenant should be denied`,
    );
  }
  assert.ok(foreign.some((c) => c.roleKey === "owner"), "Owner must be covered by this rule too");
});

test("nonexistent and other-tenant carry the same expectation", () => {
  // RL-M1-026 requires the two to be indistinguishable in the response. They
  // must therefore be indistinguishable in what the matrix expects, or the
  // matrix would be asserting the leak it is meant to prevent.
  const cells = generateMatrix();
  for (const route of guardedRoutes()) {
    for (const role of ALL_DEFAULT_ROLES) {
      const of = (subject: string) =>
        cells.find((c) => c.routeKey === routeKey(route) && c.roleKey === role.key && c.subject === subject);
      assert.equal(
        of("other-tenant")?.expected,
        of("nonexistent")?.expected,
        `${role.key} on ${routeKey(route)}: forbidden and absent must expect the same answer`,
      );
    }
  }
});

test("expectations follow the role definitions rather than a second list", () => {
  // If the matrix recorded expectations by hand it would be a second opinion
  // about the permission model, and the two would drift. Spot-check that it
  // tracks the roles: Billing holds nothing but billing actions, so every
  // guarded route outside billing must expect a denial for it.
  const cells = generateMatrix();
  const billing = ALL_DEFAULT_ROLES.find((r) => r.key === "billing");
  assert.ok(billing);

  for (const route of guardedRoutes()) {
    const cell = cells.find(
      (c) => c.routeKey === routeKey(route) && c.roleKey === "billing" && c.subject === "own",
    );
    const shouldAllow = billing.actions.includes(route.requires);
    assert.equal(cell?.expected, shouldAllow ? "allow" : "deny", `billing on ${routeKey(route)}`);
  }
});

test("every cell explains itself", () => {
  // A failing matrix cell that says only "expected deny, got allow" sends
  // someone reading three files. The reason is what makes it actionable.
  for (const cell of generateMatrix()) {
    assert.ok(cell.because.length > 10, `${cell.routeKey}/${cell.roleKey} has no useful reason`);
  }
});

// ---------------------------------------------------------------------------
// Generation refuses rather than producing a misleading matrix
// ---------------------------------------------------------------------------

test("a duplicate route is refused", () => {
  const first = ROUTES[0];
  assert.ok(first);
  assert.throws(() => generateMatrix([first, first]), MatrixGenerationError);
});

test("an unguarded route with no stated reason is refused", () => {
  assert.throws(
    () =>
      generateMatrix([
        { method: "POST", path: "/danger", summary: "x", scope: "organization", requires: null, publicReason: "  " },
      ]),
    (error: unknown) =>
      error instanceof MatrixGenerationError && error.problems.some((p) => /why it is unguarded/.test(p)),
  );
});

test("a scoped route whose parameter is not in its path is refused", () => {
  // The mistake this catches is a rename: someone changes `:projectId` to `:id`
  // and the scope silently stops resolving, which would make every cell for
  // that route test the organization scope instead of the project.
  assert.throws(
    () =>
      generateMatrix([
        {
          method: "GET",
          path: "/projects/:id",
          summary: "Read a project",
          scope: "path-node",
          scopeParam: "projectId",
          requires: "project.read",
        },
      ]),
    (error: unknown) =>
      error instanceof MatrixGenerationError && error.problems.some((p) => /not a parameter of the path/.test(p)),
  );
});

test("a route requiring an action outside the catalogue is refused", () => {
  assert.throws(
    () =>
      generateMatrix([
        {
          method: "GET",
          path: "/anything",
          summary: "Requires something invented",
          scope: "organization",
          // Only reachable through a cast, which is exactly how it would arrive.
          requires: "site.delete_everything" as never,
        },
      ]),
    (error: unknown) =>
      error instanceof MatrixGenerationError && error.problems.some((p) => /not in the catalogue/.test(p)),
  );
});
