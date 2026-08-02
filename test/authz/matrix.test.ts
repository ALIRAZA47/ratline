/**
 * The exhaustive authorization matrix (RL-M1-025).
 *
 * Brief §6.3: "every role × every endpoint × own-resource / other-team-resource
 * / nonexistent-resource". RL-M1-024 generates those cells and says what should
 * happen. This file runs them.
 *
 * ## What is actually being executed, since it is not what the name suggests
 *
 * There is no HTTP server yet, so no cell can be verified end to end. What CAN
 * be verified today is the layer underneath: a real `can()` call, over a real
 * connection as `ratline_app` — the unprivileged, NOBYPASSRLS role production
 * uses — against a real Postgres holding real grants, real scope hierarchy and
 * real row-level security. Nothing here is mocked; §9 rules that out, and it
 * would rule it out even if the matrix were the only test in the repository,
 * because a mocked authorization matrix tests the mock.
 *
 * That distinction is not a footnote, it is the harness's main output. Every
 * cell records the layer that verified it and the report writes the histogram,
 * so `transport: 0` appears in STATUS.md as a number. Reporting "546/546
 * passed" without it would be technically true and completely misleading —
 * every endpoint could be entirely unguarded and this suite would still be
 * green, because there are no endpoints.
 *
 * `test/support/matrix_harness.ts` holds the tripwire that stops that from
 * becoming permanent.
 *
 * ## The world
 *
 * Two organizations, each with a full organization → team → project →
 * environment tree. The actor always belongs to the first. `other-tenant`
 * therefore names a REAL node owned by somebody else, which is the case that
 * matters: an identifier that resolves for its owner and must not resolve here.
 * A made-up identifier would test nothing but `gen_random_uuid`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { can } from "../../src/authz/can.ts";
import { contextForRequest } from "../../src/authz/context.ts";
import { ALL_DEFAULT_ROLES } from "../../src/authz/roles.ts";
import {
  generateMatrix,
  MATRIX_SUBJECTS,
  type MatrixCell,
  type MatrixSubject,
} from "../../src/authz/matrix.ts";
import { ROUTES, routeKey, type Route } from "../../src/api/routes.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  describeFailure,
  runMatrix,
  summariseResults,
  transportLayerExists,
  writeMatrixReport,
  type CellExecutor,
  type CellResult,
} from "../support/matrix_harness.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

type Tree = { organization: string; project: string; environment: string };

type World = {
  readonly orgId: string;
  readonly own: Tree;
  readonly other: Tree;
  /** One user per role, each granted exactly that role at organization scope. */
  readonly userForRole: ReadonlyMap<string, string>;
};

/** organization → team → project → environment, returning the interesting nodes. */
async function seedTree(client: Client, orgId: string): Promise<Tree> {
  const root = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  const organization = root.rows[0]?.id ?? "";

  const node = async (kind: string, parent: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, $2, $3) returning id",
      [orgId, kind, parent],
    );
    return r.rows[0]?.id ?? "";
  };

  const teamNode = await node("team", organization);
  await client.query("insert into teams (org_id, scope_node_id, slug, name) values ($1, $2, 'web', 'Web')", [
    orgId,
    teamNode,
  ]);

  const projectNode = await node("project", teamNode);
  const project = await client.query<{ id: string }>(
    "insert into projects (org_id, scope_node_id, slug, name) values ($1, $2, 'shop', 'Shop') returning id",
    [orgId, projectNode],
  );

  const environmentNode = await node("environment", projectNode);
  await client.query(
    `insert into environments (org_id, project_id, scope_node_id, slug, name, kind)
     values ($1, $2, $3, 'production', 'Production', 'production')`,
    [orgId, project.rows[0]?.id ?? "", environmentNode],
  );

  return { organization, project: projectNode, environment: environmentNode };
}

async function seedWorld(client: Client): Promise<World> {
  const organization = async (slug: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into organizations (slug, name) values ($1, $2) returning id",
      [slug, slug],
    );
    return r.rows[0]?.id ?? "";
  };

  const orgId = await organization("acme");
  const otherOrgId = await organization("globex");

  const userForRole = new Map<string, string>();
  for (const role of ALL_DEFAULT_ROLES) {
    const user = await client.query<{ id: string }>(
      "insert into users (email, name) values ($1, $2) returning id",
      [`${role.key}@acme.example`, role.name],
    );
    const userId = user.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);
    // Granted at ORGANIZATION scope, so the grant inherits down to the project
    // and environment nodes the path-scoped routes resolve against. A grant made
    // at each node separately would test inheritance not at all, and inheritance
    // is where a scoping bug hides.
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, $3, 'organization')`,
      [orgId, userId, role.key],
    );
    userForRole.set(role.key, userId);
  }

  // The other tenant gets a member too. Without one its tree would be
  // unreachable for a reason that has nothing to do with authorization.
  const stranger = await client.query<{ id: string }>(
    "insert into users (email, name) values ('owner@globex.example', 'Stranger') returning id",
  );
  const strangerId = stranger.rows[0]?.id ?? "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [otherOrgId, strangerId]);
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, 'owner', 'organization')`,
    [otherOrgId, strangerId],
  );

  return {
    orgId,
    own: await seedTree(client, orgId),
    other: await seedTree(client, otherOrgId),
    userForRole,
  };
}

// ---------------------------------------------------------------------------
// Mapping a cell onto a scope node
// ---------------------------------------------------------------------------

/**
 * Which node in the tree a path parameter names.
 *
 * Written out rather than inferred, so a new `path-node` route with a parameter
 * nobody has thought about fails here instead of silently resolving against the
 * organization root — which would grant it every inherited permission and make
 * its whole row of the matrix meaningless.
 */
const NODE_FOR_PARAM: Readonly<Record<string, keyof Tree>> = {
  projectId: "project",
  environmentId: "environment",
};

function scopeNodeFor(route: Route, subject: MatrixSubject, world: World): string {
  // An identifier that names nothing. Fresh each time, so no cell can pass by
  // recognising a constant.
  if (subject === "nonexistent") return randomUUID();

  const tree = subject === "other-tenant" ? world.other : world.own;

  if (route.scope === "organization") return tree.organization;

  if (route.scope === "path-node") {
    const param = route.scopeParam ?? "";
    const key = NODE_FOR_PARAM[param];
    if (key === undefined) {
      throw new Error(
        `${routeKey(route)} scopes on ":${param}", which the matrix harness cannot map to a ` +
          `node. Add it to NODE_FOR_PARAM — resolving it to the organization root instead ` +
          `would silently grant the route every inherited permission.`,
      );
    }
    return tree[key];
  }

  throw new Error(
    `${routeKey(route)} declares scope "${route.scope}", which the matrix harness cannot build ` +
      `a subject for. Extend the harness rather than dropping the route from the matrix.`,
  );
}

const ROUTE_BY_KEY = new Map(ROUTES.map((route) => [routeKey(route), route]));

/**
 * Verify one cell by asking the real decision function.
 *
 * `resourceId` is null throughout, and that is safe HERE for a reason that
 * would not hold generally: this world contains no resource-scoped grants, so
 * there is nothing for a null to drop. A resource-scoped deny in the fixture
 * would make the null fail open, exactly as `ScopeRef` warns.
 */
function decisionExecutor(world: World): CellExecutor {
  return async (cell: MatrixCell) => {
    const route = ROUTE_BY_KEY.get(cell.routeKey);
    if (route === undefined) throw new Error(`no route for cell ${cell.routeKey}`);

    if (route.requires === null) {
      // Nothing to execute: an unguarded route has no decision to make. Saying
      // so is the honest verdict, and the report counts it apart from the cells
      // that were actually decided.
      return {
        layer: "declaration",
        satisfied: cell.expected === "allow" && route.publicReason.trim() !== "",
        detail: "unguarded by declaration; no permission check exists to run",
      };
    }

    const userId = world.userForRole.get(cell.roleKey);
    if (userId === undefined) throw new Error(`no seeded user for role ${cell.roleKey}`);

    const ctx = contextForRequest({
      orgId: world.orgId,
      userId,
      requestId: `matrix-${randomUUID()}`,
    });
    const decision = await can(ctx, route.requires, {
      scopeNodeId: scopeNodeFor(route, cell.subject, world),
      resourceId: null,
    });

    return {
      layer: "decision",
      actual: decision.allowed ? "allow" : "deny",
      // Deliberately excludes scopeNodeId: two subjects have different ids by
      // construction, and comparing them would make the indistinguishability
      // check below pass for the wrong reason.
      signature: `${String(decision.allowed)}:${decision.reason}`,
      detail: `can() answered ${decision.reason}`,
    };
  };
}

/** Connect the pool as `ratline_app` against the scratch database. */
async function usingApplicationConnection(database: string, fn: () => Promise<void>): Promise<void> {
  // `ratline_app` is created NOLOGIN by migration 2 — a login role with no
  // password would be the default credential C4 forbids. asApplicationRole()
  // performs the deployment step that enables it; calling it with an empty body
  // is how this file asks for that without duplicating the logic.
  await asApplicationRole(database, () => Promise.resolve(undefined));

  const url = new URL(DATABASE_URL);
  url.pathname = `/${database}`;
  url.username = "ratline_app";
  url.password = "";
  connect({ connectionString: url.toString() });
  try {
    await fn();
  } finally {
    await disconnect();
  }
}

// ---------------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------------

test("the authorization matrix", { skip }, async (t) => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    const cells = generateMatrix();
    let results: CellResult[] = [];

    await usingApplicationConnection(database, async () => {
      results = await runMatrix(cells, decisionExecutor(world));
    });

    const report = summariseResults(results);
    // Written before the assertions, so a failing matrix still reports itself
    // to STATUS rather than leaving the previous run's number in place.
    writeMatrixReport(ROOT, report);

    await t.test("every role is exercised against every endpoint and every subject", () => {
      assert.equal(
        report.cells,
        ROUTES.length * ALL_DEFAULT_ROLES.length * MATRIX_SUBJECTS.length,
        "a cell went missing between generation and execution",
      );
      assert.equal(report.routes, ROUTES.length);
      assert.equal(report.roles, ALL_DEFAULT_ROLES.length);
      assert.equal(report.subjects, MATRIX_SUBJECTS.length);
    });

    await t.test("every cell matches the expectation generated for it", () => {
      assert.deepEqual(report.failures, [], "the matrix disagrees with the permission model");
      assert.equal(report.failed, 0);
    });

    await t.test("no cell passed without something being decided or declared", () => {
      // A cell with no layer would be a cell nobody checked, counted as passing.
      for (const result of results) {
        assert.ok(
          result.layer === "decision" || result.layer === "declaration",
          `${describeFailure(result)}: verified by nothing`,
        );
      }
      assert.ok(report.verified_by.decision > 0);
    });

    await t.test("another tenant's real node is refused to every role, Owner included", () => {
      const foreign = results.filter((r) => r.cell.subject === "other-tenant" && r.layer === "decision");
      assert.ok(foreign.length > 0);
      for (const result of foreign) {
        assert.equal(result.actual, "deny", describeFailure(result));
      }
      assert.ok(foreign.some((r) => r.cell.roleKey === "owner"));
    });

    await t.test("forbidden and absent are indistinguishable to the decision function", () => {
      // RL-M1-026 owns the HTTP response. This is the same property one layer
      // down: if `can()` answered `no-grant` for another tenant's node and
      // `unknown-scope` for a made-up one, the reason would reach the audit log
      // and the error body, and the difference would be an existence oracle.
      const decided = results.filter((r) => r.layer === "decision");
      const at = (roleKey: string, key: string, subject: MatrixSubject) =>
        decided.find((r) => r.cell.roleKey === roleKey && r.cell.routeKey === key && r.cell.subject === subject);

      let compared = 0;
      for (const role of ALL_DEFAULT_ROLES) {
        for (const route of ROUTES) {
          const foreign = at(role.key, routeKey(route), "other-tenant");
          const absent = at(role.key, routeKey(route), "nonexistent");
          if (foreign === undefined || absent === undefined) continue;
          assert.equal(
            foreign.signature,
            absent.signature,
            `${role.key} on ${routeKey(route)}: another tenant's resource answered ` +
              `"${String(foreign.signature)}" and a nonexistent one "${String(absent.signature)}" — ` +
              `the difference tells a caller the first one exists`,
          );
          compared += 1;
        }
      }
      assert.ok(compared > 0, "nothing was compared, so this test proved nothing");
    });

    await t.test("the report says how much of the matrix is not yet verified end to end", () => {
      // The number that matters is the one that is zero. If this ever reads
      // above zero without the harness being re-pointed, something is lying.
      assert.equal(report.verified_by.transport, 0);
      assert.match(report.note, /verified end to end/);
      assert.equal(report.executed, true);
    });
  });
});

// ---------------------------------------------------------------------------
// The harness itself — a harness that cannot report a failure is not a harness
// ---------------------------------------------------------------------------

test("the harness reports a wrong answer rather than passing it", async () => {
  const cells = generateMatrix();
  // An executor that always allows. Against a matrix containing denials — which
  // the generator test pins — this must produce failures. Without this test the
  // comparison in runMatrix could be absent and every run would read green.
  const alwaysAllow: CellExecutor = (cell) =>
    Promise.resolve(
      cell.action === null
        ? { layer: "declaration", satisfied: true, detail: "declared" }
        : { layer: "decision", actual: "allow", signature: "true:granted", detail: "lying" },
    );

  const report = summariseResults(await runMatrix(cells, alwaysAllow));
  assert.ok(report.failed > 0, "a permissive executor must fail the matrix");
  assert.ok(report.failures.length > 0);
  assert.match(report.failures[0] ?? "", /expected deny, got allow/);
});

test("the harness reports a wrongly refused cell too", async () => {
  const cells = generateMatrix();
  const alwaysDeny: CellExecutor = (cell) =>
    Promise.resolve(
      cell.action === null
        ? { layer: "declaration", satisfied: true, detail: "declared" }
        : { layer: "decision", actual: "deny", signature: "false:no-grant", detail: "lying" },
    );

  const report = summariseResults(await runMatrix(cells, alwaysDeny));
  // Denying everything is the failure mode that looks safe, which is why it
  // needs its own assertion: a matrix that only checked for over-permission
  // would call a completely broken system secure.
  assert.ok(report.failed > 0, "an unconditionally refusing executor must fail the matrix too");
  assert.match(report.failures.join("\n"), /expected allow, got deny/);
});

test("a declaration cell is never counted as a permission check", async () => {
  const cells = generateMatrix().filter((c) => c.action === null);
  assert.ok(cells.length > 0);
  const report = summariseResults(
    await runMatrix(cells, () =>
      Promise.resolve({ layer: "declaration", satisfied: true, detail: "declared" }),
    ),
  );
  assert.equal(report.verified_by.decision, 0);
  assert.equal(report.verified_by.declaration, cells.length);
  assert.match(report.note, /never counted as a permission check/);
});

test("the failure list is capped but says how much it dropped", async () => {
  const cells = generateMatrix();
  const report = summariseResults(
    await runMatrix(cells, () =>
      Promise.resolve({
        layer: "decision",
        actual: "allow",
        signature: "true:granted",
        detail: "lying",
      }),
    ),
  );
  // A CI log with 400 identical lines is a log nobody reads; one that silently
  // shows the first 20 is a log that lies about the size of the problem.
  assert.ok(report.failures.length <= 21);
  assert.match(report.failures.at(-1) ?? "", /and \d+ more/);
  assert.ok(report.failed > report.failures.length);
});

test("the harness must be re-pointed at real requests the moment a server exists", () => {
  // The tripwire. Verifying at the decision layer is the strongest thing
  // available while there is no HTTP layer, and it stops being sufficient the
  // instant there is one: a route can consult can() correctly in the model and
  // still forget to call it, which is the single most common way an endpoint
  // ends up unguarded.
  //
  // If this test is failing, you have just added src/api/server.ts. Add a
  // transport executor that drives real requests through it, use it for every
  // cell it can reach, and delete this test — do not delete it first.
  assert.equal(
    transportLayerExists(ROOT),
    false,
    "src/api/server.ts now exists, so the matrix must verify cells through real " +
      "requests rather than through can() alone. See the note above this assertion.",
  );
});
