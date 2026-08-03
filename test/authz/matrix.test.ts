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
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
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
import { isSafeMethod, ROUTES, routeKey, type Route } from "../../src/api/routes.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  describeFailure,
  runMatrix,
  summariseResults,
  writeMatrixReport,
  type CellExecutor,
  type CellResult,
} from "../support/matrix_harness.ts";
import {
  boundRouteKeys,
  createServer,
  transportCoverage,
  validateBindings,
  type ServerDeps,
} from "../../src/api/server.ts";
import { mintSessionToken, sessionTokenDigest } from "../../src/auth/model.ts";
import {
  cookiePolicy,
  CSRF_HEADER,
  csrfTokenForSessionId,
  insecureCookiesAcknowledged,
  resolveTrustedOrigins,
} from "../../src/api/csrf.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/**
 * A secrets directory that reads as already claimed.
 *
 * Every suite except the bootstrap one wants the endpoint closed — an open
 * bootstrap route would be a second way to create a tenant underneath a test
 * that is measuring something else.
 */
const CLAIMED_SECRETS_DIR = (() => {
  const dir = mkdtempSync(join(tmpdir(), "rl-claimed-"));
  writeFileSync(join(dir, "bootstrap.spent"), "claimed by the test fixture\n", { mode: 0o600 });
  return dir;
})();

/**
 * The server, driven as the deployment drives it.
 *
 * `resolveTenant` is replaced per-world below; everything else is real. A
 * harness that constructed a rearranged server would verify the rearrangement.
 */
const SERVER_DEPS: ServerDeps = {
  cookieSecret: new Uint8Array(32).fill(7),
  resolveTenant: () => Promise.resolve(null),
  signInIdentityId: "00000000-0000-4000-8000-000000000000",
  sealingKey: Buffer.alloc(32, 9),
  secretsDir: CLAIMED_SECRETS_DIR,
  trustedOrigins: ["http://127.0.0.1:7712"],
};

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

type Tree = { organization: string; project: string; environment: string; projectId: string };

type World = {
  readonly orgId: string;
  readonly own: Tree;
  readonly other: Tree;
  /** One user per role, each granted exactly that role at organization scope. */
  readonly userForRole: ReadonlyMap<string, string>;
  /** A REAL member of the other tenant — the IDOR subject for member routes. */
  readonly otherUserId: string;
  /**
   * A member who holds no role and whose sessions nothing depends on.
   *
   * THE MATRIX MUTATES THE WORLD IT MEASURES. `POST /members/:userId/revoke-sessions`
   * is a real request against a real repository, so it really ends that
   * member's sessions — and the first version aimed it at the Viewer, whose
   * own cells then answered 401 for the rest of the run. Two roles were
   * recorded as denied a permission they hold, because an earlier cell had
   * signed them out.
   *
   * The bystander exists to absorb that. Any state-changing route the matrix
   * learns to drive should be aimed here, and a route whose effect cannot be
   * absorbed needs the world rebuilt per cell rather than a shared one.
   */
  readonly bystanderId: string;
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
  const projectId = project.rows[0]?.id ?? "";

  const environmentNode = await node("environment", projectNode);
  await client.query(
    `insert into environments (org_id, project_id, scope_node_id, slug, name, kind)
     values ($1, $2, $3, 'production', 'Production', 'production')`,
    [orgId, project.rows[0]?.id ?? "", environmentNode],
  );

  return { organization, project: projectNode, environment: environmentNode, projectId };
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

  const bystander = await client.query<{ id: string }>(
    "insert into users (email, name) values ('bystander@acme.example', 'Bystander') returning id",
  );
  const bystanderId = bystander.rows[0]?.id ?? "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, bystanderId]);

  return {
    orgId,
    own: await seedTree(client, orgId),
    other: await seedTree(client, otherOrgId),
    userForRole,
    otherUserId: strangerId,
    bystanderId,
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

// ---------------------------------------------------------------------------
// The transport executor — a real request, through the real server
// ---------------------------------------------------------------------------

/**
 * Which cells a real request can actually express.
 *
 * Not all of them, and the reason is worth stating rather than hiding behind a
 * lower number. `other-tenant` and `nonexistent` are expressed by naming a
 * resource in the path. A route with NO identifier in its path — `GET /members`,
 * `GET /audit` — has no way to name one over HTTP: the tenant comes from the
 * session and nothing else. At the decision layer those cells are expressible,
 * because `can()` takes a scope node directly, so they stay verified there.
 *
 * Pretending otherwise would be the worse failure: driving `GET /audit` with a
 * foreign identifier that the URL cannot carry would test the actor's own
 * tenant and record it as an IDOR check that passed.
 */
function expressibleOverHttp(route: Route, subject: MatrixSubject): boolean {
  // An UNGUARDED route has nothing for this layer to say. Its claim is "no
  // permission is required", and a request cannot prove that by succeeding:
  // POST /auth/sign-in with no credentials answers 401, which is a refusal
  // about a password rather than about a permission. Driving it here recorded
  // seven roles being "denied" a route that has no guard at all. It stays a
  // declaration, checked structurally.
  if (route.requires === null) return false;

  if (subject === "own") return true;
  return route.scope !== "organization";
}

/** A live session for a role's user, written the way the schema defines one. */
async function mintSessionFor(
  client: Client,
  orgId: string,
  userId: string,
): Promise<{ token: string; sessionId: string }> {
  const token = mintSessionToken();
  const row = await client.query<{ id: string }>(
    `insert into sessions (org_id, user_id, token_hash, expires_at)
     values ($1, $2, $3, now() + interval '8 hours') returning id`,
    [orgId, userId, sessionTokenDigest(token)],
  );
  return { token, sessionId: row.rows[0]?.id ?? "" };
}

/**
 * Verify one cell by making a real request.
 *
 * The mapping from response to verdict is deliberately blunt: anything the
 * server answers other than a refusal is an allow. A 200 that happens to carry
 * an empty list is still the guard letting the request through, which is what
 * the matrix is asking about — and RL-M1-026's refusal is the only 404 the
 * server produces, which is why the comparison can be this simple.
 */
function transportExecutor(
  world: World,
  sessions: ReadonlyMap<string, { token: string; sessionId: string }>,
  cookieName: string,
): CellExecutor {
  const bound = boundRouteKeys(SERVER_DEPS);
  const app = createServer({
    ...SERVER_DEPS,
    resolveTenant: () => Promise.resolve(world.orgId),
  });

  const decide = decisionExecutor(world);

  return async (cell: MatrixCell) => {
    const route = ROUTE_BY_KEY.get(cell.routeKey);
    if (route === undefined) throw new Error(`no route for cell ${cell.routeKey}`);

    // Fall back rather than pretend. A cell the server does not bind, or one a
    // URL cannot express, is still verified — one layer down, and the report
    // says which.
    if (!bound.has(cell.routeKey) || !expressibleOverHttp(route, cell.subject)) {
      return decide(cell);
    }

    const session = sessions.get(cell.roleKey);
    const path = pathFor(route, cell.subject, world);

    // A real CSRF token on every unsafe method. Omitting it was the first
    // version's other bug, and the refusal it produced was CORRECT — the guard
    // is live. A matrix that left it out would measure CSRF instead of
    // authorization and report a permission failure for both.
    const headers: Record<string, string> = {
      cookie: `${cookieName}=${session?.token ?? ""}`,
      origin: "http://127.0.0.1:7712",
    };
    if (!isSafeMethod(route.method) && session !== undefined) {
      headers[CSRF_HEADER] = csrfTokenForSessionId(SERVER_DEPS.cookieSecret, session.sessionId);
    }

    const response = await app.request(path, { method: route.method, headers });

    const allowed = response.status !== 404 && response.status !== 401;
    return {
      layer: "transport",
      actual: allowed ? "allow" : "deny",
      signature: `${String(response.status)}:${(await response.text()).slice(0, 40)}`,
      detail: `${route.method} ${path} answered ${String(response.status)}`,
    };
  };
}

/**
 * The concrete path a cell asks for.
 *
 * Every `:param` is substituted, including on organization-scoped routes.
 * Leaving them was the first version's bug: `/members/:userId/revoke-sessions`
 * went to the server with the literal text `:userId`, the repository found no
 * such member, and three roles that DO hold the permission were recorded as
 * refused. A path parameter is not decoration because the scope happens to be
 * the organization.
 *
 * A parameter this does not know throws rather than passing through, for the
 * same reason NODE_FOR_PARAM does: a route silently addressed with a literal
 * would report its whole row as denied and look like a working guard.
 */
function pathFor(route: Route, subject: MatrixSubject, world: World): string {
  let path = route.path;
  for (const match of route.path.matchAll(/:([A-Za-z][A-Za-z0-9]*)/g)) {
    const param = match[1] ?? "";
    path = path.replace(`:${param}`, valueFor(param, subject, world));
  }
  return path;
}

function valueFor(param: string, subject: MatrixSubject, world: World): string {
  if (subject === "nonexistent") return randomUUID();
  const own = subject === "own";
  switch (param) {
    case "projectId":
      return own ? world.own.projectId : world.other.projectId;
    case "userId":
      // The bystander, not a role user. Someone other than the caller, so the
      // self-shortcut in revokeSessionsOfUser does not answer instead of the
      // permission — and someone the rest of the run does not depend on, because
      // this route really does end their sessions.
      return own ? world.bystanderId : world.otherUserId;
    default:
      throw new Error(
        `${param} is a path parameter the matrix harness cannot supply a value for. ` +
          `Add it — a route addressed with the literal ":${param}" reports its whole row ` +
          `as denied and looks like a working guard.`,
      );
  }
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

    // A live session per role, so the transport executor can present a real
    // cookie rather than a manufactured actor.
    const tokens = new Map<string, { token: string; sessionId: string }>();
    for (const [roleKey, userId] of world.userForRole) {
      tokens.set(roleKey, await mintSessionFor(client, world.orgId, userId));
    }
    const cookieName = cookiePolicy(resolveTrustedOrigins(), insecureCookiesAcknowledged()).name;

    await usingApplicationConnection(database, async () => {
      results = await runMatrix(cells, transportExecutor(world, tokens, cookieName));
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
      // `transport` joined the accepted set when the server landed — it is the
      // STRONGEST of the three, not an exception to the rule.
      for (const result of results) {
        assert.ok(
          result.layer === "transport" || result.layer === "decision" || result.layer === "declaration",
          `${describeFailure(result)}: verified by nothing`,
        );
      }
      assert.ok(report.verified_by.decision > 0);
      assert.ok(report.verified_by.transport > 0);
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

    await t.test("the report says how much of the matrix is verified end to end", () => {
      // This assertion used to demand ZERO, because there was no server. It now
      // demands the opposite: real requests reach real routes, and the number
      // is on the page rather than in a caveat.
      assert.ok(
        report.verified_by.transport > 0,
        "no cell was verified through a real request — the executor is falling back for all of them",
      );
      assert.ok(
        report.verified_by.decision > 0,
        "every cell claims transport verification, including ones a URL cannot express",
      );
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

test("the transport executor drives every route the server actually binds", () => {
  // This replaces the tripwire RL-M1-025 left here, which failed the moment
  // src/api/server.ts appeared. It has done its job: the harness is now pointed
  // at real requests, and what remains is to keep it honest about WHICH cells
  // it reaches.
  //
  // Not every declared route is bound — the server refuses to stub one it has
  // no repository function for, because a stub answers everybody the same way
  // and reports itself as guarded. So the coverage this asserts is the
  // intersection, and `transportCoverage()` is what STATUS reports.
  const coverage = transportCoverage(SERVER_DEPS);
  assert.ok(coverage.bound > 0, "the server binds nothing; transport coverage would still be zero");
  assert.ok(coverage.bound <= coverage.declared);
  assert.deepEqual(validateBindings(SERVER_DEPS), [], "a handler is bound to a route the table does not declare");
});
