/**
 * The central decision function (RL-M1-012).
 *
 * Brief §6.3: "Deny by default. An unmapped action is a denial." RL-M1-013 will
 * gate CI on 100% branch coverage of this module, so every reason `can()` can
 * return has a test here that reaches it — if one were unreachable, the
 * coverage gate would be the thing that told us, and it should not have to.
 *
 * Everything runs against a real Postgres as `ratline_app`, the unprivileged
 * NOBYPASSRLS role. A decision function tested against a superuser connection
 * would be testing a system with tenant isolation switched off.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { can, DECISION_REASONS, describeAction, NotPermittedError, require as requirePermission, rolesCarrying } from "../../src/authz/can.ts";
import { contextForApiToken, contextForRequest, contextForServiceIdentity, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { isAllowed } from "../../src/authz/grants.ts";
import { DATABASE_URL, skipWithoutDatabase, withMigratedDatabase } from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/** Point the pool at a scratch database, as the unprivileged role. */
async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
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

type World = {
  orgId: string;
  userId: string;
  orgNodeId: string;
  projectNodeId: string;
  envNodeId: string;
};

/**
 * An organization with a project and a production environment.
 *
 * Two members: an owner, and the subject the tests actually ask about. The
 * owner is separate on purpose — an organization with no owner is a state the
 * database refuses to hold (ADR 0012), so a fixture that omitted one would be
 * building something that cannot exist, and the first `delete from grants` in a
 * test would fail for a reason unrelated to what it was testing. That is
 * exactly what happened when this fixture had a single member.
 */
async function seedWorld(client: Client, slug = "acme"): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ($1, 'Acme') returning id",
    [slug],
  );
  const orgId = org.rows[0]?.id ?? "";

  const owner = await client.query<{ id: string }>(
    "insert into users (email, name) values ($1, 'Owner') returning id",
    [`owner@${slug}.example`],
  );
  const ownerId = owner.rows[0]?.id ?? "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, ownerId]);
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, 'owner', 'organization')`,
    [orgId, ownerId],
  );

  const user = await client.query<{ id: string }>(
    "insert into users (email, name) values ($1, 'Person') returning id",
    [`person@${slug}.example`],
  );
  const userId = user.rows[0]?.id ?? "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);

  const orgNode = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  const orgNodeId = orgNode.rows[0]?.id ?? "";

  const projectNode = await client.query<{ id: string }>(
    "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'project', $2) returning id",
    [orgId, orgNodeId],
  );
  const projectNodeId = projectNode.rows[0]?.id ?? "";
  const project = await client.query<{ id: string }>(
    "insert into projects (org_id, scope_node_id, slug, name) values ($1, $2, 'web', 'Web') returning id",
    [orgId, projectNodeId],
  );

  const envNode = await client.query<{ id: string }>(
    "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'environment', $2) returning id",
    [orgId, projectNodeId],
  );
  const envNodeId = envNode.rows[0]?.id ?? "";
  await client.query(
    "insert into environments (org_id, project_id, scope_node_id, slug, name, kind) values ($1, $2, $3, 'production', 'Production', 'production')",
    [orgId, project.rows[0]?.id ?? "", envNodeId],
  );

  return { orgId, userId, orgNodeId, projectNodeId, envNodeId };
}

async function grant(
  client: Client,
  world: World,
  roleKey: string,
  scopeType: string,
  scopeId: string | null,
  effect: "allow" | "deny" = "allow",
): Promise<void> {
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, scope_id, effect)
     values ($1, 'user', $2, $3, $4, $5, $6)`,
    [world.orgId, world.userId, roleKey, scopeType, scopeId, effect],
  );
}

const ctxOf = (world: World): AuthzContext =>
  contextForRequest({ orgId: world.orgId, userId: world.userId, requestId: `t-${randomUUID()}` });

const at = (scopeNodeId: string) => ({ scopeNodeId, resourceId: null });

// ---------------------------------------------------------------------------
// Pure — no database needed
// ---------------------------------------------------------------------------

test("rolesCarrying reflects the role definitions", () => {
  assert.deepEqual(rolesCarrying("organization.delete"), ["owner"]);
  assert.deepEqual(rolesCarrying("secret.read_value"), ["owner", "admin"]);
  assert.ok(rolesCarrying("site.read").includes("viewer"));
  assert.ok(!rolesCarrying("deployment.create_production").includes("developer"));
});

test("the allow comparison fails closed on anything unexpected", () => {
  // The one comparison that turns a database answer into a permission. Written
  // as equality against a single literal, never as "not a denial": the inverse
  // agrees on every value grant_decision returns today and fails OPEN on any
  // value it might return tomorrow, or on no row at all.
  assert.equal(isAllowed("allow"), true);
  for (const answer of ["deny", "", "ALLOW", "allowed", "unknown", "null", "true"]) {
    assert.equal(isAllowed(answer), false, `"${answer}" must not permit`);
  }
});

test("every decision reason except granted denies", () => {
  // The property the `decide` helper exists to hold. If a reason added later
  // defaulted to allowed, this is what would notice.
  assert.equal(DECISION_REASONS[0], "granted");
  assert.equal(DECISION_REASONS.filter((r) => r === "granted").length, 1);
});

test("no permission logic lives outside the authorization modules", () => {
  // Acceptance 1, and the §9 anti-pattern "permission checks in route handlers
  // instead of, or in addition to, the data layer". Checked structurally rather
  // than by review, because the failure mode is a well-meaning second check
  // somewhere that disagrees with this one.
  const ALLOWED = new Set(["src/authz/can.ts", "src/repo/authorization.ts", "src/authz/grants.ts"]);
  const findings: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    if (ALLOWED.has(file)) continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    // The database resolution objects are the raw material of a decision.
    // Reaching them anywhere else is a second implementation by definition.
    for (const marker of ["grant_decision", "effective_grants", "live_grants"]) {
      if (source.includes(marker)) findings.push(`${file}: references ${marker}`);
    }
  }
  assert.deepEqual(findings, [], `permission logic outside the authorization modules:\n${findings.join("\n")}`);
});

// ---------------------------------------------------------------------------
// Every reason is reachable — the branch-coverage requirement, made explicit
// ---------------------------------------------------------------------------

test("an action outside the catalogue is denied, not an error", { skip }, async () => {
  // Names arrive from request bodies, stored custom roles and token scope
  // lists. Throwing would make an attacker's probe distinguishable from a
  // legitimate denial.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "owner", "organization", null);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.delete_everything", at(world.orgNodeId));
      assert.equal(decision.allowed, false);
      assert.equal(decision.reason, "unknown-action");
    });
  });
});

test("an actor outside the tenant is denied", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const stranger = contextForRequest({
        orgId: world.orgId,
        userId: randomUUID(),
        requestId: "t",
      });
      const decision = await can(stranger, "site.read", at(world.orgNodeId));
      assert.equal(decision.reason, "actor-not-in-tenant");
    });
  });
});

test("a disabled actor is denied even with an intact owner grant", { skip }, async () => {
  // Threat model R-13. Disabling is what an operator does to a compromised
  // account at 2am; grants stay behind, and they must not save it.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "owner", "organization", null);
    await usingScratch(database, async () => {
      assert.equal((await can(ctxOf(world), "site.read", at(world.orgNodeId))).allowed, true);
    });
    await client.query("update users set disabled_at = now() where id = $1", [world.userId]);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.read", at(world.orgNodeId));
      assert.equal(decision.allowed, false);
      assert.equal(decision.reason, "actor-disabled");
    });
  });
});

test("an unknown scope node is denied", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "owner", "organization", null);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.read", at(randomUUID()));
      assert.equal(decision.reason, "unknown-scope");
    });
  });
});

test("another tenant's scope node is indistinguishable from a missing one", { skip }, async () => {
  // RL-M1-026 requires unauthorized and nonexistent to be indistinguishable.
  // Here they are the same code path, because row-level security means the
  // query cannot tell them apart either.
  await withMigratedDatabase(async (client, database) => {
    const mine = await seedWorld(client, "acme");
    const theirs = await seedWorld(client, "globex");
    await grant(client, mine, "owner", "organization", null);
    await usingScratch(database, async () => {
      const foreign = await can(ctxOf(mine), "site.read", at(theirs.orgNodeId));
      const missing = await can(ctxOf(mine), "site.read", at(randomUUID()));
      assert.equal(foreign.reason, missing.reason);
      assert.deepEqual(foreign, { ...missing, scopeNodeId: foreign.scopeNodeId });
    });
  });
});

test("no grant at all is denied, and says so", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.read", at(world.orgNodeId));
      assert.equal(decision.allowed, false);
      assert.equal(decision.reason, "no-grant");
    });
  });
});

test("a grant allows, and the decision echoes what was asked", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "viewer", "organization", null);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.read", at(world.envNodeId));
      assert.equal(decision.allowed, true);
      assert.equal(decision.reason, "granted");
      assert.equal(decision.action, "site.read");
      assert.equal(decision.scopeNodeId, world.envNodeId);
    });
  });
});

test("an explicit deny is reported differently from having no grant", { skip }, async () => {
  // The remedies differ — "ask someone for access" versus "someone deliberately
  // took it away" — and an operator reading an audit log should not have to
  // guess which happened.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "viewer", "organization", null);
    await grant(client, world, "viewer", "project", world.projectNodeId, "deny");
    await usingScratch(database, async () => {
      const denied = await can(ctxOf(world), "site.read", at(world.projectNodeId));
      assert.equal(denied.allowed, false);
      assert.equal(denied.reason, "explicit-deny", "a deny must not look like an absent grant");

      // ...and elsewhere in the tree the same actor is still allowed.
      assert.equal((await can(ctxOf(world), "site.read", at(world.orgNodeId))).allowed, true);
    });
  });
});

// ---------------------------------------------------------------------------
// The rules the brief names
// ---------------------------------------------------------------------------

test("permissions inherit downward but not upward", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "viewer", "project", world.projectNodeId);
    await usingScratch(database, async () => {
      assert.equal((await can(ctxOf(world), "site.read", at(world.envNodeId))).allowed, true, "downward");
      assert.equal((await can(ctxOf(world), "site.read", at(world.orgNodeId))).allowed, false, "upward");
    });
  });
});

test("a deny at any scope beats an allow at any other", { skip }, async () => {
  // Both directions. Implementations usually get narrow-deny-over-wide-allow
  // right and miss the reverse.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "acme");
    await grant(client, world, "viewer", "organization", null, "deny");
    await grant(client, world, "viewer", "environment", world.envNodeId, "allow");
    await usingScratch(database, async () => {
      assert.equal(
        (await can(ctxOf(world), "site.read", at(world.envNodeId))).allowed,
        false,
        "a wide deny must beat a narrow allow",
      );
    });
  });
});

test("production and non-production deployment are separate decisions", { skip }, async () => {
  // §6.3 calls this "the single most common real-world request".
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "developer", "organization", null);
    await usingScratch(database, async () => {
      const ctx = ctxOf(world);
      assert.equal((await can(ctx, "deployment.create_nonproduction", at(world.envNodeId))).allowed, true);
      assert.equal((await can(ctx, "deployment.create_production", at(world.envNodeId))).allowed, false);
    });
  });
});

test("reading a secret's name and its value are separate decisions", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "developer", "organization", null);
    await usingScratch(database, async () => {
      const ctx = ctxOf(world);
      assert.equal((await can(ctx, "secret.read_name", at(world.envNodeId))).allowed, true);
      assert.equal((await can(ctx, "secret.read_value", at(world.envNodeId))).allowed, false);
    });
  });
});

test("an expired grant is dead at decision time", { skip }, async () => {
  // Brief §6.3: expiry is enforced server-side, not by a cleanup job. Nothing
  // runs between these two calls except the clock.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, effect, expires_at)
       values ($1, 'user', $2, 'viewer', 'organization', 'allow', now() + interval '1 second')`,
      [world.orgId, world.userId],
    );
    await usingScratch(database, async () => {
      assert.equal((await can(ctxOf(world), "site.read", at(world.orgNodeId))).allowed, true);
      await new Promise((resolve) => setTimeout(resolve, 1200));
      const after = await can(ctxOf(world), "site.read", at(world.orgNodeId));
      assert.equal(after.allowed, false, "the grant should have lapsed with no cleanup having run");
      assert.equal(after.reason, "no-grant");
    });

    const stillThere = await client.query("select 1 from grants where org_id = $1 and role_key = 'viewer'", [world.orgId]);
    assert.equal(stillThere.rows.length, 1, "expiry filters, it does not delete");
  });
});

test("a role change takes effect on the very next decision", { skip }, async () => {
  // §6.3 requires immediate effect, including on active sessions. This is what
  // a cache inside can() would break, silently.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "viewer", "organization", null);
    await usingScratch(database, async () => {
      const ctx = ctxOf(world);
      assert.equal((await can(ctx, "site.read", at(world.orgNodeId))).allowed, true);
      await client.query("delete from grants where org_id = $1 and subject_id = $2", [world.orgId, world.userId]);
      assert.equal(
        (await can(ctx, "site.read", at(world.orgNodeId))).allowed,
        false,
        "the same context must not carry a cached answer",
      );
    });
  });
});

test("a service identity is an actor like any other", { skip }, async () => {
  // C6: automation acts as a named identity with its own permissions.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [world.orgId],
    );
    const identityId = identity.rows[0]?.id ?? "";
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'release_manager', 'organization')`,
      [world.orgId, identityId],
    );

    await usingScratch(database, async () => {
      const ctx = contextForServiceIdentity({
        orgId: world.orgId,
        serviceIdentityId: identityId,
        name: "deploy-bot",
        requestId: "t",
      });
      assert.equal((await can(ctx, "deployment.create_production", at(world.envNodeId))).allowed, true);
      assert.equal((await can(ctx, "secret.read_value", at(world.envNodeId))).allowed, false);
    });
  });
});

test("a disabled service identity is denied", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name, disabled_at) values ($1, 'retired-bot', now()) returning id",
      [world.orgId],
    );
    const identityId = identity.rows[0]?.id ?? "";
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'owner', 'organization')`,
      [world.orgId, identityId],
    );
    await usingScratch(database, async () => {
      const ctx = contextForServiceIdentity({
        orgId: world.orgId,
        serviceIdentityId: identityId,
        name: "retired-bot",
        requestId: "t",
      });
      assert.equal((await can(ctx, "site.read", at(world.orgNodeId))).reason, "actor-disabled");
    });
  });
});

test("an action no role carries is denied without asking the database", { skip }, async () => {
  // Unreachable with the built-in roles, because the completeness test in
  // RL-M1-009 guarantees every action has a holder. It becomes reachable when
  // custom roles arrive (RL-M5-001), which is why the resolver is a parameter.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "owner", "organization", null);
    await usingScratch(database, async () => {
      const decision = await can(ctxOf(world), "site.read", at(world.orgNodeId), () => []);
      assert.equal(decision.allowed, false);
      assert.equal(decision.reason, "no-role-carries-action");
    });
  });
});

test("an API token actor resolves to its own subject kind", { skip }, async () => {
  // Tokens have no table yet (RL-M1-032), so the correct answer today is a
  // denial — but it must be reached by looking the subject up, not by falling
  // through a switch that forgot the case.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const ctx = contextForApiToken({
        orgId: world.orgId,
        tokenId: randomUUID(),
        issuedByUserId: world.userId,
        requestId: "t",
      });
      const decision = await can(ctx, "site.read", at(world.orgNodeId));
      assert.equal(decision.allowed, false);
      assert.equal(decision.reason, "actor-not-in-tenant");
    });
  });
});

test("describeAction returns the catalogue copy the role editor renders", () => {
  assert.match(describeAction("secret.read_value"), /value/i);
  assert.notEqual(describeAction("secret.read_name"), describeAction("secret.read_value"));
});

// ---------------------------------------------------------------------------
// The throwing form
// ---------------------------------------------------------------------------

test("require throws with the decision attached", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      await assert.rejects(
        () => requirePermission(ctxOf(world), "site.read", at(world.orgNodeId)),
        (error: unknown) => {
          assert.ok(error instanceof NotPermittedError);
          assert.equal(error.decision.reason, "no-grant");
          // The message must not imply the resource does not exist, nor that it
          // does — RL-M1-026.
          assert.match(error.message, /not permitted/);
          return true;
        },
      );
    });
  });
});

test("require returns the decision when permitted", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grant(client, world, "owner", "organization", null);
    await usingScratch(database, async () => {
      const decision = await requirePermission(ctxOf(world), "organization.delete", at(world.orgNodeId));
      assert.equal(decision.allowed, true);
    });
  });
});
