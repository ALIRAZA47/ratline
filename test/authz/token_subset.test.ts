/**
 * Scoped API tokens, and the ceiling that makes them scoped (RL-M1-032).
 *
 * Brief §6.3: "API tokens carry a subset of the issuing user's permissions and
 * never more. Scoped, expiring, revocable, with last-used tracking and an
 * obvious revoke-all." Threat model R-12 recorded the gap this closes: until
 * now an `api_token` grant could be written with no intersection against its
 * issuer at all, so a token's permissions were whatever its grants said.
 *
 * The three acceptance criteria, and where each is proved:
 *
 *   1. A token can never carry a permission its issuing user lacks, checked at
 *      use time as well as issue time
 *        -> "a token cannot be issued carrying ..." (issue time)
 *        -> "downgrading the issuing user ..." (use time — the one that matters)
 *   2. Tokens expire, are revocable individually and in bulk, and track last use
 *        -> "an expired token is dead ...", "a revoked token ...",
 *           "revoke-all kills every token ...", "last use is recorded ..."
 *   3. A test downgrades the issuing user and confirms the token loses the
 *      permission immediately
 *        -> "downgrading the issuing user strips the token immediately"
 *
 * Two rules this file follows, both load-bearing:
 *
 * **Every assertion about a decision runs as `ratline_app`.** `usingScratch`
 * points the connection pool that `can()` and the repository use at the scratch
 * database as that role — unprivileged, NOBYPASSRLS — and `asApplicationRole`
 * does the same for the handful of raw-SQL assertions. The migration connection
 * is the superuser `initdb` created, and a superuser bypasses row-level security
 * unconditionally, so the same assertions written on it would pass without
 * exercising a single policy. Writes that are fixture setup are made on the
 * migration connection, because they are not the thing under test.
 *
 * **Nothing is mocked, and nothing is re-issued.** The headline test changes one
 * row and asks the same question again through the same context object. If it
 * ever needed a second call to anything to make the answer change, the answer
 * would be coming from somewhere other than the decision function.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { can, NotPermittedError, rolesCarrying } from "../../src/authz/can.ts";
import {
  contextForApiToken,
  contextForRequest,
  contextForServiceIdentity,
  type AuthzContext,
} from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  findApiTokenBySecret,
  issueApiToken,
  listApiTokensIssuedBy,
  recordApiTokenUse,
  revokeApiToken,
  revokeApiTokensIssuedBy,
  type ApiToken,
} from "../../src/repo/api_tokens.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

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
  /** The person who issues tokens in these tests. */
  userId: string;
  /** A second member, for the "someone else's token" cases. */
  otherId: string;
  orgNodeId: string;
  projectNodeId: string;
  envNodeId: string;
};

/**
 * An organization with a project, a production environment, and three members:
 * an owner, the issuer, and one other person.
 *
 * The owner is separate on purpose — an organization with no owner is a state
 * the database refuses to hold (ADR 0012), so the first `delete from grants` in
 * a test would fail for a reason unrelated to what it was testing.
 */
async function seedWorld(client: Client, slug = "acme"): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ($1, 'Acme') returning id",
    [slug],
  );
  const orgId = org.rows[0]?.id ?? "";

  const member = async (email: string, name: string): Promise<string> => {
    const row = await client.query<{ id: string }>(
      "insert into users (email, name) values ($1, $2) returning id",
      [email, name],
    );
    const id = row.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, id]);
    return id;
  };

  const ownerId = await member(`owner@${slug}.example`, "Owner");
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, 'owner', 'organization')`,
    [orgId, ownerId],
  );

  const userId = await member(`person@${slug}.example`, "Person");
  const otherId = await member(`other@${slug}.example`, "Other");

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
    `insert into environments (org_id, project_id, scope_node_id, slug, name, kind)
     values ($1, $2, $3, 'production', 'Production', 'production')`,
    [orgId, project.rows[0]?.id ?? "", envNodeId],
  );

  return { orgId, userId, otherId, orgNodeId, projectNodeId, envNodeId };
}

/** A role assignment for a user, written as fixture setup. */
async function grantRole(
  client: Client,
  orgId: string,
  userId: string,
  roleKey: string,
  scopeType = "organization",
  scopeId: string | null = null,
): Promise<void> {
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, scope_id)
     values ($1, 'user', $2, $3, $4, $5)`,
    [orgId, userId, roleKey, scopeType, scopeId],
  );
}

const userCtx = (world: World, userId: string): AuthzContext =>
  contextForRequest({ orgId: world.orgId, userId, requestId: `t-${randomUUID()}` });

const tokenCtx = (world: World, token: ApiToken): AuthzContext =>
  contextForApiToken({
    orgId: world.orgId,
    tokenId: token.id,
    issuedByUserId: token.issuedBy,
    requestId: `t-${randomUUID()}`,
  });

const at = (scopeNodeId: string) => ({ scopeNodeId, resourceId: null });

/** An hour from now — every token must name an expiry, so every test names one. */
const inAnHour = (): Date => new Date(Date.now() + 60 * 60 * 1000);

// ---------------------------------------------------------------------------
// ACCEPTANCE 3 — the headline
// ---------------------------------------------------------------------------

test("downgrading the issuing user strips the token immediately", { skip }, async () => {
  // THE test this task exists for, and the half of R-12 that an issue-time check
  // cannot close. Between the allow and the deny, exactly one thing happens: the
  // issuer's grant is removed. The token is not re-issued, not revoked, not
  // expired, and its own grant is untouched — asserted at the end, so "the token
  // stopped working" cannot be explained by anything except the ceiling.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token } = await issueApiToken(issuer, {
        name: "CI deploys",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });

      // The same context object is reused across the change, so a cached answer
      // inside it would show up as a false pass.
      const asToken = tokenCtx(world, token);
      const before = await can(asToken, "deployment.create_nonproduction", at(world.envNodeId));
      assert.equal(before.allowed, true, "the token should work while its issuer holds the role");
      assert.equal(before.reason, "granted");

      // The downgrade. One row, removed by someone else, mid-flight.
      await client.query(
        "delete from grants where org_id = $1 and subject_type = 'user' and subject_id = $2",
        [world.orgId, world.userId],
      );

      const after = await can(asToken, "deployment.create_nonproduction", at(world.envNodeId));
      assert.equal(after.allowed, false, "the token must lose the permission with no re-issue");
      assert.equal(
        after.reason,
        "exceeds-issuer",
        "and the reason must say the issuer is the problem, not the token",
      );
    });

    // Nothing else ran. The token is live and its own grant is intact and
    // unexpired — the only thing that changed is who is behind it.
    const tokenRow = await client.query<{ revoked_at: Date | null; expires_at: Date }>(
      "select revoked_at, expires_at from api_tokens where org_id = $1",
      [world.orgId],
    );
    assert.equal(tokenRow.rows.length, 1);
    assert.equal(tokenRow.rows[0]?.revoked_at, null, "the token was not revoked");
    assert.ok((tokenRow.rows[0]?.expires_at.getTime() ?? 0) > Date.now(), "and has not expired");

    const tokenGrants = await client.query<{ expires_at: Date | null }>(
      "select expires_at from grants where org_id = $1 and subject_type = 'api_token'",
      [world.orgId],
    );
    assert.equal(tokenGrants.rows.length, 1, "the token's own grant is still there");
    assert.equal(tokenGrants.rows[0]?.expires_at, null, "and was never given an expiry");
  });
});

// ---------------------------------------------------------------------------
// ACCEPTANCE 1 — the ceiling, at issue time and at use time
// ---------------------------------------------------------------------------

test("a token cannot be issued carrying a permission its issuer lacks", { skip }, async () => {
  // The easy half, and the one an operator notices: a Developer asking for a
  // Release Manager token is refused rather than handed something that silently
  // does nothing.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      await assert.rejects(
        () =>
          issueApiToken(issuer, {
            name: "too much",
            expiresAt: inAnHour(),
            grants: [{ roleKey: "release_manager", scopeNodeId: world.orgNodeId, resourceId: null }],
          }),
        (error: unknown) => {
          assert.ok(error instanceof NotPermittedError);
          // Whichever action it stopped on, it has to be one the issuer's role
          // genuinely does not carry — asserted by the role model rather than by
          // naming an action, so a reordering of the role's list cannot make
          // this test pass for the wrong reason.
          assert.ok(
            !rolesCarrying(error.decision.action as never).includes("developer"),
            `stopped on ${error.decision.action}, which a developer does hold`,
          );
          assert.equal(error.decision.reason, "no-grant");
          return true;
        },
      );
    });

    // Refused before anything was written: no token, no grant, no orphan.
    const tokens = await client.query("select 1 from api_tokens where org_id = $1", [world.orgId]);
    assert.equal(tokens.rows.length, 0, "a refused issue must leave nothing behind");
    const grants = await client.query("select 1 from grants where subject_type = 'api_token'");
    assert.equal(grants.rows.length, 0);
  });
});

test("a token holds the intersection, so it may hold strictly less than its issuer", { skip }, async () => {
  // The ceiling is an upper bound, not an equality. A token that could only ever
  // hold exactly what its issuer holds would be a copy of the user, which is the
  // opposite of "scoped".
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token } = await issueApiToken(issuer, {
        name: "read only",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);

      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      const narrower = await can(asToken, "deployment.create_nonproduction", at(world.envNodeId));
      assert.equal(narrower.allowed, false, "the token was never given this");
      assert.equal(narrower.reason, "no-grant", "and the token's own grants are what refuse it");

      // The test must not pass because the issuer lacks it too.
      assert.equal(
        (await can(issuer, "deployment.create_nonproduction", at(world.envNodeId))).allowed,
        true,
        "the issuing user does hold it — the token simply was not given it",
      );
    });
  });
});

test("a token's scope narrows independently of its issuer's", { skip }, async () => {
  // Scoping and the ceiling are separate constraints and both apply: an
  // organization-wide Developer may mint a token that reaches one project only.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token } = await issueApiToken(issuer, {
        name: "one project",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.projectNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);

      assert.equal(
        (await can(asToken, "deployment.create_nonproduction", at(world.envNodeId))).allowed,
        true,
        "downward, into the environment under the project",
      );
      assert.equal(
        (await can(asToken, "deployment.create_nonproduction", at(world.orgNodeId))).allowed,
        false,
        "but never upward, even though the issuer holds it there",
      );
    });
  });
});

test("a deny on the issuer strips the token, wherever the deny sits", { skip }, async () => {
  // The ceiling is the same `grant_decision` call the primary decision uses, so
  // "denies always win" reaches a token through its issuer for free. Written out
  // because the alternative implementation — comparing role lists at issue time
  // — gets exactly this case wrong.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token } = await issueApiToken(issuer, {
        name: "CI",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);
      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      // A narrower deny on the ISSUER, added after the token existed.
      await client.query(
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, scope_id, effect)
         values ($1, 'user', $2, 'developer', 'project', $3, 'deny')`,
        [world.orgId, world.userId, world.projectNodeId],
      );

      assert.equal(
        (await can(asToken, "site.read", at(world.envNodeId))).reason,
        "exceeds-issuer",
        "a deny reaching the issuer must reach the token",
      );
      assert.equal(
        (await can(asToken, "site.read", at(world.orgNodeId))).allowed,
        true,
        "and must not reach further than it reaches for the issuer",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// A disabled or departed issuer
// ---------------------------------------------------------------------------

test("a disabled issuer's token stops working", { skip }, async () => {
  // Disabling is what an operator does to a compromised account at 2am (threat
  // model R-13). If the tokens that account minted kept working, disabling it
  // would close the front door and leave the side door open.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const { token } = await issueApiToken(userCtx(world, world.userId), {
        name: "CI",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);
      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      await client.query("update users set disabled_at = now() where id = $1", [world.userId]);

      const after = await can(asToken, "site.read", at(world.envNodeId));
      assert.equal(after.allowed, false);
      assert.equal(after.reason, "issuer-disabled");
    });
  });
});

test("a departed issuer's token stops working, with its grants intact", { skip }, async () => {
  // Removing a person from the organization "ends their access immediately"
  // (the `member.remove` action). A token is access. The row survives for the
  // audit log — deliberately, see migration 7 note 5 — and is inert.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const { token } = await issueApiToken(userCtx(world, world.userId), {
        name: "CI",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);
      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      await client.query("delete from memberships where org_id = $1 and user_id = $2", [
        world.orgId,
        world.userId,
      ]);

      const after = await can(asToken, "site.read", at(world.envNodeId));
      assert.equal(after.allowed, false);
      assert.equal(after.reason, "issuer-not-in-tenant");
    });

    // The issuer's own grants are still there. The token died because the
    // person left, not because anything cleaned up after them.
    const stillGranted = await client.query(
      "select 1 from grants where subject_type = 'user' and subject_id = $1",
      [world.userId],
    );
    assert.equal(stillGranted.rows.length, 1);
    const stillThere = await client.query("select 1 from api_tokens where id is not null");
    assert.equal(stillThere.rows.length, 1, "the token row survives for the audit log");
  });
});

// ---------------------------------------------------------------------------
// ACCEPTANCE 2 — expiry, revocation, revoke-all, last use
// ---------------------------------------------------------------------------

test("an expired token is dead, and expiry filters rather than deletes", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const { token } = await issueApiToken(userCtx(world, world.userId), {
        name: "short-lived",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);
      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      // Backdated rather than waited out: the CHECK compares the expiry against
      // the row's own creation, not the wall clock, precisely so a row can be
      // moved into the past honestly. Nothing runs in between.
      await client.query(
        `update api_tokens
         set created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
         where id = $1`,
        [token.id],
      );

      const after = await can(asToken, "site.read", at(world.envNodeId));
      assert.equal(after.allowed, false, "an expired token must not act");
      assert.equal(after.reason, "actor-disabled", "an expired credential is a disabled actor");

      assert.equal(
        await findApiTokenBySecret(userCtx(world, world.userId), "irrelevant"),
        null,
      );
    });

    const row = await client.query("select 1 from api_tokens where id is not null");
    assert.equal(row.rows.length, 1, "expiry filters, it does not delete");
  });
});

test("expiry and revocation are predicates in the view, not a cleanup job", { skip }, async () => {
  // Structural evidence for §6.3's "enforced server-side, not by a cleanup job",
  // and for ADR 0012's clock. It is also the only honest way to pin
  // `statement_timestamp()` here: every decision opens its own transaction, so
  // `now()` and `statement_timestamp()` would be indistinguishable through
  // `can()` however long the test waited.
  await withMigratedDatabase(async (client) => {
    const view = await client.query<{ definition: string }>(
      "select pg_get_viewdef('live_api_tokens'::regclass, true) as definition",
    );
    const definition = view.rows[0]?.definition ?? "";
    assert.match(definition, /revoked_at IS NULL/i, "revocation must be a predicate");
    assert.match(definition, /expires_at/, "and so must expiry");
    assert.match(definition, /statement_timestamp\(\)/, "evaluated per statement, not per transaction");

    // A view runs as its OWNER unless told otherwise, and the owner here is a
    // superuser — which would hand every tenant's tokens to any caller.
    const options = await client.query<{ reloptions: string[] | null }>(
      "select reloptions from pg_class where relname = 'live_api_tokens'",
    );
    assert.deepEqual(options.rows[0]?.reloptions, ["security_invoker=true"]);

    // Nothing on a schedule, and nothing hanging off the table.
    const triggers = await client.query<{ tgname: string }>(
      "select tgname from pg_trigger where tgrelid = 'api_tokens'::regclass and not tgisinternal",
    );
    assert.deepEqual(triggers.rows.map((r) => r.tgname), []);
  });
});

test("a revoked token stops working, and revoking is idempotent", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token } = await issueApiToken(issuer, {
        name: "laptop",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      const asToken = tokenCtx(world, token);
      assert.equal((await can(asToken, "site.read", at(world.envNodeId))).allowed, true);

      assert.equal(await revokeApiToken(issuer, token.id), true);

      const after = await can(asToken, "site.read", at(world.envNodeId));
      assert.equal(after.allowed, false, "a revoked token must not act");
      assert.equal(after.reason, "actor-disabled");

      assert.equal(await revokeApiToken(issuer, token.id), false, "revoking twice is not an error");
      assert.equal(
        await revokeApiToken(issuer, randomUUID()),
        false,
        "and a token that does not exist is the same answer as one that is not yours",
      );

      // Still listed, marked revoked — "inspect" means seeing what you killed.
      const listed = await listApiTokensIssuedBy(issuer, world.userId);
      assert.equal(listed.length, 1);
      assert.notEqual(listed[0]?.revokedAt, null);
    });
  });
});

test("revoke-all kills every token a person holds, and nobody else's", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");
    await grantRole(client, world.orgId, world.otherId, "developer");

    await usingScratch(database, async () => {
      const mine = userCtx(world, world.userId);
      const theirs = userCtx(world, world.otherId);
      const spec = {
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      };

      const first = await issueApiToken(mine, { name: "ci", ...spec });
      await issueApiToken(mine, { name: "laptop", ...spec });
      await issueApiToken(mine, { name: "phone", ...spec });
      const other = await issueApiToken(theirs, { name: "their ci", ...spec });

      assert.equal(await revokeApiTokensIssuedBy(mine, world.userId), 3, "all three at once");
      assert.equal(
        await revokeApiTokensIssuedBy(mine, world.userId),
        0,
        "and nothing left live to revoke a second time",
      );

      assert.equal(
        (await can(tokenCtx(world, first.token), "site.read", at(world.envNodeId))).reason,
        "actor-disabled",
      );
      assert.equal(
        (await can(tokenCtx(world, other.token), "site.read", at(world.envNodeId))).allowed,
        true,
        "someone else's token must survive — this is revoke-all, not revoke-everything",
      );
    });
  });
});

test("last use is recorded, and a dead token has no use to record", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const { token, secret } = await issueApiToken(issuer, {
        name: "ci",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      assert.equal(token.lastUsedAt, null, "a token that has never been used says so");

      // The shape the authentication path has: a secret arrives, it names a live
      // token, and using it is recorded once for the request.
      const found = await findApiTokenBySecret(issuer, secret);
      assert.equal(found?.id, token.id);

      const usedAt = await recordApiTokenUse(tokenCtx(world, token), token.id);
      assert.ok(usedAt instanceof Date, "the instant of use is returned");

      const listed = await listApiTokensIssuedBy(issuer, world.userId);
      assert.equal(listed[0]?.lastUsedAt?.getTime(), usedAt.getTime());

      await revokeApiToken(issuer, token.id);
      assert.equal(
        await recordApiTokenUse(tokenCtx(world, token), token.id),
        null,
        "a revoked token cannot be used, so there is nothing to record",
      );
      assert.equal(await findApiTokenBySecret(issuer, secret), null);
    });
  });
});

// ---------------------------------------------------------------------------
// The secret
// ---------------------------------------------------------------------------

test("the secret is returned once and never stored", { skip }, async () => {
  // A token that can be read back out of the database is a stored credential,
  // and a database backup becomes a set of live logins.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    let secret = "";
    let tokenId = "";
    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const issued = await issueApiToken(issuer, {
        name: "ci",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });
      secret = issued.secret;
      tokenId = issued.token.id;

      assert.match(secret, /^rlt_[A-Za-z0-9_-]{43}$/, "256 bits, base64url, and labelled");
      assert.ok(!Object.keys(issued.token).includes("secret"), "the token itself carries no secret");

      assert.equal((await findApiTokenBySecret(issuer, secret))?.id, tokenId);
      assert.equal(
        await findApiTokenBySecret(issuer, `${secret}x`),
        null,
        "a secret that is nearly right is entirely wrong",
      );
    });

    // Every column of the stored row, checked against the plaintext. Not just
    // token_hash: the point is that the secret is nowhere, not that one named
    // column does not hold it.
    const row = await client.query<Record<string, unknown>>("select * from api_tokens where id = $1", [
      tokenId,
    ]);
    const stored = row.rows[0] ?? {};
    for (const [column, value] of Object.entries(stored)) {
      assert.notEqual(String(value), secret, `${column} holds the plaintext token`);
    }
    assert.match(String(stored["token_hash"]), /^[0-9a-f]{64}$/, "what is stored is a digest");

    // And the schema refuses a plaintext even written by hand.
    await assert.rejects(
      () => client.query("update api_tokens set token_hash = $1 where id = $2", [secret, tokenId]),
      /api_tokens_hash_shape/,
    );
  });
});

// ---------------------------------------------------------------------------
// Who may manage a token
// ---------------------------------------------------------------------------

test("a token cannot issue another token", { skip }, async () => {
  // The delegation chain closing itself: "a subset of the issuing user's
  // permissions" has no meaning when the issuer is not a user.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const { token } = await issueApiToken(userCtx(world, world.userId), {
        name: "ci",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });

      await assert.rejects(
        () =>
          issueApiToken(tokenCtx(world, token), {
            name: "a child token",
            expiresAt: inAnHour(),
            grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
          }),
        /only a user may issue an API token/,
      );

      const identity = await client.query<{ id: string }>(
        "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
        [world.orgId],
      );
      await assert.rejects(
        () =>
          issueApiToken(
            contextForServiceIdentity({
              orgId: world.orgId,
              serviceIdentityId: identity.rows[0]?.id ?? "",
              name: "deploy-bot",
              requestId: "t",
            }),
            { name: "bot token", expiresAt: inAnHour(), grants: [] },
          ),
        /only a user may issue an API token/,
      );
    });
  });
});

test("reaching someone else's tokens takes the administrative action, not your own", { skip }, async () => {
  // The catalogue splits `api_token.manage_own` from `read_any` / `revoke_any`
  // because managing your own escalates nothing — a token never carries more
  // than you hold — while reaching someone else's is administration.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");
    await grantRole(client, world.orgId, world.otherId, "developer");

    await usingScratch(database, async () => {
      const mine = userCtx(world, world.userId);
      const theirs = userCtx(world, world.otherId);
      const { token } = await issueApiToken(theirs, {
        name: "their ci",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
      });

      // A Developer holds manage_own and nothing more.
      await assert.rejects(
        () => revokeApiToken(mine, token.id),
        (error: unknown) =>
          error instanceof NotPermittedError && error.decision.action === "api_token.revoke_any",
      );
      await assert.rejects(
        () => listApiTokensIssuedBy(mine, world.otherId),
        (error: unknown) =>
          error instanceof NotPermittedError && error.decision.action === "api_token.read_any",
      );
      await assert.rejects(
        () => revokeApiTokensIssuedBy(mine, world.otherId),
        (error: unknown) => error instanceof NotPermittedError,
      );

      // An Admin holds both, and revoke-all is the thing they reach for.
      await client.query(
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
         values ($1, 'user', $2, 'admin', 'organization')`,
        [world.orgId, world.userId],
      );
      assert.equal((await listApiTokensIssuedBy(mine, world.otherId)).length, 1);
      assert.equal(await revokeApiTokensIssuedBy(mine, world.otherId), 1);
    });
  });
});

test("issuing requires the permission to issue", { skip }, async () => {
  // Checked in the data layer, not left to a route handler (brief §9). A Viewer
  // deliberately holds no `api_token.manage_own` at all.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "viewer");

    await usingScratch(database, async () => {
      await assert.rejects(
        () =>
          issueApiToken(userCtx(world, world.userId), {
            name: "nope",
            expiresAt: inAnHour(),
            grants: [{ roleKey: "viewer", scopeNodeId: world.orgNodeId, resourceId: null }],
          }),
        (error: unknown) =>
          error instanceof NotPermittedError && error.decision.action === "api_token.manage_own",
      );
    });
  });
});

test("a role whose actions cannot be enumerated is refused rather than issued", { skip }, async () => {
  // Fail closed. A role with no known actions would make the ceiling check
  // vacuously true — every one of zero actions is permitted — so an unknown role
  // key, or a resolver that returns nothing, must stop the issue rather than
  // produce a token whose ceiling was never tested.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await grantRole(client, world.orgId, world.userId, "developer");

    await usingScratch(database, async () => {
      const issuer = userCtx(world, world.userId);
      const spec = (roleKey: string) => ({
        name: "unknown role",
        expiresAt: inAnHour(),
        grants: [{ roleKey, scopeNodeId: world.orgNodeId, resourceId: null }],
      });

      await assert.rejects(() => issueApiToken(issuer, spec("wizard")), /is not a role/);
      await assert.rejects(
        () => issueApiToken(issuer, spec("viewer"), () => []),
        /carries no actions/,
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

test("a token is invisible and unusable outside its tenant", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const mine = await seedWorld(client, "acme");
    const theirs = await seedWorld(client, "globex");
    await grantRole(client, mine.orgId, mine.userId, "developer");

    let tokenId = "";
    let issuedBy = "";
    await usingScratch(database, async () => {
      const { token } = await issueApiToken(userCtx(mine, mine.userId), {
        name: "ci",
        expiresAt: inAnHour(),
        grants: [{ roleKey: "developer", scopeNodeId: mine.orgNodeId, resourceId: null }],
      });
      tokenId = token.id;
      issuedBy = token.issuedBy;

      // The other tenant, naming a real token id it should not know.
      const foreign = contextForApiToken({
        orgId: theirs.orgId,
        tokenId,
        issuedByUserId: issuedBy,
        requestId: "t",
      });
      assert.equal(
        (await can(foreign, "site.read", at(theirs.orgNodeId))).reason,
        "actor-not-in-tenant",
        "a token from another organization is not an actor here",
      );
    });

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, theirs.orgId);
      const rows = await app.query("select 1 from api_tokens");
      assert.equal(rows.rows.length, 0, "row-level security must hide the whole table");
      const live = await app.query("select 1 from live_api_tokens");
      assert.equal(live.rows.length, 0, "including through the liveness view");
      await app.query("rollback");
    });

    // And symmetrically, so the test cannot pass by there being nothing.
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine.orgId);
      const rows = await app.query<{ id: string }>("select id from live_api_tokens");
      assert.deepEqual(rows.rows.map((r) => r.id), [tokenId]);
      await app.query("rollback");
    });
  });
});
