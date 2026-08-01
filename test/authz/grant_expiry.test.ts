/**
 * Grants, denies and time-bound scoping (RL-M1-011).
 *
 * The four acceptance criteria, and where each is proved:
 *
 *   1. A grant attaches a role to any node in the hierarchy for a user, service
 *      identity or token    -> "a grant attaches at every level ...", "... for
 *                              every kind of subject"
 *   2. Denies exist and always win over grants
 *                           -> "a narrower deny beats a wider allow" AND
 *                              "a wider deny beats a narrower allow"
 *   3. Expiry is evaluated at decision time
 *                           -> "an already-expired grant is dead ..."
 *   4. A test advances the clock past expiry and confirms denial with no
 *      cleanup job having run
 *                           -> "a grant dies mid-transaction the moment it
 *                              expires"
 *
 * Two rules this file follows, both of them load-bearing:
 *
 * **Every assertion about a decision runs as `ratline_app`.** The migration
 * connection is the superuser `initdb` created, and a superuser bypasses
 * row-level security unconditionally — so the same assertions written on that
 * connection would pass without exercising a single policy, including the
 * `security_invoker` setting on the view that the whole tenant boundary of this
 * feature rests on. Writes are made on the migration connection, because they
 * are fixture setup rather than the thing under test.
 *
 * **The clock is never mocked.** Acceptance 4 says "advances the clock", and
 * the only honest version of that with a server-side predicate is real time:
 * rows are written with real past timestamps, or the test waits. The waiting
 * test holds ONE transaction open across the expiry so that "no cleanup job
 * having run" is not a claim about the system but a property of the test — no
 * statement of any kind is issued between the allow and the deny.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { setTimeout as sleep } from "node:timers/promises";
import type { Client } from "pg";

import {
  asApplicationRole,
  seedOrganization,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";
import { GRANT_EFFECTS, isAllowed, SUBJECT_TYPES } from "../../src/authz/grants.ts";

const skip = skipWithoutDatabase;

// ---------------------------------------------------------------------------
// Local fixtures.
//
// These live here rather than in test/support/db.ts because another workstream
// owns that file right now. `seedTree` and `insertGrant` are general enough that
// they should move there once RL-M1-012 needs them too — noted rather than done.
// ---------------------------------------------------------------------------

type Tree = {
  readonly orgNodeId: string;
  readonly teamNodeId: string;
  readonly projectNodeId: string;
  readonly envNodeId: string;
};

/** organization -> team -> project -> environment, returning each scope node id. */
async function seedTree(client: Client, orgId: string, slug = "web"): Promise<Tree> {
  const root = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  const orgNodeId = root.rows[0]?.id ?? "";

  const node = async (kind: string, parent: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, $2, $3) returning id",
      [orgId, kind, parent],
    );
    return r.rows[0]?.id ?? "";
  };

  const teamNodeId = await node("team", orgNodeId);
  await client.query("insert into teams (org_id, scope_node_id, slug, name) values ($1, $2, $3, 'Team')", [
    orgId,
    teamNodeId,
    `${slug}-team`,
  ]);

  const projectNodeId = await node("project", teamNodeId);
  const project = await client.query<{ id: string }>(
    "insert into projects (org_id, scope_node_id, slug, name) values ($1, $2, $3, 'Project') returning id",
    [orgId, projectNodeId, slug],
  );

  const envNodeId = await node("environment", projectNodeId);
  await client.query(
    `insert into environments (org_id, project_id, scope_node_id, slug, name, kind)
     values ($1, $2, $3, 'production', 'Production', 'production')`,
    [orgId, project.rows[0]?.id ?? "", envNodeId],
  );

  return { orgNodeId, teamNodeId, projectNodeId, envNodeId };
}

async function addUser(client: Client, orgId: string, email: string): Promise<string> {
  const user = await client.query<{ id: string }>(
    "insert into users (email, name) values ($1, 'Person') returning id",
    [email],
  );
  const userId = user.rows[0]?.id ?? "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);
  return userId;
}

type GrantSpec = {
  readonly orgId: string;
  readonly subjectId: string;
  readonly roleKey: string;
  readonly scopeType: string;
  readonly scopeId?: string | null;
  readonly subjectType?: string;
  readonly effect?: string;
  /** Interval added to now() for `created_at`. Negative backdates the row. */
  readonly createdOffset?: string;
  /** Interval added to now() for `expires_at`. Absent or null means never. */
  readonly expiresOffset?: string | null;
};

/**
 * Insert a grant. Times are expressed as intervals from now so a test never has
 * to name an absolute instant, and `createdOffset` exists so an ALREADY expired
 * row can be written without waiting for one to expire — the constraint refuses
 * an expiry before the row's own creation, not an expiry in the past.
 */
async function insertGrant(client: Client, spec: GrantSpec): Promise<string> {
  const r = await client.query<{ id: string }>(
    `insert into grants
       (org_id, subject_type, subject_id, role_key, scope_type, scope_id, effect, created_at, expires_at)
     values ($1, $2, $3, $4, $5, $6, $7, now() + $8::interval, now() + $9::interval)
     returning id`,
    [
      spec.orgId,
      spec.subjectType ?? "user",
      spec.subjectId,
      spec.roleKey,
      spec.scopeType,
      spec.scopeId ?? null,
      spec.effect ?? "allow",
      spec.createdOffset ?? "0 seconds",
      spec.expiresOffset ?? null,
    ],
  );
  return r.rows[0]?.id ?? "";
}

type Question = {
  readonly subjectId: string;
  readonly nodeId: string;
  readonly roleKeys: readonly string[];
  readonly subjectType?: string;
  readonly resourceId?: string | null;
};

/**
 * The decision, asked exactly the way `can()` will ask it. Casts are explicit so
 * the interface RL-M1-012 has to satisfy is visible in the call rather than
 * inferred by the server.
 */
async function decide(app: Client, q: Question): Promise<string> {
  const r = await app.query<{ decision: string }>(
    "select grant_decision($1::text, $2::uuid, $3::uuid, $4::text[], $5::uuid) as decision",
    [q.subjectType ?? "user", q.subjectId, q.nodeId, [...q.roleKeys], q.resourceId ?? null],
  );
  return r.rows[0]?.decision ?? "";
}

/** One transaction as the unprivileged application role, with the tenant set. */
async function asTenant<T>(
  database: string,
  orgId: string | null,
  fn: (app: Client) => Promise<T>,
): Promise<T> {
  return asApplicationRole(database, async (app) => {
    await app.query("begin");
    try {
      await setTenant(app, orgId);
      return await fn(app);
    } finally {
      await app.query("rollback");
    }
  });
}

/** The roles a hypothetical action belongs to, for the questions below. */
const DEV = ["developer"] as const;

// ---------------------------------------------------------------------------
// Acceptance 1 — a grant attaches a role to any node, for any kind of subject
// ---------------------------------------------------------------------------

test("a grant attaches at every level of the hierarchy", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    // Each level in turn, asked at the environment at the bottom of the tree.
    const levels = [
      ["organization", null, tree.orgNodeId],
      ["team", tree.teamNodeId, tree.teamNodeId],
      ["project", tree.projectNodeId, tree.projectNodeId],
      ["environment", tree.envNodeId, tree.envNodeId],
    ] as const;

    for (const [scopeType, scopeId] of levels) {
      const id = await insertGrant(client, {
        orgId,
        subjectId: alice,
        roleKey: "developer",
        scopeType,
        scopeId,
      });

      const answer = await asTenant(database, orgId, (app) =>
        decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
      );
      assert.equal(answer, "allow", `a ${scopeType}-scope grant should convey at the environment`);
      assert.ok(isAllowed(answer));

      await client.query("delete from grants where id = $1", [id]);
    }
  });
});

test("a grant attaches for every kind of subject the brief names", { skip }, async () => {
  // Brief §6.3 and PLAN §4: user, service identity, API token. The token id is
  // a bare uuid because there is no api_tokens table yet (RL-M1-030) — what is
  // being proved here is that the subject kind resolves, not that the token
  // exists.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);

    const alice = await addUser(client, orgId, "alice@acme.example");
    const bot = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [orgId],
    );
    const token = await client.query<{ id: string }>("select gen_random_uuid() as id");

    const subjects = [
      ["user", alice],
      ["service_identity", bot.rows[0]?.id ?? ""],
      ["api_token", token.rows[0]?.id ?? ""],
    ] as const;

    for (const [subjectType, subjectId] of subjects) {
      await insertGrant(client, {
        orgId,
        subjectType,
        subjectId,
        roleKey: "developer",
        scopeType: "project",
        scopeId: tree.projectNodeId,
      });
    }

    for (const [subjectType, subjectId] of subjects) {
      const answer = await asTenant(database, orgId, (app) =>
        decide(app, { subjectType, subjectId, nodeId: tree.envNodeId, roleKeys: DEV }),
      );
      assert.equal(answer, "allow", `a ${subjectType} grant should resolve`);
    }

    // And the kinds do not bleed into one another: the same id under a
    // different subject kind is a different subject.
    const crossed = await asTenant(database, orgId, (app) =>
      decide(app, { subjectType: "api_token", subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
    );
    assert.equal(crossed, "deny", "subject_type must be part of the identity, not decoration");
  });
});

test("an unknown subject kind is refused by the database", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        insertGrant(client, {
          orgId,
          subjectType: "robot",
          subjectId: "00000000-0000-0000-0000-000000000001",
          roleKey: "developer",
          scopeType: "organization",
        }),
      /grants_subject_type/,
    );
  });
});

// ---------------------------------------------------------------------------
// Inheritance direction — downward only
// ---------------------------------------------------------------------------

test("a grant at an ancestor conveys to every node below it", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "team",
      scopeId: tree.teamNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      for (const node of [tree.teamNodeId, tree.projectNodeId, tree.envNodeId]) {
        assert.equal(
          await decide(app, { subjectId: alice, nodeId: node, roleKeys: DEV }),
          "allow",
          "a team-scope grant must reach the whole subtree",
        );
      }
    });
  });
});

test("a grant at a descendant does not convey upward", { skip }, async () => {
  // If it did, every environment-scoped grant would silently become a
  // project-wide one — which is exactly how "deploy to staging" turns into
  // "deploy to production".
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "environment",
      scopeId: tree.envNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "allow",
        "it must still work where it was granted",
      );
      for (const above of [tree.projectNodeId, tree.teamNodeId, tree.orgNodeId]) {
        assert.equal(
          await decide(app, { subjectId: alice, nodeId: above, roleKeys: DEV }),
          "deny",
          "inheritance runs downward only",
        );
      }
    });
  });
});

test("a sibling subtree does not convey", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const web = await seedTree(client, orgId, "web");
    const api = await seedTree(client, orgId, "api");
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: web.projectNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: web.envNodeId, roleKeys: DEV }), "allow");
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: api.envNodeId, roleKeys: DEV }),
        "deny",
        "a grant on one project must not reach another",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — denies always win, in BOTH directions
// ---------------------------------------------------------------------------

test("a narrower deny beats a wider allow", { skip }, async () => {
  // Brief §6.3: "A grant on a project applies to all its environments unless a
  // narrower deny exists."
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "environment",
      scopeId: tree.envNodeId,
      effect: "deny",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "deny",
        "the deny on the environment must win there",
      );
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.projectNodeId, roleKeys: DEV }),
        "allow",
        "and must not leak upward and revoke the project grant as well",
      );
    });
  });
});

test("a wider deny beats a narrower allow", { skip }, async () => {
  // The direction that "most specific wins" gets wrong. A deny on the project
  // has to survive an allow on one of its environments, or a deny is only ever
  // a suggestion that anyone holding a narrower grant may ignore.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
      effect: "deny",
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "environment",
      scopeId: tree.envNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "deny",
        "the wider deny must win over the narrower allow",
      );
    });
  });
});

test("an organization-wide deny beats an allow anywhere beneath it", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "organization",
      effect: "deny",
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "environment",
      scopeId: tree.envNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      for (const node of [tree.orgNodeId, tree.teamNodeId, tree.projectNodeId, tree.envNodeId]) {
        assert.equal(await decide(app, { subjectId: alice, nodeId: node, roleKeys: DEV }), "deny");
      }
    });
  });
});

test("a deny of a role that does not carry the action changes nothing", { skip }, async () => {
  // PLAN §5: "If any DENY matches the action". A deny matches through the role
  // it names, so denying a role the action does not belong to must not deny it.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "billing",
      scopeType: "environment",
      scopeId: tree.envNodeId,
      effect: "deny",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }), "allow");
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: ["billing", "developer"] }),
        "deny",
        "an action carried by both roles is denied through the denied one",
      );
    });
  });
});

test("with nothing granted, and with no role carrying the action, the answer is deny", { skip }, async () => {
  // Deny by default (brief §6.3), at the SQL layer as well as in the catalogue.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
    });

    await asTenant(database, orgId, async (app) => {
      const bob = "00000000-0000-0000-0000-0000000000bb";
      assert.equal(await decide(app, { subjectId: bob, nodeId: tree.envNodeId, roleKeys: DEV }), "deny");
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: [] }),
        "deny",
        "an action no role carries is a denial, not an allow",
      );
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: ["nonexistent_role"] }),
        "deny",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 and 4 — expiry, evaluated at decision time
// ---------------------------------------------------------------------------

test("an already-expired grant is dead on the first decision, with nothing having run", { skip }, async () => {
  // Acceptance 3. The row is written with real timestamps in the past and is
  // then read for the first time — there is no window in which a cleanup job
  // could have acted, because the grant was never live in this database.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    const expired = await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
      createdOffset: "-2 hours",
      expiresOffset: "-1 hour",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }), "deny");

      const live = await app.query("select 1 from live_grants where grant_id = $1", [expired]);
      assert.equal(live.rows.length, 0, "an expired grant must not appear in live_grants");
    });

    // The row is still there. Expiry removed nothing; it filtered.
    const row = await client.query("select 1 from grants where id = $1", [expired]);
    assert.equal(row.rows.length, 1, "expiry must not delete the row — history is not enforcement");
  });
});

test("a grant dies mid-transaction the moment it expires", { skip }, async () => {
  // ACCEPTANCE 4, and the sharpest statement of §6.3's "expiry is enforced
  // server-side, not by a cleanup job".
  //
  // One transaction is held open across the expiry instant. Between the allow
  // and the deny the only statements issued are a clock reading and the two
  // decisions themselves: no job, no trigger, no sweep, nothing that could have
  // deleted or rewritten anything. The answer changes because time passed.
  //
  // It also pins the choice of clock. `now()` is frozen for the life of a
  // transaction, so the test asserts that `now()` has NOT moved while the
  // decision flipped — if the predicate used `now()`, this test could not pass.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await asTenant(database, orgId, async (app) => {
      const before = await app.query<{ txn: string }>("select now()::text as txn");
      const txnClock = before.rows[0]?.txn ?? "";

      // Written from the migration connection while the reader's transaction is
      // open, which is how a grant is made in production too: by someone else.
      const grantId = await insertGrant(client, {
        orgId,
        subjectId: alice,
        roleKey: "developer",
        scopeType: "project",
        scopeId: tree.projectNodeId,
        expiresOffset: "700 milliseconds",
      });

      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "allow",
        "the grant should be live until it expires",
      );

      await sleep(900);

      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "deny",
        "the same question, in the same transaction, must answer deny once the expiry passes",
      );

      const after = await app.query<{ txn: string; stmt: string }>(
        "select now()::text as txn, statement_timestamp()::text as stmt",
      );
      assert.equal(
        after.rows[0]?.txn,
        txnClock,
        "the transaction never ended, so nothing between the two decisions could have run",
      );
      assert.notEqual(
        after.rows[0]?.stmt,
        txnClock,
        "and the statement clock is what moved — that is what the predicate reads",
      );

      // Nothing swept the row away: it is still there, unchanged, just dead.
      const row = await client.query<{ expires_at: Date }>("select expires_at from grants where id = $1", [
        grantId,
      ]);
      assert.equal(row.rows.length, 1, "no cleanup job ran, and none exists");
    });
  });
});

test("a deny expires too, and the allow it was suppressing comes back", { skip }, async () => {
  // The symmetric case, and the one where getting expiry wrong fails CLOSED
  // rather than open — which is why it is the one nobody tests.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "environment",
      scopeId: tree.envNodeId,
      effect: "deny",
      createdOffset: "-2 hours",
      expiresOffset: "-1 hour",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }), "allow");
    });
  });
});

test("expiry is a query predicate, and no cleanup job exists to be relied on", { skip }, async () => {
  // Structural evidence for §6.3, so the property survives someone "optimising"
  // the filter out of the view and into a nightly sweep.
  await withMigratedDatabase(async (client) => {
    const view = await client.query<{ definition: string }>(
      "select pg_get_viewdef('live_grants'::regclass, true) as definition",
    );
    const definition = view.rows[0]?.definition ?? "";
    assert.match(definition, /expires_at/, "the expiry filter must live in the view");
    assert.match(definition, /statement_timestamp\(\)/, "and must be evaluated per statement");

    // The only trigger on grants is the last-owner floor from migration 2.
    // Anything else here would be enforcement happening on a schedule.
    const triggers = await client.query<{ tgname: string }>(
      "select tgname from pg_trigger where tgrelid = 'grants'::regclass and not tgisinternal order by tgname",
    );
    assert.deepEqual(triggers.rows.map((r) => r.tgname), ["grants_owner_floor"]);

    const events = await client.query("select 1 from pg_event_trigger");
    assert.equal(events.rows.length, 0, "no event trigger may be in the enforcement path");
  });
});

// ---------------------------------------------------------------------------
// The shape of the column, and the constraints around it
// ---------------------------------------------------------------------------

test("effect defaults to allow so rows written before this migration keep their meaning", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    // The insert migration 2's own tests write, with no effect named.
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'viewer', 'organization')`,
      [orgId, userId],
    );
    const r = await client.query<{ effect: string }>(
      "select effect from grants where org_id = $1 and role_key = 'viewer'",
      [orgId],
    );
    assert.equal(r.rows[0]?.effect, "allow");
  });
});

test("effect and subject_type accept exactly what TypeScript believes they do", { skip }, async () => {
  // src/authz/grants.ts mirrors these two enumerations. A mirror that can drift
  // is worse than no mirror, so it is read back out of the database rather than
  // trusted.
  await withMigratedDatabase(async (client) => {
    const r = await client.query<{ conname: string; definition: string }>(
      `select conname, pg_get_constraintdef(oid) as definition
       from pg_constraint
       where conrelid = 'grants'::regclass and conname in ('grants_effect', 'grants_subject_type')`,
    );
    const definitions = new Map(r.rows.map((row) => [row.conname, row.definition]));

    for (const effect of GRANT_EFFECTS) {
      assert.match(definitions.get("grants_effect") ?? "", new RegExp(`'${effect}'`));
    }
    for (const subject of SUBJECT_TYPES) {
      assert.match(definitions.get("grants_subject_type") ?? "", new RegExp(`'${subject}'`));
    }
    // And nothing the database accepts is missing from TypeScript.
    assert.equal((definitions.get("grants_effect") ?? "").match(/'[a-z_]+'::text/g)?.length, GRANT_EFFECTS.length);
    assert.equal(
      (definitions.get("grants_subject_type") ?? "").match(/'[a-z_]+'::text/g)?.length,
      SUBJECT_TYPES.length,
    );
  });
});

test("effect is constrained to allow and deny", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        insertGrant(client, {
          orgId,
          subjectId: userId,
          roleKey: "developer",
          scopeType: "organization",
          effect: "maybe",
        }),
      /grants_effect/,
    );
  });
});

test("a grant cannot be created already expired", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        insertGrant(client, {
          orgId,
          subjectId: userId,
          roleKey: "developer",
          scopeType: "organization",
          expiresOffset: "-1 hour",
        }),
      /grants_expiry_after_creation/,
      "a grant that is dead on arrival is a mistake, and should be loud",
    );
  });
});

test("a historical grant may still be imported with both timestamps in the past", { skip }, async () => {
  // The reason the constraint compares against `created_at` rather than the wall
  // clock: a rule written against now() would refuse a migration from another
  // system, and would make a database dump un-restorable once time passed.
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    const id = await insertGrant(client, {
      orgId,
      subjectId: userId,
      roleKey: "developer",
      scopeType: "organization",
      createdOffset: "-3 days",
      expiresOffset: "-2 days",
    });
    assert.notEqual(id, "");
  });
});

// ---------------------------------------------------------------------------
// The last-owner floor, which expiry and denies would otherwise quietly break
// ---------------------------------------------------------------------------

test("an organization-scope owner grant cannot be given an expiry", { skip }, async () => {
  // Time passing is not an event, so no trigger can catch an owner grant that
  // simply lapses. Brief §6.3's "at least one must always exist" therefore
  // requires that the row the floor counts cannot expire in the first place.
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        client.query(
          `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, expires_at)
           values ($1, 'user', $2, 'owner', 'organization', now() + interval '1 hour')`,
          [orgId, userId],
        ),
      /grants_owner_floor_is_unconditional/,
    );
    await assert.rejects(
      () => client.query("update grants set expires_at = now() + interval '1 hour' where org_id = $1", [orgId]),
      /grants_owner_floor_is_unconditional/,
      "and it cannot be given one afterwards either",
    );
  });
});

test("the last owner cannot be neutralised by an organization-wide deny", { skip }, async () => {
  // The floor trigger counts rows, not effects. A deny of `owner` at
  // organization scope would leave the count satisfied and the organization
  // ownerless, so the row is refused rather than the trigger made cleverer.
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        insertGrant(client, {
          orgId,
          subjectId: userId,
          roleKey: "owner",
          scopeType: "organization",
          effect: "deny",
        }),
      /grants_owner_floor_is_unconditional/,
    );
  });
});

test("an owner grant at a narrower node may still expire and may still be denied", { skip }, async () => {
  // The constraint has to be exactly as wide as the floor it protects. A
  // team-scope owner grant is not what "at least one Owner always exists"
  // counts, so time-bounding one is legitimate.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "owner",
      scopeType: "team",
      scopeId: tree.teamNodeId,
      expiresOffset: "1 hour",
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "owner",
      scopeType: "project",
      scopeId: tree.projectNodeId,
      effect: "deny",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.teamNodeId, roleKeys: ["owner"] }), "allow");
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: ["owner"] }), "deny");
    });
  });
});

// ---------------------------------------------------------------------------
// Resource scope — the fifth level of the hierarchy, which owns no scope node
// ---------------------------------------------------------------------------

test("a resource-scoped grant matches the resource named, and nothing above it", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");
    const site = "00000000-0000-0000-0000-00000000515e";
    const otherSite = "00000000-0000-0000-0000-0000000051fe";

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "resource",
      scopeId: site,
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV, resourceId: site }),
        "allow",
      );
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV, resourceId: otherSite }),
        "deny",
        "a grant on one resource must not reach another",
      );
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "deny",
        "and must not convey at the environment containing it",
      );
    });
  });
});

test("a resource-scoped deny beats an allow inherited from above it", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");
    const site = "00000000-0000-0000-0000-00000000515e";

    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "project",
      scopeId: tree.projectNodeId,
    });
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "resource",
      scopeId: site,
      effect: "deny",
    });

    await asTenant(database, orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV, resourceId: site }),
        "deny",
        "the deny on the site must win over the project grant above it",
      );
      assert.equal(
        await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }),
        "allow",
        "asking about the environment rather than the site is a different question",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Tenant isolation of the new objects
// ---------------------------------------------------------------------------

test("the resolution objects run with the caller's permissions, not their owner's", { skip }, async () => {
  // A SECURITY DEFINER function, or a view without security_invoker, would run
  // as the migration role — a superuser, which bypasses row-level security
  // unconditionally — and hand every tenant's grants to anyone able to call it.
  // Migration 4 had to retrofit exactly this onto scope_ancestry.
  await withMigratedDatabase(async (client) => {
    const view = await client.query<{ reloptions: string[] | null }>(
      "select reloptions from pg_class where relname = 'live_grants'",
    );
    assert.deepEqual(view.rows[0]?.reloptions, ["security_invoker=true"]);

    const functions = await client.query<{ proname: string; prosecdef: boolean }>(
      "select proname, prosecdef from pg_proc where proname in ('effective_grants', 'grant_decision') order by proname",
    );
    assert.equal(functions.rows.length, 2, "both resolution functions should exist");
    for (const fn of functions.rows) {
      assert.equal(fn.prosecdef, false, `${fn.proname} must not be SECURITY DEFINER`);
    }
  });
});

test("resolution never crosses tenants", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    const theirs = await seedTree(client, globex.orgId, "theirs");
    const spy = await addUser(client, acme.orgId, "spy@acme.example");
    const theirUser = await addUser(client, globex.orgId, "them@globex.example");

    await insertGrant(client, {
      orgId: globex.orgId,
      subjectId: theirUser,
      roleKey: "developer",
      scopeType: "project",
      scopeId: theirs.projectNodeId,
    });

    await asTenant(database, acme.orgId, async (app) => {
      // Their node, their subject, asked from our tenant.
      assert.equal(
        await decide(app, { subjectId: theirUser, nodeId: theirs.envNodeId, roleKeys: DEV }),
        "deny",
      );
      assert.equal(await decide(app, { subjectId: spy, nodeId: theirs.envNodeId, roleKeys: DEV }), "deny");

      const visible = await app.query<{ org_id: string }>("select org_id from live_grants");
      assert.deepEqual(
        [...new Set(visible.rows.map((r) => r.org_id))],
        [acme.orgId],
        "live_grants leaked another tenant",
      );
    });

    // And the grant is real — the test must not pass by there being nothing.
    await asTenant(database, globex.orgId, async (app) => {
      assert.equal(
        await decide(app, { subjectId: theirUser, nodeId: theirs.envNodeId, roleKeys: DEV }),
        "allow",
      );
    });
  });
});

test("with no tenant set, resolution answers deny", { skip }, async () => {
  // The missing-setting case has to fail closed, the same way the policies do.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const alice = await addUser(client, orgId, "alice@acme.example");
    await insertGrant(client, {
      orgId,
      subjectId: alice,
      roleKey: "developer",
      scopeType: "organization",
    });

    await asTenant(database, null, async (app) => {
      assert.equal(await decide(app, { subjectId: alice, nodeId: tree.envNodeId, roleKeys: DEV }), "deny");
      const rows = await app.query("select 1 from live_grants");
      assert.equal(rows.rows.length, 0);
    });
  });
});
