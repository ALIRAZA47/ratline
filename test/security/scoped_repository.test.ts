/**
 * The scoped data-access primitive and the authorization context — layer 2 of
 * C3 (RL-M1-007, ADR 0003).
 *
 * C3: "There is no unscoped findById in the codebase; make the unscoped variant
 * impossible to call rather than merely discouraged."
 *
 * Two kinds of assertion here, and they answer different questions:
 *
 *   - Structural, over the source: every repository function takes an
 *     AuthzContext first, no repository writes its own tenant predicate, and
 *     the system-context list has not grown. These catch a mistake at review
 *     time, which is the point of layers 1 and 2 — layer 3 already prevents the
 *     leak, but silently. ("Nothing outside src/repo/ imports the handle" was
 *     the fourth of these until RL-M1-008 turned it into a lint rule; see the
 *     note where it used to be, and test/security/lint_rules.test.ts.)
 *
 *   - Behavioural, against a real Postgres: a repository function run with a
 *     foreign tenant returns nothing, AND still returns nothing when its own
 *     WHERE clause is deleted. That last one is the acceptance criterion.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

import {
  contextForRequest,
  contextForServiceIdentity,
  contextForSystem,
  SYSTEM_PURPOSES,
  type AuthzContext,
} from "../../src/authz/context.ts";
import { connect, disconnect, scoped, assertNotPrivileged } from "../../src/db/internal/handle.ts";
import { currentOrganization, findMember, findProject, listMembers } from "../../src/repo/index.ts";
import {
  DATABASE_URL,
  seedOrganization,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

// ---------------------------------------------------------------------------
// Structural — the rules hold across the whole layer, not just where I looked
// ---------------------------------------------------------------------------

test("every exported repository function takes an AuthzContext first", () => {
  // Discovered from the source rather than listed, so a function added later
  // without a context fails here instead of quietly becoming an unscoped read.
  const findings: string[] = [];
  for (const file of globSync("src/repo/**/*.ts", { cwd: ROOT })) {
    if (file.endsWith("index.ts")) continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const match of source.matchAll(/export\s+(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)/g)) {
      const name = match[1] ?? "";
      const params = (match[2] ?? "").trim();
      if (!/^ctx\s*:\s*AuthzContext\b/.test(params)) {
        findings.push(`${file}: ${name}(${params.slice(0, 40)}…) does not take ctx: AuthzContext first`);
      }
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

// "nothing outside src/repo imports the database handle" used to be a test
// here, scanning src/** with a regex. RL-M1-008 replaced it with a real
// `no-restricted-imports` rule in eslint.config.js, proved by a fixture in
// test/security/lint_rules.test.ts. The rule is strictly stronger: it reads
// import declarations rather than guessing at them with a regex, it covers
// scripts/ and re-export forms the scan never looked at, and it fails in the
// editor rather than at test time. Keeping the scan alongside it would mean two
// things to update and one of them going quietly stale.

test("no repository function writes its own tenant predicate", () => {
  // A hand-written `org_id = ...` is not wrong, but it is a sign someone
  // believes scoping is their job. It is not — it is the transaction's. If this
  // ever needs an exception, it needs a comment explaining why.
  const findings: string[] = [];
  for (const file of globSync("src/repo/**/*.ts", { cwd: ROOT })) {
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const match of source.matchAll(/org_id\s*=\s*\$\d/g)) {
      findings.push(`${file}: ${match[0]} — scoping is the transaction's job, not the query's`);
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

test("the system-context list has not grown silently", () => {
  // Every entry is a place that operates outside a user's authority. Adding one
  // should be an argued change, not an import someone slipped in.
  assert.deepEqual([...SYSTEM_PURPOSES], ["audit-chain-verification", "instance-administration"]);
});

// ---------------------------------------------------------------------------
// The context cannot be forged by accident
// ---------------------------------------------------------------------------

test("an object literal is not an AuthzContext", () => {
  // The compile-time half cannot be asserted at runtime, so it is asserted at
  // build time: the assignment below fails typecheck without the suppression
  // directive, and typecheck fails WITH the directive if the brand ever stops
  // working, because the directive would then be unused. Either way CI catches
  // it.
  //
  // (Take care wording comments near here: TypeScript reads any comment line
  // beginning with the suppression directive as a real directive, including one
  // inside explanatory prose. That is how this test first appeared to prove the
  // brand was broken when it was not.)
  // @ts-expect-error - a literal lacks the brand, which is the entire point
  const forged: AuthzContext = { orgId: randomUUID(), actor: { kind: "user", id: randomUUID() }, requestId: "r", ip: null };
  assert.ok(forged);
});

test("a context refuses a malformed tenant or actor", () => {
  // orgId reaches a session setting that every row-level security policy reads.
  // A malformed one fails closed, but as a baffling empty result rather than an
  // error, so it is rejected where it is built.
  assert.throws(() => contextForRequest({ orgId: "not-a-uuid", userId: randomUUID(), requestId: "r" }), /UUID orgId/);
  assert.throws(() => contextForRequest({ orgId: randomUUID(), userId: "nope", requestId: "r" }), /UUID actor id/);
  assert.throws(() => contextForRequest({ orgId: randomUUID(), userId: randomUUID(), requestId: "  " }), /requestId/);
});

test("every context names an actor", () => {
  // C6: no privileged action without a recorded actor, including automation.
  const orgId = randomUUID();
  assert.equal(contextForRequest({ orgId, userId: randomUUID(), requestId: "r" }).actor.kind, "user");
  assert.equal(
    contextForServiceIdentity({ orgId, serviceIdentityId: randomUUID(), name: "deploy-bot", requestId: "r" }).actor.kind,
    "service_identity",
  );
  const system = contextForSystem({
    purpose: "audit-chain-verification",
    orgId,
    serviceIdentityId: randomUUID(),
    requestId: "r",
  });
  assert.equal(system.actor.kind, "service_identity");
  assert.match(system.actor.kind === "service_identity" ? system.actor.name : "", /^system:/);
});

test("an unenumerated system purpose is refused", () => {
  assert.throws(
    () =>
      contextForSystem({
        // @ts-expect-error - not a SystemPurpose; checked at runtime too
        purpose: "just-this-once",
        orgId: randomUUID(),
        serviceIdentityId: randomUUID(),
        requestId: "r",
      }),
    /enumerated system purpose/,
  );
});

test("a context is frozen", () => {
  const ctx = contextForRequest({ orgId: randomUUID(), userId: randomUUID(), requestId: "r" });
  assert.throws(() => {
    // @ts-expect-error - readonly, and frozen at runtime as well
    ctx.orgId = randomUUID();
  }, TypeError);
});

// ---------------------------------------------------------------------------
// Behavioural — against a real database, as the unprivileged role
// ---------------------------------------------------------------------------

/** Point the pool at a scratch database, as `ratline_app`. */
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

/**
 * A context for a REAL member of the tenant.
 *
 * The userId used to be a random uuid, which worked only while the repository
 * reads were ungated (RL-M1-043). Now they resolve a permission, and a
 * non-member is refused as `actor-not-in-tenant` — a correct refusal that
 * happens for the wrong reason here, and would have made these tests pass
 * without exercising row-level security at all.
 */
const ctxFor = (orgId: string, userId: string): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `test-${randomUUID()}` });

test("a repository sees its own tenant and no other", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");

    await usingScratch(database, async () => {
      const mine = await currentOrganization(ctxFor(acme.orgId, acme.userId));
      assert.equal(mine?.slug, "acme");

      const members = await listMembers(ctxFor(acme.orgId, acme.userId));
      assert.deepEqual(members.map((m) => m.email), ["owner@acme.example"]);

      // Symmetric, so the test cannot pass by seeing nothing at all.
      const theirs = await currentOrganization(ctxFor(globex.orgId, globex.userId));
      assert.equal(theirs?.slug, "globex");
    });
  });
});

test("findMember returns null for a real user in another tenant", { skip }, async () => {
  // The IDOR shape: a valid id from somewhere the caller should not reach.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");

    await usingScratch(database, async () => {
      assert.notEqual(await findMember(ctxFor(acme.orgId, acme.userId), acme.userId), null, "own member should be found");
      assert.equal(
        await findMember(ctxFor(acme.orgId, acme.userId), globex.userId),
        null,
        "a member of another tenant must be indistinguishable from one that does not exist",
      );
      assert.equal(await findMember(ctxFor(acme.orgId, acme.userId), randomUUID()), null);
    });
  });
});

test("absent and forbidden are the same answer", { skip }, async () => {
  // RL-M1-026 requires the responses be indistinguishable. Here the reason is
  // structural: the repository has nothing to tell them apart with.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    const foreign = await client.query<{ id: string }>("select id from organizations where id = $1", [globex.orgId]);

    await usingScratch(database, async () => {
      const forbidden = await findProject(ctxFor(acme.orgId, acme.userId), foreign.rows[0]?.id ?? randomUUID());
      const absent = await findProject(ctxFor(acme.orgId, acme.userId), randomUUID());
      assert.equal(forbidden, absent, "both must be exactly null");
    });
  });
});

test("a repository query with its WHERE clause deleted still returns nothing foreign", { skip }, async () => {
  // THE acceptance criterion. This is findMember with its predicate removed —
  // the exact bug C3 is written about — issued through the same scoped() path a
  // repository function uses.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    await seedOrganization(client, "globex");

    await usingScratch(database, async () => {
      const rows = await scoped(ctxFor(acme.orgId, acme.userId), async (query) =>
        // No predicate whatsoever.
        query<{ org_id: string }>("select org_id from memberships"),
      );
      assert.equal(rows.length, 1, "should see only its own tenant's membership");
      assert.equal(rows[0]?.org_id, acme.orgId);
    });
  });
});

test("the tenant does not leak between transactions on a pooled connection", { skip }, async () => {
  // The worst failure this design can have, and an invisible one: a connection
  // returned to the pool still carrying a tenant would serve one customer's
  // data to the next request.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");

    await usingScratch(database, async () => {
      // Force reuse of a single connection.
      connect({ max: 1 });
      for (const org of [acme, globex, acme]) {
        const seen = await scoped(ctxFor(org.orgId, org.userId), async (query) =>
          query<{ id: string }>("select id from organizations"),
        );
        assert.deepEqual(seen.map((r) => r.id), [org.orgId], "each transaction must see only its own tenant");
      }
    });
  });
});

test("a query outside scoped() sees nothing, not the previous tenant", { skip }, async () => {
  // The tenant is set with set_config(..., true) — transaction-local. Session-
  // wide would look identical in every test above, because scoped() always sets
  // the tenant before querying. The difference only shows here, and it is the
  // difference between failing closed and failing stale:
  //
  //   transaction-local -> a query outside scoped() sees NOTHING
  //   session-wide      -> it sees whatever tenant ran last on that connection
  //
  // The second is how a future refactor that queries outside the primitive
  // silently serves one customer's data to another instead of returning empty.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    await seedOrganization(client, "globex");

    await usingScratch(database, async () => {
      const pool = connect({ max: 1 });

      const inside = await scoped(ctxFor(acme.orgId, acme.userId), async (query) =>
        query<{ id: string }>("select id from organizations"),
      );
      assert.deepEqual(inside.map((r) => r.id), [acme.orgId], "inside the primitive, the tenant applies");

      // Same pooled connection, no transaction, no tenant bound.
      const outside = await pool.query<{ id: string }>("select id from organizations");
      assert.equal(
        outside.rows.length,
        0,
        "the tenant outlived its transaction — a query outside scoped() must see nothing",
      );
    });
  });
});

test("the application refuses to run as a role that can bypass isolation", { skip }, async () => {
  // Layer 3 is silently disabled by a superuser connection, and nothing else
  // would notice — every query keeps returning correct-looking results, for
  // every tenant.
  await withMigratedDatabase(async (_client, database) => {
    const url = new URL(DATABASE_URL);
    url.pathname = `/${database}`;
    connect({ connectionString: url.toString() }); // the superuser dev role
    try {
      await assert.rejects(() => assertNotPrivileged(), /refuses to start/);
    } finally {
      await disconnect();
    }

    await usingScratch(database, async () => {
      await assertNotPrivileged(); // ratline_app is fine
    });
  });
});
