/**
 * Re-authentication for the highest-risk actions (RL-M1-037).
 *
 * ADR 0017 proposed this as the control an idle timeout was reaching for, and
 * the difference is what it measures. An idle timeout asks the browser how long
 * since a request — a question a polling dashboard answers on the operator's
 * behalf, which is why ADR 0017 refused to ship one. This asks the operator to
 * prove they still know the password, which nothing can answer for them, and it
 * binds to the moment of danger rather than to a clock.
 *
 * ## The two orderings that matter, both asserted below
 *
 *   PERMISSION BEFORE FRESHNESS. An actor who does not hold the action must be
 *   refused as not holding it, never asked to prove a password they would then
 *   have proved for nothing. Asking first also makes the prompt an oracle:
 *   "you were asked to re-authenticate" would mean "you hold this permission".
 *
 *   FAIL CLOSED ON AN UNKNOWN SESSION. A job or a service identity cannot prove
 *   freshness, and "we cannot tell" is not a reason to assume recent.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { can, NotPermittedError, require as requirePermission, StaleAuthenticationError } from "../../src/authz/can.ts";
import { contextForRequest, contextForServiceIdentity, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { checkFreshness, markAuthenticated, readReauthPolicy, REAUTH_OFF } from "../../src/repo/reauthentication.ts";
import { mintSessionToken, sessionTokenDigest } from "../../src/auth/model.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const skip = skipWithoutDatabase;

type World = {
  readonly orgId: string;
  readonly ownerId: string;
  readonly viewerId: string;
  readonly orgNodeId: string;
};

async function seedWorld(client: Client, listed: string[] = [], windowSeconds = 900): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ('acme', 'Acme') returning id",
  );
  const orgId = org.rows[0]?.id ?? "";

  const mk = async (email: string, role: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into users (email, name) values ($1, 'Person') returning id",
      [email],
    );
    const id = r.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, id]);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, $3, 'organization')`,
      [orgId, id, role],
    );
    return id;
  };

  const ownerId = await mk("owner@acme.example", "owner");
  const viewerId = await mk("viewer@acme.example", "viewer");

  if (listed.length > 0 || windowSeconds !== 900) {
    await client.query(
      `insert into organization_security_policies (org_id, reauth_actions, reauth_window_seconds)
       values ($1, $2, $3)`,
      [orgId, listed, windowSeconds],
    );
  }

  const node = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  return { orgId, ownerId, viewerId, orgNodeId: node.rows[0]?.id ?? "" };
}

/** A session whose password was proved `agoSeconds` ago. */
async function mintSession(client: Client, world: World, userId: string, agoSeconds: number): Promise<string> {
  const token = mintSessionToken();
  const row = await client.query<{ id: string }>(
    `insert into sessions (org_id, user_id, token_hash, expires_at, authenticated_at)
     values ($1, $2, $3, now() + interval '8 hours', now() - make_interval(secs => $4::int))
     returning id`,
    [world.orgId, userId, sessionTokenDigest(token), agoSeconds],
  );
  return row.rows[0]?.id ?? "";
}

async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
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

const ctxFor = (world: World, userId: string, sessionId: string | null): AuthzContext =>
  contextForRequest({ orgId: world.orgId, userId, requestId: `r-${randomUUID()}`, sessionId });

const at = (world: World) => ({ scopeNodeId: world.orgNodeId, resourceId: null });

// ---------------------------------------------------------------------------
// Acceptance 2 — the policy, not a constant
// ---------------------------------------------------------------------------

test("an organization that has configured nothing has the control off", { skip }, async () => {
  // Off by default is the safe direction here, which is the opposite of most
  // security defaults and worth stating. Re-authentication nobody asked for
  // locks operators out of an installation that never configured it.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const policy = await readReauthPolicy(ctxFor(world, world.ownerId, null));
      assert.deepEqual(policy, REAUTH_OFF);
    });
  });
});

test("the set and the window come from the policy row", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value", "terminal.open"], 60);
    await usingScratch(database, async () => {
      const policy = await readReauthPolicy(ctxFor(world, world.ownerId, null));
      assert.deepEqual([...policy.actions], ["secret.read_value", "terminal.open"]);
      assert.equal(policy.windowSeconds, 60);
    });
  });
});

test("the window cannot exceed the session's own lifetime", { skip }, async () => {
  // A window longer than the absolute session lifetime would make the control
  // unreachable while appearing to be on — the worst state for a security
  // setting, because it reads as protection.
  await withMigratedDatabase(async (client) => {
    const world = await seedWorld(client);
    await assert.rejects(
      () =>
        client.query(
          `insert into organization_security_policies (org_id, reauth_window_seconds) values ($1, $2)`,
          [world.orgId, 9 * 60 * 60],
        ),
      /organization_security_policies_reauth_window/,
    );
  });
});

// ---------------------------------------------------------------------------
// Acceptance 1 — a listed action asks again once the session is old
// ---------------------------------------------------------------------------

test("an unlisted action never asks, however old the session", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.ownerId, 60 * 60);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      assert.deepEqual(await checkFreshness(ctx, "organization.read"), {
        fresh: true,
        reason: "not-required",
      });
      await requirePermission(ctx, "organization.read", at(world));
    });
  });
});

test("a listed action passes on a freshly authenticated session", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 900);
    const sessionId = await mintSession(client, world, world.ownerId, 10);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      assert.deepEqual(await checkFreshness(ctx, "secret.read_value"), { fresh: true, reason: "recent" });
      await requirePermission(ctx, "secret.read_value", at(world));
    });
  });
});

test("a listed action is refused once the window has passed", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.ownerId, 120);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      assert.deepEqual(await checkFreshness(ctx, "secret.read_value"), { fresh: false, reason: "stale" });
      await assert.rejects(
        () => requirePermission(ctx, "secret.read_value", at(world)),
        StaleAuthenticationError,
      );
    });
  });
});

test("proving the password again clears it", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.ownerId, 120);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      await assert.rejects(() => requirePermission(ctx, "secret.read_value", at(world)), StaleAuthenticationError);

      assert.equal(await markAuthenticated(ctx, sessionId), true);
      await requirePermission(ctx, "secret.read_value", at(world));
    });
  });
});

// ---------------------------------------------------------------------------
// The two orderings
// ---------------------------------------------------------------------------

test("a missing permission is refused as missing, not as stale", { skip }, async () => {
  // The ordering that matters most. A Viewer does not hold secret.read_value,
  // so asking them to re-authenticate would waste their password AND tell them
  // they hold a permission they do not — the prompt would be an oracle.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.viewerId, 60 * 60);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.viewerId, sessionId);
      await assert.rejects(
        () => requirePermission(ctx, "secret.read_value", at(world)),
        (error: unknown) => {
          assert.ok(error instanceof NotPermittedError, `got ${String(error)}`);
          assert.ok(!(error instanceof StaleAuthenticationError));
          return true;
        },
      );
    });
  });
});

test("an actor with no session cannot reach a listed action at all", { skip }, async () => {
  // Fails closed. A job, a migration or a service identity cannot prove
  // freshness, and "we cannot tell" is not a reason to assume recent. The
  // remedy for a job that legitimately needs a listed action is a policy that
  // does not list it, never a hole here.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 900);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deployer') returning id",
      [world.orgId],
    );
    const identityId = identity.rows[0]?.id ?? "";
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'admin', 'organization')`,
      [world.orgId, identityId],
    );

    await usingScratch(database, async () => {
      const ctx = contextForServiceIdentity({
        orgId: world.orgId,
        serviceIdentityId: identityId,
        name: "deployer",
        requestId: `r-${randomUUID()}`,
      });
      assert.deepEqual(await checkFreshness(ctx, "secret.read_value"), {
        fresh: false,
        reason: "no-session",
      });
      await assert.rejects(
        () => requirePermission(ctx, "secret.read_value", at(world)),
        StaleAuthenticationError,
      );
    });
  });
});

test("can() answers without demanding a password", { skip }, async () => {
  // The role editor's live preview and the navigation rail both ask can().
  // Neither should demand a password to answer "would this be allowed", and a
  // freshness check inside can() would make the whole interface unusable the
  // moment an organization turned this on.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.ownerId, 60 * 60);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      const decision = await can(ctx, "secret.read_value", at(world));
      assert.equal(decision.allowed, true, "can() must answer the permission question alone");
      await assert.rejects(() => requirePermission(ctx, "secret.read_value", at(world)), StaleAuthenticationError);
    });
  });
});

// ---------------------------------------------------------------------------
// markAuthenticated is self-only
// ---------------------------------------------------------------------------

test("nobody can refresh somebody else's authentication", { skip }, async () => {
  // The hole `repository_gating.test.ts` caught in the first draft. This
  // function moves the timestamp that grants privilege, so an unscoped one
  // would let anybody who can reach it hand a stale session its privileges
  // back. There is no permission that should allow it — proving a password is
  // something only its owner can do — so the predicate is the check.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const victimSession = await mintSession(client, world, world.viewerId, 60 * 60);
    await usingScratch(database, async () => {
      const owner = ctxFor(world, world.ownerId, null);
      assert.equal(
        await markAuthenticated(owner, victimSession),
        false,
        "an Owner refreshed another member's session",
      );
    });

    const still = await client.query<{ stale: boolean }>(
      "select authenticated_at < now() - interval '30 minutes' as stale from sessions where id = $1",
      [victimSession],
    );
    assert.equal(still.rows[0]?.stale, true, "the victim's session was refreshed anyway");
  });
});

test("automation cannot prove a password", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deployer') returning id",
      [world.orgId],
    );
    await usingScratch(database, async () => {
      const ctx = contextForServiceIdentity({
        orgId: world.orgId,
        serviceIdentityId: identity.rows[0]?.id ?? "",
        name: "deployer",
        requestId: `r-${randomUUID()}`,
      });
      await assert.rejects(() => markAuthenticated(ctx, randomUUID()), /only a user proves a password/);
    });
  });
});

test("a revoked session is stale even when it was authenticated a moment ago", { skip }, async () => {
  // The session is minted FRESH — ten seconds old against a sixty-second
  // window — and then revoked. That combination is the whole test: a stale-by-age
  // session would answer "stale" whether the code read `live_sessions` or
  // `sessions`, so the first version of this test passed against a mutation
  // that read the table directly. Only a session that is fresh by age and dead
  // by revocation can tell the two apart.
  //
  // Migration 10 note 3 calls reading the table "the single mistake that would
  // honour a revoked session". This is that mistake, made and caught.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, ["secret.read_value"], 60);
    const sessionId = await mintSession(client, world, world.ownerId, 10);
    await client.query(
      "update sessions set revoked_at = now(), revoked_reason = 'revoked' where id = $1",
      [sessionId],
    );
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.ownerId, sessionId);
      assert.deepEqual(
        await checkFreshness(ctx, "secret.read_value"),
        { fresh: false, reason: "stale" },
        "a revoked session was honoured because its timestamp was recent",
      );
      assert.equal(await markAuthenticated(ctx, sessionId), false);
    });
  });
});
