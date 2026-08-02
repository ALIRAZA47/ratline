/**
 * Administrative reset of a second factor (RL-M1-038).
 *
 * RL-M1-019 shipped without this deliberately: turning off anybody's second
 * factor is the most dangerous capability in the feature, the catalogue had no
 * action to check an administrator against, and shipping the capability with
 * the check "to follow" is what §9 rejects. R-26 recorded the gap.
 *
 * ## Why this one is more dangerous than the password reset
 *
 * R-17 is closed "as far as a password alone permits", and the thing that
 * permits it is precisely two-factor: an operator who resets somebody's
 * password still cannot sign in as them. This action removes that bound.
 * Whoever holds both can take an account outright — which is why the two live
 * with the same two roles rather than being split. Splitting them would suggest
 * the pair is safer than either one, and it is the opposite, so the test below
 * asserts they move together.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { ACTION_CATALOGUE, isAction } from "../../src/authz/catalogue.ts";
import { ALL_DEFAULT_ROLES, DEFAULT_ROLE_KEYS, DEFAULT_ROLES } from "../../src/authz/roles.ts";
import { contextForRequest, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { hashPassword } from "../../src/auth/passwords.ts";
import { signIn, validateSession } from "../../src/auth/sessions.ts";
import { mintSessionToken, sessionTokenDigest } from "../../src/auth/model.ts";
import {
  NotPermittedToResetSecondFactor,
  resetMemberSecondFactor,
} from "../../src/auth/two_factor.ts";
import { listAudit } from "../../src/repo/audit.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const skip = skipWithoutDatabase;
const PASSWORD = "correct-horse-battery-staple-4471";

// ---------------------------------------------------------------------------
// Acceptance 1 — catalogued, and held by exactly two roles
// ---------------------------------------------------------------------------

test("turning off another member's second factor is a catalogued action", () => {
  assert.ok(isAction("member.reset_two_factor"));
  const entry = ACTION_CATALOGUE["member.reset_two_factor"];
  assert.equal(entry.resource, "member");
  assert.equal(entry.scope, "organization");
  assert.ok(entry.description.length > 20);
});

test("only Owner and Admin carry it", () => {
  const holders = DEFAULT_ROLE_KEYS.filter((key) =>
    DEFAULT_ROLES[key].actions.includes("member.reset_two_factor"),
  );
  assert.deepEqual([...holders], ["owner", "admin"]);
});

test("it moves with the password reset, never apart from it", () => {
  // The pair is what takes an account. A role holding one and not the other
  // would look like a narrowing and would not be one: a password reset alone is
  // bounded by the factor, and a factor reset alone leaves the account reachable
  // by anyone who already knows the password. Asserted in BOTH directions so
  // neither can be granted quietly.
  for (const role of ALL_DEFAULT_ROLES) {
    assert.equal(
      role.actions.includes("member.reset_two_factor"),
      role.actions.includes("member.reset_password"),
      `${role.key} holds one of the account-takeover pair and not the other`,
    );
  }
});

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

type World = {
  readonly orgId: string;
  readonly actorId: string;
  readonly subjectId: string;
  readonly subjectEmail: string;
};

async function seedWorld(client: Client, roleKey: string, requireTwoFactor = false): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ('acme', 'Acme') returning id",
  );
  const orgId = org.rows[0]?.id ?? "";

  const mk = async (email: string, role: string | null): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into users (email, name) values ($1, 'Person') returning id",
      [email],
    );
    const id = r.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, id]);
    if (role !== null) {
      await client.query(
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
         values ($1, 'user', $2, $3, 'organization')`,
        [orgId, id, role],
      );
    }
    return id;
  };

  await mk("owner@acme.example", "owner");
  const actorId = await mk("actor@acme.example", roleKey);
  const subjectEmail = "subject@acme.example";
  const subjectId = await mk(subjectEmail, "viewer");

  await client.query("update users set password_hash = $1 where id = $2", [
    await hashPassword(PASSWORD),
    subjectId,
  ]);

  // A confirmed enrolment plus recovery codes, written directly: this suite is
  // about REMOVING them, and going through the enrolment flow would test that
  // flow instead.
  await client.query(
    `insert into two_factor_enrolments
       (org_id, user_id, secret_sealed, algorithm, digits, period_seconds, confirmed_at)
     values ($1, $2, 'v1$AAAA$BBBB', 'SHA1', 6, 30, now())`,
    [orgId, subjectId],
  );
  await client.query(
    `insert into two_factor_recovery_codes (org_id, user_id, code_hash)
     values ($1, $2, repeat('a', 64)), ($1, $2, repeat('b', 64))`,
    [orgId, subjectId],
  );

  if (requireTwoFactor) {
    await client.query(
      `insert into organization_security_policies (org_id, two_factor_required)
       values ($1, true)
       on conflict (org_id) do update set two_factor_required = true`,
      [orgId],
    );
  }

  return { orgId, actorId, subjectId, subjectEmail };
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

const ctxFor = (world: World, userId: string): AuthzContext =>
  contextForRequest({ orgId: world.orgId, userId, requestId: `r-${randomUUID()}` });

/**
 * A live session for the subject, written directly.
 *
 * Not obtained through `signIn`, and the reason is the feature under test: a
 * member WITH a confirmed second factor cannot reach a session from a password
 * alone — `signIn` hands back a challenge instead, which is exactly what
 * RL-M1-019 built. Completing the factor would need a real code from the sealed
 * secret, and this fixture's secret is a placeholder because the suite is about
 * REMOVING the enrolment rather than using it.
 *
 * So the credential is minted the way the schema defines it — a token, its
 * digest stored — and `validateSession` still resolves it exactly as it would
 * one issued by the authentication layer.
 */
async function mintSession(client: Client, world: World): Promise<string> {
  const token = mintSessionToken();
  await client.query(
    `insert into sessions (org_id, user_id, token_hash, expires_at)
     values ($1, $2, $3, now() + interval '8 hours')`,
    [world.orgId, world.subjectId, sessionTokenDigest(token)],
  );
  return token;
}

async function countRows(client: Client, table: string, userId: string): Promise<number> {
  const r = await client.query<{ n: string }>(
    `select count(*)::text as n from ${table} where user_id = $1`,
    [userId],
  );
  return Number(r.rows[0]?.n ?? "0");
}

// ---------------------------------------------------------------------------
// Acceptance 2 — audited with the actor, and the member is signed out
// ---------------------------------------------------------------------------

test("an Admin's reset removes the enrolment and its recovery codes", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "admin");
    assert.equal(await countRows(client, "two_factor_enrolments", world.subjectId), 1);
    assert.equal(await countRows(client, "two_factor_recovery_codes", world.subjectId), 2);

    await usingScratch(database, async () => {
      const removed = await resetMemberSecondFactor(ctxFor(world, world.actorId), world.subjectId);
      assert.equal(removed, 1);
    });

    assert.equal(await countRows(client, "two_factor_enrolments", world.subjectId), 0);
    assert.equal(
      await countRows(client, "two_factor_recovery_codes", world.subjectId),
      0,
      "recovery codes left behind are live credentials for a factor that no longer exists",
    );
  });
});

test("the reset signs the member out", { skip }, async () => {
  // The only detection this capability has. Their session passed a factor that
  // no longer exists, and ending it is what makes the reset visible to the
  // person it was done to.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "admin");
    const token = await mintSession(client, world);
    await usingScratch(database, async () => {
      const anonymous = ctxFor(world, world.subjectId);
      assert.notEqual(await validateSession(anonymous, token), null, "the fixture session is not live");

      await resetMemberSecondFactor(ctxFor(world, world.actorId), world.subjectId);

      assert.equal(await validateSession(anonymous, token), null);
    });
  });
});

test("the reset is audited against the operator, never the member", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      const actor = ctxFor(world, world.actorId);
      await resetMemberSecondFactor(actor, world.subjectId);

      const entries = await listAudit(actor, { action: "member.reset_two_factor" });
      assert.equal(entries.length, 1);
      const entry = entries[0];
      assert.ok(entry);
      assert.equal(entry.actorId, world.actorId, "an account takeover that named the victim would be worse than none");
      assert.equal(entry.resourceId, world.subjectId);
      assert.equal(entry.decision, "allow");
      assert.equal(entry.metadata["enrolments_removed"], 1);
      assert.equal(entry.metadata["administrative"], true);
    });
  });
});

test("no audit entry carries the sealed secret or a recovery code hash", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      await resetMemberSecondFactor(ctxFor(world, world.actorId), world.subjectId);
    });

    // The raw rows, not the mapped entries: the point is what was WRITTEN.
    const rows = await client.query<{ row: string }>("select audit_entries::text as row from audit_entries");
    assert.ok(rows.rows.length > 0);
    for (const { row } of rows.rows) {
      assert.ok(!row.includes("v1$AAAA$BBBB"), "an audit entry carries the sealed secret");
      assert.ok(!row.includes("aaaaaaaa"), "an audit entry carries a recovery code hash");
    }
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the member is forced back into enrolment
// ---------------------------------------------------------------------------

test("a reset member is forced into enrolment at next login when the policy requires one", { skip }, async () => {
  // The end-to-end shape of the third acceptance. Nothing in the reset forces
  // anything; `signIn` does, because there is no confirmed enrolment left. This
  // asserts the reset actually reaches that state rather than leaving a stale
  // row that still counts.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "admin", true);
    await usingScratch(database, async () => {
      await resetMemberSecondFactor(ctxFor(world, world.actorId), world.subjectId);

      const result = await signIn(ctxFor(world, world.subjectId), {
        email: world.subjectEmail,
        password: PASSWORD,
      });

      assert.equal(result.ok, false, "the password alone must not produce a session");
      assert.ok(result.ok === false && result.secondFactor !== null, "no enrolment challenge was issued");
      assert.equal(
        result.ok === false && result.secondFactor?.enrolmentRequired,
        true,
        "the member was asked to VERIFY a factor that no longer exists, rather than to enrol",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

for (const roleKey of ["developer", "viewer", "infrastructure", "release_manager"] as const) {
  test(`a ${roleKey} is refused, completely and audibly`, { skip }, async () => {
    await withMigratedDatabase(async (client, database) => {
      const world = await seedWorld(client, roleKey);
      const token = await mintSession(client, world);
      await usingScratch(database, async () => {
        const actor = ctxFor(world, world.actorId);
        const anonymous = ctxFor(world, world.subjectId);

        await assert.rejects(
          () => resetMemberSecondFactor(actor, world.subjectId),
          NotPermittedToResetSecondFactor,
        );

        // A refusal with an effect is the bug RL-M1-034 found by copying the
        // wrong ordering. Infrastructure holds member.revoke_sessions and not
        // this action, so it is the case that would expose it.
        assert.notEqual(
          await validateSession(anonymous, token),
          null,
          "a refused reset ended the member's session anyway",
        );

        const denials = await listAudit(actor, { action: "member.reset_two_factor", decision: "deny" });
        assert.equal(denials.length, 1);
        assert.equal(denials[0]?.actorId, world.actorId);
      });

      assert.equal(await countRows(client, "two_factor_enrolments", world.subjectId), 1);
      assert.equal(await countRows(client, "two_factor_recovery_codes", world.subjectId), 2);
    });
  });
}

test("resetting your own factor through this route is refused", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      // A meaning refusal, not a permission one: removing your own factor is a
      // self-service action that must prove possession first.
      await assert.rejects(
        () => resetMemberSecondFactor(ctxFor(world, world.actorId), world.actorId),
        /somebody else's account/,
      );
    });
  });
});
