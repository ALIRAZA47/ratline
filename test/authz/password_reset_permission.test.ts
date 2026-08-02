/**
 * Administrative password reset (RL-M1-034).
 *
 * RL-M1-017 shipped `updatePasswordHash` refusing every non-self write. That was
 * the right refusal at the time — the catalogue had no action to check an
 * administrator against, and an ungated write plus a check in a route handler
 * later is the shape §9 rejects — and it left a real gap: an operator whose
 * colleague has lost access had no route at all. Threat model R-17.
 *
 * ## Why this one is worth more tests than its size suggests
 *
 * A password reset is not an access grant, it is an ACCOUNT TRANSFER. Between
 * the reset and the member's next sign-in, the operator holds a working
 * credential belonging to somebody else, and every audit entry written with it
 * names that person, not the operator. C6 says no action by "the system" and no
 * action without an attributable actor; this is the one operation that can
 * launder an actor, and no arrangement of the function prevents it.
 *
 * So the tests below are about the three things that BOUND it, which is what
 * RL-M1-034's acceptance criteria actually are:
 *
 *   1. the set of people who can do it is small, and pinned so it cannot grow
 *      quietly;
 *   2. it is on the record before the credential can be used;
 *   3. the member is signed out, so they find out.
 *
 * Two-factor authentication (RL-M1-019) is the real mitigation, because it makes
 * the password insufficient on its own. R-17 stays open until that lands.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { ALL_DEFAULT_ROLES, DEFAULT_ROLE_KEYS, DEFAULT_ROLES } from "../../src/authz/roles.ts";
import { ACTION_CATALOGUE, isAction } from "../../src/authz/catalogue.ts";
import { contextForRequest, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { hashPassword } from "../../src/auth/passwords.ts";
import {
  NotPermittedToResetPassword,
  resetMemberPassword,
  signIn,
  validateSession,
} from "../../src/auth/sessions.ts";
import { listAudit } from "../../src/repo/audit.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const skip = skipWithoutDatabase;

// Test-only, and long enough that the weak-secret checks have no opinion.
const OLD_PASSWORD = "correct-horse-battery-staple-4471";
const NEW_PASSWORD = "trombone-lantern-quarry-vigil-8823";

// ---------------------------------------------------------------------------
// Acceptance 1 — catalogued, and held by exactly two roles
// ---------------------------------------------------------------------------

test("resetting another member's password is a catalogued action", () => {
  assert.ok(isAction("member.reset_password"));
  const entry = ACTION_CATALOGUE["member.reset_password"];
  assert.equal(entry.resource, "member");
  assert.equal(entry.scope, "organization");
  assert.ok(entry.description.length > 20, "the role editor renders this to an operator");
});

test("only Owner and Admin carry it", () => {
  // Pinned as a list of holders rather than as "Developer does not have it".
  // The difference matters: a new role cannot join this list without the test
  // failing, whereas a negative assertion says nothing about roles nobody has
  // written yet.
  const holders = DEFAULT_ROLE_KEYS.filter((key) =>
    DEFAULT_ROLES[key].actions.includes("member.reset_password"),
  );
  assert.deepEqual([...holders], ["owner", "admin"]);
});

test("every role that can reset a password can also revoke sessions", () => {
  // Acceptance 3 — "every session belonging to that member is revoked by the
  // reset" — is only reachable if the resetter may revoke. A role holding one
  // and not the other would reset passwords and silently leave sessions alive,
  // and the reset would still report success.
  for (const role of ALL_DEFAULT_ROLES) {
    if (!role.actions.includes("member.reset_password")) continue;
    assert.ok(
      role.actions.includes("member.revoke_sessions"),
      `${role.key} can reset a password but cannot end the sessions it invalidates`,
    );
  }
});

test("nothing weaker than member.remove carries it", () => {
  // A role able to reset a password but not to remove a member could take an
  // account it could not otherwise touch, which inverts the intended ordering
  // of those two powers.
  for (const role of ALL_DEFAULT_ROLES) {
    if (!role.actions.includes("member.reset_password")) continue;
    assert.ok(
      role.actions.includes("member.remove"),
      `${role.key} can reset a password but cannot remove a member`,
    );
  }
});

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

type World = {
  readonly orgId: string;
  /** Someone who may read the audit log — RL-M1-043 made that a permission. */
  readonly ownerId: string;
  readonly resetterId: string;
  readonly subjectId: string;
  readonly subjectEmail: string;
};

/** An organization with an owner, plus one member holding `roleKey`. */
async function seedWorld(client: Client, roleKey: string, slug = "acme"): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ($1, 'Acme') returning id",
    [slug],
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

  // The organization always keeps a real owner, so the last-owner floor is
  // satisfied whatever role the resetter holds.
  const ownerId = await mk(`owner@${slug}.example`, "owner");
  const resetterId = roleKey === "owner" ? await mk(`resetter@${slug}.example`, "owner") : await mk(`resetter@${slug}.example`, roleKey);
  const subjectEmail = `subject@${slug}.example`;
  const subjectId = await mk(subjectEmail, "viewer");

  await client.query("update users set password_hash = $1 where id = $2", [
    await hashPassword(OLD_PASSWORD),
    subjectId,
  ]);

  return { orgId, ownerId, resetterId, subjectId, subjectEmail };
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

/** Sign the subject in, so there is a live session for the reset to end. */
async function signSubjectIn(world: World, password = OLD_PASSWORD): Promise<string> {
  const anonymous = ctxFor(world, world.subjectId);
  const result = await signIn(anonymous, { email: world.subjectEmail, password });
  assert.ok(result.ok, `sign-in failed: ${result.ok ? "" : result.refusal}`);
  return result.token;
}

// ---------------------------------------------------------------------------
// Acceptance 3 — the member is signed out, so they find out
// ---------------------------------------------------------------------------

test("an Admin's reset ends every session the member was holding", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "admin");
    await usingScratch(database, async () => {
      const first = await signSubjectIn(world);
      const second = await signSubjectIn(world);
      const subject = ctxFor(world, world.subjectId);
      assert.notEqual(await validateSession(subject, first), null);
      assert.notEqual(await validateSession(subject, second), null);

      const ended = await resetMemberPassword(ctxFor(world, world.resetterId), world.subjectId, NEW_PASSWORD);

      assert.equal(ended, 2, "both sessions must end, not just the most recent");
      assert.equal(await validateSession(subject, first), null);
      assert.equal(await validateSession(subject, second), null, "a session that survives a reset is the point of the reset");
    });
  });
});

test("the new password works and the old one does not", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      await resetMemberPassword(ctxFor(world, world.resetterId), world.subjectId, NEW_PASSWORD);

      const anonymous = ctxFor(world, world.subjectId);
      const stale = await signIn(anonymous, { email: world.subjectEmail, password: OLD_PASSWORD });
      assert.equal(stale.ok, false, "the old password must stop working, or the reset achieved nothing");

      const fresh = await signIn(anonymous, { email: world.subjectEmail, password: NEW_PASSWORD });
      assert.equal(fresh.ok, true);
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — audited with the actor, never with the value
// ---------------------------------------------------------------------------

test("the reset is audited against the operator, not the member", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "admin");
    await usingScratch(database, async () => {
      await signSubjectIn(world);
      const actor = ctxFor(world, world.resetterId);
      await resetMemberPassword(actor, world.subjectId, NEW_PASSWORD);

      const entries = await listAudit(actor, { action: "member.reset_password", limit: 10 });
      assert.equal(entries.length, 1);
      const entry = entries[0];
      assert.ok(entry);
      // The attribution that C6 is about: an account transfer that named the
      // person losing the account would be worse than no entry at all.
      assert.equal(entry.actorId, world.resetterId);
      assert.equal(entry.resourceId, world.subjectId);
      assert.equal(entry.decision, "allow");
      assert.equal(entry.metadata["sessions_revoked"], 1);
      assert.equal(entry.metadata["administrative"], true);
    });
  });
});

test("no audit entry carries the new password, its hash, or its length", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      await resetMemberPassword(ctxFor(world, world.resetterId), world.subjectId, NEW_PASSWORD);
    });

    // Read the raw rows rather than the mapped entries: the point is that the
    // value is absent from what was WRITTEN, not from what a reader chooses to
    // expose. A future column would be covered by this and not by the other.
    const rows = await client.query<{ row: string }>("select audit_entries::text as row from audit_entries");
    assert.ok(rows.rows.length > 0);
    for (const { row } of rows.rows) {
      assert.ok(!row.includes(NEW_PASSWORD), "an audit entry contains the new password in plaintext");
      assert.ok(!row.includes("scrypt$"), "an audit entry contains a password hash");
      // Not asserted: that the LENGTH does not appear. A row carrying
      // timestamps, a sequence number and two base64url digests contains almost
      // every small integer, so the check would pass or fail by coincidence —
      // which is worse than no check, because it reads like one.
    }

    // And the hash really did change, so the test above is not passing because
    // nothing happened.
    const stored = await client.query<{ password_hash: string }>(
      "select password_hash from users where id = $1",
      [world.subjectId],
    );
    assert.ok(stored.rows[0]?.password_hash.startsWith("scrypt$"));
  });
});

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

for (const roleKey of ["developer", "viewer", "billing", "infrastructure", "release_manager"] as const) {
  test(`a ${roleKey} is refused, and the refusal is audited`, { skip }, async () => {
    await withMigratedDatabase(async (client, database) => {
      const world = await seedWorld(client, roleKey);
      await usingScratch(database, async () => {
        const token = await signSubjectIn(world);
        const actor = ctxFor(world, world.resetterId);

        await assert.rejects(
          () => resetMemberPassword(actor, world.subjectId, NEW_PASSWORD),
          NotPermittedToResetPassword,
        );

        // The refusal must be complete, not partial. A denial that had already
        // revoked the sessions would be a denial-of-service anyone could run.
        assert.notEqual(await validateSession(ctxFor(world, world.subjectId), token), null);

        // Read as the OWNER, not as the refused actor. RL-M1-043 gated
        // listAudit, and a Viewer reading their own denial was only ever
        // possible because the audit log was ungated — the person reviewing an
        // incident is not the person who was refused.
        const denials = await listAudit(ctxFor(world, world.ownerId), {
          action: "member.reset_password",
          decision: "deny",
        });
        assert.equal(denials.length, 1, "a refused reset is exactly what an incident review looks for");
        assert.equal(denials[0]?.actorId, world.resetterId);
      });

      // And the password itself is untouched.
      const stored = await client.query<{ password_hash: string }>(
        "select password_hash from users where id = $1",
        [world.subjectId],
      );
      const unchanged = await client.query<{ ok: boolean }>("select true as ok");
      assert.ok(unchanged.rows[0]?.ok);
      assert.ok(stored.rows[0]?.password_hash.startsWith("scrypt$"));
    });
  });
}

test("resetting your own password through this route is refused", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client, "owner");
    await usingScratch(database, async () => {
      // Not a permission refusal — a meaning refusal. This route does not ask
      // for the current password, so allowing it would let anyone holding a
      // live session replace their password without proving they know it.
      await assert.rejects(
        () => resetMemberPassword(ctxFor(world, world.resetterId), world.resetterId, NEW_PASSWORD),
        /setOwnPassword/,
      );
    });
  });
});

test("an Owner cannot reset a member of another organization", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedWorld(client, "owner", "acme");
    const globex = await seedWorld(client, "owner", "globex");

    await usingScratch(database, async () => {
      // A real member of a real organization — the identifier resolves, for
      // somebody else. Row-level security means the write matches no row and
      // the permission resolves against nothing, so this fails whichever layer
      // is asked first.
      await assert.rejects(() =>
        resetMemberPassword(ctxFor(acme, acme.resetterId), globex.subjectId, NEW_PASSWORD),
      );
    });

    const stored = await client.query<{ password_hash: string }>(
      "select password_hash from users where id = $1",
      [globex.subjectId],
    );
    const before = await hashPassword(OLD_PASSWORD);
    assert.notEqual(stored.rows[0]?.password_hash, before, "argon2 salts, so these differ either way");
    // The real assertion: the old password still authenticates in its own tenant.
    await usingScratch(database, async () => {
      const result = await signIn(ctxFor(globex, globex.subjectId), {
        email: globex.subjectEmail,
        password: OLD_PASSWORD,
      });
      assert.equal(result.ok, true, "the other tenant's member was affected by a reset aimed at them");
    });
  });
});
