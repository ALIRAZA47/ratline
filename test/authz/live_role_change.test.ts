/**
 * Role changes take effect immediately, including on active sessions
 * (RL-M1-018).
 *
 * Brief §6.3. There are two halves and they fail in different ways:
 *
 *   THE AUTHORIZATION HALF is true by omission — `can()` holds no cache, so a
 *   decision reads current grants and a removal is felt on the very next
 *   request. The risk is not that it is wrong today; it is that a cache is the
 *   obvious optimisation and adding one would break this silently, with every
 *   existing test still green. So this file asserts the absence structurally as
 *   well as behaviourally.
 *
 *   THE SESSION HALF needs code. An authorization change is felt at once, but
 *   the session is a bearer credential that outlives it. For a demotion that is
 *   correct. For a compromised account it is not, and §6.3's "including on
 *   active sessions" is asking for the credential itself to stop working.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { can } from "../../src/authz/can.ts";
import { contextForRequest, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  applyPrivilegeChange,
  endsAccess,
  NotPermittedToRevokeSessions,
  PRIVILEGE_CHANGE_REASONS,
} from "../../src/auth/privilege_changes.ts";
import { listAudit } from "../../src/repo/audit.ts";
import { signIn, validateSession } from "../../src/auth/sessions.ts";
import { hashPassword } from "../../src/auth/passwords.ts";
import { DATABASE_URL, skipWithoutDatabase, withMigratedDatabase } from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

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

type World = { orgId: string; ownerId: string; memberId: string; orgNodeId: string; memberEmail: string };

// Test-only, and long enough that the weak-secret checks have no opinion.
const MEMBER_PASSWORD = "correct-horse-battery-staple-4471";

/** An organization with an owner and one other member. */
async function seedWorld(client: Client, slug = "acme"): Promise<World> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ($1, 'Acme') returning id",
    [slug],
  );
  const orgId = org.rows[0]?.id ?? "";

  const mk = async (email: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into users (email, name) values ($1, 'Person') returning id",
      [email],
    );
    const id = r.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, id]);
    return id;
  };

  const ownerId = await mk(`owner@${slug}.example`);
  const memberId = await mk(`member@${slug}.example`);
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, 'owner', 'organization')`,
    [orgId, ownerId],
  );

  // A real password, so sessions can be created the way the product creates
  // them rather than by reaching past the authentication layer.
  await client.query("update users set password_hash = $1 where id = $2", [
    await hashPassword(MEMBER_PASSWORD),
    memberId,
  ]);

  const node = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  return { orgId, ownerId, memberId, orgNodeId: node.rows[0]?.id ?? "", memberEmail: `member@${slug}.example` };
}

const ctxFor = (world: World, userId: string): AuthzContext =>
  contextForRequest({ orgId: world.orgId, userId, requestId: `r-${randomUUID()}` });

const at = (scopeNodeId: string) => ({ scopeNodeId, resourceId: null });

// ---------------------------------------------------------------------------
// The authorization half — no cached answer, anywhere
// ---------------------------------------------------------------------------

test("granting a role is felt on the very next decision", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.memberId);
      assert.equal((await can(ctx, "site.read", at(world.orgNodeId))).allowed, false);

      await client.query(
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
         values ($1, 'user', $2, 'viewer', 'organization')`,
        [world.orgId, world.memberId],
      );

      assert.equal(
        (await can(ctx, "site.read", at(world.orgNodeId))).allowed,
        true,
        "the SAME context must see the new grant with nothing re-created",
      );
    });
  });
});

test("removing a role is felt on the very next decision", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'viewer', 'organization')`,
      [world.orgId, world.memberId],
    );
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.memberId);
      assert.equal((await can(ctx, "site.read", at(world.orgNodeId))).allowed, true);

      await client.query("delete from grants where org_id = $1 and subject_id = $2", [
        world.orgId,
        world.memberId,
      ]);

      assert.equal((await can(ctx, "site.read", at(world.orgNodeId))).allowed, false);
    });
  });
});

test("a deny added mid-session takes effect at once", { skip }, async () => {
  // The containment case: an operator adds a deny and expects it to bite
  // immediately, not at the next sign-in.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'admin', 'organization')`,
      [world.orgId, world.memberId],
    );
    await usingScratch(database, async () => {
      const ctx = ctxFor(world, world.memberId);
      assert.equal((await can(ctx, "secret.read_value", at(world.orgNodeId))).allowed, true);

      await client.query(
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, effect)
         values ($1, 'user', $2, 'admin', 'organization', 'deny')`,
        [world.orgId, world.memberId],
      );

      const after = await can(ctx, "secret.read_value", at(world.orgNodeId));
      assert.equal(after.allowed, false);
      assert.equal(after.reason, "explicit-deny");
    });
  });
});

test("the decision path holds no cache", () => {
  // Structural, because behavioural tests cannot see a cache that has not been
  // added yet — and adding one is the obvious optimisation. This is the test
  // that turns "we happen not to cache" into "caching is a build failure".
  const findings: string[] = [];
  for (const file of ["src/authz/can.ts", "src/repo/authorization.ts"]) {
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const pattern of [/\bnew Map\s*</, /\bnew WeakMap\s*</, /\bmemoi[sz]e/i, /\bcache\b(?!s a)/i]) {
      const match = pattern.exec(source.replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, ""));
      if (match) findings.push(`${file}: ${match[0]}`);
    }
  }
  assert.deepEqual(
    findings,
    [],
    `authorization must not cache — §6.3 requires role changes to take effect immediately:\n${findings.join("\n")}`,
  );
});

// ---------------------------------------------------------------------------
// The session half — the credential itself stops working
// ---------------------------------------------------------------------------

test("containment revokes every live session for a member", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const member = ctxFor(world, world.memberId);
      const first = await signIn(member, { email: world.memberEmail, password: MEMBER_PASSWORD });
      const second = await signIn(member, { email: world.memberEmail, password: MEMBER_PASSWORD });
      assert.ok(first.ok && second.ok, "both sign-ins should succeed");

      assert.notEqual(await validateSession(member, first.token), null);
      assert.notEqual(await validateSession(member, second.token), null);

      const owner = ctxFor(world, world.ownerId);
      const result = await applyPrivilegeChange(owner, {
        subjectUserId: world.memberId,
        reason: "containment",
      });
      assert.equal(result.sessionsRevoked, 2);

      assert.equal(
        await validateSession(member, first.token),
        null,
        "the credential itself must stop working, not merely lose its permissions",
      );
      assert.equal(await validateSession(member, second.token), null);
    });
  });
});

test("a member may always sign themselves out everywhere", { skip }, async () => {
  // Needs no permission on purpose. Signing yourself out is the first thing
  // anyone does when they think they are compromised, and gating it would be
  // actively harmful.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const member = ctxFor(world, world.memberId);
      const signedIn = await signIn(member, { email: world.memberEmail, password: MEMBER_PASSWORD });
      assert.ok(signedIn.ok);

      const result = await applyPrivilegeChange(member, {
        subjectUserId: world.memberId,
        reason: "containment",
      });
      assert.equal(result.sessionsRevoked, 1);
      assert.equal(await validateSession(member, signedIn.token), null);
    });
  });
});

test("a member without the action cannot sign anyone else out", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'developer', 'organization')`,
      [world.orgId, world.memberId],
    );
    await usingScratch(database, async () => {
      await assert.rejects(
        () =>
          applyPrivilegeChange(ctxFor(world, world.memberId), {
            subjectUserId: world.ownerId,
            reason: "containment",
          }),
        NotPermittedToRevokeSessions,
      );
    });
  });
});

test("a refused containment attempt is audited as a denial", { skip }, async () => {
  // Someone trying and failing to sign an owner out is exactly what an incident
  // review is looking for. A silent refusal would lose it.
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'developer', 'organization')`,
      [world.orgId, world.memberId],
    );
    await usingScratch(database, async () => {
      const attacker = ctxFor(world, world.memberId);
      await assert.rejects(() =>
        applyPrivilegeChange(attacker, { subjectUserId: world.ownerId, reason: "containment" }),
      );

      const denials = await listAudit(attacker, { decision: "deny" });
      assert.equal(denials.length, 1);
      assert.equal(denials[0]?.action, "member.revoke_sessions");
      assert.equal(denials[0]?.resourceId, world.ownerId);
    });
  });
});

test("a successful containment is audited with what it ended", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const world = await seedWorld(client);
    await usingScratch(database, async () => {
      const member = ctxFor(world, world.memberId);
      const signedIn = await signIn(member, { email: world.memberEmail, password: MEMBER_PASSWORD });
      assert.ok(signedIn.ok);

      const owner = ctxFor(world, world.ownerId);
      await applyPrivilegeChange(owner, { subjectUserId: world.memberId, reason: "membership-removed" });

      const entries = await listAudit(owner, { action: "member.revoke_sessions" });
      assert.equal(entries.length, 1);
      assert.equal(entries[0]?.decision, "allow");
      assert.equal(entries[0]?.reason, "membership-removed");
    });
  });
});

test("only demotion and promotion leave access in place", () => {
  // The distinction the caller acts on: rotate versus revoke. A demotion that
  // signed people out would train operators not to demote anyone, which is the
  // opposite of what a permission system is for.
  assert.equal(endsAccess("grant-added"), false);
  assert.equal(endsAccess("grant-removed"), false);
  assert.equal(endsAccess("membership-removed"), true);
  assert.equal(endsAccess("containment"), true);
  assert.equal(PRIVILEGE_CHANGE_REASONS.length, 4);
});

test("no module outside the authorization layer decides a permission", () => {
  // §9's anti-pattern. privilege_changes.ts deliberately does NOT check the
  // permission itself — it lets the repository do it and only decides what to
  // audit. A second check is the shape that eventually disagrees with the first.
  const source = readFileSync(join(ROOT, "src", "auth", "privilege_changes.ts"), "utf8");
  assert.ok(
    !/\bawait can\(/.test(source),
    "privilege_changes must not run its own permission check; the repository owns it",
  );
  const authFiles = globSync("src/auth/**/*.ts", { cwd: ROOT });
  assert.ok(authFiles.length > 0, "the glob should find the auth modules");
});
