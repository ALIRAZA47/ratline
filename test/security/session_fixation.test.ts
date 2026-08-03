/**
 * Password authentication and session management (RL-M1-017).
 *
 * Brief §6.7 names session fixation in the minimum security suite, and this
 * file is that entry. It also carries the other three acceptance criteria,
 * because they are the same mechanism seen from different sides:
 *
 *   1. Passwords are hashed with a memory-hard function, vetted parameters
 *                      -> "the hash is memory-hard, with the parameters …",
 *                         "a stored hash carries the parameters …",
 *                         "the comparison is constant-time …"
 *   2. Identifiers rotate on privilege change and on login
 *                      -> "signing in mints a new identifier …",
 *                         "a privilege change rotates the identifier"
 *   3. A pre-login identifier is never honoured after login
 *                      -> "a pre-login identifier is never honoured after login"
 *   4. Sessions are revocable server-side, and revocation is immediate
 *                      -> "signing out kills the identifier immediately",
 *                         "revoking every session of one person …",
 *                         "an expired session is dead with no cleanup …"
 *
 * Two rules this file follows, both load-bearing.
 *
 * **Every assertion about session validity runs as `ratline_app`.** The
 * migration connection is the superuser `initdb` created, and a superuser
 * bypasses row-level security unconditionally — so the same assertions written
 * on that connection would pass without exercising a single policy. Repository
 * calls go through a pool pointed at `ratline_app` (`usingScratch`), and the
 * raw-SQL assertions go through `asApplicationRole`. Writes made on the
 * migration connection are fixture setup, never the thing under test.
 *
 * **The pre-authentication calls use a service-identity context.** Sign-in
 * happens before there is a user to attribute it to, and `contextForRequest`
 * wants a user id. C6 already says automation acts as a named service identity,
 * and a sign-in attempt is exactly that case — so the tests exercise the shape
 * an interface can actually use, rather than quietly presupposing that the
 * caller already knows who is signing in. See the header of
 * `src/auth/sessions.ts`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { NotPermittedError } from "../../src/authz/can.ts";
import {
  contextForRequest,
  contextForServiceIdentity,
  type AuthzContext,
} from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  SESSION_END_REASONS,
  SESSION_TOKEN_PREFIX,
  sessionTokenDigest,
} from "../../src/auth/model.ts";
import {
  hashPassword,
  memoryCostBytes,
  needsRehash,
  parseStoredHash,
  PASSWORD_PARAMETERS,
  SALT_BYTES,
  UnreadableHashError,
  verifyPassword,
} from "../../src/auth/passwords.ts";
import {
  listSessions,
  revokeAllSessions,
  revokeSession,
  rotateSession,
  setOwnPassword,
  signIn,
  signOut,
  validateSession,
  type SignInResult,
} from "../../src/auth/sessions.ts";
import { startSession } from "../../src/repo/sessions.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/** The fixture password. Nothing in `src/` may contain one; a test may. */
const PASSPHRASE = "correct horse battery staple";
const OTHER_PASSPHRASE = "a different one entirely";

/**
 * Hashing costs 128 MiB and a couple of hundred milliseconds by design, so the
 * fixture hash is computed once for the whole file rather than once per test.
 * Every *verification* still pays full price, which is the part under test.
 */
let fixture: Promise<string> | null = null;
function fixtureHash(): Promise<string> {
  fixture ??= hashPassword(PASSPHRASE);
  return fixture;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Tenant = {
  readonly orgId: string;
  readonly ownerId: string;
  /** A named service identity for the pre-authentication path. See the header. */
  readonly signInIdentityId: string;
};

async function seedTenant(client: Client, slug: string): Promise<Tenant> {
  const { orgId, userId } = await seedOrganization(client, slug);
  const identity = await client.query<{ id: string }>(
    "insert into service_identities (org_id, name) values ($1, 'sign-in') returning id",
    [orgId],
  );
  return { orgId, ownerId: userId, signInIdentityId: identity.rows[0]?.id ?? "" };
}

/** A member with, optionally, a password. Returns the user id. */
async function addMember(
  client: Client,
  orgId: string,
  email: string,
  storedHash: string | null = null,
): Promise<string> {
  const existing = await client.query<{ id: string }>("select id from users where email = $1", [email]);
  const userId =
    existing.rows[0]?.id ??
    (
      await client.query<{ id: string }>(
        "insert into users (email, name, password_hash) values ($1, 'Person', $2) returning id",
        [email, storedHash],
      )
    ).rows[0]?.id ??
    "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);
  return userId;
}

async function grantRole(client: Client, orgId: string, userId: string, roleKey: string): Promise<void> {
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, $3, 'organization')`,
    [orgId, userId, roleKey],
  );
}

const requestCtx = (orgId: string, userId: string): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `rl-${randomUUID()}` });

const signInCtx = (tenant: Tenant): AuthzContext =>
  contextForServiceIdentity({
    orgId: tenant.orgId,
    serviceIdentityId: tenant.signInIdentityId,
    name: "sign-in",
    requestId: `rl-${randomUUID()}`,
  });

/**
 * Point the repository pool at a scratch database as `ratline_app` — the
 * unprivileged, NOBYPASSRLS role the application connects as in production.
 *
 * The `asApplicationRole` call first is not decoration: it is what grants that
 * role LOGIN, once per process. Without it this file would depend on some
 * earlier test run having done it, which is the kind of ordering dependency that
 * turns into a mysterious CI failure on a fresh cluster.
 */
async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
  await asApplicationRole(database, () => Promise.resolve());
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

/** Narrow a sign-in to its success branch, failing the test with the refusal. */
function signedIn(result: SignInResult): Extract<SignInResult, { ok: true }> {
  if (!result.ok) assert.fail(`expected a sign-in, got refusal "${result.refusal}"`);
  return result;
}

// ---------------------------------------------------------------------------
// Acceptance 3 — THE session fixation test
// ---------------------------------------------------------------------------

test("a pre-login identifier is never honoured after login", { skip }, async () => {
  // The attack: an identifier that existed before the sign-in is still accepted
  // afterwards, so whoever planted it is now inside an authenticated session.
  //
  // Three things are asserted, and all three have to hold. That the old
  // identifier is dead. That the new one is different — a defence that revoked
  // the old identifier and handed back the same string would pass the first
  // assertion and be worthless. And that the new session is a different row,
  // because rotating the secret in place would leave no record that anything
  // happened.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    let plantedDigest = "";
    let survivingDigest = "";

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const credentials = { email: "alice@acme.example", password: PASSPHRASE };

      const before = signedIn(await signIn(ctx, credentials));
      const planted = before.token;
      assert.notEqual(
        await validateSession(ctx, planted),
        null,
        "the identifier has to be live to begin with, or this test proves nothing",
      );

      // The victim signs in, and the browser sends what was planted in it.
      const after = signedIn(await signIn(ctx, { ...credentials, presentedToken: planted }));

      assert.equal(
        await validateSession(ctx, planted),
        null,
        "the pre-login identifier is still honoured — this is session fixation",
      );
      assert.notEqual(after.token, planted, "sign-in returned the identifier it was handed");
      assert.notEqual(after.session.id, before.session.id, "the session row was reused, not replaced");
      assert.equal(after.session.rotatedFrom, before.session.id, "the chain should record what it replaced");
      assert.notEqual(await validateSession(ctx, after.token), null, "the new identifier must work");

      plantedDigest = sessionTokenDigest(planted);
      survivingDigest = sessionTokenDigest(after.token);
    });

    // And again in SQL, as the unprivileged role: the retired identifier is not
    // merely unused, it is absent from the liveness view and recorded dead with
    // a reason and a time.
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);

      const live = await app.query<{ token_hash: string }>("select token_hash from live_sessions");
      assert.deepEqual(
        live.rows.map((r) => r.token_hash),
        [survivingDigest],
        "exactly one identifier should be live, and it should be the new one",
      );

      const dead = await app.query<{ revoked_reason: string; revoked_at: Date | null }>(
        "select revoked_reason, revoked_at from sessions where token_hash = $1",
        [plantedDigest],
      );
      assert.equal(dead.rows[0]?.revoked_reason, "rotated");
      assert.notEqual(dead.rows[0]?.revoked_at, null);
      await app.query("rollback");
    });
  });
});

test("an identifier supplied by the client is never adopted", { skip }, async () => {
  // The stronger half of the defence, and the one that does not depend on the
  // interface remembering to pass what it received: there is no code path that
  // turns a client-supplied string into an authenticated identifier. Signing in
  // while presenting an identifier for somebody ELSE'S session must not produce
  // a session under that identifier either.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    await addMember(client, acme.orgId, "mallory@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);

      const attacker = signedIn(
        await signIn(ctx, { email: "mallory@acme.example", password: PASSPHRASE }),
      );

      const victim = signedIn(
        await signIn(ctx, {
          email: "alice@acme.example",
          password: PASSPHRASE,
          presentedToken: attacker.token,
        }),
      );

      assert.notEqual(victim.token, attacker.token);
      assert.equal(
        await validateSession(ctx, attacker.token),
        null,
        "the presented identifier must be revoked, whoever it belonged to",
      );
      assert.equal(
        victim.session.rotatedFrom,
        null,
        "a session must not record another person's session as its predecessor",
      );
      assert.equal(victim.session.userId, (await validateSession(ctx, victim.token))?.userId);
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — rotation on login and on privilege change
// ---------------------------------------------------------------------------

test("signing in mints a new identifier every time", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const seen = new Set<string>();
      for (let i = 0; i < 3; i++) {
        const result = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
        assert.ok(result.token.startsWith(SESSION_TOKEN_PREFIX), "an identifier should be recognisable in a log");
        seen.add(result.token);
      }
      assert.equal(seen.size, 3, "two sign-ins produced the same identifier");
    });
  });
});

test("a privilege change rotates the identifier", { skip }, async () => {
  // §6.3: role changes take effect immediately, including on active sessions.
  // Rotation is the half of that which this task owns — the identifier in the
  // browser is never older than the authority behind it.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const first = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));

      const rotated = await rotateSession(ctx, first.token, "privilege-change");
      assert.notEqual(rotated, null, "a live identifier should rotate");
      assert.notEqual(rotated?.token, first.token);
      assert.equal(rotated?.session.rotatedFrom, first.session.id);
      assert.equal(await validateSession(ctx, first.token), null, "the old identifier must be dead");
      assert.notEqual(await validateSession(ctx, rotated?.token ?? ""), null);

      // Rotating something already dead must not mint anything: if it could,
      // revocation would be a speed bump rather than an ending.
      assert.equal(await rotateSession(ctx, first.token, "rotated"), null);
    });

    const reasons = await client.query<{ revoked_reason: string }>(
      "select revoked_reason from sessions where revoked_reason is not null",
    );
    assert.deepEqual(reasons.rows.map((r) => r.revoked_reason), ["privilege-change"]);
  });
});

// ---------------------------------------------------------------------------
// Acceptance 4 — revocation, immediate and server-side
// ---------------------------------------------------------------------------

test("signing out kills the identifier immediately, with nothing having run", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const session = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));

      assert.notEqual(await validateSession(ctx, session.token), null);
      assert.equal(await signOut(ctx, session.token), true);
      assert.equal(
        await validateSession(ctx, session.token),
        null,
        "the very next request must be refused — revocation is a predicate, not a sweep",
      );
      assert.equal(await signOut(ctx, session.token), false, "revocation should be idempotent");
    });

    // The row survives. Revocation recorded something; it did not delete it.
    const rows = await client.query<{ revoked_reason: string }>("select revoked_reason from sessions");
    assert.deepEqual(rows.rows.map((r) => r.revoked_reason), ["signed-out"]);
  });
});

test("revoking every session of one person ends all of them and nobody else's", { skip }, async () => {
  // The compromised-account case: a laptop is missing and every credential it
  // held has to stop working now.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    await addMember(client, acme.orgId, "bob@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const alices: string[] = [];
      for (let i = 0; i < 3; i++) {
        alices.push(signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE })).token);
      }
      const bob = signedIn(await signIn(ctx, { email: "bob@acme.example", password: PASSPHRASE }));

      const owner = requestCtx(acme.orgId, acme.ownerId);
      assert.equal(await revokeAllSessions(owner, aliceId), 3, "should report the credentials it ended");

      for (const token of alices) {
        assert.equal(await validateSession(ctx, token), null, "every one of them must be dead");
      }
      assert.notEqual(await validateSession(ctx, bob.token), null, "and nobody else's may be touched");

      assert.equal(await revokeAllSessions(owner, aliceId), 0, "a second sweep ends nothing");
    });
  });
});

test("revoking one session by identity leaves the others alone", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const laptop = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const phone = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));

      // Alice ending her own other session needs no permission: acting on
      // yourself escalates nothing.
      const alice = requestCtx(acme.orgId, aliceId);
      assert.equal(await revokeSession(alice, laptop.session.id), true);
      assert.equal(await validateSession(ctx, laptop.token), null);
      assert.notEqual(await validateSession(ctx, phone.token), null);

      assert.equal(await revokeSession(alice, randomUUID()), false, "an unknown session id is not an error");

      const listed = await listSessions(alice);
      assert.equal(listed.length, 2, "an ended session stays visible — it did not vanish, it died");
      assert.deepEqual(
        listed.map((s) => s.revokedReason).sort(),
        [null, "revoked"],
      );
    });
  });
});

test("ending somebody else's sessions needs permission", { skip }, async () => {
  // There is no catalogued action for this yet — src/authz/catalogue.ts records
  // the gap and hands it to RL-M1-018 — so it is gated on `member.remove`,
  // which can only ever be too strict. This test pins both directions, because
  // a stand-in that let everyone through would be worse than no stand-in.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    const bobId = await addMember(client, acme.orgId, "bob@acme.example", await fixtureHash());
    await grantRole(client, acme.orgId, bobId, "viewer");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const alice = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const bob = signedIn(await signIn(ctx, { email: "bob@acme.example", password: PASSPHRASE }));

      await assert.rejects(
        () => revokeAllSessions(requestCtx(acme.orgId, bobId), aliceId),
        NotPermittedError,
        "a Viewer must not be able to sign another member out",
      );
      await assert.rejects(
        () => revokeSession(requestCtx(acme.orgId, bobId), alice.session.id),
        NotPermittedError,
      );
      assert.notEqual(await validateSession(ctx, alice.token), null, "and the refusal must have changed nothing");

      // Bob may still end his own, and an Owner may end anyone's.
      assert.equal(await revokeAllSessions(requestCtx(acme.orgId, bobId), bobId), 1);
      assert.equal(await validateSession(ctx, bob.token), null);
      assert.equal(await revokeAllSessions(requestCtx(acme.orgId, acme.ownerId), aliceId), 1);
      assert.equal(await validateSession(ctx, alice.token), null);
    });
  });
});

// ---------------------------------------------------------------------------
// Expiry — a predicate, never a job
// ---------------------------------------------------------------------------

test("an already-expired session is dead on first sight, with no cleanup having run", { skip }, async () => {
  // Written with real timestamps in the past and then read for the first time.
  // There is no window in which a job could have acted, because the session was
  // never live in this database.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    const token = `${SESSION_TOKEN_PREFIX}${randomUUID()}`;

    await client.query(
      `insert into sessions (org_id, user_id, token_hash, created_at, expires_at)
       values ($1, $2, $3, now() - interval '2 hours', now() - interval '1 hour')`,
      [acme.orgId, aliceId, sessionTokenDigest(token)],
    );

    await usingScratch(database, async () => {
      assert.equal(await validateSession(signInCtx(acme), token), null);
    });

    // The row is still there. Expiry filtered; it removed nothing.
    const row = await client.query("select 1 from sessions where token_hash = $1", [
      sessionTokenDigest(token),
    ]);
    assert.equal(row.rows.length, 1, "expiry must not delete the row — history is not enforcement");
  });
});

test("a session dies mid-transaction the moment it expires", { skip }, async () => {
  // The sharpest form of "revocation and expiry are enforced server-side, not by
  // a cleanup job". One transaction is held open across the expiry instant.
  // Between the two reads the only statements issued are the reads themselves —
  // no job, no trigger, no sweep. The answer changes because time passed.
  //
  // It also pins the clock. `now()` is frozen for the life of a transaction, so
  // the test asserts `now()` has NOT moved while the answer flipped: if the view
  // used `now()`, this test could not pass.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");
    const digest = sessionTokenDigest(`${SESSION_TOKEN_PREFIX}${randomUUID()}`);

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const opened = await app.query<{ txn: string }>("select now()::text as txn");
      const txnClock = opened.rows[0]?.txn ?? "";

      // Written from the migration connection while the reader's transaction is
      // open, which is how a session is created in production too: by another
      // request, on another connection.
      await client.query(
        `insert into sessions (org_id, user_id, token_hash, expires_at)
         values ($1, $2, $3, now() + interval '700 milliseconds')`,
        [acme.orgId, aliceId, digest],
      );

      const live = await app.query("select 1 from live_sessions where token_hash = $1", [digest]);
      assert.equal(live.rows.length, 1, "the session should be live until it expires");

      await sleep(900);

      const after = await app.query("select 1 from live_sessions where token_hash = $1", [digest]);
      assert.equal(after.rows.length, 0, "the same question, in the same transaction, must now find nothing");

      const clocks = await app.query<{ txn: string; stmt: string }>(
        "select now()::text as txn, statement_timestamp()::text as stmt",
      );
      assert.equal(
        clocks.rows[0]?.txn,
        txnClock,
        "the transaction never ended, so nothing between the two reads could have run",
      );
      assert.notEqual(
        clocks.rows[0]?.stmt,
        txnClock,
        "and the statement clock is what moved — that is what the view reads",
      );
      await app.query("rollback");
    });
  });
});

test("liveness is a view predicate, and no job exists to be relied on", { skip }, async () => {
  // Structural evidence, so the property survives someone "optimising" the
  // filter out of the view and into a nightly sweep.
  await withMigratedDatabase(async (client) => {
    const view = await client.query<{ definition: string }>(
      "select pg_get_viewdef('live_sessions'::regclass, true) as definition",
    );
    const definition = view.rows[0]?.definition ?? "";
    assert.match(definition, /revoked_at IS NULL/i, "revocation must be filtered in the view");
    assert.match(definition, /expires_at/, "and so must expiry");
    assert.match(definition, /statement_timestamp\(\)/, "evaluated per statement, not per transaction");

    const invoker = await client.query<{ reloptions: string[] | null }>(
      "select reloptions from pg_class where relname = 'live_sessions'",
    );
    assert.deepEqual(
      invoker.rows[0]?.reloptions,
      ["security_invoker=true"],
      "a view without security_invoker runs as its owner — a superuser — and hands over every tenant",
    );

    const triggers = await client.query<{ tgname: string }>(
      "select tgname from pg_trigger where tgrelid = 'sessions'::regclass and not tgisinternal",
    );
    assert.deepEqual(triggers.rows.map((r) => r.tgname), [], "no trigger may be in the enforcement path");

    const events = await client.query("select 1 from pg_event_trigger");
    assert.equal(events.rows.length, 0, "and no event trigger either");
  });
});

// ---------------------------------------------------------------------------
// The identifier itself
// ---------------------------------------------------------------------------

test("only a digest is stored, and the column cannot hold an identifier", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    let issued = "";
    await usingScratch(database, async () => {
      issued = signedIn(
        await signIn(signInCtx(acme), { email: "alice@acme.example", password: PASSPHRASE }),
      ).token;
    });

    const stored = await client.query<{ token_hash: string }>("select token_hash from sessions");
    const hashes = stored.rows.map((r) => r.token_hash);
    assert.deepEqual(hashes, [sessionTokenDigest(issued)]);
    assert.ok(!hashes.includes(issued), "the plaintext identifier reached the database");
    assert.match(hashes[0] ?? "", /^[0-9a-f]{64}$/);

    await assert.rejects(
      () =>
        client.query(
          "insert into sessions (org_id, user_id, token_hash, expires_at) values ($1, $2, $3, now() + interval '1 hour')",
          [acme.orgId, aliceId, issued],
        ),
      /sessions_hash_shape/,
      "storing a plaintext identifier must violate a constraint, not merely a convention",
    );
  });
});

test("a session is scoped to one organization and invisible from another", { skip }, async () => {
  // A person may belong to several organizations; a session names one of them.
  // The identifier minted in Acme has to be nothing at all in Globex, including
  // for the same human.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const stored = await fixtureHash();
    await addMember(client, acme.orgId, "carol@example.com", stored);
    await addMember(client, globex.orgId, "carol@example.com", stored);

    await usingScratch(database, async () => {
      const inAcme = signedIn(
        await signIn(signInCtx(acme), { email: "carol@example.com", password: PASSPHRASE }),
      );
      assert.notEqual(await validateSession(signInCtx(acme), inAcme.token), null);
      assert.equal(
        await validateSession(signInCtx(globex), inAcme.token),
        null,
        "an identifier from another organization must be indistinguishable from nonsense",
      );
      assert.equal(await signOut(signInCtx(globex), inAcme.token), false);
      assert.notEqual(
        await validateSession(signInCtx(acme), inAcme.token),
        null,
        "and the failed attempt must not have ended it",
      );
    });
  });
});

test("with no tenant bound, the sessions table is invisible", { skip }, async () => {
  // The missing-setting case has to fail closed, exactly as migration 4's
  // policies do: current_setting(..., true) is NULL, and org_id = NULL is not
  // true, so nothing matches.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");
    await client.query(
      `insert into sessions (org_id, user_id, token_hash, expires_at)
       values ($1, $2, $3, now() + interval '1 hour')`,
      [acme.orgId, aliceId, sessionTokenDigest("anything")],
    );

    await asApplicationRole(database, async (app) => {
      for (const relation of ["sessions", "live_sessions"]) {
        const r = await app.query(`select 1 from ${relation}`);
        assert.equal(r.rows.length, 0, `${relation}: visible with no tenant set`);
      }

      // And a write cannot be aimed at another tenant. WITH CHECK, not just
      // USING.
      await app.query("begin");
      await setTenant(app, acme.orgId);
      await assert.rejects(
        () =>
          app.query(
            `insert into sessions (org_id, user_id, token_hash, expires_at)
             values ($1, $2, $3, now() + interval '1 hour')`,
            [globex.orgId, aliceId, sessionTokenDigest("implant")],
          ),
        /row-level security/i,
      );
      await app.query("rollback");
    });
  });
});

test("a session cannot be created for someone outside the organization", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const outsider = await addMember(client, globex.orgId, "dave@globex.example");

    await usingScratch(database, async () => {
      await assert.rejects(
        () =>
          startSession(requestCtx(acme.orgId, acme.ownerId), {
            userId: outsider,
            tokenDigest: sessionTokenDigest("nope"),
            expiresAt: new Date(Date.now() + 60_000),
            rotatedFrom: null,
            userAgent: "",
            ip: null,
          }),
        /not a member of this organization/,
      );
    });
  });
});

test("last-seen is recorded by validating, not by remembering to call something", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const issued = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.equal(issued.session.lastSeenAt, null, "a session has not been used when it is issued");

      const used = await validateSession(ctx, issued.token);
      assert.notEqual(used?.lastSeenAt, null, "validating a session is using it");
      assert.ok((used?.lastSeenAt?.getTime() ?? 0) >= issued.session.createdAt.getTime());
    });
  });
});

test("the ending reasons TypeScript knows are exactly the ones the schema accepts", { skip }, async () => {
  // A mirror that can drift is worse than no mirror, so it is read back out of
  // the database rather than trusted — the pattern test/authz/grant_expiry.test.ts
  // uses for the grant vocabulary.
  await withMigratedDatabase(async (client) => {
    const r = await client.query<{ definition: string }>(
      `select pg_get_constraintdef(oid) as definition
       from pg_constraint
       where conrelid = 'sessions'::regclass and conname = 'sessions_end_reason'`,
    );
    const definition = r.rows[0]?.definition ?? "";
    for (const reason of SESSION_END_REASONS) {
      assert.match(definition, new RegExp(`'${reason}'`), `the schema does not accept "${reason}"`);
    }
    assert.equal(
      definition.match(/'[a-z-]+'::text/g)?.length,
      SESSION_END_REASONS.length,
      "the schema accepts a reason TypeScript does not know about",
    );
  });
});

// ---------------------------------------------------------------------------
// Acceptance 1 — the password hash
// ---------------------------------------------------------------------------

test("the hash is memory-hard, with the parameters written down", () => {
  // Not "scrypt is used" — the parameters are the security property, and a
  // silent downgrade of N is the mutation that leaves everything else working.
  assert.ok(
    PASSWORD_PARAMETERS.cost >= 131072,
    `N is ${PASSWORD_PARAMETERS.cost}; the current OWASP minimum for scrypt is 2^17 with r=8, p=1`,
  );
  assert.equal(PASSWORD_PARAMETERS.cost & (PASSWORD_PARAMETERS.cost - 1), 0, "N must be a power of two");
  assert.ok(PASSWORD_PARAMETERS.blockSize >= 8, "r below 8 buys back the memory this is chosen for");
  assert.ok(PASSWORD_PARAMETERS.parallelization >= 1);
  assert.ok(PASSWORD_PARAMETERS.keyLength >= 32, "a 256-bit derived key");
  assert.ok(SALT_BYTES >= 16, "a 128-bit per-password salt");

  // 128 · N · r. The number an operator has to plan for, and the number that
  // makes this memory-hard rather than merely slow.
  assert.equal(memoryCostBytes(), 128 * 1024 * 1024);
});

test("a stored hash carries its parameters and a salt of its own", async () => {
  const first = await hashPassword(PASSPHRASE);
  const second = await hashPassword(PASSPHRASE);

  assert.notEqual(first, second, "the same password hashed twice must not collide — the salt is per password");
  assert.match(first, /^scrypt\$n=\d+,r=\d+,p=\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);

  const parsed = parseStoredHash(first);
  assert.deepEqual({ ...parsed.parameters }, { ...PASSWORD_PARAMETERS });
  assert.equal(parsed.salt.length, SALT_BYTES);
  assert.notDeepEqual(parsed.salt, parseStoredHash(second).salt);

  // The parameters travel with the hash, which is what makes raising them
  // possible without invalidating every password on the installation.
  const legacy = `scrypt$n=16384,r=8,p=1$${Buffer.alloc(16, 1).toString("base64url")}$${Buffer.alloc(32, 2).toString("base64url")}`;
  assert.equal(needsRehash(legacy), true, "a hash made with weaker parameters must be recognised");
  assert.equal(needsRehash(first), false);

  // Corruption is loud. An unreadable hash is not a failed sign-in — it means
  // something wrote a value this module did not produce (brief §9).
  assert.throws(() => parseStoredHash("hunter2"), UnreadableHashError);
  assert.throws(() => parseStoredHash("scrypt$n=0,r=8,p=1$AAAA$AAAA"), UnreadableHashError);
});

test("the comparison is constant-time, and that is a property of the source", () => {
  // THE HONEST TEST. Swapping `secretEquals` for `===` on the two encoded
  // strings is functionally identical: every assertion in this file about which
  // passwords are accepted passes either way, because both answer the same
  // question. Only the time taken differs, and a timing assertion precise enough
  // to see it would be too flaky to keep.
  //
  // So the property is pinned where it is actually visible: in the source. A
  // strict-equality operator inside a function whose entire job is comparing a
  // secret has no legitimate use, so its absence is checkable and its presence
  // is a finding.
  //
  // This is not complete, and saying so matters: `Buffer.compare(a, b) < 1`
  // would also be non-constant-time and would also pass. It catches the
  // mutation somebody actually makes, not every mutation possible.
  const source = readFileSync(join(ROOT, "src", "auth", "passwords.ts"), "utf8");

  assert.match(
    source,
    /import \{ secretEquals \} from "\.\.\/crypto\/secrets\.ts"/,
    "the one constant-time comparison in the codebase should be the one used here",
  );

  const start = source.indexOf("export async function verifyPassword");
  assert.ok(start > 0, "verifyPassword should exist");
  const body = source.slice(start, source.indexOf("\n}", start));

  assert.match(body, /return secretEquals\(/, "verifyPassword must return a constant-time comparison");
  assert.doesNotMatch(
    body,
    /[=!]==/,
    "verifyPassword contains a strict-equality operator; a secret comparison must not use one",
  );
});

test("an unknown account still pays for a full derivation", async () => {
  // Nonexistent and unauthorized have to be indistinguishable (§6.3's
  // acceptance gate), and a fast path for "no stored hash" would make them
  // distinguishable by a stopwatch rather than by the response body.
  //
  // The threshold is deliberately loose. A real derivation costs a couple of
  // hundred milliseconds; the fast path this rules out costs under one. Anything
  // in between is a comfortable margin, and a loaded machine only ever makes the
  // measured value larger.
  const started = process.hrtime.bigint();
  const answer = await verifyPassword(null, PASSPHRASE);
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  assert.equal(answer, false, "an account with no password cannot be signed into");
  assert.ok(
    elapsedMs > 25,
    `the no-password path returned in ${elapsedMs.toFixed(1)}ms, which is a timing oracle for account existence`,
  );
});

test("a wrong password is refused and a right one is accepted", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    await addMember(client, acme.orgId, "sso@acme.example", null);

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const email = "alice@acme.example";

      const wrong = await signIn(ctx, { email, password: OTHER_PASSPHRASE });
      assert.equal(wrong.ok, false);
      assert.equal(wrong.ok ? "" : wrong.refusal, "credential-rejected");

      // A near miss, in case anything compares a prefix.
      const nearly = await signIn(ctx, { email, password: `${PASSPHRASE} ` });
      assert.equal(nearly.ok, false);

      const right = signedIn(await signIn(ctx, { email, password: PASSPHRASE }));
      assert.equal(right.mustRehash, false, "a hash made with the current parameters needs no upgrade");
      assert.notEqual(await validateSession(ctx, right.token), null);

      // An account that has never had a password cannot be signed into by
      // supplying none, or any.
      const sso = await signIn(ctx, { email: "sso@acme.example", password: PASSPHRASE });
      assert.equal(sso.ok ? "" : sso.refusal, "no-password-set");

      // And an address with no account here is refused without saying so.
      const absent = await signIn(ctx, { email: "nobody@acme.example", password: PASSPHRASE });
      assert.equal(absent.ok ? "" : absent.refusal, "unknown-account");
    });
  });
});

test("a disabled account cannot sign in, however good the password", { skip }, async () => {
  // Disabling is what an operator does to a compromised account at 2am, so an
  // intact credential must not save it.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    await client.query("update users set disabled_at = now() where email = 'alice@acme.example'");

    await usingScratch(database, async () => {
      const result = await signIn(signInCtx(acme), {
        email: "alice@acme.example",
        password: PASSPHRASE,
      });
      assert.equal(result.ok ? "" : result.refusal, "account-disabled");
    });
  });
});

test("changing a password ends every session it was holding open", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const laptop = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const phone = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));

      const ended = await setOwnPassword(requestCtx(acme.orgId, aliceId), OTHER_PASSPHRASE);
      assert.equal(ended, 2, "every session the old credential opened has to go");
      assert.equal(await validateSession(ctx, laptop.token), null);
      assert.equal(await validateSession(ctx, phone.token), null);

      const old = await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE });
      assert.equal(old.ok, false, "the old password must stop working");
      signedIn(await signIn(ctx, { email: "alice@acme.example", password: OTHER_PASSPHRASE }));
    });
  });
});
