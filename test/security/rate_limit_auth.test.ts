/**
 * Rate limiting on every authentication path (RL-M1-020, threat model R-15).
 *
 * Brief §6.7 names "rate limiting on all auth endpoints including password
 * reset" in the security suite's minimum coverage, and this file is that entry.
 * R-15 is the reason it is urgent rather than nominal: `src/auth/passwords.ts`
 * derives a 128 MiB scrypt hash per sign-in attempt, deliberately including for
 * accounts that do not exist (ADR 0014), so an unauthenticated burst is a
 * resource lever on a control plane the brief expects to run on a laptop.
 *
 * The three acceptance criteria map onto tests like this:
 *
 *   1. Login, two-factor, password reset and token exchange are all limited
 *                  -> "every authentication path refuses once its published
 *                      budget is spent" (all four, at their real limits)
 *   2. Limits apply per account and per source address independently
 *                  -> "the account dimension trips with every attempt from a
 *                      different address", "the address dimension trips with
 *                      every attempt against a different account",
 *                      "a refusal in one dimension does not stop the other
 *                      counting"
 *   3. A test drives each endpoint past its limit and confirms rejection
 *                  -> the same first test; every path, over its limit, refused
 *
 * Everything else here exists because a limiter can pass all three of those and
 * still be worthless: one that fails open when the database is unwell, one that
 * never releases, one that only counts accounts that exist, or one that stores
 * the addresses it counted in plaintext.
 *
 * **Every assertion runs as `ratline_app`.** The migration connection is the
 * superuser `initdb` created, and a superuser bypasses row-level security
 * unconditionally — the same assertions written on it would pass without
 * exercising a single policy. Repository calls go through a pool pointed at
 * `ratline_app` (`usingScratch`); raw-SQL assertions go through
 * `asApplicationRole`. Writes on the migration connection are fixture setup,
 * never the thing under test.
 *
 * **The calls use a service-identity context.** A sign-in attempt happens before
 * there is anybody to attribute it to, and `contextForRequest` wants a user id.
 * C6 already says automation acts as a named service identity, and
 * `test/security/session_fixation.test.ts` made the same choice for the same
 * reason — this is the open seam ADR 0014 records and RL-M1-024 closes, not a
 * new one.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { contextForServiceIdentity, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  AUTH_PATHS,
  AUTH_RATE_LIMITS,
  checkAuthRateLimit,
  RATE_LIMIT_DIMENSIONS,
  rateLimitKey,
  recordAuthAttempt,
  resetAuthRateLimit,
  type AuthAttempt,
  type AuthPath,
  type PathRules,
  type RateLimitDecision,
} from "../../src/auth/rate_limit.ts";
import { pruneAuthRateLimits } from "../../src/repo/rate_limits.ts";
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Tenant = { readonly orgId: string; readonly signInIdentityId: string };

async function seedTenant(client: Client, slug: string): Promise<Tenant> {
  const { orgId } = await seedOrganization(client, slug);
  const identity = await client.query<{ id: string }>(
    "insert into service_identities (org_id, name) values ($1, 'sign-in') returning id",
    [orgId],
  );
  return { orgId, signInIdentityId: identity.rows[0]?.id ?? "" };
}

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
 * The `asApplicationRole` call first is what grants that role LOGIN, once per
 * process; without it this file would depend on some earlier test having done
 * it, which is the ordering dependency that becomes a mysterious CI failure on a
 * fresh cluster.
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

/** A rule pair, for tests that want small numbers or a short window. */
const rules = (account: number, address: number, windowMs = 60_000): PathRules => ({
  account: { limit: account, windowMs },
  address: { limit: address, windowMs },
});

const attempt = (path: AuthPath, account: string, address: string): AuthAttempt => ({
  path,
  account,
  address,
});

/** Attempt `times` times, returning every decision in order. */
async function attemptTimes(
  ctx: AuthzContext,
  times: number,
  make: (n: number) => AuthAttempt,
  override?: PathRules,
): Promise<RateLimitDecision[]> {
  const decisions: RateLimitDecision[] = [];
  for (let n = 0; n < times; n++) {
    const one = make(n);
    decisions.push(
      override === undefined
        ? await recordAuthAttempt(ctx, one)
        : await recordAuthAttempt(ctx, one, override),
    );
  }
  return decisions;
}

type StoredBucket = {
  dimension: string;
  path: string;
  bucket_key: string;
  attempts: number;
  window_started_at: Date;
  expires_at: Date;
};

/** Read the counter table as the unprivileged role, with a tenant bound. */
async function storedBuckets(database: string, orgId: string): Promise<StoredBucket[]> {
  return asApplicationRole(database, async (app) => {
    await app.query("begin");
    await setTenant(app, orgId);
    const rows = await app.query<StoredBucket>(
      `select dimension, path, bucket_key, attempts, window_started_at, expires_at
         from auth_rate_limits order by dimension, path, bucket_key`,
    );
    await app.query("rollback");
    return rows.rows;
  });
}

// ---------------------------------------------------------------------------
// Acceptance 1 and 3 — every path, driven past its limit, refused
// ---------------------------------------------------------------------------

test("every authentication path refuses once its published budget is spent", { skip }, async () => {
  // THE acceptance test. Each of the four paths named in acceptance 1 is driven
  // past the limit that ships, not past a convenient one invented here — a test
  // that only ever exercised an override would pass with the published limits
  // set to a billion.
  //
  // Each path gets its own account and address so the four budgets cannot prop
  // each other up, and each attempt names an account that does not exist,
  // because the limiter must not care.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);

      for (const path of AUTH_PATHS) {
        const limit = AUTH_RATE_LIMITS[path].account.limit;
        const account = `nobody-${path}@acme.example`;
        const address = `203.0.113.${AUTH_PATHS.indexOf(path) + 1}`;

        const spending = await attemptTimes(ctx, limit, () => attempt(path, account, address));
        assert.deepEqual(
          spending.map((d) => d.allowed),
          Array(limit).fill(true),
          `${path}: every attempt within the budget of ${limit} should be allowed`,
        );
        assert.deepEqual(
          spending.map((d) => d.counters[0]?.attempts),
          Array.from({ length: limit }, (_, n) => n + 1),
          `${path}: the account counter should climb one per attempt`,
        );

        const over = await recordAuthAttempt(ctx, attempt(path, account, address));
        assert.equal(over.allowed, false, `${path}: attempt ${limit + 1} was not refused`);
        assert.equal(over.refusedBy, "account", `${path}: the account budget is the one that ran out first`);
        assert.ok(
          (over.retryAt?.getTime() ?? 0) > Date.now(),
          `${path}: a refusal must say when it releases, or the caller cannot render Retry-After`,
        );

        // And it stays refused. A limiter that lets the next attempt through is
        // a speed bump.
        const stillOver = await recordAuthAttempt(ctx, attempt(path, account, address));
        assert.equal(stillOver.allowed, false, `${path}: the refusal did not hold`);
      }
    });
  });
});

test("the published limits are finite, positive, and wider per address than per account", () => {
  // The behavioural test above spends the ACCOUNT budget on every path, because
  // it is the smaller one — so nothing there would notice an address limit set
  // to a billion. Eight numbers, checked where they are cheap to check.
  for (const path of AUTH_PATHS) {
    const pathRules = AUTH_RATE_LIMITS[path];
    for (const dimension of RATE_LIMIT_DIMENSIONS) {
      const rule = pathRules[dimension];
      assert.ok(Number.isInteger(rule.limit) && rule.limit > 0, `${path}/${dimension}: limit must be a positive integer`);
      assert.ok(rule.limit <= 1000, `${path}/${dimension}: a limit of ${rule.limit} is not a limit`);
      assert.ok(
        Number.isInteger(rule.windowMs) && rule.windowMs >= 60_000,
        `${path}/${dimension}: a window shorter than a minute gives an attacker a fresh budget every minute`,
      );
      assert.ok(rule.windowMs <= 24 * 60 * 60_000, `${path}/${dimension}: a window this long is a lockout`);
    }
    assert.ok(
      pathRules.address.limit >= pathRules.account.limit,
      `${path}: an address budget below the account budget makes a shared office address trip before any person does`,
    );
  }
});

// ---------------------------------------------------------------------------
// Acceptance 2 — the two dimensions, each able to trip on its own
// ---------------------------------------------------------------------------

test("the account dimension trips with every attempt from a different address", { skip }, async () => {
  // The botnet shape: one account, a fresh address every time, so the address
  // dimension never has anything to say. Per-address limiting alone would let
  // this run for ever.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(4, 100);

      const spending = await attemptTimes(
        ctx,
        4,
        (n) => attempt("login", "victim@acme.example", `198.51.100.${n + 1}`),
        only,
      );
      assert.deepEqual(spending.map((d) => d.allowed), [true, true, true, true]);

      const over = await recordAuthAttempt(
        ctx,
        attempt("login", "victim@acme.example", "198.51.100.99"),
        only,
      );
      assert.equal(over.allowed, false, "a thousand addresses must not buy a thousand guesses at one password");
      assert.equal(over.refusedBy, "account");
      assert.equal(
        over.counters.find((c) => c.dimension === "address")?.attempts,
        1,
        "the address that tripped it was on its first attempt — the account dimension acted alone",
      );
    });
  });
});

test("the address dimension trips with every attempt against a different account", { skip }, async () => {
  // The spray shape: one attacker, one address, a different account every time,
  // so no account budget is ever spent. Per-account limiting alone would let
  // this enumerate the whole installation.
  //
  // This one uses the PUBLISHED login address limit rather than an override,
  // because it is the only test that spends an address budget and the number
  // that ships should be the number under test.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const limit = AUTH_RATE_LIMITS.login.address.limit;

      const spending = await attemptTimes(ctx, limit, (n) =>
        attempt("login", `person-${n}@acme.example`, "192.0.2.7"),
      );
      assert.deepEqual(
        spending.map((d) => d.allowed),
        Array(limit).fill(true),
        "every attempt inside the address budget should be allowed",
      );

      const over = await recordAuthAttempt(ctx, attempt("login", "one-more@acme.example", "192.0.2.7"));
      assert.equal(over.allowed, false, "one address must not get unlimited guesses by changing account");
      assert.equal(over.refusedBy, "address");
      assert.equal(
        over.counters.find((c) => c.dimension === "account")?.attempts,
        1,
        "the account it named was on its first attempt — the address dimension acted alone",
      );
    });
  });
});

test("a refusal in one dimension does not stop the other counting", { skip }, async () => {
  // The hole that makes "independently" nominal rather than true. If a refusal
  // by the account dimension short-circuited the address dimension, an attacker
  // would spend one account's budget for free — as far as their address was
  // concerned — and then move to the next account with a clean address budget.
  //
  // So: hammer ONE account well past its budget from one address, then attempt
  // a DIFFERENT account from the same address. The address must have been
  // counting the whole time.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(2, 6);

      await attemptTimes(ctx, 6, () => attempt("login", "first@acme.example", "192.0.2.9"), only);

      const next = await recordAuthAttempt(ctx, attempt("login", "second@acme.example", "192.0.2.9"), only);
      assert.equal(
        next.allowed,
        false,
        "moving to a fresh account must not hand back a fresh address budget",
      );
      assert.equal(next.refusedBy, "address");
      assert.equal(
        next.counters.find((c) => c.dimension === "account")?.attempts,
        1,
        "the new account really is on its first attempt",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Failing closed
// ---------------------------------------------------------------------------

test("a store it cannot reach is a refusal, not a pass", { skip }, async () => {
  // The property that decides whether this is a security control or a
  // decoration. The store is most likely to be unreachable precisely because
  // something is overwhelming it, so failing open hands the attacker exactly the
  // flood the limiter exists to stop.
  //
  // The pool is pointed at a port nothing listens on, which is a real connection
  // failure rather than a simulated one — nothing here mocks the thing under
  // test (§9).
  await withMigratedDatabase(async (client) => {
    const acme = await seedTenant(client, "acme");

    await disconnect();
    connect({ connectionString: "postgres://ratline@127.0.0.1:1/ratline_test", max: 1 });
    try {
      const ctx = signInCtx(acme);
      const one = attempt("login", "alice@acme.example", "192.0.2.10");

      const recorded = await recordAuthAttempt(ctx, one);
      assert.equal(recorded.allowed, false, "an unreachable counter must refuse the request");
      assert.equal(recorded.refusedBy, "store-unavailable");
      assert.notEqual(recorded.storeError, null, "the failure must be carried out, not swallowed (§9)");

      // The read-only path has to fail the same way. A `check` that returned
      // "not limited" because it could not look would be the same hole through
      // a different door.
      const checked = await checkAuthRateLimit(ctx, one);
      assert.equal(checked.allowed, false, "checking against an unreachable counter must also refuse");
      assert.equal(checked.refusedBy, "store-unavailable");
      assert.notEqual(checked.storeError, null);
    } finally {
      await disconnect();
    }
  });
});

test("failing closed is what the source says, not only what it happened to do", () => {
  // Structural backstop. The behavioural test above proves the current code
  // refuses; this one makes the *rule* visible, so a later refactor that adds a
  // second catch has somewhere obvious to be wrong. `storeUnavailable` is the
  // one construction of that decision, and it is not reachable with
  // `allowed: true`.
  const source = readFileSync(join(ROOT, "src", "auth", "rate_limit.ts"), "utf8");
  const start = source.indexOf("function storeUnavailable");
  assert.ok(start > 0, "storeUnavailable should exist and be the single answer to a store failure");
  const body = source.slice(start, source.indexOf("\n}", start));
  assert.match(body, /allowed:\s*false/, "a store failure must produce a refusal");
  assert.doesNotMatch(body, /allowed:\s*true/, "a store failure must never produce a pass");

  assert.equal(
    source.match(/catch \(cause\) \{\s*return storeUnavailable\(cause\);\s*\}/g)?.length,
    2,
    "both the counting path and the read-only path must route a store failure to the same refusal",
  );
});

// ---------------------------------------------------------------------------
// A window, not a lockout
// ---------------------------------------------------------------------------

test("a spent window releases on its own, with no administrator involved", { skip }, async () => {
  // A limit that has to be cleared by a person is a denial of service an
  // attacker triggers against any account they can name, for the price of one
  // burst. Written with a real short window and a real wait: the counter has to
  // come back by itself.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const brief = rules(2, 2, 400);
      const one = attempt("login", "alice@acme.example", "192.0.2.11");

      await attemptTimes(ctx, 2, () => one, brief);
      const refused = await recordAuthAttempt(ctx, one, brief);
      assert.equal(refused.allowed, false, "the budget should be spent");

      await sleep(600);

      const after = await recordAuthAttempt(ctx, one, brief);
      assert.equal(after.allowed, true, "the window must release without anybody clearing it");
      assert.equal(
        after.counters[0]?.attempts,
        1,
        "and it must release fully — a window that comes back already spent is still a lockout",
      );
    });
  });
});

test("attempts against a spent window do not push its release further away", { skip }, async () => {
  // The difference between a fixed window and a sliding one, and it is the
  // difference between "limited for fifteen minutes" and "limited for as long as
  // I keep sending traffic". A sliding window would let an attacker hold any
  // named account locked out indefinitely by attempting once per window.
  //
  // This also pins the cost property from migration 11 note 1: past the limit
  // the statement stops writing, so a sustained flood costs an index probe
  // rather than a row version. `attempts`, `window_started_at` and `expires_at`
  // all standing still is what "stopped writing" looks like from outside.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const one = attempt("login", "alice@acme.example", "192.0.2.12");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      await attemptTimes(ctx, 3, () => one, rules(3, 3));
    });
    const spent = await storedBuckets(database, acme.orgId);

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      for (let n = 0; n < 5; n++) {
        const refused = await recordAuthAttempt(ctx, one, rules(3, 3));
        assert.equal(refused.allowed, false);
      }
    });
    const flooded = await storedBuckets(database, acme.orgId);

    assert.deepEqual(
      flooded.map((b) => [b.dimension, b.attempts, b.expires_at.getTime(), b.window_started_at.getTime()]),
      spent.map((b) => [b.dimension, b.attempts, b.expires_at.getTime(), b.window_started_at.getTime()]),
      "five more attempts moved the counter or the window: the limiter is amplifying the flood it is meant to absorb",
    );
    assert.deepEqual(
      flooded.map((b) => b.attempts),
      [3, 3],
      "the counter should saturate at the limit rather than climb",
    );
  });
});

test("a success clears the account budget and never the address budget", { skip }, async () => {
  // The other half of "a window is not a lockout": somebody who mistyped their
  // password twice and then got it right should not spend the next quarter hour
  // one mistake from being refused.
  //
  // And the half that must NOT happen: an attacker who holds one valid account
  // of their own must not be able to wipe their ADDRESS budget by signing into
  // it, then spray from a clean slate for free.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(5, 3);
      const one = attempt("login", "alice@acme.example", "192.0.2.13");

      await attemptTimes(ctx, 2, () => one, only);
      assert.equal(await resetAuthRateLimit(ctx, one), true, "there was a spent budget to clear");
      assert.equal(await resetAuthRateLimit(ctx, one), false, "clearing twice is not an error, it is a no-op");

      const afterReset = await recordAuthAttempt(ctx, one, only);
      assert.equal(afterReset.allowed, true);
      assert.equal(
        afterReset.counters.find((c) => c.dimension === "account")?.attempts,
        1,
        "the account budget should be fresh",
      );
      assert.equal(
        afterReset.counters.find((c) => c.dimension === "address")?.attempts,
        3,
        "the address budget must have kept counting through the reset",
      );

      const next = await recordAuthAttempt(ctx, one, only);
      assert.equal(next.allowed, false, "the address budget survived the success, as it must");
      assert.equal(next.refusedBy, "address");
    });
  });
});

test("a success on one path does not refresh another path's budget", { skip }, async () => {
  // The sharp case. If signing in successfully cleared the TWO-FACTOR budget,
  // an attacker who already knows the password could brute-force the second
  // factor by signing in again between batches — which is precisely the
  // situation two-factor authentication exists for.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(2, 50);
      const account = "alice@acme.example";
      const address = "192.0.2.14";

      await attemptTimes(ctx, 2, () => attempt("two-factor", account, address), only);
      assert.equal(
        (await recordAuthAttempt(ctx, attempt("two-factor", account, address), only)).allowed,
        false,
        "the second-factor budget should be spent",
      );

      // A perfectly good sign-in on the login path.
      await resetAuthRateLimit(ctx, attempt("login", account, address));

      assert.equal(
        (await recordAuthAttempt(ctx, attempt("two-factor", account, address), only)).allowed,
        false,
        "a successful password must not buy more guesses at the second factor",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// The limiter must not become an account-existence oracle
// ---------------------------------------------------------------------------

test("an account that does not exist is limited exactly like one that does", { skip }, async () => {
  // A limiter that counted only real accounts would tell an attacker which
  // addresses are real by which ones start being refused — handing back the
  // disclosure ADR 0014 spends 128 MiB per attempt to prevent. Count the
  // attempt, not the outcome.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await client.query("insert into users (email, name) values ('real@acme.example', 'Real')");
    await client.query(
      "insert into memberships (org_id, user_id) select $1, id from users where email = 'real@acme.example'",
      [acme.orgId],
    );

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(3, 100);

      const forReal = await attemptTimes(ctx, 4, () => attempt("login", "real@acme.example", "192.0.2.15"), only);
      const forGhost = await attemptTimes(ctx, 4, () => attempt("login", "ghost@acme.example", "192.0.2.16"), only);

      assert.deepEqual(
        forGhost.map((d) => [d.allowed, d.refusedBy]),
        forReal.map((d) => [d.allowed, d.refusedBy]),
        "an address with no account behind it must be limited on exactly the same schedule",
      );
      assert.deepEqual(forReal.map((d) => d.allowed), [true, true, true, false]);
    });
  });
});

test("nothing in the limiter can look an account up", { skip: false }, () => {
  // Structural, because the behavioural test above can only show that the two
  // cases agree today. The property is that there is no code path here that
  // resolves an identifier at all — so it cannot start to disagree.
  for (const file of [
    join("src", "auth", "rate_limit.ts"),
    join("src", "repo", "rate_limits.ts"),
  ]) {
    const source = readFileSync(join(ROOT, file), "utf8");
    const code = source
      .split("\n")
      .filter((line) => !/^\s*(\*|\/\*|\/\/|--)/.test(line))
      .join("\n");
    for (const forbidden of [/\bfrom users\b/, /\bfrom memberships\b/, /findPasswordCredential/, /password_hash/]) {
      assert.doesNotMatch(
        code,
        forbidden,
        `${file} reaches for account data (${String(forbidden)}); the limiter must count what was presented, not what exists`,
      );
    }
  }
});

// ---------------------------------------------------------------------------
// What is stored
// ---------------------------------------------------------------------------

test("only a digest is stored, and the column cannot hold an identifier", { skip }, async () => {
  // This table is written by unauthenticated callers, so a plaintext form would
  // be an attacker-populated list of every address anyone ever tried, sitting in
  // the database and in every backup of it.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const account = "alice@acme.example";
    const address = "192.0.2.17";

    await usingScratch(database, async () => {
      await recordAuthAttempt(signInCtx(acme), attempt("login", account, address));
    });

    const stored = await storedBuckets(database, acme.orgId);
    assert.equal(stored.length, 2, "one bucket per dimension");
    for (const bucket of stored) {
      assert.match(bucket.bucket_key, /^[0-9a-f]{64}$/);
    }
    assert.deepEqual(
      stored.map((b) => b.bucket_key).sort(),
      [rateLimitKey(account), rateLimitKey(address)].sort(),
      "the keys should be the digests of what was presented",
    );

    const flattened = JSON.stringify(stored);
    assert.ok(!flattened.includes(account), "the plaintext identifier reached the database");
    assert.ok(!flattened.includes(address), "the plaintext source address reached the database");

    await assert.rejects(
      () =>
        client.query(
          `insert into auth_rate_limits (org_id, dimension, path, bucket_key, window_started_at, expires_at, attempts)
           values ($1, 'account', 'login', $2, now(), now() + interval '1 hour', 1)`,
          [acme.orgId, account],
        ),
      /auth_rate_limits_key_shape/,
      "storing a plaintext identifier must violate a constraint, not merely a convention",
    );
  });
});

test("the paths and dimensions TypeScript knows are exactly the ones the schema accepts", { skip }, async () => {
  // A mirror that can drift is worse than no mirror, so it is read back out of
  // the database rather than trusted — the pattern grant_expiry.test.ts and
  // session_fixation.test.ts already use for their vocabularies.
  await withMigratedDatabase(async (client) => {
    const definitions = await client.query<{ conname: string; definition: string }>(
      `select conname, pg_get_constraintdef(oid) as definition
         from pg_constraint
        where conrelid = 'auth_rate_limits'::regclass
          and conname in ('auth_rate_limits_path', 'auth_rate_limits_dimension')`,
    );
    const byName = new Map(definitions.rows.map((r) => [r.conname, r.definition]));

    const paths = byName.get("auth_rate_limits_path") ?? "";
    for (const path of AUTH_PATHS) {
      assert.match(paths, new RegExp(`'${path}'`), `the schema does not accept the path "${path}"`);
    }
    assert.equal(
      paths.match(/'[a-z-]+'::text/g)?.length,
      AUTH_PATHS.length,
      "the schema accepts a path TypeScript does not know about",
    );

    const dimensions = byName.get("auth_rate_limits_dimension") ?? "";
    for (const dimension of RATE_LIMIT_DIMENSIONS) {
      assert.match(dimensions, new RegExp(`'${dimension}'`), `the schema does not accept "${dimension}"`);
    }
    assert.equal(
      dimensions.match(/'[a-z-]+'::text/g)?.length,
      RATE_LIMIT_DIMENSIONS.length,
      "the schema accepts a dimension TypeScript does not know about",
    );
  });
});

// ---------------------------------------------------------------------------
// The clock — a window boundary is an expiry (ADR 0012)
// ---------------------------------------------------------------------------

test("a window ends mid-transaction the moment it expires", { skip }, async () => {
  // The same shape as the session expiry test, because it is the same question.
  // One transaction is held open across the window boundary; between the two
  // reads the only statements issued are the reads themselves. The answer
  // changes because time passed.
  //
  // It also pins the clock. `now()` is frozen for the life of a transaction, so
  // the test asserts `now()` has NOT moved while the answer flipped: with `now()`
  // as the clock this test could not pass, and a limit would outlive its window
  // for as long as a transaction ran.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const key = rateLimitKey("alice@acme.example");

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const opened = await app.query<{ txn: string }>("select now()::text as txn");
      const txnClock = opened.rows[0]?.txn ?? "";

      // Written from the migration connection while the reader's transaction is
      // open, which is how a bucket is created in production too: by another
      // request, on another connection.
      await client.query(
        `insert into auth_rate_limits (org_id, dimension, path, bucket_key, window_started_at, expires_at, attempts)
         values ($1, 'account', 'login', $2, now(), now() + interval '700 milliseconds', 9)`,
        [acme.orgId, key],
      );

      const live = `select 1 from auth_rate_limits
                     where bucket_key = $1 and expires_at > statement_timestamp()`;
      assert.equal((await app.query(live, [key])).rows.length, 1, "the window should be live until it ends");

      await sleep(900);

      assert.equal(
        (await app.query(live, [key])).rows.length,
        0,
        "the same question, in the same transaction, must now find nothing",
      );

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
        "and the statement clock is what moved — that is the one the limiter reads",
      );
      await app.query("rollback");
    });
  });
});

test("the counter reads the statement clock, and no job is in the enforcement path", { skip }, async () => {
  // Structural evidence, so the property survives someone "optimising" the
  // window filter into a nightly sweep — which would make a limit outlive its
  // window until the sweep ran.
  await withMigratedDatabase(async (client) => {
    const triggers = await client.query<{ tgname: string }>(
      "select tgname from pg_trigger where tgrelid = 'auth_rate_limits'::regclass and not tgisinternal",
    );
    assert.deepEqual(triggers.rows.map((r) => r.tgname), [], "no trigger may be in the enforcement path");

    const source = readFileSync(join(ROOT, "src", "repo", "rate_limits.ts"), "utf8");
    assert.match(source, /statement_timestamp\(\)/, "the window boundary is judged per statement");
    assert.doesNotMatch(
      source.replace(/^\s*(\*|\/\*|\/\/).*$/gm, ""),
      /\bnow\(\)/,
      "`now()` is frozen for the transaction; a window that ended would still read as live inside a long one",
    );
    assert.doesNotMatch(
      source.replace(/^\s*(\*|\/\*|\/\/).*$/gm, ""),
      /clock_timestamp\(\)/,
      "`clock_timestamp()` would judge the two dimensions of one decision against different instants",
    );
  });
});

// ---------------------------------------------------------------------------
// Tenant isolation, and the residual it implies
// ---------------------------------------------------------------------------

test("a counter is invisible from another tenant and with no tenant bound", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");

    await usingScratch(database, async () => {
      await recordAuthAttempt(signInCtx(acme), attempt("login", "alice@acme.example", "192.0.2.18"));
    });

    await asApplicationRole(database, async (app) => {
      // Nothing bound: the missing-setting case has to fail closed, exactly as
      // migration 4's policies do.
      assert.equal(
        (await app.query("select 1 from auth_rate_limits")).rows.length,
        0,
        "visible with no tenant set",
      );

      await app.query("begin");
      await setTenant(app, globex.orgId);
      assert.equal(
        (await app.query("select 1 from auth_rate_limits")).rows.length,
        0,
        "another tenant's counters are visible",
      );

      // And a write cannot be aimed at another tenant. WITH CHECK, not just
      // USING.
      await assert.rejects(
        () =>
          app.query(
            `insert into auth_rate_limits (org_id, dimension, path, bucket_key, window_started_at, expires_at, attempts)
             values ($1, 'account', 'login', $2, now(), now() + interval '1 hour', 1)`,
            [acme.orgId, rateLimitKey("implant")],
          ),
        /row-level security/i,
      );
      await app.query("rollback");
    });
  });
});

test("spending a budget in one tenant leaves the other tenant's alone", { skip }, async () => {
  // The consequence of note 7 in migration 11, tested so it reads as a decision
  // rather than an accident — and so the residual it implies (an attacker who
  // knows several organization ids gets a budget in each) is visible in the
  // suite rather than only in prose.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const one = attempt("login", "alice@example.com", "192.0.2.19");
    const only = rules(2, 2);

    await usingScratch(database, async () => {
      await attemptTimes(signInCtx(acme), 2, () => one, only);
      assert.equal((await recordAuthAttempt(signInCtx(acme), one, only)).allowed, false);
      assert.equal(
        (await recordAuthAttempt(signInCtx(globex), one, only)).allowed,
        true,
        "counters are per tenant — recorded here because it is a real weakening, not because it is desirable",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Hygiene, which must never be enforcement
// ---------------------------------------------------------------------------

test("pruning removes dead windows and cannot touch a live one", { skip }, async () => {
  // A prune that could delete a live bucket would be a way to lift any limit by
  // calling it in a loop. The predicate is the window having already ended, so
  // it cannot be.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const live = attempt("login", "live@acme.example", "192.0.2.20");
    const dying = attempt("login", "dying@acme.example", "192.0.2.21");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      await attemptTimes(ctx, 2, () => live, rules(2, 2, 60_000));
      await attemptTimes(ctx, 2, () => dying, rules(2, 2, 300));

      assert.equal((await recordAuthAttempt(ctx, live, rules(2, 2, 60_000))).allowed, false);
      await sleep(500);

      assert.equal(await pruneAuthRateLimits(ctx), 2, "the ended window's two buckets should go");
      assert.equal(
        (await recordAuthAttempt(ctx, live, rules(2, 2, 60_000))).allowed,
        false,
        "a live limit must survive a prune — otherwise pruning is a bypass",
      );
    });

    const left = await storedBuckets(database, acme.orgId);
    assert.deepEqual(
      left.map((b) => b.bucket_key).sort(),
      [rateLimitKey("live@acme.example"), rateLimitKey("192.0.2.20")].sort(),
      "only the live buckets should remain",
    );
  });
});

// ---------------------------------------------------------------------------
// check() — consults without spending
// ---------------------------------------------------------------------------

test("checking spends nothing and agrees with what recording would say", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const only = rules(2, 50);
      const one = attempt("login", "alice@acme.example", "192.0.2.22");

      // Nothing recorded yet: no live window has anything to say.
      const fresh = await checkAuthRateLimit(ctx, one, only);
      assert.equal(fresh.allowed, true);
      assert.deepEqual(fresh.counters, [], "a bucket with no live window has nothing to report");

      await attemptTimes(ctx, 2, () => one, only);

      const spent = await checkAuthRateLimit(ctx, one, only);
      assert.equal(spent.allowed, false, "the budget is spent, and checking should say so");
      assert.equal(spent.refusedBy, "account");

      // Checking twice must not have moved anything: a gate that consumed
      // budget could refuse a request it was only asked about.
      assert.equal((await checkAuthRateLimit(ctx, one, only)).allowed, false);
      const stored = await storedBuckets(database, acme.orgId);
      assert.deepEqual(
        stored.map((b) => b.attempts),
        [2, 2],
        "checking consumed budget",
      );
    });
  });
});
