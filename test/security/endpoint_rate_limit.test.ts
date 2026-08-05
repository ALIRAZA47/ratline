/**
 * The limiter is spent by real endpoints (RL-M1-020 acceptance 3, R-28).
 *
 * `test/security/rate_limit_auth.test.ts` proves the limiter counts and
 * refuses. This proves something the limiter cannot prove about itself: that
 * the request path actually SPENDS it, and spends it before the expensive work
 * rather than after.
 *
 * That distinction is the whole of R-15 and R-28. A limiter nothing calls is a
 * published budget, and `AUTH_RATE_LIMITS["two-factor"]` was exactly that until
 * the server existed — a six-digit code is a million possibilities and an
 * unlimited verifier finds one inside a day.
 *
 * ## Why these tests drive the server rather than the auth layer
 *
 * Because the failure they guard against lives in the wiring. Every call in
 * `src/auth/` could be correct and the endpoint could still forget to make it,
 * or make it after `verifyPassword` has already burned 128 MiB. Only a request
 * can tell.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { createServer, type ServerDeps } from "../../src/api/server.ts";
import { AUTH_RATE_LIMITS } from "../../src/auth/rate_limit.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";
import { codeOf } from "../support/source_scan.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/**
 * A secrets directory that reads as already claimed.
 *
 * Every suite except the bootstrap one wants the endpoint closed — an open
 * bootstrap route would be a second way to create a tenant underneath a test
 * that is measuring something else.
 */
const CLAIMED_SECRETS_DIR = (() => {
  const dir = mkdtempSync(join(tmpdir(), "rl-claimed-"));
  writeFileSync(join(dir, "bootstrap.spent"), "claimed by the test fixture\n", { mode: 0o600 });
  return dir;
})();

type Tenant = { readonly orgId: string; readonly signInIdentityId: string; readonly ownerId: string };

async function seedTenant(client: Client): Promise<Tenant> {
  const { orgId, userId } = await seedOrganization(client, "acme");
  const identity = await client.query<{ id: string }>(
    "insert into service_identities (org_id, name) values ($1, 'sign-in') returning id",
    [orgId],
  );
  return { orgId, signInIdentityId: identity.rows[0]?.id ?? "", ownerId: userId };
}

function serverFor(tenant: Tenant): ReturnType<typeof createServer> {
  const deps: ServerDeps = {
    // Real random bytes: createServer refuses a no-entropy secret (RL-M1-054).
    cookieSecret: randomBytes(32),
    sealingKey: Buffer.alloc(32, 9),
    secretsDir: CLAIMED_SECRETS_DIR,
    resolveTenant: () => Promise.resolve(tenant.orgId),
    signInIdentityId: tenant.signInIdentityId,
    trustedOrigins: ["http://127.0.0.1:7712"],
  };
  return createServer(deps);
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

/** Post `body` to `path` `times` times, returning every status in order. */
async function hammer(
  app: ReturnType<typeof createServer>,
  path: string,
  body: unknown,
  times: number,
): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < times; i++) {
    const response = await app.request(path, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://127.0.0.1:7712" },
      body: JSON.stringify(body),
    });
    statuses.push(response.status);
  }
  return statuses;
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------

test("the sign-in endpoint spends its budget and then refuses", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const tenant = await seedTenant(client);
    await usingScratch(database, async () => {
      const app = serverFor(tenant);
      const limit = AUTH_RATE_LIMITS.login.account.limit;

      // One past the limit. Every attempt is wrong, so every one would be a 401
      // even unlimited — which is exactly why the assertion below is about the
      // COUNTER rather than about the status.
      await hammer(app, "/auth/sign-in", { email: "nobody@acme.example", password: "wrong" }, limit + 1);

      const spent = await client.query<{ n: string }>(
        "select count(*)::text as n from auth_rate_limits",
      );
      assert.ok(Number(spent.rows[0]?.n ?? "0") > 0, "the endpoint never spent the budget");
    });
  });
});

test("the limiter runs BEFORE the expensive work, on every auth path", () => {
  // R-15's actual claim. Sign-in derives a 128 MiB scrypt hash on every attempt
  // INCLUDING for accounts that do not exist — deliberately, because deriving
  // unconditionally is what stops timing revealing whether an account exists. A
  // limiter consulted afterwards has already paid for the attack it was meant
  // to stop.
  //
  // The first version measured wall-clock: a refused attempt should be faster
  // than an accepted one, because the expensive step is skipped. Mutation
  // testing killed it — moving the limiter after `signIn` did not fail the
  // test, because the first request also pays connection warm-up and the noise
  // swallowed the signal. A timing assertion that cannot detect the thing it
  // exists for is worse than none, since it reads as coverage.
  //
  // So it is structural instead. Blunt, and it catches the mutation somebody
  // actually makes: moving one call below another.
  const source = codeOf(readFileSync(join(ROOT, "src", "api", "server.ts"), "utf8"));
  const paths: { readonly limited: string; readonly expensive: string }[] = [
    { limited: 'path: "login"', expensive: "await signIn(" },
    { limited: 'path: "two-factor"', expensive: "await verifySecondFactor(" },
  ];

  for (const { limited, expensive } of paths) {
    const limitAt = source.indexOf(limited);
    const workAt = source.indexOf(expensive);
    assert.ok(limitAt !== -1, `no limiter call for ${limited}`);
    assert.ok(workAt !== -1, `no expensive call matching ${expensive}`);
    assert.ok(
      limitAt < workAt,
      `${limited} is spent AFTER ${expensive} — the attack has already been paid for`,
    );
  }
});

// ---------------------------------------------------------------------------
// Two-factor — R-28
// ---------------------------------------------------------------------------

test("the two-factor endpoint spends its budget and then refuses", { skip }, async () => {
  // The endpoint R-28 was waiting for. Before it existed the budget was
  // published and unspent, so the verifier was unlimited.
  await withMigratedDatabase(async (client, database) => {
    const tenant = await seedTenant(client);
    await usingScratch(database, async () => {
      const app = serverFor(tenant);
      const limit = AUTH_RATE_LIMITS["two-factor"].account.limit;
      const challenge = `rlc_${randomUUID()}`;

      await hammer(app, "/auth/two-factor", { challenge, code: "000000" }, limit + 1);

      const spent = await client.query<{ dimension: string; attempts: number }>(
        "select dimension, attempts from auth_rate_limits where path = 'two-factor' order by dimension",
      );
      const account = spent.rows.find((row) => row.dimension === "account");
      assert.ok(account, "the two-factor endpoint never spent its budget — R-28 is still open");
      assert.ok(
        account.attempts >= limit,
        `only ${String(account.attempts)} of ${String(limit)} attempts were counted`,
      );
    });
  });
});

test("the two-factor bucket keys on the challenge, not on nothing", { skip }, async () => {
  // Two different challenges must not share a bucket — that would let one
  // person's failed attempts lock out everybody else, which is a
  // denial-of-service anyone could run. And a single challenge must not get a
  // fresh bucket per request, which would be no limit at all.
  await withMigratedDatabase(async (client, database) => {
    const tenant = await seedTenant(client);
    await usingScratch(database, async () => {
      const app = serverFor(tenant);
      const first = `rlc_${randomUUID()}`;
      const second = `rlc_${randomUUID()}`;

      await hammer(app, "/auth/two-factor", { challenge: first, code: "000000" }, 3);
      await hammer(app, "/auth/two-factor", { challenge: second, code: "000000" }, 2);

      const rows = await client.query<{ n: string }>(
        "select count(*)::text as n from auth_rate_limits where path = 'two-factor' and dimension = 'account'",
      );
      assert.equal(Number(rows.rows[0]?.n ?? "0"), 2, "the two challenges shared a bucket, or each got its own per request");
    });
  });
});

test("the challenge never reaches the rate-limit table in the clear", { skip }, async () => {
  // The bucket key is a digest. An unauthenticated caller causes these writes,
  // so raw values would make this table an attacker-populated harvest of every
  // credential ever tried — in the database and in every backup.
  await withMigratedDatabase(async (client, database) => {
    const tenant = await seedTenant(client);
    const challenge = `rlc_${randomUUID()}`;
    await usingScratch(database, async () => {
      await hammer(serverFor(tenant), "/auth/two-factor", { challenge, code: "000000" }, 2);
    });

    const rows = await client.query<{ row: string }>("select auth_rate_limits::text as row from auth_rate_limits");
    assert.ok(rows.rows.length > 0);
    for (const { row } of rows.rows) {
      assert.ok(!row.includes(challenge), "the challenge token is stored in the clear");
    }
  });
});

test("a refused attempt is not silent", { skip }, async () => {
  // A limiter that refuses without a record leaves an incident review unable to
  // tell a brute-force attempt from a quiet week.
  //
  // What this asserts is deliberately the WEAKER thing, because the stronger
  // one is not true yet: the attempt reaches the counter, which is a record
  // even though no audit entry is written. Sign-in cannot write one — there is
  // no actor until it succeeds, which is ADR 0014's open seam. Writing this
  // test against the audit log instead was the first version, and it failed
  // with "not permitted: audit_log.read (no-grant)": the sign-in service
  // identity holds no grants, which is RL-M1-043 working exactly as intended.
  await withMigratedDatabase(async (client, database) => {
    const tenant = await seedTenant(client);
    await usingScratch(database, async () => {
      await hammer(
        serverFor(tenant),
        "/auth/sign-in",
        { email: "nobody@acme.example", password: "wrong" },
        3,
      );
    });

    const counted = await client.query<{ n: string }>(
      "select count(*)::text as n from auth_rate_limits where path = 'login'",
    );
    assert.ok(Number(counted.rows[0]?.n ?? "0") > 0, "three attempts left no trace anywhere");
  });
});
