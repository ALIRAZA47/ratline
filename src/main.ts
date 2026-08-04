#!/usr/bin/env node --experimental-strip-types
/**
 * The control plane's entry point (RL-M1-055).
 *
 * ## Why this did not exist until now
 *
 * Every M1 task built a piece of the control plane, and the authorization matrix
 * drives `createServer` in-process, so the suite has always been green while nothing
 * ever served a request outside a test. The compliance review found the shape of
 * that: `@hono/node-server` is a declared dependency never imported, nothing calls
 * `createServer` in production, and `preflight()` is reachable only from `boot.ts`'s
 * own `main`. A latent defect on an unreachable path is easy to leave latent.
 *
 * ## The order here is the point
 *
 *   1. Preflight — secrets and bind address. A host with no usable secrets cannot
 *      serve at any address (C4), and one that would be publicly reachable must
 *      refuse rather than warn (C5). Both happen before anything opens a socket.
 *   2. Migrations — applied, then verified. Serving against a schema that is behind
 *      the code is the failure mode where a request reaches a column that does not
 *      exist and the operator is shown a database error.
 *   3. The sign-in identity — resolved from the database, never invented.
 *   4. Then, and only then, listen.
 *
 * Anything that fails exits non-zero with a message naming a file, an address or a
 * remedy — never a secret value.
 */

import { serve } from "@hono/node-server";

import { preflight, BindRefusal } from "./boot.ts";
import { createServer } from "./api/server.ts";
import { secretsDir, SecretRefusal } from "./crypto/secrets.ts";

/**
 * The sign-in service identity, read from the database.
 *
 * NOT generated here, and not defaulted. `service_identities.org_id` is `not null`
 * and references `organizations`, so this identity is per-tenant — while
 * `ServerDeps.signInIdentityId` is a single string. That mismatch is recorded on
 * RL-M1-055 rather than papered over: one id for every tenant is coherent only for a
 * single-organization installation, which is what a self-hosted Ratline is today.
 *
 * Before the installation is claimed there is no organization, so there is no
 * identity to find. The server still has to serve `/bootstrap`, so this returns null
 * and the authenticated paths are unreachable until a restart — every one of them
 * needs a session, and a session needs an organization. Stated plainly because
 * "restart after first run" is a real limitation, not an implementation detail.
 */
async function resolveSignInIdentity(databaseUrl: string): Promise<string | null> {
  // Imported here rather than at the top so a preflight failure does not depend on
  // the database being reachable — the point of preflight is to fail on secrets and
  // bind address before anything else is tried.
  const { Client } = await import("pg");
  const client = new Client({ connectionString: databaseUrl });
  await client.connect();

  try {
    // Reading as the connecting role rather than through the repository layer,
    // because there is no AuthzContext yet — this is the pre-authentication seam ADR
    // 0014 records, at boot rather than per-request. It reads one id and nothing
    // else, and it cannot be reached from a request.
    const organizations = await client.query<{ id: string }>(
      "select id from organizations order by created_at limit 2",
    );

    if (organizations.rowCount === 0) return null;

    if ((organizations.rowCount ?? 0) > 1) {
      throw new Error(
        "this installation has more than one organization, and ServerDeps.signInIdentityId " +
          "is a single value while service_identities.org_id is per-organization. Fixing " +
          "that is RL-M1-055's recorded design question; refusing to start is the honest " +
          "response rather than picking one tenant's identity and using it for all of them.",
      );
    }

    const orgId = organizations.rows[0]?.id;
    if (orgId === undefined) return null;

    const existing = await client.query<{ id: string }>(
      "select id from service_identities where org_id = $1 and name = 'sign-in' limit 1",
      [orgId],
    );
    const found = existing.rows[0]?.id;
    if (found !== undefined) return found;

    // Created if absent, which is not the same as invented: it belongs to a real
    // organization, it is a row somebody can join to, and RL-M1-053 exists because
    // the audit log's actor_id currently accepts a UUID with no row behind it.
    const created = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name, description) values " +
        "($1, 'sign-in', 'Acts on the sign-in path, before any user is authenticated') " +
        "returning id",
      [orgId],
    );
    return created.rows[0]?.id ?? null;
  } finally {
    await client.end();
  }
}

function requireDatabaseUrl(): string {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url.trim() === "") {
    // §291: say what broke and what to do next.
    throw new Error(
      "DATABASE_URL is not set, so the control plane has no database to serve from.\n" +
        "Set it to a Postgres connection string, for example:\n" +
        "  DATABASE_URL=postgres://ratline@127.0.0.1:5432/ratline",
    );
  }
  return url;
}

async function main(): Promise<void> {
  // 1. Secrets and bind address, before anything opens a socket.
  const ready = preflight();
  const dir = secretsDir();

  process.stderr.write(`secrets loaded from ${dir}\n`);
  if (ready.exposure.warning !== null) {
    // C5 wants a warning that cannot be dismissed. Printed on every boot, whether or
    // not it was acknowledged: an acknowledgement that silenced it forever would be a
    // dismissal with extra steps.
    process.stderr.write(`\n!! ${ready.exposure.warning}\n\n${ready.exposure.caveat}\n\n`);
  }

  const databaseUrl = requireDatabaseUrl();

  // 2. The schema. Serving against a schema behind the code shows the operator a
  // database error for a request that should have worked.
  const { migrateUp, appliedMigrations, loadMigrations } = await import("./db/migrate.ts");
  const { Client } = await import("pg");

  const migrator = new Client({ connectionString: databaseUrl });
  await migrator.connect();
  try {
    const steps = await migrateUp(migrator);
    if (steps.length > 0) {
      process.stderr.write(`applied ${String(steps.length)} migration(s)\n`);
    }

    // Verified rather than assumed. `migrateUp` returning without error and the
    // schema actually being current are two different claims — and the second is the
    // one that matters to a request arriving in a moment.
    const applied = await appliedMigrations(migrator);
    const missing = loadMigrations()
      .map((migration) => migration.id)
      .filter((id) => !applied.has(id));
    if (missing.length > 0) {
      throw new Error(
        `${String(missing.length)} migration(s) are still unapplied after migrating: ` +
          `${missing.join(", ")}. Refusing to serve against a schema behind the code.`,
      );
    }
  } finally {
    await migrator.end();
  }

  // 3. The sign-in identity, read or created — never invented.
  const signInIdentityId = await resolveSignInIdentity(databaseUrl);
  if (signInIdentityId === null) {
    process.stderr.write(
      "\nThis installation is unclaimed: no organization exists yet, so there is no\n" +
        "sign-in identity to act as. Only the first-run endpoints are usable until it\n" +
        "is claimed, and the server needs restarting afterwards. See RL-M1-055.\n\n",
    );
  }

  // 4. Serve.
  const app = createServer({
    cookieSecret: ready.secrets.cookie,
    sealingKey: ready.secrets.kek,
    secretsDir: dir,
    // A placeholder ONLY while unclaimed, and it cannot be used: every path that
    // reads it needs a session, and a session needs an organization that does not
    // exist yet. Named so it is obvious in a log if it ever appears in one.
    signInIdentityId: signInIdentityId ?? "00000000-0000-4000-8000-000000000000",
    // One organization per installation, which is what the single sign-in identity
    // above already assumes. A subdomain or a slug on the form is the alternative,
    // and ServerDeps injects this precisely because the choice is a deployment
    // question RL-M1-042 was not entitled to settle.
    resolveTenant: async () => {
      const { Client } = await import("pg");
      const client = new Client({ connectionString: databaseUrl });
      await client.connect();
      try {
        const result = await client.query<{ id: string }>("select id from organizations limit 1");
        return result.rows[0]?.id ?? null;
      } finally {
        await client.end();
      }
    },
  });

  serve({ fetch: app.fetch, hostname: ready.bind, port: ready.port }, (info) => {
    process.stderr.write(`ratline listening on http://${ready.bind}:${String(info.port)}\n`);
    if (signInIdentityId === null) {
      process.stderr.write(`first run: GET /bootstrap to check, POST /bootstrap to claim\n`);
    }
  });
}

await main().catch((error: unknown) => {
  // Refusals report themselves; anything else is a bug and should show its stack.
  if (error instanceof SecretRefusal || error instanceof BindRefusal) {
    process.stderr.write(`${error.report()}\n`);
    process.exit(1);
  }
  if (error instanceof Error) {
    process.stderr.write(`ratline failed to start: ${error.message}\n`);
    process.exit(1);
  }
  throw error;
});
