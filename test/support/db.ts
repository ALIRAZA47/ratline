/**
 * Shared database plumbing for tests that need a real Postgres.
 *
 * Skip policy, deliberately asymmetric:
 *
 *   - DATABASE_URL set (which CI always does) and unreachable  -> throw.
 *   - DATABASE_URL unset and no local cluster                  -> skip.
 *
 * A suite that silently skips is worse than one that fails, because the summary
 * still reads green. So the only thing that can skip is a developer's laptop
 * with no database, and it gets told how to start one.
 *
 * Isolation is a scratch DATABASE, not a scratch schema. Schemas look cheaper
 * and are wrong here: an extension is installed once per database, so
 * `create extension if not exists citext` silently no-ops for the second schema
 * and the type is then invisible to it. Anything a migration can create that is
 * database-scoped — extensions, event triggers, roles — has the same problem.
 * Per-database costs ~100ms and is actually isolated.
 */

import { randomUUID } from "node:crypto";
import { Client } from "pg";

import { loadMigrations, migrateUp, type SqlClient } from "../../src/db/migrate.ts";

const EXPLICIT_URL = process.env["DATABASE_URL"];
export const DATABASE_URL = EXPLICIT_URL ?? "postgres://ratline@127.0.0.1:55432/ratline_test";

/** Same server, different database. */
function urlFor(database: string): string {
  const url = new URL(DATABASE_URL);
  url.pathname = `/${database}`;
  return url.toString();
}

async function probe(): Promise<boolean> {
  const client = new Client({ connectionString: DATABASE_URL, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    await client.end();
    return true;
  } catch {
    return false;
  }
}

const available = await probe();

if (!available && EXPLICIT_URL !== undefined) {
  throw new Error(
    `DATABASE_URL is set to ${EXPLICIT_URL} but the database is unreachable. ` +
      `Refusing to skip: an integration suite that silently skips still reads green.`,
  );
}

/** Pass as node:test's `skip` option. `false` when a database is available. */
export const skipWithoutDatabase: false | string = available
  ? false
  : "no database — run ./scripts/pg start, or set DATABASE_URL";

// Before any test runs, so a file that connects as `ratline_app` directly does
// not depend on some other file having gone first. Awaited at module scope: the
// suites are the only consumer, and a race between this and the first
// connection is exactly the bug being closed.
let loginEnabled: Promise<void> | null = null;

/**
 * The migration creates `ratline_app` as NOLOGIN on purpose: a login role
 * created automatically with no password would be precisely the default
 * credential C4 forbids, so enabling login is a deployment act.
 *
 * Tests are a deployment of a sort, and this is their equivalent of that step —
 * cluster-scoped, idempotent, and done once per process rather than per test.
 *
 * ## Why it now runs at module load rather than only from asApplicationRole
 *
 * `alter role` is CLUSTER-PERSISTENT, and that made this a latent defect the
 * suite carried for a dozen sessions without noticing. Some early test enabled
 * login on the development cluster once; every test written afterwards that
 * connected as `ratline_app` by building its own URL — rather than going through
 * `asApplicationRole` — worked because of that leftover state, not because it
 * arranged anything.
 *
 * The first CI run against a FRESH cluster failed twelve of them with
 * `role "ratline_app" is not permitted to log in`. Locally they had been green
 * for the wrong reason: passing because a previous run had mutated the cluster.
 *
 * So it runs once per process from `withMigratedDatabase`, immediately after the
 * migrations — because the migrations are what CREATE the role.
 *
 * Doing it at module load was the first attempt and was worse than the bug it
 * fixed: on a fresh cluster the role does not exist yet, `alter role` threw
 * during import, and every file importing this one failed to LOAD. CI reported
 * 236 of 259 rather than 598 — three hundred tests silently not running, which
 * is the exact failure shape this file is written against. It passed locally
 * only because the role was already there.
 */
async function ensureApplicationRoleCanLogIn(): Promise<void> {
  loginEnabled ??= (async () => {
    const admin = new Client({ connectionString: urlFor("postgres") });
    await admin.connect();
    try {
      await admin.query("alter role ratline_app login");
    } finally {
      await admin.end();
    }
  })();
  await loginEnabled;
}



let counter = 0;

/**
 * A name no other process can generate (RL-M1-045).
 *
 * The first version was `rl_t_${process.hrtime.bigint().toString(36)}_${counter++}`
 * and it produced a real, reproducible flake: roughly one full-suite run in
 * three failed somewhere with `terminating connection due to administrator
 * command`.
 *
 * `process.hrtime.bigint()` is monotonic since BOOT and shared across
 * processes, and `counter` restarts at zero in each one — so two test files
 * that reached this line in the same nanosecond got the same database name.
 * `node --test` starts a batch of file processes together, which is exactly the
 * condition that makes that collision reachable.
 *
 * What turned a collision into a failure is `with (force)` on the drop below.
 * It was added so a leaked connection could not wedge the drop and leak a
 * database into the next run — a good reason — and it means the loser of a
 * collision does not get a harmless "already exists", it gets its connections
 * terminated mid-test. The two decisions are individually right and were
 * jointly a landmine.
 *
 * `randomUUID` rather than the pid: pids are reused, and a rerun that landed on
 * a recycled pid at the same nanosecond would be back where it started.
 */
function scratchName(): string {
  return `rl_t_${randomUUID().replaceAll("-", "").slice(0, 16)}_${counter++}`;
}

/**
 * Create a scratch database, run `fn` against it, drop it afterwards whatever
 * happens. Migrations are NOT applied — use {@link withMigratedDatabase} for
 * that; this one exists so the migration cycle itself can be tested.
 */
export async function withScratchDatabase(
  fn: (client: Client & SqlClient, name: string) => Promise<void>,
): Promise<void> {
  const name = scratchName();
  const admin = new Client({ connectionString: urlFor("postgres") });
  await admin.connect();

  try {
    // Identifier is generated here, never user input, and is quoted regardless.
    await admin.query(`create database "${name}"`);
  } catch (cause) {
    await admin.end();
    throw cause;
  }

  const client = new Client({ connectionString: urlFor(name) });
  try {
    await client.connect();
    await fn(client, name);
  } finally {
    await client.end().catch(() => undefined);
    // FORCE disconnects anything still attached, so one leaked connection
    // cannot wedge the drop and leak a database into the next run.
    await admin.query(`drop database if exists "${name}" with (force)`);
    await admin.end();
  }
}

/** A scratch database with every migration applied. */
export async function withMigratedDatabase(
  fn: (client: Client & SqlClient, database: string) => Promise<void>,
): Promise<void> {
  await withScratchDatabase(async (client, name) => {
    await migrateUp(client, loadMigrations());
    // AFTER migrating, because migration 2 is what CREATES `ratline_app`, and
    // once per process because `alter role` is cluster-wide. Here rather than
    // only in asApplicationRole so a test that builds its own ratline_app URL
    // — as several do — cannot depend on another file having gone first.
    await ensureApplicationRoleCanLogIn();
    await fn(client, name);
  });
}


/**
 * Open a second connection to the same scratch database as `ratline_app` — the
 * unprivileged, NOBYPASSRLS role the application connects as in production.
 *
 * This exists because a superuser bypasses row-level security unconditionally,
 * whatever the policies say. The development role created by `initdb` IS a
 * superuser, so an RLS test that reused the migration connection would pass
 * without exercising a single policy: a test that cannot fail. Every assertion
 * about tenant isolation has to come through here.
 */
export async function asApplicationRole<T>(
  database: string,
  fn: (client: Client & SqlClient) => Promise<T>,
): Promise<T> {
  await ensureApplicationRoleCanLogIn();
  const url = new URL(urlFor(database));
  url.username = "ratline_app";
  url.password = "";
  const client = new Client({ connectionString: url.toString() });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

/** Set the tenant for the current transaction, the way the repository layer will. */
export async function setTenant(client: Client, orgId: string | null): Promise<void> {
  // set_config's third argument scopes it to the transaction, so a pooled
  // connection cannot carry a tenant into the next request.
  await client.query("select set_config('ratline.org_id', $1, true)", [orgId ?? ""]);
}

/** An organization with one owner — the minimum valid tenant. */
export async function seedOrganization(
  client: Client,
  slug = "acme",
): Promise<{ orgId: string; userId: string; grantId: string }> {
  const org = await client.query<{ id: string }>(
    "insert into organizations (slug, name) values ($1, $2) returning id",
    [slug, "Acme"],
  );
  const user = await client.query<{ id: string }>(
    "insert into users (email, name) values ($1, $2) returning id",
    [`owner@${slug}.example`, "Owner"],
  );
  const orgId = org.rows[0]?.id ?? "";
  const userId = user.rows[0]?.id ?? "";

  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);
  const grant = await client.query<{ id: string }>(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, 'owner', 'organization') returning id`,
    [orgId, userId],
  );
  return { orgId, userId, grantId: grant.rows[0]?.id ?? "" };
}
