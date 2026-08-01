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

let counter = 0;

/**
 * Create a scratch database, run `fn` against it, drop it afterwards whatever
 * happens. Migrations are NOT applied — use {@link withMigratedDatabase} for
 * that; this one exists so the migration cycle itself can be tested.
 */
export async function withScratchDatabase(
  fn: (client: Client & SqlClient, name: string) => Promise<void>,
): Promise<void> {
  const name = `rl_t_${process.hrtime.bigint().toString(36)}_${counter++}`;
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
  fn: (client: Client & SqlClient) => Promise<void>,
): Promise<void> {
  await withScratchDatabase(async (client) => {
    await migrateUp(client, loadMigrations());
    await fn(client);
  });
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
