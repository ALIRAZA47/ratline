/**
 * Migration cycle against a real Postgres (RL-M1-003, acceptance 2).
 *
 * Brief §6.7 forbids mocking anything that touches infrastructure, and §9 lists
 * "a migration that can't be rolled back" as an anti-pattern. Asserting that a
 * down section exists is a parser check; the only way to know a rollback works
 * is to apply every migration, reverse it, and apply it again. A down path that
 * drops the wrong object or leaves a type, extension or sequence behind passes
 * the first up and fails the second.
 *
 * Each test runs in its own scratch schema so a failure cannot leave debris
 * that makes the next run pass or fail for the wrong reason.
 *
 * Skipping: when DATABASE_URL is set — which CI always does — an unreachable
 * database is a failure, never a skip, so integration coverage cannot quietly
 * evaporate. Only a developer with no local database gets a skip, with a
 * message telling them how to start one.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "pg";

import {
  loadMigrations,
  migrateDown,
  migrateUp,
  migrationStatus,
  type SqlClient,
} from "../../src/db/migrate.ts";

const EXPLICIT_URL = process.env["DATABASE_URL"];
const URL = EXPLICIT_URL ?? "postgres://ratline@127.0.0.1:55432/ratline_test";

async function reachable(): Promise<boolean> {
  const client = new Client({ connectionString: URL, connectionTimeoutMillis: 3000 });
  try {
    await client.connect();
    await client.end();
    return true;
  } catch {
    return false;
  }
}

const available = await reachable();
if (!available && EXPLICIT_URL !== undefined) {
  throw new Error(
    `DATABASE_URL is set to ${EXPLICIT_URL} but the database is unreachable. ` +
      `Refusing to skip: an integration suite that silently skips is worse than one that fails.`,
  );
}
const skip = available ? false : "no database — run ./scripts/pg start, or set DATABASE_URL";

/** Run against an isolated schema, dropped afterwards whatever happens. */
async function withSchema(fn: (client: SqlClient) => Promise<void>): Promise<void> {
  const name = `mig_${process.hrtime.bigint().toString(36)}`;
  const client = new Client({ connectionString: URL });
  await client.connect();
  try {
    await client.query(`create schema "${name}"`);
    await client.query(`set search_path to "${name}"`);
    await fn(client);
  } finally {
    // CASCADE is correct here and only here: the scratch schema is ours, we
    // created everything in it, and leaving debris would corrupt later runs.
    await client.query(`drop schema if exists "${name}" cascade`);
    await client.end();
  }
}

test("every migration applies, reverses, and applies again", { skip }, async () => {
  const migrations = loadMigrations();
  await withSchema(async (client) => {
    const up1 = await migrateUp(client, migrations);
    assert.equal(up1.length, migrations.length, "first up should apply everything");

    const down = await migrateDown(client, migrations, migrations.length);
    assert.equal(down.length, migrations.length, "down should reverse everything");

    const stillApplied = (await migrationStatus(client, migrations)).filter((r) => r.applied);
    assert.deepEqual(stillApplied, [], "nothing should remain recorded as applied");

    // The second up is the real assertion. If a down left an object behind,
    // this is where it surfaces — as a duplicate-object error, not a silent pass.
    const up2 = await migrateUp(client, migrations);
    assert.equal(up2.length, migrations.length, "a down path did not fully reverse its migration");
  });
});

test("re-running up is a no-op rather than an error", { skip }, async () => {
  const migrations = loadMigrations();
  await withSchema(async (client) => {
    await migrateUp(client, migrations);
    const again = await migrateUp(client, migrations);
    assert.deepEqual(again, [], "migrations must be idempotent (brief §6.7)");
  });
});

test("a failing migration leaves no partial state", { skip }, async () => {
  // The bookkeeping row and the schema change commit together. If they could
  // commit separately, a crash between them would leave a migration applied but
  // recorded as pending, and the next run would apply it twice.
  const broken = [
    {
      id: "20990101000001_broken",
      file: "20990101000001_broken.sql",
      up: "create table will_not_exist (id int); select this_function_does_not_exist();",
      down: "drop table if exists will_not_exist;",
      checksum: "deadbeefdeadbeef",
    },
  ];
  await withSchema(async (client) => {
    await assert.rejects(() => migrateUp(client, broken));
    const applied = (await migrationStatus(client, broken)).filter((r) => r.applied);
    assert.deepEqual(applied, [], "a failed migration must not be recorded as applied");

    const result = await client.query(
      "select 1 from information_schema.tables where table_name = 'will_not_exist'",
    );
    assert.equal(result.rows.length, 0, "the failed migration's table must have been rolled back");
  });
});

test("an applied migration edited afterwards is refused", { skip }, async () => {
  const migrations = loadMigrations();
  const first = migrations[0];
  assert.ok(first !== undefined, "there should be at least one migration");

  await withSchema(async (client) => {
    await migrateUp(client, [first]);
    const tampered = { ...first, checksum: "0000000000000000" };
    await assert.rejects(
      () => migrateUp(client, [tampered]),
      /contents changed/,
      "the database and the repository disagreeing must stop the deploy",
    );
  });
});
