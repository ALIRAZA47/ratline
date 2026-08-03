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

import {
  loadMigrations,
  migrateDown,
  migrateUp,
  migrationStatus,
} from "../../src/db/migrate.ts";
import { skipWithoutDatabase, withScratchDatabase } from "../support/db.ts";

const skip = skipWithoutDatabase;

test("every migration applies, reverses, and applies again", { skip }, async () => {
  const migrations = loadMigrations();
  await withScratchDatabase(async (client) => {
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
  await withScratchDatabase(async (client) => {
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
  await withScratchDatabase(async (client) => {
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

  await withScratchDatabase(async (client) => {
    await migrateUp(client, [first]);
    const tampered = { ...first, checksum: "0000000000000000" };
    await assert.rejects(
      () => migrateUp(client, [tampered]),
      /contents changed/,
      "the database and the repository disagreeing must stop the deploy",
    );
  });
});
