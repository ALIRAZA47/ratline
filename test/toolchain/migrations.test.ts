/**
 * Migration tooling (RL-M1-003).
 *
 * Brief §9 lists "a migration that can't be rolled back" as an anti-pattern, so
 * these tests are mostly about what the parser *refuses*. The up/down/up cycle
 * against a real database lives in test/integration/migrations_cycle.test.ts,
 * because asserting a down path exists is not the same as knowing it works.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  loadMigrations,
  migrateDown,
  migrateUp,
  MigrationError,
  MIGRATIONS_DIR,
  parseMigration,
  type Migration,
  type SqlClient,
} from "../../src/db/migrate.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const NAME = "20260101000001_example.sql";

test("a well-formed migration parses into up and down", () => {
  const migration = parseMigration(
    NAME,
    "-- migrate:up\ncreate table t (id int);\n\n-- migrate:down\ndrop table t;\n",
  );
  assert.equal(migration.id, "20260101000001_example");
  assert.equal(migration.up, "create table t (id int);");
  assert.equal(migration.down, "drop table t;");
  assert.match(migration.checksum, /^[0-9a-f]{16}$/);
});

test("a migration with no down section is refused", () => {
  assert.throws(
    () => parseMigration(NAME, "-- migrate:up\ncreate table t (id int);\n"),
    (e: unknown) => e instanceof MigrationError && /reversible/.test(e.message),
    "acceptance 3: a migration without a down migration must fail the build",
  );
});

test("a migration with an empty down section is refused", () => {
  // An empty down is worse than a missing one: it silently pretends to work,
  // so a rollback reports success and changes nothing.
  assert.throws(
    () => parseMigration(NAME, "-- migrate:up\ncreate table t (id int);\n\n-- migrate:down\n\n"),
    (e: unknown) => e instanceof MigrationError && /silently pretends/.test(e.message),
  );
});

test("a migration with an empty up section is refused", () => {
  assert.throws(
    () => parseMigration(NAME, "-- migrate:up\n\n-- migrate:down\ndrop table t;\n"),
    (e: unknown) => e instanceof MigrationError && /up section is empty/.test(e.message),
  );
});

test("markers in the wrong order are refused", () => {
  assert.throws(
    () => parseMigration(NAME, "-- migrate:down\ndrop table t;\n\n-- migrate:up\ncreate table t (id int);\n"),
    MigrationError,
  );
});

test("a missing up marker is refused", () => {
  assert.throws(() => parseMigration(NAME, "create table t (id int);\n"), MigrationError);
});

test("badly named migrations are refused", () => {
  const body = "-- migrate:up\nselect 1;\n\n-- migrate:down\nselect 1;\n";
  for (const bad of [
    "example.sql",
    "1_example.sql",
    "20260101000001.sql",
    "20260101000001_Example.sql",
    "20260101000001_example-name.sql",
    "20260101000001_example.txt",
  ]) {
    assert.throws(() => parseMigration(bad, body), MigrationError, `${bad} should be rejected`);
  }
});

test("the checksum covers the up section so an edit after applying is detectable", () => {
  const body = (up: string) => `-- migrate:up\n${up}\n\n-- migrate:down\ndrop table t;\n`;
  const before = parseMigration(NAME, body("create table t (id int);"));
  const after = parseMigration(NAME, body("create table t (id bigint);"));
  assert.notEqual(before.checksum, after.checksum);
});

test("a comment change in the down section does not invalidate an applied migration", () => {
  // The checksum deliberately covers only `up`. Re-checksumming `down` would
  // make fixing a broken rollback look like schema drift and block deploys.
  const with_ = (down: string) => `-- migrate:up\ncreate table t (id int);\n\n-- migrate:down\n${down}\n`;
  assert.equal(
    parseMigration(NAME, with_("drop table t;")).checksum,
    parseMigration(NAME, with_("drop table t; -- fixed")).checksum,
  );
});

// ---------------------------------------------------------------------------
// The migrations actually in the repository
// ---------------------------------------------------------------------------

test("every committed migration parses and has a non-empty down path", () => {
  const migrations = loadMigrations();
  assert.ok(migrations.length > 0, "there should be at least one migration");
  for (const migration of migrations) {
    assert.notEqual(migration.down.trim(), "", `${migration.file} has no down path`);
  }
});

test("committed migrations are uniquely and monotonically ordered", () => {
  const ids = loadMigrations().map((m) => m.id);
  assert.deepEqual([...ids].sort(), ids, "files must sort into application order");
  assert.equal(new Set(ids).size, ids.length, "duplicate migration id");
});

test("no committed migration uses a destructive shortcut", () => {
  // `drop ... cascade` silently removes dependent objects the author may not
  // know about, which makes the down path unreliable in exactly the moment it
  // matters. Flag it here rather than discovering it during a rollback.
  const findings: string[] = [];
  for (const migration of loadMigrations()) {
    const sql = readFileSync(join(MIGRATIONS_DIR, migration.file), "utf8").toLowerCase();
    if (/\bcascade\b/.test(sql)) findings.push(`${migration.file}: uses CASCADE`);
    if (/\bdrop\s+database\b/.test(sql)) findings.push(`${migration.file}: drops a database`);
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

// ---------------------------------------------------------------------------
// Runner decision logic
//
// These use a recording client. That is not mocking the thing under test: the
// subject here is the runner's *decisions* — what it refuses, and whether each
// step is wrapped in a transaction. Whether the SQL itself applies is covered
// by the up/down/up cycle against a real Postgres in CI, which is the only
// place that question can honestly be answered.
// ---------------------------------------------------------------------------

type Recorded = { sql: string; params: readonly unknown[] };

function recordingClient(applied: { id: string; checksum: string }[] = []): {
  client: SqlClient;
  log: Recorded[];
} {
  const log: Recorded[] = [];
  const client: SqlClient = {
    query(sql, params = []) {
      log.push({ sql: sql.trim(), params });
      if (/select id, checksum from schema_migrations/.test(sql)) {
        return Promise.resolve({ rows: applied.map((a) => ({ id: a.id, checksum: a.checksum })) });
      }
      return Promise.resolve({ rows: [] });
    },
  };
  return { client, log };
}

const example = (up: string): Migration =>
  parseMigration(NAME, `-- migrate:up\n${up}\n\n-- migrate:down\ndrop table t;\n`);

test("an already-applied migration whose contents changed is refused", async () => {
  // The database no longer matches the repository, so every later assumption
  // about the schema is unsound. Failing loudly beats applying nothing quietly.
  const migration = example("create table t (id bigint);");
  const { client } = recordingClient([{ id: migration.id, checksum: "0000000000000000" }]);
  await assert.rejects(
    () => migrateUp(client, [migration]),
    (e: unknown) => e instanceof MigrationError && /contents changed/.test(e.message),
  );
});

test("an unchanged applied migration is skipped rather than reapplied", async () => {
  const migration = example("create table t (id int);");
  const { client, log } = recordingClient([{ id: migration.id, checksum: migration.checksum }]);
  const done = await migrateUp(client, [migration]);
  assert.deepEqual(done, []);
  assert.ok(!log.some((r) => r.sql.includes("create table t")));
});

test("each applied migration commits with its bookkeeping row", async () => {
  // If the schema change and the record of it could commit separately, a crash
  // between them leaves a migration applied but marked pending, and the next
  // run applies it twice.
  const migration = example("create table t (id int);");
  const { client, log } = recordingClient();
  await migrateUp(client, [migration]);

  const sequence = log.map((r) => r.sql).filter((s) => /^(begin|commit|rollback)$/.test(s) || /create table t|insert into schema_migrations/.test(s));
  assert.deepEqual(sequence, [
    "begin",
    "create table t (id int);",
    "insert into schema_migrations (id, checksum) values ($1, $2)",
    "commit",
  ]);
});

test("a failing migration rolls back and does not record itself as applied", async () => {
  const migration = example("this is not valid sql;");
  const log: Recorded[] = [];
  const client: SqlClient = {
    query(sql, params = []) {
      log.push({ sql: sql.trim(), params });
      if (sql.includes("not valid sql")) return Promise.reject(new Error("syntax error"));
      return Promise.resolve({ rows: [] });
    },
  };
  await assert.rejects(() => migrateUp(client, [migration]), MigrationError);
  assert.ok(log.some((r) => r.sql === "rollback"), "must roll back");
  assert.ok(!log.some((r) => r.sql.includes("insert into schema_migrations")), "must not record success");
});

test("rolling back a migration missing from the repository is refused", async () => {
  const { client } = recordingClient([{ id: "20250101000001_gone", checksum: "abc" }]);
  await assert.rejects(
    () => migrateDown(client, [], 1),
    (e: unknown) => e instanceof MigrationError && /absent from the repository/.test(e.message),
  );
});

test("rollback happens newest first", async () => {
  const older = parseMigration("20260101000001_a.sql", "-- migrate:up\nselect 1;\n\n-- migrate:down\nselect 'down-a';\n");
  const newer = parseMigration("20260101000002_b.sql", "-- migrate:up\nselect 2;\n\n-- migrate:down\nselect 'down-b';\n");
  const { client, log } = recordingClient([
    { id: older.id, checksum: older.checksum },
    { id: newer.id, checksum: newer.checksum },
  ]);
  await migrateDown(client, [older, newer], 2);
  const downs = log.map((r) => r.sql).filter((s) => s.startsWith("select 'down-"));
  assert.deepEqual(downs, ["select 'down-b';", "select 'down-a';"]);
});

test("the migration runner does not shell out", () => {
  // C2. A migration runner that shells out to psql would put user-influenced
  // strings on a command line, which is exactly the class C2 forbids.
  const source = readFileSync(join(ROOT, "src", "db", "migrate.ts"), "utf8");
  for (const token of ["child_process", "execSync", "spawnSync", "exec("]) {
    assert.ok(!source.includes(token), `migrate.ts references ${token}`);
  }
});
