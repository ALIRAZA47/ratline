/**
 * Migration runner (RL-M1-003).
 *
 * Brief §9 lists "a migration that can't be rolled back" as an anti-pattern, so
 * the down path is not optional here — a migration file without one is a build
 * failure, not a warning. CI applies every migration up, then down, then up
 * again against a scratch database, which is the only way to know a down path
 * works rather than merely exists.
 *
 * Migrations are plain SQL. A file is one migration, split by a marker:
 *
 *     -- migrate:up
 *     create table ...;
 *
 *     -- migrate:down
 *     drop table ...;
 *
 * Deliberately not a dependency. `node:sql` is not available and an ORM's
 * migration tool would pull in the ORM's opinions about schema authorship; C3
 * needs row-level security and forced policies, which are easier to express in
 * SQL than to coax out of a builder.
 *
 * Each migration runs inside a transaction together with its bookkeeping row,
 * so a failure leaves no partial state and no false record of success.
 */

import { createHash } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
export const MIGRATIONS_DIR = join(ROOT, "src", "db", "migrations");

const UP_MARKER = "-- migrate:up";
const DOWN_MARKER = "-- migrate:down";

export type Migration = {
  readonly id: string;
  readonly file: string;
  readonly up: string;
  readonly down: string;
  readonly checksum: string;
};

export class MigrationError extends Error {
  readonly file: string;

  constructor(file: string, message: string) {
    super(`${file}: ${message}`);
    this.name = "MigrationError";
    this.file = file;
  }
}

/**
 * Parse one migration file. Throws when the down path is missing or empty —
 * that refusal is the whole point of the acceptance criterion.
 */
export function parseMigration(file: string, source: string): Migration {
  const name = basename(file);

  if (!/^\d{14}_[a-z0-9_]+\.sql$/.test(name)) {
    throw new MigrationError(name, "name must be <14-digit timestamp>_<snake_case>.sql");
  }

  const upAt = source.indexOf(UP_MARKER);
  const downAt = source.indexOf(DOWN_MARKER);

  if (upAt === -1) throw new MigrationError(name, `missing "${UP_MARKER}"`);
  if (downAt === -1) {
    throw new MigrationError(
      name,
      `missing "${DOWN_MARKER}". Every migration must be reversible (brief §9). ` +
        `If the change is genuinely irreversible, say so explicitly in the down ` +
        `section with a raise, so the refusal is deliberate and reviewed.`,
    );
  }
  if (downAt < upAt) throw new MigrationError(name, `"${DOWN_MARKER}" must come after "${UP_MARKER}"`);

  const up = source.slice(upAt + UP_MARKER.length, downAt).trim();
  const down = source.slice(downAt + DOWN_MARKER.length).trim();

  if (up === "") throw new MigrationError(name, "the up section is empty");
  if (down === "") {
    throw new MigrationError(
      name,
      "the down section is empty. An empty down silently pretends to roll back.",
    );
  }

  return {
    id: name.slice(0, name.length - ".sql".length),
    file: name,
    up,
    down,
    // Covers only the up section: editing an applied migration's up is the
    // dangerous case, because the database no longer matches the file.
    checksum: createHash("sha256").update(up).digest("hex").slice(0, 16),
  };
}

/** Load every migration in order. Throws on the first malformed file. */
export function loadMigrations(dir: string = MIGRATIONS_DIR): readonly Migration[] {
  const files = globSync("*.sql", { cwd: dir }).sort();
  const seen = new Set<string>();
  const migrations: Migration[] = [];

  for (const file of files) {
    const migration = parseMigration(file, readFileSync(join(dir, file), "utf8"));
    if (seen.has(migration.id)) throw new MigrationError(file, "duplicate migration id");
    seen.add(migration.id);
    migrations.push(migration);
  }
  return migrations;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/**
 * The minimum a client must provide. Keeping this an interface rather than
 * importing a driver means the runner is testable and the driver choice stays
 * in one place (ADR 0001).
 */
export type SqlClient = {
  query(sql: string, params?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
};

const BOOKKEEPING = `
create table if not exists schema_migrations (
  id          text primary key,
  checksum    text not null,
  applied_at  timestamptz not null default now()
)`;

export async function appliedMigrations(client: SqlClient): Promise<Map<string, string>> {
  await client.query(BOOKKEEPING);
  const result = await client.query("select id, checksum from schema_migrations order by id");
  const applied = new Map<string, string>();
  for (const row of result.rows) {
    applied.set(String(row["id"]), String(row["checksum"]));
  }
  return applied;
}

export type StepReport = { readonly id: string; readonly direction: "up" | "down" };

/**
 * Apply every unapplied migration.
 *
 * Refuses if an already-applied migration's checksum no longer matches: the
 * file was edited after it ran, so the database and the repository disagree and
 * every later assumption is unsound.
 */
export async function migrateUp(
  client: SqlClient,
  migrations: readonly Migration[] = loadMigrations(),
): Promise<readonly StepReport[]> {
  const applied = await appliedMigrations(client);
  const done: StepReport[] = [];

  for (const migration of migrations) {
    const previous = applied.get(migration.id);
    if (previous !== undefined) {
      if (previous !== migration.checksum) {
        throw new MigrationError(
          migration.file,
          `already applied, but its contents changed since (recorded ${previous}, now ${migration.checksum}). ` +
            `The database no longer matches the repository. Write a new migration instead of editing this one.`,
        );
      }
      continue;
    }

    // The migration and its bookkeeping row commit together, so a crash cannot
    // leave a schema change recorded as unapplied or vice versa.
    await client.query("begin");
    try {
      await client.query(migration.up);
      await client.query("insert into schema_migrations (id, checksum) values ($1, $2)", [
        migration.id,
        migration.checksum,
      ]);
      await client.query("commit");
    } catch (cause) {
      await client.query("rollback");
      throw new MigrationError(migration.file, `up failed: ${(cause as Error).message}`);
    }
    done.push({ id: migration.id, direction: "up" });
  }
  return done;
}

/** Roll back the most recent `count` applied migrations, newest first. */
export async function migrateDown(
  client: SqlClient,
  migrations: readonly Migration[] = loadMigrations(),
  count = 1,
): Promise<readonly StepReport[]> {
  const applied = await appliedMigrations(client);
  const byId = new Map(migrations.map((m) => [m.id, m]));
  const toRevert = [...applied.keys()].sort().reverse().slice(0, count);
  const done: StepReport[] = [];

  for (const id of toRevert) {
    const migration = byId.get(id);
    if (migration === undefined) {
      throw new MigrationError(
        id,
        `applied to this database but absent from the repository, so it cannot be rolled back. ` +
          `Restore the file or reset the database.`,
      );
    }

    await client.query("begin");
    try {
      await client.query(migration.down);
      await client.query("delete from schema_migrations where id = $1", [id]);
      await client.query("commit");
    } catch (cause) {
      await client.query("rollback");
      throw new MigrationError(migration.file, `down failed: ${(cause as Error).message}`);
    }
    done.push({ id, direction: "down" });
  }
  return done;
}

/** Current state, for `migrate status` and for tests. */
export async function migrationStatus(
  client: SqlClient,
  migrations: readonly Migration[] = loadMigrations(),
): Promise<readonly { id: string; applied: boolean }[]> {
  const applied = await appliedMigrations(client);
  return migrations.map((m) => ({ id: m.id, applied: applied.has(m.id) }));
}
