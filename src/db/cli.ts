#!/usr/bin/env node --experimental-strip-types
/**
 * Migration CLI (RL-M1-003).
 *
 *   ./scripts/migrate up          apply everything unapplied
 *   ./scripts/migrate down [n]    roll back the last n (default 1)
 *   ./scripts/migrate status      what is applied
 *   ./scripts/migrate cycle       up, down to empty, up again — the CI gate
 *
 * `cycle` is the one that matters. Asserting a down path *exists* is a parser
 * check; running up → down → up against a real database is the only way to know
 * it works. A down that drops the wrong object, or leaves a type or extension
 * behind, passes the first up and fails the second.
 *
 * Connection comes from DATABASE_URL, or from the project-local cluster
 * (`./scripts/pg start`) when that is unset.
 */

import { Client } from "pg";

import {
  loadMigrations,
  migrateDown,
  migrateUp,
  migrationStatus,
  MigrationError,
  type SqlClient,
} from "./migrate.ts";

const DEFAULT_URL = "postgres://ratline@127.0.0.1:55432/ratline_dev";

function databaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env["DATABASE_URL"];
  if (configured !== undefined && configured.trim() !== "") return configured.trim();
  return DEFAULT_URL;
}

async function withClient<T>(fn: (client: SqlClient) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: databaseUrl() });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

async function main(): Promise<void> {
  const [command = "up", arg] = process.argv.slice(2);
  const migrations = loadMigrations();

  switch (command) {
    case "up": {
      const done = await withClient((c) => migrateUp(c, migrations));
      console.log(done.length === 0 ? "nothing to apply" : `applied ${done.map((d) => d.id).join(", ")}`);
      return;
    }

    case "down": {
      const count = arg === undefined ? 1 : Number(arg);
      if (!Number.isInteger(count) || count < 1) throw new Error(`bad count "${arg}"`);
      const done = await withClient((c) => migrateDown(c, migrations, count));
      console.log(done.length === 0 ? "nothing to roll back" : `rolled back ${done.map((d) => d.id).join(", ")}`);
      return;
    }

    case "status": {
      const rows = await withClient((c) => migrationStatus(c, migrations));
      for (const row of rows) console.log(`${row.applied ? "applied" : "pending"}  ${row.id}`);
      console.log(`\n${rows.filter((r) => r.applied).length}/${rows.length} applied`);
      return;
    }

    case "cycle": {
      await withClient(async (client) => {
        const total = migrations.length;
        console.log(`cycling ${total} migration(s) against ${databaseUrl().replace(/:[^:@/]*@/, ":***@")}`);

        // Normalise first. Comparing "how many did each up apply" is only
        // meaningful from a known starting point, and a database with some
        // migrations already applied would otherwise report a spurious failure
        // — first up applies 0, second applies N, and nothing is actually wrong.
        const pre = (await migrationStatus(client, migrations)).filter((r) => r.applied).length;
        if (pre > 0) {
          await migrateDown(client, migrations, pre);
          console.log(`  reset — rolled back ${pre} pre-existing`);
        }

        const expect = (label: string, actual: number) => {
          if (actual !== total) {
            throw new Error(
              `${label} handled ${actual} migration(s), expected ${total}. ` +
                `A down path did not fully reverse its migration.`,
            );
          }
        };

        expect("first up", (await migrateUp(client, migrations)).length);
        console.log(`  up   — applied ${total}`);

        expect("down", (await migrateDown(client, migrations, total)).length);
        console.log(`  down — rolled back ${total}`);

        const remaining = (await migrationStatus(client, migrations)).filter((r) => r.applied);
        if (remaining.length > 0) {
          throw new Error(
            `after rolling everything back, ${remaining.length} migration(s) are still recorded as applied: ` +
              remaining.map((r) => r.id).join(", "),
          );
        }

        // The second up is the real test. If a down path left an object behind,
        // this is where it surfaces — as a duplicate-object error, not a pass.
        expect("second up", (await migrateUp(client, migrations)).length);
        console.log(`  up   — applied ${total}`);
        console.log("cycle ok — every migration reverses cleanly");
      });
      return;
    }

    default:
      console.error(`unknown command "${command}"\n\nusage: migrate {up|down [n]|status|cycle}`);
      process.exit(1);
  }
}

try {
  await main();
} catch (error) {
  if (error instanceof MigrationError) {
    console.error(`migration error: ${error.message}`);
    process.exit(1);
  }
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
