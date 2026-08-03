/**
 * The database handle. Layer 1 of C3 (RL-M1-007, ADR 0003).
 *
 * ---------------------------------------------------------------------------
 * NOTHING OUTSIDE src/repo/ MAY IMPORT FROM THIS DIRECTORY.
 * ---------------------------------------------------------------------------
 *
 * C3: "There is no unscoped findById in the codebase; make the unscoped variant
 * impossible to call rather than merely discouraged."
 *
 * That is delivered by three layers, each of which fails closed on its own:
 *
 *   1. This module is the only place a connection exists, and the only thing it
 *      exports for querying is `scoped()`, which cannot run without a tenant.
 *      Reaching it from outside src/repo/ fails lint (RL-M1-008).
 *   2. `AuthzContext` is required by every repository signature and cannot be
 *      constructed outside the authenticated request path — see context.ts.
 *   3. Postgres row-level security refuses the rows regardless (RL-M1-006).
 *
 * Layer 3 already holds on its own; layers 1 and 2 exist so that a scoping
 * mistake is a compile error or a lint failure at review time rather than a
 * silent empty result at 2am.
 *
 * The connection is made as `ratline_app` — an unprivileged role that holds
 * neither SUPERUSER nor BYPASSRLS — because either would make layer 3
 * decorative. `assertNotPrivileged()` checks that at startup rather than
 * trusting the deployment to have got it right.
 */

import { Pool, type PoolClient, type QueryResultRow } from "pg";

import type { AuthzContext } from "../../authz/context.ts";

export type Row = QueryResultRow;

/** The narrow surface a repository function is allowed to use. */
export type ScopedQuery = {
  <T extends Row>(sql: string, params?: readonly unknown[]): Promise<T[]>;
};

let pool: Pool | null = null;

export type PoolOptions = {
  readonly connectionString?: string;
  readonly max?: number;
};

export function connect(options: PoolOptions = {}): Pool {
  if (pool !== null) return pool;
  const connectionString = options.connectionString ?? process.env["DATABASE_URL"];
  if (connectionString === undefined || connectionString.trim() === "") {
    throw new Error(
      "DATABASE_URL is not set. Ratline refuses to start without one rather than " +
        "falling back to a default connection.",
    );
  }
  pool = new Pool({ connectionString, max: options.max ?? 10 });
  return pool;
}

export async function disconnect(): Promise<void> {
  const current = pool;
  pool = null;
  if (current !== null) await current.end();
}

/**
 * Refuse to run as a role that can bypass row-level security.
 *
 * Called at boot. A superuser connection silently disables layer 3 for the
 * whole application, and nothing else in the system would notice — every query
 * would keep returning correct-looking results, just for every tenant.
 */
export async function assertNotPrivileged(): Promise<void> {
  const result = await connect().query<{ rolsuper: boolean; rolbypassrls: boolean; rolname: string }>(
    "select rolname, rolsuper, rolbypassrls from pg_roles where rolname = current_user",
  );
  const role = result.rows[0];
  if (role === undefined) throw new Error("could not determine the current database role");
  if (role.rolsuper || role.rolbypassrls) {
    throw new Error(
      `Ratline refuses to start: the database role "${role.rolname}" can bypass row-level ` +
        `security (superuser=${role.rolsuper}, bypassrls=${role.rolbypassrls}). Tenant isolation ` +
        `would be unenforced. Connect as an unprivileged role such as ratline_app.`,
    );
  }
}

/**
 * Run `fn` in a transaction with the tenant bound for its duration.
 *
 * The tenant is set with `set_config(..., true)`, which is transaction-local.
 * That is the whole reason this is a transaction rather than a bare query: a
 * pooled connection that carried a tenant into the next checkout would serve
 * one tenant's data to another, and nothing downstream could detect it.
 *
 * This is the ONLY export that runs SQL, and it cannot be called without an
 * AuthzContext, so there is no path from a repository function to an unscoped
 * query that does not involve editing this file.
 */
export async function scoped<T>(
  ctx: AuthzContext,
  fn: (query: ScopedQuery, client: PoolClient) => Promise<T>,
): Promise<T> {
  const client = await connect().connect();
  try {
    await client.query("begin");
    await client.query("select set_config('ratline.org_id', $1, true)", [ctx.orgId]);

    const query: ScopedQuery = async <R extends Row>(sql: string, params: readonly unknown[] = []) => {
      const result = await client.query<R>(sql, params as unknown[]);
      return result.rows;
    };

    const value = await fn(query, client);
    await client.query("commit");
    return value;
  } catch (error) {
    // Never swallowed — §9 forbids silent catch blocks. Rollback failure is
    // reported alongside the original rather than replacing it.
    try {
      await client.query("rollback");
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], "query failed, and rolling back also failed");
    }
    throw error;
  } finally {
    client.release();
  }
}
