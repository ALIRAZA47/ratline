/**
 * Row-level security — layer 3 of C3 (RL-M1-006, ADR 0003).
 *
 * C3: "There is no unscoped findById in the codebase; make the unscoped variant
 * impossible to call rather than merely discouraged."
 *
 * Layers 1 and 2 — an unreachable database handle and a required AuthzContext —
 * are application-level and can both be wrong at once. This layer is the one
 * that still holds. The test that proves it is `queries with no predicate at
 * all`: it issues bare `select * from <table>` with a foreign tenant set, which
 * is what a repository function looks like with its WHERE clause deleted.
 *
 * EVERY assertion here runs as `ratline_app`, an unprivileged NOBYPASSRLS role.
 * A superuser bypasses row-level security unconditionally, and the development
 * role created by initdb is one — so running these on the migration connection
 * would pass without exercising a single policy.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Client } from "pg";

import {
  asApplicationRole,
  seedOrganization,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const skip = skipWithoutDatabase;

/** Tables carrying an org_id, and therefore a tenant_isolation policy. */
const TENANT_TABLES = [
  "memberships",
  "service_identities",
  "grants",
  "scope_nodes",
  "teams",
  "projects",
  "environments",
] as const;

/** Two fully-populated tenants in one database. */
async function twoTenants(client: Client): Promise<{ mine: string; theirs: string }> {
  const acme = await seedOrganization(client, "acme");
  const globex = await seedOrganization(client, "globex");

  for (const [orgId, slug] of [
    [acme.orgId, "acme"],
    [globex.orgId, "globex"],
  ] as const) {
    const root = await client.query<{ id: string }>(
      "select id from scope_nodes where org_id = $1 and kind = 'organization'",
      [orgId],
    );
    const teamNode = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'team', $2) returning id",
      [orgId, root.rows[0]?.id ?? ""],
    );
    await client.query("insert into teams (org_id, scope_node_id, slug, name) values ($1, $2, $3, 'Team')", [
      orgId,
      teamNode.rows[0]?.id ?? "",
      `${slug}-team`,
    ]);
    const projectNode = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'project', $2) returning id",
      [orgId, teamNode.rows[0]?.id ?? ""],
    );
    const project = await client.query<{ id: string }>(
      "insert into projects (org_id, scope_node_id, slug, name) values ($1, $2, $3, 'Project') returning id",
      [orgId, projectNode.rows[0]?.id ?? "", `${slug}-web`],
    );
    const envNode = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'environment', $2) returning id",
      [orgId, projectNode.rows[0]?.id ?? ""],
    );
    await client.query(
      "insert into environments (org_id, project_id, scope_node_id, slug, name, kind) values ($1, $2, $3, 'production', 'Production', 'production')",
      [orgId, project.rows[0]?.id ?? "", envNode.rows[0]?.id ?? ""],
    );
    await client.query("insert into service_identities (org_id, name) values ($1, 'deploy-bot')", [orgId]);
  }
  return { mine: acme.orgId, theirs: globex.orgId };
}

// ---------------------------------------------------------------------------
// Acceptance 1 — enabled AND forced on every tenant-scoped table
// ---------------------------------------------------------------------------

test("row-level security is enabled and forced on every tenant-scoped table", { skip }, async () => {
  // FORCE is the half that is easy to omit and fatal to omit: without it the
  // table OWNER is exempt, and the owner is exactly who many deployments
  // connect as, leaving the policies decorative.
  await withMigratedDatabase(async (client) => {
    const result = await client.query<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }>(
      `select c.relname, c.relrowsecurity, c.relforcerowsecurity
       from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relkind = 'r' and c.relname <> 'schema_migrations'`,
    );
    const problems: string[] = [];
    for (const row of result.rows) {
      if (!row.relrowsecurity) problems.push(`${row.relname}: RLS not enabled`);
      if (!row.relforcerowsecurity) problems.push(`${row.relname}: RLS not FORCED`);
    }
    assert.deepEqual(problems, [], problems.join("\n"));
  });
});

test("the application role cannot bypass row-level security", { skip }, async () => {
  // Acceptance 2. If this role were a superuser or held BYPASSRLS, every other
  // test in this file would pass while proving nothing.
  await withMigratedDatabase(async (client) => {
    const r = await client.query<{ rolsuper: boolean; rolbypassrls: boolean }>(
      "select rolsuper, rolbypassrls from pg_roles where rolname = 'ratline_app'",
    );
    assert.equal(r.rows.length, 1, "the application role should exist");
    assert.equal(r.rows[0]?.rolsuper, false, "the application role must not be a superuser");
    assert.equal(r.rows[0]?.rolbypassrls, false, "the application role must not hold BYPASSRLS");
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the predicate-free proof
// ---------------------------------------------------------------------------

test("queries with no predicate at all see only the current tenant", { skip }, async () => {
  // THIS is the acceptance criterion. `select * from <table>` with no WHERE is
  // precisely what a repository function looks like when its scoping is
  // deleted, forgotten, or bypassed by a bug in layers 1 and 2.
  await withMigratedDatabase(async (client, database) => {
    const { mine, theirs } = await twoTenants(client);

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);

      for (const table of TENANT_TABLES) {
        const rows = await app.query<{ org_id: string }>(`select org_id from ${table}`);
        assert.ok(rows.rows.length > 0, `${table}: expected to see own rows`);
        const foreign = rows.rows.filter((r) => r.org_id !== mine);
        assert.deepEqual(foreign, [], `${table}: leaked ${foreign.length} row(s) from another tenant`);
      }

      const orgs = await app.query<{ id: string }>("select id from organizations");
      assert.deepEqual(orgs.rows.map((r) => r.id), [mine]);
      await app.query("rollback");
    });

    // And symmetrically, so the test cannot pass by seeing nothing at all.
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, theirs);
      const rows = await app.query<{ org_id: string }>("select org_id from projects");
      assert.deepEqual(rows.rows.map((r) => r.org_id), [theirs]);
      await app.query("rollback");
    });
  });
});

test("naming another tenant's row by primary key returns nothing", { skip }, async () => {
  // The IDOR shape: the caller knows a real id and asks for it directly.
  await withMigratedDatabase(async (client, database) => {
    const { mine, theirs } = await twoTenants(client);
    const target = await client.query<{ id: string }>("select id from projects where org_id = $1", [theirs]);
    const foreignId = target.rows[0]?.id ?? "";

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);
      const r = await app.query("select * from projects where id = $1", [foreignId]);
      assert.equal(r.rows.length, 0, "an unscoped findById must still return nothing");
      await app.query("rollback");
    });
  });
});

test("an unset tenant sees nothing rather than everything", { skip }, async () => {
  // The missing-setting case has to fail closed. current_setting(..., true)
  // returns NULL when unset, and `org_id = NULL` is NULL, not true.
  await withMigratedDatabase(async (client, database) => {
    await twoTenants(client);
    await asApplicationRole(database, async (app) => {
      for (const table of [...TENANT_TABLES, "organizations", "users"]) {
        const r = await app.query(`select 1 from ${table}`);
        assert.equal(r.rows.length, 0, `${table}: visible with no tenant set`);
      }
    });
  });
});

test("a connection carries no tenant from the previous transaction", { skip }, async () => {
  // set_config(..., true) is transaction-local. If it leaked, a pooled
  // connection would serve one tenant's data to the next request — the worst
  // failure this design can have, and an invisible one.
  await withMigratedDatabase(async (client, database) => {
    const { mine } = await twoTenants(client);
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);
      assert.ok((await app.query("select 1 from projects")).rows.length > 0);
      await app.query("commit");

      const after = await app.query("select 1 from projects");
      assert.equal(after.rows.length, 0, "the tenant setting leaked past its transaction");
    });
  });
});

test("writes cannot be aimed at another tenant", { skip }, async () => {
  // WITH CHECK, not just USING. Without it a caller could INSERT a row owned by
  // someone else, or UPDATE one out of its own tenant and lose it.
  await withMigratedDatabase(async (client, database) => {
    const { mine, theirs } = await twoTenants(client);
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);

      await assert.rejects(
        () => app.query("insert into service_identities (org_id, name) values ($1, 'implant')", [theirs]),
        /row-level security/i,
        "inserting into another tenant must be refused",
      );

      await app.query("rollback");
      await app.query("begin");
      await setTenant(app, mine);

      await assert.rejects(
        () => app.query("update service_identities set org_id = $1", [theirs]),
        /row-level security/i,
        "moving a row out of its tenant must be refused",
      );
      await app.query("rollback");
    });
  });
});

test("deletes and updates cannot reach another tenant's rows", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { mine, theirs } = await twoTenants(client);

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);
      // No WHERE clause at all — the destructive version of the same mistake.
      const deleted = await app.query("delete from service_identities");
      assert.equal(deleted.rowCount, 1, "should only have been able to delete own row");
      await app.query("commit");
    });

    const survivors = await client.query<{ org_id: string }>("select org_id from service_identities");
    assert.deepEqual(survivors.rows.map((r) => r.org_id), [theirs], "the other tenant's row must survive");
  });
});

test("the ancestry view respects the caller's policies, not its owner's", { skip }, async () => {
  // A view runs with its OWNER's permissions unless security_invoker is set, so
  // this view would otherwise hand back every tenant's hierarchy to anyone who
  // can select from it — a complete bypass of everything above.
  await withMigratedDatabase(async (client, database) => {
    const { mine } = await twoTenants(client);
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);
      const r = await app.query<{ org_id: string }>("select org_id from scope_ancestry");
      assert.ok(r.rows.length > 0, "should see own ancestry");
      assert.deepEqual([...new Set(r.rows.map((x) => x.org_id))], [mine], "the view leaked another tenant");
      await app.query("rollback");
    });
  });
});

test("users are visible only through shared membership", { skip }, async () => {
  // Users are global rather than org-scoped, so without a policy a tenant could
  // enumerate every account on the installation by email.
  await withMigratedDatabase(async (client, database) => {
    const { mine } = await twoTenants(client);
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, mine);
      const r = await app.query<{ email: string }>("select email from users");
      assert.deepEqual(r.rows.map((x) => x.email), ["owner@acme.example"]);
      await app.query("rollback");
    });
  });
});

test("the application role cannot rewrite migration bookkeeping", { skip }, async () => {
  // Editing schema_migrations would let application code fake a schema state,
  // which the checksum guard in RL-M1-003 exists to prevent.
  await withMigratedDatabase(async (_client, database) => {
    await asApplicationRole(database, async (app) => {
      await assert.rejects(
        () => app.query("delete from schema_migrations"),
        /permission denied/i,
      );
    });
  });
});
