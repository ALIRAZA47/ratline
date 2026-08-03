/**
 * Identity schema invariants (RL-M1-004).
 *
 * These run against a real Postgres because the properties being asserted are
 * properties *of the database*, not of the application. The whole point of
 * acceptance 3 is that the last-owner rule survives code that forgets it — a
 * hand-run UPDATE during an incident, a cascade, a future repository function
 * with a bug. A test that went through application code would prove nothing
 * about that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { seedOrganization, skipWithoutDatabase, withMigratedDatabase } from "../support/db.ts";

const skip = skipWithoutDatabase;

// ---------------------------------------------------------------------------
// Acceptance 1 and 2 — org scoping, and org_id non-nullable everywhere
// ---------------------------------------------------------------------------

test("the identity tables exist", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const result = await client.query<{ table_name: string }>(
      `select table_name from information_schema.tables
       where table_schema = current_schema() and table_type = 'BASE TABLE'`,
    );
    const tables = result.rows.map((r) => r.table_name).sort();
    for (const expected of ["organizations", "users", "memberships", "service_identities", "grants"]) {
      assert.ok(tables.includes(expected), `missing table ${expected}; got ${tables.join(", ")}`);
    }
  });
});

test("every tenant-scoped table carries a non-nullable org_id", { skip }, async () => {
  // Discovered from the schema rather than listed, so a table added later
  // without org_id fails here instead of becoming a cross-tenant hole that
  // nobody notices until RL-M1-006 tries to write a policy for it.
  //
  // Three deliberate exceptions, each for a different reason:
  //   organizations     — is the tenant. Its own `id` is the tenant key, so an
  //                       org_id column would be a self-reference.
  //   users             — a person belongs to several organizations, so the
  //                       tenant boundary is `memberships`, not `users`.
  //   schema_migrations — bookkeeping for the migration runner, not app data.
  //
  // The list is short and each entry is argued. Adding a fourth should be hard:
  // a table here without org_id is a table row-level security cannot scope
  // (RL-M1-006), which is a cross-tenant hole waiting for someone to query it.
  const NOT_TENANT_SCOPED = new Set(["organizations", "users", "schema_migrations"]);

  await withMigratedDatabase(async (client) => {
    const tables = await client.query<{ table_name: string }>(
      `select table_name from information_schema.tables
       where table_schema = current_schema() and table_type = 'BASE TABLE'`,
    );

    const problems: string[] = [];
    for (const { table_name } of tables.rows) {
      if (NOT_TENANT_SCOPED.has(table_name)) continue;
      const column = await client.query<{ is_nullable: string }>(
        `select is_nullable from information_schema.columns
         where table_schema = current_schema() and table_name = $1 and column_name = 'org_id'`,
        [table_name],
      );
      const found = column.rows[0];
      if (found === undefined) problems.push(`${table_name}: no org_id column`);
      else if (found.is_nullable !== "NO") problems.push(`${table_name}: org_id is nullable`);
    }
    assert.deepEqual(problems, [], problems.join("\n"));
  });
});

test("email uniqueness is case-insensitive", { skip }, async () => {
  // A case-sensitive unique index would let Ali@example.com and ali@example.com
  // become two accounts. That is an account-takeover shape, not a cosmetic bug.
  await withMigratedDatabase(async (client) => {
    await client.query("insert into users (email, name) values ('Ali@Example.com', 'Ali')");
    await assert.rejects(
      () => client.query("insert into users (email, name) values ('ali@example.com', 'Impostor')"),
      /duplicate key/i,
    );
  });
});

test("a membership cannot reference a missing organization or user", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        client.query("insert into memberships (org_id, user_id) values ($1, $2)", [
          orgId,
          "00000000-0000-0000-0000-000000000000",
        ]),
      /foreign key/i,
    );
    await assert.rejects(
      () =>
        client.query("insert into memberships (org_id, user_id) values ($1, $2)", [
          "00000000-0000-0000-0000-000000000000",
          userId,
        ]),
      /foreign key/i,
    );
  });
});

test("a narrower-than-organization grant must name the node it applies to", { skip }, async () => {
  // A project-scope grant with a null scope_id would silently mean "every
  // project", which is a privilege escalation dressed as a null.
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        client.query(
          `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, scope_id)
           values ($1, 'user', $2, 'developer', 'project', null)`,
          [orgId, userId],
        ),
      /grants_scope_id_matches_type/,
    );
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the last-owner invariant, enforced by the database
// ---------------------------------------------------------------------------

test("the last owner cannot be deleted", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { grantId } = await seedOrganization(client);
    await assert.rejects(
      () => client.query("delete from grants where id = $1", [grantId]),
      /no owner/,
      "the database must refuse, not merely the application",
    );
  });
});

test("the last owner cannot be demoted", { skip }, async () => {
  // Deletion is the obvious attack on this invariant. Changing the role in
  // place is the one an application-level check usually misses.
  await withMigratedDatabase(async (client) => {
    const { grantId } = await seedOrganization(client);
    await assert.rejects(
      () => client.query("update grants set role_key = 'viewer' where id = $1", [grantId]),
      /no owner/,
    );
  });
});

test("the last owner cannot be removed by a cascading membership delete", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, userId } = await seedOrganization(client);
    // Removing the person from the organization must not quietly strip the last
    // owner grant along the way.
    await client.query("delete from memberships where org_id = $1 and user_id = $2", [orgId, userId]);
    const owners = await client.query(
      "select 1 from grants where org_id = $1 and role_key = 'owner' and scope_type = 'organization'",
      [orgId],
    );
    assert.equal(owners.rows.length, 1, "the owner grant should still stand");
  });
});

test("ownership can be transferred in one transaction, in either order", { skip }, async () => {
  // This is why the trigger is DEFERRABLE INITIALLY DEFERRED. A non-deferred
  // check would make handover impossible without a window of zero owners,
  // forcing operators to grant-then-revoke and leaving two owners if the second
  // step failed.
  await withMigratedDatabase(async (client) => {
    const { orgId, grantId } = await seedOrganization(client);
    const successor = await client.query<{ id: string }>(
      "insert into users (email, name) values ('next@acme.example', 'Next') returning id",
    );
    const successorId = successor.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, successorId]);

    await client.query("begin");
    // Remove first, add second — the order that a non-deferred trigger rejects.
    await client.query("delete from grants where id = $1", [grantId]);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'owner', 'organization')`,
      [orgId, successorId],
    );
    await client.query("commit");

    const owners = await client.query<{ subject_id: string }>(
      "select subject_id from grants where org_id = $1 and role_key = 'owner' and scope_type = 'organization'",
      [orgId],
    );
    assert.equal(owners.rows.length, 1);
    assert.equal(owners.rows[0]?.subject_id, successorId);
  });
});

test("a transaction that ends with no owner is rolled back at commit", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { grantId } = await seedOrganization(client);
    await client.query("begin");
    await client.query("delete from grants where id = $1", [grantId]);
    // The deferred trigger fires here, not at the DELETE.
    await assert.rejects(() => client.query("commit"), /no owner/);
    await client.query("rollback");
  });
});

test("one owner may be removed while another remains", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId, grantId } = await seedOrganization(client);
    const second = await client.query<{ id: string }>(
      "insert into users (email, name) values ('second@acme.example', 'Second') returning id",
    );
    const secondId = second.rows[0]?.id ?? "";
    await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, secondId]);
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'owner', 'organization')`,
      [orgId, secondId],
    );

    await client.query("delete from grants where id = $1", [grantId]);
    const owners = await client.query("select 1 from grants where org_id = $1 and role_key = 'owner'", [orgId]);
    assert.equal(owners.rows.length, 1, "removing one of two owners must be allowed");
  });
});

test("deleting an organization is not blocked by its own owner grant", { skip }, async () => {
  // The cascade removes the grants. Refusing that would make an organization
  // undeletable, which is a worse bug than the one the trigger prevents.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await client.query("delete from organizations where id = $1", [orgId]);
    const left = await client.query("select 1 from grants where org_id = $1", [orgId]);
    assert.equal(left.rows.length, 0);
  });
});

test("only a person can satisfy the last-owner floor", { skip }, async () => {
  // Found while building API tokens (RL-M1-032). A service identity or token
  // holding `owner` at organization scope used to satisfy the floor that §6.3
  // intends a human to satisfy, so every person could be removed from ownership
  // — leaving an organization administered only by a credential, which cannot
  // answer a break-glass notification and, if lost, leaves no route back in.
  await withMigratedDatabase(async (client) => {
    const { orgId, grantId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [orgId],
    );

    await assert.rejects(
      () =>
        client.query(
          `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
           values ($1, 'service_identity', $2, 'owner', 'organization')`,
          [orgId, identity.rows[0]?.id ?? ""],
        ),
      /grants_organization_owner_is_a_person/,
      "a non-person must not be able to hold organization-scope owner at all",
    );

    // ...and the human owner is still the only thing holding the floor up.
    await assert.rejects(
      () => client.query("delete from grants where id = $1", [grantId]),
      /no owner who is a person/,
    );
  });
});

test("one organization's owners do not satisfy another's floor", { skip }, async () => {
  // The trigger counts per organization. A global count would let a busy tenant
  // mask an ownerless one.
  await withMigratedDatabase(async (client) => {
    await seedOrganization(client, "acme");
    const other = await seedOrganization(client, "globex");
    await assert.rejects(
      () => client.query("delete from grants where id = $1", [other.grantId]),
      /no owner/,
    );
  });
});
