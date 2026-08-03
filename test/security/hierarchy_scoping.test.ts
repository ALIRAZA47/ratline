/**
 * Scope hierarchy and inheritance (RL-M1-005).
 *
 * The scope path is what every permission check will resolve against, so a bug
 * here is a bug in every authorization decision at once. Two failure directions
 * matter and they are not symmetric:
 *
 *   - A path that is too SHORT matches more descendants, so a grant reaches
 *     further than intended. That is a privilege escalation.
 *   - A path that is too LONG matches fewer, so a legitimate grant stops
 *     working. That is an outage.
 *
 * The first is worse and quieter, which is why these tests lean on ancestry
 * boundaries and cross-tenant containment rather than on happy paths.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Client } from "pg";

import { seedOrganization, skipWithoutDatabase, withMigratedDatabase } from "../support/db.ts";

const skip = skipWithoutDatabase;

type Tree = { orgNodeId: string; teamNodeId: string; projectNodeId: string; envNodeId: string };

/** organization → team → project → environment, returning each scope node id. */
async function seedTree(client: Client, orgId: string, slug = "web"): Promise<Tree> {
  const orgNode = await client.query<{ id: string }>(
    "select id from scope_nodes where org_id = $1 and kind = 'organization'",
    [orgId],
  );
  const orgNodeId = orgNode.rows[0]?.id ?? "";

  const node = async (kind: string, parent: string): Promise<string> => {
    const r = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, $2, $3) returning id",
      [orgId, kind, parent],
    );
    return r.rows[0]?.id ?? "";
  };

  const teamNodeId = await node("team", orgNodeId);
  await client.query(
    "insert into teams (org_id, scope_node_id, slug, name) values ($1, $2, $3, $4)",
    [orgId, teamNodeId, `${slug}-team`, "Team"],
  );

  const projectNodeId = await node("project", teamNodeId);
  const project = await client.query<{ id: string }>(
    "insert into projects (org_id, scope_node_id, slug, name) values ($1, $2, $3, $4) returning id",
    [orgId, projectNodeId, slug, "Project"],
  );

  const envNodeId = await node("environment", projectNodeId);
  await client.query(
    "insert into environments (org_id, project_id, scope_node_id, slug, name, kind) values ($1, $2, $3, 'production', 'Production', 'production')",
    [orgId, project.rows[0]?.id ?? "", envNodeId],
  );

  return { orgNodeId, teamNodeId, projectNodeId, envNodeId };
}

async function ancestorsOf(client: Client, nodeId: string): Promise<string[]> {
  const r = await client.query<{ ancestor_id: string }>(
    "select ancestor_id from scope_ancestry where node_id = $1 order by ancestor_depth",
    [nodeId],
  );
  return r.rows.map((row) => row.ancestor_id);
}

// ---------------------------------------------------------------------------
// Acceptance 1 and 3 — the chain, and inheritance in one query
// ---------------------------------------------------------------------------

test("an organization gets a root scope node automatically", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const r = await client.query<{ kind: string; parent_id: string | null }>(
      "select kind, parent_id from scope_nodes where org_id = $1",
      [orgId],
    );
    assert.equal(r.rows.length, 1);
    assert.equal(r.rows[0]?.kind, "organization");
    assert.equal(r.rows[0]?.parent_id, null);
  });
});

test("the full chain resolves ancestry root-first in one query", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);

    assert.deepEqual(await ancestorsOf(client, tree.envNodeId), [
      tree.orgNodeId,
      tree.teamNodeId,
      tree.projectNodeId,
      tree.envNodeId,
    ]);
    assert.deepEqual(await ancestorsOf(client, tree.projectNodeId), [
      tree.orgNodeId,
      tree.teamNodeId,
      tree.projectNodeId,
    ]);
    assert.deepEqual(await ancestorsOf(client, tree.orgNodeId), [tree.orgNodeId]);
  });
});

test("inheritance runs downward only", { skip }, async () => {
  // A grant on an environment must never convey at the project above it. If
  // ancestry were symmetric, every environment-scoped grant would silently
  // become a project-wide one.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    assert.ok(!(await ancestorsOf(client, tree.projectNodeId)).includes(tree.envNodeId));
    assert.ok(!(await ancestorsOf(client, tree.teamNodeId)).includes(tree.projectNodeId));
  });
});

test("siblings do not inherit from each other", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const a = await seedTree(client, orgId, "web");
    const b = await seedTree(client, orgId, "api");

    const ancestors = await ancestorsOf(client, a.envNodeId);
    for (const foreign of [b.teamNodeId, b.projectNodeId, b.envNodeId]) {
      assert.ok(!ancestors.includes(foreign), "a sibling subtree must not be an ancestor");
    }
    // They do share the organization root — that is the point of inheritance.
    assert.ok(ancestors.includes(a.orgNodeId));
  });
});

test("ancestry never crosses tenants", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    const mine = await seedTree(client, acme.orgId);
    const theirs = await seedTree(client, globex.orgId);

    const ancestors = await ancestorsOf(client, mine.envNodeId);
    for (const foreign of Object.values(theirs)) {
      assert.ok(!ancestors.includes(foreign), "cross-tenant ancestry would defeat C3 entirely");
    }
  });
});

test("a node cannot be parented into another tenant", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    const theirRoot = await client.query<{ id: string }>(
      "select id from scope_nodes where org_id = $1 and kind = 'organization'",
      [globex.orgId],
    );
    await assert.rejects(
      () =>
        client.query("insert into scope_nodes (org_id, kind, parent_id) values ($1, 'team', $2)", [
          acme.orgId,
          theirRoot.rows[0]?.id ?? "",
        ]),
      /cross tenants/,
    );
  });
});

test("the path is maintained by the database, not the caller", { skip }, async () => {
  // A path written by application code would break inheritance OPEN when it got
  // it wrong — a shorter path matches more descendants. The trigger overwrites
  // whatever the caller supplies.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);

    const inserted = await client.query<{ id: string; path: string }>(
      "insert into scope_nodes (org_id, kind, parent_id, path) values ($1, 'project', $2, 'nonsense') returning id, path::text",
      [orgId, tree.teamNodeId],
    );
    const path = inserted.rows[0]?.path ?? "";
    assert.notEqual(path, "nonsense", "a caller-supplied path must not survive");
    assert.ok(path.includes(tree.teamNodeId.replace(/-/g, "_")), "the parent must be in the path");
  });
});

test("only one organization node exists per tenant", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await assert.rejects(
      () => client.query("insert into scope_nodes (org_id, kind, parent_id) values ($1, 'organization', null)", [orgId]),
      /scope_nodes_org_root_idx|duplicate key/,
    );
  });
});

test("a non-root node must have a parent and a root must not", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await assert.rejects(
      () => client.query("insert into scope_nodes (org_id, kind, parent_id) values ($1, 'team', null)", [orgId]),
      /scope_nodes_root_shape/,
    );
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — environment kind
// ---------------------------------------------------------------------------

test("environment kind is constrained to the three the brief names", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    const project = await client.query<{ id: string }>("select id from projects where org_id = $1", [orgId]);
    const node = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'environment', $2) returning id",
      [orgId, tree.projectNodeId],
    );
    await assert.rejects(
      () =>
        client.query(
          "insert into environments (org_id, project_id, scope_node_id, slug, name, kind) values ($1, $2, $3, 'qa', 'QA', 'qa')",
          [orgId, project.rows[0]?.id ?? "", node.rows[0]?.id ?? ""],
        ),
      /environments_kind/,
    );
  });
});

test("is_production is derived from kind and cannot be set independently", { skip }, async () => {
  // A row saying kind='production' with is_production=false would be a silent
  // production-permission bypass. Generating the column removes the state.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await seedTree(client, orgId);

    const r = await client.query<{ kind: string; is_production: boolean }>(
      "select kind, is_production from environments where org_id = $1",
      [orgId],
    );
    assert.equal(r.rows[0]?.kind, "production");
    assert.equal(r.rows[0]?.is_production, true);

    await assert.rejects(
      () => client.query("update environments set is_production = false where org_id = $1", [orgId]),
      /can only be updated to DEFAULT/i,
    );
  });
});

test("changing kind changes is_production with it", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await seedTree(client, orgId);
    await client.query("update environments set kind = 'staging' where org_id = $1", [orgId]);
    const r = await client.query<{ is_production: boolean }>(
      "select is_production from environments where org_id = $1",
      [orgId],
    );
    assert.equal(r.rows[0]?.is_production, false);
  });
});

test("deleting a project removes its environments and their scope nodes", { skip }, async () => {
  // Orphaned scope nodes would keep conveying grants to resources that no
  // longer exist, and would resurface if an id were ever reused.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const tree = await seedTree(client, orgId);
    await client.query("delete from projects where org_id = $1", [orgId]);

    const envs = await client.query("select 1 from environments where org_id = $1", [orgId]);
    assert.equal(envs.rows.length, 0);
    const nodes = await client.query("select 1 from scope_nodes where id = any($1)", [
      [tree.projectNodeId, tree.envNodeId],
    ]);
    assert.equal(nodes.rows.length, 0, "scope nodes must not outlive what they scope");
  });
});
