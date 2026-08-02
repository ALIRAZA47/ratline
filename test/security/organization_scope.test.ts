/**
 * The one organization-wide scope lookup (RL-M1-039).
 *
 * Three repositories had grown their own copy of this — `api_tokens.ts`, then
 * `sessions.ts`, then `two_factor.ts`, each noting in a comment that the others
 * existed. Collapsing them is a refactor; these tests are what make it a
 * durable one.
 *
 * ## Why a scope lookup is worth its own security suite
 *
 * Every permission decision resolves against a scope node, and the two ways of
 * getting it wrong are not symmetric. A node too far DOWN the tree makes a
 * legitimate grant stop working — an outage, noticed within minutes. A node too
 * far UP makes a narrow grant reach further than intended — a privilege
 * escalation, noticed by nobody. The organization root is the top of the tree,
 * so every wrong answer here is the second kind.
 *
 * The fourth test is the one that keeps the refactor: it fails if a repository
 * grows a private copy again, which is how the three copies happened in the
 * first place — each author reasonably deciding a ten-line helper was not worth
 * a shared module.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { contextForRequest } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { organizationScopeNode, organizationScopeRef } from "../../src/repo/scope.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
  await asApplicationRole(database, () => Promise.resolve(undefined));
  const url = new URL(DATABASE_URL);
  url.pathname = `/${database}`;
  url.username = "ratline_app";
  url.password = "";
  connect({ connectionString: url.toString() });
  try {
    await fn();
  } finally {
    await disconnect();
  }
}

test("the organization-wide ref names no resource, ever", { skip }, async () => {
  // This is the whole reason `organizationScopeRef` exists rather than a
  // `ScopeRef` literal at each call site. `ScopeRef`'s own documentation is
  // explicit that a resource id supplied when the question is not about a
  // resource silently WIDENS the answer — it brings resource-scoped grants into
  // a question that is not about one. There is now one place that can go wrong
  // instead of three, and this is the assertion that makes the one place safe.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = contextForRequest({ orgId, userId, requestId: `r-${randomUUID()}` });
      const ref = await organizationScopeRef(ctx);
      assert.equal(ref.resourceId, null, "an organization-wide question is not about a resource");
      assert.equal(ref.scopeNodeId, await organizationScopeNode(ctx));
    });
  });
});

test("it resolves the organization root and not some other node in the tenant", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);

    // A tenant with more than one node, so "returns a node" and "returns the
    // ROOT" can disagree. With only the root present they cannot, and the test
    // would pass against a lookup that picked an arbitrary row.
    const root = await client.query<{ id: string }>(
      "select id from scope_nodes where org_id = $1 and kind = 'organization'",
      [orgId],
    );
    const rootId = root.rows[0]?.id ?? "";
    const team = await client.query<{ id: string }>(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'team', $2) returning id",
      [orgId, rootId],
    );
    const teamId = team.rows[0]?.id ?? "";
    await client.query("insert into teams (org_id, scope_node_id, slug, name) values ($1, $2, 'web', 'Web')", [
      orgId,
      teamId,
    ]);
    await client.query(
      "insert into scope_nodes (org_id, kind, parent_id) values ($1, 'project', $2)",
      [orgId, teamId],
    );

    await usingScratch(database, async () => {
      const ctx = contextForRequest({ orgId, userId, requestId: `r-${randomUUID()}` });
      const resolved = await organizationScopeNode(ctx);
      assert.equal(resolved, rootId);
      assert.notEqual(resolved, teamId, "a grant checked at the team node would miss everything beside it");
    });
  });
});

test("a tenant with no root node refuses rather than answering", { skip }, async () => {
  // Returning null or an empty string here would be worse than throwing: the
  // empty string is a scope node id that matches nothing, so every permission
  // check would quietly deny, and a whole tenant would look like a permissions
  // problem rather than a broken one.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    // The root node is created by a trigger, so removing it is the only way to
    // reach this state — which is the point: it should be unreachable, and the
    // code should still refuse if it is reached.
    await client.query("delete from scope_nodes where org_id = $1 and kind = 'organization'", [orgId]);

    await usingScratch(database, async () => {
      const ctx = contextForRequest({ orgId, userId, requestId: `r-${randomUUID()}` });
      await assert.rejects(() => organizationScopeNode(ctx), /no root scope node/);
    });
  });
});

test("no repository keeps a private copy of the lookup", () => {
  // The test that keeps the refactor. Three copies did not arrive by
  // carelessness — each author reasonably judged a ten-line helper not worth a
  // shared module, and each left a comment saying the others existed. A comment
  // does not stop the fourth.
  const offenders: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    const path = relative(ROOT, join(ROOT, file)).replaceAll("\\", "/");
    if (path === "src/repo/scope.ts") continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    if (/function\s+organizationScopeNode/.test(source)) {
      offenders.push(`${path} defines its own organizationScopeNode`);
    }
    // The query itself, wherever it is written. A copy under a different name
    // is the same duplication with the search made harder.
    if (path !== "src/repo/scope.ts" && /kind = 'organization'/.test(source)) {
      offenders.push(`${path} looks up the organization root directly`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "import organizationScopeNode or organizationScopeRef from src/repo/scope.ts instead. " +
      "A second copy is a second chance to resolve the wrong node, and a node resolved too " +
      "far up the tree fails OPEN.",
  );
});
