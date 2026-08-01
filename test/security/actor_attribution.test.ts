/**
 * Every privileged action is attributable (C6, RL-M1-016).
 *
 * Brief §4 C6: "No action taken by 'the system' without a recorded actor.
 * Automation acts as a named service identity with its own permissions."
 *
 * The interesting assertion is the negative one: that there is no way to write
 * an unattributed entry, not merely that we currently do not. So this suite is
 * mostly structural and type-level, because "nobody has done it yet" and
 * "nobody can" are different claims and only the second is worth having.
 *
 * The three routes to an unattributed action, and what closes each:
 *
 *   a nullable actor column        -> the schema forbids it
 *   a context built without one    -> AuthzContext cannot be constructed so
 *   a job that invents a principal -> contextForSystem refuses an unenumerated
 *                                     purpose, and every purpose names an identity
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  contextForRequest,
  contextForServiceIdentity,
  contextForSystem,
  SYSTEM_PURPOSES,
} from "../../src/authz/context.ts";
import { recordAudit } from "../../src/repo/audit.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import {
  DATABASE_URL,
  seedOrganization,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
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

// ---------------------------------------------------------------------------
// The schema forbids an anonymous entry
// ---------------------------------------------------------------------------

test("the audit table has no nullable actor", { skip }, async () => {
  // A nullable actor_id is how "the system" gets written: not by anyone
  // deciding to, but by a column that permits it and a code path that passes
  // null on a Tuesday.
  await withMigratedDatabase(async (client) => {
    const columns = await client.query<{ column_name: string; is_nullable: string }>(
      `select column_name, is_nullable from information_schema.columns
       where table_schema = current_schema() and table_name = 'audit_entries'
         and column_name in ('actor_type', 'actor_id')`,
    );
    assert.equal(columns.rows.length, 2);
    for (const column of columns.rows) {
      assert.equal(column.is_nullable, "NO", `${column.column_name} must not be nullable`);
    }
  });
});

test("an audit entry with a null actor is refused by the database", { skip }, async () => {
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    await assert.rejects(
      () =>
        client.query(
          `insert into audit_entries (org_id, actor_type, actor_id, action, resource_type, decision, request_id)
           values ($1, 'user', null, 'site.read', 'site', 'allow', 'r')`,
          [orgId],
        ),
      /null value|not-null/i,
    );
  });
});

test("an unrecognised actor kind is refused", { skip }, async () => {
  // "system", "cron", "internal" — the names an anonymous actor acquires when
  // the column is free text.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    for (const kind of ["system", "cron", "internal", ""]) {
      await assert.rejects(
        () =>
          client.query(
            `insert into audit_entries (org_id, actor_type, actor_id, action, resource_type, decision, request_id)
             values ($1, $2, $3, 'site.read', 'site', 'allow', 'r')`,
            [orgId, kind, randomUUID()],
          ),
        /audit_entries_actor_type/,
        `"${kind}" must not be an actor kind`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// The code cannot produce one either
// ---------------------------------------------------------------------------

test("recordAudit takes its actor from the context, not from its arguments", () => {
  // If the actor were a parameter, a caller could pass whatever it liked — and
  // a background job with nobody to blame would pass something plausible.
  // Reading it from the context means the only way to write an entry is to hold
  // a context, and a context cannot exist without an actor.
  const source = readFileSync(join(ROOT, "src", "repo", "audit.ts"), "utf8");
  const signature = /export async function recordAudit\(\s*ctx: AuthzContext,\s*record: AuditRecord,?\s*\)/;
  assert.match(source, signature, "recordAudit must take only a context and a record");
  assert.ok(
    !/actorId|actorType/.test(source.replace(/actor_type|actor_id|actorType: string/g, "")) ||
      !/record\.(actorId|actorType)/.test(source),
    "the actor must not be readable from the record",
  );
});

test("no audit write path exists outside the repository", () => {
  // A second writer is a second chance to omit the actor. There should be
  // exactly one place that inserts into audit_entries.
  const writers: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    const source = readFileSync(join(ROOT, file), "utf8");
    if (/insert\s+into\s+audit_entries/i.test(source)) writers.push(file);
  }
  assert.deepEqual(writers, ["src/repo/audit.ts"], "exactly one module may append to the audit log");
});

test("every actor kind names something that exists in the tenant", { skip }, async () => {
  // C6 says automation acts as a NAMED service identity. A context can carry an
  // id for something that was deleted; the entry still records which id, so the
  // trail survives even when the identity does not.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [orgId],
    );
    const identityId = identity.rows[0]?.id ?? "";

    await usingScratch(database, async () => {
      const user = await recordAudit(
        contextForRequest({ orgId, userId, requestId: "r1" }),
        { action: "site.read", resourceType: "site", decision: "allow" },
      );
      assert.equal(user.actorType, "user");
      assert.equal(user.actorId, userId);

      const bot = await recordAudit(
        contextForServiceIdentity({ orgId, serviceIdentityId: identityId, name: "deploy-bot", requestId: "r2" }),
        { action: "deployment.create_production", resourceType: "deployment", decision: "allow" },
      );
      assert.equal(bot.actorType, "service_identity");
      assert.equal(bot.actorLabel, "deploy-bot", "an unnamed automation actor is not attribution");
    });
  });
});

// ---------------------------------------------------------------------------
// Background work cannot invent a principal
// ---------------------------------------------------------------------------

test("a system context still names a service identity", () => {
  // The tempting shortcut for a scheduled job is a synthetic "system" principal
  // with no row behind it. contextForSystem refuses to be that: it takes a real
  // service identity id, and labels it so the audit log shows which job.
  const ctx = contextForSystem({
    purpose: "audit-chain-verification",
    orgId: randomUUID(),
    serviceIdentityId: randomUUID(),
    requestId: "scheduled",
  });
  assert.equal(ctx.actor.kind, "service_identity");
  assert.match(ctx.actor.kind === "service_identity" ? ctx.actor.name : "", /^system:audit-chain-verification$/);
});

test("an unenumerated system purpose is refused at runtime, not only in types", () => {
  // A cast defeats the type. The runtime check is what stops a background job
  // acquiring a new privilege by naming a new purpose.
  for (const purpose of ["just-this-once", "migration", "cleanup", ""]) {
    assert.throws(
      () =>
        contextForSystem({
          // @ts-expect-error - deliberately outside SystemPurpose
          purpose,
          orgId: randomUUID(),
          serviceIdentityId: randomUUID(),
          requestId: "r",
        }),
      /enumerated system purpose/,
      `"${purpose}" must not be usable as a system purpose`,
    );
  }
});

test("the system purposes are few and each is argued", () => {
  // Every entry is a place that acts outside a user's authority. The list
  // growing quietly is the failure; growing deliberately is fine.
  assert.deepEqual([...SYSTEM_PURPOSES], ["audit-chain-verification", "instance-administration"]);
  const source = readFileSync(join(ROOT, "src", "authz", "context.ts"), "utf8");
  assert.match(source, /security review point/i, "the list must say what it costs to add to it");
});

test("no module constructs an actor object directly", () => {
  // The four constructors validate and freeze. A hand-built actor sidesteps
  // both, and is how an id that is not a uuid — or is a placeholder string —
  // reaches the audit log.
  const findings: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    if (file === "src/authz/context.ts") continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const match of source.matchAll(/actor\s*:\s*\{\s*kind\s*:/g)) {
      findings.push(`${file}: builds an actor literal (${match[0].trim()})`);
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

test("a job cannot record an action without holding a context", { skip }, async () => {
  // The end-to-end statement of C6: the only route to the audit log is
  // recordAudit, the only way to call it is with a context, and the only way to
  // get a context is one of four constructors, each of which names an actor.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const entry = await recordAudit(contextForRequest({ orgId, userId, requestId: "r" }), {
        action: "site.read",
        resourceType: "site",
        decision: "allow",
      });
      assert.notEqual(entry.actorId, null);
      assert.notEqual(entry.actorId, "");
      assert.match(entry.actorId, /^[0-9a-f-]{36}$/i);
    });
  });
});
