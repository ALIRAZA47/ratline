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
  // C6 says automation acts as a NAMED service identity. RL-M1-053: this test
  // carried its title without checking it. Its old comment conceded that "a
  // context can carry an id for something that was deleted" and stopped there,
  // which quietly covered a second case the title does not allow — an id for
  // something that NEVER existed. Deletion is defensible and is still allowed
  // (see the ghost tests below and migration 14's argument for why this is a
  // write-time check and not a foreign key). Never-existed is not, and the title
  // asserts the property either way.
  //
  // So the entry is now JOINED back to the identity it names. An audit row that
  // cannot be resolved to a row is the exact experience an incident reviewer got
  // before this, and asserting it here rather than only in the schema means the
  // claim is checked from the side that reads the log.
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

    // The reviewer's query, run as the reviewer would run it: resolve each
    // entry's actor to a row in the table its kind names.
    const resolved = await client.query<{ actor_type: string; actor_id: string; resolved: string | null }>(
      `select a.actor_type, a.actor_id,
              case a.actor_type
                when 'user' then (select u.name from users u
                                  join memberships m on m.user_id = u.id
                                  where u.id = a.actor_id and m.org_id = a.org_id)
                when 'service_identity' then (select s.name from service_identities s
                                              where s.id = a.actor_id and s.org_id = a.org_id)
                when 'api_token' then (select t.name from api_tokens t
                                       where t.id = a.actor_id and t.org_id = a.org_id)
              end as resolved
       from audit_entries a where a.org_id = $1 order by a.seq`,
      [orgId],
    );

    assert.ok(resolved.rows.length >= 2, "the two entries above must be in the log");
    for (const row of resolved.rows) {
      assert.notEqual(
        row.resolved,
        null,
        `audit actor ${row.actor_type}:${row.actor_id} resolves to nothing — ` +
          `"attributable" then rests on the caller-supplied label alone (C6)`,
      );
    }
  });
});

// ---------------------------------------------------------------------------
// A ghost actor is refused by the database (RL-M1-053)
// ---------------------------------------------------------------------------

test("an audit entry naming an actor that does not exist is refused", { skip }, async () => {
  // The defect: actor_id was `uuid not null` with no reference, so any 128 bits
  // were accepted. An incident reviewer joining audit_entries to
  // service_identities got nothing back, and C6's "attributable" rested on a
  // label the caller chose.
  //
  // Refused by the database, not by the repository: recordAudit is the only
  // writer today, and "the only writer is careful" is a convention. This runs as
  // the migrator, past every layer of application code, which is the only way to
  // show the schema itself objects.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const insert = `insert into audit_entries
        (org_id, actor_type, actor_id, action, resource_type, decision, request_id)
      values ($1, $2, $3, 'site.read', 'site', 'allow', 'r')`;

    for (const kind of ["user", "service_identity", "api_token"]) {
      await assert.rejects(
        () => client.query(insert, [orgId, kind, randomUUID()]),
        /does not exist in organization/,
        `a ghost ${kind} must not be recordable as an actor`,
      );
    }

    // The specific value src/main.ts used to pass while an installation was
    // unclaimed. Named here so a future reintroduction of a placeholder uuid
    // fails on the value itself rather than on a general rule.
    await assert.rejects(
      () => client.query(insert, [orgId, "service_identity", "00000000-0000-4000-8000-000000000000"]),
      /does not exist in organization/,
      "a placeholder identity is a ghost like any other",
    );
  });
});

test("another tenant's real identity is not an actor here", { skip }, async () => {
  // Existence alone is not attribution. An id that resolves in a different
  // organization names a row nobody in THIS tenant could have acted as, and the
  // entry would look attributable to anyone who did not check the org.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const other = await seedOrganization(client, "other");
    const theirs = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [other.orgId],
    );

    await assert.rejects(
      () =>
        client.query(
          `insert into audit_entries
             (org_id, actor_type, actor_id, action, resource_type, decision, request_id)
           values ($1, 'service_identity', $2, 'site.read', 'site', 'allow', 'r')`,
          [orgId, theirs.rows[0]?.id ?? ""],
        ),
      /does not exist in organization/,
    );
  });
});

test("a user who exists but is not a member of the tenant is not an actor here", { skip }, async () => {
  // `users` is global — one person, many organizations — so "exists" is not the
  // question. The suite's title says "in the tenant", and for a person that means
  // membership.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const stranger = await client.query<{ id: string }>(
      "insert into users (email, name) values ('stranger@elsewhere.example', 'Stranger') returning id",
    );

    await assert.rejects(
      () =>
        client.query(
          `insert into audit_entries
             (org_id, actor_type, actor_id, action, resource_type, decision, request_id)
           values ($1, 'user', $2, 'site.read', 'site', 'allow', 'r')`,
          [orgId, stranger.rows[0]?.id ?? ""],
        ),
      /does not exist in organization/,
    );
  });
});

test("an entry whose actor is deleted afterwards survives", { skip }, async () => {
  // The property migration 14 protects by NOT being a foreign key, asserted so a
  // future change to a real key fails here rather than silently taking audit
  // history with it. The record of what somebody did must outlive their account —
  // that is most of what an audit log is for.
  await withMigratedDatabase(async (client) => {
    const { orgId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'retired-bot') returning id",
      [orgId],
    );
    const identityId = identity.rows[0]?.id ?? "";

    await client.query(
      `insert into audit_entries
         (org_id, actor_type, actor_id, actor_label, action, resource_type, decision, request_id)
       values ($1, 'service_identity', $2, 'retired-bot', 'site.read', 'site', 'allow', 'r')`,
      [orgId, identityId],
    );

    await client.query("delete from service_identities where id = $1", [identityId]);

    const kept = await client.query<{ actor_id: string; actor_label: string }>(
      "select actor_id, actor_label from audit_entries where org_id = $1 and actor_id = $2",
      [orgId, identityId],
    );
    assert.equal(kept.rows.length, 1, "deleting an identity must not delete what it did");
    assert.equal(kept.rows[0]?.actor_label, "retired-bot");
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
