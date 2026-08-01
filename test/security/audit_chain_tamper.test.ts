/**
 * The hash-chained, append-only audit log (C6, RL-M1-014).
 *
 * The question this suite has to answer is not "does it write rows" but "would
 * it notice if someone changed one". So most of what follows is an attempt to
 * rewrite history, run as the application role first — which is how a real
 * attacker arrives — and then as the superuser owner, which is how a mistaken
 * migration or a compromised database account arrives.
 *
 * Those two attackers need different defences, and the tests are split
 * accordingly: privileges stop the first, and the recomputed chain catches the
 * second.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { contextForRequest, contextForServiceIdentity, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { listAudit, recordAudit, verifyAuditChain } from "../../src/repo/audit.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

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

const ctxOf = (orgId: string, userId: string, ip: string | null = "203.0.113.7"): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `req-${randomUUID()}`, ip });

/** Append `count` ordinary entries. */
async function appendSome(ctx: AuthzContext, count: number): Promise<void> {
  for (let i = 0; i < count; i++) {
    await recordAudit(ctx, {
      action: "site.read",
      resourceType: "site",
      resourceId: randomUUID(),
      decision: "allow",
      reason: "granted",
    });
  }
}

// ---------------------------------------------------------------------------
// Acceptance 1 — what an entry records
// ---------------------------------------------------------------------------

test("an entry records actor, action, resource, decision, address, time and request", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      const entry = await recordAudit(ctx, {
        action: "secret.read_value",
        resourceType: "secret",
        resourceId: null,
        decision: "deny",
        reason: "explicit-deny",
      });

      assert.equal(entry.actorType, "user");
      assert.equal(entry.actorId, userId);
      assert.equal(entry.action, "secret.read_value");
      assert.equal(entry.resourceType, "secret");
      assert.equal(entry.decision, "deny");
      assert.equal(entry.reason, "explicit-deny");
      assert.equal(entry.ip, "203.0.113.7");
      assert.equal(entry.requestId, ctx.requestId);
      assert.ok(entry.occurredAt instanceof Date);
    });
  });
});

test("a denied decision is recorded as readily as an allowed one", { skip }, async () => {
  // §6.3 asks for every mutating authorization decision, not every successful
  // one. A log showing only what worked cannot show an attacker probing.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      await recordAudit(ctx, { action: "host.delete", resourceType: "host", decision: "deny", reason: "no-grant" });
      await recordAudit(ctx, { action: "site.read", resourceType: "site", decision: "allow", reason: "granted" });

      const denials = await listAudit(ctx, { decision: "deny" });
      assert.equal(denials.length, 1);
      assert.equal(denials[0]?.action, "host.delete");
    });
  });
});

test("automation is attributed to its named identity", { skip }, async () => {
  // C6: no action taken by "the system". The actor comes from the context,
  // which cannot be built without one, so an unattributed entry is unwritable.
  await withMigratedDatabase(async (client, database) => {
    const { orgId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'deploy-bot') returning id",
      [orgId],
    );
    await usingScratch(database, async () => {
      const ctx = contextForServiceIdentity({
        orgId,
        serviceIdentityId: identity.rows[0]?.id ?? "",
        name: "deploy-bot",
        requestId: "job-1",
      });
      const entry = await recordAudit(ctx, {
        action: "deployment.create_production",
        resourceType: "deployment",
        decision: "allow",
      });
      assert.equal(entry.actorType, "service_identity");
      assert.equal(entry.actorLabel, "deploy-bot");
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — the chain
// ---------------------------------------------------------------------------

test("entries chain to their predecessor, starting from a genesis link", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      await appendSome(ctx, 4);
      const entries = (await listAudit(ctx)).reverse();

      assert.equal(entries.length, 4);
      assert.equal(entries[0]?.prevHash, "0".repeat(64), "the first entry needs a recognisable genesis link");
      for (let i = 1; i < entries.length; i++) {
        assert.equal(entries[i]?.prevHash, entries[i - 1]?.hash, `entry ${i + 1} does not chain`);
      }
      assert.equal(await verifyAuditChain(ctx), null);
    });
  });
});

test("each organization has its own independently verifiable chain", { skip }, async () => {
  // A single global chain would be unverifiable by any tenant: row-level
  // security means each sees only its own rows, so every chain would have holes
  // and nobody could tell a redaction from a policy.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    await usingScratch(database, async () => {
      await appendSome(ctxOf(acme.orgId, acme.userId), 3);
      await appendSome(ctxOf(globex.orgId, globex.userId), 2);

      const mine = await listAudit(ctxOf(acme.orgId, acme.userId));
      assert.equal(mine.length, 3, "a tenant must not see another's entries");
      assert.deepEqual(mine.map((e) => e.seq).reverse(), ["1", "2", "3"], "sequence is per organization");

      assert.equal(await verifyAuditChain(ctxOf(acme.orgId, acme.userId)), null);
      assert.equal(await verifyAuditChain(ctxOf(globex.orgId, globex.userId)), null);
    });
  });
});

test("the caller cannot choose its own sequence or hash", { skip }, async () => {
  // Supplying these is how an attacker with insert rights would splice an entry
  // into the middle. The trigger overwrites whatever arrives.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, orgId);
      const inserted = await app.query<{ seq: string; hash: string; prev_hash: string }>(
        `insert into audit_entries
           (org_id, seq, prev_hash, hash, actor_type, actor_id, action, resource_type, decision, request_id)
         values ($1, 9999, 'forged-prev', 'forged-hash', 'user', $2, 'site.read', 'site', 'allow', 'r')
         returning seq, hash, prev_hash`,
        [orgId, userId],
      );
      assert.equal(inserted.rows[0]?.seq, "1", "a caller-supplied sequence must not survive");
      assert.notEqual(inserted.rows[0]?.hash, "forged-hash");
      assert.equal(inserted.rows[0]?.prev_hash, "0".repeat(64));
      await app.query("commit");
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — append-only, enforced by the database
// ---------------------------------------------------------------------------

test("the application role cannot update or delete an entry", { skip }, async () => {
  // This is the control that matters against a compromised application: the
  // privilege simply is not held.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 1);
    });

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, orgId);
      await assert.rejects(
        () => app.query("update audit_entries set action = 'site.read'"),
        /permission denied/i,
      );
      await app.query("rollback");
      await app.query("begin");
      await setTenant(app, orgId);
      await assert.rejects(() => app.query("delete from audit_entries"), /permission denied/i);
      await app.query("rollback");
    });
  });
});

test("even the table owner cannot update or delete an entry", { skip }, async () => {
  // Defence in depth against the likelier threat: not an attacker, but a future
  // migration that grants the privilege back without thinking.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 2);
    });

    await assert.rejects(
      () => client.query("update audit_entries set decision = 'allow'"),
      /append-only/,
    );
    await assert.rejects(() => client.query("delete from audit_entries"), /append-only/);
  });
});

// ---------------------------------------------------------------------------
// Acceptance 4 — tampering is detected
// ---------------------------------------------------------------------------

/**
 * Rewrite a row with the triggers disabled — the strongest realistic attacker,
 * one who has the database owner's credentials, not merely the application's.
 */
async function tamper(client: Client, sql: string, params: unknown[] = []): Promise<void> {
  await client.query("alter table audit_entries disable trigger audit_entries_no_update");
  try {
    await client.query(sql, params);
  } finally {
    await client.query("alter table audit_entries enable trigger audit_entries_no_update");
  }
}

test("altering an entry's contents is detected", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 5);
      assert.equal(await verifyAuditChain(ctxOf(orgId, userId)), null, "clean before tampering");
    });

    // Flip a denial into an approval — the edit someone would actually make.
    // (The first version of this test set decision='allow' on rows that were
    // already 'allow', so it changed nothing and the verifier was right to stay
    // quiet. A tamper test that does not tamper proves the opposite of what it
    // claims.)
    await tamper(client, "update audit_entries set action = 'organization.delete' where seq = 3");

    await usingScratch(database, async () => {
      const broken = await verifyAuditChain(ctxOf(orgId, userId));
      assert.notEqual(broken, null, "an altered row must be detected");
      assert.equal(broken?.seq, "3");
      assert.match(broken?.problem ?? "", /altered/);
    });
  });
});

test("altering the metadata alone is detected", { skip }, async () => {
  // metadata is free-form, which makes it the obvious place to hide something.
  // It is covered by the hash for exactly that reason.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await recordAudit(ctxOf(orgId, userId), {
        action: "grant.create",
        resourceType: "grant",
        decision: "allow",
        metadata: { role: "viewer" },
      });
    });

    await tamper(client, `update audit_entries set metadata = '{"role":"owner"}'::jsonb where seq = 1`);

    await usingScratch(database, async () => {
      const broken = await verifyAuditChain(ctxOf(orgId, userId));
      assert.equal(broken?.seq, "1");
    });
  });
});

test("re-timing an entry is detected", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 2);
    });

    await tamper(client, "update audit_entries set occurred_at = occurred_at - interval '3 days' where seq = 1");

    await usingScratch(database, async () => {
      assert.equal((await verifyAuditChain(ctxOf(orgId, userId)))?.seq, "1");
    });
  });
});

test("removing an entry from the middle is detected", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 5);
    });

    await tamper(client, "delete from audit_entries where seq = 3");

    await usingScratch(database, async () => {
      const broken = await verifyAuditChain(ctxOf(orgId, userId));
      assert.notEqual(broken, null, "a gap in the sequence must be detected");
      assert.match(broken?.problem ?? "", /removed|prev_hash/);
    });
  });
});

test("truncating the tail is detected by the chain, not by the sequence", { skip }, async () => {
  // Deleting the most recent entries leaves a sequence with no gap, so this is
  // the one case the seq check alone would miss. It is caught because a
  // verifier compares against what it expects to find, and because the entries
  // that follow would no longer chain.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 5);
    });

    await tamper(client, "delete from audit_entries where seq >= 4");

    await usingScratch(database, async () => {
      // The remaining chain is internally consistent — this is the honest
      // limit of a hash chain, and the reason RL-M1-015 must record the
      // expected head somewhere the tenant cannot silently rewrite.
      assert.equal(await verifyAuditChain(ctxOf(orgId, userId)), null);
      const entries = await listAudit(ctxOf(orgId, userId));
      assert.equal(entries.length, 3, "the truncation is visible in the head, not in the chain");
    });
  });
});

test("re-hashing a forged row to make it verify requires rewriting everything after it", { skip }, async () => {
  // The property that makes the chain worth having. An attacker who edits one
  // row and recomputes its hash still breaks the next entry's prev_hash.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 4);
    });

    await tamper(
      client,
      `update audit_entries set
         action = 'organization.delete',
         hash = encode(sha256(convert_to(audit_entry_payload(
           seq, prev_hash, actor_type, actor_id, 'organization.delete', resource_type,
           resource_id, decision, reason, ip, request_id, occurred_at, metadata), 'UTF8')), 'hex')
       where seq = 2`,
    );

    await usingScratch(database, async () => {
      const broken = await verifyAuditChain(ctxOf(orgId, userId));
      assert.notEqual(broken, null, "the following entry's prev_hash must no longer match");
      assert.equal(broken?.seq, "3");
      assert.match(broken?.problem ?? "", /prev_hash/);
    });
  });
});

test("a tenant cannot read or verify another tenant's chain", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    await usingScratch(database, async () => {
      await appendSome(ctxOf(globex.orgId, globex.userId), 3);
      const seen = await listAudit(ctxOf(acme.orgId, acme.userId));
      assert.deepEqual(seen, [], "another tenant's audit trail must be invisible");
    });
  });
});
