/**
 * Scheduled audit chain verification (RL-M1-015).
 *
 * RL-M1-014 left one gap on purpose and wrote it down: a hash chain cannot
 * detect truncation of its own head, because the evidence is the part that was
 * removed. Verification alone reports clean on a shortened log — and the newest
 * entries are exactly what someone covering their tracks would remove.
 *
 * Most of this suite is about that gap. The rest is about the other way a
 * verification job fails: by noticing and saying nothing.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Client } from "pg";

import { contextForRequest, type AuthzContext } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { recordAudit } from "../../src/repo/audit.ts";
import {
  lastAuditVerification,
  listAuditVerifications,
  runAuditVerification,
} from "../../src/repo/audit_verification.ts";
import {
  AuditChainCompromised,
  verificationContext,
  verifyAuditChainForTenant,
  type VerificationAlert,
} from "../../src/jobs/audit_verification_job.ts";
import {
  DATABASE_URL,
  seedOrganization,
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

const ctxOf = (orgId: string, userId: string): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `req-${randomUUID()}` });

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

/** Rewrite history with the append-only trigger disabled. */
async function tamper(client: Client, sql: string): Promise<void> {
  await client.query("alter table audit_entries disable trigger audit_entries_no_update");
  try {
    await client.query(sql);
  } finally {
    await client.query("alter table audit_entries enable trigger audit_entries_no_update");
  }
}

// ---------------------------------------------------------------------------
// Acceptance 1 — verification runs and records its own result
// ---------------------------------------------------------------------------

test("a clean chain verifies and the run is recorded", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      await appendSome(ctx, 3);

      const result = await runAuditVerification(ctx);
      assert.equal(result.outcome, "clean");
      assert.equal(result.headSeq, "3");

      const runs = await listAuditVerifications(ctx);
      assert.equal(runs.length, 1, "the run itself must be recorded, or there is no watermark");
      assert.equal(runs[0]?.entriesSeen, "3");
    });
  });
});

test("an organization with no entries is clean at head zero, not an error", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const result = await runAuditVerification(ctxOf(orgId, userId));
      assert.equal(result.outcome, "clean");
      assert.equal(result.headSeq, "0");
    });
  });
});

test("never verified and verified clean are different states", { skip }, async () => {
  // The interface must not present "unknown" as "healthy". A tenant whose chain
  // has never been checked is in a different position from one checked a minute
  // ago, and only one of them is reassuring.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      assert.equal(await lastAuditVerification(ctx), null, "never verified must be distinguishable");
      await runAuditVerification(ctx);
      assert.notEqual(await lastAuditVerification(ctx), null);
    });
  });
});

// ---------------------------------------------------------------------------
// The gap RL-M1-014 recorded: truncation of the head
// ---------------------------------------------------------------------------

test("truncating the tail is caught by the watermark, which the chain cannot do", { skip }, async () => {
  // THE test for this task. The chain is internally perfect after truncation —
  // every prev_hash matches and every hash recomputes — so verification alone
  // reports clean. Only the remembered head reveals it.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      await appendSome(ctx, 6);
      assert.equal((await runAuditVerification(ctx)).outcome, "clean");
    });

    await tamper(client, "delete from audit_entries where seq >= 4");

    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      const result = await runAuditVerification(ctx);
      assert.equal(result.outcome, "truncated", "a shortened log must not report clean");
      assert.match(result.detail, /head moved backwards/);
      assert.match(result.detail, /3 entries were removed/);
    });
  });
});

test("a replaced head at the same position is caught", { skip }, async () => {
  // Rebuilding the chain wholesale keeps the sequence length and so slips past
  // a length comparison. The stored hash is what catches it.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 3);
      assert.equal((await runAuditVerification(ctxOf(orgId, userId))).outcome, "clean");
    });

    // Re-hash the head so the chain still verifies internally, but its content
    // differs from what the last run recorded.
    await tamper(
      client,
      `update audit_entries set
         action = 'organization.delete',
         hash = encode(sha256(convert_to(audit_entry_payload(
           seq, prev_hash, actor_type, actor_id, 'organization.delete', resource_type,
           resource_id, decision, reason, ip, request_id, occurred_at, metadata), 'UTF8')), 'hex')
       where seq = 3`,
    );

    await usingScratch(database, async () => {
      const result = await runAuditVerification(ctxOf(orgId, userId));
      assert.notEqual(result.outcome, "clean", "a replaced head must not report clean");
    });
  });
});

test("a growing chain is not mistaken for a tampered one", { skip }, async () => {
  // The watermark must only fire on backwards movement. If ordinary growth
  // tripped it, the alert would be ignored within a day.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      const ctx = ctxOf(orgId, userId);
      await appendSome(ctx, 2);
      assert.equal((await runAuditVerification(ctx)).outcome, "clean");
      await appendSome(ctx, 5);
      assert.equal((await runAuditVerification(ctx)).outcome, "clean");
      await appendSome(ctx, 1);
      assert.equal((await runAuditVerification(ctx)).outcome, "clean");
    });
  });
});

test("an altered entry is still reported as broken, not truncated", { skip }, async () => {
  // The two failures need different responses: broken means the contents
  // changed, truncated means entries are gone. Reporting one as the other sends
  // an incident in the wrong direction.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 4);
      await runAuditVerification(ctxOf(orgId, userId));
    });

    await tamper(client, "update audit_entries set action = 'host.delete' where seq = 2");

    await usingScratch(database, async () => {
      const result = await runAuditVerification(ctxOf(orgId, userId));
      assert.equal(result.outcome, "broken");
      assert.match(result.detail, /entry 2/);
    });
  });
});

test("the verification history is itself append-only", { skip }, async () => {
  // A watermark an attacker can edit is not a watermark. After truncating the
  // log they would simply rewrite the record of where the head used to be.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 2);
      await runAuditVerification(ctxOf(orgId, userId));
    });

    await assert.rejects(
      () => client.query("update audit_verifications set head_seq = 0"),
      /append-only/,
    );
    await assert.rejects(() => client.query("delete from audit_verifications"), /append-only/);
  });
});

test("one tenant's verification history is invisible to another", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedOrganization(client, "acme");
    const globex = await seedOrganization(client, "globex");
    await usingScratch(database, async () => {
      await appendSome(ctxOf(globex.orgId, globex.userId), 2);
      await runAuditVerification(ctxOf(globex.orgId, globex.userId));
      assert.deepEqual(await listAuditVerifications(ctxOf(acme.orgId, acme.userId)), []);
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — a broken chain alerts rather than failing silently
// ---------------------------------------------------------------------------

test("the job alerts and raises on a broken chain", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'audit-verifier') returning id",
      [orgId],
    );
    // RL-M1-043 gated the verification reads, so the verifier now needs the
    // permission its own module says the deployment must grant it. A named
    // service identity that bypassed permissions would be named in name only.
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'admin', 'organization')`,
      [orgId, identity.rows[0]?.id ?? ""],
    );

    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 3);
    });
    await tamper(client, "update audit_entries set decision = 'deny' where seq = 2");

    await usingScratch(database, async () => {
      const alerts: VerificationAlert[] = [];
      const ctx = verificationContext({
        orgId,
        serviceIdentityId: identity.rows[0]?.id ?? "",
        requestId: "scheduled-1",
      });

      await assert.rejects(
        () => verifyAuditChainForTenant(ctx, { onAlert: (a) => void alerts.push(a) }),
        (error: unknown) => {
          assert.ok(error instanceof AuditChainCompromised);
          assert.match(error.message, /no longer be trusted/);
          return true;
        },
        "a broken chain must fail the job, not merely log",
      );

      assert.equal(alerts.length, 1, "the alert must fire even though the job then fails");
      assert.equal(alerts[0]?.outcome, "broken");
    });
  });
});

test("the job records every run, including clean ones", { skip }, async () => {
  // "When was this last checked" is the first question asked in an incident,
  // and a log that records only failures cannot answer it.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'audit-verifier') returning id",
      [orgId],
    );
    // RL-M1-043 gated the verification reads, so the verifier now needs the
    // permission its own module says the deployment must grant it. A named
    // service identity that bypassed permissions would be named in name only.
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'admin', 'organization')`,
      [orgId, identity.rows[0]?.id ?? ""],
    );

    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 2);
      const ctx = verificationContext({
        orgId,
        serviceIdentityId: identity.rows[0]?.id ?? "",
        requestId: "scheduled-1",
      });

      const outcome = await verifyAuditChainForTenant(ctx, {
        onAlert: () => assert.fail("a clean chain must not alert"),
      });
      assert.equal(outcome.result.outcome, "clean");
      assert.equal(outcome.alerted, false);

      const runs = await listAuditVerifications(ctx);
      assert.equal(runs.length, 1);
    });
  });
});

test("the verifier is attributed to a named service identity", { skip }, async () => {
  // C6. The audit entry the job writes records who verified; "the system" is
  // not an acceptable answer.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    const identity = await client.query<{ id: string }>(
      "insert into service_identities (org_id, name) values ($1, 'audit-verifier') returning id",
      [orgId],
    );
    // RL-M1-043 gated the verification reads, so the verifier now needs the
    // permission its own module says the deployment must grant it. A named
    // service identity that bypassed permissions would be named in name only.
    await client.query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'service_identity', $2, 'admin', 'organization')`,
      [orgId, identity.rows[0]?.id ?? ""],
    );
    const identityId = identity.rows[0]?.id ?? "";

    await usingScratch(database, async () => {
      await appendSome(ctxOf(orgId, userId), 1);
      const ctx = verificationContext({ orgId, serviceIdentityId: identityId, requestId: "scheduled-1" });
      await verifyAuditChainForTenant(ctx, { onAlert: () => assert.fail("should be clean") });
    });

    const entries = await client.query<{ actor_type: string; actor_id: string; actor_label: string }>(
      "select actor_type, actor_id, actor_label from audit_entries where org_id = $1 order by seq desc limit 1",
      [orgId],
    );
    assert.equal(entries.rows[0]?.actor_type, "service_identity");
    assert.equal(entries.rows[0]?.actor_id, identityId);
    assert.match(entries.rows[0]?.actor_label ?? "", /^system:audit-chain-verification$/);
  });
});
