/**
 * The audit log (C6, RL-M1-014).
 *
 * Brief §4 C6: "Every privileged action is auditable and attributable. No
 * action taken by 'the system' without a recorded actor."
 *
 * The actor is not a parameter here — it is taken from the AuthzContext, which
 * cannot be constructed without one (see src/authz/context.ts). So there is no
 * way to write an unattributed entry: not by forgetting, not by passing null,
 * not by a background job that has nobody to blame.
 *
 * Sequence, previous hash and hash are assigned by the database, never here.
 * An audit chain computed by the application it audits proves nothing (see the
 * migration's opening note).
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";

export type AuditRecord = {
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId?: string | null;
  readonly decision: "allow" | "deny";
  readonly reason?: string;
  /** Never a secret value — ADR 0006. This table is handed to people during incidents. */
  readonly metadata?: Readonly<Record<string, string | number | boolean | null>>;
};

export type AuditEntry = {
  readonly id: string;
  readonly seq: string;
  readonly hash: string;
  readonly prevHash: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly actorLabel: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly decision: string;
  readonly reason: string;
  readonly ip: string | null;
  readonly requestId: string;
  readonly occurredAt: Date;
  /**
   * Read back, not just written. An entry whose structured detail is
   * write-only is an entry an operator cannot act on — and RL-M1-026 trades
   * telling the caller nothing for telling the operator everything, which is
   * only a fair trade if the second half is reachable.
   */
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
};

type EntryRow = {
  id: string;
  seq: string;
  hash: string;
  prev_hash: string;
  actor_type: string;
  actor_id: string;
  actor_label: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  decision: string;
  reason: string;
  ip: string | null;
  request_id: string;
  occurred_at: Date;
  metadata: Record<string, string | number | boolean | null> | null;
};

const toEntry = (row: EntryRow): AuditEntry => ({
  id: row.id,
  seq: row.seq,
  hash: row.hash,
  prevHash: row.prev_hash,
  actorType: row.actor_type,
  actorId: row.actor_id,
  actorLabel: row.actor_label,
  action: row.action,
  resourceType: row.resource_type,
  resourceId: row.resource_id,
  decision: row.decision,
  reason: row.reason,
  ip: row.ip,
  requestId: row.request_id,
  occurredAt: row.occurred_at,
  // `jsonb` comes back parsed. Null becomes {} so every reader can index it
  // without a guard that would otherwise be forgotten at one call site.
  metadata: row.metadata ?? {},
});

/** A human-readable label for the actor, so a reader need not resolve an id. */
function labelOf(ctx: AuthzContext): string {
  return ctx.actor.kind === "service_identity" ? ctx.actor.name : "";
}

/**
 * Append one entry.
 *
 * Both allowed and denied decisions are recorded. §6.3 asks for "every mutating
 * authorization decision", not every successful one — a log that shows only what
 * worked cannot show an attacker probing.
 */
export async function recordAudit(ctx: AuthzContext, record: AuditRecord): Promise<AuditEntry> {
  return scoped(ctx, async (query) => {
    const rows = await query<EntryRow>(
      `insert into audit_entries
         (org_id, actor_type, actor_id, actor_label, action, resource_type,
          resource_id, decision, reason, ip, request_id, metadata)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       returning *`,
      [
        ctx.orgId,
        ctx.actor.kind,
        ctx.actor.id,
        labelOf(ctx),
        record.action,
        record.resourceType,
        record.resourceId ?? null,
        record.decision,
        record.reason ?? "",
        ctx.ip,
        ctx.requestId,
        JSON.stringify(record.metadata ?? {}),
      ],
    );
    const row = rows[0];
    if (row === undefined) throw new Error("the audit entry was not written");
    return toEntry(row);
  });
}

export type AuditQuery = {
  readonly actorId?: string;
  readonly action?: string;
  readonly decision?: "allow" | "deny";
  readonly limit?: number;
};

/** Recent entries for the current tenant, newest first. */
export async function listAudit(ctx: AuthzContext, filter: AuditQuery = {}): Promise<AuditEntry[]> {
  return scoped(ctx, async (query) => {
    const rows = await query<EntryRow>(
      `select * from audit_entries
       where ($1::uuid is null or actor_id = $1)
         and ($2::text is null or action = $2)
         and ($3::text is null or decision = $3)
       order by seq desc
       limit $4`,
      [filter.actorId ?? null, filter.action ?? null, filter.decision ?? null, filter.limit ?? 100],
    );
    return rows.map(toEntry);
  });
}

export type ChainBreak = { readonly seq: string; readonly problem: string };

/**
 * Verify this tenant's chain, returning the first break or null.
 *
 * Recomputes every hash from the row's own contents rather than trusting the
 * stored one, so a row altered by something able to bypass the triggers is
 * still caught. RL-M1-015 runs this on a schedule.
 */
export async function verifyAuditChain(ctx: AuthzContext): Promise<ChainBreak | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ broken_seq: string; problem: string }>(
      "select broken_seq, problem from verify_audit_chain($1)",
      [ctx.orgId],
    );
    const row = rows[0];
    return row === undefined ? null : { seq: row.broken_seq, problem: row.problem };
  });
}
