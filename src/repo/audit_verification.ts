/**
 * Scheduled audit chain verification (RL-M1-015).
 *
 * RL-M1-014 recorded a limit rather than hiding it: a hash chain cannot detect
 * truncation of its own head, because the evidence is the part that was
 * removed. Verification alone reports clean on a log somebody shortened.
 *
 * What closes that is remembering where the head was last time, outside the
 * chain, and refusing a head that moved backwards. See migration 9 for why the
 * watermark lives in its own append-only table.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import { require as requirePermission } from "../authz/can.ts";
import { organizationScopeRef } from "./scope.ts";

/**
 * `truncated` is the outcome this whole mechanism exists for: the chain
 * verifies perfectly AND is shorter than it was, which is what a deletion from
 * the end looks like from the inside.
 */
export const VERIFICATION_OUTCOMES = ["clean", "broken", "truncated"] as const;
export type VerificationOutcome = (typeof VERIFICATION_OUTCOMES)[number];

export type VerificationResult = {
  readonly outcome: VerificationOutcome;
  readonly detail: string;
  readonly headSeq: string;
};

export type VerificationRun = {
  readonly outcome: VerificationOutcome;
  readonly detail: string;
  readonly headSeq: string;
  readonly entriesSeen: string;
  readonly verifiedAt: Date;
};

function asOutcome(value: string): VerificationOutcome {
  // Anything unrecognised is treated as broken, not clean. A verification
  // result the code does not understand is not evidence of health.
  return VERIFICATION_OUTCOMES.includes(value as VerificationOutcome)
    ? (value as VerificationOutcome)
    : "broken";
}

/**
 * Verify the current tenant's chain and record the run.
 *
 * Recording is not optional and not a separate call: an unrecorded verification
 * leaves no watermark, so the next run has nothing to compare against and
 * truncation becomes invisible again.
 */
export async function runAuditVerification(ctx: AuthzContext): Promise<VerificationResult> {
  // Gated even though the only caller today is the background job, because the
  // job runs as a NAMED service identity (`contextForSystem`) rather than as an
  // anonymous task — which was the whole point of building it that way. A named
  // actor that bypasses permissions is a named actor in name only, so the
  // deployment must grant its identity the permission below.
  //
  // `audit_log.read` rather than a verify action of its own. Writing
  // "audit_log.verify" was the first attempt and there is no such action: the
  // catalogue has exactly one audit permission. `can()` denied it as
  // `unknown-action`, which is the right failure and is why nothing leaked —
  // but nothing CAUGHT it either, because `require()` takes a plain string.
  // Recorded as RL-M1-044.
  //
  // Splitting verification into its own action is defensible and is not this
  // fix's call to make: it would change who can trip an integrity check, which
  // is a permission-model decision.
  await requirePermission(ctx, "audit_log.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<{ outcome: string; detail: string; head_seq: string }>(
      "select outcome, detail, head_seq from run_audit_verification($1)",
      [ctx.orgId],
    );
    const row = rows[0];
    if (row === undefined) throw new Error("audit verification returned no result");
    return { outcome: asOutcome(row.outcome), detail: row.detail, headSeq: row.head_seq };
  });
}

/** Verification history, newest first — what the interface shows. */
export async function listAuditVerifications(
  ctx: AuthzContext,
  limit = 20,
): Promise<VerificationRun[]> {
  await requirePermission(ctx, "audit_log.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<{
      outcome: string;
      detail: string;
      head_seq: string;
      entries_seen: string;
      verified_at: Date;
    }>(
      `select outcome, detail, head_seq, entries_seen, verified_at
       from audit_verifications order by verified_at desc limit $1`,
      [limit],
    );
    return rows.map((row) => ({
      outcome: asOutcome(row.outcome),
      detail: row.detail,
      headSeq: row.head_seq,
      entriesSeen: row.entries_seen,
      verifiedAt: row.verified_at,
    }));
  });
}

/**
 * The most recent run, or null if verification has never run.
 *
 * Null is not "healthy". A tenant whose chain has never been verified is in a
 * different state from one verified a minute ago, and the interface has to show
 * the difference — "unknown" and "clean" are not the same answer.
 */
export async function lastAuditVerification(ctx: AuthzContext): Promise<VerificationRun | null> {
  const runs = await listAuditVerifications(ctx, 1);
  return runs[0] ?? null;
}
