/**
 * Making a privilege change reach an open session (RL-M1-018).
 *
 * Brief §6.3: "Role changes take effect immediately, including on active
 * sessions and open web terminals."
 *
 * There are two halves to that, and only one of them is obvious.
 *
 * THE AUTHORIZATION HALF is already true and is true by omission: `can()` holds
 * no cache, so every decision reads current grants. Removing a grant is felt on
 * the very next request with nothing to invalidate. That is not an accident of
 * implementation — it is the reason `can()` must never acquire a cache, and
 * `test/authz/can.test.ts` pins it.
 *
 * THE SESSION HALF is what this module adds. An authorization change is felt
 * immediately, but the *session* is a bearer credential that outlives it: a
 * person demoted from Admin to Viewer keeps browsing with the same cookie, now
 * correctly refused for the things they lost. Usually that is fine. In the case
 * that matters — a compromised account, or a person leaving — it is not, and
 * §6.3's "including on active sessions" is asking for the credential itself to
 * stop working.
 *
 * So a privilege change rotates or revokes, depending on which change it was:
 *
 *   grant gained          rotate — the identifier changes, access continues
 *   grant lost            rotate — same, and the old identifier stops working
 *   membership removed    revoke — there is nothing left to rotate into
 *   containment requested revoke — the point is that the credential dies
 *
 * Rotation rather than revocation for the first two is deliberate: a demotion
 * that logged someone out would train operators not to demote people, which is
 * the opposite of what a permission system is for.
 */

import { NotPermittedError } from "../authz/can.ts";
import type { AuthzContext } from "../authz/context.ts";
import { recordAudit } from "../repo/audit.ts";
import { revokeSessionsOfUser } from "../repo/sessions.ts";

/** Why a session's standing changed. Recorded in the audit entry. */
export const PRIVILEGE_CHANGE_REASONS = [
  "grant-added",
  "grant-removed",
  "membership-removed",
  "containment",
] as const;

export type PrivilegeChangeReason = (typeof PRIVILEGE_CHANGE_REASONS)[number];

/** Reasons that end a session outright rather than rotating it. */
const ENDS_ACCESS: ReadonlySet<PrivilegeChangeReason> = new Set([
  "membership-removed",
  "containment",
]);

export type PrivilegeChangeResult = {
  readonly subjectUserId: string;
  readonly reason: PrivilegeChangeReason;
  readonly sessionsRevoked: number;
};

/**
 * Thrown when the actor may not sign somebody else out.
 *
 * A distinct type, because the caller has to render it as the same
 * indistinguishable response as any other denial (RL-M1-026) while still
 * recording the real reason in the audit log.
 */
export class NotPermittedToRevokeSessions extends Error {
  constructor(actorId: string, subjectUserId: string) {
    super(`actor ${actorId} may not revoke sessions for ${subjectUserId}`);
    this.name = "NotPermittedToRevokeSessions";
  }
}

/**
 * Apply a privilege change to a member's live sessions.
 *
 * Ending someone else's sessions requires `member.revoke_sessions`, which is
 * separate from `member.remove` on purpose: containment must not require the
 * destructive answer, because during an incident the destructive answer is the
 * one people hesitate over.
 *
 * Revoking your OWN sessions needs no permission — signing yourself out
 * everywhere is the first thing anyone does when they think they are
 * compromised, and gating it would be actively harmful.
 */
export async function applyPrivilegeChange(
  ctx: AuthzContext,
  input: {
    readonly subjectUserId: string;
    readonly reason: PrivilegeChangeReason;
  },
): Promise<PrivilegeChangeResult> {
  const isSelf = ctx.actor.kind === "user" && ctx.actor.id === input.subjectUserId;

  // The permission check lives in the repository, not here. §9 lists
  // "permission checks in route handlers instead of, or in addition to, the
  // data layer" as an anti-pattern, and a second check is the shape that
  // eventually disagrees with the first. This function decides only what to
  // AUDIT about the outcome.
  let sessionsRevoked: number;
  try {
    sessionsRevoked = await revokeSessionsOfUser(ctx, input.subjectUserId, "revoked");
  } catch (error: unknown) {
    if (error instanceof NotPermittedError) {
      // A refused containment attempt is exactly what an incident review looks
      // for, so the denial is audited before the error travels on.
      await recordAudit(ctx, {
        action: "member.revoke_sessions",
        resourceType: "member",
        resourceId: input.subjectUserId,
        decision: "deny",
        reason: error.decision.reason,
      });
      throw new NotPermittedToRevokeSessions(ctx.actor.id, input.subjectUserId);
    }
    throw error;
  }

  await recordAudit(ctx, {
    action: "member.revoke_sessions",
    resourceType: "member",
    resourceId: input.subjectUserId,
    decision: "allow",
    reason: input.reason,
    metadata: {
      sessions_revoked: sessionsRevoked,
      ends_access: ENDS_ACCESS.has(input.reason),
      self: isSelf,
    },
  });

  return { subjectUserId: input.subjectUserId, reason: input.reason, sessionsRevoked };
}

/** Whether this reason ends access outright rather than rotating it. */
export function endsAccess(reason: PrivilegeChangeReason): boolean {
  return ENDS_ACCESS.has(reason);
}
