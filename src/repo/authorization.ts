/**
 * Authorization reads (RL-M1-012).
 *
 * `can()` lives in src/authz/ and holds no database handle — C3 keeps that
 * inside src/repo/. So the decision function asks these questions and does the
 * deciding itself.
 *
 * Everything here is a read. Nothing in this module grants, revokes or elevates.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import { isAllowed, RESOLUTION_OBJECTS, type Decision, type SubjectType } from "../authz/grants.ts";

export type ScopeRef = {
  /** The hierarchy node the question is about. */
  readonly scopeNodeId: string;
  /**
   * The specific resource, when the question is about one.
   *
   * Resource is the fifth hierarchy level and owns no scope node, so a
   * resource-scoped grant cannot resolve by ancestry (ADR 0012). Passing null
   * when the question IS about a resource silently widens the answer — it drops
   * resource-scoped denies, which fails open — so callers must be explicit.
   */
  readonly resourceId: string | null;
};

/**
 * Ask the database for the allow/deny decision covering `roleKeys` at `scope`.
 *
 * Precedence, inheritance and expiry all live in `grant_decision` (ADR 0012).
 * Re-implementing any of them here would give two answers to one question.
 */
export async function resolveGrantDecision(
  ctx: AuthzContext,
  subjectType: SubjectType,
  subjectId: string,
  roleKeys: readonly string[],
  scope: ScopeRef,
): Promise<Decision> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ decision: string }>(
      `select ${RESOLUTION_OBJECTS.decision}($1, $2, $3, $4, $5) as decision`,
      [subjectType, subjectId, scope.scopeNodeId, roleKeys, scope.resourceId],
    );
    // A missing row is not "no opinion", it is a denial — and anything other
    // than a literal "allow" denies, so a value the database learns to return
    // later fails closed rather than open.
    //
    // The comparison itself is isAllowed() rather than written out here. It was
    // duplicated inline at first, and mutation testing showed the copy could be
    // inverted to the fail-open form with no test noticing: the two agree on
    // every value grant_decision actually returns today, and differ only on the
    // ones that would matter. One implementation, one test.
    return isAllowed(rows[0]?.decision ?? "") ? "allow" : "deny";
  });
}

/**
 * Is there an ALLOW reaching this subject at this scope, ignoring denies?
 *
 * Used only to explain a denial. `grant_decision` answers "deny" both for an
 * explicit deny and for no grant at all, and those need different remedies —
 * "ask someone for access" versus "someone deliberately took it away". An
 * operator reading an audit log at 2am should not have to guess which.
 *
 * This must never be used to decide anything: it ignores denies by design, so
 * treating it as an authorization answer would invert the precedence rule that
 * ADR 0012 puts in the database.
 */
export async function hasAllowingGrant(
  ctx: AuthzContext,
  subjectType: SubjectType,
  subjectId: string,
  roleKeys: readonly string[],
  scope: ScopeRef,
): Promise<boolean> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ present: boolean }>(
      `select exists (
         select 1 from ${RESOLUTION_OBJECTS.effectiveGrants}($1, $2, $3, $4) g
         where g.effect = 'allow' and g.role_key = any($5)
       ) as present`,
      [subjectType, subjectId, scope.scopeNodeId, scope.resourceId, roleKeys],
    );
    return rows[0]?.present === true;
  });
}

export type ActorStatus = {
  readonly exists: boolean;
  readonly disabled: boolean;
};

/**
 * Whether the actor exists in this tenant and is still enabled.
 *
 * "May this actor act at all" is one question per request, not one per
 * hierarchy node, which is why it is separate from grant resolution (threat
 * model R-13). A disabled account whose grants are intact must still be
 * refused, and a disabled account is the shape a compromised one is put into.
 */
export async function findActorStatus(
  ctx: AuthzContext,
  subjectType: SubjectType,
  subjectId: string,
): Promise<ActorStatus> {
  return scoped(ctx, async (query) => {
    if (subjectType === "user") {
      // Scoped through memberships: a user is only an actor here if they belong
      // to this tenant. Row-level security already confines the join.
      const rows = await query<{ disabled_at: Date | null }>(
        `select u.disabled_at
         from memberships m join users u on u.id = m.user_id
         where m.user_id = $1`,
        [subjectId],
      );
      const row = rows[0];
      return { exists: row !== undefined, disabled: row?.disabled_at != null };
    }

    if (subjectType === "service_identity") {
      const rows = await query<{ disabled_at: Date | null }>(
        "select disabled_at from service_identities where id = $1",
        [subjectId],
      );
      const row = rows[0];
      return { exists: row !== undefined, disabled: row?.disabled_at != null };
    }

    // An API token (RL-M1-032). A revoked or expired token is a disabled actor,
    // which is exactly what `disabled` means here — "may this actor act at all",
    // asked once per request rather than once per node. That is why it is
    // answered here rather than as another branch of the decision: a revoked
    // token and a disabled user are the same question with the same answer, and
    // both are the shape a compromised credential is put into.
    //
    // The two questions are asked as two EXISTS against different relations on
    // purpose. Liveness lives in `live_api_tokens` and nowhere else (migration
    // 7), so writing `revoked_at is null and expires_at > ...` here would be a
    // second copy of the predicate, free to drift from the first — and the way
    // it would drift is open, because a forgotten clause honours a dead token.
    const rows = await query<{ present: boolean; live: boolean }>(
      `select
         exists (select 1 from api_tokens where id = $1) as present,
         exists (select 1 from live_api_tokens where id = $1) as live`,
      [subjectId],
    );
    const row = rows[0];
    return { exists: row?.present === true, disabled: row?.live !== true };
  });
}

/** Does this scope node exist in the current tenant? */
export async function scopeNodeExists(ctx: AuthzContext, scopeNodeId: string): Promise<boolean> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>("select id from scope_nodes where id = $1", [scopeNodeId]);
    return rows.length > 0;
  });
}
