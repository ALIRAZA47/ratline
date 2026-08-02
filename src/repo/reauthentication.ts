/**
 * Freshness of authentication (RL-M1-037).
 *
 * ADR 0017 proposed this as the control an idle timeout was reaching for. The
 * difference is what it measures: an idle timeout asks the browser how long
 * since a request, which a polling dashboard answers on the operator's behalf;
 * this asks the operator to prove they still know the password, which nothing
 * can answer for them. And it binds to the moment of danger rather than to a
 * clock, so ordinary work costs nothing.
 *
 * ## Where the check lives, and why not in a route handler
 *
 * RL-M1-037's fourth acceptance: "the check lives with the action, not in a
 * route handler, so a second caller cannot skip it."
 *
 * It lives in `require()`. Every repository function that gates on a permission
 * already calls that, so a sensitive action cannot be reached without passing
 * through here — including by a caller written next year who has never heard of
 * re-authentication. A guard the caller has to remember is a guard the second
 * caller forgets, which is the same argument §9 makes about permission checks
 * in handlers, applied one layer along.
 *
 * `can()` deliberately does NOT check freshness. It answers "may this actor do
 * this", which is what the role editor's live preview asks (RL-M5-004) and what
 * the navigation rail asks — neither should demand a password. `require()`
 * answers "may they, right now, on this session", which is what a repository
 * about to do something asks.
 *
 * ## Fails closed on an unknown session
 *
 * A context with no session — a job, a migration, a service identity — cannot
 * prove freshness, and "we cannot tell" is not a reason to assume recent. So an
 * action in the policy's set is refused outright for those actors rather than
 * waved through. That is stricter than it needs to be for a background job and
 * it is the right direction: a job that legitimately needs a listed action
 * should be granted it by a policy that does not list it, not by a hole.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";

export type ReauthPolicy = {
  /** Catalogued action names. Empty means the control is off. */
  readonly actions: readonly string[];
  /** How recently a password must have been proved. Zero means "always ask". */
  readonly windowSeconds: number;
};

/** Off. What an organization that has never configured this gets. */
export const REAUTH_OFF: ReauthPolicy = { actions: [], windowSeconds: 900 };

/**
 * The organization's policy.
 *
 * An absent row means the control is off, matching how `two_factor_required`
 * reads absence (migration 12 note 7). Storing a row per organization by
 * default would be a row that exists to say nothing.
 */
export async function readReauthPolicy(ctx: AuthzContext): Promise<ReauthPolicy> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ reauth_actions: string[]; reauth_window_seconds: number }>(
      "select reauth_actions, reauth_window_seconds from organization_security_policies",
    );
    const row = rows[0];
    if (row === undefined) return REAUTH_OFF;
    return { actions: row.reauth_actions, windowSeconds: row.reauth_window_seconds };
  });
}

export type FreshnessVerdict =
  /** The action is not listed, so nothing is asked. */
  | { readonly fresh: true; readonly reason: "not-required" }
  /** Listed, and a password was proved recently enough. */
  | { readonly fresh: true; readonly reason: "recent" }
  /** Listed, and it was not. */
  | { readonly fresh: false; readonly reason: "stale" }
  /** Listed, and this actor has no session to measure. */
  | { readonly fresh: false; readonly reason: "no-session" };

/**
 * Is this action reachable on this session right now?
 *
 * `statement_timestamp()` rather than `now()`, for ADR 0012's reason: `now()`
 * is frozen for the whole transaction, so a long-running one would judge
 * freshness against when it started. Fifteen minutes is short enough that the
 * difference is reachable.
 */
export async function checkFreshness(ctx: AuthzContext, action: string): Promise<FreshnessVerdict> {
  const policy = await readReauthPolicy(ctx);
  if (!policy.actions.includes(action)) return { fresh: true, reason: "not-required" };
  if (ctx.sessionId === null) return { fresh: false, reason: "no-session" };

  return scoped(ctx, async (query) => {
    const rows = await query<{ fresh: boolean }>(
      // `live_sessions`, never `sessions`. Migration 10 note 3 is explicit that
      // reading the table directly to answer whether a session may act is "the
      // single mistake that would honour a revoked session" — and this question
      // is exactly that one, asked about a timestamp. The first version read the
      // table and a test caught it.
      `select authenticated_at > statement_timestamp() - make_interval(secs => $2::int) as fresh
       from live_sessions where id = $1`,
      [ctx.sessionId, policy.windowSeconds],
    );
    // A session that cannot be found is not fresh. It may have been revoked
    // between the request arriving and this query; assuming otherwise would
    // make a revoked session the most privileged one in the system.
    return rows[0]?.fresh === true
      ? { fresh: true, reason: "recent" }
      : { fresh: false, reason: "stale" };
  });
}

/**
 * Record that a password was just proved for this session.
 *
 * Called by the re-authentication endpoint after the password verifies, and by
 * sign-in when the session is created. Nothing else may call it — a function
 * that moves this timestamp is a function that grants privilege.
 */
export async function markAuthenticated(ctx: AuthzContext, sessionId: string): Promise<boolean> {
  // SELF ONLY, enforced in the statement rather than by the caller. The first
  // version took any session id and `repository_gating.test.ts` refused it,
  // correctly: this function moves the timestamp that grants privilege, so an
  // unscoped one would let anybody who can reach it refresh somebody else's
  // session into a re-authenticated state. There is no permission that should
  // allow that — proving a password is something only its owner can do — so the
  // predicate is the check, and it is not skippable by a caller.
  if (ctx.actor.kind !== "user") {
    throw new Error(
      `only a user proves a password, so refreshing authentication is not meaningful for a ` +
        `${ctx.actor.kind}.`,
    );
  }
  const userId = ctx.actor.id;

  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(
      // The UPDATE targets the table and the PREDICATE reads the view, so
      // liveness is expressed once, where migration 10 put it. Spelling out
      // "revoked_at is null and expires_at > …" here would be a second copy of
      // that predicate, free to drift — and it would drift open, because a
      // forgotten clause refreshes a dead session.
      `update sessions set authenticated_at = statement_timestamp()
       where id = (select id from live_sessions where id = $1 and user_id = $2)
       returning id`,
      [sessionId, userId],
    );
    return rows.length > 0;
  });
}
