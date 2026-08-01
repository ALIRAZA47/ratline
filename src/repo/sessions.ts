/**
 * Session and credential queries (RL-M1-017).
 *
 * Every rule the rest of `src/repo/` follows holds here:
 *
 *   - `ctx: AuthzContext` is the FIRST parameter of every exported function.
 *   - Nothing writes a tenant predicate by hand. `scoped()` binds the tenant for
 *     the transaction and row-level security applies it, so a forgotten
 *     `where org_id = …` changes nothing about what comes back.
 *   - Absent, revoked, expired and belonging-to-another-tenant are the same
 *     answer — `null` — because the query cannot tell them apart either.
 *
 * Three things are specific to this module and worth reading before changing it.
 *
 * **Liveness is read from `live_sessions`, never from `sessions`.** Migration 10
 * puts the expiry and revocation predicates in that view and nowhere else.
 * Asking `sessions` directly whether a session may act is the single mistake
 * that would honour a revoked one, which is why there is somewhere else to read.
 *
 * **The digest lookup is an indexed equality, not a constant-time comparison.**
 * That is deliberate and it matches `findApiTokenBySecret`. It is safe for the
 * same reason a plain digest is safe there: the identifier is 256 bits from a
 * CSPRNG, so there is no dictionary and nothing for a timing signal to narrow.
 * The constant-time comparison lives where it earns its keep, on the password,
 * in `src/auth/passwords.ts`.
 *
 * **Administrative revocation is gated by `member.remove`, as a deliberate
 * over-approximation.** `src/authz/catalogue.ts` records, in its KNOWN GAPS
 * list, that "revoking another member's active sessions" has no action yet and
 * arrives with RL-M1-018. Until it does, ending someone else's sessions is
 * gated on the ability to remove them from the organization outright. That can
 * only be too strict — anyone who may remove a member entirely may certainly end
 * that member's sessions — and erring in the other direction is what would be
 * dangerous. When RL-M1-018 adds the action, these two call sites change and
 * nothing else does.
 */

import { scoped, type ScopedQuery } from "../db/internal/handle.ts";
import { require as requirePermission } from "../authz/can.ts";
import type { AuthzContext } from "../authz/context.ts";
import { isSessionEndReason, sessionTokenDigest, type Session, type SessionEndReason } from "../auth/model.ts";
import type { ScopeRef } from "./authorization.ts";

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

type SessionRow = {
  id: string;
  org_id: string;
  user_id: string;
  created_at: Date;
  expires_at: Date;
  last_seen_at: Date | null;
  revoked_at: Date | null;
  revoked_reason: string | null;
  rotated_from: string | null;
  user_agent: string;
  ip: string | null;
};

/**
 * The columns a session is described by. Never `token_hash`: nothing outside
 * this file has any use for the digest, and a record that carried it would reach
 * a log line the first time somebody debugged a sign-in.
 *
 * `host(ip)` rather than `ip` because the column is `inet` and every consumer
 * wants the address without a netmask — the same shape `audit_entries` uses.
 */
const SESSION_COLUMNS = `
  id, org_id, user_id, created_at, expires_at, last_seen_at,
  revoked_at, revoked_reason, rotated_from, user_agent, host(ip) as ip`;

function toSession(row: SessionRow): Session {
  return {
    id: row.id,
    orgId: row.org_id,
    userId: row.user_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastSeenAt: row.last_seen_at,
    revokedAt: row.revoked_at,
    // Read back through the guard rather than cast. The column is constrained,
    // so a value this list does not know is a schema change nobody mirrored —
    // and null ("no ending recorded") is the safe reading of one.
    revokedReason: isSessionEndReason(row.revoked_reason) ? row.revoked_reason : null,
    rotatedFrom: row.rotated_from,
    userAgent: row.user_agent,
    ip: row.ip,
  };
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

/**
 * The tenant's root hierarchy node, which organization-scope questions ask
 * about.
 *
 * A copy of the helper in `src/repo/api_tokens.ts`, which is not exported.
 * Noted rather than fixed: it belongs in one place, and moving it means editing
 * that module, which this task does not own.
 */
async function organizationScopeNode(ctx: AuthzContext): Promise<string> {
  return scoped(ctx, async (query) => {
    // No tenant predicate: row-level security confines this to one
    // organization, which has exactly one root node.
    const rows = await query<{ id: string }>("select id from scope_nodes where kind = 'organization'");
    const row = rows[0];
    if (row === undefined) {
      throw new Error("this organization has no root scope node; the tenant is not usable");
    }
    return row.id;
  });
}

const organizationScope = (scopeNodeId: string): ScopeRef => ({ scopeNodeId, resourceId: null });

/**
 * Is this row the acting user's own?
 *
 * The same shape as `src/repo/api_tokens.ts`: a question about data, not about
 * permissions. Which action the answer selects, and whether the actor holds it,
 * is `can()`'s business.
 */
function isSelf(ctx: AuthzContext, userId: string): boolean {
  return ctx.actor.kind === "user" && ctx.actor.id === userId;
}

/** The acting user, or a refusal. Sessions belong to people, not to automation. */
function actingUser(ctx: AuthzContext, what: string): string {
  if (ctx.actor.kind !== "user") {
    throw new Error(
      `only a user has sessions of their own, so ${what} is not meaningful for a ${ctx.actor.kind}.`,
    );
  }
  return ctx.actor.id;
}

// ---------------------------------------------------------------------------
// The password credential
// ---------------------------------------------------------------------------

export type PasswordCredential = {
  readonly userId: string;
  readonly email: string;
  /**
   * The stored hash, or null for an account that has none — SSO-only, or never
   * set. Compared in `src/auth/passwords.ts`, in constant time.
   *
   * It is returned to the process rather than compared in SQL on purpose: `=`
   * in Postgres is not a constant-time comparison, and a password is exactly
   * the input where that matters.
   */
  readonly storedHash: string | null;
  readonly disabled: boolean;
};

type CredentialRow = { user_id: string; email: string; password_hash: string | null; disabled_at: Date | null };

/**
 * The credential for an email address in this tenant, or null.
 *
 * The join runs through `memberships`, which answers "is this person a member of
 * the organization they are signing in to" structurally rather than as a second
 * check somebody could forget. A person who exists on the installation but not
 * in this tenant is invisible here — migration 4's `users` policy sees to that
 * as well — so a sign-in form cannot be used to discover which accounts exist
 * elsewhere.
 *
 * Null for an address that matches nothing and for one that belongs to another
 * tenant. The caller cannot tell which, and neither can the query.
 */
export async function findPasswordCredential(
  ctx: AuthzContext,
  email: string,
): Promise<PasswordCredential | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<CredentialRow>(
      `select m.user_id, u.email::text as email, u.password_hash, u.disabled_at
       from memberships m
       join users u on u.id = m.user_id
       where u.email = $1`,
      [email],
    );
    const row = rows[0];
    if (row === undefined) return null;
    return {
      userId: row.user_id,
      email: row.email,
      storedHash: row.password_hash,
      disabled: row.disabled_at != null,
    };
  });
}

/**
 * Replace a person's own stored hash.
 *
 * Refuses to write anyone else's. An administrative password reset is a
 * different action with different consequences — it takes an account away from
 * the person holding it — and `src/authz/catalogue.ts` has no action for it, so
 * there is nothing to check an administrator against. Refusing is the honest
 * answer; adding an ungated one here and a check in a route handler later is the
 * shape brief §9 rejects outright.
 */
export async function updatePasswordHash(
  ctx: AuthzContext,
  userId: string,
  storedHash: string,
): Promise<boolean> {
  if (!isSelf(ctx, userId)) {
    throw new Error(
      "a password can only be replaced by the person it belongs to. An administrative reset " +
        "needs a catalogued action to check anyone against, and there is not one yet.",
    );
  }
  return scoped(ctx, async (query) => {
    // Scoped through memberships so the write cannot reach a person outside this
    // tenant, the same way the read above is.
    const rows = await query<{ id: string }>(
      `update users set password_hash = $2
       where id = $1 and exists (select 1 from memberships m where m.user_id = users.id)
       returning id`,
      [userId, storedHash],
    );
    return rows.length > 0;
  });
}

// ---------------------------------------------------------------------------
// Creating a session
// ---------------------------------------------------------------------------

export type NewSession = {
  readonly userId: string;
  /** The digest of the identifier. The identifier itself never arrives here. */
  readonly tokenDigest: string;
  readonly expiresAt: Date;
  /** The session this one replaces, or null when it starts a fresh chain. */
  readonly rotatedFrom: string | null;
  readonly userAgent: string;
  readonly ip: string | null;
};

/**
 * The one INSERT. Shared by {@link startSession} and
 * {@link replaceSession} so there is a single place a session comes into
 * existence.
 *
 * The row is selected out of `memberships` rather than assembled from
 * parameters, which makes "a session belongs to a member of this tenant" a
 * property of the statement: a user who is not a member matches no row and the
 * insert writes nothing. `current_tenant()` supplies the organization, so there
 * is no argument a caller could get wrong and no way to aim this at another
 * tenant — row-level security would refuse it anyway; this makes the attempt
 * unwriteable.
 */
async function writeSession(query: ScopedQuery, input: NewSession): Promise<Session> {
  const rows = await query<SessionRow>(
    `insert into sessions (org_id, user_id, token_hash, expires_at, rotated_from, user_agent, ip)
     select current_tenant(), m.user_id, $2::text, $3::timestamptz, $4::uuid, $5::text, $6::inet
     from memberships m
     where m.user_id = $1::uuid
     returning ${SESSION_COLUMNS}`,
    [input.userId, input.tokenDigest, input.expiresAt, input.rotatedFrom, input.userAgent, input.ip],
  );
  const row = rows[0];
  if (row === undefined) {
    throw new Error(
      "no session was written: the account is not a member of this organization. A session " +
        "names one person acting in one organization (migration 10), so there is nothing to create.",
    );
  }
  return toSession(row);
}

/** Start a session for a person who has just proved who they are. */
export async function startSession(ctx: AuthzContext, input: NewSession): Promise<Session> {
  return scoped(ctx, (query) => writeSession(query, input));
}

// ---------------------------------------------------------------------------
// Using one
// ---------------------------------------------------------------------------

/**
 * The live session this identifier names, with its last-seen stamped, or null.
 *
 * Null for an identifier that matches nothing, for a revoked or expired session,
 * and for one belonging to another tenant — the caller cannot tell which,
 * because neither can the query. The lookup is by digest, so the identifier is
 * never compared against anything stored: there is nothing stored to compare it
 * against.
 *
 * This DIFFERS from `recordApiTokenUse`, deliberately. There, finding a token
 * and recording its use are two calls; here they are one statement. A session's
 * last-seen is how a stolen cookie is noticed after the fact, and a separate
 * call is a call that can be forgotten — by a new route, by a middleware
 * reordering, by anyone who did not know it existed. Folding it into the lookup
 * costs one UPDATE against a unique index instead of one SELECT, and makes the
 * tracking a property of validating rather than of remembering.
 */
export async function useSessionToken(ctx: AuthzContext, token: string): Promise<Session | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<SessionRow>(
      // The subquery reads the liveness view, so a revoked or expired session
      // matches nothing and is not even touched. `statement_timestamp()` is the
      // clock throughout (migration 10, ADR 0012).
      `update sessions set last_seen_at = statement_timestamp()
       where id = (select live.id from live_sessions live where live.token_hash = $1)
       returning ${SESSION_COLUMNS}`,
      [sessionTokenDigest(token)],
    );
    const row = rows[0];
    return row === undefined ? null : toSession(row);
  });
}

// ---------------------------------------------------------------------------
// Ending one
// ---------------------------------------------------------------------------

/**
 * The UPDATE that ends a live session. Shared so revocation has one shape.
 *
 * `exists (… live_sessions …)` rather than `revoked_at is null`: a session that
 * has expired is already dead, and re-marking it would move its `revoked_at`
 * away from the moment anything actually happened. It also makes revocation
 * idempotent — a second call ends nothing, and a caller that could tell "already
 * revoked" from "never existed" would have an oracle for other people's session
 * identifiers.
 */
const END_SESSION = `
  update sessions
  set revoked_at = statement_timestamp(), revoked_reason = $1
  where exists (select 1 from live_sessions live where live.id = sessions.id)`;

/**
 * Revoke the session this identifier names. The session as it was, or null.
 *
 * No permission check: holding the identifier IS the authority to end it. That
 * is signing out, and it is also the first half of rotation.
 */
export async function revokeSessionByToken(
  ctx: AuthzContext,
  token: string,
  reason: SessionEndReason,
): Promise<Session | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<SessionRow>(
      `${END_SESSION} and sessions.token_hash = $2 returning ${SESSION_COLUMNS}`,
      [reason, sessionTokenDigest(token)],
    );
    const row = rows[0];
    return row === undefined ? null : toSession(row);
  });
}

export type SessionReplacement = {
  /** The identifier being retired. */
  readonly presentedToken: string;
  readonly reason: SessionEndReason;
  /** The digest of the identifier taking its place. */
  readonly tokenDigest: string;
  readonly expiresAt: Date;
  readonly userAgent: string;
  readonly ip: string | null;
};

/**
 * Retire one identifier and issue another to the same person, in ONE
 * transaction.
 *
 * This is the rotation acceptance 2 requires, and the reason it is a single
 * repository function rather than two calls from `src/auth/` is atomicity: two
 * transactions can be interrupted between them, and the interesting half of that
 * — old one dead, new one never written — would sign somebody out mid-request.
 * Committing together means the outcome is either "rotated" or "nothing
 * happened", and there is no moment at which two live identifiers exist for one
 * chain.
 *
 * Null when the presented identifier is not live. A dead identifier cannot be
 * exchanged for a fresh one; if it could, revocation would be a speed bump.
 *
 * Membership is re-checked by `writeSession`, so someone removed from the
 * organization since their last request cannot rotate their way onward.
 */
export async function replaceSession(
  ctx: AuthzContext,
  input: SessionReplacement,
): Promise<{ ended: Session; started: Session } | null> {
  return scoped(ctx, async (query) => {
    const ended = await query<SessionRow>(
      `${END_SESSION} and sessions.token_hash = $2 returning ${SESSION_COLUMNS}`,
      [input.reason, sessionTokenDigest(input.presentedToken)],
    );
    const row = ended[0];
    if (row === undefined) return null;

    const started = await writeSession(query, {
      userId: row.user_id,
      tokenDigest: input.tokenDigest,
      expiresAt: input.expiresAt,
      rotatedFrom: row.id,
      userAgent: input.userAgent,
      ip: input.ip,
    });
    return { ended: toSession(row), started };
  });
}

/** Who a session belongs to, or null when it is absent or in another tenant. */
async function holderOf(ctx: AuthzContext, sessionId: string): Promise<string | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ user_id: string }>("select user_id from sessions where id = $1", [
      sessionId,
    ]);
    return rows[0]?.user_id ?? null;
  });
}

/**
 * Revoke one session by identity — the "sign out that other browser" case, and
 * the administrative "end that session" case.
 *
 * True when it was live and is not any more. False for a session that is absent,
 * in another tenant, or already over.
 */
export async function revokeSessionById(
  ctx: AuthzContext,
  sessionId: string,
  reason: SessionEndReason,
): Promise<boolean> {
  const holder = await holderOf(ctx, sessionId);
  if (holder === null) return false;
  if (!isSelf(ctx, holder)) {
    await requirePermission(ctx, "member.remove", organizationScope(await organizationScopeNode(ctx)));
  }
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(`${END_SESSION} and sessions.id = $2 returning id`, [
      reason,
      sessionId,
    ]);
    return rows.length > 0;
  });
}

/**
 * Revoke every live session a person holds in this tenant, and say how many
 * there were.
 *
 * The compromised-account case: one call, no list to work through, no session
 * left behind because it was not on the screen. Brief §6.3 asks for exactly this
 * shape for API tokens ("an obvious revoke-all") and the reasoning transfers
 * without change — a laptop is missing, and every credential it held has to stop
 * working now rather than at the next sweep.
 *
 * Already-dead sessions are not counted, so the number means "credentials this
 * ended" rather than "rows this touched".
 */
export async function revokeSessionsOfUser(
  ctx: AuthzContext,
  userId: string,
  reason: SessionEndReason,
): Promise<number> {
  if (!isSelf(ctx, userId)) {
    await requirePermission(ctx, "member.remove", organizationScope(await organizationScopeNode(ctx)));
  }
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(`${END_SESSION} and sessions.user_id = $2 returning id`, [
      reason,
      userId,
    ]);
    return rows.length;
  });
}

/**
 * Every session the acting user holds in this tenant, live or not, newest first.
 *
 * Ended sessions are included on purpose: "these are your sessions" means seeing
 * that the one you killed on Tuesday is dead, not seeing it vanish.
 *
 * There is no listing of anyone ELSE's sessions here. A person's session list
 * carries their addresses and devices, and reading it needs an action the
 * catalogue does not have yet (RL-M1-018). An ungated one would be worse than
 * its absence.
 */
export async function listOwnSessions(ctx: AuthzContext): Promise<Session[]> {
  const userId = actingUser(ctx, "listing your sessions");
  return scoped(ctx, async (query) => {
    const rows = await query<SessionRow>(
      `select ${SESSION_COLUMNS} from sessions where user_id = $1 order by created_at desc, id`,
      [userId],
    );
    return rows.map(toSession);
  });
}
