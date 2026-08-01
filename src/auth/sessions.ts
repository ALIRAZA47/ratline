/**
 * Sign-in, session lifetime and revocation (RL-M1-017).
 *
 * The functions an interface calls. Every query behind them is in
 * `src/repo/sessions.ts`, because C3 (ADR 0003 layer 1) puts the database
 * handle out of reach of everything except the repository layer; what lives
 * here is the order things happen in, and the decisions about it.
 *
 * ## Session fixation, which is acceptance 3
 *
 * Fixation is the attack where an identifier the attacker planted before
 * sign-in is still honoured after it. Two things close it, and the first is the
 * one that matters:
 *
 *   1. **A presented identifier is never adopted.** {@link signIn} always mints
 *      a fresh one. There is no code path anywhere in this module that turns an
 *      identifier supplied by a client into an authenticated one, so there is
 *      nothing to fix in place — the property is structural rather than a check
 *      somebody remembered to write.
 *   2. **A presented identifier is revoked.** Anything the client was carrying
 *      is ended at sign-in, before the new session exists, so a planted
 *      identifier is not merely unused afterwards — it is dead, with a recorded
 *      reason and time. The ordering is deliberate: interrupted between the two
 *      steps, the outcome is "nobody is signed in", never "two live
 *      identifiers".
 *
 * The same rotation runs on a privilege change ({@link rotateSession}), which
 * acceptance 2 also requires. And because a session names one organization
 * (migration 10), moving between organizations is a privilege change that
 * cannot be skipped: the old identifier names the old tenant and is invisible
 * from the new one.
 *
 * ## The context a sign-in runs in — a real seam, reported rather than papered over
 *
 * Every function here takes an `AuthzContext`, because everything reaches the
 * database and `scoped()` binds one tenant per transaction. That has a
 * consequence worth stating plainly: **a sign-in attempt needs a context before
 * there is anybody to attribute it to.** `contextForRequest` wants a user id,
 * and the sign-in request is precisely the one that has none yet.
 *
 * Nothing here invents a way around that, because `src/authz/context.ts` is
 * where such a decision belongs and this task does not own it. Two options exist
 * and the interface layer (RL-M1-024) has to pick one:
 *
 *   - **A named service identity.** `contextForServiceIdentity` already exists
 *     and C6 already says automation acts as one — a sign-in attempt is an
 *     action taken before any user is identified, which is exactly the case C6
 *     describes. This needs no new constructor, and it is what
 *     `test/security/session_fixation.test.ts` uses for the pre-authentication
 *     calls, so the shape is exercised rather than assumed.
 *   - **A `contextForSignInAttempt`** whose actor kind is explicitly
 *     unauthenticated. Cleaner to read, and an addition to a module whose whole
 *     point is that its constructors are enumerated and reviewed.
 *
 * Either way, the actor on the context is NOT consulted by anything in this
 * module that authenticates. Identity comes from the row, and the row is
 * reachable only by presenting the secret that names it.
 */

import type { AuthzContext } from "../authz/context.ts";
import {
  findPasswordCredential,
  listOwnSessions,
  replaceSession,
  revokeSessionById,
  revokeSessionByToken,
  revokeSessionsOfUser,
  startSession,
  updatePasswordHash,
  useSessionToken,
} from "../repo/sessions.ts";
import {
  DEFAULT_SESSION_LIFETIME_MS,
  mintSessionToken,
  sessionTokenDigest,
  type Session,
} from "./model.ts";
import { hashPassword, needsRehash, verifyPassword } from "./passwords.ts";

/** A session and the identifier that names it. The identifier exists only here. */
export type IssuedSession = {
  readonly session: Session;
  /**
   * The plaintext identifier, the only time it exists outside the caller's
   * memory. Set it in a cookie and forget it; it is not recoverable, because
   * what the database holds is a digest.
   */
  readonly token: string;
};

/**
 * Why a sign-in was refused.
 *
 * FOR THE AUDIT LOG, NOT FOR THE RESPONSE. Brief §6.3's acceptance gate
 * requires that nonexistent and unauthorized be indistinguishable to the
 * caller, so an interface must render every value here as one message and one
 * status. The distinction exists because an operator reading the audit log at
 * 2am needs it and because the remedies differ — "that address has no account
 * here" and "that account has no password, it signs in through SSO" send a
 * support ticket to different places.
 *
 * The timing does not distinguish them either: {@link signIn} performs a full
 * key derivation on every path, including the one where no account was found.
 */
export const SIGN_IN_REFUSALS = [
  "unknown-account",
  "credential-rejected",
  "account-disabled",
  "no-password-set",
] as const;

export type SignInRefusal = (typeof SIGN_IN_REFUSALS)[number];

export type SignInResult =
  | (IssuedSession & {
      readonly ok: true;
      /**
       * The stored hash was made with weaker parameters than the ones in use
       * now. Signing in is the only moment the password exists in plaintext,
       * so it is the only moment it can be upgraded — see
       * {@link setOwnPassword}. Ignoring this is not a fault, it just leaves
       * that account at the parameters it was created with.
       */
      readonly mustRehash: boolean;
    })
  | { readonly ok: false; readonly refusal: SignInRefusal };

export type SignInInput = {
  readonly email: string;
  readonly password: string;
  /**
   * Whatever identifier the client was already carrying, if any.
   *
   * It is revoked, never adopted. Passing it is what closes the fixation case
   * for a planted identifier; omitting it is safe but leaves the planted one
   * alive until it expires, so an interface should always pass what it received.
   */
  readonly presentedToken?: string | null;
  readonly userAgent?: string;
  readonly ip?: string | null;
  /** Overrides {@link DEFAULT_SESSION_LIFETIME_MS}. Absolute, never extended. */
  readonly lifetimeMs?: number;
};

function expiryFrom(lifetimeMs: number | undefined): Date {
  return new Date(Date.now() + (lifetimeMs ?? DEFAULT_SESSION_LIFETIME_MS));
}

/**
 * Authenticate a password and start a session.
 *
 * The order below is the security-relevant part:
 *
 *   1. Look the account up — through `memberships`, so an address that belongs
 *      to another tenant is not found at all.
 *   2. **Derive, unconditionally.** Even when step 1 found nothing, so that the
 *      time taken says nothing about whether the account exists. ADR 0003 is
 *      honest that response timing is not fully closed in v1; this is the one
 *      place where closing it is free, because the work happens anyway on the
 *      path that succeeds.
 *   3. Decide, and refuse with a reason that is for the audit log only.
 *   4. Revoke whatever the client was carrying.
 *   5. Mint a new identifier.
 *
 * Steps 4 and 5 are in that order on purpose. Interrupted between them, nobody
 * is signed in — which is the failure worth having.
 */
export async function signIn(ctx: AuthzContext, input: SignInInput): Promise<SignInResult> {
  const credential = await findPasswordCredential(ctx, input.email);

  // Step 2. `verifyPassword` performs a full derivation against a throwaway
  // salt when there is no stored hash, so this line costs the same whether or
  // not the account exists. It is deliberately not inside a conditional.
  const matched = await verifyPassword(credential?.storedHash ?? null, input.password);

  if (credential === null) return { ok: false, refusal: "unknown-account" };
  if (credential.disabled) return { ok: false, refusal: "account-disabled" };
  if (credential.storedHash === null) return { ok: false, refusal: "no-password-set" };
  if (!matched) return { ok: false, refusal: "credential-rejected" };

  // Step 4. Whatever the client presented ends here, whoever it belonged to.
  let ended: Session | null = null;
  const presented = input.presentedToken ?? "";
  if (presented.length > 0) {
    ended = await revokeSessionByToken(ctx, presented, "rotated");
  }

  // Step 5. A fresh identifier, always. Nothing the client supplied is reused.
  const token = mintSessionToken();
  const session = await startSession(ctx, {
    userId: credential.userId,
    tokenDigest: sessionTokenDigest(token),
    expiresAt: expiryFrom(input.lifetimeMs),
    // The chain is recorded only when the retired session belonged to the same
    // person. A planted identifier belongs to the attacker, and calling the
    // victim's new session its successor would write the attacker's fiction
    // into our own audit trail.
    rotatedFrom: ended !== null && ended.userId === credential.userId ? ended.id : null,
    userAgent: input.userAgent ?? "",
    ip: input.ip ?? null,
  });

  return { ok: true, session, token, mustRehash: needsRehash(credential.storedHash) };
}

/**
 * The live session this identifier names, or null.
 *
 * Null for an identifier that matches nothing, one that has been revoked, one
 * that has expired, and one belonging to another tenant. The caller cannot tell
 * which, because the query cannot either.
 *
 * Revocation and expiry are predicates on the view this reads, evaluated with
 * `statement_timestamp()` — so a session revoked a millisecond ago is already
 * gone here, with no job having run and none existing to run (migration 10,
 * ADR 0012).
 *
 * Calling this stamps the session's last-seen. See `useSessionToken` for why
 * that is folded into the lookup rather than left to the caller.
 */
export async function validateSession(ctx: AuthzContext, token: string): Promise<Session | null> {
  return useSessionToken(ctx, token);
}

/** Why an identifier is being replaced. A rotation is never recorded as a sign-out. */
export type RotationReason = "rotated" | "privilege-change";

export type RotationInput = {
  readonly userAgent?: string;
  readonly ip?: string | null;
  readonly lifetimeMs?: number;
};

/**
 * Replace a live identifier with a new one for the same person.
 *
 * Acceptance 2's other half: "session identifiers rotate on privilege change".
 * Call this whenever what the holder may do changes — a grant added or removed,
 * a role edited, a break-glass elevation starting or ending — so that the
 * identifier in the browser is never older than the authority behind it.
 *
 * Null when the presented identifier is not live. A dead identifier cannot be
 * exchanged for a fresh one; if it could, revocation would be a speed bump.
 * Both halves commit in one transaction (`replaceSession`), so there is no
 * instant at which one chain has two live identifiers.
 */
export async function rotateSession(
  ctx: AuthzContext,
  token: string,
  reason: RotationReason,
  input: RotationInput = {},
): Promise<IssuedSession | null> {
  const next = mintSessionToken();
  const result = await replaceSession(ctx, {
    presentedToken: token,
    reason,
    tokenDigest: sessionTokenDigest(next),
    expiresAt: expiryFrom(input.lifetimeMs),
    // The request doing the rotating is the one to record, not the request that
    // started the session being retired.
    userAgent: input.userAgent ?? "",
    ip: input.ip ?? null,
  });
  return result === null ? null : { session: result.started, token: next };
}

/** End the session this identifier names. True when it was live and is not now. */
export async function signOut(ctx: AuthzContext, token: string): Promise<boolean> {
  return (await revokeSessionByToken(ctx, token, "signed-out")) !== null;
}

/**
 * End one session by identity — "sign out that other browser", and the
 * administrative case.
 *
 * Ending someone else's requires `member.remove`; see the header of
 * `src/repo/sessions.ts` for why that action and not another.
 */
export async function revokeSession(ctx: AuthzContext, sessionId: string): Promise<boolean> {
  return revokeSessionById(ctx, sessionId, "revoked");
}

/**
 * End every live session a person holds in this tenant, and say how many there
 * were.
 *
 * The compromised-account case. Immediate, because liveness is a predicate on
 * every lookup rather than a cache to invalidate or a job to wait for: the very
 * next {@link validateSession} reads a view that no longer contains these rows.
 */
export async function revokeAllSessions(ctx: AuthzContext, userId: string): Promise<number> {
  return revokeSessionsOfUser(ctx, userId, "revoked");
}

/** Every session the acting user holds in this tenant, newest first, live or not. */
export async function listSessions(ctx: AuthzContext): Promise<Session[]> {
  return listOwnSessions(ctx);
}

/**
 * Replace the acting user's own password, and end every session it was holding
 * open.
 *
 * The revocation is written FIRST, and the order is the whole point. Written
 * the other way round, a failure between the two steps leaves the new password in
 * place and the old sessions alive — which is the exact state somebody changing
 * their password because they think they have been compromised was trying to
 * leave. This way a failure leaves the old password working and the sessions
 * dead, which is inconvenient and safe.
 *
 * The caller is signed out by this, including on the device that called it. Mint
 * a new session, or send them back to the sign-in form.
 *
 * Returns how many sessions were ended.
 */
export async function setOwnPassword(ctx: AuthzContext, password: string): Promise<number> {
  if (ctx.actor.kind !== "user") {
    throw new Error(
      `only a user has a password; this context acts as a ${ctx.actor.kind}. Automation ` +
        `authenticates with a credential of its own, never with somebody's password.`,
    );
  }
  const stored = await hashPassword(password);
  const ended = await revokeSessionsOfUser(ctx, ctx.actor.id, "password-changed");
  const written = await updatePasswordHash(ctx, ctx.actor.id, stored);
  if (!written) {
    throw new Error("the password was not written: this account is not a member of this organization.");
  }
  return ended;
}
