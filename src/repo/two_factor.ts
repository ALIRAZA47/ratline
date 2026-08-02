/**
 * Two-factor enrolment, recovery codes, challenges and the organization policy
 * (RL-M1-019).
 *
 * Every rule the rest of `src/repo/` follows holds here:
 *
 *   - `ctx: AuthzContext` is the FIRST parameter of every exported function.
 *   - Nothing writes a tenant predicate by hand. `scoped()` binds the tenant for
 *     the transaction and row-level security applies it.
 *   - Absent, spent, expired and belonging-to-another-tenant are the same
 *     answer, because the query cannot tell them apart either.
 *
 * Five things are specific to this module and worth reading before changing it.
 *
 * **NO EXPORTED FUNCTION TAKES A USER ID EXCEPT THE TWO THAT ONLY READ
 * BOOLEANS.** Everything that writes or reads a second factor derives the person
 * from something the caller has already proved: `ctx.actor` for a signed-in
 * person, or a live challenge for one who has just presented a password. That is
 * deliberate and it is the main defence in this file. A function that accepted a
 * user id would be one refactor away from letting a member enrol a factor for
 * somebody else, and there is no catalogued action to check them against if it
 * did — see the KNOWN GAP note at the foot of this file.
 *
 * **A CHALLENGE MAY NOT REPLACE A CONFIRMED ENROLMENT.** This is the single
 * sharpest rule here. An attacker who knows a password but not the factor
 * receives a challenge like anybody else; if that challenge could be used to
 * start a fresh enrolment, they would simply enrol their own authenticator and
 * two-factor authentication would be decorative. So {@link startEnrolment}
 * refuses the `challenge` subject whenever a confirmed enrolment exists, and the
 * refusal is a property of the INSERT's own predicate rather than a check above
 * it. The `self` subject may replace, because holding a session already means
 * having passed the factor being replaced.
 *
 * **CONSUMING A FACTOR AND CONSUMING THE CHALLENGE HAPPEN IN ONE TRANSACTION,
 * IN THAT ORDER, UNDER A LOCK TAKEN FIRST.** {@link redeemChallenge} locks the
 * challenge row by digest before it touches anything, so two concurrent
 * redemptions serialise. The factor is consumed first and the challenge second,
 * so that a WRONG code leaves both intact — a typo must not cost a full
 * re-authentication, and the rate limiter is what bounds retries
 * (`AUTH_RATE_LIMITS["two-factor"]`), not the destruction of the challenge.
 *
 * **THE SEALED SECRET IS RETURNED TO THE PROCESS, AND THAT IS THE ONE PLACE
 * THIS DIRECTORY DIFFERS FROM `api_tokens.ts`.** That module can say "there is
 * no function here that returns a stored secret" because a token is a digest.
 * A TOTP secret has to be recomputed against, so it is encrypted rather than
 * hashed (migration 12 note 2) and it does come back out — sealed. Opening it
 * needs the key-encryption key, which lives on disk and never in this database,
 * so what crosses this boundary is ciphertext.
 *
 * **THE POLICY IS READABLE WITHOUT A PERMISSION, AND WRITEABLE ONLY WITH ONE.**
 * The read happens on the sign-in path, before there is an actor to check
 * anything against, and the value is not a secret in any case: an organization
 * that requires a second factor announces that fact to every person who signs
 * in, by construction. Writing it is `organization.manage_security_policy`.
 */

import { scoped, type ScopedQuery } from "../db/internal/handle.ts";
import { require as requirePermission } from "../authz/can.ts";
import type { AuthzContext } from "../authz/context.ts";
import { challengeTokenDigest } from "../auth/model.ts";
import { isTotpAlgorithm, type TotpAlgorithm } from "../auth/totp.ts";
import { organizationScopeRef } from "./scope.ts";

// ---------------------------------------------------------------------------
// Who is acting, and how they proved it
// ---------------------------------------------------------------------------

/**
 * The two authorities that reach a person's second factor.
 *
 * There is no third, and in particular there is no "this administrator, acting
 * for that member". Neither variant carries a user id: the id is derived here,
 * from the context or from the challenge row, so a caller cannot name somebody
 * else even by accident.
 */
export type FactorSubject =
  /** A signed-in person acting on their own enrolment. */
  | { readonly kind: "self" }
  /** Someone who has just presented a correct password and owes a second factor. */
  | { readonly kind: "challenge"; readonly challengeToken: string };

/** The acting user, or a refusal. A second factor belongs to a person, not to automation. */
function actingUser(ctx: AuthzContext, what: string): string {
  if (ctx.actor.kind !== "user") {
    throw new Error(
      `only a user has a second factor of their own, so ${what} is not meaningful for a ` +
        `${ctx.actor.kind}. Automation authenticates with a credential of its own.`,
    );
  }
  return ctx.actor.id;
}

/**
 * The tenant's root hierarchy node, which organization-scope questions ask about.
 *
 * The third copy of this helper — `src/repo/api_tokens.ts` and
 * `src/repo/sessions.ts` have the other two, and the second one already carries
 * this note. Recorded rather than fixed for the same reason: it belongs in one
 * place, and moving it means editing two modules this task does not own.
 */

// ---------------------------------------------------------------------------
// The organization policy
// ---------------------------------------------------------------------------

export type SecurityPolicy = {
  /** Brief §6.3: "enforced 2FA as org-level policies". */
  readonly twoFactorRequired: boolean;
  /** Null when this organization has never set a policy. */
  readonly updatedAt: Date | null;
  /**
   * Null when nobody has set it, and also null when it was set by automation —
   * the column references `users`, and a service identity is not one. The
   * attribution of record is the audit entry `src/auth/two_factor.ts` writes,
   * which names any actor kind (C6); this column is a convenience for the
   * settings screen.
   */
  readonly updatedBy: string | null;
};

type PolicyRow = { two_factor_required: boolean; updated_at: Date; updated_by: string | null };

const NO_POLICY: SecurityPolicy = Object.freeze({
  twoFactorRequired: false,
  updatedAt: null,
  updatedBy: null,
});

/**
 * This organization's security policy, or the default when it has never set one.
 *
 * Absence is not an error and is not null: migration 12 note 7 makes "no row"
 * mean "nothing is required", so every organization has an answer without
 * anything having had to create a row for it.
 *
 * No permission check. See the module header.
 */
export async function readSecurityPolicy(ctx: AuthzContext): Promise<SecurityPolicy> {
  return scoped(ctx, async (query) => {
    const rows = await query<PolicyRow>(
      "select two_factor_required, updated_at, updated_by from organization_security_policies",
    );
    const row = rows[0];
    if (row === undefined) return NO_POLICY;
    return {
      twoFactorRequired: row.two_factor_required,
      updatedAt: row.updated_at,
      updatedBy: row.updated_by,
    };
  });
}

/**
 * Set this organization's security policy.
 *
 * Gated on `organization.manage_security_policy`, whose catalogue description
 * already names this setting by name. The check is here, in the data layer,
 * rather than in whatever eventually serves `PUT /organization/security-policy`
 * — brief §9 lists a route-handler check as an anti-pattern precisely because a
 * second caller forgets it.
 */
export async function writeSecurityPolicy(
  ctx: AuthzContext,
  input: { readonly twoFactorRequired: boolean },
): Promise<SecurityPolicy> {
  await requirePermission(
    ctx,
    "organization.manage_security_policy",
    await organizationScopeRef(ctx),
  );
  const setBy = ctx.actor.kind === "user" ? ctx.actor.id : null;

  return scoped(ctx, async (query) => {
    const rows = await query<PolicyRow>(
      // `current_tenant()` rather than a parameter: the tenant comes from the
      // transaction, so there is no argument a caller could get wrong and no
      // way to aim this at another organization.
      `insert into organization_security_policies (org_id, two_factor_required, updated_by)
       values (current_tenant(), $1, $2)
       on conflict (org_id) do update
          set two_factor_required = excluded.two_factor_required,
              updated_at = statement_timestamp(),
              updated_by = excluded.updated_by
       returning two_factor_required, updated_at, updated_by`,
      [input.twoFactorRequired, setBy],
    );
    const row = rows[0];
    if (row === undefined) throw new Error("the security policy was not written");
    return {
      twoFactorRequired: row.two_factor_required,
      updatedAt: row.updated_at,
      updatedBy: row.updated_by,
    };
  });
}

// ---------------------------------------------------------------------------
// What sign-in needs to know
// ---------------------------------------------------------------------------

export type SecondFactorRequirement = {
  /** Whether this organization requires one of everybody. */
  readonly policyRequires: boolean;
  /** Whether this person has a CONFIRMED factor. A pending enrolment is not one. */
  readonly enrolled: boolean;
};

/**
 * What this person owes before they are authenticated here.
 *
 * The one exported function that takes a user id, and it may: it answers two
 * booleans about somebody whose password has just been verified by the caller,
 * and reveals nothing that a sign-in attempt would not reveal anyway.
 *
 * `enrolled` reads `confirmed_two_factor_enrolments`, never the table. An
 * abandoned enrolment must not count as compliance (migration 12 note 5).
 */
export async function readSecondFactorRequirement(
  ctx: AuthzContext,
  userId: string,
): Promise<SecondFactorRequirement> {
  const policy = await readSecurityPolicy(ctx);
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(
      "select id from confirmed_two_factor_enrolments where user_id = $1",
      [userId],
    );
    return { policyRequires: policy.twoFactorRequired, enrolled: rows.length > 0 };
  });
}

// ---------------------------------------------------------------------------
// The challenge
// ---------------------------------------------------------------------------

export type NewChallenge = {
  readonly userId: string;
  /** The digest of the identifier. The identifier itself never arrives here. */
  readonly tokenDigest: string;
  readonly expiresAt: Date;
};

export type Challenge = {
  readonly id: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
};

type ChallengeRow = { id: string; user_id: string; created_at: Date; expires_at: Date };

/**
 * Record that this person proved a password and owes a second factor.
 *
 * The row is selected out of `memberships` rather than assembled from
 * parameters, exactly as `writeSession` is, so "a challenge belongs to a member
 * of this tenant" is a property of the statement: a user who is not a member
 * matches no row and the insert writes nothing.
 */
export async function startChallenge(ctx: AuthzContext, input: NewChallenge): Promise<Challenge> {
  return scoped(ctx, async (query) => {
    const rows = await query<ChallengeRow>(
      `insert into two_factor_challenges (org_id, user_id, token_hash, expires_at)
       select current_tenant(), m.user_id, $2::text, $3::timestamptz
       from memberships m
       where m.user_id = $1::uuid
       returning id, user_id, created_at, expires_at`,
      [input.userId, input.tokenDigest, input.expiresAt],
    );
    const row = rows[0];
    if (row === undefined) {
      throw new Error(
        "no second-factor challenge was written: the account is not a member of this organization.",
      );
    }
    return { id: row.id, userId: row.user_id, createdAt: row.created_at, expiresAt: row.expires_at };
  });
}

/**
 * The live challenge this identifier names, or null.
 *
 * Null for an identifier that matches nothing, one already redeemed, one that
 * has lapsed, and one belonging to another tenant — the caller cannot tell
 * which, because neither can the query. Liveness comes from
 * `live_two_factor_challenges` and from nowhere else (migration 12 note 9).
 *
 * Takes the plaintext and digests it here, exactly as `useSessionToken` does.
 * The lookup is then an indexed equality rather than a constant-time comparison,
 * and that is safe for `src/repo/sessions.ts`'s reason: the identifier is 256
 * bits from a CSPRNG, so there is no dictionary and nothing for a timing signal
 * to narrow.
 */
export async function findLiveChallenge(
  ctx: AuthzContext,
  challengeToken: string,
): Promise<Challenge | null> {
  return scoped(ctx, (query) => liveChallenge(query, challengeToken));
}

async function liveChallenge(query: ScopedQuery, challengeToken: string): Promise<Challenge | null> {
  const rows = await query<ChallengeRow>(
    "select id, user_id, created_at, expires_at from live_two_factor_challenges where token_hash = $1",
    [challengeTokenDigest(challengeToken)],
  );
  const row = rows[0];
  return row === undefined
    ? null
    : { id: row.id, userId: row.user_id, createdAt: row.created_at, expiresAt: row.expires_at };
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

export type StoredEnrolment = {
  readonly id: string;
  readonly userId: string;
  /** Ciphertext. Opening it needs the key-encryption key. See the module header. */
  readonly secretSealed: string;
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  readonly periodSeconds: number;
  readonly confirmedAt: Date | null;
};

type EnrolmentRow = {
  id: string;
  user_id: string;
  secret_sealed: string;
  algorithm: string;
  digits: number;
  period_seconds: number;
  confirmed_at: Date | null;
};

function toEnrolment(row: EnrolmentRow): StoredEnrolment {
  if (!isTotpAlgorithm(row.algorithm)) {
    // Loud rather than defaulted. Guessing an algorithm would silently refuse
    // every code this person produces, which is a lockout wearing the costume of
    // a wrong password (brief §9: no silent recovery from a data problem).
    throw new Error(
      `enrolment ${row.id} names the algorithm "${row.algorithm}", which this build does not know. ` +
        `The schema and src/auth/totp.ts have disagreed.`,
    );
  }
  return {
    id: row.id,
    userId: row.user_id,
    secretSealed: row.secret_sealed,
    algorithm: row.algorithm,
    digits: row.digits,
    periodSeconds: row.period_seconds,
    confirmedAt: row.confirmed_at,
  };
}

const ENROLMENT_COLUMNS = "id, user_id, secret_sealed, algorithm, digits, period_seconds, confirmed_at";

/**
 * Why an enrolment could not be started or confirmed.
 *
 * Unlike a sign-in refusal these ARE for the response: the person is looking at
 * an enrolment screen, they have already proved a password, and "the code was
 * wrong" and "your sign-in expired, start again" need different actions from
 * them. Nothing here distinguishes anything an unauthenticated caller could not
 * already determine.
 */
export const ENROLMENT_REFUSALS = [
  /** The challenge is spent, lapsed, or belongs to another tenant. */
  "no-live-challenge",
  /**
   * A confirmed factor already exists and the subject is a challenge. THE rule
   * from the module header: otherwise a stolen password would be enough to
   * replace somebody's authenticator with your own.
   */
  "already-enrolled",
  /** Nothing is part-way through enrolling, so there is nothing to confirm. */
  "no-pending-enrolment",
  /** The person is not a member of this organization. */
  "not-a-member",
] as const;

export type EnrolmentRefusal = (typeof ENROLMENT_REFUSALS)[number];

export type EnrolmentWrite =
  | { readonly ok: true; readonly userId: string; readonly enrolmentId: string }
  | { readonly ok: false; readonly refusal: EnrolmentRefusal };

export type NewEnrolment = {
  /** Ciphertext, produced by `sealTotpSecret`. The plaintext never arrives here. */
  readonly secretSealed: string;
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  readonly periodSeconds: number;
};

/**
 * Take the row lock on a challenge, by digest, before anything is examined.
 *
 * No liveness predicate: its only job is to serialise, and a spent row still has
 * to be lockable for that to work. Every operation a challenge authorises takes
 * this first, so two requests carrying one challenge cannot interleave — which
 * is what makes "single use" a property rather than a hope.
 */
async function lockChallenge(query: ScopedQuery, challengeToken: string): Promise<void> {
  await query("select id from two_factor_challenges where token_hash = $1 for update", [
    challengeTokenDigest(challengeToken),
  ]);
}

/** Who a subject names, and the challenge that vouched for them if one did. */
type ResolvedSubject = { readonly userId: string; readonly challengeId: string | null };

/**
 * Resolve which person a subject names, inside an open transaction.
 *
 * Never from a parameter. `self` is the acting user; `challenge` is whoever the
 * live challenge row names, read from the liveness view after the row has been
 * locked so the answer cannot go stale between the two.
 */
async function resolveSubject(
  query: ScopedQuery,
  ctx: AuthzContext,
  subject: FactorSubject,
  what: string,
): Promise<ResolvedSubject | null> {
  if (subject.kind === "self") return { userId: actingUser(ctx, what), challengeId: null };
  await lockChallenge(query, subject.challengeToken);
  const challenge = await liveChallenge(query, subject.challengeToken);
  return challenge === null ? null : { userId: challenge.userId, challengeId: challenge.id };
}

/**
 * Begin an enrolment: write a PENDING one, replacing any earlier pending one.
 *
 * Pending, because a secret nobody has proved they can use is not a second
 * factor (migration 12 note 5) — writing it as confirmed would lock somebody out
 * of their own account the moment they closed the tab.
 *
 * The `challenge` subject is refused when a confirmed enrolment exists; see the
 * module header for why that is the sharpest rule in this file. The `self`
 * subject may replace a confirmed enrolment, because a session in hand already
 * means the factor being replaced was presented — that is the new-phone case,
 * and without it there is no way to move an enrolment at all.
 *
 * The consequence of allowing it, recorded rather than glossed: a person who
 * begins a re-enrolment and abandons it has no second factor until they finish,
 * because the row is now pending. Somebody holding a stolen session can
 * therefore strip a victim's factor — but they already hold a session that
 * passed it, so this costs the victim a re-enrolment rather than costing them
 * access. Staging the new secret beside the old one would close it and needs two
 * more columns; it is named here so the omission reads as a decision.
 */
export async function startEnrolment(
  ctx: AuthzContext,
  subject: FactorSubject,
  input: NewEnrolment,
): Promise<EnrolmentWrite> {
  return scoped(ctx, async (query) => {
    const resolved = await resolveSubject(query, ctx, subject, "enrolling a second factor");
    if (resolved === null) return { ok: false, refusal: "no-live-challenge" };
    const { userId } = resolved;

    if (subject.kind === "challenge") {
      const confirmed = await query<{ id: string }>(
        "select id from confirmed_two_factor_enrolments where user_id = $1",
        [userId],
      );
      if (confirmed.length > 0) return { ok: false, refusal: "already-enrolled" };
    }

    const rows = await query<{ id: string }>(
      // Selected out of `memberships` for `writeSession`'s reason: membership
      // becomes a property of the statement rather than a check above it.
      // `created_at` is reset with the secret so the row's age describes the
      // secret it holds, and `last_used_step` with it, because a fresh secret
      // has accepted nothing.
      `insert into two_factor_enrolments
         (org_id, user_id, secret_sealed, algorithm, digits, period_seconds)
       select current_tenant(), m.user_id, $2::text, $3::text, $4::smallint, $5::smallint
       from memberships m
       where m.user_id = $1::uuid
       on conflict (org_id, user_id) do update
          set secret_sealed = excluded.secret_sealed,
              algorithm = excluded.algorithm,
              digits = excluded.digits,
              period_seconds = excluded.period_seconds,
              created_at = statement_timestamp(),
              confirmed_at = null,
              last_used_step = null
       returning id`,
      [userId, input.secretSealed, input.algorithm, input.digits, input.periodSeconds],
    );
    const row = rows[0];
    if (row === undefined) return { ok: false, refusal: "not-a-member" };
    return { ok: true, userId, enrolmentId: row.id };
  });
}

/** The pending enrolment a subject is part-way through, or null. */
export async function findPendingEnrolment(
  ctx: AuthzContext,
  subject: FactorSubject,
): Promise<StoredEnrolment | null> {
  return scoped(ctx, async (query) => {
    const resolved = await resolveSubject(query, ctx, subject, "reading your enrolment");
    if (resolved === null) return null;
    const rows = await query<EnrolmentRow>(
      `select ${ENROLMENT_COLUMNS} from two_factor_enrolments
        where user_id = $1 and confirmed_at is null`,
      [resolved.userId],
    );
    const row = rows[0];
    return row === undefined ? null : toEnrolment(row);
  });
}

/** The confirmed enrolment a subject holds, or null. Reads the view, never the table. */
export async function findConfirmedEnrolment(
  ctx: AuthzContext,
  subject: FactorSubject,
): Promise<StoredEnrolment | null> {
  return scoped(ctx, async (query) => {
    const resolved = await resolveSubject(query, ctx, subject, "reading your enrolment");
    if (resolved === null) return null;
    const rows = await query<EnrolmentRow>(
      `select ${ENROLMENT_COLUMNS} from confirmed_two_factor_enrolments where user_id = $1`,
      [resolved.userId],
    );
    const row = rows[0];
    return row === undefined ? null : toEnrolment(row);
  });
}

/**
 * Confirm a pending enrolment and issue its recovery codes, in ONE transaction.
 *
 * One transaction because the two halves are one fact. Confirmed without codes
 * is a person with a second factor and no way back if they lose it; codes
 * without a confirmation is a set of live credentials for a factor that does not
 * exist. Neither is a state worth being able to reach.
 *
 * `step` is the counter the confirming code came from, recorded as
 * `last_used_step` so that the very code used to prove the enrolment cannot then
 * be used to sign in (migration 12 note 3).
 *
 * Previous recovery codes are deleted rather than kept. Re-enrolling means a new
 * secret, and leaving the old codes alive would leave a credential for the
 * factor that was just replaced.
 *
 * When a CHALLENGE authorised this, that challenge is spent here too, in the
 * same transaction. It has done its job — the person proved a password, was told
 * to enrol, and has now produced a code from the secret they were handed — and
 * leaving it live would be a second, unused credential lying around for the
 * length of its window.
 */
export async function confirmEnrolment(
  ctx: AuthzContext,
  subject: FactorSubject,
  input: { readonly step: number; readonly recoveryCodeDigests: readonly string[] },
): Promise<EnrolmentWrite> {
  return scoped(ctx, async (query) => {
    const resolved = await resolveSubject(query, ctx, subject, "confirming your enrolment");
    if (resolved === null) return { ok: false, refusal: "no-live-challenge" };
    const { userId, challengeId } = resolved;

    const rows = await query<{ id: string }>(
      // `confirmed_at is null` is the whole guard: confirming twice does
      // nothing, so two racing confirmations cannot both issue a set of codes.
      // `last_used_step` is set to the confirming counter so that the very code
      // used to prove the enrolment cannot then be used to sign in.
      `update two_factor_enrolments
          set confirmed_at = statement_timestamp(), last_used_step = $2::bigint
        where user_id = $1 and confirmed_at is null
        returning id`,
      [userId, input.step],
    );
    const row = rows[0];
    if (row === undefined) return { ok: false, refusal: "no-pending-enrolment" };

    await query("delete from two_factor_recovery_codes where user_id = $1", [userId]);
    for (const digest of input.recoveryCodeDigests) {
      await query(
        `insert into two_factor_recovery_codes (org_id, user_id, code_hash)
         values (current_tenant(), $1, $2)`,
        [userId, digest],
      );
    }

    if (challengeId !== null) {
      await query(
        "update two_factor_challenges set consumed_at = statement_timestamp() where id = $1",
        [challengeId],
      );
    }
    return { ok: true, userId, enrolmentId: row.id };
  });
}

/** How many recovery codes the acting user has left. */
export async function countOwnRecoveryCodes(ctx: AuthzContext): Promise<number> {
  const userId = actingUser(ctx, "counting your recovery codes");
  return scoped(ctx, async (query) => {
    const rows = await query<{ left: string }>(
      "select count(*)::text as left from two_factor_recovery_codes where user_id = $1 and used_at is null",
      [userId],
    );
    return Number(rows[0]?.left ?? "0");
  });
}

// ---------------------------------------------------------------------------
// Redeeming a challenge
// ---------------------------------------------------------------------------

/**
 * Which second factor is being presented, already verified by
 * `src/auth/two_factor.ts`.
 *
 * A TOTP arrives as the COUNTER it came from rather than as the code, because
 * what this module has to enforce is that the counter has never been accepted
 * before — the arithmetic that turned six digits into a counter is
 * `src/auth/totp.ts`'s and does not belong in a query. A recovery code arrives
 * as its digest, because the digest is what is stored.
 */
export type PresentedFactor =
  | { readonly kind: "totp"; readonly step: number }
  | { readonly kind: "recovery-code"; readonly digest: string };

export const REDEMPTION_REFUSALS = [
  "no-live-challenge",
  /** No confirmed enrolment, so there is no factor this could be. */
  "not-enrolled",
  /**
   * The counter has already been accepted, or the recovery code is unknown or
   * already spent. One value on purpose: telling "already used" from "never
   * existed" would be an oracle for other people's recovery codes.
   */
  "factor-rejected",
] as const;

export type RedemptionRefusal = (typeof REDEMPTION_REFUSALS)[number];

export type ChallengeRedemption =
  | {
      readonly ok: true;
      readonly userId: string;
      readonly factor: PresentedFactor["kind"];
      /** Unspent codes left afterwards, so an interface can nag before they run out. */
      readonly recoveryCodesLeft: number;
    }
  | { readonly ok: false; readonly refusal: RedemptionRefusal };

/**
 * Spend a second factor and the challenge it answers, atomically.
 *
 * The order inside the transaction is the security-relevant part:
 *
 *   1. **Lock the challenge row by digest**, before anything is examined. Two
 *      concurrent redemptions of one challenge serialise here, so the
 *      single-use rule cannot be raced.
 *   2. **Ask the liveness view** whether it may still be redeemed. Asked after
 *      the lock, so the answer cannot go stale between the two.
 *   3. **Consume the factor**, guarded so that a counter that has been accepted
 *      before, or a recovery code already spent, matches nothing.
 *   4. **Consume the challenge.**
 *
 * Three before four so a WRONG code leaves both intact: the transaction commits
 * having changed nothing, and the person can try again. A typo must not cost a
 * full re-authentication, and it is the rate limiter that bounds retries rather
 * than the destruction of the challenge.
 *
 * The session is NOT created here, and the seam is deliberate: creating one is
 * `writeSession`'s job in `src/repo/sessions.ts`, which is the single place a
 * session comes into existence, and duplicating that insert to gain one
 * transaction would be trading a real invariant for a smaller failure window.
 * The window this leaves is "factor spent, session not written", which sends the
 * person back to the sign-in form — the safe direction.
 */
export async function redeemChallenge(
  ctx: AuthzContext,
  input: { readonly challengeToken: string; readonly factor: PresentedFactor },
): Promise<ChallengeRedemption> {
  return scoped(ctx, async (query) => {
    // 1. The lock, before anything is examined.
    await lockChallenge(query, input.challengeToken);

    // 2. Liveness, from the view and nowhere else.
    const challenge = await liveChallenge(query, input.challengeToken);
    if (challenge === null) return { ok: false, refusal: "no-live-challenge" };

    const enrolled = await query<{ id: string }>(
      "select id from confirmed_two_factor_enrolments where user_id = $1",
      [challenge.userId],
    );
    if (enrolled.length === 0) return { ok: false, refusal: "not-enrolled" };

    // 3. The factor.
    const spent = await spendFactor(query, challenge.userId, input.factor);
    if (!spent) return { ok: false, refusal: "factor-rejected" };

    // 4. The challenge. Under the lock from step 1, so this cannot lose a race.
    await query(
      "update two_factor_challenges set consumed_at = statement_timestamp() where id = $1",
      [challenge.id],
    );

    const left = await query<{ left: string }>(
      "select count(*)::text as left from two_factor_recovery_codes where user_id = $1 and used_at is null",
      [challenge.userId],
    );
    return {
      ok: true,
      userId: challenge.userId,
      factor: input.factor.kind,
      recoveryCodesLeft: Number(left[0]?.left ?? "0"),
    };
  });
}

/**
 * Consume one factor. True when it was there to consume.
 *
 * Both branches are a single guarded UPDATE rather than a read followed by a
 * write, because the guard IS the enforcement: a counter that does not advance
 * and a recovery code that is not unspent match no row, and two concurrent
 * attempts cannot both succeed.
 */
async function spendFactor(
  query: ScopedQuery,
  userId: string,
  factor: PresentedFactor,
): Promise<boolean> {
  if (factor.kind === "totp") {
    const rows = await query<{ id: string }>(
      // Strictly greater, so the counter only ever moves forward: the code just
      // used is dead, and so is every earlier code still inside the accepted
      // window (migration 12 note 3).
      `update two_factor_enrolments
          set last_used_step = $2::bigint
        where user_id = $1
          and confirmed_at is not null
          and (last_used_step is null or last_used_step < $2::bigint)
        returning id`,
      [userId, factor.step],
    );
    return rows.length > 0;
  }
  const rows = await query<{ id: string }>(
    `update two_factor_recovery_codes
        set used_at = statement_timestamp()
      where user_id = $1 and code_hash = $2 and used_at is null
      returning id`,
    [userId, factor.digest],
  );
  return rows.length > 0;
}

// ---------------------------------------------------------------------------
// KNOWN GAP — recorded rather than guessed at
//
// THERE IS NO ADMINISTRATIVE RESET. A member who loses their authenticator AND
// their recovery codes cannot be helped by anybody in this build: there is no
// function here that writes another person's enrolment, and there is no
// catalogued action to check an administrator against if there were.
// `src/authz/catalogue.ts` records the gap alongside the others.
//
// Shipping the capability first and the permission check afterwards is the
// shape brief §9 rejects outright ("TODO: add auth check later"), and an
// administrative reset is the single most dangerous action in this feature —
// whoever holds it can turn off anybody's second factor, which is the whole
// control. It needs an action, a role decision, an audit entry and a test of its
// own. Until then the honest answer is the one `updatePasswordHash` gives to the
// same question: refuse, and say why.
//
// The operator's route back in the meantime is the database, which is loud,
// deliberate and leaves a trail in the shell history of whoever did it.
// ---------------------------------------------------------------------------
