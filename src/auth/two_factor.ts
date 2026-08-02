/**
 * Two-factor authentication: enrolment, verification, and the organization
 * policy that requires it (RL-M1-019).
 *
 * The functions an interface calls. Every query behind them is in
 * `src/repo/two_factor.ts` (C3, ADR 0003); the arithmetic is in
 * `src/auth/totp.ts`. What lives here is the order things happen in, what gets
 * audited, and the decisions about both.
 *
 * ## The shape, which is the security argument
 *
 * A person who owes a second factor is given NO SESSION. `signIn` returns a
 * CHALLENGE instead — a short-lived, single-use credential that says "this
 * password was accepted" and is good for exactly one thing: being exchanged for
 * a session by presenting a second factor.
 *
 * That is not the obvious design. The obvious design mints the session and marks
 * it "second factor pending", and it is rejected in migration 12 note 1 for a
 * reason worth repeating here: a flag on a session makes every existing reader
 * of that table wrong by omission, and the only thing standing between a stolen
 * half-session and a full one would be every future caller remembering a
 * predicate. With a challenge, a caller that knows nothing about two-factor
 * authentication receives no session token and therefore fails CLOSED.
 *
 * It also means `signIn`'s result had to grow a third case, and it grew it as an
 * `ok: false` — see the type in `src/auth/sessions.ts`. Existing code that
 * branches on `ok` treats "owes a second factor" as "not signed in", which is
 * the correct reading and the safe one.
 *
 * ## Four rules
 *
 * **1. A CHALLENGE CANNOT ENROL OVER A CONFIRMED FACTOR.** The whole feature
 * rests on this. Somebody who knows a password but not the factor gets a
 * challenge like anybody else; if that challenge could start a fresh enrolment
 * they would enrol their own authenticator and be done. `startEnrolment` refuses
 * it in the data layer, and `test/security/twofactor.test.ts` drives the attack.
 *
 * **2. VERIFICATION IS AN AUTHENTICATION PATH AND IS RATE LIMITED LIKE THE
 * OTHERS.** `AUTH_PATHS` has carried `two-factor` since RL-M1-020 and
 * `AUTH_RATE_LIMITS` already publishes its budget. Nothing here calls the
 * limiter, for the same reason nothing calls it on the sign-in path: the limiter
 * has to run BEFORE the expensive work, which makes the ordering the route
 * handler's (ADR 0015, and the list at the foot of `src/auth/rate_limit.ts`).
 * What this module owes that list is repeated at the bottom of this file,
 * because a second factor that can be guessed a thousand times a minute is not a
 * second factor.
 *
 * **3. SPENDING A RECOVERY CODE IS AUDITED, SEPARATELY FROM VERIFYING.**
 * Acceptance 3 asks for it by name, and it is the right thing to ask for: a
 * recovery code is the bypass around the control, so its use is the event an
 * incident review looks for. The audit entry names the actor, the person, the
 * request and how many codes are left — never the code.
 *
 * **4. THE KEY IS A PARAMETER, NEVER A DEFAULT.** Sealing and opening the shared
 * secret needs the key-encryption key, and every function here that touches one
 * takes it as an argument. It could have been loaded lazily from
 * `src/crypto/secrets.ts` and that would have been worse: a module that reads
 * the filesystem to find a key has a default location, and a default location is
 * one step from a default value (C4). The caller has it already — `preflight()`
 * returns it — so passing it costs nothing and makes the dependency visible in
 * the signature.
 *
 * ## The context these run in
 *
 * The same seam `src/auth/sessions.ts` documents: verification happens before
 * there is a user to attribute it to, so the calls take an `AuthzContext` whose
 * actor is a named service identity (C6 already sanctions that, and the session
 * and rate-limit suites already use the shape). The actor on the context is NOT
 * consulted by anything that authenticates — identity comes from the challenge
 * row, and the row is reachable only by presenting the credential that names it.
 */

import type { AuthzContext } from "../authz/context.ts";
import { recordAudit } from "../repo/audit.ts";
import { NotPermittedError } from "../authz/can.ts";
import { revokeSessionsOfUser } from "../repo/sessions.ts";
import { currentOrganization, findMember } from "../repo/organizations.ts";
import { startSession } from "../repo/sessions.ts";
import {
  confirmEnrolment as writeConfirmation,
  findConfirmedEnrolment,
  findLiveChallenge,
  findPendingEnrolment,
  readSecondFactorRequirement,
  readSecurityPolicy,
  redeemChallenge,
  startChallenge,
  startEnrolment,
  writeSecurityPolicy,
  ENROLMENT_REFUSALS,
  type EnrolmentRefusal,
  type FactorSubject,
  type PresentedFactor,
  type RedemptionRefusal,
  type SecurityPolicy,
  type StoredEnrolment,
  clearSecondFactor,
} from "../repo/two_factor.ts";
import {
  challengeTokenDigest,
  DEFAULT_SESSION_LIFETIME_MS,
  mintChallengeToken,
  mintSessionToken,
  sessionTokenDigest,
  type IssuedSession,
} from "./model.ts";
import {
  base32Encode,
  mintRecoveryCode,
  mintTotpSecret,
  openTotpSecret,
  otpauthUri,
  recoveryCodeDigest,
  sealTotpSecret,
  verifyTotp,
  RECOVERY_CODE_COUNT,
  TOTP_PARAMETERS,
  type TotpParameters,
} from "./totp.ts";

export type { FactorSubject, RedemptionRefusal, SecurityPolicy };

// ---------------------------------------------------------------------------
// What a person owes at sign-in
// ---------------------------------------------------------------------------

/**
 * How long a challenge lives.
 *
 * Five minutes: long enough to unlock a phone, open an authenticator and read
 * six digits with a fumble or two, short enough that a challenge captured from a
 * proxy log is worthless by the time anybody reads it. It is deliberately
 * nothing like a session lifetime — the two credentials mean different things,
 * and a challenge that lived for hours would be a password-only session by
 * another name.
 */
export const CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;

export const SECOND_FACTOR_DEMANDS = [
  /** Nothing: the organization does not require one and this person has not enrolled. */
  "none",
  /** They hold a confirmed factor and must present a code. */
  "verify",
  /** The organization requires one and they have not enrolled. Acceptance 2. */
  "enrol",
] as const;

export type SecondFactorDemand = (typeof SECOND_FACTOR_DEMANDS)[number];

/**
 * What a person owes, given the policy and their enrolment.
 *
 * A pure function over two booleans so the rule can be read, and tested, without
 * a database standing in the way of it.
 *
 * BEING ENROLLED IS ENFORCED WHETHER OR NOT THE ORGANIZATION REQUIRES IT. A
 * person who turned two-factor authentication on for themselves has to keep
 * using it, because the alternative — enforcing it only while the policy is on —
 * would mean an administrator turning the policy off silently downgraded
 * everybody who had opted in, without their knowing.
 *
 * The other direction is acceptance 2: the organization requires one and this
 * person has not enrolled, so they are sent to enrol before they get a session.
 */
export function secondFactorDemand(requirement: {
  readonly policyRequires: boolean;
  readonly enrolled: boolean;
}): SecondFactorDemand {
  if (requirement.enrolled) return "verify";
  return requirement.policyRequires ? "enrol" : "none";
}

/**
 * What this person owes, asked once per sign-in.
 *
 * Takes a user id because the caller has just verified that person's password;
 * it answers two booleans and reveals nothing a sign-in attempt would not.
 */
export async function demandFor(ctx: AuthzContext, userId: string): Promise<SecondFactorDemand> {
  return secondFactorDemand(await readSecondFactorRequirement(ctx, userId));
}

/** The challenge, and the identifier that names it. The identifier exists only here. */
export type SecondFactorChallenge = {
  /**
   * The plaintext identifier, the only time it exists outside the caller's
   * memory. It is not recoverable: what the database holds is a digest.
   */
  readonly token: string;
  readonly expiresAt: Date;
  /**
   * True when this person has to ENROL before they can verify — the forced
   * enrolment acceptance 2 asks for. False when they already hold a factor and
   * merely have to present a code.
   */
  readonly enrolmentRequired: boolean;
};

/**
 * Mint a challenge for somebody whose password has just been accepted.
 *
 * Called by `signIn` and by nothing else. Exported rather than inlined there so
 * that the lifetime, the identifier minting and the digest rule live beside the
 * rest of the two-factor logic instead of leaking into the session module.
 */
export async function issueChallenge(
  ctx: AuthzContext,
  userId: string,
  demand: Exclude<SecondFactorDemand, "none">,
): Promise<SecondFactorChallenge> {
  const token = mintChallengeToken();
  const challenge = await startChallenge(ctx, {
    userId,
    tokenDigest: challengeTokenDigest(token),
    expiresAt: new Date(Date.now() + CHALLENGE_LIFETIME_MS),
  });
  return { token, expiresAt: challenge.expiresAt, enrolmentRequired: demand === "enrol" };
}

// ---------------------------------------------------------------------------
// Enrolment
// ---------------------------------------------------------------------------

/**
 * Why an enrolment step was refused.
 *
 * The repository's list plus the one this layer decides: a code that does not
 * come from the secret it was handed. Unlike a sign-in refusal these ARE for the
 * response — the person is on an enrolment screen and has already proved a
 * password, and "the code was wrong" and "your sign-in expired" need different
 * things from them.
 */
export const ENROLMENT_FAILURES = [...ENROLMENT_REFUSALS, "code-rejected"] as const;

export type EnrolmentFailure = (typeof ENROLMENT_FAILURES)[number];

export type EnrolmentStart =
  | {
      readonly ok: true;
      /**
       * The shared secret, base32, the only time it exists outside the caller's
       * memory in plaintext. Show it once, as a QR code and as text for whoever
       * cannot scan one, and forget it.
       */
      readonly secret: string;
      /** The same secret as an `otpauth://` URI, which is what a QR code encodes. */
      readonly uri: string;
      readonly parameters: TotpParameters;
    }
  | { readonly ok: false; readonly failure: EnrolmentRefusal };

/**
 * Begin an enrolment: mint a secret, seal it, and hand the plaintext back once.
 *
 * The enrolment written is PENDING. Nothing about this call makes the person
 * compliant, and nothing about it takes away a factor they already have unless
 * they are enrolling as `self` — see `startEnrolment` in the repository for the
 * consequence of that and why it is accepted.
 */
export async function beginEnrolment(
  ctx: AuthzContext,
  sealingKey: Buffer,
  subject: FactorSubject,
  parameters: TotpParameters = TOTP_PARAMETERS,
): Promise<EnrolmentStart> {
  const secret = mintTotpSecret();
  const written = await startEnrolment(ctx, subject, {
    secretSealed: sealTotpSecret(sealingKey, secret),
    algorithm: parameters.algorithm,
    digits: parameters.digits,
    periodSeconds: parameters.periodSeconds,
  });
  if (!written.ok) return { ok: false, failure: written.refusal };

  // The label an authenticator application shows. Both halves are looked up
  // rather than taken from the caller: a caller-supplied issuer would let one
  // enrolment masquerade as another organization's inside somebody's phone.
  const organization = await currentOrganization(ctx);
  const member = await findMember(ctx, written.userId);
  return {
    ok: true,
    secret: base32Encode(secret),
    uri: otpauthUri({
      issuer: organization?.name ?? "Ratline",
      account: member?.email ?? written.userId,
      secret,
      parameters,
    }),
    parameters,
  };
}

export type EnrolmentCompletion =
  | {
      readonly ok: true;
      /**
       * The recovery codes, in plaintext, the only time they exist outside the
       * caller's memory. What the database holds is a digest of each.
       */
      readonly recoveryCodes: readonly string[];
      /**
       * The session, when a challenge authorised this enrolment — the person was
       * forced to enrol at sign-in and has now finished, so they are signed in.
       * Null when a signed-in person enrolled from their own settings; they
       * already have one.
       */
      readonly session: IssuedSession | null;
    }
  | { readonly ok: false; readonly failure: EnrolmentFailure };

export type ConfirmationInput = {
  readonly subject: FactorSubject;
  readonly presented: string;
  /** When the code is judged. A parameter so a test can pin the clock. */
  readonly atMs?: number;
  readonly userAgent?: string;
  readonly ip?: string | null;
  readonly lifetimeMs?: number;
};

/**
 * Confirm a pending enrolment by proving a code from it, and issue the recovery
 * codes.
 *
 * The code has to come from the PENDING secret, which is what makes this a proof
 * rather than a formality: a person whose authenticator was set up wrong, or
 * whose clock is hours out, finds out here instead of at their next sign-in with
 * no way back.
 *
 * The counter the confirming code came from is recorded as spent, so that same
 * code cannot then be presented to sign in.
 */
export async function confirmEnrolment(
  ctx: AuthzContext,
  sealingKey: Buffer,
  input: ConfirmationInput,
): Promise<EnrolmentCompletion> {
  const pending = await findPendingEnrolment(ctx, input.subject);
  if (pending === null) {
    return {
      ok: false,
      failure: input.subject.kind === "challenge" ? "no-live-challenge" : "no-pending-enrolment",
    };
  }

  const step = verifyAgainstSealed(sealingKey, pending, input.presented, input.atMs ?? Date.now());
  if (step === null) return { ok: false, failure: "code-rejected" };

  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () => mintRecoveryCode());
  const written = await writeConfirmation(ctx, input.subject, {
    step,
    recoveryCodeDigests: codes.map(recoveryCodeDigest),
  });
  if (!written.ok) return { ok: false, failure: written.refusal };

  await recordAudit(ctx, {
    action: "two_factor.enrol",
    resourceType: "member",
    resourceId: written.userId,
    decision: "allow",
    reason: input.subject.kind === "challenge" ? "forced-at-sign-in" : "self-service",
    metadata: {
      algorithm: pending.algorithm,
      digits: pending.digits,
      period_seconds: pending.periodSeconds,
      recovery_codes_issued: codes.length,
    },
  });

  // A challenge authorised this, so the person was mid-sign-in. The repository
  // has already spent that challenge; finishing the sign-in here is what stops
  // them having to type a second code thirty seconds after the first.
  const session =
    input.subject.kind === "challenge" ? await mintSessionFor(ctx, written.userId, input) : null;
  return { ok: true, recoveryCodes: codes, session };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export type SecondFactorResult =
  | (IssuedSession & {
      readonly ok: true;
      /** Which factor was accepted. A recovery code is worth showing in the interface. */
      readonly factor: PresentedFactor["kind"];
      /** Unspent recovery codes left, so an interface can nag before they run out. */
      readonly recoveryCodesLeft: number;
    })
  | { readonly ok: false; readonly refusal: RedemptionRefusal };

export type VerificationInput = {
  readonly challengeToken: string;
  /** A TOTP code or a recovery code. Nothing here needs to be told which. */
  readonly presented: string;
  readonly userAgent?: string;
  readonly ip?: string | null;
  readonly lifetimeMs?: number;
  /** When the code is judged. A parameter so a test can pin the clock. */
  readonly atMs?: number;
};

/**
 * Present a second factor and, if it holds, exchange the challenge for a
 * session.
 *
 * The order below is the security-relevant part:
 *
 *   1. Find the CONFIRMED enrolment behind the challenge — the view, never the
 *      table, so a half-finished enrolment is not a second factor.
 *   2. Try the presented value as a TOTP code.
 *   3. **If it is not one, try it as a recovery code — always.** Not as a
 *      fallback the caller asks for: this module is never told which kind was
 *      presented, so it cannot behave differently for the two and cannot become
 *      an oracle for which one somebody holds. A wrong six-digit code costs one
 *      extra digest lookup that matches nothing.
 *   4. Spend the factor and the challenge together, in the repository, in one
 *      transaction (see `redeemChallenge` for the ordering inside it).
 *   5. Only then mint a session.
 *
 * A REPLAYED TOTP CODE FAILS AT STEP 4, NOT STEP 2. Step 2 says only "this code
 * comes from that secret"; whether that counter has already been accepted is a
 * fact about stored state, and it is enforced by the same UPDATE that spends it
 * so two requests cannot both win. It does not then fall through to step 3 — a
 * replayed code is refused, not retried as something else.
 */
export async function verifySecondFactor(
  ctx: AuthzContext,
  sealingKey: Buffer,
  input: VerificationInput,
): Promise<SecondFactorResult> {
  const subject: FactorSubject = { kind: "challenge", challengeToken: input.challengeToken };
  const enrolment = await findConfirmedEnrolment(ctx, subject);
  if (enrolment === null) {
    // Told apart only for the audit log and the enrolment redirect. An
    // interface renders both as one response (see the list at the foot of this
    // file), because the difference is "this account has a second factor".
    const challenge = await findLiveChallenge(ctx, input.challengeToken);
    return { ok: false, refusal: challenge === null ? "no-live-challenge" : "not-enrolled" };
  }

  const step = verifyAgainstSealed(sealingKey, enrolment, input.presented, input.atMs ?? Date.now());
  const factor: PresentedFactor =
    step === null
      ? { kind: "recovery-code", digest: recoveryCodeDigest(input.presented) }
      : { kind: "totp", step };

  const redemption = await redeemChallenge(ctx, { challengeToken: input.challengeToken, factor });
  if (!redemption.ok) {
    await recordAudit(ctx, {
      action: "two_factor.verify",
      resourceType: "member",
      resourceId: enrolment.userId,
      decision: "deny",
      reason: redemption.refusal,
      metadata: { presented_as: factor.kind },
    });
    return { ok: false, refusal: redemption.refusal };
  }

  if (redemption.factor === "recovery-code") {
    // Acceptance 3. Its own entry, separate from the verification, because this
    // is the bypass around the control and it is what an incident review looks
    // for. The code itself is never recorded — only that one was spent.
    await recordAudit(ctx, {
      action: "two_factor.recovery_code_used",
      resourceType: "member",
      resourceId: redemption.userId,
      decision: "allow",
      reason: "second-factor-recovery",
      metadata: { recovery_codes_left: redemption.recoveryCodesLeft },
    });
  }

  const issued = await mintSessionFor(ctx, redemption.userId, input);

  await recordAudit(ctx, {
    action: "two_factor.verify",
    resourceType: "member",
    resourceId: redemption.userId,
    decision: "allow",
    reason: redemption.factor,
    metadata: { session_id: issued.session.id, recovery_codes_left: redemption.recoveryCodesLeft },
  });

  return {
    ok: true,
    ...issued,
    factor: redemption.factor,
    recoveryCodesLeft: redemption.recoveryCodesLeft,
  };
}

// ---------------------------------------------------------------------------
// The organization policy
// ---------------------------------------------------------------------------

/** This organization's policy. Readable without a permission; see the repository. */
export async function twoFactorPolicy(ctx: AuthzContext): Promise<SecurityPolicy> {
  return readSecurityPolicy(ctx);
}

/**
 * Require, or stop requiring, a second factor of everybody in this organization.
 *
 * The permission check is in the data layer
 * (`organization.manage_security_policy`), not here — brief §9 lists a check in
 * the calling layer as an anti-pattern, and a second check is the shape that
 * eventually disagrees with the first. This function decides only what to audit
 * about the outcome, exactly as `applyPrivilegeChange` does.
 *
 * Turning it ON does not sign anybody out, and does not need to: acceptance 2 is
 * about the NEXT sign-in, and existing sessions belong to people who passed
 * whatever was required when they got them. An installation that wants the
 * stronger reading has `revokeAllSessions` already.
 */
export async function setTwoFactorPolicy(
  ctx: AuthzContext,
  twoFactorRequired: boolean,
): Promise<SecurityPolicy> {
  const policy = await writeSecurityPolicy(ctx, { twoFactorRequired });
  await recordAudit(ctx, {
    action: "organization.manage_security_policy",
    resourceType: "organization",
    resourceId: ctx.orgId,
    decision: "allow",
    reason: twoFactorRequired ? "two-factor-required" : "two-factor-optional",
    metadata: { two_factor_required: twoFactorRequired },
  });
  return policy;
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/**
 * Open a sealed secret, judge one code against it, and wipe the plaintext.
 *
 * One function so that "the opened secret does not outlive the comparison it was
 * opened for" is stated once and cannot be forgotten by the second caller. The
 * `finally` matters: `verifyTotp` can throw on a malformed stored parameter, and
 * an exception is exactly when a wipe gets skipped.
 */
function verifyAgainstSealed(
  sealingKey: Buffer,
  enrolment: StoredEnrolment,
  presented: string,
  atMs: number,
): number | null {
  const secret = openTotpSecret(sealingKey, enrolment.secretSealed);
  try {
    return verifyTotp(
      secret,
      presented,
      {
        algorithm: enrolment.algorithm,
        digits: enrolment.digits,
        periodSeconds: enrolment.periodSeconds,
      },
      { atMs },
    );
  } finally {
    secret.fill(0);
  }
}

async function mintSessionFor(
  ctx: AuthzContext,
  userId: string,
  input: { readonly userAgent?: string; readonly ip?: string | null; readonly lifetimeMs?: number },
): Promise<IssuedSession> {
  const token = mintSessionToken();
  const session = await startSession(ctx, {
    userId,
    tokenDigest: sessionTokenDigest(token),
    expiresAt: new Date(Date.now() + (input.lifetimeMs ?? DEFAULT_SESSION_LIFETIME_MS)),
    // A challenge is not a session, so there is no predecessor to chain to. Any
    // session this person was carrying was already revoked by `signIn`, before
    // the challenge existed.
    rotatedFrom: null,
    userAgent: input.userAgent ?? "",
    ip: input.ip ?? null,
  });
  return { session, token };
}

/**
 * Thrown when the actor may not turn off somebody else's second factor.
 *
 * A distinct type, so the caller renders it as the same indistinguishable
 * refusal as any other denial (RL-M1-026) while the audit log keeps the real
 * reason. The same split `resetMemberPassword` and `applyPrivilegeChange` make.
 */
export class NotPermittedToResetSecondFactor extends Error {
  constructor(actorId: string, subjectUserId: string) {
    super(`actor ${actorId} may not reset the second factor for ${subjectUserId}`);
    this.name = "NotPermittedToResetSecondFactor";
  }
}

/**
 * Turn off another member's second factor, for somebody who has lost both their
 * authenticator and their recovery codes (RL-M1-038).
 *
 * ## The bound this removes
 *
 * R-17 is closed "as far as a password alone permits" because two-factor is
 * what stops an administrative password reset being sufficient: an operator who
 * resets a password still cannot sign in as that person. This removes that
 * bound, so whoever holds both actions can take an account outright. They are
 * deliberately held by the same two roles — splitting them would suggest the
 * pair is safer than either one, and it is the opposite.
 *
 * What bounds it instead is the same three things RL-M1-034 relies on, and they
 * are this task's acceptance criteria rather than three unrelated requirements:
 * a small pinned set of holders, an audit entry written before the account can
 * be used, and the member signed out so they notice.
 *
 * ## Ordering, and the lesson RL-M1-034 paid for
 *
 * The clear goes FIRST, because the clear is where the permission is resolved.
 * Revoking first would mean an operator holding `member.revoke_sessions` but not
 * `member.reset_two_factor` ended a member's sessions on the way to being
 * refused — a refusal with an effect, and an unaudited one. That exact bug was
 * found by a test in RL-M1-034 and is not repeated here.
 *
 * ## What happens next, which is the third acceptance
 *
 * Nothing here forces re-enrolment, and it does not need to: with no confirmed
 * enrolment, `signIn` consults the organization's requirement and issues an
 * enrolment challenge on its own. The forcing already exists. This task's job is
 * to make sure clearing the factor actually reaches that state, rather than
 * leaving a stale row that still counts.
 *
 * Returns how many enrolments were removed.
 */
export async function resetMemberSecondFactor(
  ctx: AuthzContext,
  subjectUserId: string,
): Promise<number> {
  let removed: number;
  try {
    removed = await clearSecondFactor(ctx, subjectUserId);
  } catch (error: unknown) {
    if (error instanceof NotPermittedError) {
      await recordAudit(ctx, {
        action: "member.reset_two_factor",
        resourceType: "member",
        resourceId: subjectUserId,
        decision: "deny",
        reason: error.decision.reason,
      });
      throw new NotPermittedToResetSecondFactor(ctx.actor.id, subjectUserId);
    }
    throw error;
  }

  // Their sessions passed a factor that no longer exists. Ending them is what
  // makes the reset visible to the person it was done to, which is the only
  // detection this capability has.
  const sessionsRevoked = await revokeSessionsOfUser(ctx, subjectUserId, "revoked");

  await recordAudit(ctx, {
    action: "member.reset_two_factor",
    resourceType: "member",
    resourceId: subjectUserId,
    decision: "allow",
    reason: "administrative-reset",
    // Counts and flags only. Nothing that could reconstruct the secret, and
    // nothing about the recovery codes beyond the fact that they went with it.
    metadata: { enrolments_removed: removed, sessions_revoked: sessionsRevoked, administrative: true },
  });

  return removed;
}


// ---------------------------------------------------------------------------
// What the interface layer still owes — RL-M1-024 and whoever builds src/api/
//
// Written here rather than in a commit message, because a second factor that is
// never asked for is not a second factor, and this list is the difference
// between "two-factor authentication exists" and "two-factor authentication is
// enforced".
//
//   1. RATE LIMIT THE `two-factor` PATH, BEFORE calling verifySecondFactor.
//      `AUTH_RATE_LIMITS["two-factor"]` publishes the budget and
//      `recordAuthAttempt` spends it. Six digits is a million possibilities and
//      an unlimited verifier finds the right one inside a day; the limiter is
//      what makes that number mean something. Key the account dimension on the
//      identifier the client presented at sign-in, NOT on a user id resolved
//      from the challenge — see note 2 in src/auth/rate_limit.ts.
//
//   2. CALL `resetAuthRateLimit` ON SUCCESS, for the `two-factor` path only.
//      Never for `login` as well: a correct password must not buy more guesses
//      at the factor, which is the exact case the path split exists for.
//
//   3. RENDER A REFUSAL AS ONE STATUS AND ONE BODY. `RedemptionRefusal` is for
//      the audit log. A response that told "wrong code" from "you have no
//      enrolment" would say which accounts have a second factor.
//
//   4. TREAT THE CHALLENGE IDENTIFIER LIKE A SESSION COOKIE. HttpOnly, Secure,
//      SameSite, its own name, and cleared the moment it is redeemed or
//      refused. It is a bearer credential; it is short-lived, not weak.
//
//   5. DO NOT LET THE ENROLMENT SCREEN BE REACHED WITHOUT A CHALLENGE OR A
//      SESSION. `FactorSubject` has exactly two variants and neither can be
//      forged from a request body, but a handler that resolved "self" from a
//      user id in the URL would defeat all of it.
//
//   6. ROUTES. `PUT /organization/security-policy` already exists in the route
//      table with `organization.manage_security_policy` on it, and matches
//      `setTwoFactorPolicy`. The enrolment and verification endpoints do not
//      exist yet; they are public routes in the matrix's sense (they are reached
//      before there is an actor) and each needs a written `publicReason`.
// ---------------------------------------------------------------------------
