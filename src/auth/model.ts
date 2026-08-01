/**
 * The session vocabulary (RL-M1-017).
 *
 * Shared by the logic in `src/auth/sessions.ts` and the queries in
 * `src/repo/sessions.ts`. It lives in its own module for one structural reason:
 * the repository has to digest a presented token to look it up, and the logic
 * has to mint one, so if either owned the minting the other would import it and
 * the two directories would depend on each other in a cycle.
 *
 * Nothing here decides anything or touches the database. Where a value here
 * mirrors a database constraint — {@link SESSION_END_REASONS} against migration
 * 10's `sessions_end_reason` — the schema is the enforcement and this is the
 * mirror; `test/security/session_fixation.test.ts` reads the constraint back out
 * of Postgres and fails if the two disagree, so the mirror cannot quietly become
 * a second, weaker source of truth. That is the pattern `src/authz/grants.ts`
 * already uses for the grant vocabulary.
 */

import { createHash, randomBytes } from "node:crypto";

/**
 * Why a session stopped. Every ending has one (migration 10 constrains the
 * column so that a revocation without a reason is unwriteable), because C6 says
 * a privileged action is attributable and ending someone's access is one.
 *
 *   signed-out        the holder asked
 *   rotated           replaced at sign-in — the session-fixation defence
 *   privilege-change  replaced because what the holder may do changed
 *   revoked           ended by someone, or by the holder from another device
 *   password-changed  ended because the credential behind it was replaced
 */
export const SESSION_END_REASONS = [
  "signed-out",
  "rotated",
  "privilege-change",
  "revoked",
  "password-changed",
] as const;

export type SessionEndReason = (typeof SESSION_END_REASONS)[number];

/** Whether a value names an ending the schema accepts. */
export function isSessionEndReason(value: unknown): value is SessionEndReason {
  return typeof value === "string" && (SESSION_END_REASONS as readonly string[]).includes(value);
}

/**
 * A session as anyone may see it.
 *
 * There is no field here for the identifier, and there is none for its digest
 * either. The plaintext exists once, at creation; the digest is an
 * implementation detail of the lookup and has no business travelling with the
 * record — a session object that carried it would end up in a log line the first
 * time someone debugged a sign-in.
 */
export type Session = {
  readonly id: string;
  readonly orgId: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly lastSeenAt: Date | null;
  readonly revokedAt: Date | null;
  readonly revokedReason: SessionEndReason | null;
  /** The session this one replaced, when it was minted by rotation. */
  readonly rotatedFrom: string | null;
  readonly userAgent: string;
  readonly ip: string | null;
};

/**
 * How long a new session lives, absolutely, from the moment it is created.
 *
 * Eight hours, matching the SSH certificate default in brief §6.4, so "how long
 * does access last before it has to be re-established" has one answer across
 * this product rather than two.
 *
 * It is never extended on use. A sliding window would make "how long can a
 * stolen identifier live" unanswerable, and renewal already has a mechanism —
 * rotation mints a new identifier and kills the old one, which is the same
 * mechanism the fixation defence uses rather than a second one.
 */
export const DEFAULT_SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;

/**
 * Bytes of identifier, from the platform CSPRNG.
 *
 * 256 bits, the same as an API token (`src/repo/api_tokens.ts`) and for the same
 * reason: it has to be unguessable against an attacker who may try forever, and
 * nothing about it is derived from anything a person chose.
 */
const IDENTIFIER_BYTES = 32;

/** So an operator who finds one in a log knows what they are looking at. */
export const SESSION_TOKEN_PREFIX = "rlsess_";

/**
 * A fresh session identifier. The only place one is created.
 *
 * Returned to the caller once and never stored — what the database holds is
 * {@link sessionTokenDigest} of this, and migration 10 constrains the column so
 * that the plaintext cannot be written into it even by hand.
 */
export function mintSessionToken(): string {
  return `${SESSION_TOKEN_PREFIX}${randomBytes(IDENTIFIER_BYTES).toString("base64url")}`;
}

/**
 * What gets stored: a SHA-256 digest, lowercase hex, 64 characters — the shape
 * migration 10's CHECK constrains the column to.
 *
 * A plain digest rather than the memory-hard function used on passwords, for
 * the reason `src/repo/api_tokens.ts` gives about token secrets: the input is
 * 256 bits from a cryptographic source, so there is no dictionary to attack and
 * no work factor to buy. Adding one would only make every authenticated request
 * slower. A password is different because a person chose it.
 */
export function sessionTokenDigest(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}
