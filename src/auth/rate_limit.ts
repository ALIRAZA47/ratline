/**
 * Rate limiting on every authentication path (RL-M1-020, threat model R-15).
 *
 * Brief §6.7 lists "rate limiting on all auth endpoints including password
 * reset" among the security suite's minimum coverage. R-15 is why it is not a
 * tick-box: `src/auth/passwords.ts` derives a 128 MiB scrypt hash per sign-in
 * attempt, and does so even when the account does not exist, because ADR 0014
 * chose to spend that cost rather than let response timing say which addresses
 * are real. Without a limiter, an unauthenticated burst is a resource lever on a
 * control plane the brief expects to run on a laptop (§6.1).
 *
 * This module is the POLICY. The three statements that touch the counter are in
 * `src/repo/rate_limits.ts`, because C3 keeps the database handle out of reach
 * of everything except the repository layer (ADR 0003). The split is not
 * tidiness: the fail-closed rule below is a decision about what to do when that
 * module FAILS, so it cannot live inside it.
 *
 * ## The four things worth reading before changing anything
 *
 * **1. Both dimensions are counted on every attempt, and neither short-circuits
 * the other.** Per account alone lets one attacker spray a thousand accounts
 * from one address. Per address alone lets a botnet concentrate on one account.
 * They are separate buckets with separate budgets, and a refusal by one does NOT
 * skip counting the other — if it did, an attacker could spend an account's
 * budget for free as far as their address was concerned, then move to the next
 * account with a clean address budget.
 *
 * **2. Counting happens before anything is looked up.** The bucket key is a
 * digest of the identifier the client PRESENTED. Nothing here resolves it, and
 * nothing here behaves differently for an identifier that names somebody. A
 * limiter that counted only real accounts would tell an attacker which addresses
 * exist by which ones start being refused — handing back the disclosure ADR 0014
 * spends 128 MiB per attempt to prevent. Count the attempt, not the outcome.
 *
 * **3. It fails CLOSED.** Any failure reaching the store produces a refusal.
 * A rate limiter that fails open is an availability feature wearing a security
 * feature's clothes: the store is most likely to be unreachable precisely
 * because something is overwhelming it, so failing open hands the attacker the
 * flood the limiter exists to stop. The error is carried out on the decision
 * rather than swallowed — brief §9 forbids silent catch blocks — and it is
 * returned rather than thrown, so that "refused" is the value a caller has to
 * handle instead of an exception a caller might catch and continue past.
 *
 * **4. A window is not a lockout.** Every limit releases by itself, in one of
 * two ways and with no administrator involved: the window ends (fixed at the
 * moment it opened, never extended, so an attacker cannot hold an account locked
 * out by attempting once per window), or the authentication succeeds and
 * {@link resetAuthRateLimit} clears the account's bucket. Success clears the
 * ACCOUNT dimension only — clearing the address dimension would let an attacker
 * with one valid account of their own wipe their address budget at will.
 *
 * ## What this module is not
 *
 * There is no HTTP layer yet (`src/api/` is empty) and nothing here invents one.
 * These are the functions an interface will call. What that interface still owes
 * is listed at the bottom of this file, because a limiter nobody calls limits
 * nothing, and that gap should be readable from here rather than discovered
 * later.
 */

import { createHash } from "node:crypto";

import type { AuthzContext } from "../authz/context.ts";
import {
  clearAuthRateLimit,
  countAuthAttempts,
  RATE_LIMIT_DIMENSIONS,
  readAuthRateLimits,
  type AuthPath,
  type CountedWindow,
  type LiveWindow,
  type RateLimitBucket,
  type RateLimitDimension,
} from "../repo/rate_limits.ts";

export {
  AUTH_PATHS,
  RATE_LIMIT_DIMENSIONS,
  pruneAuthRateLimits,
  type AuthPath,
  type RateLimitDimension,
} from "../repo/rate_limits.ts";

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

/**
 * The digest a bucket is keyed by.
 *
 * SHA-256 of the normalised value, lowercase hex — the shape migration 11's
 * `auth_rate_limits_key_shape` constrains the column to, so a plaintext
 * identifier cannot be written into it even by hand.
 *
 * A plain digest rather than a memory-hard hash, for the reason
 * `src/auth/model.ts` gives about session identifiers turned inside out: the
 * point here is not to resist a dictionary attack on the key — the key space IS
 * the set of email addresses and IP addresses, so it is enumerable and a work
 * factor would not change that. The point is that this table is written by
 * unauthenticated callers, so its plaintext form would be an attacker-populated
 * list of every address anyone ever tried, sitting in the database and in every
 * backup of it. Hashing makes it a counter key instead of a harvest. Anyone who
 * already knows an address can confirm it appears here, and that is accepted:
 * they already know it.
 *
 * Normalisation is NFKC, trimmed, lowercased. Emails are `citext` in the schema,
 * so lowercasing matches the database's own view of identity and stops
 * `Alice@…` and `alice@…` from being two budgets.
 */
export function rateLimitKey(value: string): string {
  const normalised = value.normalize("NFKC").trim().toLowerCase();
  return createHash("sha256").update(normalised, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

export type RateLimitRule = {
  /** Attempts permitted in one window. */
  readonly limit: number;
  /** How long a window lasts, in milliseconds. Fixed at the moment it opens. */
  readonly windowMs: number;
};

/** One rule per dimension. Both apply; either can refuse. */
export type PathRules = Readonly<Record<RateLimitDimension, RateLimitRule>>;

const MINUTE = 60_000;

/**
 * The published limits.
 *
 * They live here rather than in the schema because they are policy: an operator
 * will tune them, and a CHECK constraint on them would make tuning a migration.
 * They are exported so a test can read them and so a reviewer can see all eight
 * numbers at once instead of hunting for them.
 *
 * How they were chosen, since numbers with no argument get "simplified" later:
 *
 *   - The ACCOUNT budgets are set against what a human does. Ten wrong passwords
 *     in a quarter of an hour is already an unusual day; five reset requests in
 *     an hour is more than anyone needs. They are the budget an attacker gets
 *     per account, so the guessing rate against one password is 40/hour.
 *   - The ADDRESS budgets are set against what an office does, because a NAT or
 *     a VPN concentrator is one address for many people. Fifty sign-ins per
 *     quarter hour from one address is a busy Monday morning; it is also 200
 *     scrypt derivations per hour from one source, which the 4-wide libuv
 *     threadpool absorbs without the queue growing.
 *   - `password-reset` is tighter and slower than the rest. Abusing it is not
 *     only guessing — it sends mail on somebody else's behalf, so the limit is
 *     also a defence against using this installation to send unwanted mail.
 *   - `token-exchange` is the loosest, because it is a machine path: CI presents
 *     a token far more often than a person presents a password. It is also the
 *     cheapest path per attempt — a token is a digest lookup, not a 128 MiB
 *     derivation (migration 7 note 1) — so the resource argument that sets the
 *     others does not apply. Credential stuffing is what bounds it.
 *
 * The address budget is deliberately about five times the account budget on
 * every path. Below roughly that ratio a shared office address trips before any
 * individual does, which trains operators to raise the limit until it stops
 * meaning anything.
 */
export const AUTH_RATE_LIMITS: Readonly<Record<AuthPath, PathRules>> = Object.freeze({
  login: Object.freeze({
    account: Object.freeze({ limit: 10, windowMs: 15 * MINUTE }),
    address: Object.freeze({ limit: 50, windowMs: 15 * MINUTE }),
  }),
  "two-factor": Object.freeze({
    account: Object.freeze({ limit: 10, windowMs: 15 * MINUTE }),
    address: Object.freeze({ limit: 50, windowMs: 15 * MINUTE }),
  }),
  "password-reset": Object.freeze({
    account: Object.freeze({ limit: 5, windowMs: 60 * MINUTE }),
    address: Object.freeze({ limit: 25, windowMs: 60 * MINUTE }),
  }),
  "token-exchange": Object.freeze({
    account: Object.freeze({ limit: 60, windowMs: 15 * MINUTE }),
    address: Object.freeze({ limit: 300, windowMs: 15 * MINUTE }),
  }),
});

// ---------------------------------------------------------------------------
// What a caller names, and what it gets back
// ---------------------------------------------------------------------------

export type AuthAttempt = {
  readonly path: AuthPath;
  /**
   * The identifier the client presented — an email address on the sign-in and
   * reset paths, a token or key identifier on the exchange path.
   *
   * NEVER a resolved user id. It is not looked up, it is not required to name
   * anybody, and the limiter behaves identically whether it does or not. See
   * note 2 in the module header.
   */
  readonly account: string;
  /**
   * The source address, as the server observed it.
   *
   * An empty string is not an error and is not a bypass: every request that
   * cannot be attributed to an address shares ONE bucket, which is the most
   * restrictive reading available and therefore the right one. It will be loud —
   * a deployment behind a misconfigured proxy will refuse everybody quickly
   * rather than quietly limiting nobody.
   */
  readonly address: string;
};

/** What refused an attempt. For the log — see {@link RateLimitDecision.refusedBy}. */
export type RateLimitRefusal = RateLimitDimension | "store-unavailable";

export type RateLimitCounter = {
  readonly dimension: RateLimitDimension;
  readonly limit: number;
  /** Attempts spent in the live window, saturating at the limit. */
  readonly attempts: number;
  /** When this window releases. */
  readonly windowEndsAt: Date;
};

export type RateLimitDecision = {
  /** Whether the caller may go on and do the expensive work. */
  readonly allowed: boolean;
  /**
   * Which dimension refused, or that the store could not be reached.
   *
   * FOR THE LOG, NOT FOR THE RESPONSE. Brief §6.3 requires refusals to be
   * indistinguishable to the caller, so an interface renders every value here as
   * one status and one body. The distinction exists because the operator reading
   * a log at 2am needs it: "this address is spraying" and "this account is under
   * attack" are different incidents with different responses.
   */
  readonly refusedBy: RateLimitRefusal | null;
  /** When the refusing window releases. Null when nothing refused. */
  readonly retryAt: Date | null;
  /** Every counter consulted, in dimension order. Empty when the store failed. */
  readonly counters: readonly RateLimitCounter[];
  /**
   * The failure that caused a store-unavailable refusal, or null.
   *
   * Carried rather than swallowed (brief §9) and rather than thrown: a thrown
   * error is something a caller can catch and continue past, and continuing past
   * this one is the fail-open case. Returning it makes the refusal the value.
   */
  readonly storeError: Error | null;
};

function valueFor(attempt: AuthAttempt, dimension: RateLimitDimension): string {
  return dimension === "account" ? attempt.account : attempt.address;
}

function bucketsFor(attempt: AuthAttempt, rules: PathRules): RateLimitBucket[] {
  return RATE_LIMIT_DIMENSIONS.map((dimension) => ({
    dimension,
    path: attempt.path,
    bucketKey: rateLimitKey(valueFor(attempt, dimension)),
    limit: rules[dimension].limit,
    windowMs: rules[dimension].windowMs,
  }));
}

/**
 * The refusal every store failure produces.
 *
 * One place, so there is exactly one way for this module to answer "the counter
 * could not be consulted", and it is a refusal.
 */
function storeUnavailable(cause: unknown): RateLimitDecision {
  return {
    allowed: false,
    refusedBy: "store-unavailable",
    retryAt: null,
    counters: [],
    storeError:
      cause instanceof Error
        ? cause
        : new Error(`the rate-limit store could not be reached: ${String(cause)}`),
  };
}

/**
 * When the dimension that refused releases.
 *
 * Falls back to "now" rather than null so that `retryAt` is never absent on a
 * refusal: a caller rendering `Retry-After` should not have to decide what to do
 * with a missing one, and "try again now" is the honest answer when the counter
 * that refused has somehow already gone.
 */
function releaseOf(counters: readonly RateLimitCounter[], refused: RateLimitDimension): Date {
  const refusing = counters.find((counter) => counter.dimension === refused);
  return refusing?.windowEndsAt ?? new Date();
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/**
 * Is this attempt currently over a limit? Consults, and spends nothing.
 *
 * For a gate that must not itself consume budget — a request being refused for
 * some other reason before any credential was examined, or an operator screen
 * asking "is this account currently limited". The sign-in path itself should
 * call {@link recordAuthAttempt}, which both counts and decides in one round
 * trip; calling this first and that afterwards would double the work and leave a
 * gap between the two.
 *
 * Absent windows are simply not over the limit. A bucket with no live window has
 * nothing to say.
 */
export async function checkAuthRateLimit(
  ctx: AuthzContext,
  attempt: AuthAttempt,
  rules: PathRules = AUTH_RATE_LIMITS[attempt.path],
): Promise<RateLimitDecision> {
  const buckets = bucketsFor(attempt, rules);
  let live: LiveWindow[];
  try {
    live = await readAuthRateLimits(ctx, buckets);
  } catch (cause) {
    return storeUnavailable(cause);
  }

  const counters: RateLimitCounter[] = [];
  let refusedBy: RateLimitDimension | null = null;
  for (const bucket of buckets) {
    const window = live.find((held) => held.dimension === bucket.dimension);
    if (window === undefined) continue;
    counters.push({
      dimension: bucket.dimension,
      limit: bucket.limit,
      attempts: window.attempts,
      windowEndsAt: window.windowEndsAt,
    });
    // `>=` because the budget is spent when the last permitted attempt has been
    // counted, not one attempt later.
    if (refusedBy === null && window.attempts >= bucket.limit) refusedBy = bucket.dimension;
  }

  return {
    allowed: refusedBy === null,
    refusedBy,
    retryAt: refusedBy === null ? null : releaseOf(counters, refusedBy),
    counters,
    storeError: null,
  };
}

// ---------------------------------------------------------------------------
// record
// ---------------------------------------------------------------------------

/**
 * Count this attempt against both dimensions and say whether it may proceed.
 *
 * THE FUNCTION AN AUTHENTICATION ROUTE CALLS, and it must be called BEFORE the
 * expensive work — before `verifyPassword`, before the mail is sent, before the
 * token is looked up. Called afterwards it is a metric rather than a limit.
 *
 * Both dimensions are always counted, including after one of them has refused;
 * see note 1 in the module header for why that is a correctness property and not
 * a wasted statement.
 *
 * "Allowed" is exactly "the counter had room for this attempt". The repository
 * statement counts an attempt precisely when the budget had space, so there is
 * one fact rather than two — a separate comparison against the limit here would
 * be a second way of deciding the same thing, and therefore a way for the two to
 * disagree.
 */
export async function recordAuthAttempt(
  ctx: AuthzContext,
  attempt: AuthAttempt,
  rules: PathRules = AUTH_RATE_LIMITS[attempt.path],
): Promise<RateLimitDecision> {
  const buckets = bucketsFor(attempt, rules);
  let windows: CountedWindow[];
  try {
    windows = await countAuthAttempts(ctx, buckets);
  } catch (cause) {
    return storeUnavailable(cause);
  }

  const counters: RateLimitCounter[] = buckets.map((bucket, index) => {
    const window = windows[index];
    if (window === undefined) {
      throw new Error(`the ${bucket.dimension} counter came back missing; refusing to guess at it`);
    }
    return {
      dimension: bucket.dimension,
      limit: bucket.limit,
      attempts: window.attempts,
      windowEndsAt: window.windowEndsAt,
    };
  });
  const refused = windows.find((window) => !window.counted);

  return {
    allowed: refused === undefined,
    refusedBy: refused?.dimension ?? null,
    retryAt: refused === undefined ? null : releaseOf(counters, refused.dimension),
    counters,
    storeError: null,
  };
}

// ---------------------------------------------------------------------------
// reset
// ---------------------------------------------------------------------------

/**
 * Clear the ACCOUNT budget for a path whose authentication actually succeeded.
 *
 * The other half of "a window is not a lockout": somebody who mistyped their
 * password four times and then got it right should not spend the next quarter of
 * an hour one mistake away from being refused.
 *
 * Two things it deliberately does NOT do.
 *
 *   - It does not clear the ADDRESS bucket. An attacker who holds one valid
 *     account of their own would otherwise wipe their address budget whenever
 *     they liked and spray from a clean slate for free. Address budgets decay
 *     only by time.
 *   - It does not clear any other PATH. A successful sign-in must not refresh
 *     the two-factor budget, or the second factor could be brute-forced by
 *     re-presenting a password that is already known — which is precisely the
 *     situation two-factor authentication exists for.
 *
 * True when there was a bucket to clear. False is not a failure; it means the
 * account had spent nothing.
 *
 * A store failure here THROWS rather than being turned into a refusal, and the
 * asymmetry with the other two is deliberate: this runs after the credential was
 * accepted, so there is no request left to refuse. Failing to clear a counter
 * costs its holder the rest of the window and nothing else, which is the safe
 * direction, and it must still be loud (§9).
 */
export async function resetAuthRateLimit(ctx: AuthzContext, attempt: AuthAttempt): Promise<boolean> {
  return clearAuthRateLimit(ctx, {
    dimension: "account",
    path: attempt.path,
    bucketKey: rateLimitKey(attempt.account),
  });
}

// ---------------------------------------------------------------------------
// What the interface layer still owes — RL-M1-024 and whoever builds src/api/
//
// Written here rather than in a commit message because a limiter nobody calls
// limits nothing, and this list is the difference between "rate limiting exists"
// and "the authentication endpoints are rate limited".
//
//   1. CALL IT, ON ALL FOUR PATHS, BEFORE THE EXPENSIVE WORK. `signIn` in
//      src/auth/sessions.ts is deliberately untouched by this task — it takes no
//      source address and knows nothing about limits — so the ordering
//      (record, refuse, only then verify) has to be the route handler's, and it
//      is the whole point. A limiter called after `verifyPassword` has already
//      spent the 128 MiB.
//
//   2. DECIDE WHAT THE SOURCE ADDRESS IS, AND DO NOT TRUST A HEADER TO SAY.
//      `X-Forwarded-For` may be honoured only from a proxy the deployment has
//      declared trusted, and only the hop it actually added. A spoofable address
//      makes the address dimension free to evade — the attacker simply picks a
//      new one per request — and worse, lets an attacker exhaust somebody else's
//      budget by claiming their address. This is the single easiest way to make
//      everything above decorative. It connects to R-11 and docs/NETWORK.md.
//
//   3. RENDER EVERY REFUSAL IDENTICALLY. One status (429), one body, and a
//      `Retry-After` derived from `retryAt`. `refusedBy` is for the log; a
//      response that distinguished "this account is limited" from "this address
//      is limited" would leak which of the two the attacker had tripped.
//
//   4. CALL `resetAuthRateLimit` ON SUCCESS, for the login and two-factor paths.
//
//   5. GIVE IT A CONTEXT. Every function here takes an `AuthzContext` and a
//      sign-in attempt has nobody to attribute it to yet — the open seam ADR 0014
//      records and RL-M1-024 has to close, by either a named service identity
//      (which C6 already sanctions, and which the tests here use) or a
//      `contextForSignInAttempt`. It is the same seam sign-in already has; this
//      module adds no new one.
//
//   6. RUN `pruneAuthRateLimits` PERIODICALLY. Hygiene, never enforcement
//      (migration 11 note 8): nothing about whether an attempt is permitted
//      depends on it having run. src/jobs/ belongs to another workstream, so it
//      is not wired here.
//
//   7. BOUND THE WORK BEHIND THE LIMITER AS WELL. This limits per account and
//      per address; it does not bound TOTAL concurrent derivations, because a
//      thousand distinct addresses each under their own budget still produce a
//      thousand sign-ins. What bounds the memory today is the libuv threadpool —
//      four concurrent scrypt calls, so roughly 512 MiB — and what is unbounded
//      is the QUEUE behind it, which is latency and held connections rather than
//      memory. `src/auth/passwords.ts` already names the fix: a bounded queue in
//      front of that module, not weaker parameters.
// ---------------------------------------------------------------------------
