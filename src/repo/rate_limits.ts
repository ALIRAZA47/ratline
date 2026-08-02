/**
 * The authentication rate-limit counter (RL-M1-020, threat model R-15).
 *
 * This module owns the three statements that touch `auth_rate_limits` and
 * nothing else. The policy — how many attempts, over how long, in what order,
 * and what to do when this module throws — lives in `src/auth/rate_limit.ts`.
 * The split is the same one `src/repo/sessions.ts` and `src/auth/sessions.ts`
 * already draw, and it matters here for one specific reason: the fail-closed
 * rule (migration 11 note 6) is a decision about a FAILURE of this module, so it
 * cannot be made inside it.
 *
 * Every rule the rest of `src/repo/` follows holds:
 *
 *   - `ctx: AuthzContext` is the FIRST parameter of every exported function.
 *   - Nothing writes a tenant predicate by hand. `scoped()` binds the tenant for
 *     the transaction and row-level security applies it.
 *   - The key is a digest supplied by the caller, never a value looked up here.
 *
 * Three things are specific to this module.
 *
 * **The counting statement stops writing once a bucket is spent.** The
 * `where … or l.attempts < $limit` on the DO UPDATE is not a nicety: it is what
 * keeps a sustained flood from turning the limiter into the attacker's write
 * amplifier. Migration 11 note 1 has the full accounting. The consequence for
 * this code is that "was this attempt counted" and "was this attempt allowed"
 * are THE SAME FACT, which is why {@link countAuthAttempts} returns `counted`
 * and the auth layer does not compare anything against the limit itself.
 *
 * **Both dimensions are counted in one transaction, in a fixed order.** Not for
 * atomicity — under-counting one dimension by one would not matter — but so that
 * two concurrent attempts can never take the two row locks in opposite orders.
 * A deadlock on the authentication path would be a self-inflicted outage, so the
 * order is imposed here rather than trusted to callers.
 *
 * **There is no `live_auth_rate_limits` view.** Migration 11 note 4 explains
 * why: the enforcement path is a write, `ON CONFLICT` cannot target a view, and
 * a view read by the cheap paths and bypassed by the expensive one would be
 * worse than none. The liveness predicate is `expires_at > statement_timestamp()`
 * and it appears only in this file.
 */

import { scoped, type ScopedQuery } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";

// ---------------------------------------------------------------------------
// The vocabulary
//
// Mirrors migration 11's CHECK constraints. The schema is the enforcement and
// these are the mirror; `test/security/rate_limit_auth.test.ts` reads both
// constraints back out of Postgres and fails if the two disagree, so the mirror
// cannot quietly become a second, weaker source of truth. That is the pattern
// `src/auth/model.ts` uses for the session ending reasons.
// ---------------------------------------------------------------------------

/**
 * The authentication paths that are limited.
 *
 * Acceptance 1 names exactly these four. They are separate budgets on purpose:
 * spending the sign-in budget must not lock somebody out of password reset, and
 * — the sharper case — a correct password must not be usable to refresh the
 * two-factor budget by signing in again.
 *
 *   login           email plus password, the 128 MiB path (R-15)
 *   two-factor      the second factor, once a first factor has been accepted
 *   password-reset  requesting a reset, which also sends mail on somebody's behalf
 *   token-exchange  presenting an API token or a refresh credential for a session
 */
export const AUTH_PATHS = ["login", "two-factor", "password-reset", "token-exchange"] as const;

export type AuthPath = (typeof AUTH_PATHS)[number];

/**
 * The two things counted, separately and always both (migration 11 note 2).
 *
 * The ORDER of this array is load-bearing: it is the lock order. Reordering it
 * is a correctness change, not a cosmetic one.
 */
export const RATE_LIMIT_DIMENSIONS = ["account", "address"] as const;

export type RateLimitDimension = (typeof RATE_LIMIT_DIMENSIONS)[number];

/** The shape migration 11's `auth_rate_limits_key_shape` constrains the column to. */
export const RATE_LIMIT_KEY_SHAPE = /^[0-9a-f]{64}$/;

// There are deliberately no `isAuthPath` / `isRateLimitDimension` guards here,
// and the reason is worth recording because `src/auth/model.ts` does have the
// equivalent for session ending reasons.
//
// A guard exists there because a value is read BACK out of the database into a
// typed field, so a schema change nobody mirrored has to be survivable. Nothing
// of the kind happens here: `dimension` and `path` travel from the caller into
// the statement and are never read back into a typed value, so a guard would
// have no call site. Writing one anyway would also have failed
// `test/security/scoped_repository.test.ts` — every exported function in this
// layer takes an `AuthzContext` first, and a pure predicate cannot — which is a
// rule pointing in the right direction: this directory is for scoped queries.

// ---------------------------------------------------------------------------
// What a caller names
// ---------------------------------------------------------------------------

/** One bucket: a dimension, a path, and the digest of what the client presented. */
export type RateLimitKey = {
  readonly dimension: RateLimitDimension;
  readonly path: AuthPath;
  /** SHA-256, lowercase hex. Computed by `rateLimitKey` in `src/auth/rate_limit.ts`. */
  readonly bucketKey: string;
};

/** A bucket plus the rule being applied to it. */
export type RateLimitBucket = RateLimitKey & {
  /** Attempts permitted in one window. At least one. */
  readonly limit: number;
  /** How long a window lasts, in milliseconds. At least one. */
  readonly windowMs: number;
};

/** The state of one bucket after an attempt was counted against it. */
export type CountedWindow = {
  readonly dimension: RateLimitDimension;
  /** Attempts spent in the live window, saturating at the limit. */
  readonly attempts: number;
  /** When this window releases. Fixed when the window opened; never extended. */
  readonly windowEndsAt: Date;
  /**
   * Whether this attempt fitted in the budget.
   *
   * The same fact as "may it proceed": the statement counts an attempt exactly
   * when there was room for it, so a false here is a refusal and no separate
   * comparison against the limit is needed or wanted — two ways of deciding the
   * same thing is one way for them to disagree.
   */
  readonly counted: boolean;
};

/** A bucket that currently holds a live window. Absent means "no live window". */
export type LiveWindow = {
  readonly dimension: RateLimitDimension;
  readonly attempts: number;
  readonly windowEndsAt: Date;
};

type WindowRow = { attempts: number; expires_at: Date; counted: boolean };

/**
 * Refuse a key the column would refuse anyway.
 *
 * Not defence in depth for its own sake: the CHECK constraint would turn a
 * mistake here into a failed INSERT, which the auth layer would correctly treat
 * as an unreachable store and refuse the request. That is a safe failure and a
 * baffling one to debug, so the mistake is named where it is made.
 */
function assertKeyShape(bucketKey: string): void {
  if (!RATE_LIMIT_KEY_SHAPE.test(bucketKey)) {
    throw new Error(
      "a rate-limit bucket key must be a SHA-256 digest in lowercase hex. The plaintext " +
        "identifier must never reach this table — see migration 11 note 3.",
    );
  }
}

function assertRule(bucket: RateLimitBucket): void {
  if (!Number.isInteger(bucket.limit) || bucket.limit < 1) {
    throw new Error(`a rate limit must be a positive whole number of attempts, got ${bucket.limit}`);
  }
  if (!Number.isInteger(bucket.windowMs) || bucket.windowMs < 1) {
    throw new Error(`a rate-limit window must be a positive whole number of ms, got ${bucket.windowMs}`);
  }
}

/**
 * The positions of `buckets`, in the canonical lock order.
 *
 * Account before address, then path, then key — the order of
 * {@link RATE_LIMIT_DIMENSIONS}. Imposed here so that no caller can create a
 * lock-ordering deadlock by passing its buckets the other way round, and
 * returned as positions so results can be handed back in the caller's order
 * whatever order the statements ran in.
 */
function lockOrder(buckets: readonly RateLimitKey[]): number[] {
  const rank = (b: RateLimitKey): string =>
    `${RATE_LIMIT_DIMENSIONS.indexOf(b.dimension)}:${b.path}:${b.bucketKey}`;
  return buckets
    .map((bucket, index) => ({ key: rank(bucket), index }))
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((entry) => entry.index);
}

// ---------------------------------------------------------------------------
// Counting an attempt
// ---------------------------------------------------------------------------

/**
 * The one counting statement.
 *
 * Read it as three claims:
 *
 *   1. A bucket that does not exist is created with one attempt against it.
 *   2. A bucket whose window has ENDED is reset in place — counter back to one,
 *      a new window opened at this statement's instant. That is how a limit
 *      releases with nobody having done anything (migration 11 note 5).
 *   3. A bucket with room left is incremented. A bucket with NO room left is not
 *      touched at all: the `where` fails, the DO UPDATE does nothing, and the
 *      UNION ALL branch reads the row back unchanged. That is the saturation
 *      property from migration 11 note 1, and it is why a sustained flood costs
 *      an index probe rather than a write.
 *
 * The second branch of the UNION ALL sees the pre-statement snapshot, which for
 * the saturated case is the current row, and is excluded entirely when the first
 * branch produced anything. So the statement returns exactly one row, always —
 * and `counted` says which branch it came from.
 *
 * `statement_timestamp()` throughout, for ADR 0012's reasoning applied to a
 * window boundary: `now()` is frozen for the transaction, so a window that ended
 * minutes ago would still read as live inside a long one, and `clock_timestamp()`
 * would judge the account row and the address row of one decision against
 * different instants.
 */
const COUNT_ATTEMPT = `
with counted as (
  insert into auth_rate_limits as l
    (org_id, dimension, path, bucket_key, window_started_at, expires_at, attempts)
  values (
    current_tenant(), $1::text, $2::text, $3::text,
    statement_timestamp(),
    statement_timestamp() + ($4::int * interval '1 millisecond'),
    1
  )
  on conflict (org_id, dimension, path, bucket_key) do update
     set attempts = case
           when l.expires_at <= statement_timestamp() then 1
           else l.attempts + 1
         end,
         window_started_at = case
           when l.expires_at <= statement_timestamp() then statement_timestamp()
           else l.window_started_at
         end,
         expires_at = case
           when l.expires_at <= statement_timestamp()
           then statement_timestamp() + ($4::int * interval '1 millisecond')
           else l.expires_at
         end
   where l.expires_at <= statement_timestamp() or l.attempts < $5::int
  returning attempts, expires_at
)
select attempts, expires_at, true as counted from counted
union all
select spent.attempts, spent.expires_at, false as counted
  from auth_rate_limits spent
 where spent.dimension = $1::text
   and spent.path = $2::text
   and spent.bucket_key = $3::text
   and not exists (select 1 from counted)`;

async function countOne(query: ScopedQuery, bucket: RateLimitBucket): Promise<CountedWindow> {
  const rows = await query<WindowRow>(COUNT_ATTEMPT, [
    bucket.dimension,
    bucket.path,
    bucket.bucketKey,
    bucket.windowMs,
    bucket.limit,
  ]);
  const row = rows[0];
  if (row === undefined) {
    // Unreachable by construction: one branch of the UNION ALL always matches.
    // Loud rather than silent, because the alternative — treating "no row" as
    // "allowed" — is a rate limiter that fails open (brief §9, migration 11
    // note 6).
    throw new Error(
      "the rate-limit counter returned no row, which it cannot do. Refusing to guess whether " +
        "this attempt was within its budget.",
    );
  }
  return {
    dimension: bucket.dimension,
    attempts: row.attempts,
    windowEndsAt: row.expires_at,
    counted: row.counted,
  };
}

/**
 * Count one attempt against every bucket named, and say which of them had room.
 *
 * EVERY bucket is counted, including the ones after a refusal. A caller that
 * stopped at the first refusal would let an attacker spend one account's budget
 * without spending any of their address's, then move to the next account with a
 * full one — which is the hole that makes "the dimensions apply independently"
 * nominal rather than true (migration 11 note 2).
 *
 * Results come back in the caller's order, whatever order the statements ran in.
 */
export async function countAuthAttempts(
  ctx: AuthzContext,
  buckets: readonly RateLimitBucket[],
): Promise<CountedWindow[]> {
  for (const bucket of buckets) {
    assertKeyShape(bucket.bucketKey);
    assertRule(bucket);
  }
  return scoped(ctx, async (query) => {
    const results: CountedWindow[] = new Array<CountedWindow>(buckets.length);
    // Sequential, not Promise.all: these share one connection and one
    // transaction, and the fixed order is the deadlock-avoidance rule.
    for (const index of lockOrder(buckets)) {
      const bucket = buckets[index];
      if (bucket === undefined) throw new Error("a bucket vanished between validation and counting");
      results[index] = await countOne(query, bucket);
    }
    return results;
  });
}

// ---------------------------------------------------------------------------
// Reading without counting
// ---------------------------------------------------------------------------

const READ_WINDOW = `
  select attempts, expires_at
    from auth_rate_limits
   where dimension = $1::text
     and path = $2::text
     and bucket_key = $3::text
     and expires_at > statement_timestamp()`;

/**
 * The live windows among these buckets, if any.
 *
 * Read-only: it spends no budget, so it is the right call for a gate that must
 * not itself consume an attempt — a request refused for some other reason before
 * the credential was ever examined, or an operator screen.
 *
 * A bucket with no live window is ABSENT from the result rather than present
 * with a zero. There is nothing to report about a window that does not exist,
 * and a zero-valued row would invite a caller to compare it against a limit.
 */
export async function readAuthRateLimits(
  ctx: AuthzContext,
  keys: readonly RateLimitKey[],
): Promise<LiveWindow[]> {
  for (const key of keys) assertKeyShape(key.bucketKey);
  return scoped(ctx, async (query) => {
    const live: LiveWindow[] = [];
    for (const index of lockOrder(keys)) {
      const key = keys[index];
      if (key === undefined) throw new Error("a bucket vanished between validation and reading");
      const rows = await query<{ attempts: number; expires_at: Date }>(READ_WINDOW, [
        key.dimension,
        key.path,
        key.bucketKey,
      ]);
      const row = rows[0];
      if (row !== undefined) {
        live.push({ dimension: key.dimension, attempts: row.attempts, windowEndsAt: row.expires_at });
      }
    }
    return live;
  });
}

// ---------------------------------------------------------------------------
// Clearing one
// ---------------------------------------------------------------------------

/**
 * Delete one bucket. True when there was one to delete.
 *
 * This is what an authentication SUCCESS calls, so that somebody who mistyped
 * their password four times and then got it right is not carrying a spent budget
 * around (migration 11 note 5).
 *
 * It takes one bucket rather than "everything for this identifier" on purpose.
 * The caller decides which, and `src/auth/rate_limit.ts` clears the ACCOUNT
 * dimension of the path that succeeded and nothing else — never the address
 * dimension, and never another path.
 *
 * No permission check. There is nothing here to protect: the row is a counter
 * keyed by a digest, and the only thing deleting one grants is a fresh budget
 * for the identifier whose credential was just proved. Reaching it requires an
 * `AuthzContext` and the tenant it names, as everything in this layer does.
 */
export async function clearAuthRateLimit(ctx: AuthzContext, key: RateLimitKey): Promise<boolean> {
  assertKeyShape(key.bucketKey);
  return scoped(ctx, async (query) => {
    const rows = await query<{ bucket_key: string }>(
      `delete from auth_rate_limits
        where dimension = $1::text and path = $2::text and bucket_key = $3::text
        returning bucket_key`,
      [key.dimension, key.path, key.bucketKey],
    );
    return rows.length > 0;
  });
}

// ---------------------------------------------------------------------------
// Hygiene, which is not enforcement
// ---------------------------------------------------------------------------

/**
 * Delete buckets whose window has already ended, and say how many.
 *
 * HYGIENE, NEVER ENFORCEMENT. Nothing about whether an attempt is permitted
 * depends on this having run: a dead bucket is reset in place by the next
 * attempt against it, and every read filters on the window being live. It exists
 * because a distributed attack creates one row per source address and those rows
 * would otherwise sit there for ever — a storage question, not a correctness one.
 *
 * The predicate is `expires_at <= statement_timestamp()`, so a live window can
 * never be deleted by it. That is what makes it safe to call from anywhere,
 * repeatedly, without it becoming a way to lift a limit.
 */
export async function pruneAuthRateLimits(ctx: AuthzContext): Promise<number> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ bucket_key: string }>(
      `delete from auth_rate_limits
        where expires_at <= statement_timestamp()
        returning bucket_key`,
    );
    return rows.length;
  });
}
