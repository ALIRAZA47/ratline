-- Authentication rate limits (RL-M1-020, threat model R-15).
--
-- Brief §6.7 names "rate limiting on all auth endpoints including password
-- reset" in the security suite's minimum coverage. R-15 says why it is urgent
-- rather than merely listed: the sign-in path derives a 128 MiB scrypt hash per
-- attempt, deliberately including for accounts that do not exist (ADR 0014, so
-- that timing does not reveal which addresses have accounts). That makes an
-- unauthenticated burst a resource lever against a control plane the brief
-- expects to run on a laptop. This table is the counter that closes it.
--
-- Eight notes before changing anything. The first three decide the shape of
-- everything else.
--
-- 1. WHY A COUNTER ROW, AND WHAT IT COSTS ON THE PATH BEING FLOODED.
--    There is no Redis and adding one is out of scope: ADR 0007 rejected a
--    second stateful service for the queue and every word of that reasoning
--    applies here — a self-hosted operator would have to install, secure, patch
--    and back it up, and Redis defaults have a long history of exposure
--    incidents. Postgres is the only shared store, so the counter lives in
--    Postgres. Which leaves the real question: a write on every failed attempt
--    is write amplification on exactly the path an attacker is flooding.
--
--    Three shapes were considered.
--
--      * A ROW PER ATTEMPT, counted with a windowed COUNT(*). Honest sliding
--        window, and unbounded growth under precisely the burst it exists to
--        survive — the attacker chooses the table size. Correctness would then
--        depend on a sweeper keeping up, which is the "cleanup job that silently
--        fails" §6.4 warns about. Rejected.
--      * NO PERSISTENCE — an in-process map. Free, and wrong twice: it is lost
--        on restart, so an attacker resets every counter by causing a crash, and
--        it cannot be reasoned about the moment there is more than one control
--        plane process. Rejected.
--      * ONE ROW PER (tenant, dimension, path, bucket), UPSERTED. Chosen. The
--        row count is bounded by the number of distinct keys seen, not by the
--        number of attempts, so a flood from one address reuses one row forever.
--
--    The cost on the flooded path, stated precisely because "it's just an
--    upsert" is not an answer:
--
--      * Below the limit: one INSERT ... ON CONFLICT DO UPDATE against the
--        primary key. One index probe, one heap update, no new row. The update
--        touches no indexed column (`attempts` is not indexed, and `expires_at`
--        only changes when the window rolls), so it is a HOT update inside the
--        page in the normal case.
--      * AT OR ABOVE THE LIMIT THE STATEMENT STOPS WRITING. The
--        `where … or l.attempts < $limit` guard on the DO UPDATE means a
--        saturated bucket is read and not modified: no new tuple version, no WAL
--        for it, no bloat. So the steady state of a SUSTAINED flood — which is
--        the case that matters, because the first few attempts are the cheap
--        part — is an index probe and a brief row lock, not a write. That is the
--        single most important property of this schema and it is why the
--        counter does not become the attacker's amplifier.
--      * Against the alternative it replaces: one index probe versus 128 MiB and
--        a couple of hundred milliseconds of scrypt. The limiter is roughly four
--        orders of magnitude cheaper than the work it declines to do.
--
--    WHAT HAPPENS WHEN THE BURST IS BIG ENOUGH THAT THE LIMITER ITSELF IS THE
--    BOTTLENECK — the question worth answering honestly. Concurrent attempts
--    against one bucket serialise on that bucket's row lock. They queue, holding
--    a pooled connection each; the pool is bounded (10 by default), so past that
--    requests wait in the pool and then in the listener's accept queue. Latency
--    rises, the pool eventually times out, the repository call throws, and
--    `src/auth/rate_limit.ts` turns that into a REFUSAL (note 6). So an
--    overwhelming burst degrades into: bounded memory, bounded connections,
--    everyone refused, and full recovery the moment the flood stops.
--
--    That is a denial of service, and calling it anything else would be
--    dishonest. It is the trade being made deliberately: without the limiter the
--    same burst reaches scrypt, and the failure is the kernel's OOM killer
--    taking the control plane — unbounded, and not recoverable by waiting. A
--    bounded, loud, self-healing availability failure is strictly better than an
--    unbounded memory one.
--
--    If that ceiling is ever reached in practice the fix is admission control in
--    front of the authentication handlers — a bounded queue, as
--    `src/auth/passwords.ts` already suggests — plus connection limits at the
--    reverse proxy. It is NOT a bigger limit here.
--
-- 2. TWO DIMENSIONS, COUNTED SEPARATELY, NEITHER ABLE TO HIDE THE OTHER.
--    `dimension` is 'account' or 'address', and they are different rows with
--    different budgets because each alone has a hole the other covers:
--
--      * Per account only — one attacker from one address sprays a thousand
--        accounts, ten attempts each, and never trips anything.
--      * Per address only — a botnet with a thousand addresses concentrates on
--        one account, ten attempts each, and never trips anything.
--
--    Both are counted on EVERY attempt, and the caller must not short-circuit
--    when the first one refuses. That is not a micro-optimisation being
--    forgone: if a refusal by the account dimension skipped the address
--    dimension, an attacker would hammer one account until its budget was spent
--    — for free, as far as the address counter was concerned — then move to the
--    next account with a full address budget. Counting both, always, is what
--    makes "independently" in the acceptance criterion true rather than nominal.
--
--    The two statements are issued in a fixed order (account, then address) in
--    one transaction, so two concurrent attempts can never take the two row
--    locks in opposite orders. A deadlock here would be a self-inflicted denial
--    of service on the authentication path.
--
-- 3. THE BUCKET KEY IS A DIGEST OF WHAT WAS PRESENTED, NEVER OF WHAT WAS FOUND.
--    A limiter that counts only attempts against accounts that exist is an
--    account-existence oracle: an attacker learns which addresses are real by
--    seeing which ones start returning "too many attempts". That would give back
--    exactly the disclosure ADR 0014 spends 128 MiB per attempt to prevent. So
--    the key is derived from the identifier the client PRESENTED, before
--    anything is looked up, and nothing in the counting path knows or cares
--    whether it names anybody.
--
--    It is stored as a SHA-256 digest, 64 lowercase hex characters, constrained
--    by `auth_rate_limits_key_shape`. Two reasons, and the second is the one
--    that matters:
--
--      * This table is written by unauthenticated callers, so the plaintext form
--        would be an attacker-populated list of every email address and source
--        address anyone has ever tried, sitting in the database and in every
--        backup of it. A digest is a counter key; a plaintext identifier is a
--        harvest.
--      * The same rule the rest of the schema already follows for credential-
--        adjacent values (migration 7 note 1, migration 10 note 2), so the
--        column shape is one the reviewer has already seen.
--
--    The cost, stated: this table cannot answer "which address is attacking me".
--    It is a counter, not a forensic record. That question belongs to the
--    sign-in audit entries — `audit_entries` already carries an `ip` column —
--    which RL-M1-024 owns, together with the pre-authentication context a
--    sign-in needs. Recording the address here as well would put the same
--    personal data in a second place with a different retention story.
--
-- 4. THE CLOCK IS `statement_timestamp()`, FOR ADR 0012'S REASONING UNCHANGED.
--    A window boundary is an expiry, so the argument transfers word for word:
--
--      * `now()` is frozen for the whole transaction. A window that ended
--        minutes ago would still be judged live late in a long one — which
--        keeps a legitimate user locked out past the window they were promised
--        — and no test that runs inside a single transaction could see it.
--      * `clock_timestamp()` is VOLATILE and advances per row, so the account
--        row and the address row of one decision could be judged against
--        different instants, and no index on `expires_at` would be usable.
--      * `statement_timestamp()` is stable within a statement and advances
--        between them: one decision, one instant, and the next request sees a
--        later one. Chosen.
--
--    It appears in three places, all in `src/repo/rate_limits.ts`: the roll
--    condition, the liveness predicate on the read, and the prune. There is
--    deliberately NO `live_auth_rate_limits` view, and the omission is a
--    decision rather than an oversight. `live_sessions` earns its place because
--    every enforcement path there is a READ and can be pointed at it. Here the
--    enforcement path is a WRITE, and `INSERT ... ON CONFLICT DO UPDATE` cannot
--    take a view as its conflict target — so a `live_` view would be read by the
--    cheap paths and bypassed by the one that matters, which is precisely the
--    misleading half-measure `live_sessions` exists to avoid.
--
-- 5. A WINDOW, NOT A LOCKOUT — AND IT RELEASES WITHOUT AN ADMINISTRATOR.
--    A limit that has to be cleared by a human is a denial of service an
--    attacker triggers against any account they can name, at the cost of one
--    burst. `expires_at` is written when the window opens and is never extended
--    by later attempts, so the window ends at a fixed instant no matter how hard
--    it is hammered — a sliding window would let an attacker hold an account
--    locked out indefinitely by attempting once per window. Two things release
--    it, neither of them a person:
--
--      * Time. Past `expires_at` the next attempt resets the counter to 1 in
--        place; that is the `case` in the DO UPDATE.
--      * Success. `resetAuthRateLimit` deletes the ACCOUNT bucket when an
--        authentication actually succeeds, so someone who mistyped four times
--        and then got it right is not carrying a spent budget around.
--
--    Success deliberately does NOT clear the ADDRESS bucket. If it did, an
--    attacker holding one valid account of their own would clear their address
--    budget at will and spray from a clean slate for free.
--
--    The residual, stated rather than hidden: a determined attacker can keep one
--    named account's bucket saturated for as long as they keep flooding, which
--    denies that account password sign-in for the duration. That is inherent to
--    any per-account limiter, it costs the attacker sustained traffic, it ends
--    when they stop, and the alternative — no per-account limit — is a botnet
--    getting unlimited guesses at one password. The fixed window is what keeps
--    the cost of the attack ongoing rather than one-shot.
--
-- 6. FAILING CLOSED IS THE APPLICATION'S JOB, AND IT IS NOT OPTIONAL.
--    Nothing in this file can make a request be refused when the database is
--    unreachable, because when the database is unreachable this file is not
--    running. The rule lives in `src/auth/rate_limit.ts`: any failure reaching
--    this table produces a refusal, never a pass. A rate limiter that fails open
--    is an availability feature wearing a security feature's clothes, and its
--    failure mode is exactly the flood it exists to stop — the store is most
--    likely to be unreachable precisely because something is overwhelming it.
--    `test/security/rate_limit_auth.test.ts` points the pool at a dead address
--    and asserts the refusal.
--
-- 7. ROW-LEVEL SECURITY, ENABLED AND FORCED, EXACTLY AS MIGRATION 4 APPLIES IT.
--    ENABLE alone is not enough: without FORCE the table owner is exempt, and
--    the owner is who many deployments connect as. `current_setting(..., true)`
--    is NULL when no tenant is bound and `org_id = NULL` is not true, so an
--    unset tenant sees nothing rather than everything. A superuser bypasses all
--    of it, which is why the application connects as `ratline_app` and every
--    assertion in the test file goes through that role.
--
--    The consequence for this table specifically, which is a real weakening and
--    is recorded rather than glossed: the counters are PER TENANT. An attacker
--    who knows several organization ids on one installation gets a fresh address
--    budget in each. It is not avoidable within the existing architecture — a
--    table without `org_id` fails `test/security/identity_invariants.test.ts`
--    (a fourth exception to "every base table is tenant-scoped" is meant to be
--    hard) and could not be read through `scoped()` at all without a second,
--    unscoped data-access primitive, which is the escape hatch C3 exists to
--    forbid. On a self-hosted installation the multiplier is the number of
--    organizations, which is small; it is reported to the threat model rather
--    than solved here.
--
-- 8. NOTHING SWEEPS THIS TABLE, AND NOTHING MAY EVER NEED TO.
--    A bucket whose window has ended is dead weight, not a wrong answer: the
--    next attempt against it resets it in place, and every read filters on
--    `expires_at > statement_timestamp()`. So correctness never depends on a
--    cleanup job — the same rule as grants (ADR 0012), API tokens (migration 7)
--    and sessions (migration 10). `pruneAuthRateLimits` exists for hygiene,
--    deletes only buckets whose window has already ended, and must never appear
--    in the enforcement path. It cannot be used to lift a live limit even by
--    someone calling it in a loop, because a live window does not match its
--    predicate.

-- migrate:up

create table auth_rate_limits (
  org_id            uuid not null references organizations (id) on delete cascade,

  -- 'account' or 'address'. Note 2.
  dimension         text not null,

  -- Which authentication path this budget belongs to. Separate budgets so that
  -- exhausting sign-in does not also lock out password reset, and — the sharper
  -- case — so that a correct password cannot be used to refresh the two-factor
  -- budget by signing in again. See `resetAuthRateLimit`.
  path              text not null,

  -- SHA-256 of the normalised identifier the client PRESENTED. Note 3.
  bucket_key        text not null,

  -- When this window opened, and when it ends. `expires_at` is fixed at the
  -- moment the window opens and is never extended by later attempts (note 5),
  -- which is what makes the release time knowable and unmovable.
  window_started_at timestamptz not null,
  expires_at        timestamptz not null,

  -- Attempts counted in the live window. Saturates at the configured limit
  -- rather than climbing, because past the limit the statement stops writing
  -- (note 1). So this column answers "is the budget spent", not "how big was
  -- the flood" — the second question belongs to metrics and to the audit log.
  attempts          integer not null,

  -- The natural key IS the key. No surrogate id: it would be a second index to
  -- maintain and a gen_random_uuid() call per attempt on the flooded path, for
  -- a column nothing would ever reference.
  primary key (org_id, dimension, path, bucket_key),

  constraint auth_rate_limits_dimension check (dimension in ('account', 'address')),
  constraint auth_rate_limits_path check (
    path in ('login', 'two-factor', 'password-reset', 'token-exchange')
  ),
  -- A SHA-256 digest, lowercase hex. An email address or an IP cannot satisfy
  -- this, so storing one is a constraint violation rather than a review finding.
  constraint auth_rate_limits_key_shape check (bucket_key ~ '^[0-9a-f]{64}$'),
  constraint auth_rate_limits_attempts_counted check (attempts > 0),
  constraint auth_rate_limits_window_has_length check (expires_at > window_started_at)
);

-- Hygiene only (note 8). The enforcement statements all find their row by the
-- primary key; this index exists so that pruning dead windows is a range scan
-- rather than a sequential one. `expires_at` changes only when a window rolls,
-- so it does not cost the common update its HOT path.
create index auth_rate_limits_expiry_idx on auth_rate_limits (expires_at);

-- ---------------------------------------------------------------------------
-- Row-level security (note 7)
-- ---------------------------------------------------------------------------

alter table auth_rate_limits enable row level security;
alter table auth_rate_limits force row level security;
create policy tenant_isolation on auth_rate_limits
  using (org_id = current_tenant())
  with check (org_id = current_tenant());

-- ---------------------------------------------------------------------------
-- Deliberately not done here, so an omission is not mistaken for a decision
--
--   * No trigger and no job. Nothing may enter the enforcement path; see note 8.
--
--   * No `blocked_until` column, and no lockout state. A limit that outlives its
--     window is a lockout, and note 5 is why this schema cannot express one.
--
--   * No foreign key from `bucket_key` to anything. There is nothing to point
--     at: the key is a digest of what was presented, which frequently names
--     nothing at all, and that is the property note 3 exists to preserve.
--
--   * No global (untenanted) bucket. It would need a table row-level security
--     cannot scope; note 7 records the consequence instead.
--
--   * The limits themselves are not in the schema. They are policy, they will be
--     tuned by operators, and a CHECK constraint on them would make tuning a
--     migration. They live in `AUTH_RATE_LIMITS` in `src/auth/rate_limit.ts`,
--     where a test can read them and a reviewer can see all of them at once.
-- ---------------------------------------------------------------------------

-- migrate:down

drop index if exists auth_rate_limits_expiry_idx;

-- The policy, the FORCE setting and the primary-key index go with the table.
drop table if exists auth_rate_limits;
