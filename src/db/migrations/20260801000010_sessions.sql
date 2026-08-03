-- Sessions: the credential a signed-in person carries (RL-M1-017).
--
-- Brief §6.7 lists session fixation in the minimum security suite, and §6.3
-- requires that role changes "take effect immediately, including on active
-- sessions". Both of those are properties of this table rather than of a route
-- handler, so they are written here.
--
-- Six notes before changing anything. The first is the one that decides the
-- shape of everything else.
--
-- 1. A SESSION IS TENANT-SCOPED. A USER IS NOT.
--    Migration 2 says in as many words that `users` is deliberately global —
--    "one human, one account, many organizations" — and migration 4 scopes it
--    by shared membership rather than by a column. A session goes the other
--    way and carries a NOT NULL `org_id`, for four reasons:
--
--      a. A person is one person; a session is not a person, it is an act of
--         access. Brief §3.3's tiebreaker is blast-radius control, and the
--         blast radius of a stolen cookie should be one organization rather
--         than everything its owner can reach.
--      b. Structurally, it is what makes the table reachable at all. `scoped()`
--         (ADR 0003 layer 2) is the only thing in the codebase that runs SQL,
--         and it binds one tenant per transaction. A session row with no
--         `org_id` could not be read through it without a second, unscoped
--         primitive — which is the escape hatch C3 exists to forbid.
--      c. RL-M1-018 requires a role change to reach an active session
--         immediately. A session bound to one organization is judged against
--         that organization's grants on every request; a session spanning
--         organizations would have to decide which tenant's rules applied.
--      d. Removing someone from an organization ends their access there and
--         leaves their access elsewhere alone, with no cleanup job.
--
--    The suite already held the same opinion before this table existed:
--    test/security/identity_invariants.test.ts requires every base table to
--    carry a non-nullable `org_id` and allows exactly three argued exceptions —
--    `organizations`, `users` and `schema_migrations`. A session that was not
--    tenant-scoped would have had to become a fourth, and that test says out
--    loud that a fourth should be hard, because a table without `org_id` is a
--    table row-level security cannot scope.
--
--    The cost, stated rather than hidden: a person who belongs to three
--    organizations holds three sessions, and switching organization mints a new
--    one. That is not an accident of the design, it is note 4 — switching
--    organization IS a privilege change, so it has to rotate the identifier
--    anyway.
--
-- 2. ONLY A DIGEST IS STORED, AND THE COLUMN CANNOT HOLD A TOKEN.
--    Exactly migration 7's rule for API tokens, for exactly its reasons. The
--    token is returned once, at creation, and never again; what is stored is a
--    SHA-256 digest, and `sessions_hash_shape` constrains the column to 64
--    lowercase hex characters, so writing a plaintext token here is a
--    constraint violation rather than a code review finding. A database backup
--    is then a set of dead references rather than a set of live logins.
--
--    A plain digest rather than a password KDF is correct here and would be
--    wrong for a password. The input is 256 bits from the platform CSPRNG, so
--    there is no dictionary to attack and no work factor to buy; adding one
--    would cost a memory-hard hash on every authenticated request. The password
--    itself IS hashed with a memory-hard function, in src/auth/passwords.ts,
--    because a password is drawn from a distribution a human chose.
--
-- 3. EXPIRY AND REVOCATION ARE QUERY PREDICATES, NOT A CLEANUP JOB.
--    The same rule as grants (ADR 0012) and API tokens (migration 7), expressed
--    the same way: one view, `live_sessions`, holds both predicates, and every
--    path that asks whether a session may act reads that view rather than the
--    table. Reading `sessions` directly to answer that question is the single
--    mistake that would honour a revoked session, which is why there is
--    somewhere else to read instead.
--
--    `statement_timestamp()` is the clock, for ADR 0012's reasoning applied
--    unchanged: `now()` is frozen for the whole transaction, so a session that
--    lapsed minutes ago would still be honoured late in a long one — and no
--    test inside a single transaction could catch it. `clock_timestamp()` is
--    volatile, so two rows of one decision could be judged against different
--    instants and no index on `expires_at` would be usable.
--    `statement_timestamp()` is stable within a statement and advances between
--    them, which is exactly "evaluated when the request is served".
--
-- 4. ROTATION IS A NEW ROW, NOT AN EDIT.
--    Session fixation is the attack where an identifier planted before sign-in
--    is still honoured after it. Two defences are possible and only one of them
--    leaves evidence:
--
--      * Overwrite `token_hash` in place. The old identifier stops working, but
--        the row that recorded it is gone, so a replay is indistinguishable
--        from a typo and there is nothing to show an operator.
--      * Revoke the old row and insert a new one, with `rotated_from` naming
--        its predecessor. The old identifier is not merely absent, it is
--        recorded dead with a reason and a time, and the chain of a session
--        across sign-in and privilege changes is readable.
--
--    The second is chosen. It also means the fixation defence and the
--    revocation mechanism are one mechanism rather than two, so there is one
--    thing to get right.
--
-- 5. NO COMPOSITE FOREIGN KEY TO `memberships`, FOR MIGRATION 7'S REASON.
--    A key to `memberships (org_id, user_id)` was considered and is rejected on
--    the same grounds note 5 of migration 7 rejects it for tokens: it buys a
--    real invariant by deleting the row when the membership goes, which loses
--    the record that anyone was ever signed in, and it splits one rule across
--    two mechanisms — a departed member enforced by a cascade while a DISABLED
--    member, which no foreign key can express, still has to be refused by
--    `can()`. One rule, one place: `can()` asks whether the actor is still an
--    enabled member of this tenant, on every decision, and answers the departed
--    and the disabled case identically.
--
--    The invariant is not lost, it is enforced where sessions are created: the
--    insert in src/repo/sessions.ts selects from `memberships`, so a session for
--    a non-member writes zero rows.
--
-- 6. ROW-LEVEL SECURITY, ENABLED AND FORCED, EXACTLY AS MIGRATION 4 APPLIES IT.
--    ENABLE alone is not enough: without FORCE the table owner is exempt, and
--    the owner is who many deployments connect as, which would leave the policy
--    decorative. `current_setting(..., true)` returns NULL when the tenant is
--    unset and `org_id = NULL` is not true, so an unset tenant sees nothing
--    rather than everything. And a superuser bypasses all of it, which is why
--    the application connects as `ratline_app` and the tests assert through it.

-- migrate:up

create table sessions (
  id             uuid primary key default gen_random_uuid(),

  -- Note 1. A session is one person acting in one organization.
  org_id         uuid not null references organizations (id) on delete cascade,
  user_id        uuid not null references users (id) on delete cascade,

  -- The digest. Never the token. See note 2.
  token_hash     text not null,

  created_at     timestamptz not null default now(),

  -- Mandatory, as for API tokens: a credential that never dies is not a
  -- session. The check compares against the row's own `created_at` rather than
  -- the wall clock, because Postgres refuses a non-immutable function in a
  -- CHECK — and a wall-clock rule would make a valid row un-updatable and a
  -- dump un-restorable purely because time passed (migration 5).
  expires_at     timestamptz not null,

  -- Brief §6.3 asks for last-used tracking on credentials. Written by the
  -- validation path in the same statement that reads the session, so it cannot
  -- be forgotten by a caller. Null means never used since it was issued.
  last_seen_at   timestamptz,

  -- Null means live. Revocation is recorded rather than deleted, so "this
  -- session was killed at 14:02, because the identifier rotated" survives, and
  -- so a revoked session cannot be resurrected by re-inserting the same row.
  revoked_at     timestamptz,
  revoked_reason text,

  -- The session this one replaced, when it was minted by rotation (note 4).
  -- Points backwards so that minting the successor is a single INSERT and the
  -- predecessor never has to be edited again.
  rotated_from   uuid references sessions (id) on delete set null,

  -- Context for the "these are your sessions" screen and for recognising a
  -- stolen cookie after the fact. Not identity, and never trusted as such.
  user_agent     text not null default '',
  ip             inet,

  unique (token_hash),

  -- A SHA-256 digest, lowercase hex. A plaintext token cannot satisfy this.
  constraint sessions_hash_shape check (token_hash ~ '^[0-9a-f]{64}$'),
  constraint sessions_expiry_after_creation check (expires_at > created_at),
  constraint sessions_revoked_after_creation check (revoked_at is null or revoked_at >= created_at),
  constraint sessions_seen_after_creation check (last_seen_at is null or last_seen_at >= created_at),

  -- C6: no privileged action without an attributable reason. A session that
  -- ended without one, or a reason with no ending, are both incoherent states.
  constraint sessions_end_is_attributable check ((revoked_at is null) = (revoked_reason is null)),
  constraint sessions_end_reason check (
    revoked_reason is null
    or revoked_reason in ('signed-out', 'rotated', 'privilege-change', 'revoked', 'password-changed')
  ),

  constraint sessions_rotated_from_is_not_self check (rotated_from is null or rotated_from <> id)
);

-- Supports "sign me out everywhere" and "end this member's sessions" — the
-- compromised-account case — and the list of a person's own sessions.
create index sessions_user_idx on sessions (org_id, user_id);

-- ---------------------------------------------------------------------------
-- Row-level security (note 6)
-- ---------------------------------------------------------------------------

alter table sessions enable row level security;
alter table sessions force row level security;
create policy tenant_isolation on sessions
  using (org_id = current_tenant())
  with check (org_id = current_tenant());

-- ---------------------------------------------------------------------------
-- Liveness (note 3)
--
-- The one place expiry and revocation are expressed. `security_invoker = true`
-- because a view runs with its OWNER's permissions by default, and the owner
-- here is the migration role — a superuser in most deployments, and a superuser
-- bypasses row-level security unconditionally. Without this line the view hands
-- every tenant's sessions to anyone who can select from it.
--
-- `token_hash` is carried so the authentication path can look a session up by
-- the digest of the credential it was handed, without ever reading the table.
-- ---------------------------------------------------------------------------

create view live_sessions with (security_invoker = true) as
  select
    s.id,
    s.org_id,
    s.user_id,
    s.token_hash,
    s.created_at,
    s.expires_at,
    s.last_seen_at,
    s.rotated_from,
    s.user_agent,
    s.ip
  from sessions s
  where s.revoked_at is null
    and s.expires_at > statement_timestamp();

-- ---------------------------------------------------------------------------
-- Deliberately not done here, so an omission is not mistaken for a decision
--
--   * No idle timeout. `expires_at` is absolute and fixed when the session is
--     created; it is never extended on use, so an identifier's lifetime is
--     bounded no matter how busy its holder is. Renewal is rotation — a new
--     row, a new identifier — which is the same mechanism as note 4 rather
--     than a second one. A sliding window would make "how long can a stolen
--     cookie live" unanswerable, which is the question this column exists to
--     answer.
--
--   * No trigger, and no job. Nothing sweeps expired or revoked rows, and
--     nothing may ever be added to the enforcement path. If retention ever
--     trims old rows it is hygiene, and `live_sessions` must remain correct
--     with no such job running at all.
--
--   * `password_hash` stays on `users`, where migration 2 put it, with its
--     existing "null means SSO-only, empty string is not allowed" constraint.
--     Moving it here would separate a person's password from the person.
--
--   * Two-factor enrolment is not modelled. RL-M1-019 owns it, and it changes
--     what "authenticated" means rather than what a session is — a session
--     minted before a second factor is presented is a different row from the
--     one minted after it, by note 4, so the seam is already the right shape.

-- migrate:down

-- The view first. Dropping a table out from under a dependent view would need
-- CASCADE, which this repository bans: a down path that removes objects it did
-- not name is not a rollback.
drop view if exists live_sessions;

drop index if exists sessions_user_idx;

-- The policy, the FORCE setting, the self-reference and the unique index all go
-- with the table.
drop table if exists sessions;
