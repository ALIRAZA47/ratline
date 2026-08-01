-- API tokens, bounded by the user who issued them (RL-M1-032, threat model R-12).
--
-- Brief §6.3: "API tokens carry a subset of the issuing user's permissions and
-- never more. Scoped, expiring, revocable, with last-used tracking and an
-- obvious revoke-all."
--
-- Migration 5 added the `api_token` subject kind so a token could hold a
-- *narrower* set than its issuer, and said in as many words that the subject
-- kind is not the ceiling. This migration adds the table; `can()` adds the
-- ceiling. Read the five notes below before changing anything here, because
-- three of them are the difference between a token store and a credential store.
--
-- 1. ONLY A HASH IS STORED, AND THE COLUMN CANNOT HOLD A TOKEN.
--    The plaintext is returned exactly once, at creation, and never again — a
--    token that can be read back out of the database is not a token, it is a
--    stored credential, and a database backup becomes a set of live logins. What
--    is stored is a SHA-256 digest, and `api_tokens_hash_shape` constrains the
--    column to 64 lowercase hex characters, so a plaintext token does not merely
--    violate a convention, it violates a CHECK. ADR 0006's envelope encryption
--    is deliberately NOT used: there is nothing to decrypt to, because nothing
--    ever needs the plaintext back. A digest is the weaker-looking choice and
--    the stronger one.
--
--    A plain digest rather than a password KDF is correct *here* and would be
--    wrong for a password: the input is 256 bits from a cryptographic source, so
--    there is no dictionary to attack and no work factor to buy. Adding one
--    would only make every request slower.
--
-- 2. THE CEILING IS ENFORCED AT USE TIME, AND NOT IN THIS FILE.
--    Nothing here may be read as the intersection with the issuing user. A
--    token's grants are ordinary rows in `grants` with `subject_type =
--    'api_token'`, and they resolve exactly like anyone else's — which is
--    precisely why the ceiling cannot live in the schema: it is the intersection
--    of two subjects' answers, and `grant_decision` answers about one subject at
--    a time. `can()` (src/authz/can.ts) requires the ISSUING USER to be allowed
--    the same action at the same scope before a token is allowed anything. Issue
--    time alone would leave a demoted user's token carrying an Admin's reach
--    forever, which is R-12 word for word.
--
--    `issued_by` exists so that check has something to ask about.
--
-- 3. EXPIRY AND REVOCATION ARE QUERY PREDICATES, NOT A CLEANUP JOB.
--    The same rule as grants, for the same reason (brief §6.3, ADR 0012), and
--    expressed the same way: one view, `live_api_tokens`, holds the predicate,
--    and every path that asks whether a token may act reads that view rather
--    than the table. `statement_timestamp()` is the clock — `now()` is frozen for
--    the whole transaction, so a token that lapsed minutes ago would still be
--    honoured late in a long one, and `clock_timestamp()` is volatile enough that
--    two rows of one decision could be judged against different instants. No job
--    sweeps expired tokens, and none may ever be in the enforcement path.
--
-- 4. EXPIRY IS MANDATORY, WHICH IS WHERE THIS DEPARTS FROM GRANTS.
--    `grants.expires_at` is nullable and null means never, because most grants
--    are permanent by design. A token is a credential that lives in CI
--    configuration, on laptops and in shell history, and §6.3 lists "expiring"
--    as part of what a token IS. So the column is NOT NULL: there is no way to
--    mint one that never dies. The check compares against the row's own
--    `created_at` rather than the wall clock for migration 5's reason — Postgres
--    refuses a non-immutable function in a CHECK, and a wall-clock rule would
--    make a valid row un-updatable and a dump un-restorable purely because time
--    passed.
--
-- 5. `issued_by` REFERENCES `users`, DELIBERATELY NOT `memberships`.
--    A composite foreign key to `memberships (org_id, user_id)` was the first
--    design and is rejected on purpose. It would have been a real invariant —
--    the issuer provably a member of the tenant — but it buys that by deleting
--    the token when the membership goes, which loses the record that the token
--    ever existed, and it splits one rule across two mechanisms: a departed
--    issuer would be enforced by a cascade while a DISABLED issuer, which no
--    foreign key can express, would still have to be enforced in `can()`. One
--    rule, one place: `can()` asks whether the issuing user is still an enabled
--    member of this tenant, and answers the departed and the disabled case
--    identically. The row survives for the audit log, inert.
--
--    The cascade from `users` stays, because a deleted account is not a
--    membership question — there is no issuer left to intersect against, so
--    there is nothing for the token to be a subset of.

-- migrate:up

create table api_tokens (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations (id) on delete cascade,

  -- The user whose permissions bound this token. See note 5.
  issued_by     uuid not null references users (id) on delete cascade,

  -- Operator-facing label: "CI deploys", "laptop". Not a secret and not unique —
  -- reusing the name of a revoked token is normal, not a mistake.
  name          text not null,

  -- The digest. Never the token. See note 1.
  token_hash    text not null,

  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,

  -- Null means live. Revocation is recorded rather than deleted so that "this
  -- token was killed at 14:02" survives, and so a revoked token cannot be
  -- resurrected by re-inserting the same row.
  revoked_at    timestamptz,

  -- Null means never used. Written by the authentication path, once per request.
  last_used_at  timestamptz,

  unique (token_hash),

  constraint api_tokens_name_present check (length(btrim(name)) > 0),
  -- A SHA-256 digest, lowercase hex. A plaintext token cannot satisfy this, so
  -- storing one is a constraint violation rather than a code review finding.
  constraint api_tokens_hash_shape check (token_hash ~ '^[0-9a-f]{64}$'),
  constraint api_tokens_expiry_after_creation check (expires_at > created_at),
  constraint api_tokens_revoked_after_creation check (revoked_at is null or revoked_at >= created_at),
  constraint api_tokens_used_after_creation check (last_used_at is null or last_used_at >= created_at)
);

-- Supports listing and revoking every token a person holds — §6.3's "obvious
-- revoke-all" — and the ownership question the manage_own / revoke_any split
-- turns on.
create index api_tokens_issued_by_idx on api_tokens (org_id, issued_by);

-- ---------------------------------------------------------------------------
-- Row-level security: layer 3 of C3, exactly as migration 4 applies it
--
-- ENABLE alone is not enough. Without FORCE the table owner is exempt, and the
-- owner is who many deployments connect as, which would leave the policy
-- decorative. `current_setting(..., true)` returns NULL when the tenant is
-- unset and `org_id = NULL` is not true, so an unset tenant sees nothing rather
-- than everything.
-- ---------------------------------------------------------------------------

alter table api_tokens enable row level security;
alter table api_tokens force row level security;
create policy tenant_isolation on api_tokens
  using (org_id = current_tenant())
  with check (org_id = current_tenant());

-- ---------------------------------------------------------------------------
-- Liveness
--
-- The one place expiry and revocation are expressed. Everything that asks
-- whether a token may act reads this view; reading `api_tokens` directly to
-- answer that question is the single mistake that would make a revoked or
-- expired token work, which is why there is somewhere else to read instead.
--
-- `security_invoker = true` for migration 5's reason: a view runs with its
-- OWNER's permissions by default, and the owner here is the migration role — a
-- superuser in most deployments, and a superuser bypasses row-level security
-- unconditionally. Without this line the view hands every tenant's tokens to
-- anyone who can select from it.
-- ---------------------------------------------------------------------------

create view live_api_tokens with (security_invoker = true) as
  select
    t.id,
    t.org_id,
    t.issued_by,
    t.name,
    t.token_hash,
    t.created_at,
    t.expires_at,
    t.last_used_at
  from api_tokens t
  where t.revoked_at is null
    and t.expires_at > statement_timestamp();

-- ---------------------------------------------------------------------------
-- Deliberately not done here, so an omission is not mistaken for a decision
--
--   * `grants.subject_id` is still not a foreign key to this table. It cannot
--     be: a grant's subject may be a user, a service identity or a token, so the
--     column cannot point at one table. A grant naming a deleted token conveys
--     nothing — `can()` refuses an actor it cannot find — so this fails closed,
--     but it does leave rows behind. Cleaning them up is hygiene and must never
--     become part of enforcement.
--
--   * A token's grants are written with no `expires_at` of their own. The
--     token's expiry is the enforcement and is asked once per request, the way
--     "may this actor act at all" is asked once per request rather than once per
--     node. Copying the token's expiry onto each grant would look like defence in
--     depth and would collide with migration 5's
--     `grants_owner_floor_is_unconditional`, which refuses an expiring
--     organization-scope owner grant whatever its subject kind.
--
--   * Migration 2's last-owner trigger counts organization-scope owner grants
--     WITHOUT filtering `subject_type`, so a token holding `owner` at
--     organization scope satisfies the floor that brief §6.3 requires a person to
--     satisfy. That is pre-existing — the subject kind has been writable since
--     migration 5 — and fixing it means editing an applied migration's function,
--     which this task may not do. Recorded here and reported rather than
--     silently worked around.

-- migrate:down

-- The view first. Dropping a table out from under a dependent view needs
-- CASCADE, which this repository bans: a down path that removes objects it did
-- not name is not a rollback.
drop view if exists live_api_tokens;

drop index if exists api_tokens_issued_by_idx;

-- The policy, the FORCE setting and the unique index go with the table.
drop table if exists api_tokens;
