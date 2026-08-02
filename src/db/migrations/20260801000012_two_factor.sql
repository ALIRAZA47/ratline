-- Two-factor authentication, and the organization policy that requires it
-- (RL-M1-019).
--
-- Brief §6.3: "SSO via OIDC/SAML and enforced 2FA as org-level policies."
-- Migration 10's closing note handed this task the seam it left open: two-factor
-- "changes what 'authenticated' means rather than what a session is".
--
-- Nine notes before changing anything. The first three decide the shape of
-- everything else.
--
-- 1. THERE IS NO HALF-AUTHENTICATED SESSION. A CHALLENGE IS A DIFFERENT ROW IN
--    A DIFFERENT TABLE.
--    The obvious design adds `two_factor_passed_at` to `sessions` and filters on
--    it. It was rejected, and the reason is the same one that decides most of
--    this schema: a nullable column on `sessions` makes every existing reader of
--    that table wrong by omission. `live_sessions` would keep handing back a
--    password-only session, `useSessionToken` would keep stamping it, and the
--    only thing standing between a stolen half-session and a full one would be
--    every future caller remembering a predicate.
--
--    So a person who owes a second factor gets NO session at all. They get a
--    `two_factor_challenges` row: a short-lived, single-use bearer credential
--    that proves a password was accepted and is good for exactly one thing —
--    being exchanged for a session by presenting a second factor. A caller that
--    knows nothing about two-factor authentication therefore fails CLOSED: it
--    receives no session token, because there is no session.
--
--    The consequence, stated: two credentials exist on the sign-in path instead
--    of one, and `two_factor_challenges` has to carry its own expiry and
--    single-use rules. That is a real cost, paid to avoid a predicate somebody
--    can forget.
--
-- 2. THE TOTP SECRET IS SEALED, NOT HASHED — AND THAT IS THE ONE PLACE THIS
--    SCHEMA DEPARTS FROM MIGRATIONS 7, 10 AND 11.
--    A session identifier and an API token are stored as digests because nothing
--    ever needs the plaintext back. A TOTP secret is different in kind: the
--    server has to recompute HMAC(secret, counter) on every verification, so
--    there is no digest that would do. It is therefore ENCRYPTED, under
--    ADR 0006's envelope shape — a fresh data key per enrolment, sealed with
--    AES-256-GCM, the data key wrapped by the key-encryption key that lives on
--    disk and never in this database (C4, `src/crypto/secrets.ts`).
--
--    `two_factor_enrolments_secret_shape` constrains the column to the sealed
--    form, so a bare base32 secret is a constraint violation rather than a code
--    review finding — the same protection `sessions_hash_shape` gives, expressed
--    for a different encoding.
--
--    What this buys and what it does not: a stolen database is a set of
--    unusable ciphertexts, and a stolen database PLUS the key file is a set of
--    usable second factors. That is inherent to a shared secret. TOTP has no
--    variant where the verifier holds something it cannot impersonate with; the
--    scheme that does is WebAuthn, which is out of scope for this task and is
--    recorded as the honest upgrade path rather than pretended away.
--
-- 3. REPLAY IS PREVENTED BY A MONOTONIC STEP, NOT BY A TABLE OF USED CODES.
--    A TOTP code is valid for a whole period, and verification accepts one step
--    either side of now for clock skew — so without a guard, a code observed
--    over the operator's shoulder or captured from a phishing page is replayable
--    for up to ninety seconds. `last_used_step` records the highest counter this
--    enrolment has ever accepted, and the update that records it refuses to move
--    backwards or stand still. So a code that has been used is dead, and so is
--    every earlier code in the window.
--
--    A `used_codes` table was the alternative and is worse in every dimension:
--    it grows, it needs sweeping, and correctness would then depend on the sweep
--    keeping up — the "cleanup job that silently fails" this repository refuses
--    everywhere else. One bigint on the row it belongs to has none of that.
--
--    The cost, stated: two devices belonging to the same person cannot both
--    verify within one period, and a person who mistypes and then retypes the
--    same code in the same period is refused. That is the correct answer to the
--    second case and an acceptable one to the first.
--
-- 4. AN ENROLMENT IS PER (ORGANIZATION, PERSON), AS A SESSION IS.
--    Migration 10 note 1's argument transfers, and one part of it is sharper
--    here: an organization that REQUIRES a second factor must be able to say
--    something about the factor its members present — that it exists, when it
--    was enrolled, that its recovery codes are spent. A factor enrolled in
--    another tenant is one this tenant cannot see, cannot audit and cannot
--    require. The structural half is the same as for sessions: a table without
--    `org_id` cannot be read through `scoped()` and fails
--    `test/security/identity_invariants.test.ts`.
--
--    The cost is real and is not hidden: a person who belongs to three
--    organizations enrols three times and carries three entries in their
--    authenticator application. `otpauth` URIs name the organization in the
--    issuer field precisely so those three entries are distinguishable.
--
-- 5. A PENDING ENROLMENT IS NOT A SECOND FACTOR.
--    `confirmed_at` is null until the person has proved they can produce a code
--    from the secret they were handed. Everything that asks "does this person
--    have a second factor" reads `confirmed_two_factor_enrolments`, never the
--    table. Without the split, generating a secret would immediately lock
--    somebody out of their own account the moment they closed the tab before
--    scanning the QR code — and worse, an organization policy check would count
--    an abandoned enrolment as compliance.
--
-- 6. RECOVERY CODES ARE HASHED, SINGLE USE, AND SPENDING ONE IS AN UPDATE, NOT
--    A SELECT-THEN-UPDATE.
--    Hashed for migration 7 note 1's reason exactly: 80 bits from the platform
--    CSPRNG, so there is no dictionary to attack and a password KDF would buy
--    nothing. Eighty rather than the usual 256 because a person TYPES this one
--    on the worst day they will have with the product, and what it has to
--    survive is an online guess through a limiter that permits ten attempts a
--    quarter hour — see `RECOVERY_CODE_BYTES` in src/auth/totp.ts for the
--    arithmetic. Single use is enforced by `used_at`, and the enforcement is
--    `update … where used_at is null returning id` — one statement, so two
--    concurrent redemptions of the same code cannot both win. A read followed by
--    a write would be a race with a very attractive prize.
--
--    Spending one is AUDITED by the application (C6, `recordAudit`). The row's
--    `used_at` says when; the audit entry says who was acting, from where, and
--    with which request id, which is what an incident review needs.
--
-- 7. THE POLICY IS A ROW, NOT A COLUMN ON `organizations`.
--    `organization.manage_security_policy` already exists in the catalogue and
--    its description already names three settings: enforced two-factor
--    authentication, session lifetime and minimum SSH key strength. Only the
--    first is implemented here; the other two get columns when they get
--    behaviour. A separate table keeps `organizations` as identity — the thing
--    every policy in migration 4 compares against — rather than turning it into
--    the settings bag every schema eventually grows.
--
--    ABSENCE MEANS NOT REQUIRED. There is no row for an organization that has
--    never set a policy, and the read treats that as `false`. The alternative —
--    a row minted with every organization — would need a trigger or an
--    application convention, and either one produces a tenant with no policy row
--    the first time somebody inserts an organization by hand.
--
-- 8. ROW-LEVEL SECURITY, ENABLED AND FORCED, EXACTLY AS MIGRATION 4 APPLIES IT.
--    ENABLE alone is not enough: without FORCE the table owner is exempt, and
--    the owner is who many deployments connect as, which would leave the policy
--    decorative. `current_setting(..., true)` returns NULL when the tenant is
--    unset and `org_id = NULL` is not true, so an unset tenant sees nothing
--    rather than everything. A superuser bypasses all of it, which is why the
--    application connects as `ratline_app` and every assertion in
--    `test/security/twofactor.test.ts` goes through that role.
--
-- 9. EXPIRY IS A QUERY PREDICATE. NOTHING SWEEPS ANY OF THESE TABLES.
--    The same rule as grants (ADR 0012), API tokens (migration 7), sessions
--    (migration 10) and rate limits (migration 11), expressed the same way: one
--    view, `live_two_factor_challenges`, holds both the expiry and the
--    single-use predicate, and every path that asks whether a challenge may be
--    exchanged reads that view rather than the table. `statement_timestamp()` is
--    the clock, for ADR 0012's reasoning unchanged — `now()` is frozen for the
--    whole transaction, so a challenge that lapsed minutes ago would still be
--    honoured late in a long one, and no test running inside one transaction
--    could catch it.

-- migrate:up

-- ---------------------------------------------------------------------------
-- The organization policy (note 7)
-- ---------------------------------------------------------------------------

create table organization_security_policies (
  -- The organization IS the key. A surrogate id would be a second index for a
  -- column nothing would ever reference, and would permit two policies for one
  -- tenant, which is not a state this table should be able to express.
  org_id              uuid primary key references organizations (id) on delete cascade,

  -- Brief §6.3: "enforced 2FA as org-level policies". Absence of the row means
  -- false; see note 7 for why there is no row per organization by default.
  two_factor_required boolean not null default false,

  updated_at          timestamptz not null default now(),

  -- C6: a policy change is a privileged action and has somebody behind it. The
  -- reference is to `users` rather than `memberships` for migration 7 note 5's
  -- reason: losing the record of who set a policy when they leave would be
  -- losing the only thing this column is for.
  updated_by          uuid references users (id)
);

-- ---------------------------------------------------------------------------
-- Enrolment (notes 2, 3, 4, 5)
-- ---------------------------------------------------------------------------

create table two_factor_enrolments (
  id                uuid primary key default gen_random_uuid(),

  -- Note 4. One person acting in one organization, as a session is.
  org_id            uuid not null references organizations (id) on delete cascade,
  user_id           uuid not null references users (id) on delete cascade,

  -- The sealed secret. Never the secret. See note 2, and `sealSecret` in
  -- src/auth/totp.ts for the encoding this shape describes.
  secret_sealed     text not null,

  -- The parameters this enrolment's codes are computed with. They travel with
  -- the row for src/auth/passwords.ts's reason: an authenticator application
  -- has already been configured with them, so changing the defaults must not
  -- invalidate an enrolment made under the old ones.
  algorithm         text not null,
  digits            smallint not null,
  period_seconds    smallint not null,

  created_at        timestamptz not null default now(),

  -- Null until a code from this secret has been produced. Note 5.
  confirmed_at      timestamptz,

  -- The highest counter this enrolment has ever accepted. Note 3. Null means
  -- none, which is the state a pending enrolment starts in.
  last_used_step    bigint,

  -- One enrolment per person per tenant. Re-enrolling REPLACES, so that a lost
  -- phone leaves no second secret behind that would still verify.
  unique (org_id, user_id),

  -- A sealed value in the form src/auth/totp.ts writes:
  -- `v1$<wrapped data key>$<sealed secret>`, both base64url. A bare base32
  -- secret cannot satisfy this, so storing one is a constraint violation rather
  -- than a review finding — migration 10 note 2's protection, for a different
  -- encoding.
  constraint two_factor_enrolments_secret_shape check (
    secret_sealed ~ '^v1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$'
  ),

  -- RFC 6238 §1.2 names these three. SHA-1 is the interoperable default and is
  -- sound here: TOTP relies on HMAC, and HMAC-SHA1 has no practical break —
  -- the collision attacks on SHA-1 do not transfer to a keyed MAC.
  constraint two_factor_enrolments_algorithm check (algorithm in ('SHA1', 'SHA256', 'SHA512')),
  -- RFC 4226 §5.3 permits six to ten; every authenticator in practice does six
  -- to eight, and fewer than six is guessable at the rate limiter's budget.
  constraint two_factor_enrolments_digits check (digits between 6 and 8),
  -- Below fifteen seconds an ordinary phone's clock drift refuses honest codes;
  -- above two minutes a shoulder-surfed code stays live far too long.
  constraint two_factor_enrolments_period check (period_seconds between 15 and 120),
  constraint two_factor_enrolments_confirmed_after_creation check (
    confirmed_at is null or confirmed_at >= created_at
  ),
  constraint two_factor_enrolments_step_positive check (last_used_step is null or last_used_step > 0)
);

-- "Does this person have a second factor" is asked on every sign-in, so it is
-- an index lookup rather than a scan. Partial, because an unconfirmed enrolment
-- is never the answer to that question (note 5).
create index two_factor_enrolments_confirmed_idx
  on two_factor_enrolments (org_id, user_id)
  where confirmed_at is not null;

-- ---------------------------------------------------------------------------
-- Recovery codes (note 6)
-- ---------------------------------------------------------------------------

create table two_factor_recovery_codes (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations (id) on delete cascade,
  user_id     uuid not null references users (id) on delete cascade,

  -- The digest. Never the code. Note 6.
  code_hash   text not null,

  created_at  timestamptz not null default now(),

  -- Null means unspent. Recorded rather than deleted, so "this code was
  -- redeemed at 03:14" survives for the incident review that will want it, and
  -- so a spent code cannot be resurrected by re-inserting the same row.
  used_at     timestamptz,

  -- Scoped to the person, not to the tenant: two people may not share a code,
  -- but the same digest colliding across tenants is not this table's business.
  unique (org_id, user_id, code_hash),

  -- A SHA-256 digest, lowercase hex. A recovery code as printed cannot satisfy
  -- this.
  constraint two_factor_recovery_codes_hash_shape check (code_hash ~ '^[0-9a-f]{64}$'),
  constraint two_factor_recovery_codes_used_after_creation check (
    used_at is null or used_at >= created_at
  )
);

-- Supports "how many are left" and the redemption statement itself.
create index two_factor_recovery_codes_user_idx on two_factor_recovery_codes (org_id, user_id);

-- ---------------------------------------------------------------------------
-- The challenge (note 1)
-- ---------------------------------------------------------------------------

create table two_factor_challenges (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations (id) on delete cascade,
  user_id      uuid not null references users (id) on delete cascade,

  -- The digest of the challenge identifier. Never the identifier. Migration 10
  -- note 2's rule, unchanged: what is stored is a SHA-256 digest, and the
  -- constraint below makes the plaintext unwriteable.
  token_hash   text not null,

  created_at   timestamptz not null default now(),

  -- Short. A challenge is the window between a correct password and a second
  -- factor, not a session — it exists for as long as it takes somebody to read
  -- six digits off a phone. The value is the application's (src/auth/two_factor.ts);
  -- the column only insists there is one.
  expires_at   timestamptz not null,

  -- Null means unredeemed. Single use, for the same reason a session identifier
  -- is retired at sign-in rather than reused: a challenge that could be
  -- exchanged twice would be a second session nobody asked for.
  consumed_at  timestamptz,

  unique (token_hash),

  constraint two_factor_challenges_hash_shape check (token_hash ~ '^[0-9a-f]{64}$'),
  constraint two_factor_challenges_expiry_after_creation check (expires_at > created_at),
  constraint two_factor_challenges_consumed_after_creation check (
    consumed_at is null or consumed_at >= created_at
  )
);

create index two_factor_challenges_user_idx on two_factor_challenges (org_id, user_id);

-- ---------------------------------------------------------------------------
-- Row-level security (note 8)
-- ---------------------------------------------------------------------------

-- All four carry `org_id`, including `organization_security_policies`, where it
-- is also the primary key — so one loop with one policy shape covers them,
-- exactly as migration 4 covers its seven.
do $$
declare
  t text;
begin
  foreach t in array array[
    'organization_security_policies', 'two_factor_enrolments',
    'two_factor_recovery_codes', 'two_factor_challenges'
  ] loop
    execute format('alter table %I enable row level security', t);
    execute format('alter table %I force row level security', t);
    execute format(
      'create policy tenant_isolation on %I using (org_id = current_tenant()) with check (org_id = current_tenant())',
      t
    );
  end loop;
end;
$$;

-- ---------------------------------------------------------------------------
-- Liveness (note 9)
--
-- Two views, and each is the ONE place its predicate is written.
--
-- `security_invoker = true` on both, for migration 7's reason: a view runs with
-- its OWNER's permissions by default, and the owner here is the migration role —
-- a superuser in most deployments, and a superuser bypasses row-level security
-- unconditionally. Without this line the views hand every tenant's rows to
-- anyone who can select from them.
-- ---------------------------------------------------------------------------

-- What "this person has a second factor" means. Asked on every sign-in.
create view confirmed_two_factor_enrolments with (security_invoker = true) as
  select
    e.id,
    e.org_id,
    e.user_id,
    e.secret_sealed,
    e.algorithm,
    e.digits,
    e.period_seconds,
    e.created_at,
    e.confirmed_at,
    e.last_used_step
  from two_factor_enrolments e
  where e.confirmed_at is not null;

-- What "this challenge may still be exchanged" means. Reading
-- `two_factor_challenges` directly to answer that is the single mistake that
-- would honour a spent or lapsed challenge, which is why there is somewhere
-- else to read instead.
create view live_two_factor_challenges with (security_invoker = true) as
  select
    c.id,
    c.org_id,
    c.user_id,
    c.token_hash,
    c.created_at,
    c.expires_at
  from two_factor_challenges c
  where c.consumed_at is null
    and c.expires_at > statement_timestamp();

-- ---------------------------------------------------------------------------
-- Deliberately not done here, so an omission is not mistaken for a decision
--
--   * NO ADMINISTRATIVE RESET, AND NO COLUMN THAT WOULD SUPPORT ONE. "Reset
--     this member's second factor" is the action that undoes two-factor
--     authentication for anybody who holds it, so it needs its own catalogued
--     action to check an administrator against, and `src/authz/catalogue.ts`
--     does not have one. Shipping the capability first and the check later is
--     the shape brief §9 rejects outright, so `src/repo/two_factor.ts` refuses
--     to write anyone else's enrolment at all — the same answer
--     `updatePasswordHash` gives to the same question. Recorded in the
--     catalogue's KNOWN GAPS list.
--
--   * NO `disabled_at` ON AN ENROLMENT. Turning a second factor off is that
--     same administrative action wearing a smaller name, and a person removing
--     their own factor while their organization requires one is a state the
--     policy exists to forbid. Re-enrolment replaces the row, which covers the
--     case that actually happens: a new phone.
--
--   * NO FOREIGN KEY FROM `two_factor_challenges` TO `sessions`. A challenge
--     exists precisely because there is no session yet.
--
--   * NO COMPOSITE FOREIGN KEY TO `memberships`, for migration 10 note 5's
--     reason: it would delete the rows when a membership goes, losing the
--     record, and it would split one rule across two mechanisms while still
--     leaving the DISABLED member to `can()`. The invariant is enforced where
--     rows are created instead — every insert in `src/repo/two_factor.ts`
--     selects from `memberships`, so a row for a non-member writes nothing.
--
--   * NO TRIGGER AND NO JOB. Nothing sweeps expired challenges or spent
--     recovery codes, and nothing may ever enter the enforcement path (note 9).
--     If retention ever trims them it is hygiene, and the views must remain
--     correct with no such job running at all.
-- ---------------------------------------------------------------------------

-- migrate:down

-- The views first. Dropping a table out from under a dependent view would need
-- CASCADE, which this repository bans: a down path that removes objects it did
-- not name is not a rollback.
drop view if exists live_two_factor_challenges;
drop view if exists confirmed_two_factor_enrolments;

drop index if exists two_factor_challenges_user_idx;
drop index if exists two_factor_recovery_codes_user_idx;
drop index if exists two_factor_enrolments_confirmed_idx;

-- The policies, the FORCE settings and the unique indexes go with the tables.
drop table if exists two_factor_challenges;
drop table if exists two_factor_recovery_codes;
drop table if exists two_factor_enrolments;
drop table if exists organization_security_policies;
