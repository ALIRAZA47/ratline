-- Grants, denies and time-bound scoping (RL-M1-011).
--
-- Migration 2 created `grants` with the minimum that made ownership
-- representable, and said this migration would extend it with expiry, deny
-- effects and further subject kinds. This is that extension, plus the
-- resolution interface RL-M1-012's `can()` is built on.
--
-- Four properties carry the weight, and each is written where it cannot be
-- forgotten rather than where it is convenient.
--
-- 1. DENIES WIN AT ANY SCOPE, IN BOTH DIRECTIONS.
--    Brief §6.3: "A grant on a project applies to all its environments unless a
--    narrower deny exists. Denies always win." The second sentence is the one
--    that is usually under-implemented. "Most specific wins" gets a narrow deny
--    over a wide allow right and silently loses the other direction, so an
--    allow on one environment defeats a deny on the project containing it. The
--    rule implemented here has no notion of specificity at all: if a deny
--    reaches this node from anywhere at or above it, the answer is deny.
--    `grant_decision` therefore never orders by depth, and asks about denies
--    before it asks about allows.
--
-- 2. EXPIRY IS A PREDICATE, NOT A JOB.
--    Brief §6.3: "Expiry is enforced server-side, not by a cleanup job."
--    PLAN §5: "filtered by expiry in SQL — expired rows never load." The filter
--    lives in one place, the `live_grants` view, and every resolution path is
--    built on that view rather than on `grants`. So an expired row is invisible
--    to the next decision with nothing having run in between, and adding a new
--    query that forgets `and expires_at > ...` is not possible without first
--    going around the view deliberately. No cleanup job exists, and none is in
--    the enforcement path if one is ever added for hygiene.
--
-- 3. `statement_timestamp()`, NOT `now()` AND NOT `clock_timestamp()`.
--    `now()` is the transaction's start time, so a decision made late in a long
--    transaction would honour a grant that lapsed minutes earlier — precisely
--    the failure "dead the moment it expires" rules out, and one that a test
--    inside a single transaction could never catch.
--    `clock_timestamp()` is volatile: two rows of one decision could be judged
--    against different instants, and no index on `expires_at` is usable.
--    `statement_timestamp()` is stable within a statement and advances between
--    statements, which is exactly "evaluated at decision time".
--
-- 4. EVERYTHING HERE IS INVOKER-RIGHTS.
--    A SECURITY DEFINER function would run as the migration role — a superuser
--    in most deployments — and a superuser bypasses row-level security
--    unconditionally, so it would hand every tenant's grants to anyone able to
--    call it. Functions default to invoker rights, so they are simply not
--    marked otherwise; a view's default is the opposite, which is why the view
--    below says so out loud. Migration 4 had to retrofit exactly this onto
--    `scope_ancestry`.
--
-- What this migration deliberately does NOT do is listed at the foot of the up
-- section, so a later session does not read an omission as a decision.

-- migrate:up

-- ---------------------------------------------------------------------------
-- Subjects
--
-- Brief §6.3: "API tokens carry a subset of the issuing user's permissions and
-- never more." Adding the subject kind is what lets a token hold a *narrower*
-- set than its issuer holds.
--
-- It is not, by itself, the ceiling. The intersection with the issuing user
-- happens at use time (PLAN §5, RL-M1-032) because intersecting only at issue
-- time would let a demoted user keep the reach of a token minted while they
-- were an Admin. Nothing in this migration may be read as that enforcement:
-- resolution below answers "what does this subject hold", and for an
-- `api_token` subject that answer is an upper bound to be intersected, not a
-- decision. There is no `api_tokens` table yet (RL-M1-030), so `subject_id`
-- cannot be a foreign key to one either.
-- ---------------------------------------------------------------------------

alter table grants drop constraint grants_subject_type;
alter table grants add constraint grants_subject_type
  check (subject_type in ('user', 'service_identity', 'api_token'));

-- ---------------------------------------------------------------------------
-- Effect
--
-- Default 'allow', so every row written before this migration keeps exactly the
-- meaning it had. A nullable effect, or a default of 'deny', would silently
-- reinterpret the owner grants that already exist — including the one that
-- keeps each organization's floor satisfied.
--
-- Note what is NOT changed: migration 2's
-- `unique (org_id, subject_type, subject_id, role_key, scope_type, scope_id)`
-- does not include `effect`, so one subject cannot hold both an allow and a
-- deny of the same role at the same *named* node; the deny replaces the allow.
-- That is the intended shape — a contradiction at one node is a data error, not
-- a policy. It does not hold at organization scope, where `scope_id` is null
-- and Postgres treats nulls as distinct in a unique constraint, so duplicate
-- organization-scope rows are already possible today. Either way the resolution
-- below is well defined, because deny wins whatever rows exist.
-- ---------------------------------------------------------------------------

alter table grants add column effect text not null default 'allow';
alter table grants add constraint grants_effect check (effect in ('allow', 'deny'));

-- ---------------------------------------------------------------------------
-- Expiry
--
-- Brief §6.3: "Time-bound grants with expiry, for contractors and incident
-- access." Null means never.
--
-- The constraint below is the honest version of "an expired grant cannot be
-- created". A CHECK cannot say `expires_at > now()`: Postgres refuses a
-- non-IMMUTABLE function in a check constraint. And if it accepted one it would
-- still be the wrong mechanism, because CHECK is re-validated on every UPDATE
-- and on restore — so a perfectly valid grant would become un-updatable, and a
-- database dump taken today would refuse to restore tomorrow, purely because
-- time passed. Comparing against the row's own `created_at` says the same thing
-- about the moment of creation, is immutable, and stays true forever after.
--
-- It also leaves the one case a wall-clock rule would wrongly reject: importing
-- historical grants, where `created_at` and `expires_at` are both in the past
-- but still in the right order.
-- ---------------------------------------------------------------------------

alter table grants add column expires_at timestamptz;
alter table grants add constraint grants_expiry_after_creation
  check (expires_at is null or expires_at > created_at);

-- PLAN §4 lists `reason` on GRANT, and brief §6.3 requires a written reason for
-- break-glass elevation. Nullable, because an ordinary grant needs none and
-- because a NOT NULL column would invalidate every existing row; "mandatory for
-- break-glass" belongs with break-glass (RL-M5-003), which is the only place
-- that knows a grant is one. An empty string is not a reason.
alter table grants add column reason text;
alter table grants add constraint grants_reason_nonempty
  check (reason is null or length(btrim(reason)) > 0);

-- ---------------------------------------------------------------------------
-- Keeping the last-owner floor true, now that a grant can expire and can deny
--
-- Migration 2 guarantees brief §6.3's "at least one must always exist; the
-- system prevents removing the last" with a constraint trigger that counts
-- organization-scope owner rows. Both of this migration's additions break that
-- count unless something is done about them:
--
--   * An owner grant with an expiry would leave the organization with no owner
--     the moment it lapsed, and no trigger can catch that, because no statement
--     runs. Time passing is not an event.
--   * A deny of `owner` at organization scope neutralises the last owner while
--     leaving in place the very row the trigger counts.
--
-- Both are closed by refusing to represent the state at all: an
-- organization-scope owner grant is unconditional — always an allow, never
-- expiring. Nothing legitimate is lost. Break-glass elevation is temporary
-- *Admin*, not temporary Owner (§6.3), and an owner grant at a narrower node (a
-- team, a project) may still expire and may still be denied, because that is
-- not what the floor counts.
--
-- Migration 2's trigger is deliberately left exactly as it is: this constraint
-- is what keeps its unfiltered count correct. Relaxing this constraint means
-- teaching that function about `effect` and `expires_at` first, and
-- test/authz/grant_expiry.test.ts fails if anyone relaxes one without the
-- other.
-- ---------------------------------------------------------------------------

alter table grants add constraint grants_owner_floor_is_unconditional check (
  role_key <> 'owner'
  or scope_type <> 'organization'
  or (effect = 'allow' and expires_at is null)
);

-- Supports "see who has access to what, and when that access expires" (the
-- `grant.read` action) and any later hygiene sweep over long-dead rows.
-- Explicitly NOT part of enforcement: the predicate in `live_grants` is what
-- enforces expiry, and it has to stay correct with no index at all.
create index grants_expiring_idx on grants (org_id, expires_at) where expires_at is not null;

-- ---------------------------------------------------------------------------
-- Resolution
--
-- Three objects, each with one job, so a change to any one of them is
-- reviewable on its own:
--
--   live_grants          every grant that has not expired, with the hierarchy
--                        node it hangs on resolved. The only place expiry is
--                        expressed.
--   effective_grants()   the grants that reach a given subject at a given node,
--                        after inheritance. The only place the direction of
--                        inheritance is expressed.
--   grant_decision()     allow or deny, denies winning, deny by default. The
--                        only place precedence is expressed.
--
-- `can()` (RL-M1-012) is built on the third for its answer and may use the
-- second to explain that answer in the audit log, which brief §6.3 requires to
-- record denials as prominently as allows.
-- ---------------------------------------------------------------------------

create view live_grants with (security_invoker = true) as
  select
    g.id            as grant_id,
    g.org_id,
    g.subject_type,
    g.subject_id,
    g.role_key,
    g.effect,
    g.scope_type,
    g.scope_id,
    g.granted_by,
    g.reason,
    g.created_at,
    g.expires_at,
    -- The hierarchy node this grant hangs on. Organization scope names no node
    -- (migration 2: it covers the whole tenant), so it resolves to the tenant's
    -- root. A resource-scoped grant names a resource rather than a node — the
    -- fifth level of §6.3's hierarchy has no row in `scope_nodes` — so it has
    -- no node at all and is matched by identity instead, in effective_grants().
    case
      when g.scope_type = 'organization' then root.id
      when g.scope_type = 'resource' then null
      else g.scope_id
    end as scope_node_id
  from grants g
  join scope_nodes root
    on root.org_id = g.org_id
   and root.kind = 'organization'
  -- THE expiry predicate. Everything that resolves a permission reads this
  -- view, so this one line is the whole of "expiry is enforced server-side,
  -- not by a cleanup job".
  where g.expires_at is null
     or g.expires_at > statement_timestamp();

create function effective_grants(
  p_subject_type text,
  p_subject_id   uuid,
  p_node_id      uuid,
  p_resource_id  uuid
) returns table (
  grant_id      uuid,
  role_key      text,
  effect        text,
  scope_type    text,
  scope_id      uuid,
  scope_node_id uuid,
  expires_at    timestamptz
)
-- STABLE, not the default VOLATILE: this reads tables and `statement_timestamp()`
-- and nothing else, so it is fixed within a statement and free to be re-planned
-- across them. Marking it VOLATILE would be a pessimisation; marking it
-- IMMUTABLE would be a lie that lets the planner fold an expiry away.
language sql stable as $$
  select g.grant_id, g.role_key, g.effect, g.scope_type, g.scope_id, g.scope_node_id, g.expires_at
  from live_grants g
  where g.subject_type = p_subject_type
    and g.subject_id = p_subject_id
    and (
      -- Inheritance, downward only. `scope_ancestry` lists a node together with
      -- itself and everything above it, so this is one indexed containment test
      -- against the GiST path index. The two columns are not interchangeable:
      -- swapping them makes a grant on an environment convey at the project
      -- above it, which is a silent privilege escalation on every narrow grant
      -- in the system at once.
      exists (
        select 1 from scope_ancestry a
        where a.node_id = p_node_id
          and a.ancestor_id = g.scope_node_id
      )
      -- Or attached to the exact resource being asked about. A resource is the
      -- last level of §6.3's hierarchy and owns no scope node, so it matches by
      -- identity; nothing inherits from a resource. A null `p_resource_id` means
      -- "the question is not about a resource" and matches nothing, rather than
      -- everything. The parameter has no default on purpose: a caller checking a
      -- resource must name it, because a forgotten resource id would drop a
      -- resource-scoped DENY and answer with the wider allow above it.
      or (
        g.scope_type = 'resource'
        and p_resource_id is not null
        and g.scope_id = p_resource_id
      )
    );
$$;

-- The decision, as PLAN §5 states it:
--
--   2. If any DENY matches the action at any scope, deny. Denies always win.
--   3. If any GRANT's role includes the action, allow.
--   4. Otherwise deny. An unmapped action is a denial.
--
-- `p_role_keys` is the set of roles that carry the action being asked about.
-- Which roles those are is catalogue knowledge — src/authz/catalogue.ts and
-- roles.ts today, stored custom roles later (RL-M5-002) — and passing it in
-- keeps the role model in one place while leaving precedence, the part that is
-- easy to get wrong, in one place too. An empty array denies, which is what
-- "an action no role carries" should mean.
--
-- Returns 'allow' or 'deny'. Only the exact string 'allow' permits anything:
-- compare for equality with 'allow', never for inequality with 'deny', so that
-- any value this function does not yet return can only fail closed.
create function grant_decision(
  p_subject_type text,
  p_subject_id   uuid,
  p_node_id      uuid,
  p_role_keys    text[],
  p_resource_id  uuid
) returns text
language sql stable as $$
  select case
    when exists (
      select 1
      from effective_grants(p_subject_type, p_subject_id, p_node_id, p_resource_id) d
      where d.effect = 'deny'
        and d.role_key = any(p_role_keys)
    ) then 'deny'
    when exists (
      select 1
      from effective_grants(p_subject_type, p_subject_id, p_node_id, p_resource_id) a
      where a.effect = 'allow'
        and a.role_key = any(p_role_keys)
    ) then 'allow'
    else 'deny'
  end;
$$;

-- ---------------------------------------------------------------------------
-- Deliberately not done here, so an omission is not mistaken for a decision
--
--   * `subject_id` is still not a foreign key, and neither is `scope_id`. A
--     grant's subject may be a user, a service identity or (once RL-M1-030
--     exists) an API token, and its scope may be a node or a resource, so
--     neither column can point at one table. A dangling id conveys nothing —
--     the joins above find no row — so this fails closed, but it does leave
--     rows behind when their subject or node is deleted. Cleaning those up is
--     hygiene, and must never become part of enforcement.
--
--   * A disabled user's grants still resolve. `users.disabled_at` and
--     `service_identities.disabled_at` are not consulted here, because whether
--     the actor is permitted to act at all is a question about the actor, asked
--     once per request, not once per node. RL-M1-012 must ask it; this
--     migration cannot make it.
--
--   * An API token's ceiling is not enforced here — see the note on subjects
--     above. RL-M1-032 owns it.
-- ---------------------------------------------------------------------------

-- migrate:down

drop function if exists grant_decision(text, uuid, uuid, text[], uuid);
drop function if exists effective_grants(text, uuid, uuid, uuid);
drop view if exists live_grants;

drop index if exists grants_expiring_idx;

-- Constraints first, so no column drop has to reach through a dependency.
alter table grants drop constraint if exists grants_owner_floor_is_unconditional;
alter table grants drop constraint if exists grants_reason_nonempty;
alter table grants drop constraint if exists grants_expiry_after_creation;
alter table grants drop constraint if exists grants_effect;

alter table grants drop column if exists reason;
alter table grants drop column if exists expires_at;
alter table grants drop column if exists effect;

-- Restoring the original subject kinds fails, deliberately, if any api_token
-- grant exists. Rolling a schema back is not a licence to delete authorization
-- rows on the way past; whoever means to do that can say so.
alter table grants drop constraint grants_subject_type;
alter table grants add constraint grants_subject_type
  check (subject_type in ('user', 'service_identity'));
