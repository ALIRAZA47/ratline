-- Re-authentication for the highest-risk actions (RL-M1-037).
--
-- ADR 0017 proposed this as the control an idle timeout was reaching for, and
-- the argument is worth repeating here because it decides the shape.
--
-- An idle timeout measured on `last_seen_at` records the last REQUEST, not the
-- last human: a dashboard that polls writes it on a timer, so the rule fires
-- only when the tab is closed — which the absolute lifetime already covers —
-- and never for the abandoned open tab, which is the whole scenario. A control
-- whose measurement is produced by the thing it constrains is not a control.
--
-- Re-authentication is not defeated by polling, because it is not measured
-- against activity at all. It asks a question the browser cannot answer on the
-- operator's behalf: prove you still know the password. And it binds to the
-- MOMENT OF DANGER rather than to a clock, so ordinary work costs nothing.
--
-- Two things are added.
--
--   1. `sessions.authenticated_at` — when a password was last proved for this
--      session. Distinct from `created_at`, because a session can be rotated
--      (RL-M1-018) without anybody proving anything, and distinct from
--      `last_seen_at` for the reason above.
--
--   2. Policy columns naming WHICH actions demand it and HOW RECENTLY. Brief
--      §6.3 makes 2FA an organization-level policy; this belongs beside it, for
--      the same reason: an installation running a payments product and one
--      running a blog do not want the same answer, and neither wants it in our
--      source.

-- migrate:up

alter table sessions
  -- Defaults to `created_at` for rows written before this migration: a session
  -- that existed was authenticated when it began, which is the truthful
  -- backfill. `now()` would have made every live session instantly fresh, and
  -- an epoch would have demanded re-authentication from everybody at once.
  add column authenticated_at timestamptz not null default now();

update sessions set authenticated_at = created_at;

comment on column sessions.authenticated_at is
  'When a password was last proved for this session (RL-M1-037). Not created_at: a rotation carries the session forward without proving anything.';

alter table organization_security_policies
  -- An ARRAY of catalogued action names rather than a boolean per action. The
  -- catalogue has over a hundred entries and grows; a column per action would
  -- need a migration every time one is added, which is how a policy stops
  -- tracking the catalogue.
  --
  -- Empty by default, and that is the safe direction: re-authentication that
  -- nobody asked for would lock operators out of an installation that never
  -- configured it, which is a worse first-run experience than an installation
  -- that has not turned a control on yet. The interface is what recommends the
  -- set; the database does not presume it.
  add column reauth_actions text[] not null default '{}',

  -- Fifteen minutes. Long enough that an operator working through an incident
  -- is not asked twice in the same task, short enough that a walked-away
  -- workstation does not carry the privilege to the end of the session's eight
  -- hours.
  add column reauth_window_seconds integer not null default 900,

  -- A window of zero would mean "always ask", which is a legitimate setting for
  -- a paranoid installation. A negative one is not, and neither is one longer
  -- than the absolute session lifetime, which would make the control
  -- unreachable while appearing to be on.
  add constraint organization_security_policies_reauth_window
    check (reauth_window_seconds >= 0 and reauth_window_seconds <= 8 * 60 * 60);

-- `live_sessions` names its columns explicitly rather than selecting *, so a
-- column added to the table does not appear in the view. That is the right
-- shape — a view whose surface changes when a table does is a view nothing can
-- rely on — and it means adding one is a two-step act. Recreated here with
-- `authenticated_at` included, because `checkFreshness` reads the VIEW: the
-- table would honour a revoked session, which migration 10 note 3 calls "the
-- single mistake" this view exists to prevent.
--
-- `security_invoker` is carried forward. Without it the view would run with its
-- owner's permissions and bypass row-level security entirely, which is the
-- mistake RL-M1-005 found in `scope_ancestry`.
-- DROP and recreate rather than `create or replace`: Postgres will only APPEND
-- columns to a replaced view, never insert one, and `authenticated_at` belongs
-- beside the other timestamps rather than tacked on the end. The drop is safe
-- because nothing holds a dependent object on this view.
drop view live_sessions;

create view live_sessions with (security_invoker = true) as
  select
    s.id,
    s.org_id,
    s.user_id,
    s.token_hash,
    s.created_at,
    s.expires_at,
    s.last_seen_at,
    s.authenticated_at,
    s.rotated_from,
    s.user_agent,
    s.ip
  from sessions s
  where s.revoked_at is null
    and s.expires_at > statement_timestamp();

comment on column organization_security_policies.reauth_actions is
  'Catalogued actions that require the password again when the session was authenticated longer ago than reauth_window_seconds (RL-M1-037).';

-- migrate:down

alter table organization_security_policies
  drop constraint organization_security_policies_reauth_window,
  drop column reauth_window_seconds,
  drop column reauth_actions;

-- The view has to lose the column before the table can.
drop view live_sessions;

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

alter table sessions drop column authenticated_at;
