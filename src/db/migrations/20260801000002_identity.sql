-- Identity: organizations, users, memberships, service identities, and the
-- organization-scope grants that make "who is an Owner" answerable (RL-M1-004).
--
-- Two decisions worth reading before changing anything here.
--
-- 1. `grants` is created in this migration rather than with the rest of the
--    grant model (RL-M1-011). It has to be: brief §6.3 requires that at least
--    one Owner always exists and that the system prevents removing the last,
--    and that invariant is meaningless until ownership is representable. The
--    alternative — an `is_owner` flag on memberships — would create a second
--    source of truth for who is an Owner, which is exactly the shape that
--    produces authorization bugs. RL-M1-011 extends this table with expiry,
--    deny effects, and non-user subjects.
--
-- 2. `users` is deliberately NOT tenant-scoped. A person can belong to several
--    organizations, so the tenant boundary is `memberships`, not `users`. Every
--    OTHER table here carries a non-nullable org_id, and the test suite asserts
--    that property across the whole schema rather than trusting this comment.

-- migrate:up

-- Organizations: the root of the hierarchy and the tenant boundary.
create table organizations (
  id          uuid primary key default gen_random_uuid(),
  slug        citext not null unique,
  name        text not null,
  created_at  timestamptz not null default now(),

  constraint organizations_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$'),
  constraint organizations_name_present check (length(btrim(name)) > 0)
);

-- People. Global, not tenant-scoped: one human, one account, many organizations.
-- Email is citext so "Ali@example.com" and "ali@example.com" cannot become two
-- accounts — a duplicate here is an account-takeover shape, not a cosmetic bug.
create table users (
  id             uuid primary key default gen_random_uuid(),
  email          citext not null unique,
  name           text not null,
  password_hash  text,
  created_at     timestamptz not null default now(),
  disabled_at    timestamptz,

  constraint users_email_shape check (email ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
  -- Null password_hash is legitimate: an SSO-only account has no password.
  -- An empty string is not, and would compare against a hash of "".
  constraint users_password_hash_nonempty check (password_hash is null or length(password_hash) > 0)
);

-- Membership is the tenant boundary for a person.
create table memberships (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations (id) on delete cascade,
  user_id     uuid not null references users (id) on delete cascade,
  created_at  timestamptz not null default now(),

  unique (org_id, user_id)
);

create index memberships_user_idx on memberships (user_id);

-- C6: automation acts as a named service identity with its own permissions,
-- never as "the system" and never anonymously.
create table service_identities (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations (id) on delete cascade,
  name        text not null,
  description text not null default '',
  created_at  timestamptz not null default now(),
  disabled_at timestamptz,

  unique (org_id, name),
  constraint service_identities_name_present check (length(btrim(name)) > 0)
);

-- Grants. RL-M1-011 extends this with expiry, deny effects and further subject
-- kinds; what exists here is the minimum that makes ownership representable.
create table grants (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations (id) on delete cascade,
  subject_type  text not null,
  subject_id    uuid not null,
  role_key      text not null,
  scope_type    text not null,
  scope_id      uuid,
  granted_by    uuid references users (id),
  created_at    timestamptz not null default now(),

  constraint grants_subject_type check (subject_type in ('user', 'service_identity')),
  constraint grants_scope_type check (scope_type in ('organization', 'team', 'project', 'environment', 'resource')),
  -- An organization-scope grant covers the whole tenant, so it names no node.
  -- Every narrower scope must name one, or it would silently mean "everything".
  constraint grants_scope_id_matches_type check (
    (scope_type = 'organization' and scope_id is null)
    or (scope_type <> 'organization' and scope_id is not null)
  ),
  unique (org_id, subject_type, subject_id, role_key, scope_type, scope_id)
);

create index grants_subject_idx on grants (org_id, subject_type, subject_id);
create index grants_owner_idx on grants (org_id) where role_key = 'owner' and scope_type = 'organization';

-- ---------------------------------------------------------------------------
-- The last-owner invariant (brief §6.3)
--
-- "At least one must always exist; the system prevents removing the last."
--
-- Postgres has no declarative way to say "at least one row matching a predicate
-- must exist per group", so this is a constraint trigger. Two properties make it
-- worth more than an application check:
--
--   * It fires however the row leaves — a delete, a role change, a membership
--     removal cascading, a hand-run UPDATE in psql during an incident.
--   * It is DEFERRABLE INITIALLY DEFERRED, so a transaction may legitimately
--     move ownership by removing the old Owner and adding the new one in either
--     order. Only the state at COMMIT has to be valid.
--
-- Deleting the organization itself is exempt: the cascade removes its grants,
-- and refusing that would make an organization undeletable.
-- ---------------------------------------------------------------------------

create function assert_organization_has_owner() returns trigger
language plpgsql as $$
declare
  target_org uuid := coalesce(new.org_id, old.org_id);
  owner_count integer;
begin
  if not exists (select 1 from organizations where id = target_org) then
    return null;  -- the organization is going away; the cascade is legitimate
  end if;

  select count(*) into owner_count
  from grants
  where org_id = target_org
    and role_key = 'owner'
    and scope_type = 'organization';

  if owner_count = 0 then
    raise exception
      'organization % would be left with no owner', target_org
      using errcode = 'integrity_constraint_violation',
            hint = 'Grant the owner role to another member before removing the last one.';
  end if;

  return null;
end;
$$;

create constraint trigger grants_owner_floor
  after delete or update on grants
  deferrable initially deferred
  for each row execute function assert_organization_has_owner();

-- migrate:down

drop trigger if exists grants_owner_floor on grants;
drop function if exists assert_organization_has_owner();
drop index if exists grants_owner_idx;
drop index if exists grants_subject_idx;
drop table if exists grants;
drop table if exists service_identities;
drop index if exists memberships_user_idx;
drop table if exists memberships;
drop table if exists users;
drop table if exists organizations;
