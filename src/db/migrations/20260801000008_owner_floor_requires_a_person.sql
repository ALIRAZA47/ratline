-- The last-owner floor must be satisfied by a PERSON (RL-M1-014 follow-up).
--
-- Found while building API tokens (RL-M1-032). Migration 2's
-- assert_organization_has_owner() counts organization-scope `owner` grants
-- without filtering subject_type, and migration 5's
-- grants_owner_floor_is_unconditional has the same blind spot. Since migration 5
-- made 'api_token' a writable subject kind, both are now easy to reach.
--
-- The hole: a service identity or an API token holding `owner` at organization
-- scope satisfies the floor that brief §6.3 intends a human to satisfy. Every
-- person could then be removed from ownership, leaving an organization
-- administered only by a credential — which cannot answer a break-glass
-- notification, cannot be asked to approve anything, and if lost or revoked
-- leaves the organization with no route back in. The floor is meant to prevent
-- exactly that state.
--
-- This is the third time a later feature has quietly widened an earlier
-- invariant here: RL-M1-006 found a view bypassing row-level security, RL-M1-011
-- found expiry defeating this same floor, and now a new subject kind defeats it
-- again. The pattern is that an invariant expressed as "count some rows" ages
-- badly as the rows gain columns. Where possible the fix is to make the bad
-- state unrepresentable rather than to count more carefully — hence a CHECK
-- alongside the trigger, as migration 5 did.

-- migrate:up

-- 1. The trigger: only a user's grant counts toward the floor.
create or replace function assert_organization_has_owner() returns trigger
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
    and scope_type = 'organization'
    and subject_type = 'user'      -- <- the fix
    and effect = 'allow'           -- <- defence in depth; the CHECK below also forbids it
    and expires_at is null;        -- <- likewise

  if owner_count = 0 then
    raise exception
      'organization % would be left with no owner who is a person', target_org
      using errcode = 'integrity_constraint_violation',
            hint = 'Grant the owner role to another member before removing the last one. '
                   'A service identity or API token cannot satisfy this: it cannot answer a '
                   'break-glass notification, and if its credential is lost the organization '
                   'has no route back in.';
  end if;

  return null;
end;
$$;

-- 2. Make the state unrepresentable, not merely counted around. An
--    organization-scope owner grant must belong to a user.
--
--    Nothing legitimate is lost. Automation that needs to act as broadly as an
--    Owner takes `admin` at organization scope, which carries everything except
--    organization deletion and ownership transfer — and those two are precisely
--    the powers that should require a person.
alter table grants add constraint grants_organization_owner_is_a_person check (
  role_key <> 'owner'
  or scope_type <> 'organization'
  or subject_type = 'user'
);

-- migrate:down

alter table grants drop constraint if exists grants_organization_owner_is_a_person;

-- Restore migration 2's function exactly as it was, so the down path is a true
-- reversal rather than an approximation of one.
create or replace function assert_organization_has_owner() returns trigger
language plpgsql as $$
declare
  target_org uuid := coalesce(new.org_id, old.org_id);
  owner_count integer;
begin
  if not exists (select 1 from organizations where id = target_org) then
    return null;
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
