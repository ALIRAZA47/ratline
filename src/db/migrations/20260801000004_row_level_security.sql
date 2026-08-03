-- Row-level security: layer 3 of C3 (RL-M1-006, ADR 0003).
--
-- C3 says an unscoped read must be impossible, not merely discouraged. Three
-- layers deliver that, and each has to fail closed on its own:
--
--   1. The raw database handle is unreachable outside src/repo/  (lint, RL-M1-008)
--   2. Every repository function requires an AuthzContext          (types, RL-M1-007)
--   3. Postgres refuses the row regardless of what the code did    (this migration)
--
-- Layer 3 is the only one that survives a bug in layers 1 and 2, a migration
-- run by hand, or a psql session opened during an incident. The test that makes
-- it real deletes a repository function's own WHERE clause and asserts the query
-- still returns nothing.
--
-- Three details carry most of the weight:
--
--   * FORCE ROW LEVEL SECURITY. Without FORCE, the table owner is exempt — and
--     the owner is exactly who the application connects as in most deployments,
--     so plain ENABLE would leave the policies decorative.
--
--   * current_setting(..., true) returns NULL when the tenant is unset, and
--     `org_id = NULL` is NULL, which is not true, so no rows match. Unset means
--     see nothing. The missing-setting case fails closed rather than open.
--
--   * A superuser bypasses RLS unconditionally, whatever the policies say. So
--     the application must not connect as one. This migration creates an
--     unprivileged role for that, and the test suite connects as it — a test run
--     as superuser would pass without exercising a single policy.

-- migrate:up

-- The role the application connects as. NOSUPERUSER and NOBYPASSRLS are the
-- point of it; NOLOGIN because the deployment grants login separately with
-- whatever credential it uses.
--
-- Roles are cluster-scoped rather than database-scoped, so this is written to
-- be idempotent and the down path deliberately does NOT drop it: another
-- database on the same cluster may be using it.
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'ratline_app') then
    create role ratline_app nologin nosuperuser nobypassrls noinherit;
  end if;
end;
$$;

grant usage on schema public to ratline_app;
grant select, insert, update, delete on all tables in schema public to ratline_app;
grant usage, select on all sequences in schema public to ratline_app;
alter default privileges in schema public
  grant select, insert, update, delete on tables to ratline_app;

-- The migration bookkeeping table is infrastructure, not tenant data. The
-- application role has no business writing it.
revoke insert, update, delete on schema_migrations from ratline_app;

-- ---------------------------------------------------------------------------
-- The tenant setting
-- ---------------------------------------------------------------------------

-- Reading the current tenant in one place, so a policy cannot get the cast or
-- the missing-value behaviour subtly wrong. STABLE, not IMMUTABLE: it varies
-- within a session.
create function current_tenant() returns uuid
language sql stable as $$
  select nullif(current_setting('ratline.org_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------
-- Policies
--
-- Every tenant-scoped table gets the same shape: visible only when its org_id
-- matches the current tenant, and writable only to the current tenant.
--
-- The WITH CHECK clause is written out even though Postgres would fall back to
-- the USING expression if it were omitted. It is not redundant to a reader: it
-- states that reads and writes are scoped by the same rule, so anyone widening
-- USING later has to notice they are widening writes too. Verified by mutation
-- — `with check (true)` fails the suite, while deleting the clause does not,
-- because the fallback quietly restores the correct behaviour.
-- ---------------------------------------------------------------------------

do $$
declare
  t text;
begin
  foreach t in array array[
    'memberships', 'service_identities', 'grants',
    'scope_nodes', 'teams', 'projects', 'environments'
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

-- The organization itself is identified by its own id, not by an org_id column.
alter table organizations enable row level security;
alter table organizations force row level security;
create policy tenant_isolation on organizations
  using (id = current_tenant())
  with check (id = current_tenant());

-- Users are global — one person, one account, many organizations — so they are
-- scoped by shared membership rather than by a column. Without this, a tenant
-- could enumerate every account on the installation by email, which is a
-- disclosure problem even though it is not cross-tenant data access.
--
-- The subquery on memberships is itself policy-filtered, which is consistent
-- and terminates: memberships is scoped by a plain column comparison.
alter table users enable row level security;
alter table users force row level security;
create policy tenant_isolation on users
  using (
    exists (
      select 1 from memberships m
      where m.user_id = users.id
        and m.org_id = current_tenant()
    )
  );

-- Inserting a user happens before any membership exists, so the read policy
-- cannot gate it. A separate insert policy keeps the read rule strict while
-- letting sign-up work; the row is invisible until a membership makes it ours.
create policy user_insert on users for insert with check (true);

-- ---------------------------------------------------------------------------
-- The view has to respect the caller's policies, not its owner's
--
-- A view runs with its OWNER's permissions unless security_invoker is set, so
-- scope_ancestry as created in migration 3 would read scope_nodes as the owner
-- and hand back every tenant's ancestry. That is a complete bypass of the layer
-- this migration exists to build, reachable by anyone who can select from the
-- view. Fixed here rather than by editing an applied migration.
-- ---------------------------------------------------------------------------

alter view scope_ancestry set (security_invoker = true);

-- migrate:down

alter view scope_ancestry reset (security_invoker);

drop policy if exists user_insert on users;
drop policy if exists tenant_isolation on users;
alter table users no force row level security;
alter table users disable row level security;

drop policy if exists tenant_isolation on organizations;
alter table organizations no force row level security;
alter table organizations disable row level security;

do $$
declare
  t text;
begin
  foreach t in array array[
    'memberships', 'service_identities', 'grants',
    'scope_nodes', 'teams', 'projects', 'environments'
  ] loop
    execute format('drop policy if exists tenant_isolation on %I', t);
    execute format('alter table %I no force row level security', t);
    execute format('alter table %I disable row level security', t);
  end loop;
end;
$$;

drop function if exists current_tenant();

alter default privileges in schema public
  revoke select, insert, update, delete on tables from ratline_app;
revoke all on all sequences in schema public from ratline_app;
revoke all on all tables in schema public from ratline_app;
revoke usage on schema public from ratline_app;

-- ratline_app is deliberately NOT dropped: it is cluster-scoped and another
-- database may hold grants against it. Dropping it here would break them.
