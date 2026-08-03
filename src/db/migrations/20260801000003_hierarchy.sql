-- The scope hierarchy: Organization → Team → Project → Environment (RL-M1-005).
--
-- Brief §6.3: "Permissions granted at any level inherit downward."
--
-- The design question this migration answers is how a permission check resolves
-- inheritance. The naive shape — walk parent pointers per request — costs a
-- query per level and turns every authorization decision into four round trips.
-- ADR 0003 calls for a materialised scope path instead, so "does any grant
-- above this node convey the action" is one indexed lookup.
--
-- `scope_nodes` is that materialisation. Every node in the hierarchy has a row,
-- whatever its kind, carrying its ancestry as a ltree-style path of ids. A grant
-- at any ancestor is then found with a single containment test.
--
-- Keeping one node table rather than a path column per entity matters because
-- `grants.scope_id` must be able to point at any level. With per-entity paths,
-- resolving a grant would need a union across four tables and a CASE on
-- scope_type — which is the walk again, with extra steps.

-- migrate:up

create extension if not exists ltree;

-- One row per node in the hierarchy, of any kind.
--
-- `path` is the materialised ancestry, root first, using each node's id with
-- hyphens replaced (ltree labels allow only [A-Za-z0-9_]). A node's own id is
-- the last label, so `path @> other.path` is exactly "this node is an ancestor
-- of, or is, that node".
create table scope_nodes (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references organizations (id) on delete cascade,
  kind        text not null,
  parent_id   uuid references scope_nodes (id) on delete cascade,
  path        ltree not null,
  created_at  timestamptz not null default now(),

  constraint scope_nodes_kind check (kind in ('organization', 'team', 'project', 'environment')),
  -- An organization node is the root and has no parent; nothing else may be one.
  constraint scope_nodes_root_shape check (
    (kind = 'organization' and parent_id is null)
    or (kind <> 'organization' and parent_id is not null)
  )
);

create index scope_nodes_path_idx on scope_nodes using gist (path);
create index scope_nodes_org_idx on scope_nodes (org_id, kind);
create unique index scope_nodes_org_root_idx on scope_nodes (org_id) where kind = 'organization';

-- ltree labels accept [A-Za-z0-9_] only, so a uuid's hyphens have to go. The
-- label stays unique and reversible, which is all the path needs it to be.
create function scope_label(node_id uuid) returns text
language sql immutable strict as $$
  select replace(node_id::text, '-', '_')
$$;

-- Maintains `path` from the parent's. Doing this in a trigger rather than in
-- application code is the point: a path written by hand, or by a repository
-- function that forgets, would silently break inheritance — and it would break
-- it *open*, since a shorter path matches more nodes.
create function set_scope_path() returns trigger
language plpgsql as $$
declare
  parent_path ltree;
  parent_org uuid;
begin
  if new.parent_id is null then
    new.path := scope_label(new.id)::ltree;
  else
    select path, org_id into parent_path, parent_org
    from scope_nodes where id = new.parent_id;

    if parent_path is null then
      raise exception 'parent scope node % does not exist', new.parent_id;
    end if;
    if parent_org <> new.org_id then
      raise exception 'scope node % would cross tenants: parent belongs to %, child to %',
        new.id, parent_org, new.org_id
        using errcode = 'integrity_constraint_violation';
    end if;

    new.path := parent_path || scope_label(new.id)::ltree;
  end if;
  return new;
end;
$$;

create trigger scope_nodes_set_path
  before insert or update of parent_id on scope_nodes
  for each row execute function set_scope_path();

-- Every organization is the root of its own tree.
create function create_organization_scope_node() returns trigger
language plpgsql as $$
begin
  insert into scope_nodes (org_id, kind, parent_id) values (new.id, 'organization', null);
  return new;
end;
$$;

create trigger organizations_create_scope_node
  after insert on organizations
  for each row execute function create_organization_scope_node();

-- ---------------------------------------------------------------------------
-- The hierarchy proper. Each entity owns a scope node, one to one.
-- ---------------------------------------------------------------------------

create table teams (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references organizations (id) on delete cascade,
  scope_node_id  uuid not null unique references scope_nodes (id) on delete cascade,
  slug           citext not null,
  name           text not null,
  created_at     timestamptz not null default now(),

  unique (org_id, slug),
  constraint teams_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
);

create table projects (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references organizations (id) on delete cascade,
  team_id        uuid references teams (id) on delete set null,
  scope_node_id  uuid not null unique references scope_nodes (id) on delete cascade,
  slug           citext not null,
  name           text not null,
  created_at     timestamptz not null default now(),

  unique (org_id, slug),
  constraint projects_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
);

create index projects_team_idx on projects (team_id);

-- Environment kind is the distinction the whole deploy permission model turns
-- on: brief §6.3 makes "deploy to staging" and "deploy to production" separate
-- actions, and §6.5 gives preview environments their own lifecycle.
--
-- `is_production` is generated, not stored by the caller. Deriving it removes
-- the failure where a row says kind='production' and is_production=false, which
-- would be a silent production-permission bypass.
create table environments (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid not null references organizations (id) on delete cascade,
  project_id     uuid not null references projects (id) on delete cascade,
  scope_node_id  uuid not null unique references scope_nodes (id) on delete cascade,
  slug           citext not null,
  name           text not null,
  kind           text not null,
  is_production   boolean generated always as (kind = 'production') stored,
  created_at     timestamptz not null default now(),

  unique (project_id, slug),
  constraint environments_kind check (kind in ('production', 'staging', 'preview')),
  constraint environments_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
);

create index environments_project_idx on environments (project_id);
create index environments_production_idx on environments (org_id) where is_production;

-- A scope node exists only to represent its entity, so it must not outlive it.
-- The foreign keys point entity -> node, which cascades the wrong way: deleting
-- a project would leave its node standing, and an orphaned node keeps conveying
-- every grant made against it. That is a privilege leak with no visible cause,
-- so the reverse direction is a trigger.
--
-- The recursion terminates: deleting a node cascades to child nodes, which
-- cascades to their entities, whose triggers then delete nodes that are already
-- gone — a no-op.
create function delete_owned_scope_node() returns trigger
language plpgsql as $$
begin
  delete from scope_nodes where id = old.scope_node_id;
  return null;
end;
$$;

create trigger teams_delete_scope_node
  after delete on teams for each row execute function delete_owned_scope_node();
create trigger projects_delete_scope_node
  after delete on projects for each row execute function delete_owned_scope_node();
create trigger environments_delete_scope_node
  after delete on environments for each row execute function delete_owned_scope_node();

-- ---------------------------------------------------------------------------
-- Resolving inheritance in one query
--
-- Given a node, `scope_ancestry` yields that node and every ancestor. A grant
-- is conveyed to a node when its scope node appears here — one indexed lookup
-- against the GiST path index, no recursive walk.
-- ---------------------------------------------------------------------------

create view scope_ancestry as
  select descendant.id as node_id,
         descendant.org_id,
         ancestor.id as ancestor_id,
         ancestor.kind as ancestor_kind,
         nlevel(ancestor.path) as ancestor_depth
  from scope_nodes descendant
  join scope_nodes ancestor
    on ancestor.path @> descendant.path
   and ancestor.org_id = descendant.org_id;

-- migrate:down

drop view if exists scope_ancestry;
drop trigger if exists environments_delete_scope_node on environments;
drop trigger if exists projects_delete_scope_node on projects;
drop trigger if exists teams_delete_scope_node on teams;
drop function if exists delete_owned_scope_node();
drop table if exists environments;
drop index if exists projects_team_idx;
drop table if exists projects;
drop table if exists teams;
drop trigger if exists organizations_create_scope_node on organizations;
drop function if exists create_organization_scope_node();
drop trigger if exists scope_nodes_set_path on scope_nodes;
drop function if exists set_scope_path();
drop function if exists scope_label(uuid);
drop index if exists scope_nodes_org_root_idx;
drop index if exists scope_nodes_org_idx;
drop index if exists scope_nodes_path_idx;
drop table if exists scope_nodes;
drop extension if exists ltree;
