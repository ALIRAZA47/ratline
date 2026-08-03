-- The hash-chained, append-only audit log (C6, RL-M1-014).
--
-- Brief §6.3: "Append-only, hash-chained audit log. Every mutating
-- authorization decision records actor, action, resource, decision, IP,
-- timestamp and request ID."
--
-- Four decisions carry this, and the first is the one that makes it worth
-- anything at all.
--
-- 1. THE DATABASE COMPUTES THE HASH, NOT THE APPLICATION.
--    An audit log whose chain is computed by the thing being audited proves
--    nothing: an attacker who owns the application writes whatever entries they
--    like and recomputes the chain over them, and it verifies perfectly. With
--    the hash in a trigger, forging history requires the database role too — and
--    the application role cannot UPDATE or DELETE, so rewriting the past means
--    escalating first. That is the difference between evidence and decoration.
--
-- 2. THE CHAIN IS PER ORGANIZATION.
--    Row-level security means a tenant can only ever see its own rows, so a
--    single global chain would be unverifiable by anyone except a superuser —
--    every tenant would hold a chain with holes in it and no way to tell a
--    redaction from a policy. Per-organization chains are each independently
--    verifiable by the tenant that owns them.
--
-- 3. APPEND-ONLY IS ENFORCED TWICE.
--    Privileges are revoked, AND a trigger raises on UPDATE or DELETE. The
--    revoke is the real control; the trigger is what catches a future migration
--    that grants the privilege back without thinking, since that is a far more
--    likely path than an attacker.
--
-- 4. A DENIED DECISION IS RECORDED AS PROMINENTLY AS AN ALLOWED ONE.
--    §6.3 asks for "every mutating authorization decision", not every successful
--    one. A log that only records what worked cannot show an attacker probing.

-- migrate:up

create table audit_entries (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations (id) on delete cascade,

  -- Position in this organization's chain. Assigned by the trigger, never by
  -- the caller. Unique so two concurrent inserts cannot both claim a slot.
  seq          bigint not null,
  prev_hash    text not null,
  hash         text not null,

  -- C6: no action without an actor. Nullable actor_id would be "the system".
  actor_type   text not null,
  actor_id     uuid not null,
  actor_label  text not null default '',

  action       text not null,
  resource_type text not null,
  resource_id  uuid,

  -- The decision itself, and why. `can()` returns a reason and it belongs here:
  -- "denied because a deny exists" and "denied because nobody granted it" need
  -- different responses from whoever reads this.
  decision     text not null,
  reason       text not null default '',

  ip           inet,
  request_id   text not null,
  occurred_at  timestamptz not null default now(),

  -- Never a secret value. ADR 0006 is explicit that change history records who
  -- and when but never the value, and this is the table most likely to be
  -- handed to someone during an incident.
  metadata     jsonb not null default '{}'::jsonb,

  constraint audit_entries_actor_type check (actor_type in ('user', 'service_identity', 'api_token')),
  constraint audit_entries_decision check (decision in ('allow', 'deny')),
  constraint audit_entries_request_id_present check (length(btrim(request_id)) > 0),
  constraint audit_entries_seq_positive check (seq > 0),
  unique (org_id, seq)
);

create index audit_entries_org_time_idx on audit_entries (org_id, occurred_at desc);
create index audit_entries_actor_idx on audit_entries (org_id, actor_type, actor_id);
create index audit_entries_action_idx on audit_entries (org_id, action);
create index audit_entries_denials_idx on audit_entries (org_id, occurred_at desc) where decision = 'deny';

-- The canonical bytes a chain link covers.
--
-- Every field that carries meaning is in here. A field left out is a field an
-- attacker may rewrite without breaking verification — so `metadata` is
-- included even though it is free-form, and `occurred_at` is included at
-- microsecond precision so entries cannot be re-timed.
create function audit_entry_payload(
  p_seq bigint, p_prev_hash text, p_actor_type text, p_actor_id uuid,
  p_action text, p_resource_type text, p_resource_id uuid, p_decision text,
  p_reason text, p_ip inet, p_request_id text, p_occurred_at timestamptz,
  p_metadata jsonb
) returns text
language sql immutable as $$
  select concat_ws(
    e'\x1f',  -- unit separator: cannot occur in any of these values, so no
              -- concatenation of two fields can imitate a different split
    p_seq::text,
    p_prev_hash,
    p_actor_type,
    p_actor_id::text,
    p_action,
    p_resource_type,
    coalesce(p_resource_id::text, ''),
    p_decision,
    p_reason,
    coalesce(host(p_ip), ''),
    p_request_id,
    to_char(p_occurred_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    -- jsonb::text is not canonical across versions; jsonb_canonical would be
    -- better and does not exist. Sorting keys via jsonb_each is enough here
    -- because metadata is written by us, not by users.
    coalesce((select string_agg(k || '=' || v::text, ',' order by k)
              from jsonb_each(p_metadata) as e(k, v)), '')
  )
$$;

-- Assigns seq, prev_hash and hash. Everything the caller supplies for those
-- three is discarded.
create function audit_entry_chain() returns trigger
language plpgsql as $$
declare
  last_seq bigint;
  last_hash text;
begin
  -- Serialise appends per organization. Without this, two concurrent inserts
  -- read the same tail and both chain off it, producing a fork that verifies
  -- for neither. Transaction-scoped, so it releases on commit or rollback.
  perform pg_advisory_xact_lock(hashtextextended(new.org_id::text, 0));

  select seq, hash into last_seq, last_hash
  from audit_entries
  where org_id = new.org_id
  order by seq desc
  limit 1;

  new.seq := coalesce(last_seq, 0) + 1;
  -- The genesis link. A fixed, recognisable value rather than an empty string,
  -- so "this is the first entry" and "prev_hash was never set" are different.
  new.prev_hash := coalesce(last_hash, repeat('0', 64));
  new.occurred_at := coalesce(new.occurred_at, now());

  new.hash := encode(
    sha256(
      convert_to(
        audit_entry_payload(
          new.seq, new.prev_hash, new.actor_type, new.actor_id, new.action,
          new.resource_type, new.resource_id, new.decision, new.reason,
          new.ip, new.request_id, new.occurred_at, new.metadata
        ),
        'UTF8'
      )
    ),
    'hex'
  );
  return new;
end;
$$;

create trigger audit_entries_chain
  before insert on audit_entries
  for each row execute function audit_entry_chain();

-- Append-only, enforced twice. See note 3 at the top.
create function audit_entries_are_append_only() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_entries is append-only; % is not permitted', tg_op
    using hint = 'Correct a mistaken entry by appending a correction that references it.';
end;
$$;

create trigger audit_entries_no_update
  before update or delete on audit_entries
  for each row execute function audit_entries_are_append_only();

-- Verify a tenant's chain, returning the first break or nothing.
--
-- Recomputes every hash rather than trusting the stored one, so a row edited by
-- something that could bypass the triggers is still caught.
create function verify_audit_chain(p_org_id uuid)
returns table (broken_seq bigint, problem text)
language plpgsql stable as $$
declare
  row_ record;
  expected_prev text := repeat('0', 64);
  expected_seq bigint := 1;
  recomputed text;
begin
  for row_ in
    select * from audit_entries where org_id = p_org_id order by seq
  loop
    if row_.seq <> expected_seq then
      broken_seq := row_.seq;
      problem := format('sequence jumps from %s to %s — an entry was removed', expected_seq - 1, row_.seq);
      return next;
      return;
    end if;

    if row_.prev_hash <> expected_prev then
      broken_seq := row_.seq;
      problem := 'prev_hash does not match the previous entry';
      return next;
      return;
    end if;

    recomputed := encode(sha256(convert_to(audit_entry_payload(
      row_.seq, row_.prev_hash, row_.actor_type, row_.actor_id, row_.action,
      row_.resource_type, row_.resource_id, row_.decision, row_.reason,
      row_.ip, row_.request_id, row_.occurred_at, row_.metadata
    ), 'UTF8')), 'hex');

    if recomputed <> row_.hash then
      broken_seq := row_.seq;
      problem := 'contents do not match the stored hash — the row was altered';
      return next;
      return;
    end if;

    expected_prev := row_.hash;
    expected_seq := row_.seq + 1;
  end loop;
  return;
end;
$$;

alter table audit_entries enable row level security;
alter table audit_entries force row level security;
create policy tenant_isolation on audit_entries
  using (org_id = current_tenant())
  with check (org_id = current_tenant());

-- The application appends and reads. It does not rewrite history.
grant select, insert on audit_entries to ratline_app;
revoke update, delete on audit_entries from ratline_app;

-- migrate:down

drop policy if exists tenant_isolation on audit_entries;
drop function if exists verify_audit_chain(uuid);
drop trigger if exists audit_entries_no_update on audit_entries;
drop function if exists audit_entries_are_append_only();
drop trigger if exists audit_entries_chain on audit_entries;
drop function if exists audit_entry_chain();
drop function if exists audit_entry_payload(bigint, text, text, uuid, text, text, uuid, text, text, inet, text, timestamptz, jsonb);
drop index if exists audit_entries_denials_idx;
drop index if exists audit_entries_action_idx;
drop index if exists audit_entries_actor_idx;
drop index if exists audit_entries_org_time_idx;
drop table if exists audit_entries;
