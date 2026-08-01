-- Scheduled audit chain verification, and the head record that makes it
-- meaningful (RL-M1-015).
--
-- RL-M1-014 built the chain and recorded an honest limit: verification cannot
-- detect truncation of its own HEAD. Removing the newest entries leaves a chain
-- that is internally perfect — every prev_hash matches, every hash recomputes,
-- the sequence has no gap. `verify_audit_chain` reports clean on a log somebody
-- shortened, which is the single most useful thing to shorten.
--
-- The fix is not a cleverer chain. A hash chain provably cannot detect its own
-- truncation, because the evidence is the part that was removed. What closes it
-- is remembering, outside the chain, where the head was last time:
--
--   verification run N   records (seq, hash) of the newest entry it saw
--   verification run N+1 refuses to accept a head that moved BACKWARDS
--
-- An attacker must now also rewrite the head record, and the same append-only
-- treatment applies to it. That does not make truncation impossible — nothing
-- can, short of shipping the head somewhere the tenant does not control — but
-- it converts a silent deletion into a loud contradiction, which is the
-- difference between a control and a hope.
--
-- The head record is deliberately a SEPARATE table rather than a column on the
-- chain. A watermark stored inside the thing it watermarks is worth nothing.

-- migrate:up

create table audit_verifications (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations (id) on delete cascade,

  -- The newest entry this run saw. The watermark.
  head_seq      bigint not null,
  head_hash     text not null,
  entries_seen  bigint not null,

  outcome       text not null,
  detail        text not null default '',
  verified_at   timestamptz not null default now(),

  constraint audit_verifications_outcome check (outcome in ('clean', 'broken', 'truncated')),
  constraint audit_verifications_head_seq check (head_seq >= 0)
);

create index audit_verifications_org_time_idx on audit_verifications (org_id, verified_at desc);

-- Append-only, like the chain itself. A verification history that can be edited
-- is a verification history an attacker edits after truncating the log.
create function audit_verifications_are_append_only() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_verifications is append-only; % is not permitted', tg_op
    using hint = 'A verification result is evidence. Append a new run rather than amending an old one.';
end;
$$;

create trigger audit_verifications_no_update
  before update or delete on audit_verifications
  for each row execute function audit_verifications_are_append_only();

alter table audit_verifications enable row level security;
alter table audit_verifications force row level security;
create policy tenant_isolation on audit_verifications
  using (org_id = current_tenant())
  with check (org_id = current_tenant());

grant select, insert on audit_verifications to ratline_app;
revoke update, delete on audit_verifications from ratline_app;

-- Run a verification and record the result.
--
-- Returns the outcome so the caller can alert without a second query. Three
-- outcomes, and `truncated` is the one this migration exists for:
--
--   clean      the chain verifies and the head has not moved backwards
--   broken     verify_audit_chain found a break
--   truncated  the chain verifies, but the head is BEHIND where it was
create function run_audit_verification(p_org_id uuid)
returns table (outcome text, detail text, head_seq bigint)
language plpgsql as $$
declare
  break record;
  -- Distinct names: the OUT parameters above are in scope for the whole body,
  -- so a variable or column called head_seq here is ambiguous and Postgres
  -- rejects the query rather than guessing.
  now_seq   bigint;
  now_hash  text;
  prev_seq  bigint;
  prev_hash_value text;
  result_outcome text;
  result_detail text := '';
  total bigint;
begin
  select e.seq, e.hash into now_seq, now_hash
  from audit_entries e where e.org_id = p_org_id
  order by e.seq desc limit 1;

  -- An organization with no entries yet is clean at head 0, not an error.
  if now_seq is null then
    now_seq := 0;
    now_hash := repeat('0', 64);
  end if;

  select * into break from verify_audit_chain(p_org_id) limit 1;

  select v.head_seq, v.head_hash into prev_seq, prev_hash_value
  from audit_verifications v where v.org_id = p_org_id
  order by v.verified_at desc, v.head_seq desc limit 1;

  select count(*) into total from audit_entries e where e.org_id = p_org_id;

  if break.broken_seq is not null then
    result_outcome := 'broken';
    result_detail := format('entry %s: %s', break.broken_seq, break.problem);

  elsif prev_seq is not null and now_seq < prev_seq then
    -- The chain is internally consistent and SHORTER than last time. Entries
    -- were removed from the end, which is the case the chain alone cannot see.
    result_outcome := 'truncated';
    result_detail := format(
      'head moved backwards: was %s, now %s — %s entries were removed from the end',
      prev_seq, now_seq, prev_seq - now_seq
    );

  elsif prev_seq is not null and now_seq = prev_seq and now_hash <> prev_hash_value then
    -- Same position, different content: the head was replaced rather than
    -- removed. Only reachable if the chain was rebuilt wholesale.
    result_outcome := 'truncated';
    result_detail := format('head %s was replaced: its hash changed since the last run', now_seq);

  else
    result_outcome := 'clean';
  end if;

  insert into audit_verifications (org_id, head_seq, head_hash, entries_seen, outcome, detail)
  values (p_org_id, now_seq, now_hash, total, result_outcome, result_detail);

  outcome := result_outcome;
  detail := result_detail;
  head_seq := now_seq;
  return next;
end;
$$;

-- migrate:down

drop function if exists run_audit_verification(uuid);
drop policy if exists tenant_isolation on audit_verifications;
drop trigger if exists audit_verifications_no_update on audit_verifications;
drop function if exists audit_verifications_are_append_only();
drop index if exists audit_verifications_org_time_idx;
drop table if exists audit_verifications;
