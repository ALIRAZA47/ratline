-- An audit actor must be something that exists (C6, RL-M1-053).
--
-- Migration 6 declared `actor_id uuid not null` with the comment "C6: no action
-- without an actor. Nullable actor_id would be 'the system'." That closes the
-- anonymous case and nothing else: a not-null uuid column accepts any 128 bits,
-- so an audit write naming a service identity with no row behind it was accepted
-- and stored. Demonstrated, and reachable in production — `ServerDeps
-- .signInIdentityId` is an unvalidated string that every CSRF rejection and every
-- sign-in attempt is recorded against, and `src/main.ts` passes a literal
-- all-zeros uuid while an installation is unclaimed.
--
-- The consequence is precise, and it is the whole of C6: an incident reviewer who
-- joins audit_entries to service_identities gets nothing back. "Attributable"
-- rested on a caller-supplied label.
--
-- WHY THIS IS A TRIGGER AND NOT A FOREIGN KEY, since the obvious reading of
-- "referential integrity" is a foreign key and this deliberately is not one.
--
-- 1. The reference is polymorphic. `actor_type` selects between users,
--    service_identities and api_tokens, and no single foreign key can point at
--    three tables. The available shape is an exclusive arc — three nullable
--    columns, one per kind, each with its own key, plus a check tying them to
--    actor_type.
--
-- 2. That shape would force a choice this table must not make. A foreign key
--    constrains the reference FOREVER, so deleting a person would either be
--    blocked or would take their audit history with it. Neither is acceptable in
--    an append-only log: the record of what somebody did is exactly the thing
--    that must outlive their account. test/security/actor_attribution.test.ts
--    already says so in writing — "the entry still records which id, so the trail
--    survives even when the identity does not".
--
-- 3. What C6 actually needs is narrower than permanent integrity and is fully
--    available: at the moment the action was recorded, the actor was real and
--    belonged to this tenant. That is a write-time property, and a trigger on
--    insert states it exactly. Never-existed is refused; later-deleted is
--    preserved. Those two cases were indistinguishable before, and only the first
--    one is a defect.
--
-- So this closes "the actor was invented" and does NOT claim "the actor is still
-- there". The distinction is written down here rather than left for somebody to
-- discover from a passing test, because a reader who assumed a foreign key would
-- draw a stronger conclusion from a green suite than the schema supports.
--
-- Following migration 8's idiom: a cross-table invariant that a CHECK cannot
-- express, raised with the same errcode so callers cannot tell it from any other
-- integrity failure, and a hint that says what to do instead.
--
-- WHY IT IS A CONSTRAINT TRIGGER RATHER THAN A PLAIN `before insert` ONE. Written
-- as BEFORE, it ran ahead of NOT NULL and ahead of the audit_entries_actor_type
-- CHECK, and so answered for them: a null actor_id and an actor kind of "system"
-- both came back saying the actor did not exist, rather than saying the column
-- cannot be null and that "system" is not an actor kind. Both were still refused,
-- and both reported the wrong reason — which two tests in
-- test/security/actor_attribution.test.ts caught by naming the constraint they
-- expected. A constraint trigger fires after the row's own constraints have been
-- checked, so each violation is reported by the thing that actually objects.

-- migrate:up

create function audit_entry_actor_exists() returns trigger
language plpgsql as $$
declare
  found boolean;
begin
  -- Each branch asks two things: does the row exist, and is it this tenant's.
  -- The tenant half matters as much as the first — an actor id belonging to
  -- another organization would be a real row and still not attribute the action
  -- to anybody who could have taken it.
  --
  -- `users` is global (one person, many organizations), so its tenant test is
  -- membership rather than a column. That is also what the audit suite's own
  -- title has always claimed: "every actor kind names something that exists in
  -- the tenant".
  if new.actor_type = 'user' then
    select exists (
      select 1 from users u
      join memberships m on m.user_id = u.id
      where u.id = new.actor_id and m.org_id = new.org_id
    ) into found;
  elsif new.actor_type = 'service_identity' then
    select exists (
      select 1 from service_identities
      where id = new.actor_id and org_id = new.org_id
    ) into found;
  elsif new.actor_type = 'api_token' then
    select exists (
      select 1 from api_tokens
      where id = new.actor_id and org_id = new.org_id
    ) into found;
  else
    -- Unreachable while audit_entries_actor_type holds, and not treated as
    -- unreachable. A future migration widening that CHECK without touching this
    -- function would otherwise silently stop validating the new kind, which is
    -- the failure mode migration 8 was written about: an invariant expressed as
    -- "handle the kinds we know" ages badly as the kinds multiply.
    raise exception
      'audit actor kind % has no existence check, so its attribution is unverified', new.actor_type
      using errcode = 'integrity_constraint_violation',
            hint = 'Add a branch to audit_entry_actor_exists() for this actor kind. '
                   'A kind nobody checks is a kind that can be invented.';
  end if;

  if not found then
    raise exception
      'audit actor %:% does not exist in organization %', new.actor_type, new.actor_id, new.org_id
      using errcode = 'integrity_constraint_violation',
            hint = 'C6 requires a recorded actor that something can be joined to. Create the '
                   'identity before acting as it — an automation acts as a named service '
                   'identity with a row, not as a uuid chosen by the caller.';
  end if;

  -- An AFTER trigger's return value is ignored; null says so, as migration 2's
  -- assert_organization_has_owner does.
  return null;
end;
$$;

create constraint trigger audit_entries_actor_exists
  after insert on audit_entries
  for each row execute function audit_entry_actor_exists();

-- migrate:down

drop trigger if exists audit_entries_actor_exists on audit_entries;
drop function if exists audit_entry_actor_exists();
