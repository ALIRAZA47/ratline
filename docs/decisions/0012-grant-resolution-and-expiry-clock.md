# 0012 — Grant resolution, the expiry clock, and unconditional owner grants

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M1-011

## Context

Brief §6.3 requires time-bound grants whose "expiry is enforced server-side, not
by a cleanup job", denies that "always win", and permissions that inherit
downward. RL-M1-012 will build `can()` on top of whatever this decides, so the
interface matters more than the implementation.

Three questions had to be answered, and the second turned out to be subtler than
it looks.

## Options considered

### Where resolution lives

| Option | Assessment |
| --- | --- |
| Entirely in TypeScript — load a subject's grants, resolve in memory | Every decision costs a round trip plus the whole grant set. Worse, the expiry filter would live in application code, so a query that forgot it would honour dead grants. Rejected. |
| Entirely in SQL, including which roles carry an action | Puts the catalogue in the database, duplicating `catalogue.ts` and letting the two disagree. Rejected. |
| **Split: SQL owns precedence, inheritance and expiry; TypeScript supplies which roles carry the action** | The database enforces what must not be skippable; the catalogue stays the single source of actions. **Chosen.** |

### The expiry clock — the subtle one

"Evaluated at decision time" sounds like an implementation detail. It is not.

| Function | Behaviour | Consequence |
| --- | --- | --- |
| `now()` | Frozen for the whole transaction | A decision late in a long transaction honours a grant that lapsed minutes earlier. A break-glass elevation would outlive its expiry for as long as the transaction runs. |
| `clock_timestamp()` | VOLATILE, advances per row | Two rows of one decision can be judged against different instants, and no index on `expires_at` is usable. |
| **`statement_timestamp()`** | STABLE within a statement, advances between them | Exactly "at decision time": one decision sees one instant, and the next statement sees a later one. **Chosen.** |

This is testable and is tested: one transaction is held open across an expiry
and the answer flips from allow to deny with nothing having run in between,
while `now()` is asserted not to have changed and `statement_timestamp()` is
asserted to have advanced. That last pair is what rules out `now()` as the clock
rather than merely suggesting it.

### The last-owner floor, which expiry quietly broke

RL-M1-004 enforces "at least one Owner always exists" with a constraint trigger
counting organization-scope owner rows. Adding expiry and denies defeated it in
two ways that no trigger can catch:

- **A lapsing owner grant.** The row is still there, so the count is still one,
  but the grant is dead. No trigger fires, because *time passing is not an
  event*.
- **An organization-scope deny of `owner`.** The counted row is untouched while
  the grant it represents is neutralised.

| Option | Assessment |
| --- | --- |
| Make the trigger smarter — filter effect and expiry in the count | Fixes the deny case, cannot fix the lapse case at all. There is no event to hang a trigger on. Rejected. |
| A scheduled job that re-checks ownerless organizations | Exactly the "cleanup job that silently fails" §6.4 warns about, and it detects rather than prevents. Rejected. |
| **Refuse to represent the state: an organization-scope `owner` grant must be `allow` and must never expire** | The dangerous states become unwriteable, so no detection is needed. **Chosen.** |

## Decision

**Resolution is three database objects, each with exactly one job:**

| Object | Owns |
| --- | --- |
| `live_grants` (view) | The expiry predicate, and nothing else |
| `effective_grants(...)` | Inheritance direction, via `scope_ancestry` |
| `grant_decision(...)` | Precedence — denies first, then allows, else deny |

Both functions read the view rather than `grants`, so no resolution path can
skip the expiry filter. All three are **invoker-rights**: a `SECURITY DEFINER`
function here would run as the migration role — a superuser — and bypass
row-level security entirely, undoing RL-M1-006. A test asserts `prosecdef` is
false and `security_invoker` is on, because that mistake is invisible in review.

**Deny-by-default is the `else` branch**, not an absence. A null role array, an
unknown node, or an unknown subject all return `deny`.

**An organization-scope `owner` grant must be `effect = 'allow'` with
`expires_at is null`**, enforced by CHECK. Nothing legitimate is lost:
break-glass is temporary *Admin*, not Owner (§6.3), and owner grants at narrower
nodes may still expire and be denied.

**The creation-time expiry check is `expires_at > created_at`, not
`> now()`.** Postgres refuses non-immutable functions in CHECK, and `now()`
would be the wrong mechanism regardless: CHECK is re-validated on UPDATE and on
restore, so a valid grant would become un-updatable and a dump taken today would
refuse to restore tomorrow, purely because time had passed.

## Consequences

**Makes easy.** Writing `can()`: it supplies the roles carrying an action and
reads one decision. Auditing the rules, because each lives in one named object.

**Makes hard.** Resource-scoped grants. The fifth hierarchy level owns no
`scope_nodes` row, so those rows cannot resolve by ancestry. Ignoring them would
drop resource-scoped *denies*, which fails open — so the functions take a
`resource_id` matched by identity, with **no default**, forcing callers to name
it. The seam closes when resource tables exist.

**What we live with.** A deny denies *through the role it names*. Denying
`developer` at a project strips an action from someone who also holds `owner`
there, if both roles carry it. That is what "denies always win" means with
role-keyed rows, and it will surprise people. Tested explicitly so it reads as a
decision.

**New attack surface.** None added; two states removed. Two gaps are recorded in
the threat model rather than fixed here: an `api_token` subject can be granted
directly with no intersection against its issuing user (RL-M1-032 owns that),
and a disabled user's grants still resolve, because "may this actor act at all"
is one question per request rather than one per node and belongs in `can()`.
