# `src/authz` — the only place permission logic lives

One function decides every authorization question:

    can(actor, action, resource, context)

**No permission logic exists anywhere else** — not in a route handler, not in a
component, not in the command palette. The role editor's live preview calls this
same function rather than reimplementing it, and RL-M5-004 tests that parity.

Rules:

- Deny by default. An unmapped action is a denial.
- Denies always win over grants, at any scope.
- Expiry is evaluated at decision time and in the SQL predicate, so an expired
  grant is dead the instant it expires — no cleanup job is in the enforcement
  path.
- 100% line and branch coverage, enforced in CI (RL-M1-013).
