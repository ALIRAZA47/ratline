# `src/repo` — every query in the system

**Every exported function takes `ctx: AuthzContext` as its first parameter.**
`AuthzContext` cannot be constructed outside the authenticated request pipeline
or a named service identity, so an unscoped read fails to compile rather than
being merely discouraged (C3, ADR 0003).

Functions return `null` for both "does not exist" and "exists in another
tenant" — the query cannot see the row, so the caller cannot tell the
difference. A single error mapper turns `null` into one uniform response
(RL-M1-026).

Genuinely cross-tenant work (instance administration, the audit chain verifier)
needs an explicitly constructed system context. That list is short, enumerated,
individually justified, and a test asserts it does not grow silently.
