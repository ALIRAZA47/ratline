# 0003 — Tenant scoping and the data-access layer

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-012

## Context

C3 is unusually precise: *"There is no unscoped `findById` in the codebase; make
the unscoped variant impossible to call rather than merely discouraged."* This
is the IDOR class that let Coolify users reach other teams' servers. §9 lists an
unscoped `findById` as automatic rejection.

"Impossible to call" rules out the usual answers. A code review convention is
not impossible. A helper you are supposed to use is not impossible. Even a lint
rule is only impossible-in-CI, which is a real improvement but still one
`eslint-disable` away.

The requirement is layered defence where each layer fails closed independently:
a bug in one does not produce a leak.

## Options considered

| Option | Assessment |
| --- | --- |
| Convention plus code review | Fails the "impossible" bar outright. Rejected. |
| A `scoped()` helper everyone is told to use | The unsafe call still type-checks. Rejected as a sole mechanism. |
| Lint rule banning the raw client outside the repository layer | Genuinely strong, catches the mistake at review time, but is bypassable and only covers code we lint. Good as **one** layer. |
| Branded context type required by every repository signature | Makes the unsafe call fail to *compile*, which is the strongest application-level guarantee available. Good as **one** layer. |
| Postgres row-level security | Enforced by the database regardless of what the application does, including in a migration, a REPL, or an injected query. The only layer that survives an application bug. |

None of these is sufficient alone. The first two are rejected; the last three
compose.

## Decision

Three independent layers, each of which fails closed on its own.

### Layer 1 — the raw handle is unreachable

The Drizzle client is constructed in `src/db/internal/` and exported from
nowhere else. `src/repo/` imports it; every other module is blocked by an
ESLint `no-restricted-imports` rule with a CI check and a fixture proving the
rule fires. Anything outside `src/repo/` that wants data calls a repository
function.

### Layer 2 — the type system

Every repository function takes an authorization context as its first parameter:

```ts
export function findSite(ctx: AuthzContext, id: SiteId): Promise<Site | null>
```

`AuthzContext` is a branded type whose constructor is not exported. The only way
to obtain one is from the authenticated request pipeline or from a named service
identity. There is no literal you can write, no `as` that is not a deliberate
lie visible in review, and no default value.

Inside the repository layer, the handle is reachable only through
`scoped(ctx, table)`, which injects the tenant predicate. `scoped()` is the sole
export from the internal module — there is no path from a repository function to
an unscoped query that does not involve editing `src/db/internal/`.

### Layer 3 — the database

Every tenant-scoped table has row-level security **enabled and forced** (forced
matters: without it, the table owner bypasses policy). The application connects
as a role that is not the table owner and holds no `BYPASSRLS`. Each transaction
sets the tenant with `SET LOCAL`, and the policy reads it.

The test that makes this real: take a repository function, **delete its
application-level predicate**, run it with a foreign tenant, and assert it still
returns zero rows. If that test passes, layer 3 is genuinely independent of
layers 1 and 2 rather than shadowing them.

### Indistinguishability

Repository functions return `null` for both "does not exist" and "exists in
another tenant" — the caller cannot tell, because the query itself cannot see
the row. A single error mapper turns `null` into one uniform response. The
matrix test (RL-M1-026) compares responses byte for byte across every resource
type for own, other-tenant and nonexistent identifiers.

Response *timing* is a weaker channel we are not fully closing in v1: a
nonexistent identifier may short-circuit earlier than a foreign one. Recorded as
a residual risk in the threat model rather than claimed as solved.

### Scope hierarchy

Organization → Team → Project → Environment → Resource is stored as a
materialised scope path on each node, so an inheriting permission check resolves
in one indexed query rather than a recursive walk per request. Grants attach to
any node; denies attach the same way and win.

## Consequences

**Makes easy.** Reviewing data access, because every query is in one directory
and every signature carries its context. Adding a resource type, because the
scoping is structural rather than per-query.

**Makes hard.** Anything genuinely cross-tenant — instance-wide administration,
fleet-level metrics, the audit chain verifier. Each needs an explicitly
constructed system context, and each such construction site is a security review
point. There will be a small, enumerated, individually justified list of them,
and a test asserting the list does not grow silently.

**What we live with.** Row-level security costs a planner pass per query and
makes some query plans worse. At the scale in the brief — tens of hosts,
hundreds of sites — this is not a concern worth trading safety for. If it ever
becomes one, the fix is targeted indexes, not disabling the policy.

**New attack surface.** The `SET LOCAL` plumbing becomes security-critical: a
connection returned to the pool with a tenant still set, or a transaction that
resets it mid-flight, is a cross-tenant leak. Mitigation: the tenant is set by
the same wrapper that opens the transaction and cannot be set by hand; a test
asserts a pooled connection carries no tenant setting on checkout.
