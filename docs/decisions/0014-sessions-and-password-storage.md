# 0014 — Sessions and password storage

**Status:** proposed
**Date:** 2026-08-02
**Task:** RL-M1-017

## Context

Brief §6.7 lists session fixation among the security suite's minimum coverage,
and §6.3 requires role changes to take effect immediately on active sessions.
C4 forbids default secrets of any kind. Four decisions had to be made, and three
of them are the kind that are cheap now and expensive later.

## Options considered

### Password hashing

| Option | Assessment |
| --- | --- |
| bcrypt | Widely deployed, but caps the password at 72 bytes and its memory cost is fixed and small. Rejected. |
| argon2id | The current preference in most guidance. Needs a native dependency, against §6.7's "prefer the standard library", and a native build is a supply-chain and portability cost on a self-hosted product. Rejected — but see Consequences. |
| **`node:crypto` scrypt** | Memory-hard, in the standard library, no build step. **Chosen.** |

Parameters: **N = 2^17, r = 8, p = 1**, 32-byte key, 16-byte per-password salt.
N = 2^17 is OWASP's published minimum at r=8/p=1 — meeting a published floor
needs no argument, going below one does. `r` stays at the standard 1 KiB block
because lowering it gives back the memory being bought, and `p = 1` because
parallelism buys CPU cost, not the memory cost an attacker finds expensive.

**The implied cost is 128 MiB per hash**, and that is a fact about the deployment
rather than a footnote: Node runs scrypt on a 4-wide threadpool, so a sign-in
burst can transiently reach ~512 MiB on a control plane the brief says must run
on a laptop. It is computed by a function rather than left as arithmetic in a
comment, and it is a genuine denial-of-service lever until RL-M1-020 lands rate
limiting.

Parameters are stored alongside the hash, so the choice is revisable without a
migration and `needsRehash()` can act on it.

### Are sessions tenant-scoped?

A user is global — one person, several organizations (migration 2). A session
could reasonably have followed.

| Option | Assessment |
| --- | --- |
| Session belongs to a user, spans organizations | One sign-in, all tenants. Convenient, and a stolen cookie reaches everything the person can reach. |
| **Session belongs to a user *within* one organization** | A session is an act of access, not a person. §3.3's tiebreaker is blast-radius control. **Chosen.** |

Three further arguments, one of them structural: `scoped()` is the only thing in
the codebase that runs SQL and it binds exactly one tenant per transaction, so an
unscoped session table would need a second data-access primitive — precisely the
escape hatch C3 exists to prevent. RL-M1-018 also needs a session judged against
one organization's grants, and removing a member ends their access there and
nowhere else for free.

The cost, stated: three organizations means three sessions, and switching
organization mints a new one. That is acceptable because switching organization
*is* a privilege change and has to rotate anyway.

### Rotation

Rotation replaces the row rather than editing it: a new identifier, a new row,
the old one revoked and retained with a pointer to its successor. An edited row
loses the evidence that a rotation happened, which is the thing an incident
review is looking for.

### Expiry

Absolute, fixed at creation, never extended on use. A sliding window makes "how
long can a stolen cookie live" unanswerable, which is the only question the
column exists to answer. Renewal is rotation — the same mechanism, not a second
one. The clock is `statement_timestamp()`, for the reasons in ADR 0012.

## Decision

All four as above. Session tokens are generated from the CSPRNG and stored only
as a hash, consistent with API tokens (RL-M1-032).

## Consequences

**Makes easy.** Revoking one session or all of a user's. Reasoning about the
lifetime of a stolen credential, because it is a number fixed at issue.

**Makes hard.** Working across organizations, which now costs a session each.
Accepted deliberately.

**What we live with — and this one deserves stating plainly.** The constant-time
comparison in `verifyPassword` is enforced *structurally*, not behaviourally. A
functional test suite cannot tell `secretEquals` from `===` or from
`Buffer.equals`: all three accept exactly the same passwords, and the difference
is only in how long a rejection takes. Mutation testing confirms it — replacing
the comparison with `Buffer.equals` fails exactly one test, and that test is a
source-level assertion that the function's body contains no `===` and no `!==`.

That assertion is deliberately incomplete and says so: `Buffer.compare(a, b) < 1`
would also be non-constant-time and would also pass it. It catches the mutation
someone actually makes, not every mutation possible. Knowing which guarantees
are enforced and which are merely conventional is worth more than pretending the
distinction does not exist.

**New attack surface.**

- The sign-in path derives a 128 MiB hash per attempt, including for accounts
  that do not exist — the no-password path performs a full derivation against a
  throwaway salt so timing does not reveal whether an account exists. That is
  correct for enumeration and is a memory lever until RL-M1-020.
- Session identifiers are bearer credentials. Hash-only storage means a database
  read does not yield a usable session, but the cookie itself is enough, which
  is what makes rotation and absolute expiry load-bearing rather than tidy.

## Open seam

A sign-in needs an `AuthzContext` *before* there is anyone to attribute it to —
the same bootstrap problem as looking a user up by email. Nothing was invented
here. The two options are a named service identity, which C6 already sanctions,
or a new `contextForSignInAttempt`. **RL-M1-024 has to pick one**, and no
sign-in audit entries are written until it does.
