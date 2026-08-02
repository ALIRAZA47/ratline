# 0015 — Authentication rate limiting

**Status:** proposed
**Date:** 2026-08-02
**Task:** RL-M1-020

## Context

Brief §6.7 requires rate limiting on all auth endpoints including password
reset. Threat-model R-15 makes it specific: the sign-in path derives a 128 MiB
scrypt hash on every attempt, *including for accounts that do not exist* — which
is correct, because deriving unconditionally is what stops timing revealing
whether an account exists (ADR 0014). The consequence is that an unauthenticated
caller can make the control plane do expensive work for free.

Four decisions, and the interesting ones are about what happens when the limiter
itself is under load.

## Options considered

### Where the counter lives

ADR 0007 rules out Redis, and that reasoning transfers unchanged: a second
stateful service is a second thing to install, secure, patch and back up on a
self-hosted product. So Postgres, which raises the real question — **a counter
written on every failed attempt is write amplification on exactly the path an
attacker is flooding.**

| Option | Assessment |
| --- | --- |
| A row per attempt | The attacker chooses the table size, and correctness depends on a sweeper keeping up with a flood. Rejected. |
| **A row per (org, dimension, path, window), upserted** | Bounded by configuration rather than by traffic. **Chosen.** |

The refinement that matters: **the statement stops writing once a bucket is
spent.** A guard on the `DO UPDATE` means a saturated bucket is read and not
modified — no new tuple version, no WAL, no bloat. The steady state of a
sustained flood is an index probe and a brief row lock, against the 128 MiB and
~200 ms of scrypt it declines.

### Fixed window or sliding

**Fixed, never extended by later attempts.** A sliding window is the more
accurate limiter and the wrong one here: it lets an attacker hold any named
account locked out indefinitely by attempting once per window. A limit that
never releases is a denial of service an attacker can aim at anyone they can
name, so the window releases on time, and a proven success clears the account
dimension immediately — neither release involves an administrator.

Success clears the **account** dimension only, and only the **path** that
succeeded. Clearing the address dimension would let an attacker holding one
valid account wipe their address budget at will; clearing every path would let a
known password refresh the two-factor budget, which is precisely the brute force
the second factor exists to stop.

### The bucket key

**A digest of the presented identifier, computed before anything is looked up.**

Two reasons, and the second was not the goal but matters as much. A limiter that
only counts *real* accounts tells an attacker which accounts exist by which ones
get limited. And because unauthenticated callers write this table, storing raw
identifiers would turn it into an attacker-populated harvest of every address
ever tried — in the database and in every backup.

The cost, stated: this table cannot say *which* address is attacking. That
belongs to sign-in audit entries, which are blocked on the pre-authentication
context seam ADR 0014 records.

### Failure of the store

**Fail closed.** A rate limiter that fails open is an availability feature
wearing a security feature's clothes, and its failure mode is exactly the flood
it exists to stop. Refusal is *returned* rather than thrown, so a caller has to
handle it as a value rather than catch it and continue past.

The exception is the reset-on-success path, which throws instead: it runs after
the credential was accepted, so there is no request left to refuse, and failing
to clear a counter costs its holder the rest of the window — the safe direction.

## Decision

All four as above. Both dimensions — per account and per source address — are
counted on **every** attempt, and a refusal by one does not short-circuit the
other. If it did, an attacker would spend one account's budget for free as far
as their address was concerned, then move to the next account with a clean
address budget.

The clock is `statement_timestamp()`, for the reasons in ADR 0012 applied to a
window boundary.

## Consequences

**Makes easy.** Bounding the queue of pending derivations, which is what R-15 is
actually about.

**Makes hard.** Nothing yet, because nothing calls it — see below.

**What we live with — the limiter's own overload mode.** Concurrent attempts on
one bucket serialise on a row lock, queue while holding pooled connections,
saturate the pool, and time out into a fail-closed refusal for everyone. That is
a denial of service. It is the *bounded, loud, self-healing* kind, traded
against an unbounded memory one, and the fix if that ceiling is ever reached is
admission control in front of the auth handlers rather than a larger limit.

**New attack surface.** A table unauthenticated callers can cause writes to.
Bounded by configuration, digested rather than raw, and tenant-scoped like
everything else — which itself has a cost: an attacker who knows N organization
ids gets N address budgets. Small on a self-hosted install, real.

## What is NOT done

**Nothing calls the limiter.** There is no HTTP layer, two-factor verification
does not exist (RL-M1-019), and password reset does not exist (RL-M1-034). All
four paths are modelled and each is driven past its published limit in the
tests, but the wiring — record, refuse, *then* do the expensive work — belongs
to route handlers that have not been written. Called after the derivation it is
a metric, not a limit.

The single easiest way to make all of this decorative is to trust a forwarded-for
header for the source address. That makes the address dimension free to evade
*and* lets an attacker exhaust someone else's budget.
