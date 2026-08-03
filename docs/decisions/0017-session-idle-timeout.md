# 0017 — Session idle timeout

**Status:** proposed
**Date:** 2026-08-02
**Task:** RL-M1-035

## Context

ADR 0014 gave sessions an **absolute** lifetime — eight hours from issue, never
extended by activity. RL-M1-035 asks the question that always follows: should
there also be an **idle** timeout, ending a session after some period without
use, independently of the absolute one?

It is worth being clear about what an idle timeout is actually bought for,
because the answer decides everything. It is not for a stolen token — that is
what revocation, rotation on privilege change and the absolute lifetime are for.
It is for one scenario: **an operator walks away from an unlocked workstation.**
Everything below is about whether an idle timeout is a good control for that
scenario.

The material facts:

- `sessions.last_seen_at` already exists and is written on every validated
  request, by `useSessionToken` in `src/repo/sessions.ts`, using
  `statement_timestamp()`.
- Sessions already expire absolutely at eight hours, and R-22 leans on that:
  the CSRF token is derived from the session id and so is constant for the
  session's life, mitigated in part by that life being short.
- Ratline is an operations console. Its long-running interactions — a deploy,
  a log tail, a web terminal held open during an incident (§6.4) — are exactly
  the moments when being signed out is most damaging.

## Options considered

| Option | Assessment |
| --- | --- |
| Idle timeout measured on `last_seen_at` | Cheap, conventional, and **defeated by the product's own dashboard.** See below. Rejected. |
| Idle timeout measured on human interaction reported by the client | The server would be trusting a browser's account of whether a human is present. A client that lies keeps the session alive forever, and the honest client is the only one restricted. Rejected. |
| Shorten the absolute lifetime instead | One predicate, not two. Real, but blunt: it signs people out mid-task on a schedule unrelated to whether they are at the desk. Partly chosen — see Decision. |
| Re-authentication for dangerous actions | Targets the actions rather than the clock, and is not defeated by polling. **Proposed as the replacement.** |
| No idle timeout | **Chosen for v1**, with the above. |

### Why `last_seen_at` cannot carry an idle timeout

`last_seen_at` records the last *request*, not the last *human*. A dashboard that
polls — for deploy status, for host health, for the tension line the design plan
calls for — writes `last_seen_at` on a timer. An idle timeout built on it would
therefore expire a session only when the browser tab is **closed**, which is
precisely the case the absolute lifetime already covers, and would never expire
the abandoned-but-open tab, which is the entire scenario.

That is the decisive point, and it is worth stating as a general one: **a control
whose measurement is produced by the thing it is meant to constrain is not a
control.** It would appear in the security policy screen, read as protection,
and protect against nothing. That is worse than its absence, because an operator
who believes the console signs itself out will lock their screen less often.

Making it real would mean suppressing polling from `last_seen_at`, which means
classifying every endpoint as human-driven or machine-driven, and keeping that
classification correct forever. The classification would fail open — a new
endpoint defaults to counting as activity — and nothing would notice.

### Why a second expiry predicate is expensive here

ADR 0012's argument applies directly: precedence and expiry live in one place
because two places give one question two answers. Session expiry is currently a
single comparison against `expires_at` in `live_sessions`. An idle rule adds a
second, and the two must agree about the clock, about transaction time versus
statement time, and about what happens to a session that is idle-expired but not
absolutely expired. Every one of those is a place to fail open.

## Decision

**No idle timeout in v1.** Instead:

1. **Keep the absolute eight-hour lifetime**, and make it configurable per
   organization through the security policy that `organization.manage_security_policy`
   and `PUT /organization/security-policy` already exist for. An organization
   that wants two hours can have two hours; that is the honest version of "we
   sign you out sooner", because it is measured on something the server actually
   knows.

2. **Propose re-authentication for the highest-risk actions** as the control
   that an idle timeout was reaching for. Revealing a secret value, opening a
   web terminal, changing the permission model, adding a host: ask for the
   password again if the session was issued more than a short while ago. It is
   not defeated by polling, it costs nothing during ordinary work, and it
   binds the check to the moment of danger rather than to a clock. Tracked as a
   new task rather than smuggled into this one.

3. **Say plainly in the interface** that Ratline does not sign an idle session
   out, so nobody assumes otherwise. The remedy for an unattended workstation is
   the operating system's screen lock, which does work, and telling an operator
   that is more use than a control that does not.

## Consequences

- An abandoned open tab keeps a usable session for up to the absolute lifetime.
  That is a real residual and it is recorded as a risk rather than papered over.
- R-22's mitigation is unchanged: the absolute lifetime still bounds a leaked
  CSRF token, and an organization tightening the lifetime tightens that too.
- Nothing new to keep in step. Session expiry stays one predicate in
  `live_sessions`.
- Two-factor authentication (RL-M1-019) does not help here — the walked-away
  case has already passed both factors — which is worth stating so the two are
  not confused.

## What is NOT done

- No idle timeout of any kind, including a configurable one defaulted to off. A
  setting that cannot be implemented honestly should not be offered.
- No client-reported activity signal.
- Re-authentication is proposed here and implemented elsewhere; this ADR does
  not decide its threshold or its action list.
