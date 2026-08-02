# 0016 — CSRF tokens and the session cookie policy

**Status:** proposed
**Date:** 2026-08-02
**Task:** RL-M1-021

## Context

Brief §6.7 names CSRF in the minimum security suite. The acceptance criteria are
that every state-changing request carries a token bound to the session, and that
cookies use SameSite and Secure "appropriately for the deployment model".

The second one is the whole decision, because Ratline's deployment model is
unusual. C5 says the dashboard binds to localhost and assumes it is not
internet-exposed, so it is commonly served as **plain HTTP on loopback**. It is
just as commonly served as **HTTPS behind a reverse proxy on a real domain**. And
`docs/NETWORK.md` recommends a third shape — **plain HTTP over a Tailscale or
WireGuard address**, where the transport is encrypted by the tunnel rather than
by TLS.

One hardcoded cookie policy is wrong for at least one of those. Worse, the
obvious way to derive one is actively harmful: threat-model **R-11** records that
a control plane bound to 127.0.0.1 behind a TLS-terminating nginx — the ordinary
production shape — is reported `contained` by `src/config/network.ts`, because a
local check cannot see the proxy. Deriving "loopback bind, therefore drop
`Secure`" from that would give the *most* exposed deployment the *weakest*
cookie. The inference is not merely imperfect; it is anti-correlated with the
truth.

Four decisions follow.

## Options considered

### Where the token comes from

| Option | Assessment |
| --- | --- |
| Random token in a new table, one row per session | Buys independent revocation, which has no use case: a token outliving its session is useless, and a session outliving its token is a session whose holder cannot act. Two lifetimes with one meaning, plus a statement on every mutating request. Rejected. |
| Random token in a new column on `sessions` | Cheaper, and still a second thing that has to be rotated in step with the identifier. The synchronisation is exactly what gets forgotten. Rejected. |
| **`HMAC-SHA256(HKDF(cookie secret, "ratline/csrf/v1"), session.id)`** | No migration, no state, no synchronisation. **Chosen.** |

The property that decided it: **rotation invalidates the token for free.**
Migration 10 note 4 makes rotation a new ROW with a new id rather than an edit,
so a token derived from the retired session does not verify against its
successor. `src/auth/privilege_changes.ts` rotates on every privilege change, and
nothing has to remember to rotate the token alongside it.

The cost, stated: the token is **constant for the life of a session**. It is not
a nonce, and replay by its own session is not an attack — the legitimate client
replays it on every request. What matters is that a cross-site attacker cannot
learn it, which is why it never travels in a cookie or a URL.

C4 is load-bearing here. The key is the cookie secret, which has no default and
which the process refuses to boot without. CloudPanel's CVE-2023-35885 is the
same key with a shipped default.

### Where the token travels

**A synchronizer token in a request header (`X-Ratline-CSRF`), not a
double-submit cookie.**

Double-submit needs no server-side binding, and its security rests entirely on
the attacker being unable to write a cookie on the site's domain. On a
self-hosted install that assumption is weak: Ratline sits at
`ratline.internal.example.com` next to whatever else the team runs, and any
neighbour can set a `Domain=.internal.example.com` cookie Ratline cannot
distinguish from its own. Deriving the expected value server-side does not care
what the attacker can write.

Requiring a *header* is also a second, independent barrier: a cross-origin page
cannot add a custom header to a form POST without a CORS preflight the server
never answers.

The deliberate consequence: **a plain `<form>` post with no JavaScript cannot be
authorized.** Ratline's interface is a scripted application (§6.6, ADR 0001), so
this rules out a shape the product does not have.

A token presented in the query string is **refused**, not ignored. A URL reaches
access logs, the `Referer` of every outbound link, and browser history; because
the token lasts as long as the session, that leak does not expire. Refusing makes
the client bug visible.

### `Secure`

| Option | Assessment |
| --- | --- |
| Always on | Correct for HTTPS and for loopback. Breaks plain HTTP over a tailnet or LAN — the browser silently declines to store the cookie and nobody can sign in. |
| Always off | Sends the session credential in the clear on every HTTPS deployment. Not a candidate. |
| Inferred from the bind address or exposure level | **The dangerous one.** R-11: the reverse-proxy deployment reports `contained`, so this hands the most exposed shape the weakest cookie. Rejected. |
| **On by default; off only on an explicit operator acknowledgement** | **Chosen.** |

`RATLINE_ALLOW_INSECURE_COOKIES=1` is the only input that can turn `Secure` off,
mirroring `RATLINE_ALLOW_PUBLIC_BIND`. Everything else — bind address, exposure
level, the shape of the declared origins — can change the cookie's *name* and
raise a *warning*, never the attribute.

A deployment reached over plain HTTP on a real network therefore **breaks
loudly**: the cookie is still marked `Secure`, the browser refuses to store it,
sign-in fails, and the operator gets a message naming both remedies (terminate
TLS, or acknowledge in writing). That is the direction to fail in. Every product
in this space earned its CVE by failing the other way.

The trusted-origin declaration `RATLINE_PUBLIC_ORIGIN` does double duty: it is
how the operator states the scheme, and it is the set the origin check compares
against. One fact, stated once, used twice — there is no second setting to
disagree with the first.

### `SameSite`

**`Strict`, everywhere, not configurable.** The only use for a knob here is
weakening it.

The cost is real and is the reason this ADR exists rather than a code comment: a
link from a chat alert into the dashboard arrives with no cookie and lands on the
sign-in page, at 2am, which is the moment §3.3 says to optimise for. The remedy
is an interface one — the sign-in screen bounces an already-live session through
a same-site redirect, which does carry the cookie — and it is recorded as owed at
the bottom of `src/api/csrf.ts`.

`Lax` would remove the bounce and would let a cross-site top-level GET carry the
session. Every state-changing route in the table is a non-GET today and
`isSafeMethod` is the single source of truth for that, so `Lax` would be *nearly*
as good. "Nearly" is not the trade to take on the cheap half of the defence,
given the token is the expensive half and is unaffected either way.

## Decision

All four as above:

1. The token is derived from the session id with a subkey of the cookie secret.
   No migration, no stored state.
2. It is presented in a request header, never a cookie and never a URL.
3. `Secure` is on by default and comes off only on an explicit, warned
   acknowledgement.
4. `SameSite=Strict`, `HttpOnly`, `Path=/`, and the `__Host-` prefix whenever
   every declared origin is https.

`Origin` (falling back to `Referer`) is checked against the declared trusted set
by exact match, as defence in depth. An unsafe request carrying neither header is
refused: every browser sends `Origin` on an unsafe method, and a non-browser
client should be presenting an API token rather than riding a cookie session — at
which point CSRF does not apply to it.

## Consequences

**Makes easy.** Adding a route: protection is on by default for every unsafe
method, and `isSafeMethod` is consulted rather than copied, so there is no second
list to update and no per-route opt-in to forget.

**Makes hard.** Any client that is not a scripted browser application. That is
intentional (see above), but it means a future "curl-able" web endpoint has to
authenticate with an API token instead — which is the right answer anyway.

**What we live with.**

- The token is stable for the session's life. Mitigated by keeping it out of
  cookies and URLs, and by session lifetime being absolute and short (8 hours,
  ADR 0014).
- Rotating the cookie secret invalidates every outstanding token. Correct: it
  invalidates every signed cookie too, so the sessions are going regardless.
- The `__Host-` prefix appears only on https deployments, so the session cookie
  name differs between deployment shapes. This is deliberate — flipping the
  policy stops resolving existing cookies rather than silently weakening them —
  but it does mean the name must be read from the policy rather than written into
  a handler.

**New attack surface.** None. The module reads headers and a URL and returns a
verdict; the only write it performs is an audit entry, and only for a request
that already carried a valid session.

## What I need decided

Two operator-facing trades, which is why this is `proposed` rather than settled
in code:

1. **`Secure` on `http://127.0.0.1:7712`.** Loopback is a "potentially
   trustworthy" origin per the Secure Contexts spec and current Chrome, Firefox
   and Safari all honour `Secure` cookies there — so the C5 default deployment
   works. If that is wrong for a browser we care about, the default deployment
   cannot sign in at all, and the fallback is `RATLINE_ALLOW_INSECURE_COOKIES=1`
   on loopback. **This has not been verified against real browsers** — there is
   no HTTP server yet to verify it with. It is the single riskiest assumption in
   this ADR.
2. **`Strict` versus `Lax`.** Strict is chosen above. If deep links from chat
   into the dashboard turn out to matter more than the residual gain, `Lax` plus
   the token is a defensible position and the change is one constant.

## What is NOT done

**Nothing calls any of this.** There is no HTTP server (`src/api/server.ts` does
not exist and another task owns it), so no cookie is set, no header is read, and
no request is refused in production. The module is exercised end to end by
`test/security/csrf.test.ts` against a real database, and the wiring is
enumerated at the bottom of `src/api/csrf.ts`. Until that wiring lands, this is a
decision and a mechanism rather than a protection — the same honest position ADR
0015 records for rate limiting.
