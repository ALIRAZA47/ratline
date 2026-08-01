# 0010 — Web server configuration generation, validation and rollback

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-019

## Context

§6.2 requires Caddy by default with Nginx as an opt-in, configuration generated
from templates with escaped values, validated with the server's own config test,
rolled back on failure, and — the strongest clause — *"never leave a host with
config that fails validation."*

That last requirement is about crash-safety, not just error handling. A host
that loses power between writing a vhost file and validating it must come back
serving. Handling the error path is not enough; the write itself has to be
atomic.

Configuration generation is also a first-class injection surface. Site names,
domains, redirect targets, header values and basic-auth realms all come from
users and all end up in a config file that a privileged process parses.

## Options considered

### Generation

| Option | Assessment |
| --- | --- |
| String concatenation | The §9 anti-pattern. Rejected. |
| General-purpose template engine with default escaping | Better, but generic HTML-oriented escaping is wrong for config grammar — escaping a quote for HTML does nothing useful in a Caddyfile. |
| Go `text/template` with per-context escaper functions and no default passthrough | Every interpolation site must name its escaper; a missing one is a compile-or-lint failure rather than a silent injection. **Chosen.** |
| Structured emission via the server's JSON API | Caddy's native config is JSON, so this eliminates the grammar entirely for Caddy — but is Caddy-specific and forecloses Nginx. Adopted **partially**, see below. |

### Which config format for Caddy

Caddy accepts both a Caddyfile and native JSON over an admin API. JSON removes
the entire text-injection class for Caddy: values are JSON strings, and a
serialiser cannot be tricked into emitting a directive.

The catch is legibility. §3.4 is explicit: *"a competent operator should always
be able to SSH in and recognise what Ratline did."* A generated JSON blob fails
that badly; a Caddyfile passes it easily.

**Resolution:** generate a Caddyfile as the on-disk artifact, because an
operator reading `/etc/caddy` must recognise it, and treat the strict escaping
plus validation plus fuzzing as the injection defence. Revisit if fuzzing shows
the Caddyfile grammar is harder to escape safely than expected — that finding
would be worth an ADR of its own.

### Applying a change

| Option | Assessment |
| --- | --- |
| Write, then reload, then check | Leaves broken config on disk if validation fails. Rejected. |
| Validate, then write, then reload | Better, but the write is still non-atomic — a crash mid-write leaves a truncated file. |
| Stage, validate, atomically swap, reload, verify, roll back on failure | Crash-safe at every point. **Chosen.** |

## Decision

### Generation

`text/template` in the agent, with a fixed set of escaper functions chosen per
interpolation context: identifiers, domains, filesystem paths, header values,
and quoted strings. There is no default passthrough — a template that
interpolates a raw value fails the build. Before templating, every value is
validated against a strict allowlist pattern for its type; a site slug that does
not match is rejected long before it reaches a template. Escaping is the second
line, not the first.

RL-M2-017 fuzzes site names, domains and paths with metacharacters and unicode
through the generated output, asserting the parse tree contains no directive the
template did not intend.

### The apply state machine

1. **Stage** — render to a temporary file in the same directory as the target,
   so the later rename is atomic on the same filesystem.
2. **Validate** — run the web server's own validator against the staged
   configuration in a complete config context, not the fragment alone; a fragment
   can be valid and still break the whole when included. Failure aborts here,
   having touched nothing live.
3. **Snapshot** — record the current known-good configuration.
4. **Swap** — `rename(2)` the staged file over the target. Atomic; a crash
   leaves either the old file or the new one, never a partial.
5. **Reload** — signal the web server to reload.
6. **Verify** — confirm the server is serving after reload, not merely that the
   reload command returned zero.
7. **Roll back** — on failure at step 5 or 6, restore the snapshot, reload
   again, and report failure with the validator's actual output.

Step 6 matters more than it looks: a reload can succeed and the server still be
unable to bind a port or read a certificate. Checking the process rather than
the exit code is the difference between "we reloaded" and "it works".

The whole sequence is idempotent and resumable (§6.7). On agent start, any
staged file left from an interrupted apply is discarded, and the live
configuration is validated; if it fails, the last known-good snapshot is
restored and the event is reported loudly rather than fixed silently.

### Nginx

Left as a documented seam. The escaper set and the state machine are
server-agnostic; only the templates and the validator invocation differ. Per
§5.2, no abstraction is being built for it now — the seam is that the
apply sequence takes the validator command as a parameter.

## Consequences

**Makes easy.** Reasoning about the injection surface, because interpolation
sites are enumerable and each names its escaper. Recovering from a bad config,
because a known-good snapshot always exists.

**Makes hard.** Every new configurable feature — redirects, headers, basic auth,
proxy settings — needs its escaper chosen deliberately and its fuzz corpus
extended. That is the intended friction.

**What we live with.** Validating in a full config context means a broken vhost
for site A blocks a deploy for site B on the same host until it is fixed. That
is correct behaviour — the alternative is reloading a config that fails — but it
is a cross-site coupling that must be explained clearly when it happens, naming
the offending site.

**New attack surface.** The staged file lives briefly in the web server's
configuration directory. It is written by `privd` with root ownership and
restrictive mode, and discarded on startup if orphaned, so it is not a window
for another process to substitute content.
