# 0004 — Host privilege separation

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-013

## Context

C1 requires that the control plane never need root SSH, and that privileged
operations pass through "a narrow, enumerated set of allowed actions with typed
arguments". ADR 0002 delivers that for the *control plane to agent* direction.

This ADR answers a question the brief leaves implicit and which decides how much
C1 is actually worth: **what privilege does the agent itself hold?**

If the agent runs as root, then C1 holds against a compromised control plane but
collapses against a compromised agent — and the agent is the component that
parses untrusted-ish input, runs on every host, and executes user build output
nearby. Coolify's failure was that one bug reached root. An agent running as
root reproduces that shape one layer down.

## Options considered

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| Agent runs as root | Simplest; every operation just works | A single agent bug is root on the host | Reproduces the failure C1 exists to prevent. Rejected. |
| Agent unprivileged, `sudo` with wildcard rules | Easy to write | Wildcards in sudoers are a well-known escape (`systemctl restart *` reaches arbitrary units; path wildcards reach arbitrary files) | Rejected. §6.4 already forbids `ALL=(ALL) NOPASSWD:ALL`, and wildcards are the same hole with extra steps. |
| Agent unprivileged, `sudo` with fully-enumerated no-argument rules | No wildcards | Every operation needs a distinct wrapper script; sudoers becomes large and generated; argument validation lives in shell | Workable but pushes validation into the weakest available language. Rejected. |
| Agent unprivileged, separate root helper over a unix socket | Real trust boundary inside the host; validation in Go; caller identified by kernel-provided peer credentials; no sudo at all | Two binaries, two units, a protocol between them | **Chosen.** |

## Decision

Two components on every managed host, with a trust boundary between them.

**`ratline-agent`** runs as the unprivileged `ratline-agent` user. It holds the
outbound connection, verifies envelopes (ADR 0002), collects inventory, manages
files inside site directories it owns, and streams logs. It performs everything
it can without privilege — which is most of the work.

**`ratline-privd`** runs as root, socket-activated, with no network access at
all. It accepts only the enumerated privileged operations:

- create or remove a site's Linux user
- install a validated systemd unit and reload the manager
- install a validated web server configuration and reload it
- install a `sudoers.d` fragment, after `visudo -c` passes
- install a certificate and key with correct ownership and mode
- install a package from the distribution's repositories
- start, stop or restart a *named-by-identifier* service in the Ratline namespace

`privd` identifies its caller by `SO_PEERCRED` rather than trusting the socket's
mode alone, and **re-validates every argument independently of the agent.** This
is the crux: `privd` does not trust `ratline-agent`. Site slugs are re-checked
against the strict pattern, paths are re-resolved and re-confirmed to be inside
the site root, unit and configuration files are re-parsed and re-validated
before install, service identifiers are checked against the Ratline naming
convention so no unit outside it can be touched.

Duplicating validation on both sides is deliberate. If it lived only in the
agent, `privd` would be a confused deputy and the boundary would be decorative.

`privd` writes every operation to a local append-only log **before** performing
it, owned by root and not writable by the agent user. That log is shipped to the
control plane audit trail and survives agent compromise — so an attacker who
owns the agent cannot erase the record of what they asked for.

## Consequences

**Makes easy.** Stating the blast radius of an agent compromise precisely, and
testing it: RL-M2-008's acceptance is that a compromised agent cannot obtain
arbitrary root through the helper.

**Makes hard.** Every privileged capability is now two implementations and two
validators. New host features cost more. Accepted — this is the property that
makes C1 mean something rather than being a statement about SSH configuration.

**What we live with.** A validation divergence between agent and `privd` shows
up as a confusing runtime failure rather than a security hole, which is the
right direction to fail but is a real support cost. Mitigation: the validators
are generated from the same operation schema, so divergence requires editing
generated code.

**New attack surface.**

- The `privd` unix socket. Reachable by the agent user by design. Its security
  rests on peer-credential checks and independent argument validation, both of
  which are directly testable.
- `privd` itself runs as root and parses input. It is deliberately small, has no
  network access, no dynamic configuration, and no shell invocation anywhere.

**What an attacker who fully owns `ratline-agent` gets.** Read and write inside
the site directories the agent manages; the ability to lie to the control plane
about this host; the ability to request catalogued privileged operations for
this host, which are legitimate operations with validated arguments (they can
create a site user, install a *validated* unit, restart a Ratline service). They
do **not** get: arbitrary root, the ability to touch units or files outside the
Ratline namespace, any reach to another host, the instruction signing key, or a
silent audit trail. Recorded in the threat model.
