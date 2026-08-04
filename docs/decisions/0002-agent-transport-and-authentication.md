# 0002 — Agent transport and authentication

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-011

## Context

C1 says the control plane must never require root SSH to a managed host, because
Coolify's CVSS 10.0 class came from an SSH account that had to be root or in the
`docker` group — every command-injection bug became host compromise. The
structural fix is not "be careful with SSH"; it is to remove the ability to
express an arbitrary command at all.

Three questions have to be answered separately, and conflating them is how this
goes wrong:

1. **Who dials whom?** Determines whether managed hosts need inbound ports.
2. **How is the channel authenticated?** Determines who can talk at all.
3. **How is the instruction authenticated?** Determines who can command.

The brief's own example blocker (§2.5) frames this as "mTLS or signed envelopes
over SSH". That is a false choice: those answer different questions.

## Options considered

### Dial direction

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| Control plane dials agent | Simple request/response; no long-lived connection | Every managed host opens an inbound port; needs firewall rules and a reachable address; breaks behind NAT | Worst option. Adds a listening service to every host in the fleet — a new pre-auth attack surface multiplied by fleet size. |
| Agent dials control plane | No inbound port on any host; works behind NAT; survives dynamic addressing | Requires connection management, backoff, and a control plane reachable from hosts | **Best.** The managed fleet exposes nothing new. Compromising a host still requires an existing service. |
| Poll over HTTPS | Trivially simple | Latency/throughput tradeoff is bad for log streaming | Equivalent to dialling out, but worse for the signature screen. |

### Channel authentication

| Option | Assessment |
| --- | --- |
| Bearer token per host | One leaked token, from a log or a backup, is indistinguishable from the host. No cryptographic binding. Rejected. |
| mTLS with per-host client certificates | Mutual authentication, individually revocable, key never transmitted. **Chosen.** |
| SSH transport, reusing sshd | Reuses an audited transport, but keeps SSH keys in the control plane and keeps a raw-SSH code path warm — the exact thing C1 wants to shrink. Rejected. |

### Instruction authentication

| Option | Assessment |
| --- | --- |
| Trust the channel — anything arriving over mTLS is legitimate | Means a TLS terminator, a reverse proxy, or a compromised control-plane *process* can command the fleet. Single layer. Rejected. |
| Signed, typed envelopes over the channel | Instruction authenticity is independent of transport. A stolen agent certificate lets an attacker *impersonate a host*, but not *command* one. **Chosen.** |
| Arbitrary commands, signed | Signing an arbitrary shell string authenticates the sender and changes nothing about C1. Rejected outright — this is the failure being designed against. |

## Decision

**Agent-initiated mTLS, carrying independently signed instruction envelopes over
an enumerated operation catalogue.** SSH is used exactly once, for bootstrap.

**Transport.** The agent dials the control plane over HTTP/2 with TLS. The server
is authenticated by its certificate as usual; the AGENT proves who it is with an
Ed25519 signature over a challenge the control plane issued, not with a client
certificate. Each host holds its own signing key, registered at enrolment via a
single-use short-lived token, and individually revocable. No managed host listens
on a Ratline port; an integration test asserts this after provisioning.

> **Amended 2026-08-04 (A-04), still `proposed`.** This paragraph originally
> specified a per-host X.509 **client certificate** over mutual TLS. That could not
> be built: Node's `crypto` can verify X.509 and cannot mint it, so issuing
> certificates needed either a subprocess — which ADR 0005 and C2 forbid the control
> plane entirely, enforced by a lint rule, because that is what makes command
> injection structurally impossible rather than merely unlikely — or a dependency,
> and the available one pulls a dependency-injection container and requires a global
> prototype-patching polyfill into the supply chain of the key that authorises every
> instruction to every host.
>
> The owner ruled for the challenge instead. It is mintable entirely in the standard
> library, and the agent already verifies Ed25519 for envelopes, so no new primitive
> enters the system.
>
> **The cost, so it is not discovered later:** standard mTLS tooling no longer
> applies. A terminating reverse proxy that authenticates clients by certificate
> cannot authenticate a Ratline agent, and neither can anything else expecting the
> identity to be in the TLS handshake. The proof moves up a layer, so Ratline's own
> code has to get it right.
>
> **Two properties the certificate version got for free and this must supply
> explicitly.** A challenge signature must be bound to the connection that requested
> it, or a signature captured once is replayable on another connection — so the
> challenge is issued per connection, held server-side, and single-use. And it must
> carry a domain separator distinct from the instruction envelope's, or a host's
> signed challenge and a signed instruction could be confused for one another by the
> same key. Both are asserted by `test/security/host_identity.test.ts`.

**Instructions.** Every instruction is an envelope:

```
{ operation, arguments, nonce, issued_at, expires_at, target_host_id }
```

signed with the control plane's Ed25519 instruction key, which is stored
separately from the database. The agent verifies, in this order, **before
interpreting any argument**: signature; that `target_host_id` is its own; that
`expires_at` has not passed; that `nonce` is unseen. Then it looks the operation
up in the catalogue and type-checks the arguments. An operation not in the
catalogue is refused — there is no default branch, and no operation accepts a
free-form command.

**Nonces** persist across agent restarts for at least the validity window, in a
bounded store. Replay after restart is tested explicitly.

**Signing key rotation** uses an overlap window: agents accept both the outgoing
and incoming key for a configured period, so rotation never requires a
flag-day.

**Responses and streams.** Results are signed by the agent so the control plane
can attribute them. Log chunks are *not* individually signed — they are data,
not instructions — but they are bound to a job identifier and rate limited.

**Bootstrap.** The only raw SSH the panel performs is installing the agent,
using an operator-supplied key for that single action, which is not retained.
The binary is checksum and signature verified before execution, and every
command in that path is an argument vector with no shell. After bootstrap, an
automated check asserts the control plane holds no credential granting root SSH
to that host.

## Consequences

**Makes easy.** Adding a host behind NAT or a dynamic address. Revoking one host
without touching the others. Reasoning about what the fleet can be told to do —
the answer is a finite list you can read.

**Makes hard.** Every new host capability requires a catalogue entry, generated
types on both sides, argument validators, and fuzz coverage. That friction is
the feature; it is what stops `site.create` growing a `preCommand` field one
afternoon.

**What we live with.** The control plane must be reachable from every managed
host. Combined with C5 (dashboard not internet-exposed), that means the *agent*
endpoint and the *dashboard* are separate listeners with separate exposure
policies: the agent endpoint may face the internet with mTLS required, while the
dashboard binds to loopback. This is a deployment subtlety operators will get
wrong if we do not make it the default shape, and it must be explicit in the
install documentation.

**New attack surface.**

- A public agent endpoint. Pre-authentication surface is the TLS handshake with
  a required client certificate; unauthenticated requests are rejected before any
  application code runs.
- The instruction signing key becomes the fleet's crown jewel alongside the SSH
  CA key. Holding it means being able to issue any *catalogued* operation to any
  host — which is unprivileged code execution fleet-wide, not root. Storage,
  rotation and compromise recovery are in the threat model.
- A stolen agent client certificate buys impersonation of one host: the attacker
  can lie about that host's inventory and health, and receive instructions and
  secrets destined for the sites on it. It buys no ability to command any host,
  including itself, because it holds no signing key.
