# 0011 — Detecting public exposure without phoning home

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M1-023

## Context

C5 requires Ratline to "detect public reachability and show a loud,
non-dismissable warning". Roughly 52,000 Coolify instances were sitting on the
public internet in January 2026, so the requirement is well aimed.

The obvious implementation is an outbound probe: call a service that reports
back whether it can reach you. That reading conflicts with two other properties
of this product.

- **C5 itself implies the dashboard runs on isolated networks.** An operator on
  an air-gapped VPN gets a probe that times out. If a failed probe means "not
  exposed", the check is useless in exactly the deployment it is meant to
  protect; if it means "unknown", it will be ignored.
- **A self-hosted security tool that calls home is a different product.** An
  outbound beacon from every install is a telemetry channel, a correlation
  point, and a dependency on someone else's uptime. Operators who chose
  self-hosted infrastructure did so partly to avoid that.

So the question is not "how do we probe" but "what can be known locally, and how
honest can we be about the rest".

## Options considered

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| Outbound probe to a Ratline-run service | Directly answers the question for the common case | Phones home from every install; fails on isolated networks; new dependency and new privacy surface; a service that learns every install's address | Rejected. Creates a fleet-wide correlation point to protect a single install. |
| Outbound probe to a third-party "what is my IP" service | No service to run | Same phone-home problem, plus trusting an arbitrary third party with the fact that a Ratline install exists at an address | Rejected. |
| Local classification of the bind address and host interfaces | No network calls; works air-gapped; deterministic and testable | Cannot see NAT port-forwarding or an upstream reverse proxy | **Chosen**, with the blind spot stated rather than hidden. |
| Refuse any non-loopback bind outright | Simplest and safest | Breaks legitimate deployments — binding to a Tailscale or private LAN interface is the *recommended* setup | Rejected as unusable. |

## Decision

**Classify locally. Never make a network call to determine exposure.**

The check has three inputs, all available on the host:

1. The configured bind address, classified as loopback, wildcard, private
   (RFC1918), carrier-grade NAT (100.64/10, which is what Tailscale uses),
   link-local, unique-local, or globally routable.
2. When the bind is a wildcard, the addresses actually configured on the host's
   interfaces — because `0.0.0.0` is only as exposed as the interfaces beneath
   it.
3. Whether the operator has explicitly acknowledged a public bind.

That yields three exposure levels:

- **contained** — loopback only. The default, and the C5 baseline.
- **network** — reachable from the local network or a VPN interface. The
  recommended shape: bind to the Tailscale or WireGuard address.
- **exposed** — a globally routable address, or a wildcard on a host that has
  one. Warned about loudly and, for a wildcard, refused unless acknowledged.

**Binding to a wildcard or a globally routable address requires
`RATLINE_ALLOW_PUBLIC_BIND=1`.** Without it the process refuses to start and the
message names the VPN, Tailscale and allowlist alternatives. Binding to a
private or CGNAT address needs no acknowledgement, because that is the setup we
recommend.

**The blind spot is stated, not hidden.** Local classification cannot see a NAT
port-forward, a cloud load balancer, or a reverse proxy in front of the process.
A host bound to `127.0.0.1` with an nginx proxy in front is fully public and
this check reports "contained". Every report carries that caveat in the text, so
"contained" is never read as "verified private". Overstating certainty here
would be worse than the warning being absent, because an operator would stop
looking.

## Consequences

**Makes easy.** Working offline and air-gapped. Testing exposure logic
deterministically, with no network and no fixtures — the classifier is a pure
function over an address and an interface list.

**Makes hard.** Catching the reverse-proxy case, which is a real way to be
exposed. The mitigation is documentation and the caveat text, not detection.
Revisit if a cheap local signal turns up.

**What we live with.** An operator who fronts Ratline with a public reverse
proxy gets no warning from us. `docs/NETWORK.md` addresses this directly rather
than leaving it implied.

**New attack surface.** None. This decision *removes* a would-be outbound
connection and the service behind it. The acknowledgement variable is a new way
to reach a dangerous state, but it is opt-in, greppable in any config
management, and reported at every boot rather than remembered once.
