# 0009 — Where builds run

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-018

## Context

The brief does not say where a build executes, and the answer shapes the agent,
the release pipeline, the host stack and the security model. It has to be
decided before M3 rather than discovered during it.

Building on the host that serves production traffic means running user-authored
code, with an unbounded dependency tree, on the machine currently answering
requests. Building elsewhere means an artifact transfer story, a build fleet, and
a way to reproduce each site's runtime somewhere it does not normally exist.

Constraints that apply: no Docker or container workloads in v1 (§5.2); the
control plane never hosts customer workloads (§6.1); per-site pinned runtimes
already exist on the target host (§6.2).

## Options considered

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| Build on the target host, as the site user | No new infrastructure; the pinned runtime is already there; no artifact transfer; matches Forge, Moss and Coolify, so operator expectations are met | Build load competes with production traffic; user build code executes on a production machine | Acceptable **only** with per-site users plus systemd sandboxing plus resource limits. Those are already required by §6.2 for the app itself. |
| Build on the control plane | Central; one place to install toolchains | Directly violates §6.1 — the control plane would host customer workloads, and it holds the fleet's signing key. Catastrophic if a build escapes. | Rejected outright. |
| Dedicated build hosts | Isolates build load from production; a natural place to harden further | Requires a build fleet, runtime reproduction, artifact transfer and cache distribution; large addition to v1 | Better isolation, materially more work. Right answer later. |
| Build in a container on the target host | Strong isolation | §5.2 puts containers out of scope, and a Docker socket on every host is the Coolify escalation path C1 exists to avoid | Rejected. |

## Decision

**Build on the target host, as the site's own unprivileged Linux user, inside a
transient systemd scope with explicit resource limits.**

Concretely:

- The checkout and build happen in the site's build directory, owned by the site
  user, under the runtime version pinned for that site.
- The build runs in a transient scope carrying the same sandboxing as the site's
  service unit — `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp` — plus `MemoryMax`, `CPUQuota` and `TasksMax`.
- **Build limits default lower than the site's runtime limits**, so a runaway
  build degrades itself before it degrades the host. Defaults: `CPUQuota` at half
  the host's cores, `MemoryMax` at a quarter of host memory, both editable per
  site. The point is a bounded default, not a magic number.
- Per-host build concurrency is capped and configurable (RL-M3-023), so a burst
  of merges does not start twenty builds at once. Queued deploys show their
  position rather than appearing hung.
- Dependency caches are keyed by lockfile content and runtime version, owned by
  the site user, and never shared between sites. Cross-site cache poisoning is
  impossible by construction and tested (RL-M3-024).
- The build never runs as `ratline-agent` and never as root.

## Consequences

**Makes easy.** The v1 architecture: no build fleet, no artifact registry, no
transfer protocol, no runtime reproduction problem. Deploys are also faster,
because the artifact never crosses a network.

**Makes hard.** Isolating build load from production load. The limits bound it
but do not eliminate contention — page cache pressure and disk I/O are not
partitioned by `CPUQuota`. An operator running a heavy Next.js build on the same
host as a latency-sensitive production site will see it.

**What we live with.** Two real risks, both of which should be visible in the
interface rather than buried here:

1. **Contention.** Mitigated by limits and concurrency caps, not solved. The
   host detail screen should show build load distinctly from application load so
   the cause is obvious at 2am.
2. **Co-location.** A non-production site's build is user-authored code running
   one sandbox boundary away from a production site on the same host. The
   isolation is Linux users plus systemd sandboxing — real, but weaker than a
   namespace. **The interface should warn when production and non-production
   sites are placed on the same host**, and the documentation should recommend
   against it. This follows from ADR 0005 and is recorded in the threat model.

**The seam for moving builds later.** The build is expressed as operations in
the catalogue (`build.prepare`, `build.run`, `release.activate`) addressed to a
host identifier. Nothing in the control plane assumes the build host and the
serving host are the same machine. Introducing dedicated build hosts later means
addressing the build operations to a different host and adding an artifact
transfer operation — not restructuring the pipeline. No abstraction is being
built for this now, per §5.2; the seam is that the host identifier is already a
parameter.

**New attack surface.** Production hosts execute user-authored code as a side
effect of deploying. This was already true of the deployed application itself;
the build widens the window and the dependency surface. The containment story is
ADR 0005's, and the escape test (RL-M3-006) is the evidence.
