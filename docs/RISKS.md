# Ratline — open risks

**Task:** RL-M0-023
**Reviewed at every milestone gate.**

Blocked tasks are appended automatically by `./scripts/tasks block` (brief §2.3).
Risks below R-01..R-09 were identified during planning and carry an owner.

**Owner "human"** means it needs a decision or a resource the agent cannot
create. Those are repeated in the gate report under "What I need from you".

---

## R-01 — No integration test host — **CLOSED 2026-08-03**

- **Owner:** human. The resource was supplied (Docker); the verification was
  the agent's to do, and is done.
- **Closed on evidence, not on the offer.** `./scripts/host start && verify`
  brings up a Debian 12.15 container and asserts the three things this risk was
  actually about:
  - SSH accepts `deployer`, uid 1000, non-root, with working `sudo -n`. That is
    the account RL-M2-010 bootstraps through and what C1 is asserted against.
  - `systemctl is-system-running` returns **running**, not degraded, with
    systemd 252 as PID 1 and five active socket units. RL-M2-008's socket
    activation, RL-M2-015's unattended upgrades and RL-M2-016's service
    management all have somewhere real to run.
  - **Root SSH is refused** — `Permission denied (publickey)` — by the image's
    default rather than by a test arranging it. RL-M2-029 asserts it stays true.
- **The systemd caveat is answered rather than outstanding.** It needed
  `--privileged` and a writable cgroup mount, which `scripts/host` supplies. No
  VM is required.
- **Two things this cost, both recorded because they are the argument for §6.7.**
  Debian ships an `operator` GROUP at gid 37, so `useradd operator` fails with
  exit 9 and the obvious fix would have put the bootstrap account into a system
  group it has no business in. And `/sbin/init` belongs to `systemd-sysv`, so a
  container with `systemd` alone cannot start it. Neither would have surfaced
  against a mock.
- **One vacuous pass caught in the verifier itself:** it first reported
  "root ssh: refused (C1 holds)" on a machine with no key file — passing because
  it could not connect. It now refuses to conclude anything until the deployer
  connection works.

## R-01 (original entry) — No integration test host — **blocks the M2 gate**

- **Owner:** human
- **Likelihood:** certain — it is already true
- **Impact:** high. M2's exit criteria cannot be demonstrated.
- **Detail:** §6.7 forbids mocking anything that touches a host, and M2 must
  prove a clean Debian 12 host provisions idempotently with zero root SSH. The
  development machine has Docker but no VM tooling (no Lima, multipass or UTM)
  and no Go toolchain. A container cannot faithfully exercise
  `ProtectSystem=strict`, `PrivateTmp`, cgroup limits or `sshd` behaviour, which
  is precisely what M2 and M4 depend on.
- **Mitigation:** needs one of — cloud API credentials for ephemeral VMs
  (Hetzner is cheapest for this shape), permission to install a local VM tool, or
  a persistent test host. Raised at the M0 gate. `RL-M2-024` is owned by human
  and blocks `RL-M2-025`, `RL-M2-026` and `RL-M2-029`.
- **Do not work around this.** §2.10 forbids fabricating a substitute for a
  missing host.

## R-02 — C2 versus user-authored build commands

- **Owner:** human
- **Likelihood:** certain — the conflict exists in the brief as written
- **Impact:** high. Determines whether sites have editable build commands.
- **Detail:** C2 forbids shell construction from user-derived data. §6.5
  requires configurable build and install commands, which are shell strings by
  nature. ADR 0005 proposes containment — materialise the command as a file,
  execute by argv, run as the site user in a resource-limited sandbox, make
  setting it a distinct permission.
- **Mitigation:** explicit ruling at the M0 gate. If the strict reading is
  intended, `RL-M3-004` becomes fixed per-framework pipelines and the product is
  materially smaller.

## R-03 — Front-end framework chosen without knowing the team — CLOSED

- **Owner:** human
- **Status:** **closed 2026-08-02. React.**
- **Detail:** ADR 0001 recommended SvelteKit on runtime size and reactivity
  grounds, but the brief offers React too and the team's daily language beats
  both arguments. It does: a framework nobody reaches for fluently is paid for
  on every screen for the life of the product, while the runtime-size cost is
  paid once per page load.
- **Outcome:** ruled before `RL-M1-028` started, which is what the mitigation
  asked for. ADR 0001 revised to record the ruling and keep the original
  recommendation visible. The residual — a larger bundle on a box the operator
  pays for — is carried as a requirement to server-render the M1 screens where
  possible and to measure the log stream and the tension line, the two surfaces
  the SvelteKit argument was built around.

## R-04 — Timing may distinguish nonexistent from unauthorized

- **Owner:** agent
- **Likelihood:** medium
- **Impact:** low-medium. Leaks existence, not contents.
- **Detail:** §6.3 requires the two to be indistinguishable. `RL-M1-026` tests
  status and body byte-for-byte, but a nonexistent identifier may short-circuit
  earlier than a foreign one.
- **Mitigation:** documented as residual (threat model R-04). Revisit at the M5
  gate; equalising response timing is a real cost and should be a deliberate
  decision rather than an assumption.

## R-05 — Production and non-production co-located on one host

- **Owner:** agent, then human for the policy call
- **Likelihood:** high — operators will do this
- **Impact:** high. It is the sharpest finding in the threat model.
- **Detail:** a Developer with `site.build_command.write` on a non-production
  site gets code execution as that site's Linux user. If a production site runs
  on the same host, that is one sandbox escape from production data. Isolation
  is Linux users plus systemd, not a namespace, because containers are out of
  scope (§5.2).
- **Mitigation:** warn in the interface when the two are placed together;
  recommend against it in documentation; adversarial escape test (`RL-M3-006`).
  Not eliminable within v1 scope.

## R-06 — Offline hosts survive SSH authority rotation

- **Owner:** agent
- **Likelihood:** medium
- **Impact:** high if the authority is ever compromised
- **Detail:** a host unreachable during rotation still trusts the old authority.
- **Mitigation:** the rotation procedure must report unreachable hosts loudly
  and refuse to declare success. Covered by `RL-M6-001`.

## R-07 — A compromised agent's false reporting is undetected

- **Owner:** agent
- **Likelihood:** low
- **Impact:** medium
- **Detail:** nothing cross-checks an agent's claims about its own host, so a
  compromised agent could report plausible-but-false inventory and health.
- **Mitigation:** none in v1. `privd`'s independent root-owned audit log gives a
  partial cross-check for privileged operations. Revisit at the M2 gate.

## R-08 — All three crown-jewel keys live on one machine

- **Owner:** human
- **Likelihood:** n/a — a structural property
- **Impact:** high. Control plane compromise reaches all of them.
- **Detail:** SSH authority, instruction signing and secret wrapping keys all sit
  on the control plane. The external key manager is a seam, not v1 scope.
- **Mitigation candidate, not yet scoped:** require second-human approval for
  the highest-risk operations — adding a host, installing a sudoers fragment,
  authority operations. Raised at the M0 gate as a scope question.

## R-09 — Build contention is bounded, not eliminated

- **Owner:** agent
- **Likelihood:** medium
- **Impact:** medium
- **Detail:** `CPUQuota` and `MemoryMax` bound a build, but page cache pressure
  and disk I/O are not partitioned. A heavy build will be visible on a
  latency-sensitive site sharing the host.
- **Mitigation:** lower default build limits than runtime limits, per-host
  concurrency caps, and build load shown separately from application load on the
  host detail screen (ADR 0009).

## R-11 — Exposure behind a reverse proxy is undetectable

- **Owner:** agent
- **Likelihood:** medium — fronting the dashboard with nginx or Caddy is a
  common instinct
- **Impact:** high. The dashboard would be internet-reachable while Ratline
  reports `contained`.
- **Detail:** the C5 check classifies the bind address and this host's
  interfaces locally. A process bound to `127.0.0.1` behind a public reverse
  proxy — including one on the same host — is fully exposed and cannot be
  distinguished from a genuinely contained one without an outbound probe.
- **Why not solved:** ADR 0011. An outbound probe would phone home from every
  install, create a fleet-wide correlation point, and fail on exactly the
  isolated networks C5 is written to protect.
- **Mitigation:** every exposure report carries the caveat in its text, so
  `contained` is never presented as `verified private`, and `docs/NETWORK.md`
  addresses the proxy case directly. Revisit if a cheap local signal turns up —
  reading the host's listening sockets for a proxy on 80/443 is a candidate, but
  it guesses at intent and would produce false positives on any host that also
  serves sites, which is most of them.

## R-14 — Managed databases change the product's failure story

- **Owner:** human
- **Likelihood:** certain, if M7 proceeds
- **Impact:** high — the highest in the register
- **Detail:** every workload Ratline manages today is reconstructible. A site
  comes back from git; that is what makes atomic releases safe, what makes a
  failed deploy a non-event, and what lets "provision twice" be an acceptance
  criterion. A database does not come back. Adding managed databases moves the
  product from "if it breaks, redeploy" to "if it breaks, the company may have
  lost its data", and several accepted decisions were taken under the old
  assumption — ADR 0009 (build on the target host) and ADR 0005 (build commands
  contained, not eliminated) both put user-authored code next to the data.
- **Mitigation:** M7 is ordered so backup and verified restore land BEFORE
  create and delete are exposed (RL-M7-005, RL-M7-006), and RL-M7-001 re-examines
  the earlier decisions rather than assuming they carry over. Host roles
  (RL-M7-002) keep sites off data hosts by default.
- **Needs a decision:** whether M7 is v1 scope, which would amend brief §5.2, or
  follows v1. Planned as the latter. See ADR 0013.

## R-10 — No remote repository yet — **CLOSED 2026-08-04**

- **Owner:** human. Resource supplied; verification was the agent's.
- **Closed on evidence:** `origin` exists, PR #2 is open against `main`, and CI
  run 30845551913 is green on all four jobs for commit `18cca24`. The `status`
  job wrote `ci-status.json`, so `tasks done` closes on a real pipeline — which
  RL-M1-002 is the first task in this project to have done.
- **It cost five runs and every failure was a real defect**, which is the return
  on the acceptance saying "run clean in CI" rather than "runs clean locally".
  See RL-M1-002's notes for the sequence.

## R-10 (original entry) — No remote repository yet

- **Owner:** human
- **Likelihood:** certain
- **Impact:** low, rising at M1
- **Detail:** the repository is local only. The CI workflow is written but has
  never run, so the metrics and CI-status files `STATUS.md` reads do not exist
  and the `tasks done` CI gate has to be bypassed with a recorded reason.
- **Mitigation:** create the GitHub organization (`ratline-dev` or `getratline`
  per §1) and push. Until then, M0 tasks are closed with `--no-ci` and the reason
  is recorded in each task's notes.
