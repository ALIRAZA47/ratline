<!--
  Committed verbatim as supplied. Amended only by the project owner.
  This comment is the only addition; it renders as nothing.
  Do not edit the text below. Propose changes in chat or via an ADR.
-->
# Ratline — Engineering Brief & Agent Operating Manual
**Project:** Ratline — self-hosted deployment and server management platform
**Document status:** authoritative brief. Supersedes any earlier version.
**Read this whole document before doing anything. Then read the Session Protocol again.**
---
## 0. How to use this document
This is not a one-shot prompt. It is a standing brief for a long-running engineering engagement executed in milestones, with the human reviewing at every gate.
Your obligations, in priority order:
1. **Track your work in the repo, not in your head.** Everything you learn, decide, defer or break goes into the tracking artifacts described in §2. A future session — possibly with no memory of this one — must be able to pick up from those files alone.
2. **Stop at every milestone gate** and produce the status report in §2.7. Do not begin the next milestone without explicit approval.
3. **Never violate a hard constraint in §4.** If a constraint blocks you, stop and escalate; do not work around it.
4. **Ask when the brief is wrong.** I would rather revise this document than have you build around a bad requirement. Proposing a change to the brief is always in scope.
### 0.1 First action
Do not scaffold. Do not install anything. Your first deliverable is **M0 — the plan** (§8), which includes standing up the tracking system in §2 with a fully populated backlog. Produce it, then stop.
---
## 1. Project identity
| | |
|---|---|
| Name | Ratline |
| CLI binary | `ratline`, with `rl` as an installed alias |
| npm package | `ratline` (control plane CLI), `@ratline/agent` if a JS agent is ever needed |
| Agent binary | `ratline-agent` |
| Suggested GitHub org | `ratline-dev` or `getratline` — the bare handle is taken |
| Config directory on hosts | `/etc/ratline`, state in `/var/lib/ratline`, logs in `/var/log/ratline` |
| Site root convention | `/srv/sites/<site-slug>/{releases,shared,current}` |
| Linux user convention | `rl-<site-slug>` |
| systemd unit convention | `ratline-<site-slug>.service` |
Naming rationale: a ratline is the rope ladder lashed across a ship's shrouds that crew climb to reach the rigging. The product is the ladder to your infrastructure. Note that the word also names WWII escape routes — do not use nautical-escape imagery in marketing copy, and keep the visual language on rigging and rope work.
---
## 2. Work tracking system — build this in M0, before anything else
This section is the reason this document exists in its expanded form. Treat the tracking artifacts as production code: they are reviewed, they are kept accurate, and a milestone with a stale tracker is not done.
### 2.1 Repository layout for tracking

```
docs/
  BRIEF.md              # this document, committed verbatim; amended only by me
  STATUS.md             # generated dashboard — never hand-edit
  PROGRESS.md           # append-only session log, newest entry at top
  tasks.yaml            # source of truth for all work items
  RISKS.md              # open risks with owner, likelihood, mitigation
  THREAT-MODEL.md       # updated at every milestone
  GLOSSARY.md           # domain terms, so vocabulary stays consistent in code and UI
  decisions/
    0001-stack-choice.md
    0002-agent-transport.md
    ...
scripts/
  tasks.ts              # CLI: list, add, start, block, done, validate, render
```

### 2.2 `tasks.yaml` schema
Source of truth. Every unit of work exists here before it is worked on.

```yaml
- id: RL-M2-014
  title: Generate and validate Caddy vhost from site config
  milestone: M2
  status: in-progress        # todo | ready | in-progress | blocked | review | done | dropped
  owner: agent               # agent | human
  estimate: M                # S (<1h) | M (half day) | L (1-2 days) | XL — split it
  depends_on: [RL-M2-009, RL-M2-011]
  blocks: [RL-M3-002]
  risk: high                 # low | medium | high — high means security-relevant
  acceptance:
    - Template renders with all values escaped, verified by a fuzz test over site names
    - `caddy validate` runs before reload and a failure aborts without touching live config
    - Rollback to previous config verified in integration test
  artifacts:
    - src/agent/webserver/caddy.go
    - test/integration/caddy_vhost_test.go
  decisions: [0004]
  notes: |
    2026-08-01 — Chose text/template with a custom escaper over string concat. See ADR 0004.
```

Rules:
- IDs are immutable and never reused: `RL-<milestone>-<3-digit sequence>`.
- A task cannot enter `in-progress` unless every `depends_on` is `done` and it has at least one `acceptance` line. That is the Definition of Ready.
- `XL` is not a valid resting state. Split it before starting.
- Any task touching authorization, secrets, remote execution or TLS is `risk: high` and requires a matching entry in the security test suite before it can go to `done`.
- Dropped tasks are never deleted. Set `status: dropped` and add a note explaining why.
### 2.3 `scripts/tasks.ts`
A small CLI so tracking is mechanical rather than a chore:
- `tasks list --milestone M2 --status in-progress`
- `tasks start RL-M2-014` — validates Definition of Ready, sets status, stamps time
- `tasks block RL-M2-014 --reason "..."` — also appends to RISKS.md if blocked more than one session
- `tasks done RL-M2-014` — refuses unless every acceptance line is checked off and CI is green
- `tasks validate` — schema check, cycle detection in `depends_on`, orphan detection. **Runs in CI. A malformed tracker fails the build.**
- `tasks render` — regenerates `STATUS.md`
### 2.4 `STATUS.md` — generated dashboard
Regenerated at the end of every session. Contains:
- Milestone progress bars: done / total tasks per milestone
- Current milestone, its exit criteria, and which are met
- Everything `in-progress` and `blocked`, with age in days
- Open high-risk tasks not yet covered by a security test
- Test health: unit pass rate, integration pass rate, authorization matrix cells passing / total, coverage on `src/authz/**` (must be 100%)
- Count of open critical and high findings from the security suite — **this number must be zero at every gate**
### 2.5 `PROGRESS.md` — session log
Append a new entry at the top at the end of every working session. Never edit past entries.

```markdown
## 2026-08-01 — Session 7 — M2
**Goal:** Agent bootstrap over SSH, host inventory reporting.
**Completed:** RL-M2-009, RL-M2-011, RL-M2-012
**In progress:** RL-M2-014 (Caddy vhost templating — escaper written, fuzz test failing on unicode site names)
**Blocked:** RL-M2-017 — needs a decision on whether agent auth uses mTLS or signed envelopes over SSH. Raised as ADR 0002, awaiting review.
**Decisions made:** ADR 0004 (template-based config generation).
**Surprises / what I learned:** systemd `ProtectSystem=strict` breaks Bun's default temp directory handling; needs an explicit `PrivateTmp` plus `BUN_TMPDIR`. Captured as RL-M4-006.
**Deviations from brief:** none.
**Next session should start with:** finishing the unicode escaping fuzz test, then RL-M2-015.
```

### 2.6 Architecture Decision Records
Any choice that would be expensive to reverse gets an ADR in `docs/decisions/`, numbered sequentially:

```markdown
# 0002 — Agent transport and authentication
**Status:** proposed | accepted | superseded by NNNN
**Date:** 2026-08-01
**Task:** RL-M2-017
## Context
What forced the decision. Include the constraints from the brief that apply.
## Options considered
Each with pros, cons, and a one-line security assessment.
## Decision
What we chose and why.
## Consequences
What this makes easy, what it makes hard, what we now have to live with.
Include the new attack surface introduced, if any.
```

ADRs are proposed by you and accepted by me. Do not mark one `accepted` yourself.
### 2.7 Milestone gate report
At every gate, produce exactly this, in chat, and commit a copy to `docs/gates/M<n>.md`:

```markdown
# Gate report — M2
## Exit criteria
- [x] Agent installs on a clean Debian 12 host in under 90 seconds
- [ ] Host inventory reports accurately after reboot — FAILING, see below
...
## What was built
Two paragraphs, plain language, no task IDs.
## What I chose to do differently from the brief, and why
...
## Known defects and deferred work
Task IDs with one-line descriptions and the milestone they were deferred to.
## Security posture
- New attack surface introduced this milestone
- Security tests added (count and what they cover)
- Open findings: N critical, N high, N medium
- Threat model diff since last gate
## Test health
Numbers from STATUS.md.
## What I need from you
Decisions, credentials, review of specific ADRs.
## Recommended next milestone scope adjustments
...
```

### 2.8 Commit and branch conventions
- Branch per task: `m2/RL-M2-014-caddy-vhost-templating`
- Commit subject: `RL-M2-014: generate caddy vhost from template with escaped values`
- Every commit references exactly one task ID. No mixed commits.
- Commit body includes `Acceptance:` lines checked off, and `Risk:` for high-risk tasks.
- Never commit directly to `main`. Never force-push a reviewed branch.
### 2.9 Session protocol
**At the start of every session, before writing any code:**
1. Read `docs/STATUS.md`, the top three entries of `docs/PROGRESS.md`, and `docs/tasks.yaml` filtered to `in-progress` and `blocked`.
2. Run `tasks validate` and the full test suite. Report anything already red before you touch it.
3. State, in two or three sentences, what you intend to accomplish this session and which task IDs you'll work.
**At the end of every session:**
1. Update `tasks.yaml` — statuses, notes, any new tasks discovered.
2. Append the `PROGRESS.md` entry.
3. Run `tasks render` to regenerate `STATUS.md`.
4. Commit the tracking updates as their own commit: `chore(tracking): session 7`.
5. Give me a three-line summary: what moved, what's blocked, what's next.
### 2.10 Stop conditions
Stop and ask me rather than proceeding, whenever:
- A hard constraint from §4 appears to conflict with a requirement elsewhere in this brief.
- You are about to introduce a dependency that runs as root, holds a Docker socket, or executes shell strings.
- A task has been `blocked` for two consecutive sessions.
- You discover a security issue in something already built and merged.
- Implementing something as specified would take more than roughly twice your estimate — the spec is probably wrong.
- You need a credential, a live host, a domain, or anything else you cannot create yourself.
Never fabricate a workaround for a missing credential or host. Say what you need.
---
## 3. Product definition
### 3.1 One sentence
Ratline is a single control plane that connects to VPS hosts I already own, provisions a hardened web stack on them, and gives my team a clean UI to deploy static sites, Node.js apps and Bun apps from Git — with role-based access control that actually holds up, and managed SSH access to the underlying boxes.
### 3.2 Positioning
Think Laravel Forge, Moss.sh and CloudPanel for provisioning and hosting, and Coolify or Dokploy for push-to-deploy. Ratline's two differentiators are a serious authorization model and a privilege architecture that does not hand the panel root on every host. Everything else is table stakes executed well.
### 3.3 Who it's for
Small engineering teams of two to twenty, running their own infrastructure on Hetzner, DigitalOcean, Vultr or bare metal. Competent with Linux, but unwilling to hand-write Nginx vhosts and systemd units per project. They run internal tools, marketing sites and production apps on the same fleet, so isolation and permissions matter far more than in a single-developer setup.
The design tiebreaker: **when in doubt, favour the team of eight with a production incident at 2am over the solo developer deploying a side project.** Density, auditability and blast-radius control beat onboarding smoothness.
### 3.4 Explicit non-goals
Not a PaaS. Not a hosting business. No multi-tenancy across untrusted customers — tenants are teams inside one organization that broadly trust each other but should not have unnecessary access. No Kubernetes. No attempt to abstract away Linux; a competent operator should always be able to SSH in and recognise what Ratline did.
---
## 4. Hard constraints
These derive from studying how the incumbents fail. They are requirements, not preferences. Violating one is grounds for rejecting the work regardless of how well it functions.
**C1 — The control plane must never require root SSH to managed hosts.**
Coolify's 2025–26 vulnerability class reached CVSS 10.0 specifically because its SSH account must be root or in the `docker` group, so every command-injection bug became instant host compromise plus container escape. Day-to-day operations run unprivileged. Privileged operations pass through a narrow, enumerated set of allowed actions with typed arguments.
**C2 — No shell command is ever constructed by string interpolation.**
All remote execution uses argv arrays with explicit arguments. No `sh -c` with any user-derived data, anywhere. Add a lint rule and a CI check that fails the build on template-literal shell construction, and a fuzz test that pushes shell metacharacters through every user-controllable field that can reach a host.
**C3 — Authorization is enforced at the data-access layer, not the route layer.**
Every query for a server, project, site, deployment, secret, log or grant is tenant-scoped inside the repository function. A handler that forgets its check must still return nothing. This is the IDOR class that let Coolify users reach other teams' servers. There is no unscoped `findById` in the codebase; make the unscoped variant impossible to call rather than merely discouraged.
**C4 — No default secrets.**
No default signing key, cookie secret, encryption key or admin password. First run generates them and the application refuses to boot without them. CloudPanel's CVE-2023-35885 was exactly this: a file manager reachable by forging a cookie signed with the shipped default key, exploited in the wild.
**C5 — The dashboard assumes it is not internet-exposed.**
Bind to localhost by default. Ship documented VPN, Tailscale and IP-allowlist setup. Detect public reachability and show a loud, non-dismissable warning. Roughly 52,000 Coolify instances were sitting on the public internet in January 2026; do not make that the path of least resistance.
**C6 — Every privileged action is auditable and attributable.**
No action taken by "the system" without a recorded actor. Automation acts as a named service identity with its own permissions.
---
## 5. Scope
### 5.1 Phase 1 — in scope
- **Static sites:** plain HTML/CSS/JS, plus build-step SPAs and SSGs — Vite, Astro, Next static export, SvelteKit static adapter, Nuxt generate, Eleventy, Hugo.
- **Node.js server apps:** Next.js, Nuxt, Remix / React Router, NestJS, Express, Hono, Fastify.
- **Bun apps:** `Bun.serve`, Elysia, Hono on Bun, and Bun used purely as a build tool for any of the above.
- **Per-site pinned runtimes:** multiple Node and Bun versions coexisting on one host with no global installs.
### 5.2 Out of scope for v1
Design so these can be added later; do not build them now. Managed databases. Email hosting. Docker or container workloads. Python, PHP, Ruby runtimes. Multi-region. Template marketplace. Billing. A public API beyond what the UI itself consumes.
If you find yourself building an abstraction "so we can add databases later", stop. Leave a clean seam and an ADR, not an implementation.
---
## 6. Technical requirements
### 6.1 Architecture
Propose and justify your own in M0, starting from this shape:
- **Control plane** — web app, API, job queue, Postgres. Runs anywhere including a laptop. Never hosts customer workloads itself.
- **Agent** — one static binary per managed host. Receives signed, typed instructions over a mutually authenticated channel. Executes only enumerated operations (`site.create`, `release.upload`, `service.reload`, `cert.renew`, …) with typed arguments. It does not accept arbitrary commands, and this is the property that satisfies C1.
- **Bootstrap over SSH** — the only raw SSH the panel performs is initial agent installation, using an operator-supplied key for that single action, ideally discarded afterwards.
Default stack suggestion, which you should challenge if you disagree: TypeScript end to end (SvelteKit or React front end, Hono or NestJS API), Postgres, a Redis-backed queue, agent in Go for a dependency-free static binary.
Required in M0 regardless of stack: a data model diagram, a trust-boundary diagram, and an explicit answer to "what can an attacker do with a compromised agent, a compromised control plane, and a compromised low-privilege user account?"
### 6.2 Host stack
- **Web server:** Caddy by default — automatic TLS and a far smaller config-injection surface. Nginx as an opt-in. Generate config from templates with escaped values, validate with the server's own config test, roll back on failure, never leave a host with config that fails validation.
- **Process supervision:** one systemd unit per app, one dedicated Linux user per site, no PM2. Use systemd sandboxing (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, read-only paths) and resource limits (`MemoryMax`, `CPUQuota`, `TasksMax`), all surfaced and editable in the UI.
- **Runtimes:** per-site pinned Node and Bun via `mise` or equivalent. Never a global install. Runtime upgrades are a deliberate, per-site, rollback-able action.
- **Releases:** atomic and Capistrano-style. Build into a timestamped release directory, health-check, swap the `current` symlink, reload. Keep N previous releases. Rollback is one click and completes in under a second.
- **Zero-downtime:** socket handoff or reload-then-drain, whichever the runtime supports. A deploy failing its health check must never take the running version down. This is a hard behavioural requirement with an integration test.
- **TLS:** Let's Encrypt via the web server, DNS-01 for wildcards, custom certificate upload, expiry alerting.
### 6.3 RBAC — the differentiator, build it properly
**Hierarchy:** Organization → Team → Project → Environment (production / staging / preview) → Resource (site, server, deployment, secret, domain, cron job, SSH grant).
Permissions granted at any level inherit downward. A grant on a project applies to all its environments unless a narrower deny exists. Denies always win.
**Default roles**, editable, with custom roles composable from the raw permission set:
| Role | Intent |
|---|---|
| Owner | Everything, including org deletion and ownership transfer. At least one must always exist; the system prevents removing the last. |
| Admin | Everything except org deletion and ownership transfer. |
| Infrastructure | Add/remove servers, manage host stack, firewall, SSH grants. Cannot read production secret values. |
| Release Manager | Deploy and roll back in production. Cannot change server config or read secret values. |
| Developer | Deploy to non-production, read logs, manage own SSH keys, read secret *names* but not values. |
| Viewer | Read-only on sites, deploy history, metrics. No raw logs, no secret values. |
| Billing | Billing only. No infrastructure visibility whatsoever. |
**Requirements:**
- One central `can(actor, action, resource, context)` decision function. No permission logic anywhere else. 100% branch coverage on this module, enforced in CI.
- Deny by default. An unmapped action is a denial. Adding a new action without adding it to the permission map fails a test.
- `secret.read_value` is separate from `secret.read_name`. Most roles need the latter and almost none need the former. This distinction shows up in the UI, the API and the audit log.
- Environment-scoped permissions are first-class. "Deploy to staging" and "deploy to production" are distinct actions, and granting one without the other is the single most common real-world request.
- Time-bound grants with expiry, for contractors and incident access. Expiry is enforced server-side, not by a cleanup job.
- Break-glass elevation: temporary Admin, requires a written reason, notifies every Owner immediately, auto-expires, and is loudly visible in the audit log and the UI banner for its duration.
- Append-only, hash-chained audit log. Every mutating authorization decision records actor, action, resource, decision, IP, timestamp and request ID. Chain verification is a scheduled job.
- API tokens carry a subset of the issuing user's permissions and never more. Scoped, expiring, revocable, with last-used tracking and an obvious revoke-all.
- SSO via OIDC/SAML and enforced 2FA as org-level policies.
- Role changes take effect immediately, including on active sessions and open web terminals.
**Acceptance gate:** an exhaustive authorization matrix test — every role × every endpoint × own-resource / other-team-resource / nonexistent-resource. Cross-tenant access is tested explicitly for every resource type, not assumed. The matrix is generated from the route table so a new endpoint without matrix coverage fails CI. Nonexistent and unauthorized must be indistinguishable in the response.
### 6.4 SSH access management
Managed SSH is part of the product, not a bolt-on.
- **Internal SSH certificate authority.** Users receive short-lived certificates, default eight hours and configurable, instead of `authorized_keys` entries. Revocation is then instant and real rather than a cleanup job that silently fails.
- **Principals map to grants.** A certificate carries principals derived from the user's roles, so host-side `AuthorizedPrincipalsFile` enforces the same model the UI shows. The UI and the host cannot disagree.
- **Per-site Linux users.** Shell access to one site lands the user as that site's user with no path to any other. Site directories are mode-restricted and per-user owned.
- **Scoped sudo.** Generated `sudoers.d` fragments allowing only the specific commands a role needs — restart *this* service, tail *this* log. Never `ALL=(ALL) NOPASSWD:ALL`. Fragments are validated with `visudo -c` before install.
- **Web terminal** subject to the same permissions, with full asciicast session recording retained and viewable from the audit log. Terminal access is its own permission, off by default for every role except Infrastructure.
- **Key hygiene.** Users upload their own public keys; the panel never handles a private key. Show fingerprint, age, last use. Support forced rotation and org-wide key policy (minimum algorithm strength).
- **CA key protection.** The CA private key is the crown jewel. Document its storage, rotation procedure, and what happens if it is compromised, in the threat model.
### 6.5 Feature checklist for v1
**Sites:** create from Git (GitHub, GitLab, Gitea, Bitbucket, plain SSH remotes), branch per environment, build command and output directory with sensible per-framework detection, install command, monorepo root directory, custom domains with DNS verification, redirects and headers, basic-auth protection for staging.
**Deployments:** push-to-deploy via signed webhooks, manual deploy, deploy a specific commit, per-server concurrency limits, live-streaming build logs, build artifact caching, one-click rollback, notifications (Slack, webhook, email), and per-PR preview environments if it doesn't blow the milestone.
**Secrets and config:** per-environment variables, envelope encryption at rest, write-only in the UI once set, automatic redaction anywhere a value could reach a build log or an error trace, `.env` import, change history that records who and when but never the value.
**Observability:** per-site CPU, memory and request metrics; host disk, load and memory with alert thresholds; structured log viewer with search and live tail; uptime checks with alerting; certificate expiry warnings.
**Operations:** per-site cron with output capture, permission-gated one-off command runner, backups of site files and configs to S3-compatible storage with restore exercised in CI, firewall management, fail2ban-equivalent policy, unattended security upgrades toggle, and self-update for both panel and agent with rollback.
### 6.6 UI direction
Do not produce a generic admin dashboard. Before building, write a short design plan — palette as four to six named hex values, a display / body / mono type pairing, a layout concept, and one signature element — then review it against this brief and revise anything that reads as a default rather than a choice. Commit it as `docs/DESIGN.md`.
- The audience lives in this tool during incidents. Density and scannability beat whitespace-heavy marketing polish, while still feeling considered.
- **The live deployment view is the signature screen.** Fast, legible log streaming with good monospace, correct ANSI handling, a sticky failed-step summary, and jump-to-error. Spend your boldness here.
- Status must be readable at a glance from across a room. Commit to a status colour language and use it identically everywhere.
- Full keyboard navigation, a ⌘K command palette covering every action, visible focus states, respected reduced-motion.
- Dark mode default, light mode fully supported.
- Copy: active voice, plain nouns from the operator's world, buttons named for what happens. Errors state what broke and what to do next. Empty states invite action rather than apologise.
- The rigging metaphor may inform the visual language — rope, tension, lashing, ladders — but subtly. No pirate imagery, no ship's wheels.
**Screen inventory:** onboarding and connect-first-server · server list · server detail · site list · site detail · new-site wizard · deployment history · live deployment · environment variables · domains and TLS · logs · metrics · cron · team and roles · role editor with live permission preview · SSH access grants · web terminal · audit log · settings.
The role editor deserves particular care: show, live, exactly what a role can and cannot do as the operator toggles permissions, including a "what would this person see?" preview.
### 6.7 Quality bar
- TypeScript strict, no `any` in application code. Go vet and staticcheck clean.
- Every remote operation idempotent and resumable. A network drop mid-deploy must never leave a half-configured host — this has an explicit chaos test that kills the connection at randomised points.
- Integration tests run against real ephemeral VMs or containers for the entire provisioning path. Mocks are not acceptable for anything that touches a host.
- Security suite covering, at minimum: command injection through every user-controllable field reaching an agent; path traversal in site paths and the file manager; cross-tenant access on every resource type; secret leakage into logs, error traces and metrics labels; rate limiting on all auth endpoints including password reset; session fixation; CSRF; and signed-webhook replay.
- Threat model in-repo, updated at every gate, with a diff shown in the gate report.
- Every dependency added requires a one-line justification in the commit body. Prefer the standard library.
---
## 7. Glossary
Keep code, UI copy and docs on these terms. Add to `docs/GLOSSARY.md` as needed.
| Term | Meaning |
|---|---|
| Host | A machine Ratline manages. Not "server" in UI copy, to avoid confusion with the web server. |
| Site | A deployable unit — one app or static bundle, one domain set, one systemd unit. |
| Release | An immutable timestamped build directory. |
| Deployment | The act of producing and activating a release. |
| Grant | A role assignment scoped to a node in the hierarchy, optionally time-bound. |
| Agent | The Ratline binary running on a host. |
| Break-glass | Emergency temporary elevation. |
---
## 8. Milestones
One at a time. Full gate report and explicit approval before the next. Each milestone's tasks are seeded in `tasks.yaml` during M0 and refined at the start of that milestone.
### M0 — Plan
Technical plan, stack decision with reasoning, data model, trust-boundary diagram, threat model v1, design plan, and the complete tracking system from §2 with the backlog populated through at least M3. **No application code.**
**Exit:** I have approved the plan, the ADRs for stack and agent transport, and the backlog.
### M1 — Control plane skeleton
Auth, org/team/project model, the `can()` function with 100% branch coverage, hash-chained audit log, UI shell with the design system applied, tracking CLI wired into CI.
**Exit:** authorization matrix test harness exists and runs, even though most endpoints don't exist yet; `tasks validate` gates the build.
### M2 — Agent and first host
Agent binary, SSH bootstrap, host inventory and health reporting, web server and runtime provisioning, config generation with validation and rollback.
**Exit:** a clean Debian 12 host goes from bare to fully provisioned in one action, twice in a row idempotently, with zero root SSH after bootstrap.
### M3 — Static sites end to end
Git connect, build pipeline, atomic release, TLS, custom domains, live log streaming, rollback.
**Exit:** a real static site deploys from a real repo, gets a real certificate, and rolls back in under a second.
### M4 — Node and Bun apps
systemd unit generation with sandboxing, process management, zero-downtime reload, env vars with redaction, health checks.
**Exit:** a Next.js app and a Bun/Elysia app both deploy, survive a failed-health-check deploy without downtime, and honour their resource limits.
### M5 — RBAC completion
Full role set, custom roles, time-bound grants, break-glass, role editor UI, and the exhaustive authorization matrix.
**Exit:** the matrix passes at 100%, every endpoint is covered, and cross-tenant probing returns indistinguishable responses for unauthorized and nonexistent.
### M6 — SSH access
Certificate authority, short-lived certificates, principals, scoped sudo, web terminal with session recording.
**Exit:** revoking a grant kills an active session within the certificate TTL and immediately blocks new ones; a developer with access to one site provably cannot reach another.
---
## 9. Anti-patterns that will get work rejected
- A `findById` that isn't tenant-scoped.
- Any string-interpolated shell command, however "safe" the input looks.
- Permission checks in route handlers instead of, or in addition to, the data layer.
- A migration that can't be rolled back.
- A test that mocks the thing it is supposed to be testing.
- Silent catch blocks.
- A milestone declared done with a stale tracker, a red test, or an unwritten gate report.
- Framework-specific hacks in the agent. The agent knows about processes, files, users and services — not about Next.js.
- "TODO: add auth check later."
---
## 10. Before you start
State every assumption you are making. Ask about anything ambiguous or that you think is the wrong call — including anything in this document. Then produce M0 and stop.
