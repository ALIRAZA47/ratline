# Ratline — session log

Append-only. Newest entry at the top. Never edit a past entry.

**Start of every session** (brief §2.9): read `STATUS.md`, the top three entries
here, and `tasks.yaml` filtered to `in-progress` and `blocked`; run
`./scripts/tasks validate` and the full test suite and report anything already
red before touching it; state in two or three sentences what you intend to do
and which task IDs.

**End of every session:** update `tasks.yaml`; append here; run
`./scripts/tasks render`; commit the tracking updates on their own as
`chore(tracking): session N`; give a three-line summary.

---

## 2026-08-01 — Session 2 — M1

**Goal:** Scaffold the control plane with strict TypeScript and the lint rules
that make the forbidden patterns unwritable, then wire CI so `tasks validate`
gates the build before any application code lands.

**Completed:** RL-M1-001.

**In progress:** none.

**In review:** RL-M1-002 — CI pipeline written and every step verified locally,
but nothing has run it on GitHub and nothing has written `ci-status.json`, so
two of three acceptance lines are unproven. Deliberately not closed.

**Blocked:** none. RL-M1-003 (migrations) needs Postgres; Docker is installed
here but its daemon is not running, which will need resolving next session.

**Decisions made:** none new. ADRs 0001–0010 remain `proposed` — "continue" was
read as approval to start M1, not as ADR acceptance, which §2.6 reserves.

**Surprises / what I learned:**

- `node --test <dir>/` does **not** recurse. It treats the argument as a module
  path, the run fails, and the coverage report comes out empty — which renders
  as **100% and a green threshold check**. A coverage gate that always passes is
  worse than none. Coverage is now collected from an explicit file list, and the
  numbers were confirmed against a known-partial case (66.67% branch, correct).
- `node:test` coverage thresholds are enforced by the runtime, so the 100%
  `can()` gate in RL-M1-013 needs no test framework at all. Verified failing and
  passing in both directions.
- Turning strict mode on found **34 violations in `scripts/tasks.ts`**, written
  in M0 before a typechecker existed. Fixed rather than excluded: argv options
  became accessors instead of an index-signature record, and the parser's array
  reads carry explicit defaults. Every CLI command was re-verified afterwards.
- A "STATUS.md is current" CI check comparing whole files can never pass:
  STATUS.md contains test health and timestamps that change every run, and it is
  rendered from gitignored files. `render --check` now compares only the
  tracker-derived sections.
- Wrote a real bug and caught it: `security-findings.json` was only written when
  failures existed, so a finding once recorded never cleared — suite green,
  STATUS.md still reporting the gate blocked.
- **Process mistake worth not repeating:** I ran `git checkout -- docs/tasks.yaml`
  to revert a CLI probe and destroyed uncommitted tracker state, silently
  reopening a task I had closed. Tracker changes belong to the end-of-session
  `chore(tracking)` commit (§2.9), so they sit uncommitted for a long time. Undo
  probes with the CLI, not with git.

**Deviations from brief:** `.github/workflows/tracking.yml` from RL-M0-025 was
folded into `ci.yml` so exactly one workflow decides whether a commit is green.
RL-M0-025's acceptance still holds; a note on that task records the move.

**Next session should start with:** getting Postgres available for RL-M1-003 —
either starting the Docker daemon or another route. Then RL-M1-003 → RL-M1-004 →
RL-M1-006 → RL-M1-007, which is the C3 spine and the most important sequence in
M1. RL-M1-022 (C4, no default secrets) is also ready and independent if the
database route stalls.

## 2026-08-01 — Session 1 — M0

**Goal:** Produce M0 in full — the tracking system from brief §2 with a backlog
populated through M3, the technical plan, data model, trust boundaries, threat
model v1, the design plan, and the decision records. No application code.

**Completed:** RL-M0-001 through RL-M0-026. All 26 M0 tasks closed.

**In progress:** none. M0 is complete and awaiting the gate.

**Blocked:** none blocked yet, but `RL-M2-024` (integration test harness against
real hosts) is owned by human and will block the M2 gate. See R-01.

**Decisions made:** ten records, all `proposed`, none self-accepted —
0001 stack, 0002 agent transport, 0003 tenant scoping, 0004 host privilege
separation, 0005 command execution and build scripts, 0006 secrets,
0007 queue on Postgres, 0008 SSH certificate authority, 0009 where builds run,
0010 web server config generation.

**Surprises / what I learned:**

- Node 20 is on `PATH` here and cannot run TypeScript, but nvm has 22.22.0 on
  disk, which strips types natively. So the tracking CLI is real, runnable,
  dependency-free TypeScript with no install step — `scripts/tasks` finds a
  suitable Node itself.
- Keeping `depends_on` and `blocks` consistent by hand across 143 tasks is
  exactly the busywork that produces the stale tracker the brief forbids. Added
  `tasks sync-blocks` to derive `blocks`; `validate` still enforces symmetry.
- The brief's schema shows acceptance lines as plain text with no way to record
  which are met, but `tasks done` must refuse until each is checked off. Added
  `acceptance_met` as a list of 1-based indices, which keeps the acceptance text
  pristine and valid YAML.
- Two of the brief's own requirements pull against each other: C2 forbids shell
  construction from user data, and §6.5 requires editable build commands. Raised
  in ADR 0005 as a §2.10 stop condition with a proposed resolution.
- C5 has a consequence worth naming — if the dashboard must work on an isolated
  network, every asset must be self-hosted. No font CDN. That shaped `DESIGN.md`.
- The agent endpoint and the dashboard need **separate exposure policies**:
  agents must reach the control plane, but the dashboard must not be public.
  Easy for an operator to get wrong, so it has to be the default shape.

**Deviations from brief:** three, all declared in the gate report —
one commit per task on a single `m0/plan` branch rather than a branch per task;
an HTML comment atop `BRIEF.md`; design-record tasks rated `risk: medium`
rather than `high`. Reasoning in `docs/gates/M0.md`.

**Next session should start with:** nothing until the gate is approved. On
approval, `RL-M1-001` then `RL-M1-002`, so CI and `tasks validate` gate the
build before any application code lands. Run
`./scripts/tasks next --milestone M1` to confirm what is ready.
