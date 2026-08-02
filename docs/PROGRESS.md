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

## 2026-08-02 — Session 12 (continued) — M1

**Completed:** RL-M1-020 reached `review`, not done.

**Surprises / what I learned:**

- **The agent reported the limit of its own work without being asked**, and it
  was the right call: acceptance 1 is met at the function level and cannot be
  met at the endpoint level, because there is no HTTP layer, no two-factor
  verification and no password reset to wire it into. I verified by grep that
  nothing in production code calls the limiter. Marking that `done` would have
  been the kind of claim that reads fine in a gate report and is false in the
  product.
- The design decision I would not have reached alone: the window is FIXED rather
  than sliding, because a sliding window lets an attacker hold any named account
  locked out indefinitely by attempting once per window. The more accurate
  limiter is the wrong one here.
- Digesting the bucket key was chosen for existence-leak reasons and turns out
  to matter more for a second one — unauthenticated callers cause writes to that
  table, so raw identifiers would make it an attacker-populated harvest of every
  address ever tried, in the database and in every backup.
- **An existing test caught the agent rather than the reverse.** RL-M1-007's
  "every exported repository function takes an AuthzContext first" flagged two
  pure type guards it had exported from `src/repo/`. It removed them and
  recorded why, rather than weakening the rule. That structural rule has now
  paid for itself twice.

**Next session should start with:** RL-M1-019 (two-factor) and RL-M1-021 (CSRF),
which finish authentication hardening. RL-M1-024 still owes the pre-authentication
context decision ADR 0014 named — it blocks sign-in audit entries and the
rate-limiter's own refusal entries.

## 2026-08-02 — Session 12 — M1

**Goal:** RL-M1-018 — role changes reaching active sessions — with rate limiting
delegated.

**Completed:** RL-M1-018.

**In progress:** RL-M1-020 (delegated, still running at the time of writing).

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none.

**Decisions made:** none new. ADRs 0001–0014 remain `proposed`.

**Surprises / what I learned:**

- **The authorization half of §6.3 was already satisfied by an absence**, and
  that is a fragile way to satisfy anything. `can()` holds no cache, so a role
  change is felt on the next request — but a cache is the obvious optimisation,
  and adding one would break the requirement silently with every existing test
  still green. Asserting the absence structurally turns it from a property we
  happen to have into one the build enforces.
- Splitting `member.revoke_sessions` from `member.remove` matters for a human
  reason rather than a technical one: containment must not require the
  destructive answer, because during an incident the destructive answer is the
  one people hesitate over, and hesitation is what an attacker counts on.
- Giving Infrastructure the new action LOOKED like an escalation and is not —
  they already hold break-glass and terminal.open. It means containing an
  incident no longer requires elevating to Admin first, which is less privilege
  and less audit noise for the commonest emergency action. Worth checking what a
  role can already reach before deciding a grant widens anything.
- I nearly put the permission check in the new module as well as the repository.
  §9 names that as an anti-pattern, and the reason is worth restating: a second
  check is the shape that eventually disagrees with the first. Catching the
  repository's refusal in order to audit it does the same job without the
  duplication.
- My first two attempts at the test used the repository's low-level session
  functions rather than the real sign-in path. Reaching past the authentication
  layer would have tested a shape the product never takes.

**Deviations from brief:** none.

**Next session should start with:** whatever RL-M1-020 reports, then RL-M1-019
(two-factor) and RL-M1-021 (CSRF), which together finish the authentication
hardening. RL-M1-024 still owes the pre-auth context decision ADR 0014 named,
and it blocks the sign-in audit entries.

## 2026-08-02 — Session 11 — M1

**Goal:** Close the audit truncation gap (RL-M1-015), prove attribution
(RL-M1-016), with password authentication and sessions delegated.

**Completed:** RL-M1-015, RL-M1-016, RL-M1-017 (delegated).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none.

**Decisions made:** ADR 0014 (proposed) — sessions and password storage.

**Surprises / what I learned:**

- **A hash chain provably cannot detect truncation of its own head**, because
  the evidence is the part that was removed. That is not a bug to fix but a
  property to work around, and the workaround is remembering the head outside
  the chain. Worth being precise about what it buys: not impossibility, but
  turning a silent deletion into a loud contradiction.
- Testing attribution as a NEGATIVE — that no code path can omit an actor —
  produced better tests than testing that we currently write one. The three
  routes (nullable column, context without an actor, job inventing a principal)
  each needed a different mechanism, and listing them was what found the third.
- **My own mutation reproductions were wrong twice in one session.** One regex
  missed a table alias and silently did nothing; one replacement referenced
  undefined variables and failed to compile rather than changing semantics. Both
  produced numbers that contradicted the agent's report — and the agent was
  right. A mutation that does not compile is not a mutation, and a mutation that
  matches nothing is worse, because it looks like a passing result. Check that
  the mutation applied before believing what the suite says about it.
- The sessions agent reported, unprompted, that no functional test can catch a
  non-constant-time comparison — every variant accepts the same passwords and
  differs only in rejection timing — and that its structural assertion is
  incomplete in a specific, named way. That is the most useful kind of report:
  it says which guarantees are enforced and which are conventional, instead of
  letting a green suite imply they are the same.
- Two things it declined to build rather than paper over: sign-in audit entries,
  because inventing an action name outside the catalogue would be the
  decentralised vocabulary this codebase avoids; and an administrative password
  reset, because shipping an ungated one is worse than shipping none. Both are
  now tasks rather than silences.

**Deviations from brief:** none.

**Next session should start with:** RL-M1-018 (role changes take effect on
active sessions) — it closes the sign-in audit gap and the administrative
revocation stand-in at once, and RL-M1-034 depends on it. RL-M1-020 (rate
limiting) is the mitigation for R-15 and is independent. RL-M1-024 has to
resolve the pre-auth context seam ADR 0014 names.

## 2026-08-02 — Session 10 — M1, and a scope change

**Goal:** The hash-chained audit log (C6), with API tokens delegated. Then a
requested scope change: managed database engines.

**Completed:** RL-M1-014, RL-M1-032 (delegated), RL-M1-033, RL-M7-001 (planning).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none in the tracker.

**Decisions made:** ADR 0013 (proposed) — managed database engines, which amends
brief §5.2.

**Surprises / what I learned:**

- **An invariant expressed as "count some rows" ages badly.** The last-owner
  floor has now been defeated three times by later features: expiry (RL-M1-011),
  and now a new subject kind — a service identity or API token holding `owner`
  at organization scope satisfied a floor §6.3 intends a person to satisfy. The
  durable fix each time was to make the bad state UNREPRESENTABLE rather than to
  count more carefully. Worth assuming the next feature will find a fourth way.
- The audit log's real question is not "does it write rows" but "would it notice
  if someone changed one". That reframing is what produced the design: the
  DATABASE computes the hash, because a chain computed by the thing being
  audited proves nothing — an attacker owning the application recomputes it and
  it verifies perfectly.
- A hash chain cannot detect truncation of its own head. Recorded as a known
  limit with its own test, and RL-M1-015 now carries the requirement to record
  the expected head after each verification run.
- Another test that proved the opposite of what it claimed: my first tamper set
  `decision = 'allow'` on rows already `'allow'`, so it changed nothing and the
  verifier was right to stay quiet. Third instance of this family after the
  vacuous RLS tests and the empty coverage report.
- **Managed databases change what the product is, not just what it does.** Every
  workload so far is reconstructible from git; a database is not. Two accepted
  ADRs — build on the target host, and build commands contained rather than
  eliminated — were argued under the old assumption and now put user-authored
  code next to data. Planning M7 without re-examining them would have been the
  real mistake, so RL-M7-001 exists to do that first.
- The one place C2's answer does not transfer: SQL DDL cannot parameterise
  identifiers, so a database name is interpolated into statement text by
  necessity. The replacement is to derive the identifier rather than accept one.

**Deviations from brief:** ADR 0013 amends §5.2, which lists managed databases
as out of scope for v1. Requested by the brief's author; the amendment itself is
theirs to make. Planned as M7 after M6 rather than folded into v1 — reversible,
and flagged.

**Next session should start with:** RL-M1-015 (scheduled chain verification,
which must close the truncation gap) or RL-M1-016 (actor attribution). RL-M1-017
(sessions) remains the clean parallel candidate. M7 does not start until the v1
scope question is answered.

## 2026-08-01 — Session 9 — M1

**Goal:** `can()` and the coverage gate that guards it, with the C2/C3 lint
rules delegated.

**Completed:** RL-M1-012, RL-M1-013, RL-M1-008 (delegated).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none in the tracker. RL-M1-028 still wants the DESIGN.md 10.1
ruling.

**Decisions made:** none new. ADRs 0001–0012 remain `proposed`.

**Surprises / what I learned:**

- **Mutation testing found a robustness bug, not a behaviour bug.** I had
  duplicated the fail-closed comparison on the database's answer instead of
  reusing `isAllowed()`. Inverting my copy to the fail-open form broke NO test:
  the two forms agree on every value `grant_decision` returns today and differ
  only on the values that would matter tomorrow. That class of defect is
  invisible to ordinary tests by construction.
- Reaching 100% branch coverage needed three *code* changes rather than three
  tests bolted on — a ternary that existed only to satisfy
  `exactOptionalPropertyTypes`, an optional field never exercised both ways, and
  an exported guard with no test at all. That is the gate doing real work rather
  than being satisfied.
- A missing measurement has to FAIL the coverage gate, not pass it. Renaming
  `can.ts` would otherwise switch off its own gate silently, which is the
  failure mode most likely to survive for months. Verified by pointing the
  matcher at a file that does not exist.
- **I repeated the session-2 mistake: `git checkout` on an uncommitted file
  destroyed the coverage gate I had just written.** Caught it because I checked
  after, not because anything told me. Probes now get reverted from a `/tmp`
  copy; `git checkout` is out of my working vocabulary for uncommitted work.
- Lint fixtures under `test/` were being counted as passing tests — Node treats
  every file in a directory named `test` as a test file. The agent flagged it as
  outside its scope, correctly, and it was a real inflation of the number the
  gate report quotes.
- The lint agent verified each of its rule's *non*-catches empirically with
  throwaway probes rather than asserting them, and wrote the blind spots into
  the rule's header. That is the right instinct: a rule that claims more than it
  detects is worse than none, because it stops people looking.

**Deviations from brief:** none.

**Next session should start with:** RL-M1-014, the hash-chained audit log — it
is the last major C-constraint (C6) without an implementation, and RL-M1-016
depends on it. RL-M1-024 (matrix generator) and RL-M1-032 (API tokens, which
closes threat-model R-12) are both ready and independent.

## 2026-08-01 — Session 8 — M1

**Goal:** RL-M1-007, the scoped data-access primitive and authorization context
— layer 2 of C3 — with the grants model delegated in parallel.

**Completed:** RL-M1-007, RL-M1-011 (delegated).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none in the tracker. RL-M1-028 still wants the DESIGN.md 10.1
ruling.

**Decisions made:** ADR 0012 (proposed) — grant resolution, the expiry clock,
and unconditional owner grants.

**Surprises / what I learned:**

- **Two mutations that pass are not the same as two mutations that are safe.**
  Binding the tenant session-wide instead of transaction-local passed every test
  I had written, because `scoped()` always sets the tenant first, so the two are
  indistinguishable from inside the primitive. The difference only appears
  outside it: transaction-local means a stray query sees nothing, session-wide
  means it sees whatever tenant ran last. Fail-closed versus fail-stale. Closed
  with a test that queries the pooled connection outside `scoped()`.
- **TypeScript reads any comment line beginning with the suppression directive
  as a real directive** — including one inside explanatory prose. My comment
  *about* `@ts-expect-error` had wrapped onto its own line and become one, which
  made the brand test appear to prove the brand was broken. Four isolated probes
  before I saw it. Now written into the test file.
- **The last-owner floor I built in RL-M1-004 was quietly defeated by adding
  expiry.** The trigger counts organization-scope owner rows without filtering
  effect or expiry, so a lapsing grant leaves an organization ownerless while
  the count still reads one — and no trigger can fire, because time passing is
  not an event. The fix is to refuse to represent the state rather than to
  detect it. This is the second time an invariant of mine has been broken by a
  later feature; worth assuming it will happen again.
- The expiry clock matters more than it looks. `now()` is frozen for a whole
  transaction, so a decision late in a long one would honour a grant that lapsed
  minutes earlier — a break-glass elevation outliving its own expiry. The test
  that proves the right clock asserts `now()` did NOT change while the answer
  flipped, which rules out the wrong one rather than merely suggesting it.
- The delegated agent reported four items as belonging in `docs/` rather than
  writing them there, which was the right call and saved me from finding them
  later. Both agents this session and last had accurate self-reports; the one
  that overclaimed was in session 5. Checking is still cheap enough to keep doing.

**Deviations from brief:** none.

**Next session should start with:** RL-M1-008 — converting the structural tests
written in RL-M1-007 into lint rules, so the forbidden patterns are unwritable
rather than merely caught. Then RL-M1-012, `can()`, which now has a resolution
interface to build on and two gaps waiting for it (R-12, R-13). RL-M1-017
(sessions) remains the clean parallel candidate.

## 2026-08-01 — Session 7 — M1

**Goal:** RL-M1-006 — row-level security, the layer C3 rests on.

**Completed:** RL-M1-006.

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none in the tracker. RL-M1-028 still wants the DESIGN.md 10.1
ruling before the shell is built.

**Decisions made:** none new. ADRs 0001–0011 remain `proposed`.

**Surprises / what I learned:**

- **The development role is a superuser, and a superuser bypasses RLS
  unconditionally.** Had I written these tests on the migration connection they
  would all have passed while exercising no policy at all — a suite that cannot
  fail, which is worse than no suite. Every assertion now connects as
  `ratline_app`, an unprivileged NOBYPASSRLS role, and there is a test asserting
  that role is neither superuser nor BYPASSRLS.
- **Found a complete bypass I had introduced in RL-M1-005.** A view runs with
  its OWNER's permissions unless `security_invoker` is set, so `scope_ancestry`
  would have returned every tenant's hierarchy to anyone able to select from it.
  Any view over a tenant table needs the same setting; the RLS suite now covers
  it.
- Deleting the `WITH CHECK` clause from a policy is NOT caught by the tests, and
  that is correct: Postgres falls back to the `USING` expression, so the
  mutation is semantically null. Making it `with check (true)` IS caught. Worth
  recording, because "the test didn't catch it" and "the change did nothing" look
  identical from the outside and lead to opposite conclusions.
- No parallel agent this session, deliberately. The remaining ready work all
  touches the database schema, and two streams writing migrations would collide
  on ordering and on which tables carry policies. Fanning out here would have
  cost more than it bought.

**Deviations from brief:** none.

**Next session should start with:** RL-M1-007 — the scoped repository primitive
and the AuthzContext type, which is layer 2 of C3 and the last piece before
RL-M1-008 can make the forbidden patterns unwritable. RL-M1-011 (grants) and
RL-M1-017 (sessions) are also ready; RL-M1-017 is the better parallel candidate
once RL-M1-007 lands, since by then the repository shape it needs will exist.

## 2026-08-01 — Session 6 — M1

**Goal:** The C3 spine — identity and hierarchy schema — with the six remaining
default roles delegated in parallel.

**Completed:** RL-M1-004 (identity), RL-M1-005 (hierarchy), RL-M1-010 (roles,
delegated).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none in the tracker. RL-M1-028 should not start until the DESIGN.md
10.1 ruling lands.

**Decisions made:** none new. ADRs 0001–0011 remain `proposed`.

**Surprises / what I learned:**

- **Test isolation had to move from scratch schemas to scratch databases.** An
  extension installs once per *database*, so `create extension if not exists
  citext` silently no-ops for a second schema and the type is then invisible to
  it. Anything database-scoped a migration can create has the same problem. Cost
  about an hour; now written down in `test/support/db.ts`.
- Deleting a project left its scope node orphaned. The foreign keys point
  entity → node, so the cascade runs the wrong way, and an orphaned node keeps
  conveying every grant made against it — a privilege leak with no visible
  cause. Fixed with reverse-direction triggers.
- The theme running through both schema migrations: **the dangerous direction is
  quiet.** A wrong scope path fails OPEN because a shorter path matches more
  descendants. So the path is computed by a trigger that overwrites whatever the
  caller supplies, and `is_production` is generated rather than stored. Both have
  tests that write the wrong value deliberately and assert it does not survive.
- The `org_id` audit test caught `organizations` itself, which *is* the tenant.
  A legitimate exception I had not thought of — worth having the test discover
  tables rather than list them.
- My own destructive-migration rule flagged `on delete cascade` on a foreign
  key. That is a declared ownership relationship, not the `drop ... cascade` the
  rule was for. Tightened, and the tightening is pinned by its own test: a rule
  that cries wolf on correct code gets an exclusion added rather than a reading.
- **I over-constrained an agent.** RL-M1-010 legitimately invalidates a
  placeholder assertion living in RL-M1-009's test file, and I had scoped the
  agent out of it. It made the minimal edit and flagged it, which was the right
  call. A task that extends another's data usually has to touch that task's
  tests; scope agents by intent, not only by file list.
- The roles agent's self-report held up under checking, unlike the previous
  session's. Its four catalogue gaps are real and are now routed to RL-M5-002,
  RL-M6-005 and RL-M1-031 rather than sitting in a transcript. The sharpest:
  §6.3 says Infrastructure "cannot read *production* secret values", and without
  an environment split on `secret.read_value` that sentence cannot be expressed
  as a role at all.

**Deviations from brief:** none beyond those already recorded.

**Next session should start with:** RL-M1-006 — row-level security, the heart of
C3 and the layer that has to hold when the other two fail. The acceptance that
matters is the third: delete a repository function's own predicate, run it with
a foreign tenant, and still get zero rows. RL-M1-011 (grants, extending the
table created in RL-M1-004) and RL-M1-017 (sessions) are both ready and
independent of it.

## 2026-08-01 — Session 5 — M1

**Goal:** Unblock the database, then run three unrelated tasks in parallel — two
delegated to subagents, one taken here.

**Completed:** RL-M1-003 (migration tooling), RL-M1-009 (permission catalogue,
delegated), RL-M1-027 (design tokens, delegated).

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none. RL-M1-004 and RL-M1-010 and RL-M1-028 are all ready.

**Decisions made:** none new. ADRs 0001–0011 remain `proposed`.

**Surprises / what I learned:**

- Postgres was already installed via Homebrew, so the Docker daemon never
  mattered. It failed to start with "postmaster became multithreaded during
  startup", a macOS locale issue the server log diagnoses itself — `LC_ALL=C`
  fixes it, and `scripts/pg` sets it so nobody rediscovers this.
- `migrate cycle` assumed an empty starting database, so a database with a
  migration already applied reported a false failure. Fixed by normalising to
  zero first. Verified the cycle genuinely catches a bad rollback by adding a
  migration that drops its table but leaves its enum type behind.
- **Subagent self-reports need checking against the files, not just reading.**
  The catalogue agent reported documenting a design tension and a known-gaps
  list "in the file"; neither was actually written down. They existed only in
  its message to me — precisely the loss brief §0 forbids, since a future
  session reads the repo, not this transcript. Both are now in the source.
- The token agent found a contradiction I wrote into DESIGN.md during M0: §4
  specifies a colour-coded environment chip, §1 says colour means status and
  nothing else may be saturated. Both cannot hold. Recorded as open question
  10.1 with a recommendation; RL-M1-028 needs it settled first. Good argument
  for building the tokens before the shell rather than together.
- It also correctly overrode an instruction of mine: I specified
  `@fontsource/archivo`, which ships only the normal width and cannot render the
  Expanded width DESIGN.md calls the signature. Using the variable package was
  the right call, and it added a test that fails if anyone switches back.
- **Parallelism has one hard contention point: `package.json`.** Source files
  split cleanly across three streams, but the dependency manifest does not. I
  nearly corrupted `node_modules` by installing `pg` while an agent was
  mid-install, and the `pg` and `@fontsource` entries ended up in one commit
  because a lockfile cannot be split. Next time: have one stream own dependency
  changes, or stage them serially at the end.

**Deviations from brief:** RL-M1-009 was re-sequenced to depend on RL-M1-001
rather than RL-M1-005. The catalogue declares actions, resource types and scope
levels, all of which come from brief §6.3 rather than from the schema — the
schema references the catalogue, not the reverse. Noted on the task. Two commits
carry a second task's dependency lines for the lockfile reason above, each
stating so in its body.

**Next session should start with:** RL-M1-004 (identity schema) then RL-M1-006
and RL-M1-007 — the C3 spine, now genuinely unblocked with Postgres running.
RL-M1-010 (the remaining six roles) is also ready and is a clean parallel stream
since it touches only `src/authz/roles.ts`. RL-M1-028 should wait on the
DESIGN.md 10.1 ruling.

## 2026-08-01 — Session 4 — M1

**Goal:** C5 — bind to loopback by default, detect public exposure, refuse an
unintended public bind, and document the VPN, Tailscale and allowlist setups.

**Completed:** RL-M1-023.

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none. RL-M1-003 still needs Postgres; the Docker daemon is down.

**Decisions made:** ADR 0011 (proposed) — exposure detection without phoning
home.

**Surprises / what I learned:**

- C5 says "detect public reachability", and the obvious implementation is an
  outbound probe. That would phone home from every install, create a fleet-wide
  correlation point, and fail on exactly the isolated networks C5 protects.
  Raised as ADR 0011: classify locally, and state the blind spot instead of
  hiding it. A dashboard behind a public reverse proxy reports `contained` and
  cannot be told apart from a genuinely private one without a probe — so the
  caveat rides along with every report. Recorded as residual risk R-11.
- My first cut printed "Acknowledged via RATLINE_ALLOW_PUBLIC_BIND" whenever a
  warning existed, including when nothing had been acknowledged. A security
  warning that misdescribes the operator's own configuration is worse than none,
  because it teaches them the text is boilerplate.
- My first cut also let a wildcard bind through unacknowledged, purely because
  this laptop has no globally routable address today. That is a fact about this
  afternoon, not the deployment. Wildcards now always require acknowledgement.
- The interesting design tension was where *not* to warn. Private, Tailscale and
  unique-local addresses start silently on purpose: they are the recommended
  setups, and demanding acknowledgement for them would train operators to set
  `RATLINE_ALLOW_PUBLIC_BIND=1` permanently, which is exactly how the control
  gets defeated.
- Mutation testing earned its place again. An RFC1918 off-by-one — treating
  172.32/16 as private — is invisible on inspection and caught by one test.

**Deviations from brief:** none.

**Next session should start with:** Postgres. Both C4 and C5 are now done and
they were the two constraints most likely to be skipped under delivery pressure;
everything else substantial in M1 runs through the database. RL-M1-003 → 004 →
006 → 007 is the C3 spine and the most important sequence in the milestone.
RL-M1-027 (design tokens) is the only meaningful task left that needs no
database, if the Docker daemon cannot be started.

## 2026-08-01 — Session 3 — M1

**Goal:** C4 — the secret store. Generate on first run, refuse to boot on
anything missing, weak or badly permissioned, with the security test that gates
the task.

**Completed:** RL-M1-022.

**In progress:** none.

**In review:** RL-M1-002, unchanged — still needs a first real CI run.

**Blocked:** none. RL-M1-003 still needs Postgres and the Docker daemon is down.

**Decisions made:** none new. ADRs 0001–0010 remain `proposed`.

**Surprises / what I learned:**

- The first design of the default-secret scanner was wrong in a way that would
  have blocked M5. It searched source text for placeholder tokens, and `admin`
  and `root` are both on that list — so the moment `src/authz/` defines the
  Admin role, the C4 test would fail on a legitimate role name. Rewritten to
  flag a string literal only when it is assigned to a secret-shaped identifier,
  which is the actual threat rather than a word count.
- Placeholder tokens have to live somewhere, and that module trips its own
  scanner. Handled with a one-file exclusion plus a test asserting the exclusion
  list stays length 1, so it cannot quietly become a general amnesty.
- Mutation-testing the suite was worth more than writing more of it. Four
  deliberate regressions — planting a default literal, planting base64 key
  material, disabling the weak-secret check, loosening file mode — fail 2, 1, 7
  and 14 tests respectively. Before that run I had no evidence the tests could
  fail at all.
- Generating secrets on first run is the obvious reading of C4 and is quietly
  dangerous: a container whose secrets volume fails to mount regenerates
  everything on each restart, invalidating sessions and agent enrolments while
  looking healthy. `generateIfMissing: false` exists for exactly that context.
- Coverage dropped to 95.4% once real source landed, which is correct and
  useful. The 100% requirement applies to `src/authz/**` (RL-M1-013), not to the
  tree as a whole.

**Deviations from brief:** none.

**Next session should start with:** RL-M1-023 (C5 — bind to localhost, detect
public reachability). It is now unblocked, it is the other constraint most
likely to be skipped under pressure, and it extends the same `preflight()`
function this session created, so the two land as one coherent boot check.
Postgres is still the gate for the RL-M1-003 → 004 → 006 → 007 spine.

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
