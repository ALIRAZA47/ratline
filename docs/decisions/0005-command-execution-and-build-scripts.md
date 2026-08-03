# 0005 — Command execution and user-authored build scripts

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-014

## Context

C2: *"No shell command is ever constructed by string interpolation. All remote
execution uses argv arrays with explicit arguments. No `sh -c` with any
user-derived data, anywhere."*

There is a genuine conflict here with §6.5, which requires sites to have a
configurable **build command** and **install command**. A build command is a
shell string by nature — `npm ci && npm run build`, `pnpm -F web build`,
`hugo --minify` — and users expect `&&`, pipes, and environment expansion to
work. Under a literal reading of C2, that feature cannot exist.

The brief's §2.10 says to stop and ask when a hard constraint conflicts with a
requirement elsewhere. **This is that case, and this ADR is the escalation.** It
proposes a resolution rather than silently picking one, because the resolution
is defensible and the milestone should not stall on it — but the human decides.

The resolution turns on separating two things the constraint text runs together:

- **Injection** — an attacker steering a command *Ratline* constructed, reaching
  privilege they were never granted. This is the Coolify failure class, and C2
  eliminates it.
- **Intended execution** — a user running code they are authorised to run, as
  themselves, inside their own sandbox. A build command *is* this. So is a
  `postinstall` script in a dependency, which runs regardless of what Ratline
  does with the build command field.

The second is not a vulnerability to be closed. It is the product. The question
is only how tightly it is contained, and whether it can ever become the first.

## Options considered

| Option | Assessment |
| --- | --- |
| No build commands at all — Ratline runs only detected, fixed commands per framework | Genuinely satisfies C2 literally. Breaks monorepos, custom pipelines, and anything the detector does not know. Would make Ratline unusable for the audience in §3.3. Rejected. |
| Interpolate the user's command into a shell invocation | What every competitor does. Straightforward violation of C2 and the exact anti-pattern in §9. Rejected. |
| Parse the build command into an argv array and refuse anything with shell syntax | Preserves C2 literally but rejects `&&`, which is in almost every real build command. Users would work around it by writing a shell script into their repository and calling it — achieving the same execution with worse visibility. Rejected as security theatre. |
| Materialise the command as a file and execute the file by argv | The user's text is never part of a command Ratline constructs; it is *content* written to a file, and the file path is a system-generated argument. **Chosen.** |

## Decision

### For every command Ratline constructs — C2 holds absolutely

- The control plane executes no processes at all. A lint rule bans importing any
  process-spawning module in control plane code, with a fixture proving it fires.
- The agent and `privd` use argument vectors only. Invoking a shell interpreter
  with a constructed string fails the build (RL-M2-028). Formatting a value into
  a process argument fails the build unless explicitly annotated and reviewed.
- Every user-controllable field that can reach a host is enumerated from the
  operation schema and fuzzed with metacharacters, newlines, null bytes, unicode
  normalisation forms and long inputs (RL-M2-027). The test fails if a new field
  appears without coverage, so the corpus cannot silently fall behind.

### For user-authored build and install commands — contained, not interpolated

1. The command text is written **atomically to a file** owned by the site's own
   Linux user, inside the site's build directory. It is content, not syntax.
2. It executes as `["/bin/sh", "<system-generated-path>"]`. Every argument is
   system-generated. No user text appears in any argument.
3. It runs **as the site's own unprivileged user**, never as `ratline-agent` and
   never as root, inside a transient systemd scope carrying the same sandboxing
   as the site's service unit: `NoNewPrivileges`, `ProtectSystem=strict`,
   `ProtectHome`, `PrivateTmp`, plus `MemoryMax`, `CPUQuota` and `TasksMax`.
4. Setting a build command is **its own permission**, distinct from deploying.
   Most roles that can deploy must not be able to change what deploying runs.
   This is the control that actually matters: it makes "can run arbitrary code
   in this sandbox" an explicit, auditable grant rather than a side effect of
   Developer.
5. Changing it is audited, with the before and after values.

### What this buys and what it does not

A user with `site.build_command.write` can run arbitrary code as that site's
Linux user on that host. That is true, expected, and equally true of any
dependency's install script. The security property we hold is that this
**cannot escalate**: not to root (ADR 0004), not to another site (per-site users
and directory modes, RL-M2-020), not to the agent's credentials, and not to
another host. RL-M3-007 tests exactly this — metacharacters in a build command
affect only that site's own sandbox.

## Consequences

**Makes easy.** Supporting real build pipelines without a special case, while
keeping a clean and testable statement of C2 for everything Ratline itself
constructs.

**Makes hard.** Sites on a shared host are isolated by Linux users and systemd
sandboxing, not by containers. That is a weaker boundary than a namespace, and
it is the boundary the whole no-Docker design rests on. It must be tested
adversarially rather than assumed (RL-M3-006).

**What we live with.** A site's build can consume host resources and, if limits
are set badly, degrade a neighbour. Bounded by the transient scope's limits;
sized in ADR 0009.

**New attack surface.** The build sandbox is now an explicit, documented
code-execution surface. The mitigating controls are the separate permission, the
per-site user, the systemd sandbox, and the audit record. The residual risk —
that production and non-production sites sharing one host means a non-production
build sits one sandbox escape away from a production site — is real, is recorded
in the threat model, and should surface as a warning in the interface when an
operator places them together.

## Escalation

**This ADR needs an explicit ruling, not just acceptance.** Confirm that
containment-not-elimination is the correct reading of C2 for user-authored build
commands. If the intended reading is stricter — no user-supplied build commands
at all in v1 — say so, and RL-M3-004 becomes fixed per-framework pipelines with
no editable command, which is a materially different and much smaller product.
