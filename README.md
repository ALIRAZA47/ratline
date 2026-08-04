# Ratline

Self-hosted deployment and server management platform. A single control plane
that connects to VPS hosts you already own, provisions a hardened web stack, and
gives your team a clean interface to deploy static sites, Node.js apps and Bun
apps from Git — with an authorization model that holds up, and managed SSH
access to the underlying machines.

**Status: M1 control plane done and running; M2 agent protocol in progress. See
[docs/STATUS.md](docs/STATUS.md) for the live numbers — it is generated, and it is
the only count here that cannot go stale.** The permission model, audit chain, sessions, two-factor,
CSRF, rate limiting and the HTTP surface are built and tested against a real
Postgres. M2 — the host agent — is planned in full and waits on CI running once.

See [docs/STATUS.md](docs/STATUS.md) for the generated dashboard; it is the only
status claim in this repository that cannot go stale.

---

## Start here

| Document | What it is |
| --- | --- |
| [docs/BRIEF.md](docs/BRIEF.md) | The governing brief. Amended only by the project owner. |
| [docs/STATUS.md](docs/STATUS.md) | Generated dashboard. Never hand-edited. |
| [docs/PLAN.md](docs/PLAN.md) | Architecture, data model, trust boundaries. |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Assets, actors, compromise scenarios, residual risks. |
| [docs/DESIGN.md](docs/DESIGN.md) | Palette, type, layout, the signature element. |
| [docs/RISKS.md](docs/RISKS.md) | Open risks, with owners. |
| [docs/GLOSSARY.md](docs/GLOSSARY.md) | One vocabulary for code, interface and docs. |
| [docs/decisions/](docs/decisions/) | Architecture decision records. |
| [docs/PROGRESS.md](docs/PROGRESS.md) | Append-only session log, newest first. |

## Tracking

`docs/tasks.yaml` is the source of truth for all work. The CLI has no
dependencies and needs no build step — Node 22.6+ runs the TypeScript directly.

```bash
./scripts/tasks validate
```

```bash
./scripts/tasks next --milestone M1
```

```bash
./scripts/tasks list --milestone M2 --risk high
```

`./scripts/tasks help` lists everything. `validate` runs in CI; a malformed
tracker fails the build.

## The two differentiators

Everything else is table stakes executed well. These are the reasons Ratline
exists:

**A privilege architecture that never hands the control plane root.** The agent
on each host executes only enumerated operations with typed arguments — there is
no operation that carries a shell command. The agent itself runs unprivileged,
and a separate root helper re-validates every argument independently rather than
trusting it. So the constraint survives agent compromise, not just control plane
compromise.

**Authorization enforced at the data-access layer.** Every query is tenant-scoped
inside the repository function, the unscoped variant cannot be written, and
Postgres row-level security holds independently of application code. A handler
that forgets its check still returns nothing.

## Local development

Node 22.6+ is required — the code runs TypeScript directly via type stripping,
so there is no build step. `.node-version` pins the version.

Start a project-local Postgres. It lives in `.ratline/` on port 55432, so it
neither collides with nor disturbs any Postgres you already run, and
`./scripts/pg reset` throws it away:

```bash
./scripts/pg start
```

Apply migrations:

```bash
./scripts/migrate up
```

Check a host is ready to serve — generates secrets on first run, refuses on
anything missing, weak or publicly bound:

```bash
./scripts/preflight
```

Run everything CI runs:

```bash
npm run check
```

`./scripts/migrate cycle` applies every migration up, down and up again. That is
the gate a new migration has to pass: asserting a down path exists is a parser
check, but only the second `up` reveals a rollback that left something behind.

## Requirements

- Node 22.6+ for the tracking CLI and the control plane (22.18+ recommended)
- Postgres 17 for development; 16+ is the floor, since C3 needs forced row-level security
- A Go toolchain from M2, for the agent
