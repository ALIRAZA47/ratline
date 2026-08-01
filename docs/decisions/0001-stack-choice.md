# 0001 — Stack choice

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-010

## Context

The brief (§6.1) proposes TypeScript end to end, SvelteKit or React on the front
end, Hono or NestJS for the API, Postgres, a Redis-backed queue, and a Go agent —
and explicitly invites disagreement. Four constraints do most of the work in
choosing:

- **C3** requires that an unscoped read be *impossible to write*, not merely
  discouraged. That is a property of the data-access layer, and it rules out any
  ORM whose generated client is the natural thing to reach for.
- **C4** requires no default secrets and a refusal to boot without them.
- **C5** means the dashboard must work with no internet access at all — no CDN
  for fonts, icons or scripts, no telemetry call on boot.
- **§6.7** requires TypeScript strict with no `any`, and a preference for the
  standard library with a written justification per dependency.

The product is also self-hosted. Every component an operator has to install,
back up, patch and monitor is a real recurring cost paid by the eight-person
team the brief tells us to optimise for, not a line in a compose file.

## Options considered

### Control plane language

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| TypeScript on Node | One language with the front end and with user-facing build tooling; excellent Postgres and crypto libraries; the team already reads it | Runtime type erasure means boundary validation must be explicit | Neutral — safety comes from the data-access design, not the language |
| Go for both control plane and agent | One language across the fleet; static binaries | Loses shared types with the front end; slower UI iteration on the signature screen | Neutral |
| Rust | Strongest guarantees | Materially slower to build a product-shaped surface this wide | Neutral |

TypeScript. The brief's reasoning holds, and the type sharing between the API,
the front end and the operation catalogue that the agent consumes is worth more
here than raw runtime safety, because the dangerous work happens on the host and
is written in Go regardless.

### Control plane runtime — **this departs from the obvious choice**

Node 22 LTS rather than Bun. Ratline *supports* Bun as a deployment target
(§5.1), which makes it tempting to run on it too. Against that: the control
plane is the component holding the fleet's signing key, and its security-update
cadence matters more than its request throughput, which is trivial. Node LTS has
a longer published support window and a larger set of audited crypto and Postgres
libraries. The brief itself (§2.5) cites Bun's temp-directory handling breaking
under `ProtectSystem=strict` as a known surprise — that is a fine thing to
support for customers and a poor thing to bet the control plane on.

Node 22.6+ also runs TypeScript directly via type stripping, which is why
`scripts/tasks.ts` needs no build step and no dependencies today.

### API framework — **departs from the brief's NestJS option**

Hono, not NestJS. NestJS is not unsafe, but its culture pushes authorization
into guards and interceptors at the route layer — precisely the anti-pattern in
§9 and the thing C3 exists to prevent. Its dependency-injection graph also makes
"where is the database handle reachable from?" a harder question to answer
statically, and that question is the one the C3 lint rule has to answer. Hono is
a thin router with an explicit middleware chain, no ambient DI, and no reason for
anyone to reach for a `@Roles()` decorator.

### Data access — the C3-critical choice

| Option | Assessment |
| --- | --- |
| Prisma | The generated client is the ergonomic path and it is unscoped by construction. Making the safe path the only path means fighting the tool. Rejected. |
| Drizzle | Typed SQL builder with no ambient client; composes cleanly with a mandatory scoping wrapper; migrations are plain SQL with a real down path. **Chosen.** |
| Hand-written SQL | Maximum control, but re-implements typing and migration tooling. Rejected on cost, not on safety. |

Drizzle, wrapped so the raw handle is never exported outside the repository
layer. See ADR 0003 for the mechanism, which is where the actual guarantee lives.

### Queue — see ADR 0007

Postgres, not Redis. Argued separately.

### Front end

SvelteKit. The reasoning: one framework covers server rendering and client
behaviour with no separate routing story; the runtime is small, which matters for
a tool people load during an incident on a hotel wifi VPN; and Svelte 5's
fine-grained reactivity suits the log stream, which is the highest-frequency
surface in the product.

**This is the weakest recommendation in this ADR and the most reversible.** The
signature screen needs virtualisation either way, `xterm.js` is framework
agnostic, and if the team writes React daily then React is the better answer for
reasons no benchmark captures. This is listed as an open question in the M0 gate
report.

### Agent

Go, as the brief proposes. Static cross-compiled binary, no runtime to install on
a managed host, direct access to the syscall and systemd surface the agent needs,
and a small enough standard library dependency footprint that "prefer the
standard library" is realistic rather than aspirational.

## Decision

| Layer | Choice |
| --- | --- |
| Control plane language | TypeScript, strict |
| Control plane runtime | Node 22 LTS |
| API framework | Hono |
| Data access | Drizzle behind a mandatory scoping layer (ADR 0003) |
| Database | Postgres 16+, row-level security enabled |
| Queue | Postgres (ADR 0007) |
| Front end | SvelteKit — **subject to confirmation, see gate report** |
| Agent | Go, static binary |
| Privileged helper | Go, static binary (ADR 0004) |
| Assets | All self-hosted: fonts, icons, scripts. No external origin at runtime. |

## Consequences

**Makes easy.** Sharing the operation catalogue's types between control plane and
front end. Running the whole control plane as one process plus one database,
which is the entire install story. Auditing what can reach the database, because
there is no DI container to reason through.

**Makes hard.** No Redis means no off-the-shelf pub/sub for log fan-out; that
runs over Postgres `LISTEN/NOTIFY` plus in-process fan-out, which caps a single
control plane at one node until we do the work to change it. Accepted for v1;
the brief rules out multi-region and does not ask for control-plane high
availability.

**What we live with.** Node's runtime type erasure means every trust boundary
needs an explicit schema check — the operation catalogue, webhook payloads,
agent responses. That is enforced by making the catalogue the only way to
construct an instruction, not by discipline.

**New attack surface.** The control plane process holds the instruction signing
key and the secret-wrapping key in memory. Node's lack of memory zeroing means a
core dump or a heap snapshot exposes them. Mitigations: core dumps disabled in
the shipped unit, no heap-snapshot endpoint, and the keys read from files the
application user can read but the site users cannot. Recorded in the threat
model.
