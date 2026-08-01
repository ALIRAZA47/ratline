# 0007 — Job queue on Postgres rather than Redis

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-016

## Context

The brief (§6.1) suggests "a Redis-backed queue" as the default stack, and
invites disagreement. This ADR disagrees.

Ratline is self-hosted. Every stateful component is something the operator has
to install, patch, monitor, back up, and reason about during an incident. The
brief's own tiebreaker — favour the team of eight with a production incident at
2am — argues for fewer moving parts in the control plane, not more.

The question is whether the workload actually needs Redis.

## Options considered

### What the workload is

Estimating the real numbers rather than assuming:

- A fleet of 100 hosts heartbeating every 15 seconds is under 7 jobs/second, and
  heartbeats are not queued work — they arrive on an open connection.
- Deployments for a twenty-person team: tens per day, low hundreds on a busy
  day. Call it 500/day worst case, which is 0.006/second average and maybe 20 in
  a burst when someone merges a train of pull requests.
- Certificate renewals, backups, uptime checks and audit verification are all
  scheduled, low-rate, and latency-insensitive.

Peak realistic throughput is tens of jobs per second, in bursts. Postgres with
`SELECT ... FOR UPDATE SKIP LOCKED` handles thousands per second on modest
hardware. We would be provisioning a second datastore for two orders of
magnitude of headroom we will never use.

The one latency-sensitive path is **build log fan-out** to connected browsers,
which is genuinely high-frequency. That is not queue work — it is pub/sub, and
`LISTEN`/`NOTIFY` plus in-process fan-out covers it for a single control plane
node.

### Options

| Option | Pros | Cons | Security assessment |
| --- | --- | --- | --- |
| Redis-backed queue | Mature libraries; very high throughput; good pub/sub | Second stateful service to install, secure, patch, back up; Redis defaults have a long history of exposure incidents; another credential; another thing to get wrong in the install docs | Adds a service that is historically deployed unauthenticated. Against C5's spirit. |
| Postgres queue with `SKIP LOCKED` | No new component; jobs are transactional with the data they mutate; one backup covers everything; one credential | Caps single-node throughput far above what we need; `LISTEN/NOTIFY` fan-out is per-node | Smallest surface. **Chosen.** |
| In-memory queue | Nothing to install | Loses jobs on restart, which is unacceptable for a half-finished deploy | Rejected. |

The transactional property deserves emphasis: enqueueing a deploy job **in the
same transaction** that creates the deployment record removes an entire class of
bug where the row exists and the job does not, or vice versa. With Redis that
requires an outbox pattern, which is more machinery than the queue saved.

## Decision

Postgres-backed job queue.

- Jobs are rows. Claiming uses `SELECT ... FOR UPDATE SKIP LOCKED` with a
  visibility timeout, so a worker that dies releases its job.
- Workers wake on `LISTEN/NOTIFY` and fall back to polling on an interval, so a
  missed notification delays a job rather than losing it.
- Enqueue happens in the same transaction as the state change that caused it.
- Retries use exponential backoff with a dead-letter state that surfaces in the
  interface rather than silently absorbing failures — §9 forbids silent catch
  blocks, and a queue that quietly drops jobs is the same anti-pattern wearing a
  different hat.
- Log fan-out to browsers uses `LISTEN/NOTIFY` plus in-process fan-out.

## Consequences

**Makes easy.** The install story: Postgres and one process. One backup. One
credential. One thing to monitor. Transactional enqueue.

**Makes hard.** Horizontal scaling of the control plane. In-process fan-out
means a browser must be connected to the node holding the stream. For v1 this is
fine — the brief rules out multi-region and does not ask for control-plane high
availability — but it is a real ceiling.

**When to revisit.** Any of:

- Sustained queue throughput above a few hundred jobs per second.
- A requirement for more than one control plane node, for availability or scale.
- Queue load measurably degrading interactive query latency.

If any of those arrives, the fix is a dedicated broker, and the queue interface
is kept narrow enough that swapping the implementation does not touch calling
code.

**New attack surface.** None added; one service's worth removed. The queue
inherits the row-level security model, which means a job row is tenant-scoped
like everything else, and a worker cannot pick up a job it could not read.
