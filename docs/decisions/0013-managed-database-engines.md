# 0013 — Managed database engines

**Status:** proposed
**Date:** 2026-08-02
**Task:** RL-M7-001
**Amends:** brief §5.2, which lists managed databases as out of scope for v1

## Context

The brief excludes managed databases from v1 and says explicitly: *"If you find
yourself building an abstraction 'so we can add databases later', stop. Leave a
clean seam and an ADR, not an implementation."* This ADR is that seam, now
requested as real scope: install PostgreSQL, MySQL and MongoDB on managed hosts,
create databases and users, and wire credentials into sites.

**The reason this was excluded is worth stating before the design, because it
changes what the product is.**

Every workload Ratline manages today is *reconstructible*. A site is a git
repository plus a build; if a host burns down, a redeploy restores it. That is
what makes the atomic-release model safe, what makes a failed deploy a
non-event, and what lets `provision twice` be an acceptance criterion.

A database is not reconstructible. A dropped database, a botched major-version
upgrade, or a restore run against the wrong instance destroys the thing the
business actually sells. Adding databases moves Ratline from *"if it breaks,
redeploy"* to *"if it breaks, you may have lost the company's data"* — and every
subsequent design decision has to be re-weighed against that, including ones
already made.

Three already-accepted decisions are affected:

- **ADR 0009 (build on the target host).** Acceptable when contention degrades a
  build. Less acceptable when the noisy neighbour is the production database.
- **ADR 0005 (build commands are contained, not eliminated).** A build running as
  the site user is one sandbox boundary from a database socket on the same host.
- **§6.5 backups** currently mean site files and configuration. A file-level copy
  of a running database directory is not a backup; it is a corrupt snapshot that
  looks like one.

## Options considered

### Should Ratline manage databases at all?

| Option | Assessment |
| --- | --- |
| Keep them out of scope; document connecting to a managed service | Preserves the reconstructible-workload property entirely. Costs the operator a second vendor and a second bill, which is much of why they self-host. |
| Manage the engine, but not the data lifecycle — install and create only, no backup or restore | Worst of both. The operator believes Ratline owns the database and discovers at the worst moment that it does not own recovery. Rejected outright: a half-managed database is more dangerous than an unmanaged one. |
| **Manage them fully, with backup and tested restore as a precondition rather than a follow-up** | The only honest version. **Chosen**, with the sequencing constraint below. |

### Where do database engines run?

| Option | Assessment |
| --- | --- |
| On the same host as the sites | Cheapest and matches the incumbents. Puts user-authored build code (ADR 0005) on the same machine as the data. |
| **On hosts designated for data, with sites refused on them by default** | A host gains a `role` — `application` or `data`. Placing a site on a data host requires the same deliberate acknowledgement pattern as a public bind (C5). **Chosen.** |
| One engine instance per site | Strongest isolation, poor density, and multiplies the upgrade surface by the number of sites. Rejected for v1 of this milestone; the schema does not preclude it. |

### How are databases and users created?

This is where the injection risk is, and it is **not** the same shape as C2.

C2 is about shell strings, and the answer there is argv arrays. That answer does
not transfer: **SQL DDL cannot parameterise identifiers.** `CREATE DATABASE $1`
is not valid in PostgreSQL or MySQL. A database name, a user name and a role
name all have to be interpolated into the statement text, which is precisely the
construction C2 exists to forbid everywhere else.

| Option | Assessment |
| --- | --- |
| Interpolate the name directly | The obvious implementation and a textbook SQL injection. Rejected. |
| Shell out to `createdb` / `mysqladmin` with argv | Satisfies C2's letter by moving the problem to a command line, and the identifier is still interpolated into SQL by the tool. Also adds a shell path C1 spent M2 removing. Rejected. |
| **Generate the identifier ourselves; validate against a strict pattern; quote with the engine's own quoting function; never accept a user-supplied identifier verbatim** | **Chosen.** See below. |

The rule: **the operator names a database in the interface; Ratline derives the
actual identifier.** A user-supplied label never becomes an identifier. The
derived identifier matches `^[a-z][a-z0-9_]{0,62}$` by construction, is checked
against that pattern before use, and is then quoted with `quote_ident`
(PostgreSQL), backtick-doubling (MySQL) or rejected outright if it would need
escaping at all (MongoDB, where database names cannot be quoted).

Belt and braces, because "the identifier is safe by construction" is exactly the
assurance that decays: a fuzz test pushes SQL metacharacters, unicode
normalisation forms and reserved words through every label field that can reach
a DDL statement, and the security suite treats an escape as a critical finding.

## Decision

**Add M7 — Managed databases**, after M6, with these properties.

**1. Backup and tested restore land before create-and-delete is exposed.**
Not after. The milestone is ordered so that the first thing that works is taking
a dump and restoring it into a scratch instance, verified byte-for-byte. Only
then do database creation and deletion become available in the interface. This
is the sequencing constraint that makes the difference between managing
databases and merely installing them.

**2. Engines are installed through the enumerated operation catalogue** (C1,
ADR 0002/0004). `database.engine.install` is a `privd` operation with a version
argument validated against a known set — not a package name passed through.

**3. Databases bind to loopback by default**, the same posture and for the same
reason as C5. Remote access requires an explicit acknowledgement, a firewall
rule, and TLS; the interface warns for as long as it lasts.

**4. Credentials are generated, never defaulted** (C4), envelope-encrypted at
rest (ADR 0006), write-only in the interface once set, and injected into sites
as an environment variable. `database.read_credentials` is a distinct action
from `database.read`, mirroring `secret.read_value` versus `secret.read_name` —
most roles need to know a database exists; almost none need its password.

**5. Restore is the most dangerous action in the product** and gets its own
permission, its own confirmation naming the target, and an audit entry recorded
before it begins rather than after it succeeds.

**6. MongoDB is scheduled last and separately.** It is not a variation on the
SQL engines: a different auth model, different backup tooling, no meaningful DDL
quoting story, and an SSPL licence that an operator should be told about rather
than have chosen for them.

**7. Major-version upgrades are explicitly NOT in M7.** In-place upgrade is
where irreversible data loss actually happens. M7 pins a version at install and
supports minor updates only; upgrades get their own milestone and their own
gate, or stay a documented manual procedure.

## Consequences

**Makes easy.** The thing operators most often leave the platform for. A site
and its database provisioned, connected and backed up in one place, with the
same permission model over both.

**Makes hard.** Everything about the product's failure story. Chaos tests,
rollback, and "provision twice idempotently" all assumed reconstructible
workloads. Each needs re-examining against a stateful one, and `RL-M7-002`
exists to do that rather than to assume it.

**What we live with.** Ratline becomes responsible for data it cannot
regenerate. That is a support burden and a reputational risk, not just an
engineering one — and it is the reason the brief excluded it. Taking it on is a
legitimate decision; taking it on without noticing the change is not.

**New attack surface**, all of it significant:

- A DDL path where identifiers cannot be parameterised — the one place in the
  system where the C2 answer does not apply.
- Long-lived database credentials distributed to site environments, which means
  a compromised site user holds a working credential to its own data. Scoped per
  site, per database, least-privilege by default.
- A listening database service on managed hosts. Loopback by default; the
  no-inbound-listener test from RL-M2-006 needs an explicit, argued exception
  rather than a quiet deletion.
- Backup archives containing the entire dataset, encrypted before leaving the
  host (ADR 0006) and covered by the same tenant-isolation test as everything
  else.

## Open question for the brief

**Does this belong in v1, or after it?** Planned here as M7, after M6, on the
grounds that M1–M6 are unfinished and that a milestone which can lose data
deserves its own gate rather than being folded into others. If it should be v1
scope instead, §5.2 needs amending and the M3–M6 sequencing should be revisited
— several of those milestones would want to know that stateful workloads exist.
