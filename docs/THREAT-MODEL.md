# Ratline — threat model

**Version:** v1 (M0)
**Date:** 2026-08-01
**Task:** RL-M0-021
**Updated at every milestone gate; the gate report shows the diff.**

---

## 1. Scope and assumptions

Ratline manages hosts an organization already owns. Per §3.4 there is **no
multi-tenancy across untrusted customers** — tenants are teams inside one
organization who broadly trust each other but should not have unnecessary
access. That shapes what counts as a finding: a Developer reaching production
secrets is a serious defect; a Developer being able to see that a production
project *exists* is not.

Assumed out of scope for v1: physical access to hosts, a malicious Linux
distribution package, a compromised Git provider, and a hostile hypervisor.

---

## 2. Assets, ranked

| # | Asset | Why it ranks here |
| --- | --- | --- |
| 1 | **SSH certificate authority key** | Mints a certificate with any principal for any host — a shell as any site user, fleet-wide. Strictly worse than #2 because it grants a shell rather than a fixed operation set. |
| 2 | **Instruction signing key** | Commands any agent, but only within the enumerated catalogue. Unprivileged code execution fleet-wide, not root. |
| 3 | **Secret-wrapping key** | Unwraps every secret in the installation. |
| 4 | Database contents | Grants, audit chain, configuration, wrapped secrets. |
| 5 | Per-host agent client certificates | Impersonates one host. |
| 6 | Site data and releases | The customer-facing product. |
| 7 | Audit log integrity | The ability to reconstruct what happened. |

Assets 1–3 are the crown jewels and all live on the control plane. That
concentration is the single biggest structural risk in the design, and §5.2
below is its honest accounting.

---

## 3. Actors

| Actor | Trust | Notes |
| --- | --- | --- |
| Owner / Admin | High | Can do damage legitimately; the control is auditability, not prevention. |
| Infrastructure | Medium-high | Manages hosts and SSH grants. **Cannot read production secret values.** |
| Release Manager | Medium | Deploys and rolls back production. No server config, no secret values. |
| Developer | Medium-low | Non-production deploys, logs, own keys, secret *names* only. |
| Viewer / Billing | Low | Read-only, or billing with no infrastructure visibility at all. |
| Service identity | Scoped | Automation. Never anonymous — C6. |
| External unauthenticated | None | Reaches the agent endpoint and any published site. |

---

## 4. Constraint-to-threat trace

Every hard constraint exists because of a specific failure. Recording the trace
so a future session does not "simplify" a constraint whose purpose was lost.

| Constraint | Threat it defends against | Where it is enforced | Evidence |
| --- | --- | --- | --- |
| **C1** no root SSH | Command injection escalating to host compromise (Coolify, CVSS 10.0) | Enumerated operation catalogue (ADR 0002) + unprivileged agent with a distrusting root helper (ADR 0004) | RL-M2-002, RL-M2-008, RL-M2-029 |
| **C2** no string-built shells | Injection through any user-controllable field | Argv-only execution; build-failing lint; schema-driven fuzz corpus (ADR 0005) | RL-M2-027, RL-M2-028, RL-M1-008 |
| **C3** authorization at the data layer | Cross-tenant IDOR (Coolify) | Unreachable raw handle + branded context + forced RLS (ADR 0003) | RL-M1-006, RL-M1-007, RL-M1-026 |
| **C4** no default secrets | Forged cookie signed with a shipped key (CloudPanel CVE-2023-35885) | First-run generation, refusal to boot, artifact grep | RL-M1-022 |
| **C5** not internet-exposed | ~52,000 publicly exposed Coolify instances, Jan 2026 | Loopback default, reachability detection, separate agent listener | RL-M1-023 |
| **C6** attributable actions | Unattributable "system" changes | No audit write path without an actor | RL-M1-016 |

---

## 5. The three required compromise scenarios

### 5.1 Compromised agent

An attacker fully controls `ratline-agent` on one host, as the unprivileged
`ratline-agent` user.

**They can:** read and write inside site directories that agent manages; read
the active secret values for sites on that host (it writes the environment
files); lie to the control plane about that host's inventory and health; request
catalogued privileged operations for that host, which `privd` will perform if
the arguments validate — so they can create a site user, install a *validated*
unit or vhost, restart a Ratline-namespaced service; disrupt service on that
host.

**They cannot:** obtain arbitrary root — `privd` accepts only enumerated
operations, re-validates every argument independently, and identifies its caller
by peer credentials (ADR 0004); touch units, files or services outside the
Ratline namespace; reach any other host — no lateral network path, and the
client certificate authenticates one host only; forge an instruction — they hold
no signing key; read the control plane database; erase their tracks — `privd`
writes its own root-owned append-only log before acting, and ships it.

**Residual risk.** Secrets for sites on that host are exposed. That is inherent:
a process running the site must have its environment. Mitigation is blast-radius
limitation (per-host, per-site) and detection, not prevention. **Detection is
currently weak** — a compromised agent reporting plausible-but-false inventory
would not be caught. Tracked as R-07.

### 5.2 Compromised control plane

An attacker controls the control plane process.

**They can:** issue any catalogued operation to every host in the fleet; unwrap
every secret; mint SSH certificates with any principals, which is a shell as any
site user on any host; read and write all data; issue and forge sessions.
Because they hold the signing key, agents will obey them — correctly, since from
the agent's perspective these are legitimate instructions.

**They cannot** — and this is the C1 payoff — **run an arbitrary command on a
host directly.** The catalogue is closed. They can, however, create a site with
a chosen build command and deploy it, which yields code execution as that site's
user. So control plane compromise means **unprivileged code execution fleet-wide
plus a shell via the certificate authority**, not instant root.

Honestly: with the SSH authority key in hand, the distinction narrows
considerably. Root still requires a local privilege escalation from a site user,
which is a real barrier but not one to lean on.

**Mitigations, some of which are v1 and some are not:**

- Keys are files outside the database, so a database backup leak is not key
  compromise. *(v1, ADR 0006)*
- No core dumps; no heap-snapshot endpoint. *(v1, ADR 0001)*
- C5 keeps the dashboard off the public internet, which is the main route in.
  *(v1, RL-M1-023)*
- The external key manager seam exists but is **not implemented in v1**.
- **Not in v1, and worth considering:** second-human approval for the highest-risk
  operations (adding a host, installing a sudoers fragment, certificate authority
  operations). Raised in the gate report as a scope question rather than added
  unilaterally.

### 5.3 Compromised low-privilege user account

A Developer's account or session is taken over.

**They can:** deploy to non-production; read logs (redacted); see secret names;
manage their own SSH keys; see project and site structure.

**They cannot:** read secret values — `secret.read_value` is a separate action
almost no role holds; deploy to production — a distinct action; change server
configuration; open a web terminal — its own permission, off by default for every
role except Infrastructure; reach another tenant's resources — the query cannot
see them.

**The real risk is lateral, and it is the sharpest finding in this model.** If a
Developer can set a build command on a non-production site (ADR 0005), they get
code execution as that site's Linux user. If that host also runs production
sites, they are then **one sandbox escape away from production data** — and the
sandbox is Linux users plus systemd, not a namespace.

Controls: `site.build_command.write` is a distinct permission, so this is an
explicit grant rather than a side effect of Developer; per-site users and
directory modes; systemd sandboxing; the escape test (RL-M3-006).

**The structural mitigation is not to co-locate production and non-production
sites.** The interface should warn when an operator does, and the documentation
should recommend against it (ADR 0009). Tracked as R-05.

---

## 6. Crown-jewel key handling

| | SSH authority key | Instruction signing key | Secret-wrapping key |
| --- | --- | --- | --- |
| **Generated** | First use of SSH features | First run | First run |
| **Stored** | File, control plane, restrictive mode, outside the database | Same | Same |
| **In backups** | Excluded from database backups | Excluded | Excluded |
| **Rotation** | New authority, distribute, remove old, revoke outstanding | Overlap window, agents accept both | Rewrap data keys only |
| **If compromised** | See below | Rotate; audit every instruction in the window | Rotate; treat every secret as disclosed and force rotation of all of them |

**SSH authority compromise recovery.** Generate a new authority. Distribute the
new trusted-authority file to every host. Remove the old authority. Revoke every
outstanding certificate. **Any host unreachable during this process still trusts
the compromised authority** — which is why the procedure must be exercised, and
why the set of unreachable hosts must be reported loudly rather than skipped
over. Tracked as R-06.

---

## 7. Attack surface inventory

| Surface | Exposure | Pre-auth reachable | Primary control |
| --- | --- | --- | --- |
| Dashboard listener | Loopback by default | No | C5, session auth, rate limits |
| Agent endpoint | May be public | TLS handshake only | Client certificate required before application code runs |
| Webhook receiver | Public | Signature check | Constant-time verify before parse; replay rejection |
| Published sites | Public | Yes | Not Ratline's code; isolation is per-site users |
| `privd` unix socket | Local, agent user | No | Peer credentials + independent argument re-validation |
| Host `sshd` | Per firewall policy | Certificate check | Short-lived certificates, principals, revocation list |
| Object storage | Outbound only | No | Client-side encryption before upload |

---

## 8. Residual risks

Carried into `RISKS.md` with owners. Listed here rather than hidden.

| ID | Risk | Why it is not solved in v1 |
| --- | --- | --- |
| R-04 | Response *timing* may distinguish nonexistent from unauthorized even when status and body match | Full timing equalisation is costly; body-level indistinguishability is tested, timing is not |
| R-05 | Production and non-production sites on one host are separated by user + systemd, not a namespace | Containers are out of scope (§5.2). Mitigated by warning and documentation |
| R-06 | A host unreachable during authority rotation keeps trusting the old authority | Inherent to offline hosts; mitigated by loud reporting |
| R-07 | A compromised agent reporting false inventory would not currently be detected | No cross-checking of agent claims in v1 |
| R-08 | All three crown-jewel keys live on one machine | External key manager is a seam, not v1 scope |
| R-09 | Build resource contention is bounded by limits but not eliminated | I/O and page cache are not partitioned by `CPUQuota` |
| R-11 | A reverse proxy, NAT port-forward or load balancer in front of the dashboard makes it public, and the C5 exposure check reports `contained` | Detection is local by decision (ADR 0011); an outbound probe would phone home from every install and fail on the isolated networks C5 protects. Mitigated by stating the blind spot in every report and in `docs/NETWORK.md`, not by detection |
| R-12 | An `api_token` grant can be written directly, with no intersection against the permissions of the user who issued it | The subject kind exists from RL-M1-011, but the ceiling §6.3 requires ("never more than the issuing user") is enforced in RL-M1-032, which has not landed. Until it does, a token's permissions are whatever its grants say |
| R-13 | A disabled user's grants still resolve to allow | "May this actor act at all" is one question per request, not one per hierarchy node, so `users.disabled_at` belongs in `can()` (RL-M1-012) rather than in the grant resolution functions. Recorded so the omission does not read as an oversight |

---

## 9. Diff since last gate

First version. No diff.
