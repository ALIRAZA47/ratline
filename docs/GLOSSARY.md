# Ratline — glossary

**Task:** RL-M0-009

One vocabulary across code, interface copy, documentation and this tracker. If a
term is here, use it exactly; if a concept needs a new term, add it here first so
it does not enter the codebase under three different names.

---

## From the brief (§7)

| Term | Meaning |
| --- | --- |
| **Host** | A machine Ratline manages. **Never "server" in interface copy**, to avoid confusion with the web server. |
| **Site** | A deployable unit — one app or static bundle, one domain set, one systemd unit. |
| **Release** | An immutable timestamped build directory. |
| **Deployment** | The act of producing and activating a release. |
| **Grant** | A role assignment scoped to a node in the hierarchy, optionally time-bound. |
| **Agent** | The Ratline binary running on a host. |
| **Break-glass** | Emergency temporary elevation. |

---

## Added during planning

Each of these named something that already existed in the design and would
otherwise have acquired several names.

| Term | Meaning | Why it was needed |
| --- | --- | --- |
| **Control plane** | The web application, API, workers and database. Never runs customer workloads. | The brief uses it; pinning it here stops "panel", "server" and "backend" drifting in. |
| **Operation** | One entry in the enumerated catalogue the agent will execute, with typed arguments — `site.create`, `release.activate`. | The unit C1 is built on. Not "command", which implies a shell string. |
| **Envelope** | A signed, typed, nonce'd, expiring instruction carrying exactly one operation. | Distinguishes the *authenticated instruction* from the *transport* that carries it (ADR 0002). |
| **Catalogue** | The complete set of operations. Closed by construction. | "The catalogue is closed" is the sentence that explains C1 in one line. |
| **Privileged helper** (`ratline-privd`) | The root, socket-activated, network-less process that performs privileged operations and distrusts the agent. | The component that makes C1 hold against agent compromise (ADR 0004). |
| **Scope path** | The materialised Organization → Team → Project → Environment path on a hierarchy node. | How inheritance resolves in one indexed query (ADR 0003). |
| **Authorization context** | The branded value carrying the actor and tenant, required as the first argument of every repository function. | The mechanism that makes an unscoped read fail to compile (ADR 0003). |
| **Principal** | The name inside an SSH certificate that a host authorises against, derived from a grant. | The join between the permission model and `sshd` (ADR 0008). |
| **Service identity** | A named non-human actor with its own permissions. | C6 — automation is never anonymous. |
| **Crown jewel** | One of the three keys whose compromise is unrecoverable without rotation: SSH authority, instruction signing, secret wrapping. | Used consistently in the threat model. |
| **Tension line** | The 2px stateful rule beneath the top bar; the deploy spine on the live deployment screen. | The signature element (`DESIGN.md`). |
| **Lashing** | The notch marking the active rail item, and a step tick on the deploy spine. | The one place the rigging metaphor is literal. |

---

## Words to avoid

| Do not write | Write instead | Why |
| --- | --- | --- |
| Server | **Host**, or "web server" when that is meant | The brief's rule. The ambiguity is real and costly. |
| Command (for agent instructions) | **Operation** | "Command" implies a shell string, which is exactly what the agent does not accept. |
| Panel, backend, app | **Control plane** | One name for one component. |
| User (for a Linux account) | **Site user** | Distinct from a Ratline user, who is a person. |
| Permission (for an assignment) | **Grant** for the assignment, **permission** only for the raw capability | The distinction matters in the role editor. |
| Deploy (as a noun) | **Deployment** | "Deploy" is the verb. |
| Env | **Environment** | Except in `.env` and environment variable names. |
| Secret (loosely) | **Secret name** or **secret value** | `secret.read_name` and `secret.read_value` are different permissions (§6.3); loose usage hides that. |

---

## Naming conventions from the brief (§1)

| Thing | Convention |
| --- | --- |
| CLI binary | `ratline`, alias `rl` |
| Agent binary | `ratline-agent` |
| Privileged helper | `ratline-privd` |
| Host config | `/etc/ratline` |
| Host state | `/var/lib/ratline` |
| Host logs | `/var/log/ratline` |
| Site root | `/srv/sites/<site-slug>/{releases,shared,current}` |
| Site Linux user | `rl-<site-slug>` |
| systemd unit | `ratline-<site-slug>.service` |

The `rl-` and `ratline-` prefixes are load-bearing, not cosmetic: `privd` uses
them to refuse any operation targeting a user, unit or path outside the Ratline
namespace (ADR 0004).
