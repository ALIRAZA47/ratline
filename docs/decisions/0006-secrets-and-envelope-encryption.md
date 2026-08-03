# 0006 — Secrets, envelope encryption and redaction

**Status:** proposed
**Date:** 2026-08-01
**Task:** RL-M0-015

## Context

C4 forbids default secrets of any kind. §6.5 requires per-environment variables
with envelope encryption at rest, write-only behaviour in the interface once
set, automatic redaction anywhere a value could reach a build log or an error
trace, and change history that records who and when but never the value. §6.3
makes `secret.read_value` a distinct permission from `secret.read_name`, and
notes that almost no role should hold the former.

The hard part is not encryption. It is the leakage paths: a value has to reach a
build environment on a host, which means it exists in plaintext somewhere on
that host, and build tools print their environment when they crash.

## Options considered

### Key hierarchy

| Option | Assessment |
| --- | --- |
| Single key encrypts every secret | One key rotation re-encrypts everything; no per-secret granularity. Rejected. |
| Envelope: per-secret data key, wrapped by a key-encryption key | Rotating the wrapping key rewraps small data keys rather than re-encrypting values; per-secret keys limit the blast radius of a single leak. **Chosen** — and it is what the brief asks for. |

### Where the key-encryption key lives

| Option | Assessment |
| --- | --- |
| In the database | Encrypting the database with a key in the database. Rejected. |
| Environment variable | Visible in `/proc`, in process listings, in crash dumps, in orchestrator config. Weak. |
| File on the control plane, restrictive mode, generated at first run | Simple, no extra infrastructure, appropriate for self-hosted. **Chosen for v1.** |
| External key manager | Right answer for larger deployments, but a dependency v1 should not require. **Left as a seam.** |

### Where redaction happens

This is the decision that matters most.

| Option | Assessment |
| --- | --- |
| In the browser | Values have already crossed the network and been stored. Cosmetic. Rejected. |
| In the control plane as logs arrive | Better, but the value has already left the host and been transmitted. Rejected. |
| On the host, before a log line is transmitted | The value never leaves the machine that legitimately holds it. **Chosen.** |

The agent already knows the values — it writes the environment file — so it is
the only component that can redact without being *given* something new.

## Decision

**Key hierarchy.** Each secret value gets a fresh 256-bit data key. The value is
sealed with AEAD under that data key. The data key is wrapped by the
key-encryption key. Ciphertext, wrapped key and a key version are stored
together. The secret's *name* is stored in plaintext, because
`secret.read_name` needs to work without unwrapping anything.

**Key-encryption key.** Generated from a cryptographic source at first run,
written to a file readable only by the control plane user, never in the database
and never in a backup that also contains the database. The application refuses
to boot if it is missing, and refuses to boot if it looks like a placeholder.
RL-M1-022 greps the built artifact for known-default patterns and fails if any
are present.

**Rotation.** Rotating the key-encryption key rewraps data keys only. Rotating a
secret's value creates a new version. Version history records actor and
timestamp and never the value — including never in the audit log's metadata,
which is a real trap because the audit log is otherwise the place we record
everything.

**Delivery to hosts.** Values are sent only to the agent on the host that runs
the site, only for the sites on that host, only over the mTLS channel, and are
written directly to an environment file owned by the site user with mode 0600.
They are never written to the release directory, never included in a build
artifact, and never passed as process arguments — arguments are world-readable
in `/proc`.

**Redaction.** The agent holds the active values for its sites and scrubs
matches from any output stream before transmission. Requirements that make this
more than a naive `String.replace`:

- Streaming-safe across chunk boundaries — a value split across two writes must
  still be caught, so the scrubber keeps a rolling tail buffer.
- Covers common encodings: base64, URL-encoding, and JSON string escaping.
- Skips very short values, which would redact ordinary text and destroy log
  usability; values below a threshold are refused at set time with an
  explanation instead.
- Applies identically to build logs, application logs, one-off command output,
  scheduled job output, notification payloads and error traces.

RL-M3-018 plants secrets in build output and asserts none reach storage or the
browser.

**Error traces.** The control plane's error serialiser has an allowlist of
serialisable fields rather than a denylist of secret ones. Structured log fields
pass through the same scrubber.

## Consequences

**Makes easy.** Stating precisely who can see a value: only a holder of
`secret.read_value`, and the site's own process. Rotating the wrapping key
cheaply.

**Makes hard.** Debugging a build that fails *because* of redaction — a log line
reading `[redacted]` where a value was expected is confusing. Mitigation: the
interface says which secret name was redacted, never the value.

**What we live with.** Secrets exist in plaintext in an environment file on the
host, readable by the site user. That is inherent to running a process with
environment variables; anyone who can execute as the site user can read them.
The boundary is the site user, and it is the same boundary the whole design
rests on.

**New attack surface.** The key-encryption key file is a single high-value
target on the control plane. Compromise means every secret in the installation.
Mitigations: filesystem permissions, exclusion from database backups, no core
dumps, and the external-key-manager seam for installations that need more.
Recorded in the threat model as one of the three crown-jewel keys, alongside the
instruction signing key (ADR 0002) and the SSH certificate authority key
(ADR 0008).
