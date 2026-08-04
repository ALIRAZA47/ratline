/**
 * Enrolling a host, and looking up the key that authenticates it (RL-M2-005).
 *
 * ADR 0002 as amended by A-04: a host registers an Ed25519 signing key at enrolment via
 * a single-use short-lived token, and the key is individually revocable.
 *
 * ## The one function here that resolves no permission, and why
 *
 * `registeredKeyFor` is called while authenticating a connection — before there is an
 * actor, because the point of the call is to find out who is connecting. It is the same
 * pre-authentication seam ADR 0014 records for sign-in, and
 * `test/security/repository_gating.test.ts` requires that argument to be written down
 * rather than assumed.
 *
 * What stands in for a permission is that the function can only ever return a key: it
 * takes a fingerprint and returns the row matching it, and there is no variant that
 * lists keys or takes a host id. A caller holding a fingerprint already holds the public
 * key it hashes.
 *
 * Everything else here requires `host.create`, `host.read` or `host.update`, resolved at
 * the data layer as C3 demands.
 *
 * ## Why the token is hashed and the key is not
 *
 * The enrolment token is a CREDENTIAL: presenting it is sufficient to register a key for
 * a host. So only its SHA-256 is stored — a token in the database is readable by every
 * backup, every replica, and every `pg_dump` in somebody's downloads folder.
 *
 * The signing key is a PUBLIC key. Storing it in full is not storing a secret, and an
 * incident needs to see exactly what was trusted.
 */

import { createHash, randomBytes } from "node:crypto";

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import { require as requirePermission } from "../authz/can.ts";
import { organizationScopeRef } from "./scope.ts";
import { fingerprint as fingerprintOf, type RegisteredKey } from "../crypto/host_identity.ts";

/**
 * How long an enrolment token lives.
 *
 * Ten minutes. An operator runs the install command with the token in hand, so the
 * window only has to cover one command — and acceptance 4 says "short lived", which is a
 * property of how long a stolen token is worth stealing.
 */
export const ENROLMENT_TOKEN_TTL_MS = 10 * 60 * 1000;

/** How long a registered key is valid before it must be rotated. */
export const KEY_LIFETIME_MS = 365 * 24 * 60 * 60 * 1000;

export class EnrolmentRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnrolmentRefused";
  }
}

export type Host = {
  readonly id: string;
  readonly name: string;
  readonly lastSeenAt: Date | null;
};

export type Enrolment = {
  readonly hostId: string;
  /**
   * The token, in plaintext, returned EXACTLY ONCE.
   *
   * Never read back — only its hash is stored. An operator who loses it revokes the
   * enrolment and mints another, which is a smaller cost than a readable credential.
   */
  readonly token: string;
  readonly expiresAt: Date;
};

const hashToken = (token: string): Buffer => createHash("sha256").update(token).digest();

/** Create a host and the single-use token that lets it register a key. */
export async function enrolHost(
  ctx: AuthzContext,
  name: string,
  now: Date = new Date(),
): Promise<Enrolment> {
  await requirePermission(ctx, "host.create", await organizationScopeRef(ctx));

  const trimmed = name.trim();
  if (trimmed === "") {
    throw new EnrolmentRefused("a host needs a name, so an operator can tell one from another.");
  }

  // 32 bytes, base64url. Long enough that guessing is not a strategy, and URL-safe
  // because it travels in a header.
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(now.getTime() + ENROLMENT_TOKEN_TTL_MS);

  return scoped(ctx, async (query) => {
    const hosts = await query<{ id: string }>(
      "insert into hosts (org_id, name) values (current_tenant(), $1) returning id",
      [trimmed],
    );
    const hostId = hosts[0]?.id;
    if (hostId === undefined) throw new EnrolmentRefused("the host could not be created.");

    await query(
      `insert into host_enrolments (org_id, host_id, token_hash, expires_at, created_by)
       values (current_tenant(), $1, $2, $3, $4)`,
      [hostId, hashToken(token), expiresAt, ctx.actor.id],
    );

    return { hostId, token, expiresAt };
  });
}

/**
 * Redeem a token and register the host's public key.
 *
 * NO PERMISSION IS RESOLVED, and the token is what stands in for one — the caller is a
 * host that has not been authenticated yet, so there is no actor to check. That is the
 * same seam as `enrolHost`'s opposite: one is an operator creating an invitation, this
 * is the invitation being used.
 *
 * The update is CONDITIONAL, not a read followed by a write. `where spent_at is null`
 * inside the statement means two agents presenting the same token concurrently cannot
 * both succeed: one updates a row, the other updates none. A `select` then an `update`
 * would have a window between them, and both would win it.
 */
export async function redeemEnrolment(
  ctx: AuthzContext,
  token: string,
  publicKeyPem: string,
  now: Date = new Date(),
): Promise<{ readonly hostId: string; readonly fingerprint: string }> {
  return scoped(ctx, async (query) => {
    const spent = await query<{ host_id: string }>(
      `update host_enrolments
          set spent_at = $1
        where token_hash = $2
          and spent_at is null
          and expires_at > $1
        returning host_id`,
      [now, hashToken(token)],
    );

    const hostId = spent[0]?.host_id;
    if (hostId === undefined) {
      // ONE refusal for every reason: unknown token, already spent, expired, wrong
      // tenant. Distinguishing them would tell whoever is guessing which guesses are
      // getting warmer — that an unknown token differs from a spent one is exactly the
      // hint an attacker wants.
      throw new EnrolmentRefused(
        "this enrolment token cannot be used. It may be unknown, already redeemed, or " +
          "expired — the answer is deliberately the same for all three. Mint a new one.",
      );
    }

    let fingerprint: string;
    try {
      fingerprint = fingerprintOf(publicKeyPem);
    } catch {
      throw new EnrolmentRefused("the public key could not be read as SPKI PEM.");
    }

    await query(
      `insert into host_keys (org_id, host_id, public_key_pem, fingerprint, expires_at)
       values (current_tenant(), $1, $2, $3, $4)`,
      [
        hostId,
        publicKeyPem,
        Buffer.from(fingerprint, "hex"),
        new Date(now.getTime() + KEY_LIFETIME_MS),
      ],
    );

    return { hostId, fingerprint };
  });
}

/**
 * The key a fingerprint identifies, for authenticating a connection.
 *
 * Returns a REVOKED key rather than null, deliberately. The caller — `verifyChallenge` —
 * refuses a revoked key itself and does so before examining the signature, which is
 * where that refusal belongs: returning null here would make "revoked" and "never
 * existed" the same answer, and the connection handler would then have to guess which
 * refusal to record in the audit log.
 *
 * Expired keys ARE filtered out, because an expiry is not a security event and there is
 * nothing to record about one.
 */
export async function registeredKeyFor(
  ctx: AuthzContext,
  fingerprint: string,
  now: Date = new Date(),
): Promise<RegisteredKey | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ host_id: string; public_key_pem: string; revoked_at: Date | null }>(
      `select host_id, public_key_pem, revoked_at
         from host_keys
        where fingerprint = $1
          and expires_at > $2`,
      [Buffer.from(fingerprint, "hex"), now],
    );

    const row = rows[0];
    if (row === undefined) return null;
    return { hostId: row.host_id, publicKeyPem: row.public_key_pem, revokedAt: row.revoked_at };
  });
}

/**
 * Revoke a host's key. Takes effect on the next connection, because that is when the
 * next lookup happens — there is no list to distribute and no cache to expire.
 */
export async function revokeHostKey(
  ctx: AuthzContext,
  hostId: string,
  reason: string,
  now: Date = new Date(),
): Promise<boolean> {
  await requirePermission(ctx, "host.update", await organizationScopeRef(ctx));

  const stated = reason.trim();
  if (stated === "") {
    // The schema requires a reason alongside the time. Enforced here too, with a message
    // an operator can act on rather than a constraint violation.
    throw new EnrolmentRefused(
      "revoking a key needs a reason, because a revocation nobody can explain later is " +
        "one somebody will undo.",
    );
  }

  return scoped(ctx, async (query) => {
    const revoked = await query<{ id: string }>(
      `update host_keys
          set revoked_at = $1, revoked_reason = $2, revoked_by = $3
        where host_id = $4
          and revoked_at is null
        returning id`,
      [now, stated, ctx.actor.id, hostId],
    );
    return revoked.length > 0;
  });
}

/** Hosts in this tenant. */
export async function listHosts(ctx: AuthzContext): Promise<Host[]> {
  await requirePermission(ctx, "host.read", await organizationScopeRef(ctx));

  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string; name: string; last_seen_at: Date | null }>(
      "select id, name, last_seen_at from hosts order by name",
    );
    return rows.map((row) => ({ id: row.id, name: row.name, lastSeenAt: row.last_seen_at }));
  });
}

/**
 * Record that a host connected.
 *
 * The address is OBSERVED on an authenticated connection rather than supplied at
 * enrolment: an address somebody sends is a claim, an address a connection came from is
 * an observation. No permission — the caller is the connection handler, acting for the
 * host itself, and there is no actor beyond the one that just authenticated.
 */
export async function recordHostSeen(
  ctx: AuthzContext,
  hostId: string,
  ip: string | null,
  now: Date = new Date(),
): Promise<void> {
  await scoped(ctx, async (query) => {
    await query("update hosts set last_seen_at = $1, last_seen_ip = $2 where id = $3", [
      now,
      ip,
      hostId,
    ]);
  });
}
