/**
 * The authorization context. Layer 2 of C3 (RL-M1-007, ADR 0003).
 *
 * C3 requires that an unscoped read be *impossible to call*, not merely
 * discouraged. A helper you are supposed to remember is not impossible; a
 * parameter you cannot construct is close.
 *
 * `AuthzContext` carries a brand — a unique symbol that is declared here and
 * exported as a type only. Nothing outside this module can produce a value with
 * that property, so an object literal that looks right does not typecheck:
 *
 *     findSite({ orgId, actor }, id)     // Error: missing [brand]
 *     findSite(ctx, id)                  // fine, ctx came from here
 *
 * The only ways to obtain one are the three constructors below, and each names
 * an actor. That is C6 — no privileged action without a recorded actor — held
 * up by the type system rather than by a convention.
 *
 * `as unknown as AuthzContext` still defeats this, as it defeats any type-level
 * guarantee in TypeScript. That is why layer 3 (row-level security) exists and
 * why the lint rule in RL-M1-008 bans the raw handle outside src/repo/. The
 * point of this layer is not to stop a determined author; it is to make the
 * accidental case impossible and the deliberate case visible in review.
 */

declare const brand: unique symbol;

/** Who is acting. Automation is never anonymous (C6). */
export type Actor =
  | { readonly kind: "user"; readonly id: string }
  | { readonly kind: "service_identity"; readonly id: string; readonly name: string }
  | { readonly kind: "api_token"; readonly id: string; readonly issuedBy: string };

export type AuthzContext = {
  readonly [brand]: true;
  /** The tenant every query in this context is confined to. */
  readonly orgId: string;
  readonly actor: Actor;
  /** Correlates every audit entry and log line for one request (RL-M1-014). */
  readonly requestId: string;
  /** Recorded on audit entries. Null for work with no inbound request. */
  readonly ip: string | null;
};

type ContextInput = {
  readonly orgId: string;
  readonly actor: Actor;
  readonly requestId: string;
  readonly ip?: string | null;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function build(input: ContextInput): AuthzContext {
  // Validated here rather than at the query, because orgId is interpolated into
  // a session setting that every row-level security policy reads. A malformed
  // value would make the policy compare against nothing and return no rows —
  // which fails closed, but as a confusing outage rather than an error.
  if (!UUID.test(input.orgId)) {
    throw new Error(`AuthzContext requires a UUID orgId, got "${input.orgId}"`);
  }
  if (!UUID.test(input.actor.id)) {
    throw new Error(`AuthzContext requires a UUID actor id, got "${input.actor.id}"`);
  }
  if (input.requestId.trim() === "") {
    throw new Error("AuthzContext requires a requestId so audit entries can be correlated");
  }
  return Object.freeze({
    orgId: input.orgId,
    actor: input.actor,
    requestId: input.requestId,
    ip: input.ip ?? null,
  }) as AuthzContext;
}

/**
 * From an authenticated request. The normal path — almost every context in the
 * system comes from here.
 */
export function contextForRequest(input: {
  readonly orgId: string;
  readonly userId: string;
  readonly requestId: string;
  readonly ip?: string | null;
}): AuthzContext {
  return build({
    orgId: input.orgId,
    actor: { kind: "user", id: input.userId },
    requestId: input.requestId,
    ...(input.ip === undefined ? {} : { ip: input.ip }),
  });
}

/** For automation. Named, permissioned, and auditable like any other actor (C6). */
export function contextForServiceIdentity(input: {
  readonly orgId: string;
  readonly serviceIdentityId: string;
  readonly name: string;
  readonly requestId: string;
}): AuthzContext {
  return build({
    orgId: input.orgId,
    actor: { kind: "service_identity", id: input.serviceIdentityId, name: input.name },
    requestId: input.requestId,
  });
}

/** For an API token. Carries who issued it, since its permissions are bounded by theirs. */
export function contextForApiToken(input: {
  readonly orgId: string;
  readonly tokenId: string;
  readonly issuedByUserId: string;
  readonly requestId: string;
  readonly ip?: string | null;
}): AuthzContext {
  return build({
    orgId: input.orgId,
    actor: { kind: "api_token", id: input.tokenId, issuedBy: input.issuedByUserId },
    requestId: input.requestId,
    ...(input.ip === undefined ? {} : { ip: input.ip }),
  });
}

/**
 * Contexts that are deliberately not tenant-scoped, for the handful of jobs
 * that genuinely span the installation: the audit chain verifier, instance
 * administration, migrations.
 *
 * Every one of these is a security review point. The list is enumerated here on
 * purpose, and `test/security/scoped_repository.test.ts` asserts it does not
 * grow silently — adding an entry is a visible, arguable change rather than a
 * new import somewhere.
 */
export const SYSTEM_PURPOSES = [
  "audit-chain-verification",
  "instance-administration",
] as const;

export type SystemPurpose = (typeof SYSTEM_PURPOSES)[number];

/**
 * A context for one of the enumerated system purposes.
 *
 * This still names an actor — a service identity — so C6 holds: there is no way
 * to act without something to attribute it to. It still carries an orgId,
 * because even system work operates on one tenant at a time; there is no
 * "all tenants" context, by design.
 */
export function contextForSystem(input: {
  readonly purpose: SystemPurpose;
  readonly orgId: string;
  readonly serviceIdentityId: string;
  readonly requestId: string;
}): AuthzContext {
  if (!SYSTEM_PURPOSES.includes(input.purpose)) {
    throw new Error(
      `"${input.purpose}" is not an enumerated system purpose. Add it to SYSTEM_PURPOSES ` +
        `deliberately, with review — this list is the set of places that operate outside a ` +
        `user's authority.`,
    );
  }
  return build({
    orgId: input.orgId,
    actor: { kind: "service_identity", id: input.serviceIdentityId, name: `system:${input.purpose}` },
    requestId: input.requestId,
  });
}
