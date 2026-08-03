/**
 * The grant model, as TypeScript sees it (RL-M1-011).
 *
 * A *grant* assigns a role at a scope; a *deny* is the same row pointing the
 * other way. Both live in the `grants` table, and the decision they compose is
 * made by SQL — `grant_decision()` in migration 5 — not here. This module is
 * deliberately thin: it names the vocabulary the database enforces so that
 * `can()` (RL-M1-012) and the repository layer are not each writing their own
 * string literals, and it holds the one comparison that must never be written
 * by hand twice.
 *
 * Nothing here decides anything. If a rule appears both in this file and in the
 * schema, the schema is the enforcement and this file is the mirror —
 * `test/authz/grant_expiry.test.ts` reads the check constraints out of Postgres
 * and fails if the two ever disagree, so the mirror cannot drift into being a
 * second, weaker source of truth.
 */

/**
 * What a grant can be attached to.
 *
 * Brief §6.3: "API tokens carry a subset of the issuing user's permissions and
 * never more." `api_token` exists so a token can hold *less* than its issuer.
 * The ceiling — the intersection with the issuing user, evaluated at use time
 * rather than at issue time — is RL-M1-032 and is not implemented anywhere yet.
 * Resolving an `api_token` subject answers "what does this token name", which
 * is an upper bound to be intersected, never a decision on its own.
 */
export const SUBJECT_TYPES = ["user", "service_identity", "api_token"] as const;

export type SubjectType = (typeof SUBJECT_TYPES)[number];

/**
 * Which way a row points.
 *
 * Brief §6.3: "Denies always win." Precedence is applied in SQL, at any scope
 * and in both directions — a deny below an allow and a deny above an allow both
 * deny — because a decision assembled in application code from separate queries
 * is a decision that can be assembled wrongly.
 */
export const GRANT_EFFECTS = ["allow", "deny"] as const;

export type GrantEffect = (typeof GRANT_EFFECTS)[number];

/** What `grant_decision()` returns. Two values, and only one of them permits. */
export type Decision = "allow" | "deny";

/**
 * The database objects that resolve a decision, in the order they compose.
 *
 * Named here so a test can assert they exist, are invoker-rights, and are the
 * only path to an authorization answer. Reading `grants` directly skips the
 * expiry predicate in `live_grants`, which is the one mistake that would make an
 * expired grant work.
 */
export const RESOLUTION_OBJECTS = {
  /** Every unexpired grant, with the hierarchy node it hangs on resolved. */
  liveGrants: "live_grants",
  /** The grants reaching a subject at a node, after downward inheritance. */
  effectiveGrants: "effective_grants",
  /** Allow or deny: denies win, and an unmatched action is a denial. */
  decision: "grant_decision",
} as const;

/**
 * Whether a decision permits.
 *
 * The comparison is written once, here, because the plausible-looking inverse —
 * `decision !== "deny"` — fails *open* for any value the function does not yet
 * return. Deny by default has to survive being extended.
 */
export function isAllowed(decision: string): boolean {
  return decision === "allow";
}

/** Whether a value names a subject kind the schema accepts. */
export function isSubjectType(value: unknown): value is SubjectType {
  return typeof value === "string" && (SUBJECT_TYPES as readonly string[]).includes(value);
}

/**
 * One row of `effective_grants()`.
 *
 * Field names are the column names, unchanged, because the mapping happens in
 * the repository layer and a rename here would be a second place to get it
 * wrong. `scope_node_id` is null for a resource-scoped grant: a resource is the
 * last level of §6.3's hierarchy and owns no node, so it matches by identity.
 */
export type EffectiveGrant = {
  readonly grant_id: string;
  readonly role_key: string;
  readonly effect: GrantEffect;
  readonly scope_type: string;
  readonly scope_id: string | null;
  readonly scope_node_id: string | null;
  readonly expires_at: Date | null;
};
