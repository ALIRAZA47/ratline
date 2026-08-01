/**
 * `can()` — the one place an authorization question is answered (RL-M1-012).
 *
 * Brief §6.3: "One central can(actor, action, resource, context) decision
 * function. No permission logic anywhere else. 100% branch coverage on this
 * module, enforced in CI."
 *
 * Every branch below denies except one. That is not stylistic — it is what
 * "deny by default" means when written out: the function has a single path to
 * `allowed: true`, and everything else, including every error, arrives at a
 * denial. An unmapped action, an unknown scope, a disabled account, a database
 * that will not answer: all deny.
 *
 * The decision carries a REASON. Three consumers need it and none of them can
 * be given a bare boolean:
 *   - the audit log records why, not just what (§6.3);
 *   - the role editor's live preview explains a denial to whoever is toggling
 *     permissions (RL-M5-004), and must call THIS function rather than
 *     reimplement it;
 *   - an operator at 2am needs to know whether they lack a grant or are being
 *     actively denied, because the remedies are different.
 *
 * What this module deliberately does NOT do:
 *   - cache. Brief §6.3 requires role changes to take effect immediately,
 *     including on active sessions (RL-M1-018). A cache here is the obvious
 *     optimisation and would break that requirement silently.
 *   - know about routes, HTTP, or the shape of a request.
 *   - own precedence, inheritance or expiry. Those live in the database
 *     (ADR 0012); duplicating them here would give one question two answers.
 */

import { ACTION_CATALOGUE, isAction, type Action } from "./catalogue.ts";
import { ALL_DEFAULT_ROLES } from "./roles.ts";
import { isAllowed, type SubjectType } from "./grants.ts";
import type { Actor, AuthzContext } from "./context.ts";
import {
  findActorStatus,
  hasAllowingGrant,
  resolveGrantDecision,
  scopeNodeExists,
  type ScopeRef,
} from "../repo/authorization.ts";

/**
 * Why a decision came out the way it did.
 *
 * Every value except `granted` is a denial. Adding one is adding a denial
 * unless the `allowed` mapping below is changed deliberately.
 */
export const DECISION_REASONS = [
  "granted",
  "no-grant",
  "explicit-deny",
  "unknown-action",
  "unknown-scope",
  "actor-disabled",
  "actor-not-in-tenant",
  "no-role-carries-action",
] as const;

export type DecisionReason = (typeof DECISION_REASONS)[number];

export type AuthorizationDecision = {
  readonly allowed: boolean;
  readonly reason: DecisionReason;
  /** Echoed so an audit entry needs no second lookup. */
  readonly action: string;
  readonly scopeNodeId: string;
  readonly resourceId: string | null;
};

function decide(
  reason: DecisionReason,
  action: string,
  scope: ScopeRef,
): AuthorizationDecision {
  return {
    // The single path to true. Written as an equality against one literal
    // rather than as a list of denials, so a reason added later denies until
    // someone deliberately says otherwise.
    allowed: reason === "granted",
    reason,
    action,
    scopeNodeId: scope.scopeNodeId,
    resourceId: scope.resourceId,
  };
}

/** Map an actor to the subject type the grant tables use. */
function subjectOf(actor: Actor): { type: SubjectType; id: string } {
  switch (actor.kind) {
    case "user":
      return { type: "user", id: actor.id };
    case "service_identity":
      return { type: "service_identity", id: actor.id };
    case "api_token":
      return { type: "api_token", id: actor.id };
  }
}

/**
 * Which default roles carry this action.
 *
 * Computed from the role definitions rather than stored, so a role losing an
 * action loses it here in the same commit. Custom roles (RL-M5-001) will add
 * their own keys to this list from the database; the shape is ready for that.
 */
export function rolesCarrying(action: Action): string[] {
  return ALL_DEFAULT_ROLES.filter((role) => role.actions.includes(action)).map((role) => role.key);
}

/**
 * May this actor take this action on this resource?
 *
 * Returns a decision rather than throwing, because a denial is an ordinary
 * outcome that the caller must audit — not an exception.
 */
export async function can(
  ctx: AuthzContext,
  action: string,
  scope: ScopeRef,
  /**
   * Which roles carry an action. Defaults to the built-in role definitions.
   *
   * A parameter rather than a fixed lookup because custom roles (RL-M5-001)
   * come from the database, and the alternative — a second decision path for
   * custom roles — is exactly the "permission logic elsewhere" §6.3 forbids.
   * It also makes the empty-role branch below reachable, which the 100% branch
   * coverage gate in RL-M1-013 requires.
   */
  resolveRoles: (action: Action) => readonly string[] = rolesCarrying,
): Promise<AuthorizationDecision> {
  // 1. An action not in the catalogue is a denial, not an error. The catalogue
  //    is closed (RL-M1-009); a name arriving from a request body, a stored
  //    custom role or a token's scope list is untrusted until checked here.
  if (!isAction(action)) return decide("unknown-action", action, scope);

  // 2. No role carries it. With the built-in roles the completeness test makes
  //    this unreachable, but a custom role set can leave an action carried by
  //    nobody, and asking the database to decide with an empty role list is a
  //    round trip whose answer is already known.
  const roleKeys = resolveRoles(action);
  if (roleKeys.length === 0) return decide("no-role-carries-action", action, scope);

  // 3. May this actor act at all? One question per request, not one per node
  //    (threat model R-13). A disabled account is the shape a compromised one
  //    is put into, so intact grants must not save it.
  const subject = subjectOf(ctx.actor);
  const status = await findActorStatus(ctx, subject.type, subject.id);
  if (!status.exists) return decide("actor-not-in-tenant", action, scope);
  if (status.disabled) return decide("actor-disabled", action, scope);

  // 4. A scope node that does not exist, or belongs to another tenant, is
  //    indistinguishable here — row-level security means the query cannot see
  //    the difference either. That is what makes RL-M1-026 structural.
  if (!(await scopeNodeExists(ctx, scope.scopeNodeId))) {
    return decide("unknown-scope", action, scope);
  }

  // 5. Precedence, inheritance and expiry, decided in the database (ADR 0012).
  const decision = await resolveGrantDecision(ctx, subject.type, subject.id, roleKeys, scope);
  if (isAllowed(decision)) return decide("granted", action, scope);

  // `grant_decision` returns "deny" both for an explicit deny and for no grant
  // at all. Distinguishing them costs one more query and matters to whoever
  // reads the audit log, because the remedies differ: one is "ask someone for
  // access", the other is "someone deliberately took it away".
  //
  // This second query IGNORES denies on purpose, so it can only ever explain a
  // denial that has already been decided above. It must never decide anything.
  const allowExists = await hasAllowingGrant(ctx, subject.type, subject.id, roleKeys, scope);
  return decide(allowExists ? "explicit-deny" : "no-grant", action, scope);
}

/**
 * Throwing form, for call sites where a denial cannot be handled meaningfully.
 *
 * Callers that must audit the denial should use `can()` and record the reason.
 */
export class NotPermittedError extends Error {
  readonly decision: AuthorizationDecision;

  constructor(decision: AuthorizationDecision) {
    super(`not permitted: ${decision.action} (${decision.reason})`);
    this.name = "NotPermittedError";
    this.decision = decision;
  }
}

export async function require(
  ctx: AuthzContext,
  action: string,
  scope: ScopeRef,
  resolveRoles: (action: Action) => readonly string[] = rolesCarrying,
): Promise<AuthorizationDecision> {
  const decision = await can(ctx, action, scope, resolveRoles);
  if (!decision.allowed) throw new NotPermittedError(decision);
  return decision;
}

/** The catalogue entry for an action, for interfaces that explain a decision. */
export function describeAction(action: Action): string {
  return ACTION_CATALOGUE[action].description;
}
