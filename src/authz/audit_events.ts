/**
 * The audit vocabulary (RL-M1-036).
 *
 * The audit log records two different kinds of thing and, until this module,
 * only one of them was closed.
 *
 *   A PERMISSION ACTION — `member.reset_password`, `secret.read_value`. Somebody
 *   asked to do something the catalogue names, and `can()` allowed or denied it.
 *   These come from `catalogue.ts` and an invented one does not compile.
 *
 *   AN EVENT — `session.csrf_rejected`, `two_factor.verify`. Something happened
 *   that is worth recording and is not a permission at all. Nobody holds
 *   `session.csrf_rejected`; there is no grant that conveys it and no role that
 *   could carry it.
 *
 * The second kind was arriving as a bare string, because `AuditRecord.action`
 * is typed `string` and `audit_entries.action` has no check constraint. That is
 * a correct decision on an unpoliced mechanism: `sesion.csrf_rejected` writes
 * cleanly and then vanishes from every filter that looks for the real name. An
 * audit log is read exactly once, during an incident, by somebody searching for
 * a specific thing — a typo there does not degrade the log, it removes an entry
 * from the only view anyone will ever take of it.
 *
 * ## Why events are not simply added to the catalogue
 *
 * Because `catalogue_completeness.test.ts` is right to reject that. Every
 * catalogued action must be carried by at least one role, and every resource
 * type must have at least one action — rules that exist so an action nobody can
 * hold cannot be invented by accident. A CSRF rejection is exactly such an
 * action: nobody should hold it, and forcing it into a role to satisfy the
 * completeness rule would put a meaningless permission in the role editor.
 *
 * So the audit vocabulary is its own closed set, related to the catalogue and
 * not identical to it, and `auditActionOf` accepts either.
 */

import { ACTION_CATALOGUE, isAction, RESOURCE_TYPES, type Action, type ResourceType } from "./catalogue.ts";

/**
 * Resource types an audit entry may name, beyond the catalogue's.
 *
 * `session` is here rather than in `RESOURCE_TYPES` for the reason above: it
 * would need an action, and there is no `session.*` permission — signing
 * somebody else out is `member.revoke_sessions`, which is a member action.
 */
export const AUDIT_ONLY_RESOURCE_TYPES = ["session"] as const;
export type AuditOnlyResourceType = (typeof AUDIT_ONLY_RESOURCE_TYPES)[number];

export type AuditResourceType = ResourceType | AuditOnlyResourceType;

export const AUDIT_RESOURCE_TYPES: readonly AuditResourceType[] = [
  ...RESOURCE_TYPES,
  ...AUDIT_ONLY_RESOURCE_TYPES,
];

export type AuditEventDefinition = {
  readonly resource: AuditResourceType;
  /** What a reader of the audit log sees. Written for 2am, not for a developer. */
  readonly description: string;
};

/**
 * Everything the system records that is not a permission decision.
 *
 * Closed, like the catalogue. Adding an entry is the deliberate act; writing an
 * unlisted one does not typecheck.
 */
export const AUDIT_EVENTS = {
  // --- authentication -------------------------------------------------------
  "two_factor.enrol": {
    resource: "member",
    description: "Enrolled a second factor, or confirmed a re-enrolment.",
  },
  "two_factor.verify": {
    resource: "member",
    description: "Presented a second factor at sign-in. Recorded whether it was accepted or refused.",
  },
  "two_factor.recovery_code_used": {
    resource: "member",
    description: "Signed in with a recovery code, which is now spent. Worth noticing: it means the authenticator is gone.",
  },

  // --- request integrity ----------------------------------------------------
  "session.csrf_rejected": {
    resource: "session",
    description: "A state-changing request arrived without a valid token bound to its session, and was refused.",
  },
} as const satisfies Record<string, AuditEventDefinition>;

export type AuditEvent = keyof typeof AUDIT_EVENTS;

export const ALL_AUDIT_EVENTS = Object.keys(AUDIT_EVENTS) as readonly AuditEvent[];

/**
 * What may appear in `audit_entries.action`.
 *
 * A permission action or an event, and nothing else. This is the type
 * `AuditRecord.action` carries, so a typo is a compile error at the call site
 * rather than a row nobody can find.
 */
export type AuditAction = Action | AuditEvent;

export function isAuditEvent(value: string): value is AuditEvent {
  return Object.hasOwn(AUDIT_EVENTS, value);
}

/**
 * Boundary guard, for a name that arrived from outside — a query string on the
 * audit viewer's filter, a stored report, a row read back from the database
 * that was written before this module existed.
 */
export function isAuditAction(value: string): value is AuditAction {
  return isAction(value) || isAuditEvent(value);
}

/**
 * Whether an entry records a permission decision or an event.
 *
 * The audit viewer (RL-M1-031) needs this to enumerate both without pretending
 * they are the same thing: filtering by "action" should offer the catalogue,
 * and filtering by "event" should offer these, because an operator looking for
 * refused CSRF attempts is not looking for a permission at all.
 */
export const AUDIT_ACTION_KINDS = ["permission", "event"] as const;
export type AuditActionKind = (typeof AUDIT_ACTION_KINDS)[number];

export function auditActionKind(action: AuditAction): AuditActionKind {
  return isAuditEvent(action) ? "event" : "permission";
}

/** The description for either kind, so a viewer needs one lookup rather than two. */
export function describeAuditAction(action: AuditAction): string {
  return isAuditEvent(action) ? AUDIT_EVENTS[action].description : ACTION_CATALOGUE[action].description;
}

/** The resource type either kind operates on. */
export function auditResourceOf(action: AuditAction): AuditResourceType {
  return isAuditEvent(action) ? AUDIT_EVENTS[action].resource : ACTION_CATALOGUE[action].resource;
}
