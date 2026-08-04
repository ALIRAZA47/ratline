/**
 * Refusals (RL-M1-026).
 *
 * Brief §6.3: "Nonexistent and unauthorized must be indistinguishable in the
 * response." §6.4 puts the same requirement on cross-tenant probing.
 *
 * The naive reading is "return 404 for both", and it is not enough. Two code
 * paths that happen to produce the same bytes today are two code paths, and one
 * of them will grow a helpful detail — a resource name in a message, a
 * `WWW-Authenticate` header on one branch, a different `Content-Length` — and
 * the oracle comes back. The requirement is not that the two responses match;
 * it is that there is only one response.
 *
 * So this module is arranged the way C3 arranges data access, for the same
 * reason (ADR 0003): make the wrong thing impossible to express rather than
 * merely wrong.
 *
 *   1. THE WIRE RESPONSE IS A FROZEN CONSTANT. Not a template, not a builder.
 *      There is nothing to parameterise, so nothing can vary by resource type,
 *      by reason, by tenant, or by whether the thing existed.
 *
 *   2. `Refusal` IS BRANDED. Like `AuthzContext`, it carries a symbol declared
 *      here and exported as a type only, so no other module can construct one.
 *      A handler cannot hand-roll "its own 404 but with a helpful message"
 *      without the cast that makes the intent visible in review.
 *
 *   3. THE TRUTH AND THE WIRE LEAVE BY THE SAME CALL. `refuse()` returns both
 *      the response and the audit record, so you cannot obtain the refusal
 *      without also producing the entry that says what really happened. That is
 *      C6 — no privileged outcome without an attributable record — and it is
 *      also what makes the indistinguishability affordable: the operator loses
 *      nothing, because the whole truth is in the audit log. Only the caller is
 *      kept in the dark.
 *
 * ## Why 404 rather than 403
 *
 * A 403 asserts the resource exists. That single fact is the whole leak: it
 * turns an identifier into a membership test, which is how an attacker maps a
 * tenant they cannot read. 404 asserts nothing.
 *
 * ## Why 401 is a separate thing and not a hole in this
 *
 * `UNAUTHENTICATED` below is returned when there is no valid session at all,
 * before any resource is considered — which is why `unauthenticated()` takes no
 * resource argument. It cannot be an existence oracle because it cannot see an
 * identifier. Returning it for an authenticated caller who merely lacks
 * permission WOULD be one, and the type prevents saying so: there is no path
 * from a decision to `unauthenticated()`.
 *
 * ## What this deliberately does not do
 *
 * No correlation identifier in the body. It is the obvious kindness and it is
 * the exact place a leak gets reintroduced, one "while we're here" at a time.
 * The audit log correlates by `requestId` server-side, where the operator is
 * and the prober is not.
 *
 * Timing is not equalised. A permission check that finds nothing may return
 * sooner than one that resolves a real row, and that is a real oracle at a
 * different layer. Threat model R-04 records it as accepted rather than fixed:
 * full equalisation costs a fixed delay on every refusal, and the mitigation
 * belongs with rate limiting (RL-M1-020), which bounds how many samples an
 * attacker can take, rather than here.
 */

import type { AuditAction, AuditEvent, AuditResourceType } from "../authz/audit_events.ts";
import type { AuditRecord } from "../repo/audit.ts";
import type { AuthzContext } from "../authz/context.ts";

declare const brand: unique symbol;

export type WireResponse = {
  readonly status: number;
  /** Sorted, lower-cased. Order is part of the bytes, so it is not left to chance. */
  readonly headers: readonly (readonly [string, string])[];
  readonly body: string;
};

/** A response nothing outside this module can construct. */
export type Refusal = WireResponse & { readonly [brand]: true };

function seal(status: number, body: string): Refusal {
  const headers: readonly (readonly [string, string])[] = [
    ["cache-control", "no-store"],
    ["content-length", String(Buffer.byteLength(body, "utf8"))],
    ["content-type", "application/json; charset=utf-8"],
  ];
  return Object.freeze({ status, headers: Object.freeze(headers), body }) as Refusal;
}

/**
 * The one refusal.
 *
 * Every unauthorized request, every cross-tenant probe and every genuine miss
 * ends here, byte for byte. The message says nothing a caller did not already
 * know.
 */
const REFUSED = seal(404, `{"error":"not_found"}`);

/**
 * No valid session. A different thing, and safe to distinguish: it is decided
 * before any identifier is read, so it cannot report on one.
 */
const UNAUTHENTICATED = seal(401, `{"error":"unauthenticated"}`);

/**
 * Why the request was really refused. Reaches the audit log and nothing else.
 *
 * `absent` covers both "no such row" and "a row belonging to another tenant",
 * because with row-level security the application genuinely cannot tell them
 * apart — the query returns nothing either way. That is not a limitation to
 * work around; it is what makes the indistinguishability structural rather than
 * remembered.
 */
export const REFUSAL_CAUSES = ["denied", "absent"] as const;
export type RefusalCause = (typeof REFUSAL_CAUSES)[number];

export type RefusalTruth = {
  /**
   * What was attempted. A catalogued action or event (RL-M1-036), never a free
   * string: the audit entry this produces is the ONLY record of the refusal,
   * because the response deliberately says nothing, so a name nobody can search
   * for loses the event entirely.
   */
  readonly action: AuditAction;
  readonly resourceType: AuditResourceType;
  /** Null when nothing resolved — which is itself the fact being withheld. */
  readonly resourceId: string | null;
  readonly cause: RefusalCause;
  /** `can()`'s DecisionReason when denied; free text otherwise. */
  readonly reason: string;
};

/**
 * Refuse a request, and say truthfully why in the same breath.
 *
 * The returned `wire` is the same object every time and does not depend on
 * `truth` in any way. That is the property `test/security/indistinguishable_404`
 * asserts by serialising the result for every resource type and every cause and
 * demanding one distinct value.
 *
 * The caller must pass `audit` to `recordAudit`. It is returned rather than
 * written here because this module holds no database handle — C3 keeps that
 * inside src/repo/ — and because a refusal produced during a failed
 * authentication has no `AuthzContext` to record against yet (ADR 0014).
 */
/**
 * A refusal that has not been accounted for yet (RL-M1-050).
 *
 * `refuse()` used to return `{ wire, audit }`, and the comment above claimed the
 * refusal could not be obtained without recording what happened. It could:
 * `refuse({...}).wire` takes the response and drops the record, which is exactly
 * what `found()` in server.ts did. The consequence was that a cross-tenant probe
 * on the one route able to express one returned an indistinguishable 404 — RL-M1-026
 * working — and wrote nothing to the audit log. Correct on the wire, invisible in
 * the record, which is the worse half of that trade: an attacker enumerating ids
 * across tenants left no trace at all.
 *
 * So the response is now sealed inside a value with no public `wire` field. The
 * only ways out are {@link recordAndRefuse}, which writes the audit entry first,
 * and {@link alreadyAudited}, which demands the name of the entry that covers it.
 * Destructuring cannot reach the response, so the failure mode is a type error
 * rather than a silence.
 */
export type PendingRefusal = {
  readonly [brand]: true;
  /** @internal Reachable only through this module's own accessors. */
  readonly truth: RefusalTruth;
};

export function refuse(truth: RefusalTruth): PendingRefusal {
  return { truth } as PendingRefusal;
}

/** The audit record a pending refusal owes. Exported for tests, not for callers. */
export function auditRecordFor(pending: PendingRefusal): AuditRecord {
  return {
    action: pending.truth.action,
    resourceType: pending.truth.resourceType,
    resourceId: pending.truth.resourceId,
    decision: "deny",
    reason: pending.truth.reason,
    // The distinction the response refuses to make, kept where it belongs.
    metadata: { refusal_cause: pending.truth.cause },
  };
}

/**
 * Record the refusal, then return the response.
 *
 * The order is the point. If `recordAudit` throws, the caller gets the exception
 * and no response — which is the right way round: a refusal nobody can account
 * for should surface as a fault, not be served quietly. Serving the 404 first and
 * auditing afterwards would put the failure exactly where nobody looks.
 */
export async function recordAndRefuse(
  ctx: AuthzContext,
  pending: PendingRefusal,
  record: (ctx: AuthzContext, entry: AuditRecord) => Promise<unknown>,
): Promise<Refusal> {
  await record(ctx, auditRecordFor(pending));
  return REFUSED;
}

/**
 * The response for a refusal whose audit entry was already written elsewhere.
 *
 * `guardCsrf` is the real case: it records `session.csrf_rejected` itself, with
 * the origin and route, before returning its verdict. Auditing again here would
 * double-count a single rejected request.
 *
 * The `writtenBy` argument is not decoration. It is the whole reason this is a
 * separate function rather than a `.wire` getter: an exemption has to name the
 * record that covers it, so `grep alreadyAudited` lists every place the guarantee
 * is claimed rather than enforced, and a reviewer can check each claim. A silent
 * escape hatch on "every refusal is audited" makes the rule advisory.
 */
export function alreadyAudited(_pending: PendingRefusal, writtenBy: AuditEvent): Refusal {
  void writtenBy;
  return REFUSED;
}

/**
 * The wire response with no audit record, FOR TESTS ONLY.
 *
 * `indistinguishable_404.test.ts` is the test that proves every refusal is one
 * frozen constant whatever caused it, and it cannot prove that without holding the
 * constant. Every other way of giving it access — a public `wire` getter, an
 * unsealing cast — would hand the same thing to production code, which is the
 * defect RL-M1-050 fixed.
 *
 * "Must not be called from src/" is worth nothing as a comment, so
 * `test/security/refusal_accounting.test.ts` scans the source and fails if this
 * name appears under `src/`. The name is deliberately unpleasant for the same
 * reason: nobody reaches for it by accident, and it reads as wrong in a diff.
 */
export function refusalWireWithoutAuditForTests(_pending: PendingRefusal): Refusal {
  return REFUSED;
}

/**
 * A second factor is owed (RL-M1-019, added by RL-M1-042).
 *
 * Two constants rather than one parameterised response, so this module keeps
 * the property the whole file is built on: nothing here varies by request.
 *
 * Safe to distinguish from {@link UNAUTHENTICATED}, and from each other, for the
 * same reason 401 is safe at all — both are only ever reached by somebody who
 * has already presented a correct password, so neither tells an unauthenticated
 * caller anything they could not learn by trying. What they DO tell a legitimate
 * one is which screen to show, and getting that wrong means asking somebody to
 * verify a factor they have not enrolled.
 */
const SECOND_FACTOR_REQUIRED = seal(401, `{"error":"second_factor_required"}`);
const SECOND_FACTOR_ENROLMENT_REQUIRED = seal(401, `{"error":"second_factor_enrolment_required"}`);

/** No session. Takes nothing, so it can report nothing. */
export function unauthenticated(): Refusal {
  return UNAUTHENTICATED;
}

/** The password was right and a factor is owed. `enrolmentRequired` picks which. */
export function secondFactorOwed(enrolmentRequired: boolean): Refusal {
  return enrolmentRequired ? SECOND_FACTOR_ENROLMENT_REQUIRED : SECOND_FACTOR_REQUIRED;
}

/**
 * The exact bytes, for a byte-for-byte comparison and for the eventual server
 * adapter. Canonical: status, then headers in the order stored, then the body.
 */
export function serialiseRefusal(refusal: Refusal): Buffer {
  const head = refusal.headers.map(([name, value]) => `${name}: ${value}`).join("\r\n");
  return Buffer.from(`HTTP ${String(refusal.status)}\r\n${head}\r\n\r\n${refusal.body}`, "utf8");
}
