/**
 * The audit log viewer's model (RL-M1-031).
 *
 * Plain TypeScript, like the rest of `lib/shell`, because JSX cannot be reached
 * by the test runner and every decision this screen makes is one worth checking.
 *
 * ## The requirement that shapes everything: denials are as visible as allows
 *
 * RL-M1-031's third acceptance sounds like a styling note and is not. An audit
 * log exists to answer one question after an incident — *what was attempted* —
 * and attempts that were refused are the most interesting rows in it. Every
 * common way of building this screen buries them:
 *
 *   - defaulting the filter to successful actions, because that is what a
 *     "recent activity" feed usually means;
 *   - rendering a denial in a dimmed colour, because it "did not happen";
 *   - offering a "hide denied" switch, which somebody leaves on.
 *
 * So the default filter is `all`, the presentation for `deny` is not dimmer
 * than for `allow`, and there is no asymmetric switch: the decision filter is
 * one control with three symmetric positions. Tests assert each of those as a
 * property rather than trusting the current values.
 *
 * ## Filters are enumerated from closed sets
 *
 * Actions and resource types come from the audit vocabulary (RL-M1-036), split
 * into permissions and events, because an operator hunting refused CSRF
 * attempts is not hunting a permission and should not have to scroll a hundred
 * of them to find four.
 */

import {
  ALL_AUDIT_EVENTS,
  AUDIT_RESOURCE_TYPES,
  auditActionKind,
  describeAuditAction,
  isAuditAction,
  type AuditAction,
  type AuditResourceType,
} from "../../../authz/audit_events.ts";
import { ALL_ACTIONS } from "../../../authz/catalogue.ts";
import { STATUS } from "../design/status.ts";
import type { VerificationOutcome } from "../../../repo/audit_verification.ts";

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/**
 * The decision filter, as one control with three symmetric positions.
 *
 * NOT a "hide denied" checkbox. A checkbox has a default and somebody leaves it
 * on; three positions with `all` first make hiding a deliberate, visible act
 * that hides allows just as readily.
 */
export const DECISION_FILTERS = ["all", "allow", "deny"] as const;
export type DecisionFilter = (typeof DECISION_FILTERS)[number];

export type AuditFilter = {
  readonly decision: DecisionFilter;
  readonly actorId: string | null;
  readonly action: AuditAction | null;
  readonly resourceType: AuditResourceType | null;
};

/**
 * What the screen shows before anybody touches it.
 *
 * `all` rather than `allow`, deliberately: the first thing an operator sees
 * after an incident must include the refusals.
 */
export const DEFAULT_FILTER: AuditFilter = {
  decision: "all",
  actorId: null,
  action: null,
  resourceType: null,
};

/** Translate the screen's filter into the repository's query. */
export function toAuditQuery(filter: AuditFilter, limit = 100): {
  readonly actorId?: string;
  readonly action?: AuditAction;
  readonly resourceType?: AuditResourceType;
  readonly decision?: "allow" | "deny";
  readonly limit: number;
} {
  return {
    ...(filter.actorId === null ? {} : { actorId: filter.actorId }),
    ...(filter.action === null ? {} : { action: filter.action }),
    ...(filter.resourceType === null ? {} : { resourceType: filter.resourceType }),
    // `all` omits the predicate entirely rather than sending both values, so
    // "no filter" is expressed as absence and cannot be got wrong by listing.
    ...(filter.decision === "all" ? {} : { decision: filter.decision }),
    limit,
  };
}

export type FilterOption = {
  readonly value: string;
  readonly label: string;
  readonly description: string;
};

export type ActionFilterGroups = {
  readonly permissions: readonly FilterOption[];
  readonly events: readonly FilterOption[];
};

/**
 * The action filter, split by kind (RL-M1-036).
 *
 * Both groups are offered because both appear in the log. Keeping them apart is
 * the point: merging them buries four events in a hundred permissions, and an
 * operator looking for refused CSRF attempts would never find them.
 */
export function actionFilterOptions(): ActionFilterGroups {
  const option = (action: AuditAction): FilterOption => ({
    value: action,
    label: action,
    description: describeAuditAction(action),
  });
  return {
    permissions: ALL_ACTIONS.map(option),
    events: ALL_AUDIT_EVENTS.map(option),
  };
}

export function resourceFilterOptions(): readonly FilterOption[] {
  return AUDIT_RESOURCE_TYPES.map((resource) => ({
    value: resource,
    label: resource,
    description: `Everything recorded about ${resource}.`,
  }));
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

export type DecisionPresentation = {
  /** The status hue token. Never a dimmed text colour — see below. */
  readonly colorToken: string;
  /** §1's corollary: status is never colour alone. */
  readonly glyph: string;
  readonly label: string;
};

/**
 * How a decision is drawn.
 *
 * `deny` reuses the `attention` status rather than `fail`, and the distinction
 * is worth stating: a refused attempt is not a system failure, it is the
 * permission model working. Painting every denial red would train operators to
 * ignore red, which is the one colour §1 spends its whole budget on.
 *
 * Both entries take a full-strength status hue. Neither takes `--chalk-dim`,
 * and `test/security/audit_viewer.test.ts` asserts that: a dimmed denial is the
 * commonest way this screen fails its third acceptance while looking finished.
 */
const DECISION_PRESENTATION: Readonly<Record<"allow" | "deny", DecisionPresentation>> = {
  allow: { colorToken: STATUS.healthy.colorToken, glyph: STATUS.healthy.glyph, label: "Allowed" },
  deny: { colorToken: STATUS.attention.colorToken, glyph: STATUS.attention.glyph, label: "Refused" },
};

export function decisionPresentation(decision: string): DecisionPresentation {
  // An unrecognised decision is drawn as a refusal rather than silently as an
  // allow. The column is a plain text column in the database; if a value ever
  // arrives that this does not know, the safe reading is "something happened
  // that nobody planned for".
  return decision === "allow" ? DECISION_PRESENTATION.allow : DECISION_PRESENTATION.deny;
}

// ---------------------------------------------------------------------------
// Chain verification, shown alongside
// ---------------------------------------------------------------------------

export type VerificationBanner = {
  readonly outcome: VerificationOutcome | "unknown";
  readonly statusId: "healthy" | "attention" | "fail" | "idle";
  readonly colorToken: string;
  readonly glyph: string;
  readonly headline: string;
  /** Whether the banner may be dismissed. A broken chain may not be. */
  readonly dismissable: boolean;
};

/**
 * The banner above the entries.
 *
 * Acceptance 2 asks for the chain's status to be shown *alongside* the entries,
 * and the reason is that the entries are worthless without it. A tampered log
 * that renders normally is worse than no log, because it is believed — so a
 * broken or truncated chain is not a dismissable notice, and "never verified"
 * is not treated as good news.
 *
 * `null` means no verification has ever run. That is `unknown`, not `clean`:
 * the whole point of the hash chain is that its absence proves nothing.
 */
export function verificationBanner(outcome: VerificationOutcome | null): VerificationBanner {
  switch (outcome) {
    case "clean":
      return {
        outcome: "clean",
        statusId: "healthy",
        colorToken: STATUS.healthy.colorToken,
        glyph: STATUS.healthy.glyph,
        headline: "The audit chain verified intact.",
        dismissable: true,
      };
    case "broken":
      return {
        outcome: "broken",
        statusId: "fail",
        colorToken: STATUS.fail.colorToken,
        glyph: STATUS.fail.glyph,
        headline: "The audit chain is broken. Entries below may have been altered.",
        dismissable: false,
      };
    case "truncated":
      return {
        outcome: "truncated",
        statusId: "fail",
        colorToken: STATUS.fail.colorToken,
        glyph: STATUS.fail.glyph,
        headline: "Entries have been removed from the end of the audit chain.",
        dismissable: false,
      };
    case null:
      return {
        outcome: "unknown",
        statusId: "idle",
        colorToken: STATUS.idle.colorToken,
        glyph: STATUS.idle.glyph,
        headline: "The audit chain has not been verified. Its integrity is unknown, not intact.",
        dismissable: false,
      };
  }
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

export type AuditRow = {
  readonly id: string;
  readonly occurredAt: Date;
  readonly actorLabel: string;
  readonly action: string;
  readonly actionKind: "permission" | "event" | "unknown";
  readonly description: string;
  readonly resourceType: string;
  readonly decision: DecisionPresentation;
  readonly reason: string;
};

type EntryLike = {
  readonly id: string;
  readonly occurredAt: Date;
  readonly actorType: string;
  readonly actorId: string;
  readonly actorLabel: string;
  readonly action: string;
  readonly resourceType: string;
  readonly decision: string;
  readonly reason: string;
};

/**
 * One stored entry, ready to render.
 *
 * `action` is typed `string` on the way in, not `AuditAction`, and that is
 * deliberate: these rows are read back from a database that may hold entries
 * written before RL-M1-036 closed the vocabulary. A viewer that threw on one of
 * those would make the oldest part of the log unreadable, which is the part an
 * investigation reaches for.
 */
export function toAuditRow(entry: EntryLike): AuditRow {
  // `isAuditAction` is a type guard, so the branch narrows and no assertion is
  // needed. The first version asserted the type twice instead, and
  // `test/security/audit_namespace.test.ts` refused it — correctly: a type
  // assertion is how the closed vocabulary gets bypassed while still compiling,
  // and a rule that exempts "the safe ones" exempts every one somebody believes
  // is safe. (Phrased without writing the assertion out; that scanner reads
  // source text and does not treat comments differently from code.)
  const known = isAuditAction(entry.action);
  return {
    id: entry.id,
    occurredAt: entry.occurredAt,
    // §6.3 and C6: an entry names who, and automation is never anonymous. The
    // label falls back to the identifier rather than to "system", which is the
    // one word C6 forbids.
    actorLabel: entry.actorLabel.trim() === "" ? `${entry.actorType} ${entry.actorId}` : entry.actorLabel,
    action: entry.action,
    actionKind: known ? auditActionKind(entry.action) : "unknown",
    description: known
      ? describeAuditAction(entry.action)
      : "Recorded before this name was catalogued.",
    resourceType: entry.resourceType,
    decision: decisionPresentation(entry.decision),
    reason: entry.reason,
  };
}
