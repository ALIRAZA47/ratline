/**
 * The audit vocabulary is closed (RL-M1-036).
 *
 * Found while reviewing RL-M1-021: `guardCsrf` audited under
 * `session.csrf_rejected` with resource type `session`, and neither the type
 * system nor the database objected — `AuditRecord` typed both as `string`, and
 * `audit_entries` has no check constraint on either column.
 *
 * That is a correct decision on an unpoliced mechanism. A CSRF rejection IS an
 * event rather than a permission; nobody holds it and no role could carry it.
 * What was missing is the thing that makes the catalogue trustworthy: a closed
 * set, so `sesion.csrf_rejected` does not write cleanly.
 *
 * ## Why a typo here is worse than it sounds
 *
 * An audit log is read exactly once — during an incident, by somebody searching
 * for a specific name. A misspelled action does not degrade the log; it removes
 * the entry from the only view anyone will ever take of it. The row is still
 * there, and it is invisible, which is the failure mode that looks like nothing
 * happened.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ALL_AUDIT_EVENTS,
  AUDIT_EVENTS,
  AUDIT_ONLY_RESOURCE_TYPES,
  AUDIT_RESOURCE_TYPES,
  auditActionKind,
  auditResourceOf,
  describeAuditAction,
  isAuditAction,
  isAuditEvent,
  type AuditAction,
} from "../../src/authz/audit_events.ts";
import { ACTION_CATALOGUE, ALL_ACTIONS, isAction, RESOURCE_TYPES } from "../../src/authz/catalogue.ts";
import { codeOf } from "../support/source_scan.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// ---------------------------------------------------------------------------
// Acceptance 1 and 2 — closed, and an outsider fails
// ---------------------------------------------------------------------------

test("an action outside both sets is not an audit action", () => {
  for (const invented of ["sesion.csrf_rejected", "session.csrf_rejcted", "", "*", "two_factor.verified"]) {
    assert.equal(isAuditAction(invented), false, `"${invented}" would write cleanly and then be unfindable`);
  }
});

test("every catalogued permission is an audit action, and every event is too", () => {
  // Both halves, because the union is only useful if neither side was dropped.
  for (const action of ALL_ACTIONS) assert.ok(isAuditAction(action), `${action} cannot be audited`);
  for (const event of ALL_AUDIT_EVENTS) assert.ok(isAuditAction(event), `${event} cannot be audited`);
});

test("no event pretends to be a permission", () => {
  // An event that WAS in the catalogue would be a permission nobody can hold —
  // catalogue_completeness rejects those, which is the reason events needed a
  // set of their own rather than an entry in the catalogue.
  for (const event of ALL_AUDIT_EVENTS) {
    assert.equal(isAction(event), false, `${event} is in the permission catalogue and should not be`);
  }
  for (const action of ALL_ACTIONS) {
    assert.equal(isAuditEvent(action), false, `${action} is duplicated as an event`);
  }
});

test("the two kinds are distinguishable, which is what the viewer needs", () => {
  // Acceptance 3. The audit viewer (RL-M1-031) offers two different filters,
  // because an operator hunting refused CSRF attempts is not hunting a
  // permission — and a single merged list would make them scroll the whole
  // catalogue to find four events.
  for (const event of ALL_AUDIT_EVENTS) assert.equal(auditActionKind(event), "event");
  for (const action of ALL_ACTIONS) assert.equal(auditActionKind(action), "permission");
  assert.ok(ALL_AUDIT_EVENTS.length > 0 && ALL_ACTIONS.length > 0);
});

test("both kinds describe themselves and name a resource", () => {
  // One lookup for a viewer, not two. A `describeAuditAction` that threw on one
  // kind would push the branch into every call site.
  const everything: AuditAction[] = [...ALL_ACTIONS, ...ALL_AUDIT_EVENTS];
  for (const action of everything) {
    assert.ok(describeAuditAction(action).length > 10, `${action} has no useful description`);
    assert.ok(
      AUDIT_RESOURCE_TYPES.includes(auditResourceOf(action)),
      `${action} names a resource type outside the audit vocabulary`,
    );
  }
});

test("an audit-only resource type is one the catalogue genuinely cannot hold", () => {
  // `session` is audit-only because there is no `session.*` permission — signing
  // somebody else out is `member.revoke_sessions`, a member action. If one ever
  // appears, the resource type should move to the catalogue rather than be
  // duplicated here, so this asserts the two sets stay disjoint.
  for (const extra of AUDIT_ONLY_RESOURCE_TYPES) {
    assert.ok(
      !RESOURCE_TYPES.includes(extra as never),
      `${extra} is in both vocabularies; the catalogue should own it alone`,
    );
    assert.equal(
      ALL_ACTIONS.some((action) => ACTION_CATALOGUE[action].resource === (extra as never)),
      false,
      `${extra} now has a permission action, so it belongs in RESOURCE_TYPES`,
    );
  }
});

test("every declared event is actually used, and every used name is declared", () => {
  // The two directions of drift. An event nobody writes is a name that looks
  // searchable and never appears; a name written without being declared is the
  // hole this task closed, and would come back the moment somebody casts.
  const sources = globSync("src/**/*.ts", { cwd: ROOT })
    .filter((file) => !file.endsWith("audit_events.ts"))
    .map((file) => readFileSync(join(ROOT, file), "utf8"))
    .join("\n");

  for (const event of ALL_AUDIT_EVENTS) {
    assert.ok(
      sources.includes(`"${event}"`),
      `${event} is declared and never recorded — either wire it up or remove it`,
    );
  }
});

test("nothing casts its way around the type", () => {
  // The type is the mechanism; a cast is how the mechanism gets bypassed while
  // still compiling, and TypeScript will not warn because the cast is the
  // author saying they know better.
  //
  // The first version of this scanned for a cast written inline at an `action:`
  // property, and mutation testing showed why that was too narrow: the real
  // case is a named constant — `export const X = "sesion.csrf_rejected" as
  // AuditEvent` — which that pattern does not see. It was caught by the
  // declared-and-used test instead, which is luck rather than design. So the
  // scan looks for the TYPE NAME, wherever the cast is written.
  const offenders: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    const path = relative(ROOT, join(ROOT, file)).replaceAll("\\", "/");
    if (path === "src/authz/audit_events.ts") continue;
    const code = codeOf(readFileSync(join(ROOT, file), "utf8"));
    for (const match of code.matchAll(/\bas\s+(AuditEvent|AuditAction|AuditResourceType)\b/g)) {
      offenders.push(`${path}: ${match[0]}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    "add the name to AUDIT_EVENTS instead of casting past the type — a cast writes a row nobody can search for",
  );
});

test("the events that exist are the ones the product actually records", () => {
  // A snapshot, and a deliberately dumb one. Its value is that adding an audit
  // event shows up in review as an explicit line rather than as a string
  // appearing somewhere in a diff — the same argument roles.ts makes for
  // writing out every role's actions by hand.
  assert.deepEqual(
    [...ALL_AUDIT_EVENTS].sort(),
    [
      "session.csrf_rejected",
      "two_factor.enrol",
      "two_factor.recovery_code_used",
      "two_factor.verify",
    ],
  );
  for (const event of ALL_AUDIT_EVENTS) {
    assert.ok(AUDIT_EVENTS[event].description.endsWith("."), `${event}'s description is not a sentence`);
  }
});
