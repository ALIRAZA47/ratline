/**
 * The audit log viewer (RL-M1-031).
 *
 * In `test/security/` rather than `test/toolchain/` because its third
 * acceptance — "denied decisions are as visible as allowed ones" — is a
 * security property wearing a styling note's clothes. An audit log exists to
 * answer one question after an incident, *what was attempted*, and the refused
 * attempts are the most interesting rows in it. A screen that buries them is
 * broken in the way that matters and looks finished.
 *
 * Every common way of building this screen buries them: defaulting the filter
 * to successful actions, because "recent activity" usually means that;
 * rendering a denial dimmed, because it did not happen; offering a "hide
 * denied" switch that somebody leaves on. Each is asserted against below as a
 * property, not as a comparison with today's values.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import {
  actionFilterOptions,
  DECISION_FILTERS,
  decisionPresentation,
  DEFAULT_FILTER,
  resourceFilterOptions,
  toAuditQuery,
  toAuditRow,
  verificationBanner,
} from "../../src/web/lib/shell/audit_view.ts";
import { ALL_AUDIT_EVENTS, AUDIT_RESOURCE_TYPES } from "../../src/authz/audit_events.ts";
import { ALL_ACTIONS } from "../../src/authz/catalogue.ts";
import { VERIFICATION_OUTCOMES } from "../../src/repo/audit_verification.ts";
import { findToken } from "../../src/web/lib/design/tokens.ts";
import { SURFACE } from "../../src/web/lib/design/palette.ts";

// ---------------------------------------------------------------------------
// Acceptance 3 — denials are as visible as allows
// ---------------------------------------------------------------------------

test("the default view includes refusals", () => {
  // The first thing an operator sees after an incident must contain the
  // denials. Defaulting to `allow` would be the single most damaging line on
  // this screen and the easiest one to write by accident.
  assert.equal(DEFAULT_FILTER.decision, "all");
  assert.equal(toAuditQuery(DEFAULT_FILTER).decision, undefined, "the default must send no decision predicate");
});

test("the decision filter is symmetric — there is no hide-denied switch", () => {
  // Three positions with `all` first, rather than a checkbox. A checkbox has a
  // default and somebody leaves it on; three positions make hiding a deliberate
  // act that hides allows just as readily.
  assert.deepEqual([...DECISION_FILTERS], ["all", "allow", "deny"]);
  assert.equal(toAuditQuery({ ...DEFAULT_FILTER, decision: "allow" }).decision, "allow");
  assert.equal(toAuditQuery({ ...DEFAULT_FILTER, decision: "deny" }).decision, "deny");
});

test("a refusal is not drawn more quietly than an allow", () => {
  // The commonest way this screen fails while looking finished. Asserted
  // against the dimmed text tokens by value, so renaming a token cannot slip
  // past it, and asserted for BOTH decisions so a future third value inherits
  // the rule.
  const dimmed = new Set<string>([SURFACE.chalkDim.dark, SURFACE.chalkDim.light]);
  for (const decision of ["allow", "deny"]) {
    const presentation = decisionPresentation(decision);
    const token = findToken(presentation.colorToken);
    assert.ok(token, `${decision} paints ${presentation.colorToken}, which is not a token`);
    assert.ok(token.kind === "color" && !token.translucent);
    for (const mode of ["dark", "light"] as const) {
      assert.ok(
        !dimmed.has(token.value[mode]),
        `${decision} is drawn in the secondary text colour in ${mode} mode — it recedes`,
      );
    }
  }
});

test("both decisions carry a glyph and a label, not colour alone", () => {
  // DESIGN §1's corollary. Roughly one in twelve men has a red/green
  // deficiency, and an incident is not the moment to find out.
  for (const decision of ["allow", "deny"]) {
    const presentation = decisionPresentation(decision);
    assert.ok(presentation.glyph.length > 0, `${decision} has no glyph`);
    assert.ok(presentation.label.length > 0, `${decision} has no label`);
  }
  assert.notEqual(decisionPresentation("allow").glyph, decisionPresentation("deny").glyph);
  assert.notEqual(decisionPresentation("allow").label, decisionPresentation("deny").label);
});

test("a refusal is not painted as a failure", () => {
  // Deliberate, and worth pinning. A refused attempt is the permission model
  // working, not a system fault. Painting every denial red would train
  // operators to ignore red, which is the one colour §1 spends its entire
  // budget on.
  assert.notEqual(decisionPresentation("deny").colorToken, "--st-fail");
  assert.notEqual(decisionPresentation("deny").colorToken, decisionPresentation("allow").colorToken);
});

test("an unrecognised decision reads as a refusal, not as an allow", () => {
  // The column is plain text in the database. If a value arrives that this does
  // not know, the safe reading is "something happened nobody planned for" —
  // fail closed, the same rule can() applies to an unknown reason.
  for (const odd of ["", "ALLOW", "permitted", "maybe"]) {
    assert.deepEqual(decisionPresentation(odd), decisionPresentation("deny"), `"${odd}" was treated as an allow`);
  }
});

// ---------------------------------------------------------------------------
// Acceptance 1 — filterable by actor, action, resource and outcome
// ---------------------------------------------------------------------------

test("all four filters reach the query", () => {
  const actorId = randomUUID();
  const query = toAuditQuery({
    decision: "deny",
    actorId,
    action: "secret.read_value",
    resourceType: "secret",
  });
  assert.equal(query.actorId, actorId);
  assert.equal(query.action, "secret.read_value");
  assert.equal(query.resourceType, "secret");
  assert.equal(query.decision, "deny");
});

test("an absent filter is absent from the query rather than sent as a value", () => {
  // `undefined` and "no predicate" have to be the same thing, or a filter set
  // to nothing quietly matches nothing. The repository builds `$n is null or
  // column = $n`, so a null would work — but only by coincidence, and only for
  // as long as every predicate keeps that shape.
  const query = toAuditQuery(DEFAULT_FILTER);
  assert.deepEqual(Object.keys(query), ["limit"]);
});

test("the action filter offers permissions and events apart", () => {
  // RL-M1-036 split the vocabulary; this is why. Merging them buries four
  // events in a hundred-odd permissions, and an operator hunting refused CSRF
  // attempts would never find them.
  const options = actionFilterOptions();
  assert.deepEqual(options.permissions.map((option) => option.value), [...ALL_ACTIONS]);
  assert.deepEqual(options.events.map((option) => option.value), [...ALL_AUDIT_EVENTS]);
  assert.ok(options.events.length > 0 && options.permissions.length > options.events.length);
  for (const option of [...options.permissions, ...options.events]) {
    assert.ok(option.description.length > 10, `${option.value} has no description for the filter`);
  }
});

test("the resource filter covers everything an entry can name", () => {
  // Including the audit-only types. A resource an entry can carry and the
  // filter cannot offer is a set of rows nobody can reach.
  assert.deepEqual(
    resourceFilterOptions().map((option) => option.value),
    [...AUDIT_RESOURCE_TYPES],
  );
});

// ---------------------------------------------------------------------------
// Acceptance 2 — chain verification shown alongside
// ---------------------------------------------------------------------------

test("never verified is unknown, not clean", () => {
  // The whole point of the hash chain is that its absence proves nothing. A
  // screen that showed a green tick before any verification had run would be
  // asserting exactly what it cannot know.
  const banner = verificationBanner(null);
  assert.equal(banner.outcome, "unknown");
  assert.notEqual(banner.statusId, "healthy");
  assert.match(banner.headline, /unknown, not intact/);
});

test("a broken or truncated chain cannot be dismissed", () => {
  // A tampered log that renders normally is worse than no log, because it is
  // believed. Dismissable is asserted as false for every bad outcome, so a
  // fourth outcome added later has to make its own case.
  for (const outcome of VERIFICATION_OUTCOMES) {
    const banner = verificationBanner(outcome);
    if (outcome === "clean") {
      assert.equal(banner.dismissable, true);
      continue;
    }
    assert.equal(banner.dismissable, false, `a ${outcome} chain can be dismissed`);
    assert.equal(banner.statusId, "fail");
  }
  assert.equal(verificationBanner(null).dismissable, false);
});

test("every banner paints a real token and says something", () => {
  for (const outcome of [...VERIFICATION_OUTCOMES, null]) {
    const banner = verificationBanner(outcome);
    assert.ok(findToken(banner.colorToken), `${String(outcome)} paints ${banner.colorToken}`);
    assert.ok(banner.glyph.length > 0, `${String(outcome)} has no glyph`);
    assert.ok(banner.headline.length > 20, `${String(outcome)} has no useful headline`);
  }
});

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

const entry = (over: Partial<Parameters<typeof toAuditRow>[0]> = {}) =>
  toAuditRow({
    id: randomUUID(),
    occurredAt: new Date(0),
    actorType: "user",
    actorId: randomUUID(),
    actorLabel: "Ali",
    action: "secret.read_value",
    resourceType: "secret",
    decision: "deny",
    reason: "no-grant",
    ...over,
  });

test("a row names who, and never the system", () => {
  // C6: no privileged action by "the system". An empty label falls back to the
  // actor's kind and identifier, which is ugly and attributable — the word
  // "system" is the one thing it must never produce.
  const named = entry({ actorLabel: "Ali" });
  assert.equal(named.actorLabel, "Ali");

  const unlabelled = entry({ actorLabel: "   ", actorType: "service_identity" });
  assert.match(unlabelled.actorLabel, /^service_identity /);
  assert.ok(!unlabelled.actorLabel.toLowerCase().includes("system"));
});

test("an entry written before the vocabulary was closed still renders", () => {
  // These rows are read back from a database that predates RL-M1-036. A viewer
  // that threw on one would make the oldest part of the log unreadable, which
  // is the part an investigation reaches for.
  const legacy = entry({ action: "site.frobnicate" });
  assert.equal(legacy.actionKind, "unknown");
  assert.equal(legacy.action, "site.frobnicate", "the stored name is shown as stored");
  assert.ok(legacy.description.length > 0);
});

test("a row keeps the reason, which is what the response refused to give", () => {
  // RL-M1-026's other half. The caller is told nothing; the operator is told
  // everything, and this is where "everything" is actually read.
  assert.equal(entry({ reason: "explicit-deny" }).reason, "explicit-deny");
  assert.equal(entry({ action: "session.csrf_rejected" }).actionKind, "event");
  assert.equal(entry({ action: "secret.read_value" }).actionKind, "permission");
});
