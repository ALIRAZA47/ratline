/**
 * The command palette shows only what an actor may run (RL-M1-029).
 *
 * DESIGN.md §8 makes the palette "the keyboard route to every action", which
 * means it is also the most complete inventory of the product's capabilities
 * anywhere in the interface. That is exactly why its filter matters: a rail with
 * five items leaks little, and a list of every action in the system leaks the
 * whole permission model.
 *
 * ## What this file can and cannot prove
 *
 * It cannot prove a Developer cannot read a secret value. Nothing in
 * `src/web/` can, because the refusal lives in the repository layer and the
 * palette never asks it — see the module header on `palette.ts`. What it proves
 * is narrower and still worth having: the palette does not OFFER a command the
 * actor lacks, so the interface does not advertise the permission model to
 * somebody probing it, and does not hand an operator a control that will fail.
 *
 * The cross-tenant and privilege questions are `test/authz/matrix.test.ts` and
 * `test/security/*`. This is the courtesy layer, tested as a courtesy layer.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ALL_COMMANDS,
  groupCommands,
  searchCommands,
  visibleCommands,
} from "../../src/web/lib/shell/palette.ts";
import { ALL_ACTIONS, isAction } from "../../src/authz/catalogue.ts";
import { ALL_DEFAULT_ROLES, DEFAULT_ROLES } from "../../src/authz/roles.ts";

// ---------------------------------------------------------------------------
// Generated, not written
// ---------------------------------------------------------------------------

test("the palette is exactly the action catalogue", () => {
  // Acceptance 1, stated directly. Equality in both directions: a command with
  // no action would be unreachable, and an action with no command would be
  // invisible to the keyboard route §8 says covers everything.
  assert.deepEqual(
    ALL_COMMANDS.map((command) => command.action),
    [...ALL_ACTIONS],
  );
  assert.ok(ALL_COMMANDS.length > 100, "the catalogue is large; a short palette means generation broke");
});

test("every command carries the catalogue's own description", () => {
  // Not a second copy. A hand-written label is a second statement about what an
  // action does, and the two disagree the first time an action's meaning is
  // narrowed — which is exactly when an operator most needs the description to
  // be right.
  for (const command of ALL_COMMANDS) {
    assert.ok(isAction(command.action));
    assert.ok(command.description.length > 10, `${command.action} has no useful description`);
    assert.equal(command.resource, command.action.split(".")[0], "resource must be the action's own prefix");
  }
});

// ---------------------------------------------------------------------------
// Acceptance 2 and 3 — only what the actor may take
// ---------------------------------------------------------------------------

test("a role that lacks a privileged action is never offered it", () => {
  // Acceptance 3, named actions rather than counts. §6.3 singles these three
  // out: secret values, the web terminal and break-glass are the capabilities
  // the role model exists to keep apart.
  //
  // The non-holders are DERIVED rather than listed. Writing them out was the
  // first version and it was wrong: it assumed Developer lacks
  // `grant.break_glass`, and Developer holds it deliberately — D3 in roles.ts
  // argues that break-glass defeats every restriction by design, so its control
  // is detection rather than prevention, and the pinned holder list includes
  // every role that could plausibly need to trip the alarm. A hand-listed
  // expectation here would have been a second opinion about the permission
  // model, which is the thing this whole file is written against.
  const privileged = ["secret.read_value", "terminal.open", "grant.break_glass"] as const;

  let checked = 0;
  for (const role of ALL_DEFAULT_ROLES) {
    const offered = new Set(visibleCommands([...role.actions]).map((command) => command.action));
    for (const action of privileged) {
      if (role.actions.includes(action)) continue;
      assert.ok(!offered.has(action), `${role.key} lacks ${action} and is offered it anyway`);
      checked += 1;
    }
  }
  assert.ok(checked > 0, "no role lacked any of these, so nothing was tested");
});

test("every role sees exactly the commands it holds, and no others", () => {
  // Stronger than the named-action check above and it subsumes it: the visible
  // set is asserted equal to the role's own action list for all seven roles, so
  // a leak of ANY action fails here, including one nobody thought to name.
  for (const role of ALL_DEFAULT_ROLES) {
    const visible = visibleCommands([...role.actions]).map((command) => command.action);
    assert.deepEqual(
      [...visible].sort(),
      [...role.actions].sort(),
      `${role.key}'s palette does not match its permissions`,
    );
  }
});

test("an actor holding nothing sees an empty palette", () => {
  // Fail closed. A filter written as "hide what is denied" rather than "show
  // what is held" passes every test above and offers the entire catalogue to
  // somebody with no grants at all — which is the state a session has before
  // any grant resolves.
  assert.deepEqual(visibleCommands([]), []);
});

test("Owner sees everything and Billing sees only billing", () => {
  // The two ends of the range, so a filter that returned a constant would fail
  // whichever constant it chose.
  assert.equal(visibleCommands([...DEFAULT_ROLES.owner.actions]).length, ALL_COMMANDS.length);

  const billing = visibleCommands([...DEFAULT_ROLES.billing.actions]);
  assert.ok(billing.length > 0);
  for (const command of billing) {
    assert.equal(command.resource, "billing", `Billing is offered ${command.action}`);
  }
});

test("an unknown permission grants nothing", () => {
  // A stored custom role (RL-M5-002) can name anything. A filter that treated
  // an unrecognised entry as a wildcard would be the worst possible failure
  // here, and it is the shape a `.some()` with a loose predicate produces.
  assert.deepEqual(visibleCommands(["site.delete_everything", "*", ""]), []);
});

// ---------------------------------------------------------------------------
// Finding things
// ---------------------------------------------------------------------------

test("an empty query lists everything rather than nothing", () => {
  // The palette opens before anything is typed, and an empty palette reads as
  // broken.
  const visible = visibleCommands([...DEFAULT_ROLES.owner.actions]);
  assert.deepEqual(searchCommands("", visible), visible);
  assert.deepEqual(searchCommands("   ", visible), visible);
});

test("search never widens the set it was given", () => {
  // The filter runs first and search runs over its output. If search reached
  // for the full catalogue instead, typing would reveal exactly the commands
  // the filter had just hidden — which is the leak this whole file is about.
  const developer = visibleCommands([...DEFAULT_ROLES.developer.actions]);
  const allowed = new Set(developer.map((command) => command.action));
  for (const query of ["secret", "terminal", "break", "value", "read", "delete"]) {
    for (const hit of searchCommands(query, developer)) {
      assert.ok(allowed.has(hit.action), `searching "${query}" surfaced ${hit.action}`);
    }
  }
});

test("punctuation is not something an operator has to know", () => {
  // `secret.read_value` must be findable by typing "read" or "value".
  const all = [...ALL_COMMANDS];
  for (const query of ["secret", "read", "value", "secret.read"]) {
    const hits = searchCommands(query, all).map((command) => command.action);
    assert.ok(hits.includes("secret.read_value"), `"${query}" does not find secret.read_value`);
  }
});

test("a name match outranks a description match", () => {
  // Typing "secret" should surface the secret actions, not every action whose
  // description mentions one. Asserted as an ordering rather than a filter,
  // because the description match is still worth having.
  const hits = searchCommands("terminal", [...ALL_COMMANDS]);
  const firstNonTerminal = hits.findIndex((command) => command.resource !== "terminal");
  const lastTerminal = hits.map((command) => command.resource).lastIndexOf("terminal");
  if (firstNonTerminal !== -1) {
    assert.ok(lastTerminal < firstNonTerminal, "a description match ranked above a name match");
  }
});

test("results keep catalogue order within a rank", () => {
  // A palette that reshuffles equal matches as unrelated actions are added is
  // one whose muscle memory is worthless — the same argument §4 makes for the
  // rail never moving.
  const hits = searchCommands("read", [...ALL_COMMANDS]).map((command) => command.action);
  const catalogueOrder = ALL_ACTIONS.filter((action) => hits.includes(action));
  const prefixMatches = hits.filter((action) => action.split(/[._]/).some((part) => part.startsWith("read")));
  assert.deepEqual(
    prefixMatches,
    catalogueOrder.filter((action) => prefixMatches.includes(action)),
  );
});

test("grouping preserves the catalogue's shape rather than inventing one", () => {
  const groups = groupCommands([...ALL_COMMANDS]);
  assert.deepEqual(
    groups.flatMap((group) => group.commands.map((command) => command.action)).sort(),
    [...ALL_ACTIONS].sort(),
    "grouping lost or duplicated a command",
  );
  for (const group of groups) {
    for (const command of group.commands) assert.equal(command.resource, group.resource);
  }
});
