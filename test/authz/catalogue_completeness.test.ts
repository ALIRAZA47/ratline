/**
 * The permission catalogue is the single source of actions (RL-M1-009).
 *
 * Brief §6.3: "Deny by default. An unmapped action is a denial. Adding a new
 * action without adding it to the permission map fails a test."
 *
 * This is that test. The one that matters is
 * "every action is mapped into at least one role" — it is the reason `roles.ts`
 * writes Owner's actions out instead of deriving them, because a role that
 * holds everything by construction makes this check unfailable and therefore
 * worthless.
 *
 * Both completeness checks are written as plain functions over data so that
 * each one can be run against a deliberately broken input in the same file.
 * A check nobody has watched fail is a check nobody knows works.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ACTION_CATALOGUE,
  ALL_ACTIONS,
  isAction,
  RESOURCE_TYPES,
  SCOPE_LEVELS,
  type Action,
  type ResourceType,
  type ScopeLevel,
} from "../../src/authz/catalogue.ts";
import { ALL_DEFAULT_ROLES, DEFAULT_ROLES } from "../../src/authz/roles.ts";

/**
 * The shape the checks need. Widened from `RoleDefinition` on purpose: custom
 * roles arrive from the database as strings (RL-M5-002), so the checks must
 * work on names the type system has not already vouched for.
 */
type RoleView = { readonly key: string; readonly actions: readonly string[] };

/** Actions the catalogue declares that no role carries. Must always be empty. */
function actionsCarriedByNoRole(
  catalogue: readonly string[],
  roles: readonly RoleView[],
): readonly string[] {
  const carried = new Set<string>();
  for (const role of roles) {
    for (const action of role.actions) carried.add(action);
  }
  return catalogue.filter((action) => !carried.has(action));
}

/** Action names a role claims that the catalogue does not declare. Must always be empty. */
function actionsNamedOutsideCatalogue(
  catalogue: readonly string[],
  roles: readonly RoleView[],
): readonly string[] {
  const declared = new Set<string>(catalogue);
  const unknown: string[] = [];
  for (const role of roles) {
    for (const action of role.actions) {
      if (!declared.has(action)) unknown.push(`${role.key}: ${action}`);
    }
  }
  return unknown;
}

// ---------------------------------------------------------------------------
// Acceptance 1 — every action is declared once, with its resource type and the
// scope level at which it is granted
// ---------------------------------------------------------------------------

test("the scope levels are the hierarchy from the brief, widest first", () => {
  // Organization → Team → Project → Environment → Resource (§6.3). The order is
  // load-bearing: inheritance runs down it, so a grant at one level conveys the
  // action at every level after it.
  assert.deepEqual(
    [...SCOPE_LEVELS],
    ["organization", "team", "project", "environment", "resource"],
  );
});

test("every action declares a known resource type and scope level", () => {
  for (const action of ALL_ACTIONS) {
    const definition = ACTION_CATALOGUE[action];
    assert.ok(
      (RESOURCE_TYPES as readonly string[]).includes(definition.resource),
      `${action} declares resource type "${definition.resource}", which is not a resource type`,
    );
    assert.ok(
      (SCOPE_LEVELS as readonly string[]).includes(definition.scope),
      `${action} declares scope "${definition.scope}", which is not a scope level`,
    );
  }
});

test("no action is declared twice", () => {
  assert.equal(
    new Set(ALL_ACTIONS).size,
    ALL_ACTIONS.length,
    "an action declared twice would have two definitions and one would silently win",
  );
});

test("an action's name begins with the resource type it acts on", () => {
  for (const action of ALL_ACTIONS) {
    const { resource } = ACTION_CATALOGUE[action];
    assert.ok(
      action.startsWith(`${resource}.`),
      `${action} acts on "${resource}" but is not named for it; the name and the declaration must not disagree`,
    );
  }
});

test("action names use one lowercase, dotted, namespaced form", () => {
  const form = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;
  for (const action of ALL_ACTIONS) {
    assert.match(
      action,
      form,
      `${action} does not match the naming form; these names appear in the API, the audit log and stored roles, so they cannot drift`,
    );
  }
});

test("every resource type has at least one action", () => {
  const covered = new Set<ResourceType>(ALL_ACTIONS.map((action) => ACTION_CATALOGUE[action].resource));
  for (const resource of RESOURCE_TYPES) {
    assert.ok(covered.has(resource), `no action operates on "${resource}"; nobody can ever touch it`);
  }
});

test("every action has a description the role editor can render", () => {
  // RL-M5-004 renders these beside each toggle and the audit log uses them to
  // describe a decision, so they are product copy, not comments.
  for (const action of ALL_ACTIONS) {
    const { description } = ACTION_CATALOGUE[action];
    assert.ok(description.length > 0, `${action} has no description`);
    assert.ok(
      description.length <= 200,
      `${action}'s description is ${String(description.length)} characters; it has to fit beside a toggle`,
    );
    assert.match(description, /^[A-Z]/, `${action}'s description should read as a sentence`);
    assert.match(description, /\.$/, `${action}'s description should end in a full stop`);
  }
});

// ---------------------------------------------------------------------------
// Deny by default — the catalogue is closed
// ---------------------------------------------------------------------------

test("a name outside the catalogue is not an action", () => {
  // §6.3: "An unmapped action is a denial." `can()` (RL-M1-012) relies on this
  // guard to reject a name that arrives as data before it resolves anything.
  assert.equal(isAction("site.frobnicate"), false);
  assert.equal(isAction(""), false);
  assert.equal(isAction("secret.read"), false, "the un-split name must not resolve to anything");
  assert.equal(isAction("toString"), false, "an inherited property is not an action");
  assert.equal(isAction("__proto__"), false);
  assert.equal(isAction(42), false, "a non-string is not an action");
  assert.equal(isAction(null), false);
  assert.equal(isAction(undefined), false);
  assert.equal(isAction({ action: "site.read" }), false);
});

test("every catalogued action is recognised", () => {
  for (const action of ALL_ACTIONS) {
    assert.ok(isAction(action), `${action} is in the catalogue but the guard rejects it`);
  }
  assert.ok(ALL_ACTIONS.length > 0);
});

// ---------------------------------------------------------------------------
// Acceptance 2 — reading a secret name and reading a secret value are separate
// ---------------------------------------------------------------------------

test("reading a secret name and reading a secret value are separate actions", () => {
  // §6.3: "Most roles need the latter and almost none need the former."
  assert.ok(isAction("secret.read_name"));
  assert.ok(isAction("secret.read_value"));
  assert.notEqual(ACTION_CATALOGUE["secret.read_name"], ACTION_CATALOGUE["secret.read_value"]);

  // A combined name would let a role acquire values by holding "read".
  for (const combined of ["secret.read", "secret.reveal", "secret.view"]) {
    assert.equal(isAction(combined), false, `${combined} would collapse the distinction`);
  }

  // The value must never be reachable through the history either (ADR 0006:
  // version history records actor and timestamp and never the value).
  assert.match(ACTION_CATALOGUE["secret.read_history"].description, /never|not/i);
});

// ---------------------------------------------------------------------------
// Acceptance 3 — production and non-production deployment are separate
// ---------------------------------------------------------------------------

test("deploying to production and to non-production are separate actions", () => {
  // §6.3: "granting one without the other is the single most common real-world
  // request."
  assert.ok(isAction("deployment.create_production"));
  assert.ok(isAction("deployment.create_nonproduction"));
  assert.equal(
    isAction("deployment.create"),
    false,
    "an unqualified deploy action would be granted by inheritance from a project-scoped grant",
  );
});

test("rolling back is separate from deploying, and split the same way", () => {
  // Release Manager is "deploy and roll back in production"; Developer is
  // non-production only. One rollback action would let a project-scoped
  // Developer roll production back.
  assert.ok(isAction("deployment.rollback_production"));
  assert.ok(isAction("deployment.rollback_nonproduction"));
  assert.equal(isAction("deployment.rollback"), false);

  for (const action of [
    "deployment.create_production",
    "deployment.create_nonproduction",
    "deployment.rollback_production",
    "deployment.rollback_nonproduction",
  ] as const) {
    assert.equal(ACTION_CATALOGUE[action].scope, "environment");
    assert.equal(ACTION_CATALOGUE[action].resource, "deployment");
  }
});

// ---------------------------------------------------------------------------
// The other splits the brief requires by name
// ---------------------------------------------------------------------------

test("opening a web terminal is its own action", () => {
  // §6.4: "Terminal access is its own permission, off by default for every role
  // except Infrastructure."
  assert.ok(isAction("terminal.open"));
  assert.equal(ACTION_CATALOGUE["terminal.open"].resource, "terminal");

  // A recording holds everything typed and printed, so replaying one is gated
  // separately from opening a session (ADR 0008).
  assert.ok(isAction("terminal.read_recording"));

  // Only Owner exists so far, and Owner holds everything. RL-M1-010 is what
  // makes "off by default for every role except Infrastructure" testable; this
  // asserts the shape it needs is here.
  assert.ok(DEFAULT_ROLES.owner.actions.includes("terminal.open"));
});

test("setting a build command is separate from deploying", () => {
  // ADR 0005: "Setting a build command is its own permission, distinct from
  // deploying. Most roles that can deploy must not be able to change what
  // deploying runs."
  assert.ok(isAction("site.build_command.write"));
  assert.equal(ACTION_CATALOGUE["site.build_command.write"].resource, "site");

  const deployActions = ALL_ACTIONS.filter(
    (action) => ACTION_CATALOGUE[action].resource === "deployment",
  );
  assert.ok(
    !deployActions.includes("site.build_command.write"),
    "setting a build command must not be a deployment action",
  );

  // It is code execution as the site user, and the description has to say so —
  // the role editor is where an operator decides whether to hand it over.
  assert.match(ACTION_CATALOGUE["site.build_command.write"].description, /code|Linux user/i);
});

test("running a one-off command is its own action", () => {
  // §6.5: "permission-gated one-off command runner".
  assert.ok(isAction("site.run_command"));
  assert.notEqual(
    ACTION_CATALOGUE["site.run_command"],
    ACTION_CATALOGUE["site.build_command.write"],
  );
  assert.notEqual(ACTION_CATALOGUE["site.run_command"], ACTION_CATALOGUE["site.update"]);
});

// ---------------------------------------------------------------------------
// Scope levels mean something
// ---------------------------------------------------------------------------

test("organization-level powers cannot be conveyed by a narrower grant", () => {
  // These resources exist only at the root of the hierarchy. Declaring one of
  // their actions at a narrower scope would let a project-scoped grant convey
  // it, which is the escalation the scope level exists to prevent.
  const organizationOnly: readonly ResourceType[] = [
    "organization",
    "member",
    "role",
    "service_identity",
    "api_token",
    "ssh_key",
    "ssh_authority",
    "audit_log",
    "billing",
  ];
  for (const action of ALL_ACTIONS) {
    const { resource, scope } = ACTION_CATALOGUE[action];
    if (!organizationOnly.includes(resource)) continue;
    assert.equal(
      scope,
      "organization",
      `${action} acts on "${resource}", which exists only at the organization level`,
    );
  }
});

test("creating something is scoped to the container it is created into", () => {
  // A thing that does not exist yet cannot be the scope of the grant that
  // creates it, so the create action attaches one level up.
  const containers: readonly (readonly [Action, ScopeLevel])[] = [
    ["team.create", "organization"],
    ["project.create", "team"],
    ["environment.create", "project"],
    ["site.create", "environment"],
    ["host.create", "organization"],
  ];
  for (const [action, scope] of containers) {
    assert.equal(ACTION_CATALOGUE[action].scope, scope, `${action} should be granted at ${scope}`);
  }
});

test("secrets are granted at the environment that holds them", () => {
  // PLAN §4: ENVIRONMENT holds SECRET. Environment scope is what makes
  // "read staging values but not production values" expressible.
  for (const action of ALL_ACTIONS) {
    if (ACTION_CATALOGUE[action].resource !== "secret") continue;
    assert.equal(ACTION_CATALOGUE[action].scope, "environment");
  }
});

// ---------------------------------------------------------------------------
// Acceptance 4 — an action that no role carries fails this test
// ---------------------------------------------------------------------------

test("every action is carried by at least one role", () => {
  const orphaned = actionsCarriedByNoRole(ALL_ACTIONS, ALL_DEFAULT_ROLES);
  assert.deepEqual(
    orphaned,
    [],
    `these actions exist in the catalogue but no role carries them, so nothing can ever be allowed to do them: ${orphaned.join(", ")}. ` +
      `Add each one to the role or roles that should hold it in src/authz/roles.ts — deciding that is the point of this failure, not a formality.`,
  );
});

test("the completeness check fails when an action is carried by no role", () => {
  // Proof that the check above has teeth. If this ever passes trivially, the
  // check is decorative and RL-M1-009's fourth acceptance line is not met.
  const catalogue = ["site.read", "site.delete", "secret.read_value"];
  const roles: readonly RoleView[] = [{ key: "owner", actions: ["site.read", "site.delete"] }];
  assert.deepEqual(actionsCarriedByNoRole(catalogue, roles), ["secret.read_value"]);

  // And it is not merely reporting everything: a fully mapped catalogue is clean.
  assert.deepEqual(
    actionsCarriedByNoRole(catalogue, [
      { key: "owner", actions: ["site.read", "site.delete", "secret.read_value"] },
    ]),
    [],
  );

  // A role set with no roles at all orphans everything rather than passing.
  assert.deepEqual(actionsCarriedByNoRole(catalogue, []), catalogue);
});

test("every action a role names exists in the catalogue", () => {
  const unknown = actionsNamedOutsideCatalogue(ALL_ACTIONS, ALL_DEFAULT_ROLES);
  assert.deepEqual(
    unknown,
    [],
    `these roles name actions the catalogue does not declare: ${unknown.join(", ")}. ` +
      `An action nothing declares can never be checked, so the role silently grants nothing.`,
  );

  // The same check, through the guard `can()` will use.
  for (const role of ALL_DEFAULT_ROLES) {
    for (const action of role.actions) {
      assert.ok(isAction(action), `${role.key} names ${action}, which is not an action`);
    }
  }
});

test("the check fails when a role names an action outside the catalogue", () => {
  // The type system already refuses this in `roles.ts`. The runtime check is
  // for custom roles, which arrive from the database as strings (RL-M5-002).
  const catalogue = ["site.read"];
  const roles: readonly RoleView[] = [
    { key: "owner", actions: ["site.read"] },
    { key: "ghost", actions: ["site.read", "site.frobnicate"] },
  ];
  assert.deepEqual(actionsNamedOutsideCatalogue(catalogue, roles), ["ghost: site.frobnicate"]);
  assert.deepEqual(actionsNamedOutsideCatalogue(catalogue, [{ key: "owner", actions: [] }]), []);
});

test("Owner holds every action in the catalogue", () => {
  // §6.3: "Owner | Everything, including org deletion and ownership transfer."
  // Owner's list is written out rather than derived, so this is the assertion
  // that keeps the two files in step.
  const owner = DEFAULT_ROLES.owner;
  assert.deepEqual(
    [...owner.actions].sort(),
    [...ALL_ACTIONS].sort(),
    "Owner and the catalogue have diverged; Owner is defined as everything",
  );
  assert.ok(owner.actions.includes("organization.delete"));
  assert.ok(owner.actions.includes("organization.transfer_ownership"));
  assert.equal(owner.lastHolderProtected, true, "the system prevents removing the last Owner");
});

test("no role lists the same action twice", () => {
  for (const role of ALL_DEFAULT_ROLES) {
    assert.equal(
      new Set(role.actions).size,
      role.actions.length,
      `${role.key} lists an action twice, which hides a paste error behind a set union`,
    );
  }
});

test("only Owner is defined so far, and it is named as the brief names it", () => {
  // The other six default roles are RL-M1-010. This pins the shape that task
  // extends, so adding a role is adding an entry rather than a redesign.
  assert.deepEqual(
    ALL_DEFAULT_ROLES.map((role) => role.name),
    ["Owner"],
  );
});
