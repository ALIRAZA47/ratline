/**
 * The seven default roles (RL-M1-010).
 *
 * Brief §6.3 is the specification and it is four sentences long per role, so
 * most of the work of this task was judgement. This file is where that
 * judgement is made checkable. It has two halves and they do different jobs:
 *
 *   **Properties.** The prohibitions in §6.3 stated as things that must be true
 *   of any future edit — Billing holds nothing but billing, Viewer mutates
 *   nothing, Infrastructure and Release Manager hold no path to a secret value.
 *   These are written over the data rather than against a copy of the list, so
 *   they cannot be satisfied by editing an expectation alongside the change.
 *   They are the assertions that matter.
 *
 *   **The snapshot.** Every role's effective action set, pinned. It is a dumb
 *   record and it is meant to be: its whole value is that changing a role
 *   produces a reviewable diff of exactly which permissions moved, with each
 *   one's operator-facing description printed beside it. A snapshot cannot tell
 *   you a change is wrong. It can stop one happening quietly.
 *
 * `test/authz/catalogue_completeness.test.ts` holds the other direction — that
 * every catalogued action is carried by some role, and that no role names an
 * action the catalogue does not declare. Neither file derives a role's actions
 * from the catalogue; see the note at the top of `src/authz/roles.ts` for why
 * that would make both files worthless.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ACTION_CATALOGUE, ALL_ACTIONS, isAction, type Action } from "../../src/authz/catalogue.ts";
import {
  ALL_DEFAULT_ROLES,
  DEFAULT_ROLE_KEYS,
  DEFAULT_ROLES,
  type DefaultRoleKey,
} from "../../src/authz/roles.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** The actions a role carries, as a set, for membership questions. */
function actionsOf(key: DefaultRoleKey): ReadonlySet<Action> {
  return new Set(DEFAULT_ROLES[key].actions);
}

/**
 * Every default role that carries an action, in role order.
 *
 * Pinning the holders of a dangerous action is stronger than asserting that one
 * role lacks it: "who can reveal a secret value" is answered by a list that a
 * new role cannot join without this test failing.
 */
function holdersOf(action: Action): readonly DefaultRoleKey[] {
  return DEFAULT_ROLE_KEYS.filter((key) => DEFAULT_ROLES[key].actions.includes(action));
}

/** The last segment of an action name — the verb. `site.build_command.write` → `write`. */
function verbOf(action: string): string {
  return action.slice(action.lastIndexOf(".") + 1);
}

function difference(from: ReadonlySet<Action>, remove: ReadonlySet<Action>): readonly Action[] {
  return [...from].filter((action) => !remove.has(action)).sort();
}

// ---------------------------------------------------------------------------
// Acceptance 1 — all seven roles exist and are editable
// ---------------------------------------------------------------------------

test("the seven roles of brief §6.3 exist, named exactly as the brief names them", () => {
  // The names are product copy and they are also how an operator recognises the
  // role in the brief, so they are pinned verbatim rather than casually.
  assert.deepEqual(
    ALL_DEFAULT_ROLES.map((role) => role.name),
    ["Owner", "Admin", "Infrastructure", "Release Manager", "Developer", "Viewer", "Billing"],
  );
  assert.deepEqual(
    [...DEFAULT_ROLE_KEYS],
    ["owner", "admin", "infrastructure", "release_manager", "developer", "viewer", "billing"],
  );

  for (const key of DEFAULT_ROLE_KEYS) {
    const role = DEFAULT_ROLES[key];
    assert.equal(role.key, key, `${key} is filed under a key it does not claim as its own`);
    assert.ok(role.description.length > 0, `${key} has no description for the role editor`);
    assert.ok(role.actions.length > 0, `${key} carries nothing and cannot be a role`);
  }
});

test("every default role is expressible as a composition of raw permissions, so it is editable", () => {
  // §6.3: "Default roles, editable, with custom roles composable from the raw
  // permission set." Editability at the storage layer is RL-M5-002; what this
  // file can check is that nothing here is *structurally* privileged — every
  // default role is a set of catalogued actions and nothing else, so the role
  // editor can render it as toggles and an operator can reproduce or change any
  // of it without new machinery.
  const catalogued = new Set<string>(ALL_ACTIONS);

  for (const role of ALL_DEFAULT_ROLES) {
    for (const action of role.actions) {
      assert.ok(isAction(action), `${role.key} names ${action}, which is not an action`);
      assert.ok(catalogued.has(action), `${role.key} names ${action}, which the catalogue does not declare`);
    }

    // A role whose actions were `ALL_ACTIONS` itself would be a wildcard wearing
    // a list's clothing, and would make the completeness test unfailable.
    assert.notEqual(
      role.actions,
      ALL_ACTIONS,
      `${role.key} shares its array with the catalogue; a derived role cannot disagree with the catalogue, and the disagreement is what the tests are for`,
    );
  }

  // Only Owner is undeletable. §6.3 protects the last Owner and nothing else;
  // a second protected role would be an unremovable grant nobody asked for.
  assert.deepEqual(
    ALL_DEFAULT_ROLES.filter((role) => role.lastHolderProtected).map((role) => role.key),
    ["owner"],
  );
});

test("no role lists the same action twice", () => {
  // A duplicate is invisible once `can()` builds a set, so it survives review as
  // a paste error and then misleads whoever counts the list afterwards.
  for (const role of ALL_DEFAULT_ROLES) {
    const seen = new Set<Action>();
    const duplicated: Action[] = [];
    for (const action of role.actions) {
      if (seen.has(action)) duplicated.push(action);
      seen.add(action);
    }
    assert.deepEqual(
      duplicated,
      [],
      `${role.key} lists ${duplicated.join(", ")} more than once`,
    );
    assert.equal(
      seen.size,
      role.actions.length,
      `${role.key} lists ${String(role.actions.length)} actions but only ${String(seen.size)} distinct ones`,
    );
  }
});

// ---------------------------------------------------------------------------
// The relationships between roles, asserted by set arithmetic rather than by
// listing — a listed expectation can be edited alongside the mistake it should
// have caught
// ---------------------------------------------------------------------------

test("Owner holds everything every other role holds", () => {
  // §6.3: "Owner | Everything". If this ever fails, some role has acquired a
  // capability that the role defined as holding all of them does not, which
  // means the catalogue and this file have diverged in a way the completeness
  // test would not necessarily catch.
  const owner = actionsOf("owner");
  for (const role of ALL_DEFAULT_ROLES) {
    const beyondOwner = difference(actionsOf(role.key), owner);
    assert.deepEqual(beyondOwner, [], `${role.key} holds ${beyondOwner.join(", ")}, which Owner does not`);
  }
});

test("Admin is Owner minus exactly organization.delete and organization.transfer_ownership", () => {
  // §6.3: "Admin | Everything except org deletion and ownership transfer."
  // Asserted as a set difference in both directions, so neither a forgotten
  // action nor a smuggled one passes. Admin's list is written out in roles.ts
  // rather than computed; this is the arithmetic that checks the copy.
  const owner = actionsOf("owner");
  const admin = actionsOf("admin");

  assert.deepEqual(
    difference(owner, admin),
    ["organization.delete", "organization.transfer_ownership"],
    "Admin is defined by subtracting exactly two actions from Owner",
  );
  assert.deepEqual(difference(admin, owner), [], "Admin cannot hold what Owner does not");
});

test("no role but Owner holds the two powers the brief reserves to Owner", () => {
  for (const action of ["organization.delete", "organization.transfer_ownership"] as const) {
    assert.deepEqual(
      holdersOf(action),
      ["owner"],
      `${action} is Owner's alone in §6.3; a second holder makes "everything except" meaningless`,
    );
  }
});

test("every role below Owner is a subset of Admin, so break-glass never costs a capability", () => {
  // Break-glass elevates to Admin (§6.3). If a role held something Admin did
  // not, elevating would *remove* a capability mid-incident, which is a trap.
  const admin = actionsOf("admin");
  for (const key of DEFAULT_ROLE_KEYS) {
    if (key === "owner") continue;
    const beyondAdmin = difference(actionsOf(key), admin);
    assert.deepEqual(beyondAdmin, [], `${key} holds ${beyondAdmin.join(", ")}, which Admin does not`);
  }
});

// ---------------------------------------------------------------------------
// Acceptance 2 — Infrastructure and Release Manager provably cannot read secret
// values
// ---------------------------------------------------------------------------

test("Infrastructure and Release Manager hold no action that reveals a secret value", () => {
  // §6.3 says Infrastructure "cannot read production secret values" and Release
  // Manager "cannot ... read secret values". RL-M1-010's acceptance drops the
  // production qualifier for both, which is stricter and is what is implemented
  // — see D1 in src/authz/roles.ts, where the discrepancy between the two
  // documents is recorded rather than quietly resolved.
  for (const key of ["infrastructure", "release_manager"] as const) {
    const actions = actionsOf(key);
    assert.equal(
      actions.has("secret.read_value"),
      false,
      `${key} holds secret.read_value, which brief §6.3 forbids it`,
    );

    // Not just that one action: no other path to a plaintext value either. A
    // terminal recording contains everything typed and printed in someone
    // else's session, including anything pasted (ADR 0008), so it is a secret
    // read by another name.
    assert.equal(actions.has("terminal.read_recording"), false, `${key} could read a pasted value back`);

    // The secret actions these roles *do* hold are value-free by construction:
    // the name is stored in plaintext (ADR 0006) and the history records actor
    // and timestamp, never the value.
    const secretActions = [...actions].filter((action) => ACTION_CATALOGUE[action].resource === "secret");
    assert.deepEqual(
      secretActions.sort(),
      ["secret.read_history", "secret.read_name"],
      `${key} holds a secret action beyond names and history`,
    );
  }

  // And the positive form: exactly these roles can reveal a value, so a new
  // role cannot join the list without this failing.
  assert.deepEqual(
    holdersOf("secret.read_value"),
    ["owner", "admin"],
    "revealing a secret value is Owner and Admin only; §6.3: almost no role needs it",
  );
});

test("Release Manager cannot change host or site configuration", () => {
  // §6.3: "Cannot change server config". Read at its widest — nothing that
  // reconfigures the host, and nothing that changes what a deployment runs.
  // ADR 0005 names the build command case directly: "Most roles that can deploy
  // must not be able to change what deploying runs."
  const releaseManager = actionsOf("release_manager");
  const forbidden: readonly Action[] = [
    "host.create",
    "host.update",
    "host.delete",
    "host.manage_stack",
    "host.manage_updates",
    "host.upgrade_agent",
    "firewall.update",
    "site.create",
    "site.update",
    "site.delete",
    "site.build_command.write",
    "site.run_command",
    "site.manage_runtime",
    "site.manage_resource_limits",
    "site.manage_deploy_triggers",
    "environment.update",
    "terminal.open",
  ];
  for (const action of forbidden) {
    assert.equal(
      releaseManager.has(action),
      false,
      `Release Manager holds ${action}: ${ACTION_CATALOGUE[action].description}`,
    );
  }

  // The positive half, so a future edit cannot satisfy this test by gutting the
  // role: it still does the job §6.3 gives it.
  for (const action of [
    "deployment.create_production",
    "deployment.rollback_production",
    "deployment.create_nonproduction",
    "deployment.rollback_nonproduction",
  ] as const) {
    assert.ok(releaseManager.has(action), `Release Manager must be able to ${action}`);
  }
});

test("Infrastructure holds the capabilities its intent line names", () => {
  // §6.3: "Add/remove servers, manage host stack, firewall, SSH grants."
  // Asserted positively so that a later edit cannot pass the prohibitions above
  // by simply emptying the role.
  const infrastructure = actionsOf("infrastructure");
  for (const action of [
    "host.create",
    "host.delete",
    "host.manage_stack",
    "firewall.read",
    "firewall.update",
    "ssh_grant.create",
    "ssh_grant.revoke",
  ] as const) {
    assert.ok(infrastructure.has(action), `Infrastructure must be able to ${action}`);
  }

  // Not application configuration, and not code execution as a site's Linux
  // user. Note this is a boundary of intent, not of reachable power:
  // Infrastructure holds terminal.open, which is a shell on the host. R4 in
  // roles.ts says so plainly rather than letting the list imply containment.
  for (const action of ["site.build_command.write", "site.run_command", "site.update"] as const) {
    assert.equal(infrastructure.has(action), false, `Infrastructure holds ${action}`);
  }
});

// ---------------------------------------------------------------------------
// Acceptance 3 — Billing has no infrastructure visibility of any kind
// ---------------------------------------------------------------------------

test("Billing holds nothing but billing actions", () => {
  // §6.3: "Billing only. No infrastructure visibility whatsoever."
  //
  // Asserted as a property of every action the role holds rather than by
  // comparing to a copy of its list, because a list comparison is satisfied by
  // editing both sides — which is exactly what someone adding "just
  // organization.read so the page has a title" would do.
  const billing = DEFAULT_ROLES.billing.actions;

  assert.ok(billing.length > 0, "an empty role would make the property below vacuously true");

  for (const action of billing) {
    const { resource } = ACTION_CATALOGUE[action];
    assert.equal(
      resource,
      "billing",
      `Billing holds ${action}, which acts on "${resource}". §6.3 gives this role no visibility of anything but billing — not the organization, not a team, not a host.`,
    );
  }

  // The same claim from the other side: every non-billing resource type is
  // entirely absent from the role.
  const visibleResources = new Set(billing.map((action) => ACTION_CATALOGUE[action].resource));
  assert.deepEqual(
    [...visibleResources],
    ["billing"],
    "Billing can see more than one kind of thing, and §6.3 allows it exactly one",
  );
});

// ---------------------------------------------------------------------------
// The prohibitions the brief states outside §6.3's table
// ---------------------------------------------------------------------------

test("terminal access is off for every role except Owner, Admin and Infrastructure", () => {
  // §6.4: "Terminal access is its own permission, off by default for every role
  // except Infrastructure." Admin holds it because §6.3 defines Admin as Owner
  // minus exactly two organization powers, and terminal access is not one of
  // them; the two sentences are reconciled in roles.ts rather than here.
  assert.deepEqual(
    holdersOf("terminal.open"),
    ["owner", "admin", "infrastructure"],
    "a role gained or lost shell access to a host",
  );

  // Replaying a recording is gated separately (ADR 0008) and is *not* on for
  // Infrastructure: a recording holds everything typed and printed in someone
  // else's session, which is the likeliest place a role denied secret values
  // would meet one. See D2 in roles.ts.
  assert.deepEqual(
    holdersOf("terminal.read_recording"),
    ["owner", "admin"],
    "a role gained the ability to replay someone else's session, values pasted into it included",
  );
});

test("Viewer changes nothing", () => {
  // §6.3: "Read-only on sites, deploy history, metrics."
  //
  // Every action Viewer holds has a verb of `read` or `read_something`. That is
  // a mechanical property rather than a claim about a list: an action whose verb
  // is create, update, delete, restart, cancel, open, rotate, upload, renew,
  // run_now, revoke or manage_anything cannot be added to this role without
  // failing here.
  for (const action of DEFAULT_ROLES.viewer.actions) {
    const verb = verbOf(action);
    assert.ok(
      verb === "read" || verb.startsWith("read_"),
      `Viewer holds ${action}, whose verb is "${verb}". Viewer is read-only; even api_token.manage_own is withheld so this stays checkable (D4 in roles.ts).`,
    );
  }
});

test("Viewer reads no raw logs and no secret values", () => {
  // §6.3: "No raw logs, no secret values." Build logs and captured job output
  // are raw logs wearing other names, and §6.5's automatic redaction is a
  // mitigation rather than a guarantee — which is why the verb test above is not
  // sufficient on its own: `read_value` and `read_output` are both reads.
  const viewer = actionsOf("viewer");
  for (const action of [
    "site.read_logs",
    "deployment.read_logs",
    "scheduled_job.read_output",
    "terminal.read_recording",
    "secret.read_value",
    "secret.read_name",
    "secret.read_history",
    "audit_log.read",
  ] as const) {
    assert.equal(
      viewer.has(action),
      false,
      `Viewer holds ${action}: ${ACTION_CATALOGUE[action].description}`,
    );
  }

  // The positive half: it can still do the job §6.3 gives it.
  for (const action of ["site.read", "site.read_metrics", "deployment.read"] as const) {
    assert.ok(viewer.has(action), `Viewer must be able to ${action}`);
  }
});

test("Developer deploys to non-production and provably not to production", () => {
  // §6.3: "Developer | Deploy to non-production". §6.3 again: "'Deploy to
  // staging' and 'deploy to production' are distinct actions, and granting one
  // without the other is the single most common real-world request."
  //
  // The split is by environment class rather than by grant scope precisely so
  // that this holds however the grant is scoped: a Developer granted at project
  // scope inherits into the production environment and still cannot deploy to
  // it, because the action it would need is not in the role at all.
  const developer = actionsOf("developer");

  for (const action of ["deployment.create_nonproduction", "deployment.rollback_nonproduction"] as const) {
    assert.ok(developer.has(action), `Developer must be able to ${action}`);
  }
  for (const action of ["deployment.create_production", "deployment.rollback_production"] as const) {
    assert.equal(
      developer.has(action),
      false,
      `Developer holds ${action}: ${ACTION_CATALOGUE[action].description} — §6.3 gives this role non-production only`,
    );
  }

  for (const action of ["deployment.create_production", "deployment.rollback_production"] as const) {
    assert.deepEqual(
      holdersOf(action),
      ["owner", "admin", "release_manager"],
      `${action} is held by a role that should not have it, or has been taken from one that should`,
    );
  }

  // The rest of the Developer intent line, so the role is not merely harmless.
  for (const action of ["site.read_logs", "ssh_key.manage_own", "secret.read_name"] as const) {
    assert.ok(developer.has(action), `Developer must be able to ${action}`);
  }
  assert.equal(developer.has("secret.read_value"), false, "§6.3: names but not values");
});

test("break-glass is held by the roles that get paged, and by nobody else", () => {
  // §6.3: break-glass is temporary Admin with a written reason, notifying every
  // Owner, auto-expiring, loud in the audit log and in a banner. It defeats
  // every restriction in roles.ts by design — its control is detection, not
  // prevention — so the only question is who is trusted to trip the alarm.
  //
  // Pinned because it is the single most arguable line in the role definitions
  // (D3 in roles.ts). Viewer and Billing cannot self-elevate.
  assert.deepEqual(
    holdersOf("grant.break_glass"),
    ["owner", "admin", "infrastructure", "release_manager", "developer"],
    "a role gained or lost the ability to elevate itself to Admin; this is the escalation valve and its holders are a deliberate list",
  );
});

test("the audit log and the permission model itself are Owner and Admin only", () => {
  // D5 in roles.ts. Infrastructure is the one exception and only for reads:
  // §6.4 derives SSH principals from grants, so it cannot issue an ssh_grant
  // sensibly without seeing the grants it has to mirror.
  for (const action of [
    "audit_log.read",
    "role.create",
    "role.update",
    "role.delete",
    "grant.create",
    "grant.revoke",
    "service_identity.create",
    "service_identity.delete",
    "api_token.read_any",
    "api_token.revoke_any",
    "organization.manage_sso",
    "organization.manage_security_policy",
  ] as const) {
    assert.deepEqual(holdersOf(action), ["owner", "admin"], `${action} escaped Owner and Admin`);
  }

  for (const action of ["role.read", "grant.read"] as const) {
    assert.deepEqual(
      holdersOf(action),
      ["owner", "admin", "infrastructure"],
      `${action} is Owner, Admin and — only because §6.4 derives SSH principals from grants — Infrastructure`,
    );
  }
});

// ---------------------------------------------------------------------------
// Acceptance 4 — the snapshot
// ---------------------------------------------------------------------------

/**
 * Every role's effective action set, sorted, pinned.
 *
 * Deliberately typed as `string[]` rather than `Action[]`: a name that leaves
 * the catalogue should fail this test with a readable privilege delta, not fail
 * to compile with a type error pointing at a line of quoted text.
 *
 * When a role changes, update the entry here in the same commit. The diff is
 * the artifact — it is what a reviewer reads to answer "what can this role do
 * now that it could not do before", which is a question no amount of reading
 * `roles.ts` answers as quickly.
 */
const ROLE_SNAPSHOT: Readonly<Record<DefaultRoleKey, readonly string[]>> = {
  owner: [
    "api_token.manage_own",
    "api_token.read_any",
    "api_token.revoke_any",
    "audit_log.read",
    "backup.create",
    "backup.delete",
    "backup.manage_policy",
    "backup.read",
    "backup.restore",
    "billing.read",
    "billing.update",
    "certificate.read",
    "certificate.renew",
    "certificate.upload",
    "deployment.cancel",
    "deployment.create_nonproduction",
    "deployment.create_production",
    "deployment.read",
    "deployment.read_logs",
    "deployment.rollback_nonproduction",
    "deployment.rollback_production",
    "domain.create",
    "domain.delete",
    "domain.read",
    "environment.create",
    "environment.delete",
    "environment.read",
    "environment.update",
    "firewall.read",
    "firewall.update",
    "grant.break_glass",
    "grant.create",
    "grant.read",
    "grant.revoke",
    "host.create",
    "host.delete",
    "host.manage_stack",
    "host.manage_updates",
    "host.read",
    "host.read_metrics",
    "host.update",
    "host.upgrade_agent",
    "member.invite",
    "member.read",
    "member.remove",
    "member.revoke_sessions",
    "organization.delete",
    "organization.manage_security_policy",
    "organization.manage_sso",
    "organization.read",
    "organization.transfer_ownership",
    "organization.update",
    "project.create",
    "project.delete",
    "project.read",
    "project.update",
    "release.delete",
    "release.read",
    "role.create",
    "role.delete",
    "role.read",
    "role.update",
    "scheduled_job.create",
    "scheduled_job.delete",
    "scheduled_job.read",
    "scheduled_job.read_output",
    "scheduled_job.run_now",
    "scheduled_job.update",
    "secret.create",
    "secret.delete",
    "secret.read_history",
    "secret.read_name",
    "secret.read_value",
    "secret.update",
    "service_identity.create",
    "service_identity.delete",
    "service_identity.read",
    "site.build_command.write",
    "site.create",
    "site.delete",
    "site.manage_deploy_triggers",
    "site.manage_resource_limits",
    "site.manage_runtime",
    "site.read",
    "site.read_logs",
    "site.read_metrics",
    "site.restart",
    "site.run_command",
    "site.update",
    "ssh_authority.read",
    "ssh_authority.rotate",
    "ssh_grant.create",
    "ssh_grant.read",
    "ssh_grant.revoke",
    "ssh_key.manage_own",
    "ssh_key.read_any",
    "ssh_key.revoke_any",
    "team.create",
    "team.delete",
    "team.manage_members",
    "team.read",
    "team.update",
    "terminal.open",
    "terminal.read_recording",
  ],
  admin: [
    "api_token.manage_own",
    "api_token.read_any",
    "api_token.revoke_any",
    "audit_log.read",
    "backup.create",
    "backup.delete",
    "backup.manage_policy",
    "backup.read",
    "backup.restore",
    "billing.read",
    "billing.update",
    "certificate.read",
    "certificate.renew",
    "certificate.upload",
    "deployment.cancel",
    "deployment.create_nonproduction",
    "deployment.create_production",
    "deployment.read",
    "deployment.read_logs",
    "deployment.rollback_nonproduction",
    "deployment.rollback_production",
    "domain.create",
    "domain.delete",
    "domain.read",
    "environment.create",
    "environment.delete",
    "environment.read",
    "environment.update",
    "firewall.read",
    "firewall.update",
    "grant.break_glass",
    "grant.create",
    "grant.read",
    "grant.revoke",
    "host.create",
    "host.delete",
    "host.manage_stack",
    "host.manage_updates",
    "host.read",
    "host.read_metrics",
    "host.update",
    "host.upgrade_agent",
    "member.invite",
    "member.read",
    "member.remove",
    "member.revoke_sessions",
    "organization.manage_security_policy",
    "organization.manage_sso",
    "organization.read",
    "organization.update",
    "project.create",
    "project.delete",
    "project.read",
    "project.update",
    "release.delete",
    "release.read",
    "role.create",
    "role.delete",
    "role.read",
    "role.update",
    "scheduled_job.create",
    "scheduled_job.delete",
    "scheduled_job.read",
    "scheduled_job.read_output",
    "scheduled_job.run_now",
    "scheduled_job.update",
    "secret.create",
    "secret.delete",
    "secret.read_history",
    "secret.read_name",
    "secret.read_value",
    "secret.update",
    "service_identity.create",
    "service_identity.delete",
    "service_identity.read",
    "site.build_command.write",
    "site.create",
    "site.delete",
    "site.manage_deploy_triggers",
    "site.manage_resource_limits",
    "site.manage_runtime",
    "site.read",
    "site.read_logs",
    "site.read_metrics",
    "site.restart",
    "site.run_command",
    "site.update",
    "ssh_authority.read",
    "ssh_authority.rotate",
    "ssh_grant.create",
    "ssh_grant.read",
    "ssh_grant.revoke",
    "ssh_key.manage_own",
    "ssh_key.read_any",
    "ssh_key.revoke_any",
    "team.create",
    "team.delete",
    "team.manage_members",
    "team.read",
    "team.update",
    "terminal.open",
    "terminal.read_recording",
  ],
  infrastructure: [
    "api_token.manage_own",
    "backup.create",
    "backup.delete",
    "backup.manage_policy",
    "backup.read",
    "backup.restore",
    "certificate.read",
    "certificate.renew",
    "certificate.upload",
    "deployment.cancel",
    "deployment.read",
    "domain.create",
    "domain.delete",
    "domain.read",
    "environment.read",
    "firewall.read",
    "firewall.update",
    "grant.break_glass",
    "grant.read",
    "host.create",
    "host.delete",
    "host.manage_stack",
    "host.manage_updates",
    "host.read",
    "host.read_metrics",
    "host.update",
    "host.upgrade_agent",
    "member.read",
    "member.revoke_sessions",
    "organization.read",
    "project.read",
    "release.read",
    "role.read",
    "scheduled_job.read",
    "scheduled_job.read_output",
    "secret.read_history",
    "secret.read_name",
    "site.manage_resource_limits",
    "site.manage_runtime",
    "site.read",
    "site.read_logs",
    "site.read_metrics",
    "site.restart",
    "ssh_authority.read",
    "ssh_authority.rotate",
    "ssh_grant.create",
    "ssh_grant.read",
    "ssh_grant.revoke",
    "ssh_key.manage_own",
    "ssh_key.read_any",
    "ssh_key.revoke_any",
    "team.read",
    "terminal.open",
  ],
  release_manager: [
    "api_token.manage_own",
    "backup.create",
    "backup.read",
    "certificate.read",
    "deployment.cancel",
    "deployment.create_nonproduction",
    "deployment.create_production",
    "deployment.read",
    "deployment.read_logs",
    "deployment.rollback_nonproduction",
    "deployment.rollback_production",
    "domain.read",
    "environment.read",
    "grant.break_glass",
    "host.read",
    "host.read_metrics",
    "member.read",
    "organization.read",
    "project.read",
    "release.delete",
    "release.read",
    "scheduled_job.read",
    "scheduled_job.read_output",
    "scheduled_job.run_now",
    "secret.read_history",
    "secret.read_name",
    "site.read",
    "site.read_logs",
    "site.read_metrics",
    "site.restart",
    "ssh_key.manage_own",
    "team.read",
  ],
  developer: [
    "api_token.manage_own",
    "certificate.read",
    "deployment.cancel",
    "deployment.create_nonproduction",
    "deployment.read",
    "deployment.read_logs",
    "deployment.rollback_nonproduction",
    "domain.read",
    "environment.read",
    "grant.break_glass",
    "member.read",
    "organization.read",
    "project.read",
    "release.read",
    "scheduled_job.read",
    "scheduled_job.read_output",
    "secret.read_history",
    "secret.read_name",
    "site.read",
    "site.read_logs",
    "site.read_metrics",
    "ssh_key.manage_own",
    "team.read",
  ],
  viewer: [
    "certificate.read",
    "deployment.read",
    "domain.read",
    "environment.read",
    "member.read",
    "organization.read",
    "project.read",
    "release.read",
    "scheduled_job.read",
    "site.read",
    "site.read_metrics",
    "team.read",
  ],
  billing: [
    "billing.read",
    "billing.update",
  ],
};

/** What moved, in both directions. */
function privilegeDelta(
  pinned: readonly string[],
  current: readonly string[],
): { readonly gained: readonly string[]; readonly lost: readonly string[] } {
  const pinnedSet = new Set(pinned);
  const currentSet = new Set(current);
  return {
    gained: current.filter((action) => !pinnedSet.has(action)),
    lost: pinned.filter((action) => !currentSet.has(action)),
  };
}

/**
 * The failure message. It prints the permissions that moved and what each one
 * lets its holder do, because "this role gained four actions" is not reviewable
 * and "this role gained the ability to reveal a secret's value in plaintext" is.
 */
function describeDelta(key: DefaultRoleKey, gained: readonly string[], lost: readonly string[]): string {
  const describe = (mark: string) => (action: string) =>
    `  ${mark} ${action}\n      ${isAction(action) ? ACTION_CATALOGUE[action].description : "not an action the catalogue declares"}`;

  return [
    `${DEFAULT_ROLES[key].name} no longer matches its pinned permission set.`,
    ...(gained.length > 0 ? ["", `GAINED — ${String(gained.length)}:`, ...gained.map(describe("+"))] : []),
    ...(lost.length > 0 ? ["", `LOST — ${String(lost.length)}:`, ...lost.map(describe("-"))] : []),
    "",
    `Pinned ${String(ROLE_SNAPSHOT[key].length)} actions, found ${String(DEFAULT_ROLES[key].actions.length)}.`,
    "If the change is intended, update ROLE_SNAPSHOT in this file in the same commit as",
    "src/authz/roles.ts, so the review sees the privilege delta and not a resorted list.",
  ].join("\n");
}

test("the snapshot names only actions the catalogue declares", () => {
  // A typo in the snapshot would otherwise be reported below as a role losing a
  // permission, which sends the reviewer to the wrong file.
  for (const key of DEFAULT_ROLE_KEYS) {
    for (const action of ROLE_SNAPSHOT[key]) {
      assert.ok(isAction(action), `the snapshot for ${key} names ${action}, which is not an action`);
    }
    assert.equal(
      new Set(ROLE_SNAPSHOT[key]).size,
      ROLE_SNAPSHOT[key].length,
      `the snapshot for ${key} lists an action twice`,
    );
    assert.deepEqual(
      [...ROLE_SNAPSHOT[key]],
      [...ROLE_SNAPSHOT[key]].sort(),
      `the snapshot for ${key} is not sorted, so its diffs will be noise`,
    );
  }
});

for (const key of DEFAULT_ROLE_KEYS) {
  test(`${DEFAULT_ROLES[key].name}'s effective permissions match the pinned set`, () => {
    const current = [...DEFAULT_ROLES[key].actions].sort();
    const { gained, lost } = privilegeDelta(ROLE_SNAPSHOT[key], current);

    if (gained.length > 0 || lost.length > 0) {
      assert.fail(describeDelta(key, gained, lost));
    }

    // Structural check as well as the set comparison above: catches a
    // duplicate, which a set difference cannot see. `no role lists the same
    // action twice` names the offending action; this only proves the snapshot
    // is not quietly hiding one.
    assert.deepEqual(
      current,
      [...ROLE_SNAPSHOT[key]],
      `${DEFAULT_ROLES[key].name} has the right permissions but not the right list — most likely one is listed twice`,
    );
  });
}
