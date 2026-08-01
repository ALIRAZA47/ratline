/**
 * Default roles — the permission map (RL-M1-009, completed by RL-M1-010).
 *
 * A role is a named composition of raw actions from `catalogue.ts`. A *grant*
 * assigns a role at a scope; that is RL-M1-011. Nothing here decides anything —
 * `can()` (RL-M1-012) reads this.
 *
 * ## Only Owner exists yet, on purpose
 *
 * The other six default roles — Admin, Infrastructure, Release Manager,
 * Developer, Viewer and Billing — are **RL-M1-010**, deliberately not started
 * here. Owner is present because "Owner has everything" is definitional in
 * brief §6.3 rather than a design choice, and because acceptance 4 of this task
 * needs a permission map to check the catalogue against.
 *
 * RL-M1-010 adds them by adding a key to `DEFAULT_ROLE_KEYS` and an entry to
 * `DEFAULT_ROLES`; nothing here needs reshaping. Two things are worth carrying
 * forward when it does:
 *
 *   - The brief's role intents are the specification (§6.3), and two of them
 *     are stated as prohibitions that a snapshot test should pin: Infrastructure
 *     and Release Manager must not hold `secret.read_value`, and Billing must
 *     hold nothing but `billing.*`.
 *   - `terminal.open` is off by default for every role except Infrastructure
 *     (§6.4), so it is not simply "whatever Admin has minus deletion".
 *
 * ## Why Owner's actions are written out rather than derived
 *
 * `actions: ALL_ACTIONS` would be shorter, correct today, and would quietly
 * destroy acceptance 4. If any role holds every action by construction, then
 * "every action is mapped to at least one role" is true of any catalogue,
 * including one with an action nobody thought about — and the test that is
 * supposed to fail can never fail.
 *
 * So the list is written out. The duplication is the mechanism: the catalogue
 * and this list are two independent statements that a test requires to agree,
 * and adding an action to one without the other is exactly the mistake brief
 * §6.3 asks to be caught. It also forces the question the check exists to
 * provoke — "who should hold this?" — at the moment the action is invented,
 * rather than at the moment someone is unexpectedly denied.
 */

import type { Action } from "./catalogue.ts";

/**
 * The default roles Ratline ships with, in descending order of privilege.
 *
 * RL-M1-010 extends this to the seven in brief §6.3. Custom roles are stored
 * per organization and composed from the same raw actions (RL-M5-002); they are
 * not listed here because they are data, not defaults.
 */
export const DEFAULT_ROLE_KEYS = ["owner"] as const;

export type DefaultRoleKey = (typeof DEFAULT_ROLE_KEYS)[number];

export type RoleDefinition = {
  readonly key: DefaultRoleKey;

  /** Shown in the interface. Title case, matching brief §6.3 exactly. */
  readonly name: string;

  /** The role's intent, in the operator's words. Rendered in the role editor. */
  readonly description: string;

  /**
   * Every action this role permits, written out. Never a wildcard — see the
   * note at the top of this file.
   */
  readonly actions: readonly Action[];

  /**
   * Whether the system refuses to remove the last holder of this role.
   *
   * Brief §6.3, Owner: "At least one must always exist; the system prevents
   * removing the last." Enforced when grants exist (RL-M1-011); declared here
   * because it is a property of the role, not of the enforcement.
   */
  readonly lastHolderProtected: boolean;
};

/**
 * Owner holds every action in the catalogue, including the two the brief
 * reserves to it alone: `organization.delete` and
 * `organization.transfer_ownership`.
 *
 * Grouped in catalogue order so the two files diff against each other.
 */
const OWNER_ACTIONS: readonly Action[] = [
  // organization
  "organization.read",
  "organization.update",
  "organization.delete",
  "organization.transfer_ownership",
  "organization.manage_sso",
  "organization.manage_security_policy",

  // team
  "team.read",
  "team.create",
  "team.update",
  "team.delete",
  "team.manage_members",

  // member
  "member.read",
  "member.invite",
  "member.remove",

  // role
  "role.read",
  "role.create",
  "role.update",
  "role.delete",

  // grant
  "grant.read",
  "grant.create",
  "grant.revoke",
  "grant.break_glass",

  // service identity
  "service_identity.read",
  "service_identity.create",
  "service_identity.delete",

  // API token
  "api_token.manage_own",
  "api_token.read_any",
  "api_token.revoke_any",

  // project
  "project.read",
  "project.create",
  "project.update",
  "project.delete",

  // environment
  "environment.read",
  "environment.create",
  "environment.update",
  "environment.delete",

  // site
  "site.read",
  "site.create",
  "site.update",
  "site.delete",
  "site.restart",
  "site.build_command.write",
  "site.run_command",
  "site.read_logs",
  "site.read_metrics",
  "site.manage_runtime",
  "site.manage_resource_limits",
  "site.manage_deploy_triggers",

  // release
  "release.read",
  "release.delete",

  // deployment
  "deployment.read",
  "deployment.read_logs",
  "deployment.create_nonproduction",
  "deployment.create_production",
  "deployment.rollback_nonproduction",
  "deployment.rollback_production",
  "deployment.cancel",

  // secret
  "secret.read_name",
  "secret.read_value",
  "secret.create",
  "secret.update",
  "secret.delete",
  "secret.read_history",

  // domain
  "domain.read",
  "domain.create",
  "domain.delete",

  // certificate
  "certificate.read",
  "certificate.upload",
  "certificate.renew",

  // scheduled job
  "scheduled_job.read",
  "scheduled_job.create",
  "scheduled_job.update",
  "scheduled_job.delete",
  "scheduled_job.run_now",
  "scheduled_job.read_output",

  // host
  "host.read",
  "host.create",
  "host.update",
  "host.delete",
  "host.read_metrics",
  "host.manage_stack",
  "host.manage_updates",
  "host.upgrade_agent",

  // firewall
  "firewall.read",
  "firewall.update",

  // backup
  "backup.read",
  "backup.create",
  "backup.restore",
  "backup.delete",
  "backup.manage_policy",

  // web terminal
  "terminal.open",
  "terminal.read_recording",

  // SSH access
  "ssh_grant.read",
  "ssh_grant.create",
  "ssh_grant.revoke",
  "ssh_key.manage_own",
  "ssh_key.read_any",
  "ssh_key.revoke_any",
  "ssh_authority.read",
  "ssh_authority.rotate",

  // audit log
  "audit_log.read",

  // billing
  "billing.read",
  "billing.update",
];

export const DEFAULT_ROLES: Readonly<Record<DefaultRoleKey, RoleDefinition>> = {
  owner: {
    key: "owner",
    name: "Owner",
    description:
      "Everything, including deleting the organization and transferring ownership. At least one Owner always exists.",
    actions: OWNER_ACTIONS,
    lastHolderProtected: true,
  },
};

/** The default roles as a list, in the order of `DEFAULT_ROLE_KEYS`. */
export const ALL_DEFAULT_ROLES: readonly RoleDefinition[] = DEFAULT_ROLE_KEYS.map(
  (key) => DEFAULT_ROLES[key],
);
