/**
 * Default roles — the permission map (RL-M1-009, completed by RL-M1-010).
 *
 * A role is a named composition of raw actions from `catalogue.ts`. A *grant*
 * assigns a role at a scope; that is RL-M1-011. Nothing here decides anything —
 * `can()` (RL-M1-012) reads this.
 *
 * All seven roles from brief §6.3 are here. They are the shipped defaults, not
 * a fixed set: §6.3 says "Default roles, editable, with custom roles composable
 * from the raw permission set", so every list below is expressible as toggles in
 * the role editor (RL-M5-004) and nothing here is structurally privileged.
 * Storing an edited or custom role is RL-M5-002; this file is what an
 * organization starts with.
 *
 * ## Why every role's actions are written out rather than derived
 *
 * `actions: ALL_ACTIONS` would be shorter, correct today, and would quietly
 * destroy RL-M1-009's fourth acceptance. If any role holds every action by
 * construction, then "every action is mapped to at least one role" is true of
 * any catalogue, including one with an action nobody thought about — and the
 * test that is supposed to fail can never fail.
 *
 * So the lists are written out, Admin's included, even though Admin is defined
 * as a subtraction. The duplication is the mechanism: the catalogue and these
 * lists are independent statements that a test requires to agree, and adding an
 * action to one without the other is exactly the mistake brief §6.3 asks to be
 * caught. It also forces the question the check exists to provoke — "who should
 * hold this?" — at the moment the action is invented, rather than at the moment
 * someone is unexpectedly denied.
 *
 * `test/authz/default_roles.test.ts` pins every list as a snapshot and asserts
 * the relationships between them (Admin as a set difference from Owner, the
 * exact holders of `secret.read_value`, `terminal.open` and `grant.break_glass`,
 * Billing's emptiness of everything but billing). A change to any list below
 * shows up in review as an explicit privilege delta.
 *
 * ## The rules used to compose these, so a reviewer can argue with the rule
 * ## rather than with ninety individual lines
 *
 *   R1. The brief's intent line is the specification. Where it enumerates
 *       capabilities ("Add/remove servers, manage host stack, firewall, SSH
 *       grants") those are held; where it states a prohibition that prohibition
 *       is absolute.
 *
 *   R2. A role additionally holds the hierarchy reads it needs to navigate to
 *       the things its intent names — `organization.read`, `team.read`,
 *       `project.read`, `environment.read` — because a role that can act on a
 *       site but cannot see the project containing it is unusable, not secure.
 *       Billing is the sole exception, and deliberately: §6.3 gives it "no
 *       infrastructure visibility whatsoever", which is stronger than the
 *       convenience R2 buys.
 *
 *   R3. An action that is *not* split by environment class is treated as
 *       conveying production. Grants are usually made at project scope, which
 *       inherits into every environment underneath, so granting a non-split
 *       action to a non-production role hands over production by inheritance.
 *       This is the catalogue's own argument for splitting deployment, applied
 *       to everything it did not split — and it is why Developer holds neither
 *       `site.restart` nor `scheduled_job.create` despite both being reasonable
 *       things to want in staging. See the KNOWN GAPS note at the foot of this
 *       file.
 *
 *   R4. Withholding an action from a role that already holds a strictly more
 *       powerful one is theatre, and is called out where it happens rather than
 *       left to look like protection. Infrastructure holds `terminal.open`
 *       (§6.4), which is a shell on the host; that is more power than most of
 *       what it is denied.
 *
 * ## Deviations and judgement calls, all of them
 *
 *   D1. **Infrastructure and Release Manager hold no `secret.read_value` at
 *       all.** §6.3 says Infrastructure "cannot read production secret values"
 *       — the narrower wording, which would permit staging values — while
 *       RL-M1-010's acceptance says "provably cannot read secret values", with
 *       no qualifier. The stricter reading is implemented: neither role holds
 *       `secret.read_value` for any environment. The narrower reading is still
 *       reachable without changing this file, because `secret.read_value` is
 *       environment-scoped: an operator who wants "staging values but not
 *       production" grants a custom role at the staging environment. Making
 *       that the deliberate act rather than the default is the safer direction
 *       to be wrong in. Flagged because the two documents genuinely disagree.
 *
 *   D2. **Infrastructure holds `terminal.open` but not
 *       `terminal.read_recording`.** §6.4 names Infrastructure as the one role
 *       terminal access is on for. A recording is a different thing: ADR 0008
 *       gates it separately because it contains everything typed and printed in
 *       *someone else's* session, including anything pasted — which is the most
 *       likely place a role denied `secret.read_value` would encounter one. The
 *       action carries no "own session" qualifier, so holding it means reading
 *       everyone's. Owner and Admin only.
 *
 *   D3. **`grant.break_glass` is held by Infrastructure, Release Manager and
 *       Developer, and by nobody else.** Break-glass grants temporary Admin, so
 *       it defeats every restriction in this file by design — its control is
 *       detection, not prevention (§6.3: written reason, every Owner notified,
 *       auto-expires, loud in the audit log and a UI banner). The question is
 *       therefore only who is trusted to trip the alarm, and the answer is the
 *       roles that get paged: §3.3's "team of eight with a production incident
 *       at 2am". Viewer and Billing cannot self-elevate.
 *
 *   D4. **Viewer holds only actions whose verb begins with `read`.** §6.3 gives
 *       it "read-only on sites, deploy history, metrics. No raw logs, no secret
 *       values". That is implemented literally: no mutation of any kind, not
 *       even `api_token.manage_own`, which every other role holds because the
 *       catalogue notes a token never carries more than its issuer. The cost is
 *       that a Viewer cannot script against the API; the benefit is that
 *       "Viewer changes nothing" is a mechanical property a test can check
 *       rather than a claim about a list. Viewer also gets no host visibility:
 *       "metrics" in the intent line is read as the site metrics it sits beside,
 *       not host metrics, on the grounds that Viewer is the role handed to
 *       someone outside the on-call rotation.
 *
 *   D5. **`audit_log.read`, `role.*` writes, `grant.create`/`revoke`,
 *       `service_identity.*` and `api_token.read_any`/`revoke_any` are Owner and
 *       Admin only.** These read or rewrite the permission model itself, and
 *       none of the five narrower intents in §6.3 mentions administration.
 *       Infrastructure holds `role.read` and `grant.read` as an exception,
 *       because §6.4 derives SSH principals from grants and it cannot issue an
 *       `ssh_grant` sensibly without seeing the grants it must mirror.
 *
 *   D6. **`release.delete` is not Infrastructure's**, though reclaiming disk on
 *       a full host is squarely its problem, because deleting a retained
 *       release removes a rollback target — a release-lifecycle decision. Owner,
 *       Admin and Release Manager hold it.
 *
 *   D7. **Release Manager holds `backup.create` but not `backup.restore`.**
 *       Taking a backup before a production deploy is release work; restoring
 *       one overwrites live files, including data no release produced, and is
 *       not what "roll back" means in §6.3 — `deployment.rollback_production`
 *       is.
 */

import type { Action } from "./catalogue.ts";

/**
 * The default roles Ratline ships with, in descending order of privilege.
 *
 * Custom roles are stored per organization and composed from the same raw
 * actions (RL-M5-002); they are not listed here because they are data, not
 * defaults.
 */
export const DEFAULT_ROLE_KEYS = [
  "owner",
  "admin",
  "infrastructure",
  "release_manager",
  "developer",
  "viewer",
  "billing",
] as const;

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
   * because it is a property of the role, not of the enforcement. Only Owner
   * has it: every other default role can be emptied, edited or deleted.
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
  "member.revoke_sessions",
  "member.reset_password",

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

/**
 * Admin: "Everything except org deletion and ownership transfer" (§6.3).
 *
 * Written out rather than computed from `OWNER_ACTIONS` for the reason at the
 * top of this file — a derived list cannot disagree with its source, and the
 * disagreement is what the tests are for. `test/authz/default_roles.test.ts`
 * asserts the subtraction is exactly those two actions, by set difference, so
 * the arithmetic is checked even though it is not performed here.
 *
 * Admin therefore holds `terminal.open`. §6.4's "off by default for every role
 * except Infrastructure" is about the five narrower roles; Admin is defined by
 * subtraction from Owner and §6.3 subtracts only the two organization powers.
 */
const ADMIN_ACTIONS: readonly Action[] = [
  // organization — everything but `delete` and `transfer_ownership`
  "organization.read",
  "organization.update",
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
  "member.revoke_sessions",
  "member.reset_password",

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

/**
 * Infrastructure: "Add/remove servers, manage host stack, firewall, SSH grants.
 * Cannot read production secret values." (§6.3)
 *
 * The whole host layer, plus the site-level knobs that are host concerns
 * wearing a site's name — the pinned runtime (§6.2 runtimes are installed on the
 * host by `host.manage_stack`, and moving a site onto one is the same job) and
 * the systemd sandboxing and resource limits (§6.2). Plus TLS and DNS, because
 * §6.2 makes certificates a property of the web server this role installs.
 *
 * Not application configuration: no `site.update`, `site.create`,
 * `site.delete`, `site.build_command.write` or `site.run_command`. The last two
 * are code execution as the site's Linux user — and R4 applies, because this
 * role holds `terminal.open` and can reach a shell anyway. Keeping them out is
 * not a containment claim; it is so that the audit log distinguishes a recorded
 * terminal session from a quiet one-off command, and so that a *narrowed* copy
 * of this role (a custom role without terminal access) is meaningfully weaker.
 *
 * Secrets: names and history, never values — see D1.
 */
const INFRASTRUCTURE_ACTIONS: readonly Action[] = [
  // organization — navigation only (R2)
  "organization.read",

  // team
  "team.read",

  // member — SSH grants are made to people; an opaque id is not a person
  "member.read",
  // Containment without escalation. Infrastructure already holds break-glass
  // and terminal.open, so this grants nothing new in reach — it means an
  // incident can be contained without first elevating to Admin, which is less
  // privilege and less audit noise for the commonest emergency action.
  "member.revoke_sessions",

  // role — §6.4 derives SSH principals from roles (D5)
  "role.read",

  // grant — the access picture an `ssh_grant` has to mirror (D5)
  "grant.read",
  "grant.break_glass",

  // API token
  "api_token.manage_own",

  // project
  "project.read",

  // environment
  "environment.read",

  // site — operate it, do not configure it
  "site.read",
  "site.restart",
  "site.read_logs",
  "site.read_metrics",
  "site.manage_runtime",
  "site.manage_resource_limits",

  // release — what is on the disk this role is responsible for. Not `delete`; D6.
  "release.read",

  // deployment — correlate a host incident with a deploy, and stop a bad one.
  // The catalogue's own note on `cancel`: at 2am you want whoever noticed to be
  // able to stop it. Cancelling leaves the previous release serving.
  "deployment.read",
  "deployment.cancel",

  // secret — names and history, never values (D1)
  "secret.read_name",
  "secret.read_history",

  // domain — DNS verification lands on the web server this role installs
  "domain.read",
  "domain.create",
  "domain.delete",

  // certificate — §6.2 TLS, including a custom upload carrying a private key
  "certificate.read",
  "certificate.upload",
  "certificate.renew",

  // scheduled job — see them and their output; defining one is code execution
  "scheduled_job.read",
  "scheduled_job.read_output",

  // host — the intent line, entire
  "host.read",
  "host.create",
  "host.update",
  "host.delete",
  "host.read_metrics",
  "host.manage_stack",
  "host.manage_updates",
  "host.upgrade_agent",

  // firewall — the intent line
  "firewall.read",
  "firewall.update",

  // backup — §6.5 groups backups with firewall and unattended upgrades under
  // Operations, which is this role
  "backup.read",
  "backup.create",
  "backup.restore",
  "backup.delete",
  "backup.manage_policy",

  // web terminal — §6.4 names this role explicitly. Not the recordings; D2.
  "terminal.open",

  // SSH access — the intent line, plus key hygiene and the certificate
  // authority, because §6.4 makes both this role's job
  "ssh_grant.read",
  "ssh_grant.create",
  "ssh_grant.revoke",
  "ssh_key.manage_own",
  "ssh_key.read_any",
  "ssh_key.revoke_any",
  "ssh_authority.read",
  "ssh_authority.rotate",
];

/**
 * Release Manager: "Deploy and roll back in production. Cannot change server
 * config or read secret values." (§6.3)
 *
 * Every deployment action, both environment classes — production is the harder
 * grant and holding it without staging would be perverse — plus the release
 * lifecycle, the logs needed to tell whether a deploy worked, and enough host
 * visibility to tell "the deploy is bad" from "the host is unwell".
 *
 * "Cannot change server config" is read at its widest: nothing under `host.*`
 * or `firewall.*` beyond reading, and none of the site-level configuration
 * either. In particular not `site.build_command.write` — ADR 0005 names this
 * exact case: "Most roles that can deploy must not be able to change what
 * deploying runs." Not `site.manage_deploy_triggers` for the same reason one
 * step removed: changing which branch deploys changes what deploying runs.
 *
 * "Cannot read secret values" is absolute — see D1.
 */
const RELEASE_MANAGER_ACTIONS: readonly Action[] = [
  // organization — navigation only (R2)
  "organization.read",

  // team
  "team.read",

  // member — deployment history names people
  "member.read",

  // grant
  "grant.break_glass",

  // API token
  "api_token.manage_own",

  // project
  "project.read",

  // environment
  "environment.read",

  // site — read it and restart it; configuring it is server config
  "site.read",
  "site.restart",
  "site.read_logs",
  "site.read_metrics",

  // release — the lifecycle, including retiring a rollback target (D6)
  "release.read",
  "release.delete",

  // deployment — the intent line, entire
  "deployment.read",
  "deployment.read_logs",
  "deployment.create_nonproduction",
  "deployment.create_production",
  "deployment.rollback_nonproduction",
  "deployment.rollback_production",
  "deployment.cancel",

  // secret — names and history, never values (D1)
  "secret.read_name",
  "secret.read_history",

  // domain
  "domain.read",

  // certificate
  "certificate.read",

  // scheduled job — run an existing job as part of a release; not define one
  "scheduled_job.read",
  "scheduled_job.run_now",
  "scheduled_job.read_output",

  // host — read-only. Enough to tell a bad deploy from a sick host.
  "host.read",
  "host.read_metrics",

  // backup — take one before a production deploy; restoring is not rollback (D7)
  "backup.read",
  "backup.create",

  // SSH access
  "ssh_key.manage_own",
];

/**
 * Developer: "Deploy to non-production, read logs, manage own SSH keys, read
 * secret *names* but not values." (§6.3)
 *
 * The intent line almost is the list. What it does not say, and what R3 decides:
 * no `site.restart`, no `scheduled_job.create`, no `secret.create`. All three
 * are reasonable things to want in staging and all three are catalogued without
 * an environment-class split, so granting one to a project-scoped Developer
 * would convey it into production by inheritance — the exact escalation the
 * catalogue splits deployment to prevent. See the KNOWN GAPS note below; the
 * fix is in the catalogue, not here.
 *
 * `deployment.cancel` is held despite not being split, because the catalogue
 * argues the case for it directly: cancelling leaves the previous release
 * serving, so it cannot break production.
 */
const DEVELOPER_ACTIONS: readonly Action[] = [
  // organization — navigation only (R2)
  "organization.read",

  // team
  "team.read",

  // member — deployment history names people
  "member.read",

  // grant
  "grant.break_glass",

  // API token
  "api_token.manage_own",

  // project
  "project.read",

  // environment
  "environment.read",

  // site — "read logs"
  "site.read",
  "site.read_logs",
  "site.read_metrics",

  // release
  "release.read",

  // deployment — "deploy to non-production", and nothing named production
  "deployment.read",
  "deployment.read_logs",
  "deployment.create_nonproduction",
  "deployment.rollback_nonproduction",
  "deployment.cancel",

  // secret — "read secret *names* but not values". History never holds a value.
  "secret.read_name",
  "secret.read_history",

  // domain
  "domain.read",

  // certificate
  "certificate.read",

  // scheduled job — read the app's own jobs and their output
  "scheduled_job.read",
  "scheduled_job.read_output",

  // SSH access — "manage own SSH keys"
  "ssh_key.manage_own",
];

/**
 * Viewer: "Read-only on sites, deploy history, metrics. No raw logs, no secret
 * values." (§6.3)
 *
 * Every action here is a `read`, and that is a property the tests check by name
 * rather than by list — see D4. No logs of any kind: not `site.read_logs`, not
 * `deployment.read_logs`, not `scheduled_job.read_output`, not
 * `terminal.read_recording`. Build logs and job output are raw logs wearing
 * different names, and §6.5's automatic redaction is a mitigation, not a
 * guarantee.
 *
 * No secret actions at all, including names: §6.3 enumerates what Viewer reads
 * and secrets are not in it.
 */
const VIEWER_ACTIONS: readonly Action[] = [
  // organization — navigation only (R2)
  "organization.read",

  // team
  "team.read",

  // member — deployment history names people
  "member.read",

  // project
  "project.read",

  // environment
  "environment.read",

  // site — "read-only on sites", and the metrics beside them
  "site.read",
  "site.read_metrics",

  // release
  "release.read",

  // deployment — "deploy history". Not the build logs; those are raw logs.
  "deployment.read",

  // domain
  "domain.read",

  // certificate
  "certificate.read",

  // scheduled job — that they exist and when they run. Not their output.
  "scheduled_job.read",
];

/**
 * Billing: "Billing only. No infrastructure visibility whatsoever." (§6.3)
 *
 * The only role R2 does not apply to. It holds no `organization.read`, no
 * `team.read`, no navigation of any kind — "whatsoever" is taken at its word,
 * and the interface for this role is the billing screen and nothing else.
 *
 * `test/authz/default_roles.test.ts` asserts this as a property — every action
 * this role holds has `resource === "billing"` — rather than by comparing to a
 * copy of the list below, so an action added here later cannot pass review by
 * also being added to the expectation.
 */
const BILLING_ACTIONS: readonly Action[] = ["billing.read", "billing.update"];

export const DEFAULT_ROLES: Readonly<Record<DefaultRoleKey, RoleDefinition>> = {
  owner: {
    key: "owner",
    name: "Owner",
    description:
      "Everything, including deleting the organization and transferring ownership. At least one Owner always exists.",
    actions: OWNER_ACTIONS,
    lastHolderProtected: true,
  },
  admin: {
    key: "admin",
    name: "Admin",
    description: "Everything except deleting the organization and transferring ownership.",
    actions: ADMIN_ACTIONS,
    lastHolderProtected: false,
  },
  infrastructure: {
    key: "infrastructure",
    name: "Infrastructure",
    description:
      "Add and remove hosts, manage the host stack, firewall and SSH access. Cannot read secret values.",
    actions: INFRASTRUCTURE_ACTIONS,
    lastHolderProtected: false,
  },
  release_manager: {
    key: "release_manager",
    name: "Release Manager",
    description:
      "Deploy and roll back in production. Cannot change host or site configuration, and cannot read secret values.",
    actions: RELEASE_MANAGER_ACTIONS,
    lastHolderProtected: false,
  },
  developer: {
    key: "developer",
    name: "Developer",
    description:
      "Deploy to staging and preview environments, read logs, manage their own SSH keys, and see secret names but never values.",
    actions: DEVELOPER_ACTIONS,
    lastHolderProtected: false,
  },
  viewer: {
    key: "viewer",
    name: "Viewer",
    description:
      "Read-only on sites, deployment history and metrics. No raw logs, no secret values, and no changes of any kind.",
    actions: VIEWER_ACTIONS,
    lastHolderProtected: false,
  },
  billing: {
    key: "billing",
    name: "Billing",
    description: "Invoices, plan and payment method. Nothing else, and no view of the infrastructure.",
    actions: BILLING_ACTIONS,
    lastHolderProtected: false,
  },
};

/** The default roles as a list, in the order of `DEFAULT_ROLE_KEYS`. */
export const ALL_DEFAULT_ROLES: readonly RoleDefinition[] = DEFAULT_ROLE_KEYS.map(
  (key) => DEFAULT_ROLES[key],
);

/**
 * KNOWN GAPS — where composing these roles ran out of catalogue.
 *
 * Recorded rather than worked around. None of these is fixable in this file:
 * each needs an action split in `catalogue.ts`, which is RL-M1-009's deliverable
 * and has its own completeness test to satisfy. Listing them stops a later
 * session assuming the resulting role was the considered answer.
 *
 *   - **Nothing but deployment is split by environment class.** The catalogue
 *     splits `deployment.create` and `deployment.rollback` into production and
 *     non-production, and argues for it precisely: a project-scoped grant
 *     inherits into every environment underneath, so an unqualified action
 *     conveys production. That argument applies unchanged to `site.restart`,
 *     `site.run_command`, `secret.create` / `update` / `delete`,
 *     `scheduled_job.create` / `update` / `delete` / `run_now` and
 *     `backup.restore`, none of which are split. The visible cost is Developer:
 *     it cannot restart its own staging app, manage staging secrets or own a
 *     staging cron job, because every one of those would come with the
 *     production equivalent attached. The workaround an operator has today is
 *     an environment-scoped grant of a custom role, which works but is not what
 *     "Developer" should have to mean.
 *
 *   - **`secret.read_value` is not split by environment class either**, which
 *     is the sharpest instance of the above: §6.3's own wording for
 *     Infrastructure is "cannot read *production* secret values", a sentence
 *     that cannot be expressed as a role at all. It can only be expressed as a
 *     grant scoped to a non-production environment. D1 resolves this by
 *     withholding the action entirely; a
 *     `secret.read_value_nonproduction` / `secret.read_value_production` split
 *     would let the role say what the brief says.
 *
 *   - **`terminal.open` is not scoped to a site.** §6.4 requires that "a
 *     developer with access to one site provably cannot reach another" and that
 *     shell access lands the user as that site's Linux user, but the action is
 *     declared at resource scope on a *host*. Whether the resource in question
 *     is the host or the site decides whether a terminal grant on one site
 *     leaks the whole box. M6 has to answer this; noted here because
 *     Infrastructure holds the action.
 *
 *   - **There is no "read own audit trail"**, so every role below Admin is
 *     opaque to itself: a Developer cannot see why they were denied. §6.3 wants
 *     denials recorded and visible; an action scoped to the actor's own
 *     decisions would let that reach the person it concerns.
 *
 *   - **There is no action for revoking a member's active sessions**, already
 *     recorded as a gap in `catalogue.ts`. It matters here because
 *     Infrastructure and Release Manager can both be handed the SSH and deploy
 *     powers to respond to a compromised account without being able to end that
 *     account's session.
 */
