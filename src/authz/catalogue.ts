/**
 * The permission catalogue — the single source of actions (RL-M1-009).
 *
 * Brief §6.3: "Deny by default. An unmapped action is a denial. Adding a new
 * action without adding it to the permission map fails a test."
 *
 * Every authorization question in Ratline is "may this actor take this action
 * on this resource", and every action there is appears exactly once in this
 * file. That has three consequences worth stating plainly:
 *
 *   1. **The catalogue is closed.** `Action` is a union of literal names, not
 *      `string`. An action that is not declared here cannot be named in a call
 *      to `can()` without a deliberate cast, and `isAction()` rejects it at the
 *      runtime boundary where names arrive as data — a request body, a stored
 *      custom role, an API token's scope list. Deny-by-default is therefore a
 *      property of the type, not a rule people are asked to remember.
 *
 *   2. **An action is the raw capability, not the assignment.** Per the
 *      glossary, the assignment of a role at a scope is a *grant*; the raw
 *      capability a role composes is a *permission*, which is what one entry
 *      here is. `Action` names it because that is the word `can()` uses.
 *
 *   3. **Splitting an action is a security decision, not a taxonomy exercise.**
 *      Where the brief requires two things to be separately grantable, they are
 *      separate entries here and nowhere else does the difference need
 *      enforcing. The splits the brief names explicitly:
 *
 *        - `secret.read_name` / `secret.read_value` (§6.3, ADR 0006)
 *        - production / non-production deployment and rollback (§6.3)
 *        - `terminal.open`, off by default for every role but Infrastructure
 *          (§6.4, ADR 0008)
 *        - `site.build_command.write`, separate from deploying (ADR 0005)
 *        - `site.run_command`, the one-off command runner (§6.5)
 *
 * This module holds data and two derivations of it. The decision function lives
 * in `can()` (RL-M1-012); roles that compose these actions live in `roles.ts`
 * (RL-M1-010). Nothing here knows about actors, grants or the database.
 */

/**
 * The levels of the hierarchy a permission can be granted at, ordered widest
 * first: Organization → Team → Project → Environment → Resource (brief §6.3).
 *
 * The order is load-bearing. Permissions inherit downward, so a grant at one
 * level conveys the action at every level after it in this list.
 */
export const SCOPE_LEVELS = [
  "organization",
  "team",
  "project",
  "environment",
  "resource",
] as const;

export type ScopeLevel = (typeof SCOPE_LEVELS)[number];

/**
 * The kinds of thing an action operates on. Each corresponds to a node in the
 * hierarchy or to a resource hanging off one (brief §6.3), and each has at
 * least one action — a resource type with none would be a resource nobody can
 * ever touch, which the completeness test rejects.
 */
export const RESOURCE_TYPES = [
  "organization",
  "team",
  "member",
  "role",
  "grant",
  "service_identity",
  "api_token",
  "project",
  "environment",
  "site",
  "release",
  "deployment",
  "secret",
  "domain",
  "certificate",
  "scheduled_job",
  "host",
  "firewall",
  "backup",
  "terminal",
  "ssh_grant",
  "ssh_key",
  "ssh_authority",
  "audit_log",
  "billing",
] as const;

export type ResourceType = (typeof RESOURCE_TYPES)[number];

export type ActionDefinition = {
  /** What the action operates on. Always the first segment of the action name. */
  readonly resource: ResourceType;

  /**
   * The narrowest level at which this action is meaningfully granted.
   *
   * Because permissions inherit downward, a grant at this level or at any level
   * above it conveys the action; a grant below it cannot, because there is no
   * narrower node for the action to attach to. Declaring the narrowest level is
   * what makes the difference visible: `organization.delete` is organization-only,
   * so no project-scoped grant can ever convey it, while `site.read` reaches all
   * the way down to a single site.
   *
   * Creating something is declared at the scope of the container it is created
   * into — `site.create` is environment-scoped because a site does not exist
   * yet to scope it to.
   */
  readonly scope: ScopeLevel;

  /**
   * One sentence, operator-facing, active voice. The role editor (RL-M5-004)
   * renders these beside each toggle and the audit log uses them to describe a
   * decision, so they are product copy: they say what the holder can do, not
   * what the code does.
   */
  readonly description: string;
};

/**
 * Every action in Ratline.
 *
 * Adding an entry here is the *only* way to create an action, and it is not
 * finished until at least one role in `roles.ts` carries it —
 * `test/authz/catalogue_completeness.test.ts` fails otherwise.
 */
const ACTIONS = {
  // --- organization -------------------------------------------------------
  // The root of the hierarchy. Deletion and ownership transfer are the two
  // powers the brief reserves to Owner alone (§6.3).
  "organization.read": {
    resource: "organization",
    scope: "organization",
    description: "View the organization's name, settings and policies.",
  },
  "organization.update": {
    resource: "organization",
    scope: "organization",
    description: "Change the organization's name and settings.",
  },
  "organization.delete": {
    resource: "organization",
    scope: "organization",
    description: "Permanently delete the organization and everything in it.",
  },
  "organization.transfer_ownership": {
    resource: "organization",
    scope: "organization",
    description: "Transfer ownership of the organization to another member.",
  },
  "organization.manage_sso": {
    resource: "organization",
    scope: "organization",
    description: "Configure OIDC or SAML single sign-on for the organization.",
  },
  "organization.manage_security_policy": {
    resource: "organization",
    scope: "organization",
    description:
      "Set organization-wide policy: enforced two-factor authentication, session lifetime and minimum SSH key strength.",
  },

  // --- team ---------------------------------------------------------------
  "team.read": {
    resource: "team",
    scope: "team",
    description: "View a team and who belongs to it.",
  },
  "team.create": {
    resource: "team",
    scope: "organization",
    description: "Create a team in the organization.",
  },
  "team.update": {
    resource: "team",
    scope: "team",
    description: "Rename a team or change its settings.",
  },
  "team.delete": {
    resource: "team",
    scope: "team",
    description: "Delete a team, along with every grant scoped to it.",
  },
  "team.manage_members": {
    resource: "team",
    scope: "team",
    description: "Add people to a team and remove them from it.",
  },

  // --- member -------------------------------------------------------------
  // People in the organization. Assigning them a role is a grant, below.
  "member.read": {
    resource: "member",
    scope: "organization",
    description: "View the people in the organization and their status.",
  },
  "member.invite": {
    resource: "member",
    scope: "organization",
    description: "Invite a person to join the organization.",
  },
  "member.remove": {
    resource: "member",
    scope: "organization",
    description: "Remove a person from the organization, ending their access immediately.",
  },
  // Separate from member.remove because the two answer different needs. Ending
  // a compromised person's sessions must not require removing them from the
  // organization — that is a destructive answer to a containment question, and
  // during an incident the destructive answer is the one people avoid taking.
  "member.revoke_sessions": {
    resource: "member",
    scope: "organization",
    description: "Sign another member out everywhere, immediately, without removing them.",
  },
  // Separate again, and the most dangerous of the four. Revoking sessions ends
  // someone's access; resetting their password TAKES THEIR ACCOUNT — for the
  // window between the reset and their next sign-in, the resetting operator
  // holds a working credential for another person, and anything done with it is
  // attributed to them. That is a C6 problem the action cannot fix, only bound:
  // hold it narrowly, audit it loudly, and end the sessions so the owner of the
  // account notices. Threat model R-17.
  "member.reset_password": {
    resource: "member",
    scope: "organization",
    description: "Set another member's password when they have lost access to their account.",
  },

  // --- role ---------------------------------------------------------------
  // Roles are editable and custom roles compose the raw permission set (§6.3),
  // so editing a role is editing the permission model itself.
  "role.read": {
    resource: "role",
    scope: "organization",
    description: "View roles and the permissions each one carries.",
  },
  "role.create": {
    resource: "role",
    scope: "organization",
    description: "Create a custom role from the raw permission set.",
  },
  "role.update": {
    resource: "role",
    scope: "organization",
    description: "Change which permissions a role carries.",
  },
  "role.delete": {
    resource: "role",
    scope: "organization",
    description: "Delete a custom role.",
  },

  // --- grant --------------------------------------------------------------
  // A grant attaches a role to any node in the hierarchy, so these are declared
  // at resource scope: holding `grant.create` on a project delegates
  // administration of that project without conveying it anywhere else.
  "grant.read": {
    resource: "grant",
    scope: "resource",
    description: "See who has access to what, and when that access expires.",
  },
  "grant.create": {
    resource: "grant",
    scope: "resource",
    description: "Assign a role at a scope, or record a deny, optionally with an expiry.",
  },
  "grant.revoke": {
    resource: "grant",
    scope: "resource",
    description: "Revoke a role assignment, or remove a deny.",
  },
  "grant.break_glass": {
    resource: "grant",
    scope: "organization",
    description:
      "Take temporary Admin access with a written reason. Every Owner is notified and it expires on its own.",
  },

  // --- service identity ---------------------------------------------------
  // C6: automation acts as a named identity with its own permissions, never
  // anonymously and never as "the system".
  "service_identity.read": {
    resource: "service_identity",
    scope: "organization",
    description: "View the identities automation acts as, and what each one may do.",
  },
  "service_identity.create": {
    resource: "service_identity",
    scope: "organization",
    description: "Create a named identity for automation to act as.",
  },
  "service_identity.delete": {
    resource: "service_identity",
    scope: "organization",
    description: "Delete a service identity, stopping everything acting as it.",
  },

  // --- API token ----------------------------------------------------------
  // A token never carries more than its issuer holds (§6.3), so managing your
  // own tokens escalates nothing and is separate from reaching anyone else's.
  "api_token.manage_own": {
    resource: "api_token",
    scope: "organization",
    description: "Issue, inspect and revoke your own API tokens.",
  },
  "api_token.read_any": {
    resource: "api_token",
    scope: "organization",
    description: "List every API token in the organization, with its scope and last use.",
  },
  "api_token.revoke_any": {
    resource: "api_token",
    scope: "organization",
    description: "Revoke any API token, including revoking every token at once.",
  },

  // --- project ------------------------------------------------------------
  "project.read": {
    resource: "project",
    scope: "project",
    description: "View a project and the environments in it.",
  },
  "project.create": {
    resource: "project",
    scope: "team",
    description: "Create a project in a team.",
  },
  "project.update": {
    resource: "project",
    scope: "project",
    description: "Rename a project or change its settings.",
  },
  "project.delete": {
    resource: "project",
    scope: "project",
    description: "Delete a project and everything in it.",
  },

  // --- environment --------------------------------------------------------
  "environment.read": {
    resource: "environment",
    scope: "environment",
    description: "View an environment and what runs in it.",
  },
  "environment.create": {
    resource: "environment",
    scope: "project",
    description: "Create an environment in a project.",
  },
  "environment.update": {
    resource: "environment",
    scope: "environment",
    description:
      "Change an environment's settings, including its branch and its staging password protection.",
  },
  "environment.delete": {
    resource: "environment",
    scope: "environment",
    description: "Delete an environment and everything in it.",
  },

  // --- site ---------------------------------------------------------------
  // The central resource. Note that three of these are code execution as the
  // site's Linux user and are deliberately not bundled into `site.update`:
  // `site.build_command.write` (ADR 0005), `site.run_command` (§6.5) and,
  // below, `scheduled_job.create`.
  "site.read": {
    resource: "site",
    scope: "resource",
    description: "View a site's configuration, status and domains.",
  },
  "site.create": {
    resource: "site",
    scope: "environment",
    description: "Create a site in an environment from a Git repository.",
  },
  "site.update": {
    resource: "site",
    scope: "resource",
    description:
      "Change a site's repository, branch, root and output directories, redirects, headers and uptime checks.",
  },
  "site.delete": {
    resource: "site",
    scope: "resource",
    description: "Delete a site, its releases and its configuration on the host.",
  },
  "site.restart": {
    resource: "site",
    scope: "resource",
    description: "Restart the site's service.",
  },
  "site.build_command.write": {
    resource: "site",
    scope: "resource",
    description:
      "Set the build and install commands. They run as the site's Linux user and can run any code, which is why this is separate from deploying.",
  },
  "site.run_command": {
    resource: "site",
    scope: "resource",
    description: "Run a one-off command for the site, as the site's Linux user.",
  },
  "site.read_logs": {
    resource: "site",
    scope: "resource",
    description: "Read the site's application logs, including live tail.",
  },
  "site.read_metrics": {
    resource: "site",
    scope: "resource",
    description: "View the site's CPU, memory and request metrics.",
  },
  "site.manage_runtime": {
    resource: "site",
    scope: "resource",
    description: "Change the Node or Bun version pinned to the site.",
  },
  "site.manage_resource_limits": {
    resource: "site",
    scope: "resource",
    description: "Change the site's sandboxing and its memory, CPU and task limits.",
  },
  "site.manage_deploy_triggers": {
    resource: "site",
    scope: "resource",
    description: "Configure push-to-deploy: which branch deploys, and the webhook that triggers it.",
  },

  // --- release ------------------------------------------------------------
  "release.read": {
    resource: "release",
    scope: "resource",
    description: "View the releases kept on the host for a site.",
  },
  "release.delete": {
    resource: "release",
    scope: "resource",
    description: "Delete a retained release, which removes it as a rollback target.",
  },

  // --- deployment ---------------------------------------------------------
  // Brief §6.3: "'Deploy to staging' and 'deploy to production' are distinct
  // actions, and granting one without the other is the single most common
  // real-world request."
  //
  // The split is by environment *class*, not by the scope the grant attaches
  // to, and that is the whole point. Grants are usually made at project scope,
  // which inherits into every environment underneath — including production. If
  // deploying were one action, a project-scoped Developer would deploy to
  // production by inheritance. Two actions mean the production capability has
  // to be named, whatever the scope of the grant.
  "deployment.read": {
    resource: "deployment",
    scope: "resource",
    description: "View deployment history and the status of a running deployment.",
  },
  "deployment.read_logs": {
    resource: "deployment",
    scope: "resource",
    description: "Read a deployment's build logs, live and archived.",
  },
  "deployment.create_nonproduction": {
    resource: "deployment",
    scope: "environment",
    description: "Deploy to a staging or preview environment.",
  },
  "deployment.create_production": {
    resource: "deployment",
    scope: "environment",
    description: "Deploy to a production environment.",
  },
  "deployment.rollback_nonproduction": {
    resource: "deployment",
    scope: "environment",
    description: "Roll a staging or preview environment back to an earlier release.",
  },
  "deployment.rollback_production": {
    resource: "deployment",
    scope: "environment",
    description: "Roll a production environment back to an earlier release.",
  },
  // Deliberately NOT split by environment class, unlike create and rollback.
  // Cancelling leaves the previous release serving, so it cannot break
  // production — and at 2am you want whoever noticed the bad deploy to be able
  // to stop it, not to go looking for someone with the production grant. The
  // inconsistency with create/rollback is intentional; argue with it here
  // rather than assuming it was an oversight.
  "deployment.cancel": {
    resource: "deployment",
    scope: "environment",
    description: "Cancel a deployment that is still running.",
  },

  // --- secret -------------------------------------------------------------
  // Secrets are held by an environment (PLAN §4), so environment is the
  // narrowest node they attach to.
  //
  // Brief §6.3: "`secret.read_value` is separate from `secret.read_name`. Most
  // roles need the latter and almost none need the former." ADR 0006 keeps the
  // name in plaintext precisely so `secret.read_name` resolves without
  // unwrapping anything.
  "secret.read_name": {
    resource: "secret",
    scope: "environment",
    description: "See that a secret exists and what it is called. Never its value.",
  },
  "secret.read_value": {
    resource: "secret",
    scope: "environment",
    description: "Reveal a secret's value in plaintext.",
  },
  "secret.create": {
    resource: "secret",
    scope: "environment",
    description: "Add a secret to an environment.",
  },
  "secret.update": {
    resource: "secret",
    scope: "environment",
    description: "Replace a secret's value with a new one.",
  },
  "secret.delete": {
    resource: "secret",
    scope: "environment",
    description: "Delete a secret from an environment.",
  },
  "secret.read_history": {
    resource: "secret",
    scope: "environment",
    description: "See who changed a secret and when. The history never holds values.",
  },

  // --- domain -------------------------------------------------------------
  "domain.read": {
    resource: "domain",
    scope: "resource",
    description: "View the domains attached to a site and whether they are verified.",
  },
  "domain.create": {
    resource: "domain",
    scope: "resource",
    description: "Attach a custom domain to a site and verify it through DNS.",
  },
  "domain.delete": {
    resource: "domain",
    scope: "resource",
    description: "Detach a domain from a site.",
  },

  // --- certificate --------------------------------------------------------
  // Uploading is separate from renewing: a custom upload carries a private key,
  // renewal only asks the web server to do what it already does automatically.
  "certificate.read": {
    resource: "certificate",
    scope: "resource",
    description: "View a domain's certificate, its issuer and its expiry.",
  },
  "certificate.upload": {
    resource: "certificate",
    scope: "resource",
    description: "Upload a custom certificate and its private key.",
  },
  "certificate.renew": {
    resource: "certificate",
    scope: "resource",
    description: "Renew a certificate now, rather than waiting for automatic renewal.",
  },

  // --- scheduled job ------------------------------------------------------
  // "Cron" in the operator's world; a scheduled job here, per the glossary.
  // Creating one is code execution on a schedule — same power class as setting
  // a build command, and separated from deploying for the same reason.
  "scheduled_job.read": {
    resource: "scheduled_job",
    scope: "resource",
    description: "View a site's scheduled jobs and when they run.",
  },
  "scheduled_job.create": {
    resource: "scheduled_job",
    scope: "resource",
    description:
      "Create a scheduled job. It runs as the site's Linux user, so this carries the same power as setting a build command.",
  },
  "scheduled_job.update": {
    resource: "scheduled_job",
    scope: "resource",
    description: "Change a scheduled job's schedule or what it runs.",
  },
  "scheduled_job.delete": {
    resource: "scheduled_job",
    scope: "resource",
    description: "Delete a scheduled job.",
  },
  "scheduled_job.run_now": {
    resource: "scheduled_job",
    scope: "resource",
    description: "Run a scheduled job immediately, outside its schedule.",
  },
  "scheduled_job.read_output": {
    resource: "scheduled_job",
    scope: "resource",
    description: "Read the captured output of a scheduled job's runs.",
  },

  // --- host ---------------------------------------------------------------
  // Hosts belong to the organization rather than to a project (PLAN §4), so
  // adding one is organization-scoped and everything else attaches to the host
  // itself. "Host", never "server" — the glossary reserves that word.
  "host.read": {
    resource: "host",
    scope: "resource",
    description: "View a host, its inventory and its health.",
  },
  "host.create": {
    resource: "host",
    scope: "organization",
    description: "Add a host and install the Ratline agent onto it.",
  },
  "host.update": {
    resource: "host",
    scope: "resource",
    description: "Change a host's settings and its alert thresholds.",
  },
  "host.delete": {
    resource: "host",
    scope: "resource",
    description: "Remove a host from Ratline.",
  },
  "host.read_metrics": {
    resource: "host",
    scope: "resource",
    description: "View a host's disk, load and memory metrics.",
  },
  "host.manage_stack": {
    resource: "host",
    scope: "resource",
    description: "Install and configure the host's web server and its available runtimes.",
  },
  "host.manage_updates": {
    resource: "host",
    scope: "resource",
    description: "Toggle unattended security upgrades and apply pending ones.",
  },
  "host.upgrade_agent": {
    resource: "host",
    scope: "resource",
    description: "Update the Ratline agent on a host, with rollback.",
  },

  // --- firewall -----------------------------------------------------------
  "firewall.read": {
    resource: "firewall",
    scope: "resource",
    description: "View a host's firewall rules and its intrusion-blocking policy.",
  },
  "firewall.update": {
    resource: "firewall",
    scope: "resource",
    description: "Change a host's firewall rules and its intrusion-blocking policy.",
  },

  // --- backup -------------------------------------------------------------
  // Restoring overwrites live files, so it is separated from taking a backup;
  // the storage policy is separated again because it names the object storage
  // and the credentials for it.
  "backup.read": {
    resource: "backup",
    scope: "resource",
    description: "View the backups taken of a site's files and configuration.",
  },
  "backup.create": {
    resource: "backup",
    scope: "resource",
    description: "Take a backup of a site now.",
  },
  "backup.restore": {
    resource: "backup",
    scope: "resource",
    description: "Restore a backup over a site's live files.",
  },
  "backup.delete": {
    resource: "backup",
    scope: "resource",
    description: "Delete a backup.",
  },
  "backup.manage_policy": {
    resource: "backup",
    scope: "resource",
    description: "Set the backup schedule and the object storage backups are written to.",
  },

  // --- web terminal -------------------------------------------------------
  // §6.4: "Terminal access is its own permission, off by default for every role
  // except Infrastructure." Reading a recording is gated separately because a
  // recording of an incident contains everything typed and printed in it,
  // including anything pasted (ADR 0008).
  "terminal.open": {
    resource: "terminal",
    scope: "resource",
    description: "Open a web terminal on a host. Off by default for every role except Infrastructure.",
  },
  "terminal.read_recording": {
    resource: "terminal",
    scope: "resource",
    description:
      "Play back a recorded terminal session, including everything typed and printed during it.",
  },

  // --- SSH access ---------------------------------------------------------
  "ssh_grant.read": {
    resource: "ssh_grant",
    scope: "resource",
    description: "See who has SSH access to which sites and hosts, and when it expires.",
  },
  "ssh_grant.create": {
    resource: "ssh_grant",
    scope: "resource",
    description: "Grant SSH access to a site or host, optionally time-bound.",
  },
  "ssh_grant.revoke": {
    resource: "ssh_grant",
    scope: "resource",
    description: "Revoke SSH access and terminate the sessions using it.",
  },
  "ssh_key.manage_own": {
    resource: "ssh_key",
    scope: "organization",
    description: "Upload, rotate and remove your own SSH public keys.",
  },
  "ssh_key.read_any": {
    resource: "ssh_key",
    scope: "organization",
    description: "View every member's SSH keys, with fingerprint, age and last use.",
  },
  "ssh_key.revoke_any": {
    resource: "ssh_key",
    scope: "organization",
    description: "Remove another member's SSH key, or force them to rotate it.",
  },
  "ssh_authority.read": {
    resource: "ssh_authority",
    scope: "organization",
    description: "View the SSH certificate authority's fingerprint and when it was last rotated.",
  },
  "ssh_authority.rotate": {
    resource: "ssh_authority",
    scope: "organization",
    description: "Rotate the SSH certificate authority and redistribute it to every host.",
  },

  // --- audit log ----------------------------------------------------------
  "audit_log.read": {
    resource: "audit_log",
    scope: "organization",
    description: "Read the audit log, including the decisions that were denied.",
  },

  // --- billing ------------------------------------------------------------
  // Billing itself is out of scope for v1 (§5.2), but the Billing role is not
  // (§6.3): "Billing only. No infrastructure visibility whatsoever." The role
  // cannot be expressed, nor proved empty of everything else, without actions
  // to hold — so the actions are declared and the feature is built later.
  "billing.read": {
    resource: "billing",
    scope: "organization",
    description: "View invoices, the current plan and the payment method.",
  },
  "billing.update": {
    resource: "billing",
    scope: "organization",
    description: "Change the plan or the payment method.",
  },
} as const satisfies Record<string, ActionDefinition>;

/**
 * Every action name, as a union of literals.
 *
 * This type is what makes deny-by-default structural: there is no `string` that
 * can be passed to `can()` unchecked, so an action that was never catalogued
 * cannot be allowed by accident — only denied, because nothing maps it.
 */
export type Action = keyof typeof ACTIONS;

/** The catalogue, keyed by action name. */
export const ACTION_CATALOGUE: Readonly<Record<Action, ActionDefinition>> = ACTIONS;

/**
 * Whether a value names a catalogued action.
 *
 * The guard at the boundary. Action names arrive as data from request bodies,
 * stored custom roles and API token scopes; anything this rejects is not an
 * action, and per brief §6.3 an action that is not in the catalogue is a
 * denial rather than an error to be worked around.
 */
/**
 * KNOWN GAPS — features the brief requires that have no action here yet.
 *
 * Recorded rather than guessed at. Deny-by-default plus the completeness test
 * in test/authz/catalogue_completeness.test.ts means adding any of these forces
 * an explicit decision about which roles hold it, which is the point. Listing
 * them here stops a later session assuming the omission was considered and
 * closed.
 *
 *   - Notification destinations — Slack, webhook and email configuration
 *     (brief §6.5). Arrives with RL-M3-025.
 *   - Audit log export, and running chain verification on demand
 *     (brief §6.3). Arrives with RL-M1-015.
 *   - (CLOSED by RL-M1-018: `member.revoke_sessions`.)
 *   - Preview environments, if RL-M3-027 decides they make v1.
 */

export function isAction(value: unknown): value is Action {
  return typeof value === "string" && Object.hasOwn(ACTION_CATALOGUE, value);
}

/** Every catalogued action. Iteration order is declaration order. */
export const ALL_ACTIONS: readonly Action[] = Object.keys(ACTION_CATALOGUE).filter(isAction);
