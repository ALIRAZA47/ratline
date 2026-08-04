/**
 * The operation catalogue (RL-M2-002) — the only things an agent can ever be
 * asked to do.
 *
 * ADR 0002: "it looks the operation up in the catalogue and type-checks the
 * arguments. An operation not in the catalogue is refused — there is no default
 * branch, and no operation accepts a free-form command."
 *
 * ## Why this file is the source and Go is generated from it
 *
 * Two implementations of one contract drift. The question is only which
 * direction, and the answer here is TypeScript, for a reason that is not
 * preference: the control plane needs the catalogue's shape available to the type
 * checker at every call site that builds an instruction, and TypeScript can
 * derive that from `as const` data with no generation step at all. Going the other
 * way would mean generating TypeScript types from Go and losing the literal-union
 * narrowing that makes an unknown operation name a compile error rather than a
 * runtime one.
 *
 * `scripts/gen-agent-protocol` writes `agent/internal/protocol/catalogue_gen.go`
 * from this file, and CI runs it with `--check`, so drift fails the build rather
 * than being promised against in a comment. The agent gains no dependency: the
 * generated file is plain Go over the standard library.
 *
 * ## Why the agent re-validates anyway
 *
 * ADR 0004 is explicit that duplicating validation is deliberate — "if it lived
 * only in the agent, privd would be a confused deputy and the boundary would be
 * decorative". The same argument applies one level up. The control plane
 * validating an instruction it is about to sign proves nothing to the agent, which
 * must assume the control plane is compromised; and `privd` re-validates again
 * because it must assume the agent is. Three checks, three distrusting parties.
 * Generation is what keeps them from disagreeing about WHAT to check while still
 * each doing the checking.
 *
 * ## The argument vocabulary is the security property
 *
 * Acceptance 3 says no operation accepts a free-form command. That is not
 * achieved by reviewing the operation list — a `string` argument called
 * `options` is a free-form command with better manners. It is achieved by there
 * being no argument kind capable of expressing one: every kind below is either a
 * constrained identifier with an RE2 pattern, a bounded number, an enumeration, or
 * a content blob that a named parser must accept before anything installs it.
 *
 * There is deliberately no `text`, `string`, `args`, `command`, `flags` or `env`
 * kind, and `test/security/agent_operation_catalogue.test.ts` fails if one appears.
 */

/**
 * How an argument is validated. Both sides implement these, and no other.
 *
 * `pattern` is RE2-compatible on purpose: Go's regexp package is RE2, which has no
 * lookahead and no backreferences. A pattern using either would work in the
 * control plane and fail to compile in the agent, so the agent would either refuse
 * everything or — worse, depending on how the error were handled — check nothing.
 * The test suite rejects both constructs rather than trusting a reviewer to notice.
 */
export type ArgumentKind = {
  /** The Go type this becomes. Only these three, so the generator stays boring. */
  readonly goType: "string" | "int64" | "bool";
  /** An RE2-compatible anchored pattern, for identifier-shaped kinds. */
  readonly pattern?: string;
  /** Longest accepted value in bytes. Absent only for `bool`. */
  readonly maxBytes?: number;
  /** Inclusive bounds, for numbers. */
  readonly min?: number;
  readonly max?: number;
  /** The complete set of accepted values, for enumerations. */
  readonly oneOf?: readonly string[];
  /**
   * The named parser that must accept this value before it is acted on.
   *
   * A content blob is the one place a long opaque string is unavoidable — a
   * systemd unit is text, and so is an nginx server block. What makes it not a
   * free-form command is that it is never executed as one: it is written to a file
   * and handed to a program that parses it, and `privd` runs that parser and
   * refuses on a non-zero exit before installing anything (ADR 0004: "after
   * `visudo -c` passes").
   *
   * A kind with `validator` is inert data until a parser vouches for it. A kind
   * without one is an identifier constrained by pattern and length.
   */
  readonly validator?: "systemd-analyze-verify" | "nginx-t" | "visudo-c" | "x509" | "pkcs8";
  /** Why this kind exists, in one line. */
  readonly why: string;
};

export const ARGUMENT_KINDS = {
  site_slug: {
    goType: "string",
    // Lower case, digits, single hyphens, no leading or trailing hyphen. This is
    // also a Linux username, a directory name and part of a systemd unit name, so
    // it is the strictest thing that can be all three.
    pattern: "^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$",
    maxBytes: 32,
    why: "one slug is simultaneously a Linux user, a directory and part of a unit name",
  },
  service_id: {
    goType: "string",
    // The `rl-` prefix is load-bearing rather than cosmetic (GLOSSARY.md): it is
    // what stops any operation from touching a unit outside Ratline's namespace,
    // so an instruction can never stop sshd.
    pattern: "^rl-[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$",
    maxBytes: 50,
    why: "the rl- prefix is what makes 'restart a service' unable to name sshd",
  },
  package_name: {
    goType: "string",
    // Debian policy's own character set, minus anything a shell would treat
    // specially — not that a shell is involved (C2 forbids one), but a package
    // name reaching a log or an error message should not be able to look like an
    // argument either.
    pattern: "^[a-z0-9][a-z0-9+.-]{1,62}$",
    maxBytes: 64,
    why: "distribution package names, narrower than dpkg allows and deliberately so",
  },
  path_in_site: {
    goType: "string",
    // Relative, and a dot may only appear BETWEEN word characters within a
    // segment. That is what admits `posts/index.html` while refusing `.hidden`,
    // `..`, `a/../b` and `index..html`, without a lookahead Go could not compile.
    //
    // The first version of this pattern excluded dots entirely, reasoning that
    // every traversal trick needs one. It also excluded every filename with an
    // extension, so the validator refused all legitimate input — caught by the one
    // test asserting a well-formed instruction is ACCEPTED, which is the test that
    // exists because a validator failing closed on everything looks identical to a
    // validator working until somebody tries to use it.
    //
    // privd re-resolves the result and re-confirms it is inside the site root
    // regardless, because a pattern is not a filesystem and a symlink is not a path.
    pattern:
      "^[a-zA-Z0-9_-]+(?:\\.[a-zA-Z0-9_-]+)*(?:/[a-zA-Z0-9_-]+(?:\\.[a-zA-Z0-9_-]+)*)*$",
    maxBytes: 255,
    why: "a path the agent may write inside a site it owns; privd re-resolves it anyway",
  },
  port: {
    goType: "int64",
    min: 1,
    max: 65535,
    why: "a TCP port, bounded so an out-of-range value is refused before it reaches a config",
  },
  runtime: {
    goType: "string",
    oneOf: ["node", "python", "static", "php", "ruby"],
    // Bounded even though `oneOf` already decides the answer. The length check
    // runs FIRST in both validators, deliberately, so a multi-megabyte value is
    // refused on sight rather than carried into a comparison — an enumeration
    // makes that comparison cheap, but "cheap" is not the same as "not performed".
    maxBytes: 16,
    why: "which runtime a site needs, from a closed set rather than a name to look up",
  },
  service_action: {
    goType: "string",
    oneOf: ["start", "stop", "restart", "reload"],
    maxBytes: 16,
    why: "the four things that can be done to a unit, enumerated so there is no fifth",
  },
  enabled: {
    goType: "bool",
    why: "a flag, for operations whose only variation is on or off",
  },
  unit_file: {
    goType: "string",
    maxBytes: 16384,
    validator: "systemd-analyze-verify",
    why: "a systemd unit, inert until systemd itself parses it without complaint",
  },
  webserver_config: {
    goType: "string",
    maxBytes: 65536,
    validator: "nginx-t",
    why: "a server block, inert until the web server's own parser accepts it",
  },
  sudoers_fragment: {
    goType: "string",
    maxBytes: 4096,
    validator: "visudo-c",
    why: "a sudoers.d fragment; ADR 0004 requires visudo -c to pass before install",
  },
  certificate_pem: {
    goType: "string",
    maxBytes: 32768,
    validator: "x509",
    why: "a certificate chain, parsed as X.509 before it is written anywhere",
  },
  private_key_pem: {
    goType: "string",
    maxBytes: 16384,
    validator: "pkcs8",
    why: "a private key, parsed before install and never logged",
  },
} as const satisfies Record<string, ArgumentKind>;

export type ArgumentKindName = keyof typeof ARGUMENT_KINDS;

/**
 * The kinds, widened to the declared type.
 *
 * `ARGUMENT_KINDS` is `as const`, so each entry's type is its own literal shape and
 * the union has no `min` on the members that lack one. That narrowing is what a
 * call site building an instruction wants, and precisely what code READING the
 * catalogue does not: the generator and the security suite both look at every
 * optional field of every kind, and against the union each access is an error.
 *
 * Exported so the widening happens once, here, next to the declaration it is sound
 * against — rather than as a cast in each reader, where the next reader copies it
 * without knowing why it is safe.
 */
export const KINDS: Record<ArgumentKindName, ArgumentKind> = ARGUMENT_KINDS;

export type ArgumentSpec = {
  readonly name: string;
  readonly kind: ArgumentKindName;
  /** Absent arguments are refused; there is no defaulting, so nothing is implied. */
  readonly required: true;
};

/**
 * Who performs an operation.
 *
 * `agent` operations need no privilege and never reach `privd`. `privd` operations
 * are the enumerated root list from ADR 0004 and nothing else — the boundary is
 * declared here so a reviewer can count the privileged operations without reading
 * any implementation, and so the agent can refuse to attempt one itself.
 */
export const PERFORMERS = ["agent", "privd"] as const;
export type Performer = (typeof PERFORMERS)[number];

export type Operation = {
  readonly name: string;
  readonly performer: Performer;
  readonly args: readonly ArgumentSpec[];
  /** What it does, in the operator's words — this reaches the audit log. */
  readonly summary: string;
  /**
   * Whether performing this twice in a row is the same as performing it once.
   *
   * M2's exit criteria include "the same action runs twice in a row
   * idempotently", and idempotence is a property of each operation rather than of
   * the runner. Declaring it here means RL-M2-024's harness can drive every
   * operation twice and assert the second run changed nothing, instead of a
   * hand-maintained list of which ones to try.
   */
  readonly idempotent: boolean;
};

const arg = (name: string, kind: ArgumentKindName): ArgumentSpec =>
  ({ name, kind, required: true }) as const;

/**
 * Every operation. ADR 0004's privileged list, plus the unprivileged work.
 *
 * Ordered by subject rather than by privilege, because that is how somebody looks
 * for one. `performer` carries the privilege.
 */
export const OPERATIONS = [
  // --- host inventory and health (RL-M2-005 onward) -------------------------
  {
    name: "host.inventory.collect",
    performer: "agent",
    args: [],
    summary: "Report this host's distribution, kernel, memory, disks and installed runtimes",
    idempotent: true,
  },
  {
    name: "host.health.report",
    performer: "agent",
    args: [],
    summary: "Report load, memory pressure, disk headroom and clock skew",
    idempotent: true,
  },

  // --- site accounts and directories ---------------------------------------
  {
    name: "site.user.create",
    performer: "privd",
    args: [arg("slug", "site_slug")],
    summary: "Create the Linux user and home directory a site runs as",
    idempotent: true,
  },
  {
    name: "site.user.remove",
    performer: "privd",
    args: [arg("slug", "site_slug")],
    summary: "Remove a site's Linux user and its home directory",
    // Removing an absent user is not an error, so the second run is a no-op —
    // but it is not the SAME as the first, because the first had something to
    // remove. Declared false so the idempotence harness does not assert a
    // property this operation does not have.
    idempotent: false,
  },
  {
    name: "site.file.write",
    performer: "agent",
    args: [arg("slug", "site_slug"), arg("path", "path_in_site")],
    summary: "Write a file inside a site directory the agent owns",
    idempotent: true,
  },

  // --- systemd units --------------------------------------------------------
  {
    name: "service.unit.install",
    performer: "privd",
    args: [arg("service", "service_id"), arg("unit", "unit_file")],
    summary: "Install a systemd unit and reload the manager",
    idempotent: true,
  },
  {
    name: "service.control",
    performer: "privd",
    args: [arg("service", "service_id"), arg("action", "service_action")],
    summary: "Start, stop, restart or reload a Ratline service",
    // start-then-start is a no-op; restart-then-restart genuinely restarts twice.
    // False rather than per-action, because the harness asks per operation and a
    // half-true answer is worse than a false one.
    idempotent: false,
  },
  {
    name: "service.enable",
    performer: "privd",
    args: [arg("service", "service_id"), arg("enabled", "enabled")],
    summary: "Set whether a Ratline service starts at boot",
    idempotent: true,
  },

  // --- web server -----------------------------------------------------------
  {
    name: "webserver.config.install",
    performer: "privd",
    args: [arg("slug", "site_slug"), arg("config", "webserver_config")],
    summary: "Install a site's web server configuration and reload it",
    idempotent: true,
  },
  {
    name: "webserver.certificate.install",
    performer: "privd",
    args: [
      arg("slug", "site_slug"),
      arg("certificate", "certificate_pem"),
      arg("key", "private_key_pem"),
    ],
    summary: "Install a certificate and its key with root ownership and mode 0600",
    idempotent: true,
  },

  // --- host packages and sudo ----------------------------------------------
  {
    name: "package.install",
    performer: "privd",
    args: [arg("package", "package_name")],
    summary: "Install a package from the distribution's repositories",
    idempotent: true,
  },
  {
    name: "sudoers.fragment.install",
    performer: "privd",
    args: [arg("slug", "site_slug"), arg("fragment", "sudoers_fragment")],
    summary: "Install a sudoers.d fragment, after visudo -c accepts it",
    idempotent: true,
  },

  // --- runtimes -------------------------------------------------------------
  {
    name: "runtime.provision",
    performer: "privd",
    args: [arg("runtime", "runtime"), arg("port", "port")],
    summary: "Make a runtime available on this host and reserve its port",
    idempotent: true,
  },
] as const satisfies readonly Operation[];

/** Every operation name, as a literal union — an unknown name is a type error. */
export type OperationName = (typeof OPERATIONS)[number]["name"];

const BY_NAME: ReadonlyMap<string, Operation> = new Map(
  OPERATIONS.map((operation) => [operation.name, operation]),
);

/**
 * Look up an operation, or `null`.
 *
 * Returns null rather than throwing so the caller must handle absence, and there
 * is no lookup that falls back to a default. ADR 0002's "no default branch" is a
 * property of this function's signature.
 */
export function operation(name: string): Operation | null {
  return BY_NAME.get(name) ?? null;
}

export function isOperationName(name: string): name is OperationName {
  return BY_NAME.has(name);
}

/** The privileged operations, for anyone auditing the trust boundary. */
export function privilegedOperations(): readonly Operation[] {
  return OPERATIONS.filter((operation) => operation.performer === "privd");
}
