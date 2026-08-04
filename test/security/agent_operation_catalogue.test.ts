/**
 * The operation catalogue's security properties, control-plane side (RL-M2-002).
 *
 * The Go half is `agent/internal/protocol/catalogue_security_test.go`, and the two are not
 * redundant. ADR 0004 requires the boundary's parties to validate independently —
 * "if it lived only in the agent, privd would be a confused deputy and the
 * boundary would be decorative" — so each side asserts its own checking. What this
 * file adds that Go cannot is the properties of the SOURCE: that the generated copy
 * is current, that no pattern uses a construct Go would reject, and that the
 * vocabulary cannot express a command.
 *
 * The tracker declared the artefact as
 * `test/security/agent_operation_catalogue_security_test.go`. That path cannot work — Go
 * requires a `_test.go` file to live in the package it tests, and `test/` is
 * outside the agent module, so a file there would never be compiled or run. A
 * security suite that silently does nothing is worse than an inconvenient path, so
 * the artefact is recorded at the two locations that execute.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ARGUMENT_KINDS,
  KINDS,
  OPERATIONS,
  isOperationName,
  operation,
  privilegedOperations,
} from "../../src/agent/catalogue.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Words that name a free-form command or an argument list.
 *
 * Acceptance 3 is "there is no operation that accepts a free-form command", and
 * the way that is achieved is by the vocabulary being unable to express one. This
 * list is the tripwire on the vocabulary, not on the operations: an operation
 * cannot smuggle one in without a kind to carry it.
 */
const FORBIDDEN_WORDS = [
  "command",
  "cmd",
  "shell",
  "script",
  "args",
  "argv",
  "flags",
  "env",
  "text",
  "raw",
  "exec",
];

test("no argument kind can express a free-form command", () => {
  for (const name of Object.keys(ARGUMENT_KINDS)) {
    for (const word of FORBIDDEN_WORDS) {
      assert.ok(
        !name.toLowerCase().includes(word),
        `argument kind "${name}" contains "${word}". No kind may name a free-form command ` +
          `or an argument list — ADR 0002: "no operation accepts a free-form command".`,
      );
    }
  }

  for (const op of OPERATIONS) {
    for (const spec of op.args) {
      for (const word of FORBIDDEN_WORDS) {
        assert.ok(
          !spec.name.toLowerCase().includes(word),
          `operation "${op.name}" has an argument "${spec.name}" containing "${word}".`,
        );
      }
    }
  }
});

test("every argument kind constrains its values", () => {
  // The load-bearing half of the test above. A kind named `site_slug` with no
  // pattern, no enumeration and no validator accepts anything at all, and its name
  // would keep the word scan perfectly happy.
  for (const [name, kind] of Object.entries(KINDS)) {
    const constrains =
      kind.pattern !== undefined ||
      kind.oneOf !== undefined ||
      kind.validator !== undefined ||
      kind.min !== undefined ||
      kind.max !== undefined ||
      kind.goType === "bool";

    assert.ok(
      constrains,
      `argument kind "${name}" constrains nothing. Every kind must be a pattern, an ` +
        `enumeration, a bounded number, a boolean, or a blob a named parser must accept.`,
    );

    if (kind.goType === "string") {
      assert.ok(
        kind.maxBytes !== undefined,
        `argument kind "${name}" is a string with no maxBytes, so it accepts unbounded ` +
          `input — a denial of service against the host regardless of what it contains.`,
      );
    }
  }
});

test("no pattern uses a construct Go's regexp cannot compile", () => {
  // Go's regexp is RE2: no lookahead, no lookbehind, no backreferences. A pattern
  // using one compiles in the control plane and fails in the agent, and the failure
  // arrives at runtime on somebody's host. Caught here because this is the side
  // where the mistake is possible — TypeScript would accept it silently.
  const unsupported: readonly [string, RegExp][] = [
    ["lookahead", /\(\?=/],
    ["negative lookahead", /\(\?!/],
    ["lookbehind", /\(\?<=/],
    ["negative lookbehind", /\(\?<!/],
    ["backreference", /\\[1-9]/],
    ["named backreference", /\\k</],
  ];

  for (const [name, kind] of Object.entries(KINDS)) {
    if (kind.pattern === undefined) continue;

    for (const [construct, probe] of unsupported) {
      assert.ok(
        !probe.test(kind.pattern),
        `argument kind "${name}" uses ${construct} in its pattern. Go's regexp is RE2 and ` +
          `cannot compile it, so the agent would refuse every instruction using this kind.`,
      );
    }

    assert.ok(
      kind.pattern.startsWith("^") && kind.pattern.endsWith("$"),
      `argument kind "${name}" pattern is not anchored at both ends. An unanchored pattern ` +
        `matches a substring, so "^rl-[a-z]+" accepts "rl-web; rm -rf /".`,
    );

    assert.ok(
      !new RegExp(kind.pattern).test(""),
      `argument kind "${name}" accepts the empty string, which makes "required" meaningless.`,
    );
  }
});

test("an operation name outside the catalogue resolves to nothing", () => {
  // The control-plane mirror of the agent's refusal. `operation()` returns null
  // rather than throwing, so the caller must handle absence — and there is no
  // lookup that falls back to a default.
  for (const name of ["host.shell.run", "exec", "site.user.creat", "", "*"]) {
    assert.equal(operation(name), null, `operation("${name}") resolved to something`);
    assert.equal(isOperationName(name), false, `isOperationName("${name}") was true`);
  }

  // And the positive case, so this does not pass by rejecting everything.
  assert.notEqual(operation("site.user.create"), null);
  assert.ok(isOperationName("site.user.create"));
});

test("every operation's arguments name a kind that exists", () => {
  const kinds = new Set(Object.keys(ARGUMENT_KINDS));

  for (const op of OPERATIONS) {
    for (const spec of op.args) {
      assert.ok(
        kinds.has(spec.kind),
        `operation "${op.name}" argument "${spec.name}" names kind "${spec.kind}", which does ` +
          `not exist. An unknown kind cannot be validated, so the argument would go unchecked.`,
      );
    }

    // Duplicate argument names would make one of them unreachable, since the wire
    // form is a map. Silently dropping an argument is how a validated instruction
    // ends up doing something other than what was signed.
    const names = op.args.map((spec) => spec.name);
    assert.deepEqual(
      [...new Set(names)],
      names,
      `operation "${op.name}" declares a duplicate argument name`,
    );
  }
});

test("the privileged operations are exactly the ones ADR 0004 enumerates", () => {
  // Pinned by name rather than by count. A count catches an addition and misses a
  // substitution, and this is the list that defines what root can be asked to do —
  // so a change here should be a visible diff in a test, not a quiet one in data.
  const expected = [
    "package.install",
    "runtime.provision",
    "service.control",
    "service.enable",
    "service.unit.install",
    "site.user.create",
    "site.user.remove",
    "sudoers.fragment.install",
    "webserver.certificate.install",
    "webserver.config.install",
  ];

  assert.deepEqual(
    privilegedOperations()
      .map((op) => op.name)
      .sort(),
    expected,
    "the set of operations privd will perform as root has changed. ADR 0004 enumerates them; " +
      "adding one widens what a compromised control plane can do to a host, so it belongs in " +
      "the ADR and in this list together.",
  );
});

test("no privileged operation takes an unconstrained content blob alone", () => {
  // A privileged operation whose only argument is a blob has nothing to scope it
  // to. `sudoers.fragment.install` takes a slug as well as the fragment for exactly
  // this reason: the fragment is what to install, and the slug is who it is for.
  for (const op of privilegedOperations()) {
    const blobs = op.args.filter(
      (spec) => KINDS[spec.kind].validator !== undefined,
    );
    if (blobs.length === 0) continue;

    const identifiers = op.args.filter(
      (spec) => KINDS[spec.kind].validator === undefined,
    );

    assert.ok(
      identifiers.length > 0,
      `privileged operation "${op.name}" takes content (${blobs
        .map((b) => b.name)
        .join(", ")}) with no identifier scoping it. A blob with nothing to scope it to ` +
        `can be installed anywhere the operation reaches.`,
    );
  }
});

test("the generated Go catalogue is current", () => {
  // Acceptance 2: the two sides "cannot drift". A generator alone makes them agree
  // when somebody remembers to run it; this is the part that makes the claim true.
  // It runs in CI as well, but having it here means a developer sees it before
  // pushing rather than after.
  //
  // execFileSync with an argv array, never a shell string (C2).
  try {
    execFileSync("./scripts/gen-agent-protocol", ["--check"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: "pipe",
    });
  } catch (cause) {
    const detail =
      typeof cause === "object" && cause !== null && "stderr" in cause
        ? String(cause.stderr)
        : String(cause);
    assert.fail(
      `agent/internal/protocol/catalogue_gen.go is out of date with src/agent/catalogue.ts.\n\n${detail}`,
    );
  }
});

test("the catalogue is not empty and every operation is reachable by name", () => {
  // Guards against the whole suite passing vacuously. Several tests above iterate
  // OPERATIONS; an empty catalogue would satisfy all of them.
  assert.ok(OPERATIONS.length >= 10, `only ${String(OPERATIONS.length)} operations declared`);
  assert.ok(Object.keys(ARGUMENT_KINDS).length >= 10);

  for (const op of OPERATIONS) {
    assert.equal(operation(op.name)?.name, op.name, `"${op.name}" is not reachable by name`);
  }
});
