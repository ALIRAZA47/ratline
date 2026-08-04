/**
 * The envelope's canonical encoding, control-plane side (RL-M2-003).
 *
 * The Go half is `agent/internal/protocol/envelope_security_test.go`. Both suites verify the
 * SAME committed vectors in `agent/internal/protocol/testdata/envelope_vectors.json`,
 * and that is the whole cross-language guarantee: two independent implementations of
 * a canonical encoding is exactly the situation where both can be self-consistent
 * and still disagree, and the failure would arrive on a host as "the agent refuses
 * every instruction" — which reads as a transport problem rather than an encoding
 * one. If either encoder changes by a byte, its verification of the committed
 * signatures fails. The vector file is the drift check; there is no second mechanism
 * to keep current.
 *
 * The tracker declared the artefact as test/security/envelope_verification_test.go.
 * Go requires a `_test.go` file in the package it tests and `test/` is outside the
 * agent module, so that path would never have been compiled or run. Both real halves
 * are recorded instead.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  INSTRUCTION_DOMAIN,
  InstructionRejected,
  MAX_VALIDITY_MS,
  NONCE_BYTES,
  canonicalBytes,
  signInstruction,
  verifyEnvelope,
  wireForm,
  type SignedEnvelope,
} from "../../src/agent/envelope.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const VECTORS = join(ROOT, "agent", "internal", "protocol", "testdata", "envelope_vectors.json");

type VectorFile = {
  readonly domain: string;
  readonly host_id: string;
  readonly test_only_private_key_pem: string;
  readonly public_key_pem: string;
  readonly vectors: readonly {
    readonly name: string;
    readonly why: string;
    readonly envelope: {
      readonly operation: string;
      readonly arguments: Record<string, string>;
      readonly nonce: string;
      readonly issued_at: number;
      readonly expires_at: number;
      readonly target_host_id: string;
      readonly signature: string;
      readonly key_id: string;
    };
    readonly canonical_hex: string;
  }[];
};

function load(): VectorFile {
  const file = JSON.parse(readFileSync(VECTORS, "utf8")) as VectorFile;
  assert.ok(
    file.vectors.length > 0,
    "the vector file is empty, so every test reading it would pass vacuously",
  );
  return file;
}

/** The vector's envelope in the shape this module uses. */
function asEnvelope(vector: VectorFile["vectors"][number]): SignedEnvelope {
  return {
    operation: vector.envelope.operation,
    arguments: vector.envelope.arguments,
    nonce: vector.envelope.nonce,
    issuedAt: vector.envelope.issued_at,
    expiresAt: vector.envelope.expires_at,
    targetHostId: vector.envelope.target_host_id,
    signature: vector.envelope.signature,
    keyId: vector.envelope.key_id,
  };
}

test("the committed vectors still encode to the committed bytes", () => {
  const file = load();
  assert.equal(file.domain, INSTRUCTION_DOMAIN, "the vectors were generated for another domain");

  for (const vector of file.vectors) {
    const got = Buffer.from(canonicalBytes(asEnvelope(vector))).toString("hex");

    if (got === vector.canonical_hex) continue;

    // Where they diverge, not merely that they do. "The bytes differ" sends the
    // reader off to reimplement the encoder to find out which field moved.
    let offset = 0;
    while (
      offset < got.length &&
      offset < vector.canonical_hex.length &&
      got[offset] === vector.canonical_hex[offset]
    ) {
      offset += 1;
    }
    assert.fail(
      `vector "${vector.name}" encodes differently than when it was generated, ` +
        `first difference at hex offset ${String(offset)} (byte ${String(Math.floor(offset / 2))}).\n` +
        `  what this vector pins: ${vector.why}\n` +
        `  committed: ...${vector.canonical_hex.slice(Math.max(0, offset - 16), offset + 32)}\n` +
        `  now:       ...${got.slice(Math.max(0, offset - 16), offset + 32)}\n\n` +
        `If the format changed on purpose, run ./scripts/gen-envelope-vectors and review the diff.`,
    );
  }
});

test("the committed signatures still verify", () => {
  const file = load();
  for (const vector of file.vectors) {
    assert.ok(
      verifyEnvelope(file.public_key_pem, asEnvelope(vector)),
      `vector "${vector.name}" no longer verifies. Either the encoding changed or the ` +
        `signature did — the previous test says which.`,
    );
  }
});

test("the length prefixes are what make the encoding unambiguous", () => {
  // The forgery this prevents: without lengths, {a: "bc"} and {ab: "c"} both flatten
  // to "abc", so one signature would be valid for two different instructions.
  // Asserted directly rather than left to the vector, because this is the property
  // the whole encoding exists for.
  const base = {
    operation: "site.file.write",
    nonce: "0".repeat(NONCE_BYTES * 2),
    issuedAt: 1_770_000_000_000,
    expiresAt: 1_770_000_060_000,
    targetHostId: "host",
  };

  const first = canonicalBytes({ ...base, arguments: { slug: "ab", path: "c" } });
  const second = canonicalBytes({ ...base, arguments: { slug: "a", path: "bc" } });

  assert.notDeepEqual(
    Buffer.from(first).toString("hex"),
    Buffer.from(second).toString("hex"),
    "two different instructions encode to the same bytes, so one signature is valid for both",
  );
});

test("the domain separator is present and carries the version", () => {
  // The same key must never produce a signature valid in two contexts. Without a
  // prefix, an agent's signed response could be replayed as an instruction if the
  // field layouts ever coincided — and "ever coincided" is a property of future
  // code, not of this file.
  const bytes = canonicalBytes({
    operation: "host.health.report",
    arguments: {},
    nonce: "0".repeat(NONCE_BYTES * 2),
    issuedAt: 1,
    expiresAt: 2,
    targetHostId: "host",
  });

  assert.ok(
    Buffer.from(bytes).subarray(0, INSTRUCTION_DOMAIN.length).toString("utf8") ===
      INSTRUCTION_DOMAIN,
    "the canonical bytes do not begin with the domain separator",
  );
  assert.equal(bytes[INSTRUCTION_DOMAIN.length], 0, "the domain separator is not NUL-terminated");
  assert.match(INSTRUCTION_DOMAIN, /-v\d+$/, "the domain must carry a version");
});

test("argument order does not change the bytes", () => {
  // Two objects with the same pairs in different insertion order must encode
  // identically, or the signature depends on how the control plane happened to build
  // the object — and the agent, which sorts, would refuse half of them.
  const base = {
    operation: "webserver.certificate.install",
    nonce: "1".repeat(NONCE_BYTES * 2),
    issuedAt: 1,
    expiresAt: 2,
    targetHostId: "host",
  };

  const forwards = canonicalBytes({
    ...base,
    arguments: { certificate: "c", key: "k", slug: "s" },
  });
  const backwards = canonicalBytes({
    ...base,
    arguments: { slug: "s", key: "k", certificate: "c" },
  });

  assert.deepEqual(Buffer.from(forwards).toString("hex"), Buffer.from(backwards).toString("hex"));
});

test("lengths count bytes, not characters", () => {
  // A character count would make the encoding disagree with Go's, which counts
  // bytes — and the disagreement would only appear for non-ASCII content, so it would
  // ship and then break the first site with a non-English config comment.
  const bytes = canonicalBytes({
    operation: "site.file.write",
    arguments: { slug: "cafe", path: "a" },
    nonce: "2".repeat(NONCE_BYTES * 2),
    issuedAt: 1,
    expiresAt: 2,
    targetHostId: "é",
  });

  // "é" as e + combining acute is 3 UTF-8 bytes and 2 UTF-16 code units.
  const hex = Buffer.from(bytes).toString("hex");
  assert.ok(hex.includes("00000003"), "a 3-byte field is not length-prefixed with 3");
});

test("signing refuses an operation outside the catalogue", () => {
  // The control plane refusing proves nothing to the agent, which re-validates
  // because it must assume this side is compromised. It still belongs here: a bug
  // should fail in these tests, not as a refusal on somebody's host that reads like a
  // protocol problem.
  const file = load();
  const key = { keyId: "k", privateKeyPem: file.test_only_private_key_pem };

  assert.throws(
    () =>
      signInstruction(key, {
        operation: "host.shell.run",
        arguments: {},
        targetHostId: "host",
        now: 1_770_000_000_000,
        validityMs: 60_000,
      }),
    InstructionRejected,
  );
});

test("signing refuses arguments the agent would refuse", () => {
  const file = load();
  const key = { keyId: "k", privateKeyPem: file.test_only_private_key_pem };
  const common = { targetHostId: "host", now: 1_770_000_000_000, validityMs: 60_000 };

  const bad: readonly [string, string, Record<string, string>][] = [
    ["a slug that is not one", "site.user.create", { slug: "Blog!" }],
    ["a missing argument", "site.file.write", { slug: "blog" }],
    ["an undeclared argument", "site.user.create", { slug: "blog", owner: "root" }],
    ["a traversal", "site.file.write", { slug: "blog", path: "../../etc/passwd" }],
    ["a port out of range", "runtime.provision", { runtime: "node", port: "70000" }],
    ["a runtime outside the set", "runtime.provision", { runtime: "cobol", port: "80" }],
    ["a service outside the rl- namespace", "service.control", { service: "sshd", action: "stop" }],
  ];

  for (const [label, operation, args] of bad) {
    assert.throws(
      () => signInstruction(key, { ...common, operation, arguments: args }),
      InstructionRejected,
      `${label} was accepted for ${operation}`,
    );
  }
});

test("signing refuses a validity window longer than the agent will accept", () => {
  // The window bounds the agent's nonce store, so a long one is not a convenience —
  // it is how much replay memory every host has to hold. Signing one the agent
  // refuses would produce instructions that fail on arrival.
  const file = load();
  const key = { keyId: "k", privateKeyPem: file.test_only_private_key_pem };

  assert.throws(
    () =>
      signInstruction(key, {
        operation: "host.health.report",
        arguments: {},
        targetHostId: "host",
        now: 1_770_000_000_000,
        validityMs: MAX_VALIDITY_MS + 1,
      }),
    InstructionRejected,
  );

  // And the boundary is accepted, so the refusal above is not simply "any window".
  assert.ok(
    signInstruction(key, {
      operation: "host.health.report",
      arguments: {},
      targetHostId: "host",
      now: 1_770_000_000_000,
      validityMs: MAX_VALIDITY_MS,
    }).signature.length > 0,
  );
});

test("every signed envelope carries all six fields plus the signature", () => {
  // Acceptance 1, checked on a real envelope rather than on the type. A field that
  // is present in the type and absent from wireForm would not be transmitted, and
  // the agent's canonical encoding would then cover a value it never received.
  const file = load();
  const key = { keyId: "k", privateKeyPem: file.test_only_private_key_pem };

  const envelope = signInstruction(key, {
    operation: "site.user.create",
    arguments: { slug: "blog" },
    targetHostId: "a-host",
    now: 1_770_000_000_000,
    validityMs: 60_000,
  });

  const wire = JSON.parse(wireForm(envelope)) as Record<string, unknown>;

  assert.deepEqual(
    Object.keys(wire).sort(),
    [
      "arguments",
      "expires_at",
      "issued_at",
      "key_id",
      "nonce",
      "operation",
      "signature",
      "target_host_id",
    ],
    "the wire form's fields have changed; the agent's Envelope struct must match, and it " +
      "refuses unknown fields",
  );

  assert.equal((wire["nonce"] as string).length, NONCE_BYTES * 2, "the nonce is not 32 hex bytes");
  assert.equal(wire["expires_at"], (wire["issued_at"] as number) + 60_000);
});

test("two instructions never share a nonce", () => {
  // A repeated nonce would be refused by the agent as a replay, so a weak generator
  // presents as intermittent instruction loss rather than as a security problem.
  const file = load();
  const key = { keyId: "k", privateKeyPem: file.test_only_private_key_pem };
  const seen = new Set<string>();

  for (let index = 0; index < 500; index += 1) {
    const envelope = signInstruction(key, {
      operation: "host.health.report",
      arguments: {},
      targetHostId: "host",
      now: 1_770_000_000_000,
      validityMs: 60_000,
    });
    assert.ok(!seen.has(envelope.nonce), "a nonce repeated within 500 instructions");
    seen.add(envelope.nonce);
  }
});
