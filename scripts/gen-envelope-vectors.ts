#!/usr/bin/env node --experimental-strip-types
/**
 * Generate the cross-language envelope test vectors (RL-M2-003).
 *
 *   ./scripts/gen-envelope-vectors
 *
 * ## Why vectors and not two test suites
 *
 * The signature is over bytes, and two independent implementations of a canonical
 * encoding is exactly the situation where both sides can be self-consistent and
 * still disagree. A TypeScript suite that signs and verifies with its own encoder
 * passes; so does a Go suite that signs and verifies with its own. Neither proves
 * they produce the same bytes, and the failure would arrive as "the agent refuses
 * every instruction" on a host, which reads as a transport problem.
 *
 * So one file of fixed inputs and the signatures TypeScript produced for them is
 * committed, and BOTH suites verify it. If either encoder changes by a byte, its
 * verification of the committed signature fails — the vector is the drift check,
 * with nothing extra to run and no second mechanism to keep current.
 *
 * The vectors are regenerated only when the envelope format changes on purpose,
 * which is a deliberate, reviewable diff — and that diff is exactly what a format
 * change should look like.
 *
 * The private key here is a TEST key with no other use. It exists so the vectors
 * are reproducible, and .gitignore's `**\/testdata/**` exception is what allows a
 * key-shaped thing to live in the tree at all.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalBytes, signInstruction, verifyEnvelope } from "../src/agent/envelope.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET_DIR = join(ROOT, "agent", "internal", "protocol", "testdata");

// Fixed, so a regenerated file differs only where the format did.
const HOST = "8f14e45f-ea8f-4b5e-9c2a-1d3b7e6a0c11";
const ISSUED_AT = 1_770_000_000_000; // 2026-02-02T02:40:00Z
const VALIDITY_MS = 60_000;

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
// Raw 32 bytes, which is what Go's ed25519.PublicKey is. Taking the tail of the
// DER avoids making the agent parse SPKI for a test fixture — the last 32 bytes of
// an Ed25519 SPKI structure are the key.
const publicKeyRaw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);

const key = { keyId: "vector-key-1", privateKeyPem };

/**
 * Cases chosen for what they distinguish, not for coverage.
 *
 * `argument-order` and `ambiguous-concatenation` are the two that would catch a
 * real encoding bug: the first fails if either side iterates a map instead of
 * sorting, and the second fails if either side drops the length prefixes.
 */
const CASES: readonly {
  name: string;
  why: string;
  operation: string;
  args: Record<string, string>;
  nonce: string;
}[] = [
  {
    name: "no-arguments",
    why: "the argument count must still be encoded, as zero, or a no-argument envelope and a one-argument envelope could share bytes",
    operation: "host.inventory.collect",
    args: {},
    nonce: "a".repeat(64),
  },
  {
    name: "single-argument",
    why: "the ordinary case",
    operation: "site.user.create",
    args: { slug: "blog" },
    nonce: "b".repeat(64),
  },
  {
    name: "argument-order",
    why: "three arguments declared out of alphabetical order; fails if either side iterates its map rather than sorting by name",
    operation: "webserver.certificate.install",
    args: {
      key: "-----BEGIN PRIVATE KEY-----\nvector\n-----END PRIVATE KEY-----\n",
      certificate: "-----BEGIN CERTIFICATE-----\nvector\n-----END CERTIFICATE-----\n",
      slug: "shop",
    },
    nonce: "c".repeat(64),
  },
  {
    name: "ambiguous-concatenation",
    why: 'the "abc" case: without length prefixes, {ab: "c"} and {a: "bc"} encode identically, so one signature would be valid for two instructions. This vector pins the prefixed form.',
    operation: "site.file.write",
    args: { slug: "ab", path: "c" },
    nonce: "d".repeat(64),
  },
  {
    name: "multibyte-content",
    why: "lengths are BYTES, not characters; fails if either side prefixes with a character count",
    operation: "webserver.config.install",
    args: { slug: "cafe", config: "# café — 日本語\nserver { }\n" },
    nonce: "e".repeat(64),
  },
  {
    name: "numeric-argument",
    why: "numbers travel as strings, so the encoding never has to agree about number formatting",
    operation: "runtime.provision",
    args: { runtime: "node", port: "8080" },
    nonce: "f".repeat(64),
  },
];

const vectors = CASES.map((testCase) => {
  const envelope = signInstruction(key, {
    operation: testCase.operation,
    arguments: testCase.args,
    targetHostId: HOST,
    now: ISSUED_AT,
    validityMs: VALIDITY_MS,
    nonce: testCase.nonce,
  });

  // Verified here before being written. A vector nobody checked is a vector that
  // could pin a bug in place, and the Go side would then be "corrected" to match it.
  if (!verifyEnvelope(publicKeyPem, envelope)) {
    throw new Error(`vector "${testCase.name}" does not verify against its own key`);
  }

  return {
    name: testCase.name,
    why: testCase.why,
    envelope: {
      operation: envelope.operation,
      arguments: envelope.arguments,
      nonce: envelope.nonce,
      issued_at: envelope.issuedAt,
      expires_at: envelope.expiresAt,
      target_host_id: envelope.targetHostId,
      signature: envelope.signature,
      key_id: envelope.keyId,
    },
    // The canonical bytes, so a mismatch says WHERE rather than only that the
    // signature failed. Debugging "bad signature" without this means reimplementing
    // the encoder to find out which byte differs.
    canonical_hex: Buffer.from(canonicalBytes(envelope)).toString("hex"),
  };
});

mkdirSync(TARGET_DIR, { recursive: true });
writeFileSync(
  join(TARGET_DIR, "envelope_vectors.json"),
  `${JSON.stringify(
    {
      note:
        "Generated by scripts/gen-envelope-vectors. Verified by BOTH " +
        "agent/internal/protocol/envelope_test.go and " +
        "test/security/envelope_encoding.test.ts. If either encoder changes by a byte, " +
        "its verification of these signatures fails — that is the point.",
      domain: "ratline-instruction-v1",
      host_id: HOST,
      test_only_private_key_pem: privateKeyPem,
      public_key_pem: publicKeyPem,
      public_key_raw_hex: publicKeyRaw.toString("hex"),
      vectors,
    },
    null,
    2,
  )}\n`,
  "utf8",
);

console.log(
  `wrote agent/internal/protocol/testdata/envelope_vectors.json — ${String(vectors.length)} vectors`,
);
