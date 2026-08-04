/**
 * Instruction signing key rotation (RL-M2-004).
 *
 * ADR 0002: "agents accept both the outgoing and incoming key for a configured period,
 * so rotation never requires a flag-day."
 *
 * The agent half was already tested — `TestRotationOverlapAcceptsBothKeys` proves
 * `Verify` accepts an envelope signed by any key in its set. This is the control-plane
 * half, plus the one assertion acceptance 4 names that nothing covered: an envelope
 * CORRECTLY SIGNED by a key the agent does not hold. That is a different claim from
 * "a forged signature is refused", and it is the one that fails if verification ever
 * falls back to key material the envelope itself carries.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CURRENT_FILE,
  DEFAULT_OVERLAP_MS,
  MIN_OVERLAP_MS,
  PREVIOUS_FILE,
  ROTATED_AT_FILE,
  RotationRefused,
  acceptedInstructionKeys,
  pruneRetiredKey,
  rotateInstructionKey,
  rotationState,
} from "../../src/crypto/rotation.ts";
import { MAX_VALIDITY_MS, canonicalBytes, signInstruction } from "../../src/agent/envelope.ts";

const NOW = 1_770_000_000_000;

/** A secrets directory with a signing key, as first run would leave it. */
function installation(): string {
  const dir = mkdtempSync(join(tmpdir(), "ratline-rotation-"));
  const { privateKey } = generateKeyPairSync("ed25519");
  const path = join(dir, CURRENT_FILE);
  writeFileSync(path, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), {
    mode: 0o600,
  });
  chmodSync(path, 0o600);
  return dir;
}

test("the minimum overlap is exactly the envelope validity window", () => {
  // The two constants live in different modules and must agree. Duplicated rather than
  // imported so the secrets layer does not depend on the protocol layer for a bound it
  // only compares against — and this assertion is what actually stops them drifting,
  // which a comment would not.
  assert.equal(
    MIN_OVERLAP_MS,
    MAX_VALIDITY_MS,
    "MIN_OVERLAP_MS must equal MAX_VALIDITY_MS. If the overlap can be shorter than an " +
      "envelope's life, an instruction signed just before rotation is refused partway " +
      "through its own validity window.",
  );
});

test("an overlap shorter than an envelope's life is refused", () => {
  const dir = installation();
  try {
    assert.throws(
      () => rotateInstructionKey(dir, { now: NOW, overlapMs: MIN_OVERLAP_MS - 1 }),
      RotationRefused,
    );
    // And the boundary is accepted, so the refusal above is not simply "any short value".
    const rotated = rotateInstructionKey(dir, { now: NOW, overlapMs: MIN_OVERLAP_MS });
    assert.equal(rotated.overlapEndsAt, NOW + MIN_OVERLAP_MS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rotation keeps the outgoing key and both are accepted during the overlap", () => {
  const dir = installation();
  try {
    const before = readFileSync(join(dir, CURRENT_FILE), "utf8");

    const { overlapEndsAt } = rotateInstructionKey(dir, { now: NOW });

    // The outgoing key is still on disk, unchanged. Moved rather than regenerated: an
    // operator who has distributed a public key must not find it silently different.
    assert.equal(readFileSync(join(dir, PREVIOUS_FILE), "utf8"), before);
    assert.notEqual(readFileSync(join(dir, CURRENT_FILE), "utf8"), before);

    const during = acceptedInstructionKeys(dir, NOW + 1000);
    assert.deepEqual(
      during.map((key) => key.keyId),
      ["current", "previous"],
      "both keys must be accepted while the overlap is open, or rotation is a flag-day",
    );
    // Raw 32 bytes, which is what Go's ed25519.PublicKey is.
    for (const key of during) assert.equal(key.raw.length, 32);

    // One millisecond before the deadline the outgoing key is still accepted; one
    // millisecond after, it is not. The boundary is asserted on both sides because a
    // deadline tested from one side passes for an off-by-one in the other direction.
    assert.equal(acceptedInstructionKeys(dir, overlapEndsAt - 1).length, 2);
    assert.equal(acceptedInstructionKeys(dir, overlapEndsAt).length, 1);
    assert.equal(acceptedInstructionKeys(dir, overlapEndsAt + 1).length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a key that never rotated has exactly one accepted key", () => {
  const dir = installation();
  try {
    const keys = acceptedInstructionKeys(dir, NOW);
    assert.deepEqual(keys.map((key) => key.keyId), ["current"]);

    const state = rotationState(dir);
    assert.equal(state.rotatedAt, null);
    assert.equal(state.overlapEndsAt, null);
    assert.equal(state.hasPrevious, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a stale previous key with a closed window is not accepted", () => {
  // Both conditions are checked, not either. A file left behind after the window closed
  // would otherwise extend acceptance indefinitely — the exact failure the deadline
  // exists to prevent, arriving through a cleanup that did not run.
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });
    const wellAfter = NOW + DEFAULT_OVERLAP_MS + 1;

    assert.ok(existsSync(join(dir, PREVIOUS_FILE)), "the file is deliberately still there");
    assert.deepEqual(
      acceptedInstructionKeys(dir, wellAfter).map((key) => key.keyId),
      ["current"],
      "a previous key whose overlap has closed must not be accepted, file or no file",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unreadable rotation stamp refuses rather than assuming a window", () => {
  // Failing the other way — assuming an open overlap — would keep a retired key accepted
  // for a period nobody can determine.
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });
    writeFileSync(join(dir, ROTATED_AT_FILE), "not a timestamp\n", { mode: 0o600 });

    assert.throws(() => acceptedInstructionKeys(dir, NOW + 1000), RotationRefused);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a second rotation during an open overlap is refused", () => {
  // Chaining would leave THREE keys able to sign an instruction to every host, and each
  // additional accepted key is another key an attacker only has to obtain one of.
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });

    assert.throws(
      () => rotateInstructionKey(dir, { now: NOW + 60_000 }),
      (error: unknown) =>
        error instanceof RotationRefused && error.message.includes("THREE keys"),
    );

    // Once the window closes, rotating again is fine.
    const after = NOW + DEFAULT_OVERLAP_MS + 1;
    assert.ok(rotateInstructionKey(dir, { now: after }).rotatedAt === after);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pruning refuses while the overlap is open, and works after", () => {
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });

    assert.throws(() => pruneRetiredKey(dir, { now: NOW + 1000 }), RotationRefused);
    assert.ok(existsSync(join(dir, PREVIOUS_FILE)), "an open overlap must keep the key");

    assert.equal(pruneRetiredKey(dir, { now: NOW + DEFAULT_OVERLAP_MS + 1 }), true);
    assert.ok(!existsSync(join(dir, PREVIOUS_FILE)));
    assert.ok(!existsSync(join(dir, ROTATED_AT_FILE)), "the stamp goes with the key it dated");

    // Reports honestly when there was nothing to do, rather than claiming a cleanup.
    assert.equal(pruneRetiredKey(dir, { now: NOW + DEFAULT_OVERLAP_MS + 2 }), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a key readable by anyone but the owner is refused on every read", () => {
  // Checked on read, not only at rotation. A key whose mode was widened afterwards is
  // exactly as exposed as one written wrongly, and the moment somebody notices is the
  // moment it is read.
  const dir = installation();
  try {
    chmodSync(join(dir, CURRENT_FILE), 0o644);
    assert.throws(() => acceptedInstructionKeys(dir, NOW), RotationRefused);
    assert.throws(() => rotateInstructionKey(dir, { now: NOW }), RotationRefused);

    chmodSync(join(dir, CURRENT_FILE), 0o600);
    assert.equal(acceptedInstructionKeys(dir, NOW).length, 1);

    // And the previous key too, which is just as able to sign.
    rotateInstructionKey(dir, { now: NOW });
    chmodSync(join(dir, PREVIOUS_FILE), 0o604);
    assert.throws(() => acceptedInstructionKeys(dir, NOW + 1000), RotationRefused);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rotation writes every file owner-only", () => {
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });
    // Read through acceptedInstructionKeys, which asserts the mode itself — so this
    // passing means the modes are right rather than that nobody looked.
    assert.equal(acceptedInstructionKeys(dir, NOW + 1000).length, 2);
    assert.equal(rotationState(dir).rotatedAt, NOW);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Acceptance 4: an envelope signed by a key the agent does not hold
// ---------------------------------------------------------------------------

test("an envelope signed by an unknown key is not in the accepted set", () => {
  // The assertion acceptance 4 names, and it is NOT the same as "a forged signature is
  // refused" — which the agent suite already covers. This one is a CORRECTLY signed
  // envelope whose key the agent was never given, and it is the case that fails if
  // verification ever falls back to key material the envelope carries.
  //
  // Verified here at the control plane by proving the stranger's key is absent from the
  // accepted set and its signature is over the same bytes a real one would be — so the
  // only thing standing between it and acceptance is the key set itself. The agent-side
  // refusal is `TestATamperedFieldInvalidatesTheSignature` and
  // `TestAnAgentWithNoKeysRefusesEverything` in envelope_security_test.go.
  const dir = installation();
  try {
    rotateInstructionKey(dir, { now: NOW });
    const accepted = acceptedInstructionKeys(dir, NOW + 1000);

    const { privateKey } = generateKeyPairSync("ed25519");
    const stranger = {
      keyId: "a-key-this-installation-never-had",
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    };

    const envelope = signInstruction(stranger, {
      operation: "site.user.create",
      arguments: { slug: "blog" },
      targetHostId: "a-host",
      now: NOW,
      validityMs: 60_000,
    });

    // It IS a real signature over the real canonical bytes — nothing is malformed.
    assert.ok(envelope.signature.length > 0);
    assert.ok(canonicalBytes(envelope).length > 0);

    // And the key is in neither slot. An agent given this set has nothing that verifies
    // it, which is the whole of the guarantee.
    const strangerRaw = Buffer.from(
      privateKey.export({ type: "pkcs8", format: "der" }),
    ).toString("hex");
    for (const key of accepted) {
      assert.ok(
        !strangerRaw.includes(key.raw.toString("hex")),
        `the stranger's key material matches the ${key.keyId} key, so this test proves nothing`,
      );
    }

    assert.deepEqual(accepted.map((key) => key.keyId), ["current", "previous"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("acceptedInstructionKeys refuses when there is no key at all", () => {
  // C4: the application refuses to boot without its secrets. Rotation must not be the
  // one path that quietly returns an empty set — an agent given no keys refuses
  // everything, which is safe, but the control plane would then be signing with nothing
  // and reporting success.
  const dir = mkdtempSync(join(tmpdir(), "ratline-rotation-empty-"));
  try {
    assert.throws(() => acceptedInstructionKeys(dir, NOW), RotationRefused);
    assert.throws(() => rotateInstructionKey(dir, { now: NOW }), RotationRefused);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
