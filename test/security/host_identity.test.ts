/**
 * How a host proves who it is (RL-M2-005, ADR 0002 as amended by A-04).
 *
 * The owner ruled that transport authentication is an Ed25519 challenge rather than an
 * X.509 client certificate. A certificate got two properties for free that this has to
 * supply deliberately, and they are the first two tests here because they are the whole
 * reason the amendment needed a test file rather than just an implementation:
 *
 *   1. A signature is bound to the connection that requested the challenge. Without
 *      that, a captured signature is a bearer token — replay it on a new connection and
 *      it authenticates whoever holds it.
 *   2. The signature lives in its own namespace. Without that, a host's signed
 *      challenge and a signed instruction could be confused for one another.
 *
 * The rest is the ordinary work: expiry, revocation before signature, and a refusal for
 * every way an answer can be wrong.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  CHALLENGE_BYTES,
  CHALLENGE_TTL_MS,
  IDENTITY_DOMAIN,
  IdentityRefused,
  challengeBytes,
  fingerprint,
  issueChallenge,
  signChallenge,
  verifyChallenge,
  type RegisteredKey,
} from "../../src/crypto/host_identity.ts";
import { INSTRUCTION_DOMAIN, canonicalBytes } from "../../src/agent/envelope.ts";
import { createChallengeStore, MAX_IN_FLIGHT } from "../../src/api/challenges.ts";
import { createServer } from "../../src/api/server.ts";

const NOW = 1_770_000_000_000;
const HOST = "8f14e45f-ea8f-4b5e-9c2a-1d3b7e6a0c11";

function host(hostId = HOST): { key: RegisteredKey; privateKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    key: {
      hostId,
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
      revokedAt: null,
    },
  };
}

// ---------------------------------------------------------------------------
// The two properties a certificate gave for free
// ---------------------------------------------------------------------------

test("a signature for one connection does not authenticate another", () => {
  // THE PROPERTY THE AMENDMENT MOST NEEDED. A certificate is bound to its TLS session by
  // the handshake; a signature over a challenge is a bearer token once it exists. So the
  // challenge is per connection, and a signature that answers one cannot answer another.
  const { key, privateKeyPem } = host();

  const first = issueChallenge(NOW);
  const second = issueChallenge(NOW);
  assert.notEqual(first.nonce, second.nonce, "two challenges must never share a nonce");

  const answer = {
    hostId: HOST,
    nonce: first.nonce,
    signature: signChallenge(privateKeyPem, HOST, first.nonce),
  };

  // Correct on the connection that issued it.
  verifyChallenge(first, answer, key, NOW + 1000);

  // Replayed on another connection: the signature is genuine, the key is genuine, and it
  // must still be refused — because it does not cover the second connection's nonce.
  assert.throws(
    () => verifyChallenge(second, answer, key, NOW + 1000),
    (error: unknown) =>
      error instanceof IdentityRefused && error.message.includes("this connection issued"),
    "a captured signature replayed on a new connection was accepted, so it is a bearer token",
  );
});

test("a challenge signature is not an instruction, and an instruction is not a challenge", () => {
  // Domain separation. The two keys are different keys TODAY, and "different keys today"
  // is a property of current code rather than of the format — so the separator makes the
  // confusion impossible instead of merely unlikely.
  assert.notEqual(IDENTITY_DOMAIN, INSTRUCTION_DOMAIN);

  const identity = challengeBytes(HOST, "a".repeat(CHALLENGE_BYTES * 2));
  const instruction = canonicalBytes({
    operation: "host.health.report",
    arguments: {},
    nonce: "a".repeat(64),
    issuedAt: NOW,
    expiresAt: NOW + 60_000,
    targetHostId: HOST,
  });

  // Neither byte string is a prefix of the other, which is the form the confusion would
  // take: a verifier reading the first N bytes of one and finding the other's domain.
  const a = Buffer.from(identity).toString("hex");
  const b = Buffer.from(instruction).toString("hex");
  assert.ok(!a.startsWith(b) && !b.startsWith(a));

  // And each begins with its own domain, NUL-terminated, so the separator cannot be
  // confused with the start of a field.
  assert.equal(identity.subarray(0, IDENTITY_DOMAIN.length).toString("utf8"), IDENTITY_DOMAIN);
  assert.equal(identity[IDENTITY_DOMAIN.length], 0);
  assert.match(IDENTITY_DOMAIN, /-v\d+$/, "the domain must carry a version");
});

// ---------------------------------------------------------------------------
// Ordinary refusals
// ---------------------------------------------------------------------------

test("an expired challenge is refused before its signature is examined", () => {
  const { key, privateKeyPem } = host();
  const challenge = issueChallenge(NOW);
  const answer = {
    hostId: HOST,
    nonce: challenge.nonce,
    signature: signChallenge(privateKeyPem, HOST, challenge.nonce),
  };

  // One millisecond inside, accepted; at the deadline, refused. An inclusive boundary is
  // a millisecond of validity nobody reasons about.
  verifyChallenge(challenge, answer, key, challenge.expiresAt - 1);
  assert.throws(
    () => verifyChallenge(challenge, answer, key, challenge.expiresAt),
    (error: unknown) => error instanceof IdentityRefused && error.message.includes("expired"),
  );
  assert.equal(challenge.expiresAt - challenge.issuedAt, CHALLENGE_TTL_MS);
});

test("a revoked key is refused, and its signature is never examined", () => {
  // Revocation is checked BEFORE the signature. A revoked host's signature should not be
  // examined at all — and refusing later would leak, by timing, whether it was
  // well-formed, which tells an attacker holding a stolen key that the key was once real.
  const { key, privateKeyPem } = host();
  const challenge = issueChallenge(NOW);

  const revoked: RegisteredKey = { ...key, revokedAt: new Date(NOW - 1000) };
  const goodAnswer = {
    hostId: HOST,
    nonce: challenge.nonce,
    signature: signChallenge(privateKeyPem, HOST, challenge.nonce),
  };
  const garbageAnswer = { ...goodAnswer, signature: Buffer.from("nonsense").toString("base64") };

  // Both refused, and for the SAME stated reason — the revocation, not the signature.
  for (const answer of [goodAnswer, garbageAnswer]) {
    assert.throws(
      () => verifyChallenge(challenge, answer, revoked, NOW + 1000),
      (error: unknown) => error instanceof IdentityRefused && error.message.includes("revoked"),
    );
  }
});

test("an answer signed by the wrong key is refused", () => {
  const { key } = host();
  const stranger = host();
  const challenge = issueChallenge(NOW);

  assert.throws(
    () =>
      verifyChallenge(
        challenge,
        {
          hostId: HOST,
          nonce: challenge.nonce,
          signature: signChallenge(stranger.privateKeyPem, HOST, challenge.nonce),
        },
        key,
        NOW + 1000,
      ),
    (error: unknown) => error instanceof IdentityRefused && error.message.includes("does not verify"),
  );
});

test("an answer naming a different host than the key it is checked against is refused", () => {
  // A wiring bug rather than an attack — the key was looked up by host id, so a mismatch
  // means the caller paired two different hosts. It must not authenticate anyone.
  const { key, privateKeyPem } = host();
  const challenge = issueChallenge(NOW);
  const other = "00000000-0000-4000-8000-000000000000";

  assert.throws(
    () =>
      verifyChallenge(
        challenge,
        { hostId: other, nonce: challenge.nonce, signature: signChallenge(privateKeyPem, other, challenge.nonce) },
        key,
        NOW + 1000,
      ),
    (error: unknown) => error instanceof IdentityRefused && error.message.includes("different host"),
  );
});

test("a malformed signature is a refusal, not a crash", () => {
  // Either outcome ends the connection, but a throw that is not an IdentityRefused would
  // reach a generic handler and could be reported as a server error — which tells an
  // attacker their input reached something it should not have.
  const { key } = host();
  const challenge = issueChallenge(NOW);

  for (const signature of ["", "not base64 !!", Buffer.alloc(10).toString("base64")]) {
    assert.throws(
      () => verifyChallenge(challenge, { hostId: HOST, nonce: challenge.nonce, signature }, key, NOW + 1000),
      IdentityRefused,
      `signature ${JSON.stringify(signature)} did not produce an IdentityRefused`,
    );
  }
});

test("the signed bytes cover both the host and the nonce", () => {
  // Length-prefixed for the reason the envelope is: without lengths, concatenation is
  // ambiguous, and both of these fields are hex-ish strings. Changing either must change
  // the bytes.
  const a = challengeBytes(HOST, "ab");
  const b = challengeBytes(HOST, "b");
  const c = challengeBytes(`${HOST}a`, "b");

  const hex = (buffer: Buffer) => buffer.toString("hex");
  assert.notEqual(hex(a), hex(b));
  assert.notEqual(hex(b), hex(c));
  // The ambiguity that length prefixes exist to remove.
  assert.notEqual(hex(challengeBytes("ab", "c")), hex(challengeBytes("a", "bc")));
});

test("challenges are unpredictable and full length", () => {
  // A repeated nonce would make one connection's signature valid on another, which is the
  // first property in this file. A weak generator presents as intermittent auth failure
  // rather than as a security problem.
  const seen = new Set<string>();
  for (let index = 0; index < 500; index += 1) {
    const challenge = issueChallenge(NOW);
    assert.equal(challenge.nonce.length, CHALLENGE_BYTES * 2, "the nonce is not 32 hex-encoded bytes");
    assert.ok(!seen.has(challenge.nonce), "a nonce repeated within 500 challenges");
    seen.add(challenge.nonce);
  }
});

test("a fingerprint identifies a key without disclosing anything", () => {
  const { key } = host();
  const other = host();

  assert.equal(fingerprint(key.publicKeyPem), fingerprint(key.publicKeyPem), "must be stable");
  assert.notEqual(fingerprint(key.publicKeyPem), fingerprint(other.key.publicKeyPem));
  assert.match(fingerprint(key.publicKeyPem), /^[0-9a-f]{16}$/);
});

/**
 * The agent computes this same value and sends it (RL-M2-006).
 *
 * `/agent/authenticate` looks a host's key up BY fingerprint, so this is not a cosmetic
 * agreement: if Go's `transport.Fingerprint` and this function ever disagree, every
 * authentication fails with a correctly registered key in place, and the symptom on the
 * host is "the agent cannot authenticate" — which reads as a network problem or a
 * revocation. That is the same class of silent cross-language drift the committed envelope
 * and identity vectors exist to catch, and it deserves the same treatment.
 *
 * A pinned literal rather than a generated vector, because adding a field to
 * identity_vectors.json regenerates every signature in it — the generator mints a fresh key
 * per run — and an unrelated wall of diff is a worse trade than two pins that name each
 * other. The other one is TestTheFingerprintAgreesWithTheControlPlane in
 * agent/internal/transport/client_security_test.go.
 */
test("the fingerprint of the committed test key is the one the agent computes", () => {
  const vectors = JSON.parse(
    readFileSync(
      new URL("../../agent/internal/protocol/testdata/identity_vectors.json", import.meta.url),
      "utf8",
    ),
  ) as { test_only_private_key_pem: string };

  const publicKeyPem = createPublicKey(vectors.test_only_private_key_pem)
    .export({ type: "spki", format: "pem" })
    .toString();

  assert.equal(
    fingerprint(publicKeyPem),
    "2b3081d8482c9302",
    "If the vectors were regenerated, this pin and the Go one are both stale — recompute " +
      "and change them together, or the agent and the control plane will name the same key " +
      "differently.",
  );
});

test("a well-formed answer from a live key is accepted", () => {
  // The other direction, so none of the above passes by refusing everything — which is
  // how a verifier most often breaks without anybody noticing.
  const { key, privateKeyPem } = host();
  const challenge = issueChallenge(NOW);

  verifyChallenge(
    challenge,
    { hostId: HOST, nonce: challenge.nonce, signature: signChallenge(privateKeyPem, HOST, challenge.nonce) },
    key,
    NOW + 1000,
  );
});

// ---------------------------------------------------------------------------
// The challenge store, which is what makes the binding property hold over HTTP
// ---------------------------------------------------------------------------

test("a challenge is consumed on first use, so an answer cannot be replayed", () => {
  // Over HTTP there is no connection to bind to — request and response are separate
  // exchanges — so the binding becomes "bound to the exchange that requested it". Taking
  // rather than reading is what makes that true: a replay of the exact same request finds
  // nothing, even if the signature is perfect.
  const store = createChallengeStore();
  const { handle, challenge } = store.issue(NOW);

  assert.deepEqual(store.take(handle, NOW + 1000), challenge);
  assert.equal(store.take(handle, NOW + 1000), null, "a challenge was answerable twice");
  assert.equal(store.size(), 0);
});

test("an expired challenge is removed and refused", () => {
  const store = createChallengeStore();
  const { handle, challenge } = store.issue(NOW);

  assert.equal(store.take(handle, challenge.expiresAt), null);
  // Removed even though it was refused: an expired entry left in the map is a slot a
  // legitimate agent cannot use, which is the bound turned into a leak.
  assert.equal(store.size(), 0);
});

test("the challenge store is bounded, because an unauthenticated caller can fill it", () => {
  // Asking for a challenge needs no credential. If issuing one allocated memory nothing
  // reclaimed, asking repeatedly would be the cheapest possible denial of service against
  // the control plane.
  const store = createChallengeStore();
  for (let index = 0; index < MAX_IN_FLIGHT; index += 1) store.issue(NOW);

  assert.throws(() => store.issue(NOW), /already in flight/);

  // And space is reclaimed by expiry, not by eviction — evicting the oldest would let a
  // flood choose which legitimate agent's challenge is forgotten.
  assert.ok(store.issue(NOW + CHALLENGE_TTL_MS + 1).handle.length > 0);
});

// ---------------------------------------------------------------------------
// Over the wire
// ---------------------------------------------------------------------------

const WIRE_DEPS = {
  cookieSecret: new Uint8Array(32).fill(7),
  resolveTenant: () => Promise.resolve("00000000-0000-4000-8000-000000000001"),
  signInIdentityId: "00000000-0000-4000-8000-000000000000",
  sealingKey: Buffer.alloc(32, 9),
  secretsDir: "/nonexistent-for-this-test",
  trustedOrigins: ["http://127.0.0.1:7712"],
};

async function post(path: string, body: unknown): Promise<Response> {
  return createServer(WIRE_DEPS).fetch(
    new Request(`http://127.0.0.1:7712${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://127.0.0.1:7712" },
      body: JSON.stringify(body),
    }),
  );
}

test("a connection presenting no proof is refused, over HTTP", () => {
  // Acceptance 3's first half, at the transport layer rather than the decision layer.
  // The revoked-key half needs a registered key and therefore a database, and lives in
  // the decision-layer tests above — recorded rather than blurred.
  return (async () => {
    for (const body of [
      {},
      { handle: "nonsense" },
      { handle: "nonsense", hostId: "h", nonce: "a", signature: "b", fingerprint: "c" },
    ]) {
      const response = await post("/agent/authenticate", body);
      assert.ok(
        response.status === 400 || response.status === 401,
        `a bad answer got ${String(response.status)}`,
      );

      const text = await response.text();
      // No detail about WHY. An unknown handle, a bad signature and a revoked key must
      // read the same, or probing tells an attacker which handles and hosts are real.
      assert.ok(
        !/revoked|expired|unknown host|no challenge/i.test(text),
        `the refusal leaks why it failed: ${text}`,
      );
    }
  })();
});

test("asking for a challenge discloses nothing about the installation", () => {
  return (async () => {
    const response = await post("/agent/challenge", {});
    assert.equal(response.status, 200);

    const payload = (await response.json()) as { handle: string; nonce: string };
    assert.equal(payload.nonce.length, CHALLENGE_BYTES * 2);
    assert.ok(payload.handle.length >= 32, "the handle must not be guessable");

    // Two requests must not share a nonce or a handle, or one agent's challenge could be
    // consumed by another.
    const second = (await (await post("/agent/challenge", {})).json()) as {
      handle: string;
      nonce: string;
    };
    assert.notEqual(payload.nonce, second.nonce);
    assert.notEqual(payload.handle, second.handle);
  })();
});
