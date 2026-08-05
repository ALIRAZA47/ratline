/**
 * The cookie secret is checked for entropy, not only for length (C4, RL-M1-054).
 *
 * ## The defect
 *
 * `weakSecretReason` correctly rejects an all-zero 32-byte secret and was never
 * reached for `ServerDeps.cookieSecret`. That value arrives as a `Uint8Array`
 * handed straight to `createServer`, bypassing `src/crypto/secrets.ts` — the only
 * caller — and `src/api/csrf.ts` validated LENGTH alone, so
 * `csrfTokenForSessionId(new Uint8Array(32), …)` returned a token happily.
 *
 * csrf.ts named the outcome it was trying to prevent two lines above that check —
 * "a token every installation on earth could compute" — and then guarded only
 * length. That sentence is the whole finding: the file knew what mattered and
 * checked the cheaper thing.
 *
 * ## Why this matters now rather than when it bites
 *
 * It was filed as latent because nothing called `createServer` in production.
 * RL-M1-042 and RL-M1-055 built and ran an entry point, so the path is live: a
 * cookie secret is now loaded at boot and handed to a real server. The secret
 * store generates a good one, so this is not exploitable through the supported
 * path — it is a missing floor under a path that has no other floor.
 *
 * ## What each test is for
 *
 * The first two are the acceptance lines. The rest pin the boundary from both
 * sides: a good secret must still work, or the fix is just an outage, and the
 * shapes that are refused must be the shapes that are weak rather than everything
 * that is not exactly 32 random bytes.
 *
 * Verified by mutation — recorded on the task. Restoring the length-only check in
 * csrfKey makes "a 32-byte secret of all zeros cannot mint a token" pass a token
 * back instead of throwing; removing the assertUsableCookieSecret call from
 * createServer makes the construction test fail while every other test in the
 * repository stays green, which is what made the gap invisible in the first place.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assertUsableCookieSecret,
  csrfTokenForSessionId,
  WeakCookieSecret,
} from "../../src/api/csrf.ts";
import { createServer, type ServerDeps } from "../../src/api/server.ts";
import { weakSecretBytesReason, weakSecretReason } from "../../src/crypto/weak-secrets.ts";

const SECRETS_DIR = mkdtempSync(join(tmpdir(), "rl-cookie-secret-"));

/** Everything a server needs except the secret under test. */
function depsWith(cookieSecret: Uint8Array): ServerDeps {
  return {
    cookieSecret,
    sealingKey: Buffer.alloc(32, 9),
    resolveTenant: () => Promise.resolve(null),
    signInIdentityId: null,
    secretsDir: SECRETS_DIR,
    trustedOrigins: ["http://127.0.0.1:7712"],
  };
}

/** 32 bytes of ASCII that pass every entropy heuristic and are still a default. */
const PLACEHOLDER_BYTES = new Uint8Array(
  Buffer.from("changeme-changeme-changeme-chang", "latin1"),
);

// ---------------------------------------------------------------------------
// Acceptance 1 — length is not entropy
// ---------------------------------------------------------------------------

test("a 32-byte secret of all zeros cannot mint a CSRF token", () => {
  // Exactly the call the task recorded as succeeding.
  assert.throws(
    () => csrfTokenForSessionId(new Uint8Array(32), "session-1"),
    (error: unknown) =>
      error instanceof WeakCookieSecret && /no entropy/.test(error.message),
    "a secret of the right length and no entropy must not key anything",
  );
});

test("every no-entropy shape of the right length is refused", () => {
  const weak: [string, Uint8Array][] = [
    ["all zeros", new Uint8Array(32)],
    ["one repeated byte", new Uint8Array(32).fill(7)],
    ["a counting sequence", Uint8Array.from({ length: 32 }, (_, i) => i)],
    ["a descending sequence", Uint8Array.from({ length: 32 }, (_, i) => 255 - i)],
    ["four values cycled", Uint8Array.from({ length: 32 }, (_, i) => i % 4)],
    ["a well-known placeholder", PLACEHOLDER_BYTES],
  ];

  for (const [what, secret] of weak) {
    assert.equal(secret.length, 32, `${what} must be the right LENGTH, or this proves nothing`);
    assert.throws(
      () => csrfTokenForSessionId(secret, "session-1"),
      WeakCookieSecret,
      `${what}: 32 bytes is not the same as 32 bytes of entropy`,
    );
  }
});

test("the placeholder case is caught by the token list, not by the entropy heuristics", () => {
  // Worth pinning separately, because it is the case that motivated reading the
  // bytes as latin1 rather than as base64. Eight distinct byte values across 32
  // bytes clears the distinct-value floor exactly, so nothing but the token list
  // objects — and base64 of these bytes does not contain "changeme" at all.
  const distinct = new Set(PLACEHOLDER_BYTES).size;
  assert.equal(distinct, 8, "if this changes, the test below is measuring something else");
  assert.equal(
    weakSecretBytesReason(PLACEHOLDER_BYTES, 32)?.includes("changeme"),
    true,
    "a 32-byte ASCII default must be recognised as a default",
  );

  // The rejected alternative, driven so the choice is evidence rather than a
  // claim in a comment: reading the same bytes as base64 — which is what
  // src/auth/totp.ts passes — sees nothing wrong with them.
  assert.equal(
    weakSecretReason(Buffer.from(PLACEHOLDER_BYTES).toString("base64"), PLACEHOLDER_BYTES, 32),
    null,
    "base64 misses this, which is why weakSecretBytesReason reads the bytes as latin1",
  );
});

// ---------------------------------------------------------------------------
// Acceptance 2 — the server cannot be constructed with one
// ---------------------------------------------------------------------------

test("createServer refuses a secret weakSecretReason rejects", () => {
  // At CONSTRUCTION, not at first use. csrfKey refuses too, and on its own that
  // leaves a server that starts, answers /health, and fails on the first sign-in —
  // which reads as an authentication bug rather than as a misconfiguration.
  for (const secret of [new Uint8Array(32), new Uint8Array(32).fill(7), PLACEHOLDER_BYTES]) {
    assert.throws(
      () => createServer(depsWith(secret)),
      WeakCookieSecret,
      "a server must not exist with a cookie secret that cannot key a token",
    );
  }
});

test("createServer refuses a secret that is simply too short", () => {
  // The old check's job, kept under test so the entropy work cannot be mistaken
  // for a replacement of it.
  assert.throws(
    () => createServer(depsWith(randomBytes(16))),
    (error: unknown) => error instanceof WeakCookieSecret && /at least 32 are required/.test(error.message),
  );
  assert.throws(() => createServer(depsWith(new Uint8Array(0))), WeakCookieSecret);
});

test("createServer accepts a real secret", () => {
  // The other half of a security check: it has to let the correct thing through,
  // or it is an outage with a rationale.
  assert.doesNotThrow(() => createServer(depsWith(randomBytes(32))));
  assert.doesNotThrow(() => createServer(depsWith(randomBytes(64))));
});

test("a real secret still mints and varies its tokens", () => {
  const secret = randomBytes(32);
  const one = csrfTokenForSessionId(secret, "session-1");
  const two = csrfTokenForSessionId(secret, "session-2");

  assert.notEqual(one, two, "two sessions must not share a token");
  assert.equal(csrfTokenForSessionId(secret, "session-1"), one, "the same session must be stable");
  assert.notEqual(
    csrfTokenForSessionId(randomBytes(32), "session-1"),
    one,
    "two installations must not compute the same token — the point of the whole check",
  );
});

// ---------------------------------------------------------------------------
// The two paths agree
// ---------------------------------------------------------------------------

test("the byte-form check and the file-form check apply the same rules", () => {
  // Two entry points to one judgement. If they diverged, a secret refused at boot
  // could be accepted by a caller that passes bytes, which is exactly the gap this
  // task closed — one path checked, the other not.
  for (const secret of [new Uint8Array(32), new Uint8Array(32).fill(7), PLACEHOLDER_BYTES]) {
    const reason = weakSecretBytesReason(secret, 32);
    assert.notEqual(reason, null);
    assert.throws(() => assertUsableCookieSecret(secret), WeakCookieSecret);
  }
  assert.equal(weakSecretBytesReason(randomBytes(32), 32), null);
  assert.doesNotThrow(() => assertUsableCookieSecret(randomBytes(32)));
});
