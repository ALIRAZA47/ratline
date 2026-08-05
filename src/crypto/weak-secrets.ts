/**
 * Known-default and low-entropy secret detection (C4, RL-M1-022).
 *
 * CloudPanel's CVE-2023-35885 was exploited in the wild because a shipped
 * default signing key let anyone forge a cookie. The defence is two-sided:
 * never ship a default, and refuse to start if one is present anyway — because
 * the dangerous case is not the value we ship, it is the value an operator
 * copies out of a tutorial.
 *
 * ---------------------------------------------------------------------------
 * This file is the ONLY place these tokens may appear in `src/`.
 * `test/security/no_default_secrets.test.ts` scans the tree for them and
 * excludes exactly this module, asserting that the exclusion list is a single
 * file. If you add placeholder strings elsewhere, that test will fail, which is
 * the intended behaviour.
 * ---------------------------------------------------------------------------
 */

import { Buffer } from "node:buffer";

/**
 * Tokens that appear in real shipped defaults, tutorials and .env.example
 * files. Compared after normalisation, so `CHANGE_ME`, `change-me` and
 * `ChangeMe` are all one entry.
 */
export const KNOWN_DEFAULT_TOKENS: readonly string[] = [
  "changeme",
  "changethis",
  "replaceme",
  "yoursecret",
  "yoursecretkey",
  "yourkeyhere",
  "supersecret",
  "secretkey",
  "mysecret",
  "topsecret",
  "defaultsecret",
  "defaultkey",
  "examplekey",
  "samplekey",
  "testsecret",
  "devsecret",
  "placeholder",
  "insecure",
  "notsecure",
  "password",
  "passw0rd",
  "letmein",
  "admin",
  "adminadmin",
  "root",
  "hunter2",
  "keyboardcat",
  "s3cr3t",
  "deadbeef",
  "0123456789",
  "abcdefgh",
  "qwerty",
];

/** Lowercase and strip everything that is not a letter or digit. */
function normalise(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Number of distinct byte values, as a cheap proxy for entropy. */
function distinctBytes(bytes: Uint8Array): number {
  return new Set(bytes).size;
}

/** True when the bytes ascend or descend by a constant step (0x00,0x01,0x02…). */
function isArithmeticSequence(bytes: Uint8Array): boolean {
  if (bytes.length < 4) return false;
  const first = bytes[0];
  const second = bytes[1];
  if (first === undefined || second === undefined) return false;
  const step = second - first;
  for (let i = 1; i < bytes.length; i++) {
    const prev = bytes[i - 1];
    const cur = bytes[i];
    if (prev === undefined || cur === undefined) return false;
    if (cur - prev !== step) return false;
  }
  return true;
}

/**
 * Returns a human-readable reason when the secret is unacceptable, or null when
 * it passes. The reason is shown to the operator, so it says what to do.
 *
 * @param raw     the secret as stored on disk (text form)
 * @param decoded the decoded bytes the secret actually contributes
 * @param minBytes the minimum acceptable decoded length
 */
export function weakSecretReason(
  raw: string,
  decoded: Uint8Array,
  minBytes: number,
): string | null {
  const trimmed = raw.trim();

  if (trimmed === "") return "the file is empty";

  const flat = normalise(trimmed);
  for (const token of KNOWN_DEFAULT_TOKENS) {
    if (flat.includes(token)) {
      return `it contains the well-known placeholder "${token}" — this is a shipped-default secret, not a real one`;
    }
  }

  if (decoded.length < minBytes) {
    return `it decodes to ${decoded.length} bytes; at least ${minBytes} are required`;
  }

  if (distinctBytes(decoded) === 1) {
    return "every byte is identical, so it carries no entropy";
  }

  if (isArithmeticSequence(decoded)) {
    return "its bytes form a counting sequence, so it carries no entropy";
  }

  // 32 random bytes have ~28 distinct values on average; fewer than a quarter
  // distinct means something generated it badly, not a CSPRNG.
  const minDistinct = Math.max(4, Math.floor(decoded.length / 4));
  if (decoded.length >= 16 && distinctBytes(decoded) < minDistinct) {
    return `it has only ${distinctBytes(decoded)} distinct byte values across ${decoded.length} bytes, which no random generator produces`;
  }

  return null;
}

/**
 * The same judgement for a secret that arrives as bytes rather than as a file
 * (C4, RL-M1-054).
 *
 * ## Why this exists
 *
 * `weakSecretReason` was only ever reached through `src/crypto/secrets.ts`, which
 * loads from disk. `ServerDeps.cookieSecret` is a `Uint8Array` handed straight to
 * `createServer`, so nothing checked it: `src/api/csrf.ts` validated LENGTH alone,
 * and `csrfTokenForSessionId(new Uint8Array(32), …)` returned a token happily.
 * csrf.ts names the exact outcome two lines above that check — "a token every
 * installation on earth could compute" — and then guarded only length.
 *
 * ## Why the bytes are read as latin1
 *
 * The placeholder scan wants TEXT, and there is no file here to read. latin1 is
 * the decoding that maps every byte to exactly one character, so nothing is lost
 * to replacement characters, and it catches the case that matters: a 32-byte
 * secret which is really the ASCII of "changeme-changeme-changeme-chang". That has
 * eight distinct byte values across 32 bytes and therefore passes every entropy
 * heuristic above — the token list is the only thing that sees it.
 *
 * Base64 was the other candidate, and is what `src/auth/totp.ts` passes. It is
 * worse on both counts: it does NOT contain "changeme" for the secret above, so it
 * misses the case this is for, and it produces more alphanumeric characters per
 * byte, so it is likelier to spell a token by accident.
 *
 * ## The false positive, stated rather than hidden
 *
 * A genuinely random secret could contain "root" or "admin" once the
 * non-alphanumeric bytes are stripped. Roughly eight alphanumeric characters
 * survive from 32 random bytes, so the chance is on the order of one in a hundred
 * thousand installations. That is accepted, because the failure is loud, says what
 * to do, and is fixed by generating a new secret — whereas the miss it prevents is
 * silent and permanent.
 */
export function weakSecretBytesReason(bytes: Uint8Array, minBytes: number): string | null {
  return weakSecretReason(Buffer.from(bytes).toString("latin1"), bytes, minBytes);
}
