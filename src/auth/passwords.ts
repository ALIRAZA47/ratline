/**
 * Password hashing (RL-M1-017, acceptance 1: "passwords are hashed with a
 * memory-hard function using vetted parameters").
 *
 * ## Why scrypt, and why from the standard library
 *
 * Brief §6.7: "Prefer the standard library", and every dependency added needs a
 * written justification. `node:crypto` ships scrypt (RFC 7914), which is
 * memory-hard by construction — the property acceptance 1 asks for, and the
 * property that makes a GPU or ASIC attacker pay for RAM rather than only for
 * arithmetic. Argon2id would be a defensible alternative and is not obviously
 * better here; it is a native dependency with a build step, on a control plane
 * that has none, to replace something the platform already provides and audits.
 *
 * ## The parameters, and what they cost
 *
 * N = 2^17, r = 8, p = 1, 32-byte key, 16-byte per-password salt.
 *
 *   - **Memory: 128 · N · r = 128 MiB per hash.** That is the whole point of
 *     choosing a memory-hard function, and it is also the number an operator
 *     has to plan for, so {@link memoryCostBytes} computes it rather than
 *     leaving it as arithmetic in a comment.
 *   - N = 2^17 is the current OWASP minimum for scrypt (with r = 8, p = 1).
 *     Going below a published floor needs an argument; meeting it needs none.
 *     For scale, RFC 7914 §2's 2009 interactive figure was N = 2^14, so this is
 *     eight times that.
 *   - r = 8 keeps the standard 1 KiB block. Lowering it lowers memory, which is
 *     the thing being bought.
 *   - p = 1 because parallelism buys CPU cost without buying memory cost, and
 *     memory is the axis an attacker finds expensive.
 *
 * The consequence, stated rather than hidden: **each concurrent hash holds
 * 128 MiB.** Node runs `scrypt` on the libuv threadpool, four wide by default,
 * so a burst of sign-ins can transiently reach roughly 512 MiB. On a control
 * plane the brief expects to run on a laptop (§6.1) that is a real
 * memory-exhaustion lever, and closing it is rate limiting on the
 * authentication endpoints — RL-M1-020, which lists this task as its dependency.
 * If that turns out to be insufficient, the answer is a bounded queue in front
 * of this module, not weaker parameters.
 *
 * `maxmem` has to be passed explicitly. OpenSSL's default ceiling is 32 MiB, so
 * anything at or above N = 2^15 fails with "memory limit exceeded" rather than
 * silently using weaker parameters — which is the right failure, but it means
 * the ceiling is derived from the parameters here instead of being a constant
 * that someone later forgets to raise.
 *
 * ## The stored form
 *
 *     scrypt$n=131072,r=8,p=1$<salt>$<key>        (both base64url)
 *
 * The parameters travel with the hash. That is what makes the choice above
 * revisable: raising N leaves every existing password verifiable against the
 * parameters it was created with, and {@link needsRehash} says which ones are
 * behind. A bare digest would make the numbers above permanent.
 *
 * ## Comparison
 *
 * {@link verifyPassword} compares with `secretEquals` — `timingSafeEqual`
 * underneath — and its body contains no `===` and no `!==` anywhere. That is
 * not style: `===` on the two encoded strings is functionally identical and
 * leaks the length of the matching prefix, and it is the one mutation a
 * functional test suite cannot see, because both versions pass every assertion
 * about which passwords are accepted. `test/security/session_fixation.test.ts`
 * pins the property structurally, since it cannot pin it behaviourally.
 */

import { randomBytes, scrypt } from "node:crypto";

import { secretEquals } from "../crypto/secrets.ts";

/** The knobs RFC 7914 defines, named as this codebase reads rather than as the paper writes. */
export type ScryptParameters = {
  /** RFC 7914's N: CPU/memory cost. Must be a power of two greater than one. */
  readonly cost: number;
  /** RFC 7914's r: block size, in 128-byte units. */
  readonly blockSize: number;
  /** RFC 7914's p: parallelisation. */
  readonly parallelization: number;
  /** Bytes of derived key. */
  readonly keyLength: number;
};

/** The parameters new hashes are created with. See the module header for why. */
export const PASSWORD_PARAMETERS: ScryptParameters = Object.freeze({
  cost: 131072,
  blockSize: 8,
  parallelization: 1,
  keyLength: 32,
});

/** Bytes of salt per password. Unique per password, never derived from anything. */
export const SALT_BYTES = 16;

const ALGORITHM = "scrypt";

/**
 * Memory one derivation holds, in bytes: 128 · N · r.
 *
 * Exported because it is capacity planning, not trivia — see the module header.
 */
export function memoryCostBytes(parameters: ScryptParameters = PASSWORD_PARAMETERS): number {
  return 128 * parameters.cost * parameters.blockSize;
}

/**
 * The ceiling handed to OpenSSL. Derived from the parameters, plus the p·128·r
 * working block and a megabyte of headroom, so raising the cost cannot leave a
 * stale constant behind to refuse it.
 */
function memoryCeilingBytes(parameters: ScryptParameters): number {
  return (
    memoryCostBytes(parameters) +
    128 * parameters.blockSize * parameters.parallelization +
    1024 * 1024
  );
}

function derive(input: string, salt: Uint8Array, parameters: ScryptParameters): Promise<Buffer> {
  // NFC first. The same password typed on two platforms can arrive as two
  // different byte sequences, and the person typing it has no way to know —
  // that is a lockout, not a security property.
  const normalised = input.normalize("NFC");
  return new Promise((resolve, reject) => {
    scrypt(
      normalised,
      salt,
      parameters.keyLength,
      {
        N: parameters.cost,
        r: parameters.blockSize,
        p: parameters.parallelization,
        maxmem: memoryCeilingBytes(parameters),
      },
      (error, key) => {
        if (error) reject(error);
        else resolve(key);
      },
    );
  });
}

type StoredHash = {
  readonly parameters: ScryptParameters;
  readonly salt: Buffer;
  readonly key: Buffer;
};

const STORED_SHAPE = /^scrypt\$n=(\d+),r=(\d+),p=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/;

/** Thrown when a stored hash cannot be read. That is corruption, not a failed sign-in. */
export class UnreadableHashError extends Error {
  constructor(reason: string) {
    // Never carries the value, only what is wrong with it.
    super(`the stored password hash is unreadable: ${reason}`);
    this.name = "UnreadableHashError";
  }
}

function positiveInteger(raw: string | undefined, field: string): number {
  const value = Number(raw ?? "");
  if (!Number.isInteger(value) || value < 1) {
    throw new UnreadableHashError(`${field} is not a positive integer`);
  }
  return value;
}

/**
 * Split a stored hash into the parameters it was made with and the bytes it
 * holds.
 *
 * Throws rather than returning null. An unreadable hash is not a wrong password
 * — it means something wrote a value this module did not produce — and quietly
 * turning it into "sign-in failed" would hide a data problem behind a login
 * form forever. Brief §9: no silent catch blocks.
 */
export function parseStoredHash(stored: string): StoredHash {
  const match = STORED_SHAPE.exec(stored);
  if (match === null) {
    throw new UnreadableHashError(`it is not in the ${ALGORITHM}$n=…,r=…,p=…$salt$key form`);
  }
  const parameters: ScryptParameters = {
    cost: positiveInteger(match[1], "n"),
    blockSize: positiveInteger(match[2], "r"),
    parallelization: positiveInteger(match[3], "p"),
    keyLength: Buffer.from(match[5] ?? "", "base64url").length,
  };
  if (parameters.keyLength < 16) {
    throw new UnreadableHashError("the derived key is shorter than 16 bytes");
  }
  return {
    parameters,
    salt: Buffer.from(match[4] ?? "", "base64url"),
    key: Buffer.from(match[5] ?? "", "base64url"),
  };
}

function encode(parameters: ScryptParameters, salt: Uint8Array, key: Uint8Array): string {
  const n = parameters.cost;
  const r = parameters.blockSize;
  const p = parameters.parallelization;
  return [
    `${ALGORITHM}$n=${n},r=${r},p=${p}`,
    Buffer.from(salt).toString("base64url"),
    Buffer.from(key).toString("base64url"),
  ].join("$");
}

/**
 * Hash a password for storage.
 *
 * The salt is 16 fresh bytes from the platform CSPRNG for every call, so two
 * people who choose the same password store different hashes and one cracked
 * hash is one account. There is no pepper and no installation-wide salt: those
 * would be another secret to hold, and C4's secret store already holds the
 * three that earn their place (ADR 0006).
 *
 * Refuses an empty password. That is the only policy this module has an opinion
 * about — length rules, breach-list checks and rotation belong with the
 * organization security policy, not with the hash function.
 */
export async function hashPassword(plain: string): Promise<string> {
  if (plain.length < 1) {
    throw new Error("a password cannot be empty; refusing to hash nothing and call it a credential");
  }
  const salt = randomBytes(SALT_BYTES);
  const key = await derive(plain, salt, PASSWORD_PARAMETERS);
  return encode(PASSWORD_PARAMETERS, salt, key);
}

/**
 * Does this presented password match the stored hash?
 *
 * `stored` is null for an account with no password — an SSO-only account, or
 * one that has never had one set (migration 2 allows the column to be null and
 * forbids the empty string, which would otherwise compare against a hash of "").
 * That case still performs a full derivation before returning false, so the
 * time taken says nothing about whether the account exists or has a password.
 * ADR 0003 is honest that response timing is not fully closed in v1; this is the
 * one place where closing it costs nothing, because the work has to happen
 * anyway on the path that succeeds.
 *
 * The comparison is `secretEquals`, and this function's body deliberately
 * contains no `===` and no `!==`: in a function whose entire job is to compare
 * a secret, a strict-equality operator has no legitimate use, so its absence is
 * a property a test can check. See the module header.
 */
export async function verifyPassword(stored: string | null, presented: string): Promise<boolean> {
  if (stored == null) {
    await derive(presented, randomBytes(SALT_BYTES), PASSWORD_PARAMETERS);
    return false;
  }
  const expected = parseStoredHash(stored);
  const actual = await derive(presented, expected.salt, expected.parameters);
  return secretEquals(actual, expected.key);
}

/**
 * Was this hash made with weaker parameters than the ones in use now?
 *
 * The upgrade path for the numbers in the module header: the only moment a
 * password exists in plaintext is the moment someone signs in with it, so that
 * is the only moment it can be re-hashed. A caller that ignores this is not
 * broken, it is merely stuck at whatever parameters it started with.
 */
export function needsRehash(stored: string): boolean {
  const { parameters } = parseStoredHash(stored);
  return (
    parameters.cost < PASSWORD_PARAMETERS.cost ||
    parameters.blockSize < PASSWORD_PARAMETERS.blockSize ||
    parameters.parallelization < PASSWORD_PARAMETERS.parallelization ||
    parameters.keyLength < PASSWORD_PARAMETERS.keyLength
  );
}
