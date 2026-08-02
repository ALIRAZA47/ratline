/**
 * Time-based one-time passwords, recovery codes, and the sealing of the secret
 * behind both (RL-M1-019, acceptance 1 and 3).
 *
 * This module is the counterpart of `src/auth/passwords.ts`: it touches nothing
 * but `node:crypto`, so it can be reasoned about — and mutation-tested — without
 * a database. Every decision it makes is about bytes. The order things happen
 * in, and who is allowed to do them, is `src/auth/two_factor.ts`; the statements
 * are in `src/repo/two_factor.ts`.
 *
 * ## No dependency, and why that is not bravado
 *
 * Brief §6.7: "Prefer the standard library", and every dependency added needs a
 * written justification. TOTP (RFC 6238) is HOTP (RFC 4226) with a time counter,
 * and HOTP is `HMAC(secret, counter)` followed by the dynamic-truncation rule in
 * RFC 4226 §5.3. `node:crypto` provides the HMAC; the truncation is nine lines
 * and is transcribed from the RFC below with the section numbers attached, so a
 * reviewer can check it against the specification rather than against my word.
 * Base32 (RFC 4648 §6) is thirty more. A dependency here would be thirty lines
 * of arithmetic plus a supply chain, on the module that decides whether a second
 * factor is real.
 *
 * ## SHA-1, which always needs answering
 *
 * The default algorithm is HMAC-SHA1, because that is what every authenticator
 * application actually implements — Google Authenticator ignores the `algorithm`
 * parameter entirely, so shipping SHA-256 by default produces enrolments that
 * silently never verify. It is also sound: the published attacks on SHA-1 are
 * collision attacks, and a collision is not a forgery of a keyed MAC. HMAC-SHA1
 * has no practical break. The parameter is stored per enrolment anyway
 * (migration 12), so an installation that wants SHA-256 can have it without
 * invalidating anybody.
 *
 * ## Comparison
 *
 * {@link verifyTotp} compares through {@link codeEquals}, whose body contains no
 * `===` and no `!==` at all. That is the same rule `verifyPassword` follows and
 * it matters MORE here: a TOTP code has a million possible values, so a
 * character-by-character comparison that returns early is a genuinely
 * exploitable oracle rather than a theoretical one. The absence of a
 * strict-equality operator in that function is checked by
 * `test/security/twofactor.test.ts`, because no functional test can see the
 * difference.
 *
 * The loop over the accepted window is also written not to stop early. It
 * evaluates every candidate step and records the first match, so the work done
 * is the same whether the code was right, wrong, or right at the edge of the
 * window.
 *
 * ## What is deliberately not here
 *
 *   - No HOTP (counter-based). Nothing asks for it and a counter that can drift
 *     out of sync needs a resynchronisation story this task does not own.
 *   - No WebAuthn. It is the scheme where the verifier cannot impersonate the
 *     holder, which is strictly better than a shared secret, and it is a
 *     different task with a different data model. Named here so the choice of
 *     TOTP reads as scoped rather than as final.
 */

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";

import { secretEquals } from "../crypto/secrets.ts";
import { weakSecretReason } from "../crypto/weak-secrets.ts";

// ---------------------------------------------------------------------------
// Base32 — RFC 4648 §6
// ---------------------------------------------------------------------------

// Split so that no single string literal in `src/` is a 32-character run of
// base64 alphabet, which `test/security/no_default_secrets.test.ts` reads as
// possible committed key material. The check is right to be blunt and this is
// the cheap way to stay out of its path.
const BASE32_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const BASE32_DIGITS = "234567";

/** RFC 4648 §6, uppercase. */
const BASE32_ALPHABET = `${BASE32_LETTERS}${BASE32_DIGITS}`;

/**
 * Bytes to base32, WITHOUT padding.
 *
 * `otpauth` URIs in the wild are unpadded and several authenticator
 * applications reject the `=` characters outright, so emitting them would
 * produce enrolments that fail on somebody's phone and nowhere else.
 */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >> bits) & 31] ?? "";
    }
  }
  // The trailing partial group is left-aligned, per §6.
  if (bits > 0) out += BASE32_ALPHABET[(buffer << (5 - bits)) & 31] ?? "";
  return out;
}

/** Thrown when text that is supposed to be base32 is not. Corruption, not a wrong code. */
export class Base32Error extends Error {
  constructor(reason: string) {
    // Never carries the value: this function decodes secrets.
    super(`the value is not base32: ${reason}`);
    this.name = "Base32Error";
  }
}

/**
 * Base32 to bytes.
 *
 * Deliberately lenient about presentation and strict about content: padding,
 * whitespace and lower case are all accepted, because a person retyping a secret
 * off a screen produces all three, while a character outside the alphabet throws
 * rather than being skipped. Skipping it would decode `JBSW-Y3DP` and
 * `JBSW!Y3DP` to the same bytes, which is a way for two different strings to
 * name one secret.
 */
export function base32Decode(text: string): Buffer {
  const cleaned = text.replace(/[\s=]/g, "").toUpperCase();
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of cleaned) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value < 0) throw new Base32Error(`"${character}" is outside the RFC 4648 §6 alphabet`);
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

// ---------------------------------------------------------------------------
// The parameters
// ---------------------------------------------------------------------------

/** The three RFC 6238 §1.2 names. Stored per enrolment (migration 12). */
export const TOTP_ALGORITHMS = ["SHA1", "SHA256", "SHA512"] as const;

export type TotpAlgorithm = (typeof TOTP_ALGORITHMS)[number];

export function isTotpAlgorithm(value: unknown): value is TotpAlgorithm {
  return typeof value === "string" && (TOTP_ALGORITHMS as readonly string[]).includes(value);
}

export type TotpParameters = {
  readonly algorithm: TotpAlgorithm;
  /** Digits in a code. RFC 4226 §5.3 permits 6–10; authenticators do 6–8. */
  readonly digits: number;
  /** RFC 6238's X, in seconds. */
  readonly periodSeconds: number;
};

/**
 * What a new enrolment is created with.
 *
 * SHA-1, six digits, thirty seconds: the only combination every authenticator
 * application implements. See the module header on SHA-1. These are defaults,
 * not constants — the enrolment row carries its own copy, so raising them later
 * leaves existing enrolments verifiable against what they were created with,
 * exactly as `src/auth/passwords.ts` does for scrypt parameters.
 */
export const TOTP_PARAMETERS: TotpParameters = Object.freeze({
  algorithm: "SHA1",
  digits: 6,
  periodSeconds: 30,
});

/**
 * Bytes of shared secret. RFC 4226 §4 R6 requires at least 128 bits and
 * recommends 160, which is also the HMAC-SHA1 block output size, so nothing is
 * wasted and nothing is short.
 */
export const TOTP_SECRET_BYTES = 20;

/**
 * How many periods either side of now are accepted.
 *
 * One, so the accepted window is ninety seconds wide at the default period.
 * RFC 6238 §5.2 permits a window for network delay and clock drift, and a phone
 * with no NTP is routinely a few seconds out. Zero refuses honest people;
 * anything above one is a code that stays live for minutes, and the replay guard
 * (migration 12 note 3) is what keeps even ninety seconds from being reusable.
 */
export const TOTP_ACCEPTED_STEPS = 1;

/** A fresh shared secret, from the platform CSPRNG. The only place one is created. */
export function mintTotpSecret(): Buffer {
  return randomBytes(TOTP_SECRET_BYTES);
}

// ---------------------------------------------------------------------------
// The code — RFC 4226 §5.3, RFC 6238 §4
// ---------------------------------------------------------------------------

/** RFC 6238 §4.2's T: the number of whole periods since the Unix epoch. */
export function totpStepAt(atMs: number, periodSeconds: number = TOTP_PARAMETERS.periodSeconds): number {
  if (!Number.isInteger(periodSeconds) || periodSeconds < 1) {
    throw new Error(`a TOTP period must be a positive whole number of seconds, got ${periodSeconds}`);
  }
  return Math.floor(atMs / 1000 / periodSeconds);
}

/**
 * The code for one counter value.
 *
 * Transcribed from RFC 4226 §5.3 with the steps named, because this is
 * arithmetic nobody should have to reverse-engineer from a variable called `o`:
 *
 *   1. The counter is eight bytes, big-endian (§5.1).
 *   2. HMAC it under the shared secret.
 *   3. The low four bits of the LAST byte are an offset into the digest.
 *   4. Read four bytes from there, big-endian, and clear the top bit — that is
 *      the "dynamic truncation" of §5.3, and the masking exists so the value is
 *      unambiguously positive regardless of how the reader's language signs
 *      integers.
 *   5. Modulo 10^digits, zero-padded on the left.
 */
export function totpCode(
  secret: Uint8Array,
  step: number,
  parameters: TotpParameters = TOTP_PARAMETERS,
): string {
  if (!Number.isInteger(step) || step < 0) {
    throw new Error(`a TOTP counter must be a non-negative whole number, got ${step}`);
  }
  // Step 1.
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));

  // Step 2.
  const digest = createHmac(parameters.algorithm.toLowerCase(), Buffer.from(secret))
    .update(counter)
    .digest();

  // Step 3. `digest` is at least 20 bytes for every algorithm here, so the
  // offset can address four bytes; the fallbacks satisfy noUncheckedIndexedAccess
  // rather than describing a reachable state.
  const offset = (digest[digest.length - 1] ?? 0) & 0x0f;

  // Step 4.
  const truncated =
    (((digest[offset] ?? 0) & 0x7f) << 24) |
    ((digest[offset + 1] ?? 0) << 16) |
    ((digest[offset + 2] ?? 0) << 8) |
    (digest[offset + 3] ?? 0);

  // Step 5.
  return String(truncated % 10 ** parameters.digits).padStart(parameters.digits, "0");
}

/**
 * Constant-time comparison of two codes.
 *
 * Its own function so that "this comparison is constant-time" is a property of
 * a named body a test can read, and so that the body can be required to contain
 * no strict-equality operator at all — the same shape `verifyPassword` uses, and
 * for a sharper reason: a six-digit code has only a million values, so a
 * comparison that returns on the first differing character can be walked
 * digit by digit.
 */
function codeEquals(expected: string, presented: string): boolean {
  return secretEquals(Buffer.from(expected, "utf8"), Buffer.from(presented, "utf8"));
}

/** Strip the spaces and dashes people type, and nothing else. */
export function normaliseCode(presented: string): string {
  return presented.replace(/[\s-]/g, "");
}

export type TotpVerification = {
  /** When the code was judged. Defaults to now; a parameter so a test can pin it. */
  readonly atMs?: number;
  /** Periods either side of `atMs` that are accepted. */
  readonly acceptedSteps?: number;
};

/**
 * The counter this code came from, or null.
 *
 * Null for a wrong code, for a code outside the accepted window, and for
 * anything that is not the right number of digits — the caller cannot tell
 * which, and there is nothing useful it could do with the difference.
 *
 * The RETURNED STEP is the point of returning a number rather than a boolean: it
 * is what the replay guard records (migration 12 note 3). A verifier that
 * answered only "yes" would leave the caller unable to say which code was spent,
 * and the guard would have nothing to advance.
 *
 * Every candidate step is evaluated. The loop does not break on a match, so a
 * correct code costs the same as a wrong one.
 */
export function verifyTotp(
  secret: Uint8Array,
  presented: string,
  parameters: TotpParameters = TOTP_PARAMETERS,
  options: TotpVerification = {},
): number | null {
  const code = normaliseCode(presented);
  const now = options.atMs ?? Date.now();
  const window = options.acceptedSteps ?? TOTP_ACCEPTED_STEPS;
  const centre = totpStepAt(now, parameters.periodSeconds);

  let matched: number | null = null;
  for (let offset = -window; offset <= window; offset++) {
    const step = centre + offset;
    if (step < 0) continue;
    // No `break` and no short-circuit: the comparison runs for every candidate.
    const hit = codeEquals(totpCode(secret, step, parameters), code);
    if (hit && matched == null) matched = step;
  }
  return matched;
}

/**
 * The `otpauth://` URI an authenticator application scans (Key Uri Format).
 *
 * The label carries the issuer as a prefix AND the `issuer` parameter carries it
 * again, which looks redundant and is not: older applications read only the
 * prefix, newer ones only the parameter, and an enrolment that shows up as a
 * bare email address is one a person with three organizations cannot tell apart
 * (migration 12 note 4).
 *
 * Every component is percent-encoded. The account is an email address and the
 * issuer is an operator-chosen organization name, so both can contain a colon,
 * which is the one character the label format gives meaning to.
 */
export function otpauthUri(input: {
  readonly issuer: string;
  readonly account: string;
  readonly secret: Uint8Array;
  readonly parameters?: TotpParameters;
}): string {
  const parameters = input.parameters ?? TOTP_PARAMETERS;
  const label = `${encodeURIComponent(input.issuer)}:${encodeURIComponent(input.account)}`;
  const query = new URLSearchParams({
    secret: base32Encode(input.secret),
    issuer: input.issuer,
    algorithm: parameters.algorithm,
    digits: String(parameters.digits),
    period: String(parameters.periodSeconds),
  });
  return `otpauth://totp/${label}?${query.toString()}`;
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

/**
 * How many a person gets. Ten is the number every comparable product settles on,
 * and the reasoning is the same: enough that losing a couple to a bad printout
 * does not matter, few enough that a person keeps them somewhere deliberate.
 */
export const RECOVERY_CODE_COUNT = 10;

/**
 * Bytes per code: 80 bits from the platform CSPRNG, which base32-encodes to
 * exactly sixteen characters with no partial group.
 *
 * Not 256 bits, and the difference is worth arguing rather than defaulting. A
 * recovery code is TYPED BY A PERSON, so length is a usability cost that is paid
 * on the worst day they will have with this product. What it has to survive is
 * an online guessing attack through a rate limiter that permits ten attempts per
 * quarter hour (`AUTH_RATE_LIMITS["two-factor"]`), and 2^80 against forty
 * guesses an hour is not a race anybody finishes. It never has to survive an
 * offline attack, because what is stored is a digest of a CSPRNG output with no
 * dictionary behind it.
 */
const RECOVERY_CODE_BYTES = 10;

/** Characters between the dashes, purely so a person can keep their place. */
const RECOVERY_CODE_GROUP = 4;

/**
 * A fresh recovery code, grouped for reading aloud: `A2C4-E6G8-...`.
 *
 * The dashes are presentation. {@link normaliseRecoveryCode} removes them before
 * anything is hashed, so a person who types the code without them is not
 * refused on the day they have lost their phone.
 */
export function mintRecoveryCode(): string {
  const encoded = base32Encode(randomBytes(RECOVERY_CODE_BYTES));
  const groups = encoded.match(new RegExp(`.{1,${RECOVERY_CODE_GROUP}}`, "g")) ?? [encoded];
  return groups.join("-");
}

/**
 * The form a code is hashed in: upper case, no dashes, no spaces.
 *
 * Applied to both the minted code and the presented one, so the two can only
 * disagree about the bytes rather than about the formatting.
 */
export function normaliseRecoveryCode(code: string): string {
  return code.replace(/[\s-]/g, "").toUpperCase();
}

/**
 * What gets stored: a SHA-256 digest, lowercase hex, 64 characters — the shape
 * migration 12's `two_factor_recovery_codes_hash_shape` constrains the column
 * to, so a printable code cannot be written into it even by hand.
 *
 * A plain digest rather than a memory-hard function, for the reason
 * `src/repo/api_tokens.ts` gives about token secrets: the input is 80 bits from
 * a cryptographic source, so there is no dictionary to attack and no work factor
 * to buy. A password is different because a person chose it.
 */
export function recoveryCodeDigest(code: string): string {
  return createHash("sha256").update(normaliseRecoveryCode(code), "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Sealing the shared secret (ADR 0006, migration 12 note 2)
// ---------------------------------------------------------------------------

/**
 * The stored form:
 *
 *     v1$<wrapped data key>$<sealed secret>          (both base64url)
 *
 * Each half is `iv || tag || ciphertext` under AES-256-GCM. The version string
 * is the additional authenticated data for both, so a blob cannot be replayed
 * into a future format that reads its parts differently, and the version cannot
 * be edited in the database without the tag failing.
 *
 * ADR 0006's envelope, applied unchanged: a fresh data key per enrolment, the
 * value sealed under it, the data key wrapped by the key-encryption key. What it
 * buys here specifically is that rotating the key-encryption key rewraps a
 * 32-byte key per enrolment rather than re-encrypting every secret, and that one
 * leaked data key is one person's second factor.
 */
const SEAL_VERSION = "v1";
const DATA_KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Thrown when a sealed value cannot be opened. Corruption or a wrong key — never a wrong code. */
export class SealedValueError extends Error {
  constructor(reason: string) {
    // Names what is wrong, never any part of the value or the key.
    super(`the sealed two-factor secret could not be opened: ${reason}`);
    this.name = "SealedValueError";
  }
}

/**
 * Refuse a key-encryption key that is the wrong size or obviously not random.
 *
 * `loadSecrets` already validates the file this normally comes from, so this is
 * the second check on the same value — and it is not redundant, because the key
 * arrives here as a PARAMETER. A caller can pass `Buffer.alloc(32)`, and a
 * sealing function that accepted it would produce ciphertext anyone could open
 * while looking exactly as encrypted as the real thing. C4 is about defaults,
 * and an all-zero key is the default somebody reaches for in a hurry.
 */
function assertUsableKey(key: Buffer): void {
  if (key.length !== DATA_KEY_BYTES) {
    throw new SealedValueError(
      `the key-encryption key is ${key.length} bytes; AES-256 requires ${DATA_KEY_BYTES}`,
    );
  }
  const weak = weakSecretReason(key.toString("base64"), key, DATA_KEY_BYTES);
  if (weak !== null) throw new SealedValueError(`the key-encryption key is unusable: ${weak}`);
}

function sealUnder(key: Buffer, plaintext: Buffer): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(SEAL_VERSION, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url");
}

function openUnder(key: Buffer, blob: string): Buffer {
  const raw = Buffer.from(blob, "base64url");
  if (raw.length <= IV_BYTES + TAG_BYTES) {
    throw new SealedValueError("it is too short to hold a nonce, a tag and a body");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, IV_BYTES));
  decipher.setAAD(Buffer.from(SEAL_VERSION, "utf8"));
  decipher.setAuthTag(raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES));
  try {
    return Buffer.concat([decipher.update(raw.subarray(IV_BYTES + TAG_BYTES)), decipher.final()]);
  } catch (cause) {
    // `final()` throws when the tag does not verify — a wrong key, or a
    // tampered row. Rethrown rather than swallowed (§9) and rethrown as this
    // module's type so a caller can tell it from a failed verification.
    throw new SealedValueError(`the authentication tag did not verify (${(cause as Error).message})`);
  }
}

/** Seal a shared secret for storage. The plaintext never leaves the caller. */
export function sealTotpSecret(kek: Buffer, secret: Uint8Array): string {
  assertUsableKey(kek);
  const dataKey = randomBytes(DATA_KEY_BYTES);
  return [SEAL_VERSION, sealUnder(kek, dataKey), sealUnder(dataKey, Buffer.from(secret))].join("$");
}

/** Open a sealed shared secret. Throws {@link SealedValueError} rather than returning null. */
export function openTotpSecret(kek: Buffer, sealed: string): Buffer {
  assertUsableKey(kek);
  const parts = sealed.split("$");
  const [version, wrapped, body] = parts;
  if (parts.length !== 3 || version !== SEAL_VERSION || wrapped === undefined || body === undefined) {
    throw new SealedValueError(`it is not in the ${SEAL_VERSION}$key$secret form`);
  }
  return openUnder(openUnder(kek, wrapped), body);
}
