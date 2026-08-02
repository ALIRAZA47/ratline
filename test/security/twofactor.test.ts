/**
 * Two-factor authentication and the organization policy (RL-M1-019).
 *
 * Brief §6.3: "SSO via OIDC/SAML and enforced 2FA as org-level policies."
 * The three acceptance criteria map onto tests like this:
 *
 *   1. Time-based one-time passwords enrol, verify and produce recovery codes
 *                  -> "enrolling hands back a secret, a URI and ten recovery
 *                      codes, and a code from that secret signs you in"
 *                     plus the RFC 6238 and RFC 4226 vectors, which are what
 *                     say the arithmetic is right rather than merely
 *                     self-consistent
 *   2. An organization can require it, and non-compliant members are forced
 *      into enrolment at next login
 *                  -> "an organization that requires a second factor hands a
 *                      member who has not enrolled no session at all",
 *                     "the forced enrolment finishes the sign-in"
 *   3. Recovery codes are single use and their consumption is audited
 *                  -> "a recovery code works once and never again",
 *                     "spending a recovery code is audited, and no entry holds
 *                      the code"
 *
 * Everything else here exists because an implementation can pass all three and
 * still be worthless: one that lets a stolen password replace somebody's
 * authenticator, one that accepts the same code twice inside its window, one
 * that stores the shared secret where a database backup carries it, or one whose
 * challenge can be redeemed from another tenant.
 *
 * **Every assertion runs as `ratline_app`.** The migration connection is the
 * superuser `initdb` created, and a superuser bypasses row-level security
 * unconditionally — the same assertions written on it would pass without
 * exercising a single policy. Repository and auth calls go through a pool
 * pointed at `ratline_app` (`usingScratch`); raw-SQL assertions go through
 * `asApplicationRole`. Writes on the migration connection are fixture setup,
 * never the thing under test.
 *
 * **The clock is a parameter, not the wall.** Every code is judged at an
 * explicit instant, so a test cannot pass or fail because it happened to run
 * across a period boundary. That matters more here than usual: the replay guard
 * is about counters, and a test whose counter moved on its own would be testing
 * the passage of time.
 *
 * **The calls use a service-identity context**, for the reason
 * `test/security/session_fixation.test.ts` and
 * `test/security/rate_limit_auth.test.ts` already give: a sign-in attempt
 * happens before there is anybody to attribute it to, C6 already says automation
 * acts as a named service identity, and this is the open seam ADR 0014 records
 * rather than a new one.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import { NotPermittedError } from "../../src/authz/can.ts";
import {
  contextForRequest,
  contextForServiceIdentity,
  type AuthzContext,
} from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { challengeTokenDigest, CHALLENGE_TOKEN_PREFIX } from "../../src/auth/model.ts";
import { hashPassword } from "../../src/auth/passwords.ts";
import { signIn, validateSession, type SignInResult } from "../../src/auth/sessions.ts";
import { AUTH_PATHS, AUTH_RATE_LIMITS } from "../../src/auth/rate_limit.ts";
import {
  base32Decode,
  base32Encode,
  mintRecoveryCode,
  mintTotpSecret,
  normaliseRecoveryCode,
  openTotpSecret,
  otpauthUri,
  recoveryCodeDigest,
  sealTotpSecret,
  totpCode,
  totpStepAt,
  verifyTotp,
  RECOVERY_CODE_COUNT,
  SealedValueError,
  TOTP_PARAMETERS,
  type TotpAlgorithm,
} from "../../src/auth/totp.ts";
import {
  beginEnrolment,
  confirmEnrolment,
  demandFor,
  secondFactorDemand,
  setTwoFactorPolicy,
  twoFactorPolicy,
  verifySecondFactor,
  CHALLENGE_LIFETIME_MS,
  type FactorSubject,
} from "../../src/auth/two_factor.ts";
import { listAudit } from "../../src/repo/audit.ts";
import { readSecondFactorRequirement, redeemChallenge } from "../../src/repo/two_factor.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  setTenant,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/** The fixture password. Nothing in `src/` may contain one; a test may. */
const PASSPHRASE = "correct horse battery staple";

/**
 * The key-encryption key the tests seal with.
 *
 * Real bytes from the platform CSPRNG rather than a constant, because
 * `sealTotpSecret` refuses a key that looks generated badly — a fixture of
 * `Buffer.alloc(32)` would be refused, which is the behaviour under test in
 * "a sealing key that is not random is refused".
 */
const SEALING_KEY = randomBytes(32);

/**
 * Hashing costs 128 MiB and a couple of hundred milliseconds by design, so the
 * fixture hash is computed once for the whole file rather than once per test.
 */
let fixture: Promise<string> | null = null;
function fixtureHash(): Promise<string> {
  fixture ??= hashPassword(PASSPHRASE);
  return fixture;
}

/** A fixed instant well clear of any boundary, advanced explicitly by the tests. */
const T0 = Date.UTC(2026, 7, 2, 12, 0, 0);
const PERIOD_MS = TOTP_PARAMETERS.periodSeconds * 1000;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Tenant = {
  readonly orgId: string;
  readonly ownerId: string;
  /** A named service identity for the pre-authentication path. See the header. */
  readonly signInIdentityId: string;
};

async function seedTenant(client: Client, slug: string): Promise<Tenant> {
  const { orgId, userId } = await seedOrganization(client, slug);
  const identity = await client.query<{ id: string }>(
    "insert into service_identities (org_id, name) values ($1, 'sign-in') returning id",
    [orgId],
  );
  return { orgId, ownerId: userId, signInIdentityId: identity.rows[0]?.id ?? "" };
}

/** A member with a password. Returns the user id. */
async function addMember(
  client: Client,
  orgId: string,
  email: string,
  storedHash: string | null = null,
): Promise<string> {
  const existing = await client.query<{ id: string }>("select id from users where email = $1", [email]);
  const userId =
    existing.rows[0]?.id ??
    (
      await client.query<{ id: string }>(
        "insert into users (email, name, password_hash) values ($1, 'Person', $2) returning id",
        [email, storedHash],
      )
    ).rows[0]?.id ??
    "";
  await client.query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, userId]);
  return userId;
}

async function grantRole(client: Client, orgId: string, userId: string, roleKey: string): Promise<void> {
  await client.query(
    `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
     values ($1, 'user', $2, $3, 'organization')`,
    [orgId, userId, roleKey],
  );
}

const requestCtx = (orgId: string, userId: string): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `rl-${randomUUID()}` });

const signInCtx = (tenant: Tenant): AuthzContext =>
  contextForServiceIdentity({
    orgId: tenant.orgId,
    serviceIdentityId: tenant.signInIdentityId,
    name: "sign-in",
    requestId: `rl-${randomUUID()}`,
  });

/**
 * Point the repository pool at a scratch database as `ratline_app` — the
 * unprivileged, NOBYPASSRLS role the application connects as in production.
 *
 * The `asApplicationRole` call first is what grants that role LOGIN, once per
 * process; without it this file would depend on some earlier test having done
 * it, which is the ordering dependency that becomes a mysterious CI failure on a
 * fresh cluster.
 */
async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
  await asApplicationRole(database, () => Promise.resolve());
  const url = new URL(DATABASE_URL);
  url.pathname = `/${database}`;
  url.username = "ratline_app";
  url.password = "";
  connect({ connectionString: url.toString() });
  try {
    await fn();
  } finally {
    await disconnect();
  }
}

/** Narrow a sign-in to its success branch, failing the test with what it got. */
function signedIn(result: SignInResult): Extract<SignInResult, { ok: true }> {
  if (!result.ok) {
    assert.fail(
      `expected a session, got refusal "${String(result.refusal)}" / secondFactor ` +
        `${result.secondFactor === null ? "null" : "issued"}`,
    );
  }
  return result;
}

/** Narrow a sign-in to the "a second factor is owed" branch. */
function challenged(result: SignInResult): { token: string; enrolmentRequired: boolean } {
  if (result.ok) assert.fail("expected a second-factor challenge, got a session");
  if (result.secondFactor === null) {
    assert.fail(`expected a second-factor challenge, got refusal "${String(result.refusal)}"`);
  }
  return {
    token: result.secondFactor.token,
    enrolmentRequired: result.secondFactor.enrolmentRequired,
  };
}

type Enrolled = { readonly secret: Buffer; readonly codes: readonly string[] };

/** Enrol the acting user from their own settings, at a fixed instant. */
async function enrolSelf(ctx: AuthzContext, atMs: number): Promise<Enrolled> {
  const subject: FactorSubject = { kind: "self" };
  const begun = await beginEnrolment(ctx, SEALING_KEY, subject);
  assert.ok(begun.ok, `enrolment should start: ${begun.ok ? "" : begun.failure}`);
  const secret = base32Decode(begun.secret);
  const done = await confirmEnrolment(ctx, SEALING_KEY, {
    subject,
    presented: totpCode(secret, totpStepAt(atMs, begun.parameters.periodSeconds), begun.parameters),
    atMs,
  });
  assert.ok(done.ok, `enrolment should confirm: ${done.ok ? "" : done.failure}`);
  return { secret, codes: done.recoveryCodes };
}

const codeAt = (secret: Uint8Array, atMs: number): string =>
  totpCode(secret, totpStepAt(atMs, TOTP_PARAMETERS.periodSeconds), TOTP_PARAMETERS);

// ---------------------------------------------------------------------------
// The arithmetic — vectors from the RFCs, not from this implementation
// ---------------------------------------------------------------------------

test("base32 matches the RFC 4648 §10 vectors, in both directions", () => {
  // A base32 encoder that is merely self-consistent produces enrolments that no
  // authenticator application can read, and the failure shows up on somebody's
  // phone rather than here.
  const vectors: readonly (readonly [string, string])[] = [
    ["", ""],
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ];
  for (const [plain, encoded] of vectors) {
    assert.equal(base32Encode(Buffer.from(plain, "utf8")), encoded, `encoding "${plain}"`);
    assert.equal(base32Decode(encoded).toString("utf8"), plain, `decoding "${encoded}"`);
  }

  // Presentation is forgiven; content is not. A person retyping a secret off a
  // screen produces all three of these.
  assert.equal(base32Decode("mzxw 6ytb-oi".replace(/-/g, "")).toString("utf8"), "foobar");
  assert.equal(base32Decode("MZXW6YTBOI======").toString("utf8"), "foobar");
  assert.throws(() => base32Decode("MZXW6YTB0I"), /outside the RFC 4648/, "0 is not in the alphabet");
});

test("HOTP matches the RFC 4226 Appendix D vectors", () => {
  // The truncation rule is nine lines of bit manipulation, and every one of them
  // is a place to be subtly wrong in a way that still produces six plausible
  // digits. These vectors are what say it is not.
  const secret = Buffer.from("12345678901234567890", "utf8");
  const expected = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  ];
  for (const [counter, code] of expected.entries()) {
    assert.equal(totpCode(secret, counter, TOTP_PARAMETERS), code, `counter ${counter}`);
  }
});

test("TOTP matches the RFC 6238 Appendix B vectors, for all three algorithms", () => {
  // The RFC's seeds are the ASCII digits repeated to the algorithm's key length,
  // and its table is in eight digits, which exercises the modulus as well as the
  // truncation.
  const seeds: Readonly<Record<TotpAlgorithm, string>> = {
    SHA1: "12345678901234567890",
    SHA256: "12345678901234567890123456789012",
    SHA512: "1234567890123456789012345678901234567890123456789012345678901234",
  };
  const vectors: readonly (readonly [number, string, string, string])[] = [
    [59, "94287082", "46119246", "90693936"],
    [1111111109, "07081804", "68084774", "25091201"],
    [1111111111, "14050471", "67062674", "99943326"],
    [1234567890, "89005924", "91819424", "93441116"],
    [2000000000, "69279037", "90698825", "38618901"],
    [20000000000, "65353130", "77737706", "47863826"],
  ];
  for (const [seconds, sha1, sha256, sha512] of vectors) {
    const step = totpStepAt(seconds * 1000, 30);
    for (const [algorithm, code] of [
      ["SHA1", sha1],
      ["SHA256", sha256],
      ["SHA512", sha512],
    ] as const) {
      assert.equal(
        totpCode(Buffer.from(seeds[algorithm], "utf8"), step, {
          algorithm,
          digits: 8,
          periodSeconds: 30,
        }),
        code,
        `${algorithm} at T=${seconds}`,
      );
    }
  }
});

test("verification accepts one period either side and nothing further", () => {
  // RFC 6238 §5.2 permits a window for clock drift. Zero refuses honest people
  // with a phone that is four seconds out; a wide one leaves a shoulder-surfed
  // code live for minutes.
  const secret = mintTotpSecret();
  const step = totpStepAt(T0, TOTP_PARAMETERS.periodSeconds);
  for (const offset of [-1, 0, 1]) {
    const code = totpCode(secret, step + offset, TOTP_PARAMETERS);
    assert.equal(verifyTotp(secret, code, TOTP_PARAMETERS, { atMs: T0 }), step + offset, `offset ${offset}`);
  }
  for (const offset of [-2, 2, 10]) {
    const code = totpCode(secret, step + offset, TOTP_PARAMETERS);
    assert.equal(verifyTotp(secret, code, TOTP_PARAMETERS, { atMs: T0 }), null, `offset ${offset}`);
  }
  assert.equal(verifyTotp(secret, "000000", TOTP_PARAMETERS, { atMs: T0 }), null);
  assert.equal(verifyTotp(secret, "", TOTP_PARAMETERS, { atMs: T0 }), null);
  // Spaces and dashes are what people type; they are not a different code.
  const now = totpCode(secret, step, TOTP_PARAMETERS);
  assert.equal(
    verifyTotp(secret, `${now.slice(0, 3)} ${now.slice(3)}`, TOTP_PARAMETERS, { atMs: T0 }),
    step,
  );
});

test("the code comparison is constant-time, and that is a property of the source", () => {
  // THE HONEST TEST, and the same one `src/auth/passwords.ts` carries. Swapping
  // `secretEquals` for `===` is functionally identical: every assertion above
  // about which codes are accepted passes either way, and only the time taken
  // differs. A timing assertion sharp enough to see it would be too flaky to
  // keep, so the property is pinned where it is visible — in the source.
  //
  // It matters more here than for a password. A six-digit code has a million
  // values, so a comparison that returns at the first differing character can be
  // walked digit by digit; there is no work factor in the way.
  const source = readFileSync(join(ROOT, "src", "auth", "totp.ts"), "utf8");
  assert.match(
    source,
    /import \{ secretEquals \} from "\.\.\/crypto\/secrets\.ts"/,
    "the one constant-time comparison in the codebase should be the one used here",
  );

  const start = source.indexOf("function codeEquals");
  assert.ok(start > 0, "codeEquals should exist and be the single comparison of two codes");
  const body = source.slice(start, source.indexOf("\n}", start));
  assert.match(body, /return secretEquals\(/, "the comparison must be the constant-time one");
  assert.doesNotMatch(body, /[=!]==/, "a secret comparison must not use a strict-equality operator");

  // And the window loop must not stop early, or a correct code costs measurably
  // less than a wrong one at the edge of the window. Comments are stripped
  // first, because the one in that loop says the word out loud.
  const verify = source.slice(source.indexOf("export function verifyTotp"));
  const code = verify
    .slice(0, verify.indexOf("\n}"))
    .split("\n")
    .filter((line) => !/^\s*(\*|\/\*|\/\/)/.test(line))
    .join("\n");
  assert.doesNotMatch(code, /\bbreak\b/, "verifyTotp must evaluate every candidate step");
  assert.match(code, /codeEquals\(/, "and it must compare through the constant-time helper");
});

test("the otpauth URI names the organization twice, and escapes both halves", () => {
  // Older authenticators read the label prefix and newer ones the parameter. An
  // enrolment that shows up as a bare email address is one a person belonging to
  // three organizations cannot tell apart (migration 12 note 4).
  const uri = otpauthUri({
    issuer: "Acme: Widgets",
    account: "alice@acme.example",
    secret: Buffer.from("foobar", "utf8"),
  });
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.ok(!uri.slice(0, uri.indexOf("?")).includes(": "), "the label must escape a colon in the issuer");
  const query = new URLSearchParams(uri.slice(uri.indexOf("?") + 1));
  assert.equal(query.get("secret"), "MZXW6YTBOI");
  assert.equal(query.get("issuer"), "Acme: Widgets");
  assert.equal(query.get("algorithm"), TOTP_PARAMETERS.algorithm);
  assert.equal(query.get("digits"), String(TOTP_PARAMETERS.digits));
  assert.equal(query.get("period"), String(TOTP_PARAMETERS.periodSeconds));
});

// ---------------------------------------------------------------------------
// Sealing — the one place this schema stores something it can read back
// ---------------------------------------------------------------------------

test("a sealed secret round-trips, is different every time, and is authenticated", () => {
  const secret = mintTotpSecret();
  const first = sealTotpSecret(SEALING_KEY, secret);
  const second = sealTotpSecret(SEALING_KEY, secret);

  assert.notEqual(first, second, "a fresh data key and nonce per enrolment, or this is ECB with steps");
  assert.deepEqual(openTotpSecret(SEALING_KEY, first), Buffer.from(secret));
  assert.deepEqual(openTotpSecret(SEALING_KEY, second), Buffer.from(secret));
  assert.match(first, /^v1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/, "the shape migration 12 constrains");

  // The wrong key must not merely produce wrong bytes — it must be detected.
  // Without the authentication tag, opening under a wrong key would hand back
  // 20 bytes of noise and every code would silently be refused for ever.
  assert.throws(() => openTotpSecret(randomBytes(32), first), SealedValueError);

  // A tampered blob is refused for the same reason.
  const [version, wrapped, body] = first.split("$");
  const flipped = `${String(body).slice(0, -2)}${String(body).slice(-2) === "AA" ? "AB" : "AA"}`;
  assert.throws(() => openTotpSecret(SEALING_KEY, `${version}$${wrapped}$${flipped}`), SealedValueError);
  assert.throws(() => openTotpSecret(SEALING_KEY, "v2$abc$def"), SealedValueError);
  assert.throws(() => openTotpSecret(SEALING_KEY, "not sealed at all"), SealedValueError);
});

test("a sealing key that is not random is refused rather than used", () => {
  // C4 is about defaults, and an all-zero key is the default somebody reaches
  // for in a hurry. A sealing function that accepted it would produce ciphertext
  // anybody could open while looking exactly as encrypted as the real thing.
  const secret = mintTotpSecret();
  assert.throws(() => sealTotpSecret(Buffer.alloc(32), secret), SealedValueError);
  assert.throws(() => sealTotpSecret(randomBytes(16), secret), /16 bytes/);
  assert.throws(
    () => sealTotpSecret(Buffer.from(Array.from({ length: 32 }, (_, i) => i)), secret),
    SealedValueError,
    "a counting sequence is not a key",
  );
});

test("recovery codes are high-entropy, grouped for typing, and hashed for storage", () => {
  const codes = Array.from({ length: 50 }, () => mintRecoveryCode());
  assert.equal(new Set(codes).size, 50, "two codes collided, which no CSPRNG does at this size");
  for (const code of codes) {
    assert.match(code, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/, `"${code}" is not the shape people are shown`);
  }

  const one = codes[0] ?? "";
  // The dashes are presentation. A person who types the code without them, or in
  // lower case, must not be refused on the day they lost their phone.
  assert.equal(recoveryCodeDigest(one), recoveryCodeDigest(one.replace(/-/g, "").toLowerCase()));
  assert.equal(recoveryCodeDigest(one), recoveryCodeDigest(` ${one} `));
  assert.match(recoveryCodeDigest(one), /^[0-9a-f]{64}$/);
  assert.notEqual(recoveryCodeDigest(one), recoveryCodeDigest(codes[1] ?? ""));
  assert.equal(normaliseRecoveryCode(one).length, 16, "80 bits, base32");
});

test("the demand rule enforces a factor somebody opted into, policy or no policy", () => {
  // Written as a pure function so the rule can be argued with directly. The
  // second line is the one worth arguing: turning the policy off must not
  // silently downgrade everybody who had opted in.
  assert.equal(secondFactorDemand({ policyRequires: false, enrolled: false }), "none");
  assert.equal(secondFactorDemand({ policyRequires: false, enrolled: true }), "verify");
  assert.equal(secondFactorDemand({ policyRequires: true, enrolled: false }), "enrol");
  assert.equal(secondFactorDemand({ policyRequires: true, enrolled: true }), "verify");
});

test("the second factor is an authentication path with a published budget", () => {
  // A six-digit code is a million possibilities, and an unlimited verifier finds
  // the right one inside a day. RL-M1-020 already carries the path; this asserts
  // the two halves have not drifted apart, and the wiring that spends the budget
  // is owed by the interface layer (see the foot of src/auth/two_factor.ts).
  assert.ok((AUTH_PATHS as readonly string[]).includes("two-factor"));
  const budget = AUTH_RATE_LIMITS["two-factor"];
  assert.ok(budget.account.limit > 0 && budget.account.limit <= 20, "a guessing budget, not a formality");
  assert.ok(budget.address.limit >= budget.account.limit);
});

// ---------------------------------------------------------------------------
// Acceptance 1 — enrol, verify, recovery codes
// ---------------------------------------------------------------------------

test("enrolling hands back a secret, a URI and ten recovery codes, and it signs you in", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = requestCtx(acme.orgId, aliceId);
      const subject: FactorSubject = { kind: "self" };

      const begun = await beginEnrolment(alice, SEALING_KEY, subject);
      assert.ok(begun.ok);
      assert.match(begun.uri, /^otpauth:\/\/totp\/Acme:alice%40acme\.example\?/);
      assert.deepEqual({ ...begun.parameters }, { ...TOTP_PARAMETERS });
      const secret = base32Decode(begun.secret);
      assert.equal(secret.length, 20, "160 bits, as RFC 4226 §4 R6 recommends");

      // A pending enrolment is NOT a second factor. Somebody who closes the tab
      // here must not be locked out, and the organization must not count them
      // as compliant.
      assert.equal(await demandFor(alice, aliceId), "none");

      const done = await confirmEnrolment(alice, SEALING_KEY, {
        subject,
        presented: codeAt(secret, T0),
        atMs: T0,
      });
      assert.ok(done.ok);
      assert.equal(done.recoveryCodes.length, RECOVERY_CODE_COUNT);
      assert.equal(new Set(done.recoveryCodes).size, RECOVERY_CODE_COUNT);
      assert.equal(done.session, null, "a person enrolling from settings already has a session");
      assert.equal(await demandFor(alice, aliceId), "verify", "now it is a second factor");

      // And now a password alone is not enough.
      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      assert.equal(challenge.enrolmentRequired, false);
      assert.ok(challenge.token.startsWith(CHALLENGE_TOKEN_PREFIX), "recognisable in a log, and not a session");

      const verified = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        // A period on from the confirming code, because the confirming one is
        // spent by construction.
        presented: codeAt(secret, T0 + PERIOD_MS),
        atMs: T0 + PERIOD_MS,
      });
      assert.ok(verified.ok, `verification should hold: ${verified.ok ? "" : verified.refusal}`);
      assert.equal(verified.factor, "totp");
      assert.equal(verified.recoveryCodesLeft, RECOVERY_CODE_COUNT);
      assert.notEqual(await validateSession(ctx, verified.token), null, "and the session must work");
      assert.equal(verified.session.userId, aliceId);
    });
  });
});

test("the shared secret is stored sealed, and the column cannot hold a bare one", { skip }, async () => {
  // A TOTP secret cannot be a digest — the server has to recompute against it —
  // so this is the one credential in the schema that is encrypted rather than
  // hashed, and the property that has to hold instead is that a database backup
  // carries ciphertext.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    let base32Secret = "";

    await usingScratch(database, async () => {
      const alice = requestCtx(acme.orgId, aliceId);
      const begun = await beginEnrolment(alice, SEALING_KEY, { kind: "self" });
      assert.ok(begun.ok);
      base32Secret = begun.secret;
    });

    const stored = await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query<{ secret_sealed: string }>(
        "select secret_sealed from two_factor_enrolments",
      );
      await app.query("rollback");
      return rows.rows;
    });
    assert.equal(stored.length, 1);
    const sealed = stored[0]?.secret_sealed ?? "";
    assert.ok(!sealed.includes(base32Secret), "the plaintext secret reached the database");
    assert.ok(
      !sealed.includes(base32Encode(base32Decode(base32Secret))),
      "nor in any re-encoding of itself",
    );
    assert.deepEqual(openTotpSecret(SEALING_KEY, sealed), base32Decode(base32Secret));

    await assert.rejects(
      () =>
        client.query(
          `insert into two_factor_enrolments (org_id, user_id, secret_sealed, algorithm, digits, period_seconds)
           values ($1, $2, $3, 'SHA1', 6, 30)`,
          [acme.orgId, aliceId, base32Secret],
        ),
      /two_factor_enrolments_secret_shape/,
      "storing a bare secret must violate a constraint, not merely a convention",
    );
  });
});

test("recovery codes are stored as digests, and the column cannot hold a printable one", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    let issued: readonly string[] = [];

    await usingScratch(database, async () => {
      issued = (await enrolSelf(requestCtx(acme.orgId, aliceId), T0)).codes;
    });

    const stored = await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query<{ code_hash: string; used_at: Date | null }>(
        "select code_hash, used_at from two_factor_recovery_codes order by code_hash",
      );
      await app.query("rollback");
      return rows.rows;
    });

    assert.equal(stored.length, RECOVERY_CODE_COUNT);
    assert.deepEqual(
      stored.map((r) => r.code_hash).sort(),
      issued.map(recoveryCodeDigest).sort(),
      "the stored values should be the digests of what was issued",
    );
    const flattened = JSON.stringify(stored);
    for (const code of issued) {
      assert.ok(!flattened.includes(code), "a printable recovery code reached the database");
      assert.ok(!flattened.includes(normaliseRecoveryCode(code)), "nor in its normalised form");
    }
    assert.deepEqual(stored.map((r) => r.used_at), Array(RECOVERY_CODE_COUNT).fill(null));

    await assert.rejects(
      () =>
        client.query(
          "insert into two_factor_recovery_codes (org_id, user_id, code_hash) values ($1, $2, $3)",
          [acme.orgId, aliceId, issued[0] ?? ""],
        ),
      /two_factor_recovery_codes_hash_shape/,
    );
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — the organization policy, and forced enrolment
// ---------------------------------------------------------------------------

test("an organization that requires a second factor hands a non-compliant member no session", { skip }, async () => {
  // THE acceptance test for criterion 2. The person's password is correct and
  // they still get nothing: no session row, no session identifier, only a
  // challenge that says "enrol".
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const owner = requestCtx(acme.orgId, acme.ownerId);
      assert.equal((await twoFactorPolicy(owner)).twoFactorRequired, false, "off by default");
      assert.equal((await setTwoFactorPolicy(owner, true)).twoFactorRequired, true);

      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      assert.equal(challenge.enrolmentRequired, true, "a non-compliant member is sent to enrol");
    });

    const sessions = await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query("select 1 from sessions");
      await app.query("rollback");
      return rows.rows.length;
    });
    assert.equal(sessions, 0, "a correct password alone must not have created a session");
  });
});

test("the forced enrolment finishes the sign-in, and only then", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      await setTwoFactorPolicy(requestCtx(acme.orgId, acme.ownerId), true);
      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      const subject: FactorSubject = { kind: "challenge", challengeToken: challenge.token };

      const begun = await beginEnrolment(ctx, SEALING_KEY, subject);
      assert.ok(begun.ok);
      const secret = base32Decode(begun.secret);

      // A wrong code at this point must not enrol anybody.
      const wrong = await confirmEnrolment(ctx, SEALING_KEY, {
        subject,
        presented: "000000",
        atMs: T0,
      });
      assert.equal(wrong.ok, false);
      assert.equal(wrong.ok ? "" : wrong.failure, "code-rejected");
      assert.equal(await demandFor(ctx, aliceId), "enrol", "a rejected code must not have enrolled them");

      const done = await confirmEnrolment(ctx, SEALING_KEY, {
        subject,
        presented: codeAt(secret, T0),
        atMs: T0,
      });
      assert.ok(done.ok);
      assert.equal(done.recoveryCodes.length, RECOVERY_CODE_COUNT);
      assert.notEqual(done.session, null, "finishing a forced enrolment signs the person in");
      assert.notEqual(await validateSession(ctx, done.session?.token ?? ""), null);
      assert.equal(await demandFor(ctx, aliceId), "verify");

      // The challenge is spent by the confirmation: it has done its job, and a
      // second credential lying around for five minutes is a second credential.
      const again = await beginEnrolment(ctx, SEALING_KEY, subject);
      assert.equal(again.ok, false);
      assert.equal(again.ok ? "" : again.failure, "no-live-challenge");
    });
  });
});

test("a challenge cannot enrol over a confirmed factor", { skip }, async () => {
  // THE attack this feature exists to stop. Somebody who knows a password but
  // not the factor gets a challenge like anybody else. If that challenge could
  // start a fresh enrolment they would enrol their own authenticator and the
  // second factor would be decorative.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      await setTwoFactorPolicy(requestCtx(acme.orgId, acme.ownerId), true);
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);

      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      assert.equal(challenge.enrolmentRequired, false, "she is enrolled; she must verify, not enrol");

      const subject: FactorSubject = { kind: "challenge", challengeToken: challenge.token };
      const attempt = await beginEnrolment(ctx, SEALING_KEY, subject);
      assert.equal(attempt.ok, false, "a stolen password must not replace an authenticator");
      assert.equal(attempt.ok ? "" : attempt.failure, "already-enrolled");

      // And nothing about the refused attempt touched her enrolment: her own
      // code still works.
      const verified = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        presented: codeAt(alice.secret, T0 + PERIOD_MS),
        atMs: T0 + PERIOD_MS,
      });
      assert.ok(verified.ok, "the real factor must still verify");
    });
  });
});

test("setting the policy needs organization.manage_security_policy", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const bobId = await addMember(client, acme.orgId, "bob@acme.example", await fixtureHash());
    await grantRole(client, acme.orgId, bobId, "viewer");

    await usingScratch(database, async () => {
      const bob = requestCtx(acme.orgId, bobId);
      await assert.rejects(
        () => setTwoFactorPolicy(bob, true),
        NotPermittedError,
        "a Viewer must not be able to turn the organization's second factor off or on",
      );
      assert.equal((await twoFactorPolicy(bob)).twoFactorRequired, false, "and nothing changed");

      const owner = requestCtx(acme.orgId, acme.ownerId);
      assert.equal((await setTwoFactorPolicy(owner, true)).twoFactorRequired, true);
      assert.equal((await twoFactorPolicy(bob)).twoFactorRequired, true, "reading it needs nothing");
      assert.equal((await setTwoFactorPolicy(owner, false)).twoFactorRequired, false);
    });
  });
});

test("a member who owes nothing signs in exactly as before", { skip }, async () => {
  // The regression this feature could most easily cause: two-factor
  // authentication that nobody asked for, refusing everybody.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const ctx = signInCtx(acme);
      const result = signedIn(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.notEqual(await validateSession(ctx, result.token), null);
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — recovery codes are single use, and audited
// ---------------------------------------------------------------------------

test("a recovery code signs you in once and never again", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const code = alice.codes[0] ?? "";
      const ctx = signInCtx(acme);

      const first = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const used = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: first.token,
        presented: code,
        atMs: T0 + PERIOD_MS,
      });
      assert.ok(used.ok, `the recovery code should work once: ${used.ok ? "" : used.refusal}`);
      assert.equal(used.factor, "recovery-code");
      assert.equal(used.recoveryCodesLeft, RECOVERY_CODE_COUNT - 1);
      assert.notEqual(await validateSession(ctx, used.token), null);

      const second = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const replayed = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: second.token,
        presented: code,
        atMs: T0 + 2 * PERIOD_MS,
      });
      assert.equal(replayed.ok, false, "a spent recovery code must never work again");
      assert.equal(replayed.ok ? "" : replayed.refusal, "factor-rejected");

      // Lower case and without the dashes is the same code, and must be just as
      // spent — otherwise the normalisation is a second namespace of codes.
      const third = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const reformatted = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: third.token,
        presented: code.replace(/-/g, "").toLowerCase(),
        atMs: T0 + 3 * PERIOD_MS,
      });
      assert.equal(reformatted.ok, false);

      // A different code from the same set still works: one spent code is one
      // spent code.
      const fourth = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const another = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: fourth.token,
        presented: alice.codes[1] ?? "",
        atMs: T0 + 4 * PERIOD_MS,
      });
      assert.ok(another.ok);
      assert.equal(another.recoveryCodesLeft, RECOVERY_CODE_COUNT - 2);
    });
  });
});

test("spending a recovery code is audited, and no entry holds the code", { skip }, async () => {
  // Acceptance 3's second half. A recovery code is the bypass around the
  // control, so its use is the event an incident review looks for — and the
  // audit log is handed to people during incidents, so it must carry the fact
  // and never the credential (ADR 0006).
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const code = alice.codes[0] ?? "";
      const ctx = signInCtx(acme);

      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      const used = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        presented: code,
        atMs: T0 + PERIOD_MS,
      });
      assert.ok(used.ok);

      // Read as the tenant's OWNER. `ctx` here is the sign-in service identity,
      // which holds no grants at all and must not — RL-M1-043 gated the audit
      // log, and a pre-authentication context reading it would be a hole rather
      // than a convenience.
      const review = requestCtx(acme.orgId, acme.ownerId);
      const entries = await listAudit(review, { action: "two_factor.recovery_code_used" });
      assert.equal(entries.length, 1, "spending a recovery code must be recorded");
      const entry = entries[0];
      assert.equal(entry?.decision, "allow");
      assert.equal(entry?.resourceType, "member");
      assert.equal(entry?.resourceId, aliceId, "the entry must name the person it happened to");
      // C6: attributable. The actor is the named service identity the
      // pre-authentication path acts as, never "the system".
      assert.equal(entry?.actorType, "service_identity");
      assert.equal(entry?.actorLabel, "sign-in");
      assert.notEqual(entry?.requestId, "");

      // A verification is recorded too, so an operator can see the shape of an
      // attack and not only its successes.
      assert.equal((await listAudit(review, { action: "two_factor.verify" })).length, 1);
      assert.equal((await listAudit(review, { action: "two_factor.enrol" })).length, 1);
    });

    const flattened = await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query<{ line: string }>(
        "select (action || ' ' || reason || ' ' || metadata::text) as line from audit_entries",
      );
      await app.query("rollback");
      return rows.rows.map((r) => r.line).join("\n");
    });
    assert.ok(flattened.includes("two_factor.recovery_code_used"));
    assert.ok(flattened.includes("recovery_codes_left"));
  });
});

// ---------------------------------------------------------------------------
// The failure directions
// ---------------------------------------------------------------------------

test("a wrong code is refused, and the challenge survives the typo", { skip }, async () => {
  // A challenge destroyed by one wrong digit would send somebody back to the
  // password form every time they fumbled, at exactly the moment they are
  // already flustered. Retries are bounded by the rate limiter, not by
  // destroying the credential.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );

      const at = T0 + PERIOD_MS;
      const right = codeAt(alice.secret, at);
      for (const wrong of ["000000", "12345", right.split("").reverse().join(""), "not-a-code"]) {
        const refused = await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: challenge.token,
          presented: wrong,
          atMs: at,
        });
        assert.equal(refused.ok, false, `"${wrong}" was accepted`);
        assert.equal(refused.ok ? "" : refused.refusal, "factor-rejected");
      }

      const accepted = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        presented: right,
        atMs: at,
      });
      assert.ok(accepted.ok, "the challenge must have survived four wrong codes");
    });
  });
});

test("a code that has been used is refused inside its own window", { skip }, async () => {
  // A TOTP code is valid for ninety seconds once the skew window is counted, so
  // without a guard a code read over somebody's shoulder is replayable for a
  // minute and a half. The counter only ever moves forward.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const ctx = signInCtx(acme);
      const at = T0 + PERIOD_MS;
      const code = codeAt(alice.secret, at);

      const first = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.ok(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: first.token,
          presented: code,
          atMs: at,
        })).ok,
      );

      // The same code, in the same period, on a fresh challenge.
      const second = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      const replayed = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: second.token,
        presented: code,
        atMs: at,
      });
      assert.equal(replayed.ok, false, "a used code was accepted again");
      assert.equal(replayed.ok ? "" : replayed.refusal, "factor-rejected");

      // And still refused a period later, while it is inside the skew window.
      const third = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.equal(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: third.token,
          presented: code,
          atMs: at + PERIOD_MS,
        })).ok,
        false,
        "the skew window must not resurrect a spent counter",
      );

      // The next period's code is a different counter and works.
      const fourth = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.ok(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: fourth.token,
          presented: codeAt(alice.secret, at + PERIOD_MS),
          atMs: at + PERIOD_MS,
        })).ok,
        "moving forward must still work, or the guard is a lockout",
      );
    });
  });
});

test("the code that confirmed an enrolment cannot then sign you in", { skip }, async () => {
  // The same replay rule at the one moment it is easiest to forget: enrolment
  // proves a code, and that proof spends it.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      const refused = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        presented: codeAt(alice.secret, T0),
        atMs: T0,
      });
      assert.equal(refused.ok, false, "the confirming code must be spent");
      assert.equal(refused.ok ? "" : refused.refusal, "factor-rejected");
    });
  });
});

test("a code from another person's secret is refused", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    const bobId = await addMember(client, acme.orgId, "bob@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const bob = await enrolSelf(requestCtx(acme.orgId, bobId), T0);
      const ctx = signInCtx(acme);
      const at = T0 + PERIOD_MS;

      const bobsChallenge = challenged(
        await signIn(ctx, { email: "bob@acme.example", password: PASSPHRASE }),
      );
      const wrongPerson = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: bobsChallenge.token,
        presented: codeAt(alice.secret, at),
        atMs: at,
      });
      assert.equal(wrongPerson.ok, false, "Alice's code signed Bob in");
      assert.equal(wrongPerson.ok ? "" : wrongPerson.refusal, "factor-rejected");

      // Nor may one person's recovery code redeem another's challenge.
      const withHerCode = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: bobsChallenge.token,
        presented: alice.codes[0] ?? "",
        atMs: at,
      });
      assert.equal(withHerCode.ok, false, "Alice's recovery code signed Bob in");

      // And Bob's own still works, so the test is not passing by refusing
      // everything.
      assert.ok(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: bobsChallenge.token,
          presented: codeAt(bob.secret, at),
          atMs: at,
        })).ok,
      );
      // Alice's code being refused for Bob must not have spent it for Alice.
      const hers = challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
      assert.ok(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: hers.token,
          presented: alice.codes[0] ?? "",
          atMs: at,
        })).ok,
        "a code offered to the wrong account must not be consumed",
      );
    });
  });
});

test("a challenge is single use, and cannot be exchanged twice", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );

      assert.ok(
        (await verifySecondFactor(ctx, SEALING_KEY, {
          challengeToken: challenge.token,
          presented: codeAt(alice.secret, T0 + PERIOD_MS),
          atMs: T0 + PERIOD_MS,
        })).ok,
      );

      const again = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        presented: codeAt(alice.secret, T0 + 2 * PERIOD_MS),
        atMs: T0 + 2 * PERIOD_MS,
      });
      assert.equal(again.ok, false, "a redeemed challenge must not mint a second session");
      assert.equal(again.ok ? "" : again.refusal, "no-live-challenge");
    });

    const sessions = await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query("select 1 from sessions");
      await app.query("rollback");
      return rows.rows.length;
    });
    assert.equal(sessions, 1, "exactly one session should exist");
  });
});

test("a challenge that has lapsed is nothing at all, with no cleanup having run", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());
    const token = `${CHALLENGE_TOKEN_PREFIX}${randomUUID()}`;

    await usingScratch(database, async () => {
      await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
    });

    // Written already expired, and read for the first time. There is no window
    // in which a job could have acted, because it was never live here.
    await client.query(
      `insert into two_factor_challenges (org_id, user_id, token_hash, created_at, expires_at)
       values ($1, $2, $3, now() - interval '20 minutes', now() - interval '10 minutes')`,
      [acme.orgId, aliceId, challengeTokenDigest(token)],
    );

    await usingScratch(database, async () => {
      const refused = await verifySecondFactor(signInCtx(acme), SEALING_KEY, {
        challengeToken: token,
        presented: "000000",
        atMs: T0,
      });
      assert.equal(refused.ok, false);
      assert.equal(refused.ok ? "" : refused.refusal, "no-live-challenge");
    });

    const left = await client.query("select 1 from two_factor_challenges where token_hash = $1", [
      challengeTokenDigest(token),
    ]);
    assert.equal(left.rows.length, 1, "expiry must filter, not delete — history is not enforcement");
  });
});

test("a challenge dies mid-transaction the moment it expires", { skip }, async () => {
  // The sharpest form of "expiry is a predicate, not a job". One transaction is
  // held open across the expiry instant, and between the two reads the only
  // statements issued are the reads themselves.
  //
  // It also pins the clock: `now()` is frozen for the life of a transaction, so
  // the test asserts `now()` has NOT moved while the answer flipped. With `now()`
  // in the view this test could not pass, and a challenge would outlive its
  // window for as long as a transaction ran.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");
    const digest = challengeTokenDigest(`${CHALLENGE_TOKEN_PREFIX}${randomUUID()}`);

    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const opened = await app.query<{ txn: string }>("select now()::text as txn");
      const txnClock = opened.rows[0]?.txn ?? "";

      // Written from the migration connection while the reader's transaction is
      // open, which is how a challenge is created in production too: by another
      // request, on another connection.
      await client.query(
        `insert into two_factor_challenges (org_id, user_id, token_hash, expires_at)
         values ($1, $2, $3, now() + interval '700 milliseconds')`,
        [acme.orgId, aliceId, digest],
      );

      const live = "select 1 from live_two_factor_challenges where token_hash = $1";
      assert.equal((await app.query(live, [digest])).rows.length, 1, "live until it expires");

      await sleep(900);

      assert.equal(
        (await app.query(live, [digest])).rows.length,
        0,
        "the same question, in the same transaction, must now find nothing",
      );

      const clocks = await app.query<{ txn: string; stmt: string }>(
        "select now()::text as txn, statement_timestamp()::text as stmt",
      );
      assert.equal(clocks.rows[0]?.txn, txnClock, "the transaction never ended");
      assert.notEqual(clocks.rows[0]?.stmt, txnClock, "and the statement clock is what moved");
      await app.query("rollback");
    });
  });
});

test("a challenge is worth nothing before the factor exists", { skip }, async () => {
  // An enrolment that was begun and never confirmed is not a second factor, so
  // there is nothing for a challenge to be exchanged against.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      await setTwoFactorPolicy(requestCtx(acme.orgId, acme.ownerId), true);
      const alice = requestCtx(acme.orgId, aliceId);
      const begun = await beginEnrolment(alice, SEALING_KEY, { kind: "self" });
      assert.ok(begun.ok);
      const secret = base32Decode(begun.secret);

      const ctx = signInCtx(acme);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      assert.equal(challenge.enrolmentRequired, true, "an abandoned enrolment is not compliance");

      const refused = await verifySecondFactor(ctx, SEALING_KEY, {
        challengeToken: challenge.token,
        // A perfectly valid code from the pending secret. It still is not a
        // factor, because nobody has confirmed it.
        presented: codeAt(secret, T0),
        atMs: T0,
      });
      assert.equal(refused.ok, false);
      assert.equal(refused.ok ? "" : refused.refusal, "not-enrolled");
    });
  });
});

test("a superseded enrolment's recovery codes cannot be redeemed", { skip }, async () => {
  // Beginning a re-enrolment makes the row pending again, and it does NOT delete
  // the recovery codes — those go when the new enrolment is confirmed. So for
  // the length of an abandoned re-enrolment there are live-looking codes in the
  // table for a factor that no longer exists.
  //
  // Two guards refuse them, and this test drives the SECOND one directly.
  // `verifySecondFactor` never reaches it, because it reads
  // `confirmed_two_factor_enrolments` first and stops — which is exactly why the
  // guard inside `redeemChallenge` needs a test of its own. It was added after a
  // mutation of that line went unnoticed by every test in this file.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      const alice = requestCtx(acme.orgId, aliceId);
      const enrolled = await enrolSelf(alice, T0);

      // A new phone, and then a distraction.
      const begun = await beginEnrolment(alice, SEALING_KEY, { kind: "self" });
      assert.ok(begun.ok);

      const ctx = signInCtx(acme);
      await setTwoFactorPolicy(requestCtx(acme.orgId, acme.ownerId), true);
      const challenge = challenged(
        await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }),
      );
      assert.equal(challenge.enrolmentRequired, true, "a pending enrolment is not a factor");

      const redemption = await redeemChallenge(ctx, {
        challengeToken: challenge.token,
        factor: { kind: "recovery-code", digest: recoveryCodeDigest(enrolled.codes[0] ?? "") },
      });
      assert.equal(redemption.ok, false, "a code for a superseded factor was redeemed");
      assert.equal(redemption.ok ? "" : redemption.refusal, "not-enrolled");
    });

    const spent = await client.query(
      "select 1 from two_factor_recovery_codes where used_at is not null",
    );
    assert.equal(spent.rows.length, 0, "and the refused attempt must not have spent one");
  });
});

// ---------------------------------------------------------------------------
// Tenancy — every one of these is a row-level security assertion
// ---------------------------------------------------------------------------

test("a challenge minted in one organization is nothing in another", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const stored = await fixtureHash();
    const carolAcme = await addMember(client, acme.orgId, "carol@example.com", stored);
    await addMember(client, globex.orgId, "carol@example.com", stored);

    await usingScratch(database, async () => {
      const alice = await enrolSelf(requestCtx(acme.orgId, carolAcme), T0);
      const inAcme = challenged(
        await signIn(signInCtx(acme), { email: "carol@example.com", password: PASSPHRASE }),
      );

      // The same human, the same password, the other organization. Her Acme
      // challenge must be indistinguishable from nonsense there.
      const fromGlobex = await verifySecondFactor(signInCtx(globex), SEALING_KEY, {
        challengeToken: inAcme.token,
        presented: codeAt(alice.secret, T0 + PERIOD_MS),
        atMs: T0 + PERIOD_MS,
      });
      assert.equal(fromGlobex.ok, false);
      assert.equal(fromGlobex.ok ? "" : fromGlobex.refusal, "no-live-challenge");

      // And it is still live where it belongs — the failed attempt spent
      // nothing.
      assert.ok(
        (await verifySecondFactor(signInCtx(acme), SEALING_KEY, {
          challengeToken: inAcme.token,
          presented: codeAt(alice.secret, T0 + PERIOD_MS),
          atMs: T0 + PERIOD_MS,
        })).ok,
      );

      // Her Globex account has no second factor: an enrolment is per tenant
      // (migration 12 note 4), and the cost of that is stated there.
      const inGlobex = await readSecondFactorRequirement(
        signInCtx(globex),
        (await client.query<{ id: string }>("select id from users where email = 'carol@example.com'"))
          .rows[0]?.id ?? "",
      );
      assert.deepEqual({ ...inGlobex }, { policyRequires: false, enrolled: false });
    });
  });
});

test("with no tenant bound, the two-factor tables are invisible", { skip }, async () => {
  // The missing-setting case has to fail closed, exactly as migration 4's
  // policies do: current_setting(..., true) is NULL, and org_id = NULL is not
  // true, so nothing matches.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example", await fixtureHash());

    await usingScratch(database, async () => {
      await setTwoFactorPolicy(requestCtx(acme.orgId, acme.ownerId), true);
      await enrolSelf(requestCtx(acme.orgId, aliceId), T0);
      const ctx = signInCtx(acme);
      challenged(await signIn(ctx, { email: "alice@acme.example", password: PASSPHRASE }));
    });

    await asApplicationRole(database, async (app) => {
      for (const relation of [
        "organization_security_policies",
        "two_factor_enrolments",
        "two_factor_recovery_codes",
        "two_factor_challenges",
        "confirmed_two_factor_enrolments",
        "live_two_factor_challenges",
      ]) {
        const r = await app.query(`select 1 from ${relation}`);
        assert.equal(r.rows.length, 0, `${relation}: visible with no tenant set`);
      }

      // Bound to the other tenant, still nothing.
      await app.query("begin");
      await setTenant(app, globex.orgId);
      for (const relation of ["two_factor_enrolments", "two_factor_challenges"]) {
        const r = await app.query(`select 1 from ${relation}`);
        assert.equal(r.rows.length, 0, `${relation}: another tenant's rows are visible`);
      }

      // And a write cannot be aimed at another tenant. WITH CHECK, not just
      // USING. Each one gets its own transaction, because the first violation
      // aborts the one it happens in.
      await assert.rejects(
        () =>
          app.query(
            `insert into two_factor_challenges (org_id, user_id, token_hash, expires_at)
             values ($1, $2, $3, now() + interval '5 minutes')`,
            [acme.orgId, aliceId, challengeTokenDigest("implant")],
          ),
        /row-level security/i,
      );
      await app.query("rollback");

      await app.query("begin");
      await setTenant(app, globex.orgId);
      await assert.rejects(
        () =>
          app.query(
            "insert into organization_security_policies (org_id, two_factor_required) values ($1, true)",
            [acme.orgId],
          ),
        /row-level security/i,
      );
      await app.query("rollback");

      // Bound to its own tenant, the rows are there — so the assertions above
      // are not passing by seeing nothing at all.
      await app.query("begin");
      await setTenant(app, acme.orgId);
      for (const relation of ["two_factor_enrolments", "two_factor_challenges"]) {
        const r = await app.query(`select 1 from ${relation}`);
        assert.equal(r.rows.length, 1, `${relation}: own rows should be visible`);
      }
      await app.query("rollback");
    });
  });
});

test("row-level security is enabled, forced and invoker-scoped on everything this adds", { skip }, async () => {
  // Structural, so the property survives someone adding a table to this
  // migration without the policy. ENABLE alone leaves the owner exempt, and a
  // view without security_invoker runs as its owner — a superuser — and hands
  // over every tenant.
  await withMigratedDatabase(async (client) => {
    const tables = [
      "organization_security_policies",
      "two_factor_enrolments",
      "two_factor_recovery_codes",
      "two_factor_challenges",
    ];
    const rows = await client.query<{
      relname: string;
      relrowsecurity: boolean;
      relforcerowsecurity: boolean;
    }>(
      `select relname, relrowsecurity, relforcerowsecurity from pg_class
        where relname = any($1::text[])`,
      [tables],
    );
    assert.equal(rows.rows.length, tables.length);
    for (const row of rows.rows) {
      assert.ok(row.relrowsecurity, `${row.relname}: RLS not enabled`);
      assert.ok(row.relforcerowsecurity, `${row.relname}: RLS not FORCED`);
    }

    const policies = await client.query<{ tablename: string; qual: string; with_check: string }>(
      "select tablename, qual, with_check from pg_policies where tablename = any($1::text[])",
      [tables],
    );
    assert.equal(policies.rows.length, tables.length, "one policy each");
    for (const policy of policies.rows) {
      assert.match(policy.qual, /current_tenant\(\)/, `${policy.tablename}: USING`);
      assert.match(policy.with_check, /current_tenant\(\)/, `${policy.tablename}: WITH CHECK`);
    }

    for (const view of ["confirmed_two_factor_enrolments", "live_two_factor_challenges"]) {
      const options = await client.query<{ reloptions: string[] | null }>(
        "select reloptions from pg_class where relname = $1",
        [view],
      );
      assert.deepEqual(options.rows[0]?.reloptions, ["security_invoker=true"], view);
    }

    // No trigger may be in the enforcement path — the same rule sessions and
    // rate limits follow, so nothing can quietly become a sweep.
    const triggers = await client.query<{ tgname: string }>(
      `select tgname from pg_trigger
        where tgrelid = any($1::regclass[]) and not tgisinternal`,
      [tables],
    );
    assert.deepEqual(triggers.rows.map((r) => r.tgname), []);

    const definition = await client.query<{ definition: string }>(
      "select pg_get_viewdef('live_two_factor_challenges'::regclass, true) as definition",
    );
    assert.match(definition.rows[0]?.definition ?? "", /consumed_at IS NULL/i);
    assert.match(definition.rows[0]?.definition ?? "", /statement_timestamp\(\)/);
  });
});

test("an enrolment cannot be written for somebody outside the organization", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const outsider = await addMember(client, globex.orgId, "dave@globex.example", await fixtureHash());

    await usingScratch(database, async () => {
      // The Acme context names a person who is not an Acme member. There is no
      // parameter through which to aim this — the subject is the acting user —
      // so the insert simply matches no membership row.
      const attempt = await beginEnrolment(requestCtx(acme.orgId, outsider), SEALING_KEY, {
        kind: "self",
      });
      assert.equal(attempt.ok, false);
      assert.equal(attempt.ok ? "" : attempt.failure, "not-a-member");
    });

    const rows = await client.query("select 1 from two_factor_enrolments");
    assert.equal(rows.rows.length, 0, "nothing may have been written");
  });
});

test("the algorithms TypeScript knows are exactly the ones the schema accepts", { skip }, async () => {
  // A mirror that can drift is worse than no mirror, so it is read back out of
  // the database — the pattern session_fixation.test.ts and
  // rate_limit_auth.test.ts already use for their vocabularies.
  await withMigratedDatabase(async (client) => {
    const r = await client.query<{ definition: string }>(
      `select pg_get_constraintdef(oid) as definition from pg_constraint
        where conrelid = 'two_factor_enrolments'::regclass
          and conname = 'two_factor_enrolments_algorithm'`,
    );
    const definition = r.rows[0]?.definition ?? "";
    for (const algorithm of ["SHA1", "SHA256", "SHA512"]) {
      assert.match(definition, new RegExp(`'${algorithm}'`), `the schema does not accept ${algorithm}`);
    }
    assert.equal(
      definition.match(/'[A-Z0-9]+'::text/g)?.length,
      3,
      "the schema accepts an algorithm TypeScript does not know about",
    );
  });
});

test("a challenge lives minutes, not hours", { skip: false }, () => {
  // A challenge is the window between a correct password and six digits. One
  // that lived as long as a session would be a password-only session by another
  // name, which is the design this whole feature refuses.
  assert.ok(CHALLENGE_LIFETIME_MS >= 60_000, "a minute is not enough to unlock a phone");
  assert.ok(CHALLENGE_LIFETIME_MS <= 15 * 60_000, "a challenge this long is a session");
});
