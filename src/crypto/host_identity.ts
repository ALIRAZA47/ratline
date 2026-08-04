/**
 * How a host proves who it is (RL-M2-005, ADR 0002 as amended by A-04).
 *
 * The agent dials out over TLS. The server is authenticated by its certificate as
 * usual; the AGENT proves its identity with an Ed25519 signature over a challenge the
 * control plane issued. It was originally going to be an X.509 client certificate, and
 * the reasoning for the change is in ADR 0002 — briefly: Node can verify X.509 and
 * cannot mint it, and both ways of fixing that broke a constraint worth more than the
 * convenience.
 *
 * ## The two properties a client certificate gave for free
 *
 * A certificate is bound to the TLS session by the handshake, and it lives in a
 * namespace nothing else in this system uses. Moving the proof up a layer loses both,
 * and each has to be supplied deliberately.
 *
 * **1. Binding to the connection.** A signature over a challenge is a bearer token
 * once it exists: capture it and it authenticates whoever holds it. So a challenge is
 * issued PER CONNECTION, held only in the memory of the process serving that
 * connection, and consumed on first use. A signature for one connection cannot be
 * presented on another, because the second connection's challenge is a different
 * random value that the first signature does not cover. That is server-side channel
 * binding, and it is stronger here than a TLS exporter would be — it needs no
 * agreement between two TLS stacks about which RFC they implement.
 *
 * **2. Domain separation.** The same Ed25519 key must never produce a signature valid
 * in two contexts. Without a separator, a host's signed challenge and a signed
 * instruction could be confused for one another — and the instruction key and the host
 * key are different keys today, but "different keys today" is a property of current
 * code, not of the format. The separator makes the confusion impossible rather than
 * merely unlikely.
 *
 * ## What this does NOT establish
 *
 * That the host may do something. It authenticates a TRANSPORT and nothing else: every
 * instruction carries its own signature over an envelope, and the agent verifies that
 * separately. A stolen host key gets an attacker a connection, not the ability to make
 * any agent act — because an agent refuses an envelope it cannot verify regardless of
 * which connection delivered it. Two independent mechanisms, and this is one.
 */

import { createPublicKey, createHash, randomBytes, sign, timingSafeEqual, verify } from "node:crypto";

/**
 * The domain separator for a host proving its identity.
 *
 * Deliberately different from `ratline-instruction-v1`. A signature made over one
 * cannot verify against the other, so a captured challenge signature is not an
 * instruction and a captured instruction is not a proof of identity.
 */
export const IDENTITY_DOMAIN = "ratline-host-identity-v1";

/** Challenge length. 32 bytes of CSPRNG output is far past guessing. */
export const CHALLENGE_BYTES = 32;

/**
 * How long a challenge may sit unanswered.
 *
 * Short, because it has one job and the agent is already connected when it receives
 * one. A long window is a longer period in which a captured challenge is still worth
 * something to somebody who also has the host key.
 */
export const CHALLENGE_TTL_MS = 30_000;

export class IdentityRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityRefused";
  }
}

export type Challenge = {
  /** The bytes the host must sign, hex encoded on the wire. */
  readonly nonce: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
};

export function issueChallenge(now: number = Date.now()): Challenge {
  return {
    nonce: randomBytes(CHALLENGE_BYTES).toString("hex"),
    issuedAt: now,
    expiresAt: now + CHALLENGE_TTL_MS,
  };
}

/**
 * The exact bytes a host signs.
 *
 * Length-prefixed for the same reason the instruction envelope is: concatenation
 * without lengths is ambiguous, and ambiguity in signed bytes is forgery. Here there
 * are only two fields, so the ambiguity is narrow — but `hostId` and `nonce` are both
 * hex-ish strings, and "narrow" is not a property to build a signature on.
 */
export function challengeBytes(hostId: string, nonce: string): Buffer {
  const encoder = new TextEncoder();
  const parts: Buffer[] = [];

  parts.push(Buffer.from(encoder.encode(IDENTITY_DOMAIN)), Buffer.from([0]));

  for (const field of [hostId, nonce]) {
    const bytes = Buffer.from(encoder.encode(field));
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length, 0);
    parts.push(length, bytes);
  }

  return Buffer.concat(parts);
}

/**
 * Sign a challenge. The agent's side, here so the test suite can drive both halves and
 * so the Go implementation has committed vectors to check itself against.
 */
export function signChallenge(privateKeyPem: string, hostId: string, nonce: string): string {
  return sign(null, challengeBytes(hostId, nonce), privateKeyPem).toString("base64");
}

/** A host's registered public key, as the repository returns it. */
export type RegisteredKey = {
  readonly hostId: string;
  /** SPKI PEM. Public, so storing it in the database is not a secret in a database. */
  readonly publicKeyPem: string;
  readonly revokedAt: Date | null;
};

/**
 * Verify a host's answer to a challenge.
 *
 * The order matters and is the same discipline as the envelope's. Expiry first, because
 * checking a signature against an expired challenge is work an unauthenticated party
 * can ask for. Then the nonce matches the one THIS connection issued. Then revocation,
 * before the signature, because a revoked host should not have its signature examined
 * at all — and because refusing it later would leak, by timing, whether the signature
 * was well-formed.
 *
 * Then the signature. Nothing before this point trusted the answer for anything.
 */
export function verifyChallenge(
  issued: Challenge,
  answer: { readonly hostId: string; readonly nonce: string; readonly signature: string },
  key: RegisteredKey,
  now: number = Date.now(),
): void {
  if (now >= issued.expiresAt) {
    throw new IdentityRefused("the challenge has expired; open a new connection");
  }

  // Constant-time, because a nonce compared byte-by-byte with early exit leaks how much
  // of a guess was right — which is the whole game when the value is the only thing
  // standing between a captured signature and a second use.
  const presented = Buffer.from(answer.nonce, "utf8");
  const expected = Buffer.from(issued.nonce, "utf8");
  if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
    throw new IdentityRefused("the answer does not match the challenge this connection issued");
  }

  if (answer.hostId !== key.hostId) {
    // The answer names a host, and the key was looked up by that name. A mismatch means
    // the caller wired two different hosts together, which is a bug rather than an
    // attack — but it must not be allowed to authenticate anyone.
    throw new IdentityRefused("the answer names a different host than the key it was checked against");
  }

  if (key.revokedAt !== null) {
    // Before the signature. A revoked host's signature is not examined, and the refusal
    // is the same shape whether the signature was valid or not.
    throw new IdentityRefused("this host's key has been revoked");
  }

  let ok = false;
  try {
    ok = verify(
      null,
      challengeBytes(answer.hostId, answer.nonce),
      createPublicKey(key.publicKeyPem),
      Buffer.from(answer.signature, "base64"),
    );
  } catch {
    // A malformed signature or an unparseable key is a refusal, not a crash. Either
    // means this connection cannot be authenticated, which is the same outcome.
    throw new IdentityRefused("the answer's signature could not be checked");
  }

  if (!ok) {
    throw new IdentityRefused("the answer's signature does not verify under this host's key");
  }
}

/**
 * A short, stable name for a public key.
 *
 * For an operator comparing what the control plane has against what a host reports. A
 * fingerprint of a PUBLIC key discloses nothing the key was not already public for.
 */
export function fingerprint(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}
