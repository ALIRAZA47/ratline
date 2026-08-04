/**
 * Verifying agent client certificates (RL-M2-005).
 *
 * ADR 0002: the agent dials the control plane over mutually authenticated TLS, and
 * "each host holds its own client certificate, issued at enrolment via a single-use
 * short-lived token, and individually revocable."
 *
 * ## This file verifies. It does not mint, and that took a wrong turn first.
 *
 * Node's standard library can PARSE and VERIFY X.509 — `X509Certificate.verify()` and
 * `.checkIssued()` — and cannot MINT it. There is no certificate-building API; the
 * legacy SPKAC `Certificate` class is something else.
 *
 * The first attempt used OpenSSL through `execFile` with an argv array, reasoning that
 * C2 forbids shell commands built by string interpolation and an argv array is what C2
 * asks for. **The lint rule refused it, and the lint rule is right.** ADR 0005 and C2
 * together say the control plane executes NO processes — "that is what makes command
 * injection structurally impossible here rather than merely unlikely" — and an argv
 * array in one file is still a process-spawning import in `src/`, which is the door the
 * rule closes. A constraint that holds only where somebody remembered to hold it is not
 * a constraint.
 *
 * So minting uses `@peculiar/x509` (see the justification in the commit that added it),
 * and it lives in `src/crypto/issue.ts` — separated so that THIS file, which runs on
 * every connection, has no dependency at all.
 *
 * That separation is the point rather than tidiness. Verification must never be wrong
 * and must never fail for an unrelated reason: a library that threw on load would
 * otherwise decide whether any host may connect. Minting happens once per host with an
 * operator present; verification happens on every connection, in process, on stdlib.
 *
 * ## What a client certificate is NOT trusted for
 *
 * It authenticates a TRANSPORT, and nothing else. It does not authorise an operation:
 * every instruction carries its own Ed25519 signature over an envelope (ADR 0002), and
 * the agent verifies that separately. A compromised or mis-issued certificate gets an
 * attacker a connection, not the ability to make the agent do anything — because the
 * agent refuses an envelope it cannot verify regardless of which TLS session delivered
 * it. Two independent mechanisms, and this is only one.
 */

import { X509Certificate, createHash } from "node:crypto";

/** How long a host certificate is valid. */
export const CERTIFICATE_DAYS = 365;

/** How long the CA itself is valid. Longer than any certificate it issues. */
export const CA_DAYS = 3650;

export class CertificateRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateRefused";
  }
}

export type Authority = {
  /** PEM, and it never leaves the control plane. */
  readonly privateKeyPem: string;
  readonly certificatePem: string;
};

export type IssuedCertificate = {
  readonly certificatePem: string;
  /** The host's private key. Returned ONCE, to be handed to the host and forgotten. */
  readonly privateKeyPem: string;
  readonly serial: string;
  /** SHA-256 of the DER, which is what a presented certificate is matched on. */
  readonly fingerprint: Buffer;
  readonly notBefore: Date;
  readonly notAfter: Date;
};

/** SHA-256 of the DER. What a presented certificate is matched on. */
export function fingerprintOf(certificate: X509Certificate): Buffer {
  return createHash("sha256").update(certificate.raw).digest();
}

export type PresentedCertificate = {
  readonly hostId: string;
  readonly fingerprint: Buffer;
  readonly serial: string;
};

/**
 * Verify a certificate a connection presented, structurally.
 *
 * IN PROCESS AND STDLIB. This runs on every connection and must not depend on a
 * subprocess: an openssl invocation that failed for an unrelated reason would otherwise
 * decide whether a host may connect, and the safe direction — refusing every host
 * because a fork failed — is still an outage.
 *
 * What this establishes: the certificate was issued by our authority, is within its
 * validity window, and names a host. What it does NOT establish is that the certificate
 * is still trusted — revocation lives in the database, and `src/repo/enrolment.ts`
 * checks it. Both are required, and separating them is deliberate: this function is
 * pure and testable without a database, and the revocation check cannot be forgotten
 * because the repository is the only thing that returns a host.
 */
export function verifyPresented(
  authority: Pick<Authority, "certificatePem">,
  certificatePem: string,
  now: Date = new Date(),
): PresentedCertificate {
  let certificate: X509Certificate;
  try {
    certificate = new X509Certificate(certificatePem);
  } catch (cause) {
    throw new CertificateRefused(
      `the presented certificate could not be parsed: ${cause instanceof Error ? cause.message : "unknown"}`,
    );
  }

  const ca = new X509Certificate(authority.certificatePem);

  // Issued by us. `checkIssued` compares the issuer chain; `verify` checks the
  // signature. BOTH, because checkIssued alone only says the names line up — anybody
  // can put our CA's name in their certificate's issuer field.
  if (!certificate.checkIssued(ca)) {
    throw new CertificateRefused("the presented certificate was not issued by this authority");
  }
  if (!certificate.verify(ca.publicKey)) {
    throw new CertificateRefused(
      "the presented certificate names this authority as its issuer but is not signed by it",
    );
  }

  const from = new Date(certificate.validFrom);
  const to = new Date(certificate.validTo);
  if (now < from) {
    throw new CertificateRefused("the presented certificate is not yet valid");
  }
  if (now >= to) {
    throw new CertificateRefused("the presented certificate has expired");
  }

  // A client certificate must be a client certificate. One also valid for serverAuth
  // could impersonate the control plane to another agent.
  if (certificate.ca) {
    throw new CertificateRefused("the presented certificate is a CA certificate, not a client one");
  }

  const hostId = commonNameOf(certificate.subject);
  if (hostId === null) {
    throw new CertificateRefused("the presented certificate has no common name, so it names no host");
  }

  return { hostId, fingerprint: fingerprintOf(certificate), serial: certificate.serialNumber };
}

/** The CN from an X.509 subject string, or null. */
function commonNameOf(subject: string): string | null {
  for (const line of subject.split("\n")) {
    const [key, ...rest] = line.split("=");
    if (key?.trim() === "CN") {
      const value = rest.join("=").trim();
      return value === "" ? null : value;
    }
  }
  return null;
}
