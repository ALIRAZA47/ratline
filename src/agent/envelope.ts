/**
 * Signed instruction envelopes (RL-M2-003), control-plane side.
 *
 * ADR 0002: every instruction is `{ operation, arguments, nonce, issued_at,
 * expires_at, target_host_id }`, signed with the control plane's Ed25519
 * instruction key, and the agent verifies "signature; that `target_host_id` is its
 * own; that `expires_at` has not passed; that `nonce` is unseen" — in that order,
 * **before interpreting any argument**.
 *
 * ## The signature is NOT over the JSON
 *
 * This is the decision the whole file turns on. JSON is not a canonical encoding:
 * key order, whitespace, `\/` escaping, unicode escape form, and number formatting
 * all vary between implementations, and two of them signing "the same object"
 * produce different bytes. Every protocol that has tried to fix this with a
 * canonical-JSON profile has produced a second specification to disagree about.
 *
 * So the signature covers {@link canonicalBytes}: a length-prefixed binary
 * encoding with one legal form per instruction. JSON remains the transport, and
 * the agent re-derives the canonical bytes from the fields it parsed before
 * verifying. A JSON quirk therefore cannot survive: any encoding difference lands
 * as a signature mismatch, which is a refusal, not a divergence.
 *
 * ## Why every field is length-prefixed
 *
 * Concatenation without lengths is ambiguous, and ambiguity in signed bytes is
 * forgery. `{a: "bc"}` and `{ab: "c"}` both flatten to `abc`: one signature would
 * be valid for two different instructions. Length prefixes make the encoding
 * injective, which is the property a signature needs and the one that is easiest
 * to lose by accident.
 *
 * ## Why there is a domain-separation prefix
 *
 * The same Ed25519 key must never produce a signature that is valid in two
 * contexts. Without a prefix, an agent's signed RESPONSE could be replayed as an
 * INSTRUCTION if the field layouts ever coincided — and "ever coincided" is a
 * property of future code, not of this file. The prefix names the context and the
 * version, so a v2 envelope cannot be verified as a v1 one either.
 */

import { createPrivateKey, createPublicKey, randomBytes, sign, verify } from "node:crypto";

import { KINDS, operation as lookupOperation, type Operation } from "./catalogue.ts";

/**
 * The domain separator. Includes the version, so a future layout change cannot be
 * verified against this one even if it happens to parse.
 */
export const INSTRUCTION_DOMAIN = "ratline-instruction-v1";

/** Nonce length in bytes. 32 is well past birthday-collision concerns. */
export const NONCE_BYTES = 32;

/**
 * How long an instruction may live, and the ceiling on that.
 *
 * A short window is what makes the nonce store bounded: the agent only has to
 * remember a nonce until it expires, so the store's size is a function of the
 * instruction rate within one window rather than of uptime.
 */
export const MAX_VALIDITY_MS = 5 * 60 * 1000;

export type Instruction = {
  readonly operation: string;
  readonly arguments: Readonly<Record<string, string>>;
  /** 32 random bytes, hex encoded. */
  readonly nonce: string;
  /** Unix milliseconds. */
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly targetHostId: string;
};

export type SignedEnvelope = Instruction & {
  /** Ed25519 signature over canonicalBytes, base64. */
  readonly signature: string;
  /**
   * Which key signed it, so an agent holding two keys during a rotation overlap
   * knows which to try first — and so a rotation that goes wrong names the key
   * rather than reporting "bad signature" for every instruction.
   *
   * NOT trusted: the agent tries every key it accepts regardless. A hint an
   * attacker controls cannot be allowed to select the verification key, because
   * naming a revoked key would then be enough to have it used.
   */
  readonly keyId: string;
};

const encoder = new TextEncoder();

function uint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function uint64(value: number): Uint8Array {
  const out = new Uint8Array(8);
  // Milliseconds since the epoch exceeds 2^32 but stays well inside Number's
  // exact-integer range, so BigInt conversion here is safe and explicit.
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

/** A length-prefixed field. */
function field(value: string): Uint8Array[] {
  const bytes = encoder.encode(value);
  return [uint32(bytes.length), bytes];
}

/**
 * The exact bytes a signature covers.
 *
 * One legal encoding per instruction, and the agent derives it independently — see
 * `canonicalBytes` in agent/internal/protocol/envelope.go. The two are checked
 * against each other by committed test vectors rather than by inspection, because
 * "these two functions agree" is not a property source review establishes.
 */
export function canonicalBytes(instruction: Instruction): Uint8Array {
  const parts: Uint8Array[] = [];

  // Domain first, NUL-terminated, so the separator cannot be confused with the
  // start of a field even if a field ever begins with the same text.
  parts.push(encoder.encode(INSTRUCTION_DOMAIN), new Uint8Array([0]));

  parts.push(...field(instruction.operation));
  parts.push(...field(instruction.targetHostId));
  parts.push(...field(instruction.nonce));
  parts.push(uint64(instruction.issuedAt));
  parts.push(uint64(instruction.expiresAt));

  // Sorted by name, so two encoders cannot disagree about map iteration order.
  // Sorted by CODE UNIT via the default comparator rather than by locale:
  // localeCompare would make the encoding depend on the machine's locale, which
  // is the kind of difference that shows up as an unverifiable instruction on one
  // host and works everywhere else.
  const names = Object.keys(instruction.arguments).sort();
  parts.push(uint32(names.length));
  for (const name of names) {
    parts.push(...field(name));
    parts.push(...field(instruction.arguments[name] ?? ""));
  }

  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export type SigningKey = {
  readonly keyId: string;
  /** PKCS#8 PEM. The private half never leaves the control plane. */
  readonly privateKeyPem: string;
};

/**
 * Reasons an instruction cannot be built. Returned rather than thrown where the
 * caller can act, thrown where the caller has a bug.
 */
export class InstructionRejected extends Error {}

/**
 * Build and sign one instruction.
 *
 * Validates against the catalogue FIRST. The control plane refusing to sign a
 * malformed instruction proves nothing to the agent — which re-validates because
 * it must assume this side is compromised — but it is still the right place for the
 * error to surface: a bug here should fail in the control plane's tests, not as a
 * refusal on somebody's host that looks like a protocol problem.
 */
export function signInstruction(
  key: SigningKey,
  input: {
    readonly operation: string;
    readonly arguments: Readonly<Record<string, string>>;
    readonly targetHostId: string;
    readonly now: number;
    readonly validityMs: number;
    /** Injected only by tests that need a fixed nonce for a vector. */
    readonly nonce?: string;
  },
): SignedEnvelope {
  const declared: Operation | null = lookupOperation(input.operation);
  if (declared === null) {
    throw new InstructionRejected(
      `"${input.operation}" is not in the operation catalogue, so no instruction can be built ` +
        `for it. See src/agent/catalogue.ts.`,
    );
  }

  assertArgumentsMatch(declared, input.arguments);

  if (input.validityMs <= 0 || input.validityMs > MAX_VALIDITY_MS) {
    throw new InstructionRejected(
      `validity ${String(input.validityMs)}ms is outside 1..${String(MAX_VALIDITY_MS)}. The ` +
        `window bounds the agent's nonce store, so a long one is not a convenience — it is ` +
        `how much replay memory every host has to hold.`,
    );
  }

  const instruction: Instruction = {
    operation: input.operation,
    arguments: input.arguments,
    nonce: input.nonce ?? randomBytes(NONCE_BYTES).toString("hex"),
    issuedAt: input.now,
    expiresAt: input.now + input.validityMs,
    targetHostId: input.targetHostId,
  };

  const signature = sign(null, canonicalBytes(instruction), createPrivateKey(key.privateKeyPem));

  return { ...instruction, signature: signature.toString("base64"), keyId: key.keyId };
}

/**
 * Check arguments against the catalogue.
 *
 * Deliberately the same rules the agent applies, in the same order — unexpected
 * before missing, length before pattern. Not shared code, because there is none to
 * share across the language boundary, and not a looser check either: a control
 * plane that accepted more than the agent does would sign instructions that are
 * refused on arrival, and the operator would see a host that rejects valid work.
 */
export function assertArgumentsMatch(
  declared: Operation,
  args: Readonly<Record<string, string>>,
): void {
  const expected = new Map(declared.args.map((spec) => [spec.name, spec]));

  for (const name of Object.keys(args)) {
    if (!expected.has(name)) {
      throw new InstructionRejected(
        `operation "${declared.name}" has no argument "${name}"; it takes ` +
          `${String(declared.args.length)} and every one is required.`,
      );
    }
  }

  for (const spec of declared.args) {
    const value = args[spec.name];
    if (value === undefined) {
      throw new InstructionRejected(
        `operation "${declared.name}" requires argument "${spec.name}".`,
      );
    }

    const kind = KINDS[spec.kind];
    const bytes = encoder.encode(value).length;
    if (kind.maxBytes !== undefined && bytes > kind.maxBytes) {
      throw new InstructionRejected(
        `argument "${spec.name}": ${String(bytes)} bytes exceeds the ` +
          `${String(kind.maxBytes)} allowed for ${spec.kind}.`,
      );
    }

    if (kind.oneOf !== undefined) {
      if (!kind.oneOf.includes(value)) {
        throw new InstructionRejected(
          `argument "${spec.name}": not one of ${kind.oneOf.join(", ")}.`,
        );
      }
      continue;
    }

    if (kind.pattern !== undefined) {
      if (!new RegExp(kind.pattern).test(value)) {
        // The value is not echoed. It reaches a log, and this message is the same
        // shape as the agent's for the same reason.
        throw new InstructionRejected(
          `argument "${spec.name}": does not match the required form for ${spec.kind}.`,
        );
      }
      continue;
    }

    if (kind.goType === "int64") {
      if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
        throw new InstructionRejected(`argument "${spec.name}": not a decimal number.`);
      }
      const parsed = Number(value);
      if (kind.min !== undefined && parsed < kind.min) {
        throw new InstructionRejected(`argument "${spec.name}": below ${String(kind.min)}.`);
      }
      if (kind.max !== undefined && parsed > kind.max) {
        throw new InstructionRejected(`argument "${spec.name}": above ${String(kind.max)}.`);
      }
      continue;
    }

    if (kind.goType === "bool") {
      if (value !== "true" && value !== "false") {
        throw new InstructionRejected(`argument "${spec.name}": not "true" or "false".`);
      }
      continue;
    }

    if (kind.validator !== undefined) {
      if (value === "") {
        throw new InstructionRejected(
          `argument "${spec.name}": empty; ${kind.validator} needs content to parse.`,
        );
      }
      continue;
    }

    throw new InstructionRejected(
      `argument kind "${spec.kind}" constrains nothing, so this instruction cannot be checked.`,
    );
  }
}

/**
 * Verify an envelope, control-plane side.
 *
 * Present so the test suite can prove a signature made here verifies here before
 * asking whether it verifies in Go — a cross-language failure is much easier to
 * read when the same-language case is already known good.
 */
export function verifyEnvelope(publicKeyPem: string, envelope: SignedEnvelope): boolean {
  return verify(
    null,
    canonicalBytes(envelope),
    createPublicKey(publicKeyPem),
    Buffer.from(envelope.signature, "base64"),
  );
}

/** The JSON that goes on the wire. Field names match the Go struct tags. */
export function wireForm(envelope: SignedEnvelope): string {
  return JSON.stringify({
    operation: envelope.operation,
    arguments: envelope.arguments,
    nonce: envelope.nonce,
    issued_at: envelope.issuedAt,
    expires_at: envelope.expiresAt,
    target_host_id: envelope.targetHostId,
    signature: envelope.signature,
    key_id: envelope.keyId,
  });
}
