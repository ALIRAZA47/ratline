/**
 * Rotating the instruction signing key (RL-M2-004).
 *
 * ADR 0002: "Signing key rotation uses an overlap window: agents accept both the
 * outgoing and incoming key for a configured period, so rotation never requires a
 * flag-day."
 *
 * The agent half already works. `Verify` in `agent/internal/protocol/envelope.go`
 * takes a SET of accepted keys and tries every one, deliberately refusing to let the
 * envelope's `key_id` hint select which — so an agent given two public keys accepts
 * envelopes signed by either, and `TestRotationOverlapAcceptsBothKeys` covers it. What
 * did not exist is the control-plane half: somewhere to keep the outgoing key, a record
 * of when the overlap ends, and a rotation that moves rather than replaces.
 *
 * ## Three files, and why the timestamp is one of them
 *
 *   instruction-signing.pem            the key envelopes are signed with, now
 *   instruction-signing.previous.pem   the outgoing key, present only during an overlap
 *   instruction-signing.rotated-at     when the rotation happened, as unix milliseconds
 *
 * The deadline could be derived from the previous key's mtime, and must not be. An
 * mtime does not survive a copy, a restore from backup, or a container image rebuild —
 * every one of which would silently move the deadline, in the direction of accepting a
 * retired key for longer. A timestamp the rotation wrote is a fact; an mtime is an
 * artefact of the filesystem.
 *
 * ## The overlap must outlast an envelope
 *
 * An envelope signed with the outgoing key one millisecond before rotation is valid for
 * up to `MAX_VALIDITY_MS` afterwards. If the overlap were shorter than that, an
 * instruction already in flight — already signed, already sent — would be refused by
 * the agent partway through its own validity window, and the operator would see a
 * deploy fail for a reason nothing in the logs connects to a key change.
 *
 * So {@link rotateInstructionKey} refuses an overlap shorter than the validity window.
 * The default is far longer, because the real constraint is not arithmetic: an agent
 * has to LEARN the new public key before the old one stops being accepted, and nothing
 * distributes keys yet. That distribution is RL-M2-006's, and until it exists the
 * default overlap is the honest answer to "how long might an agent be behind".
 */

import { createPublicKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { secretsDir } from "./secrets.ts";

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const GROUP_AND_OTHER = 0o077;

export const CURRENT_FILE = "instruction-signing.pem";
export const PREVIOUS_FILE = "instruction-signing.previous.pem";
export const ROTATED_AT_FILE = "instruction-signing.rotated-at";

/**
 * The shortest overlap that cannot orphan an in-flight envelope.
 *
 * Mirrors `MAX_VALIDITY_MS` in `src/agent/envelope.ts` and `MaxValidity` in the agent.
 * Duplicated as a number rather than imported, because importing the envelope module
 * here would make the secrets layer depend on the protocol layer for a bound it only
 * needs to compare against — and the test asserts the two agree, which is the part
 * that actually keeps them from drifting.
 */
export const MIN_OVERLAP_MS = 5 * 60 * 1000;

/**
 * The default overlap: seven days.
 *
 * Not chosen for arithmetic. The binding constraint is how long an agent might go
 * without learning the new public key, and nothing distributes keys yet (RL-M2-006), so
 * this is a guess at "an agent that was offline over a long weekend". It is deliberately
 * generous: the cost of too long is that a retired key stays accepted, and the cost of
 * too short is that a host stops accepting instructions and an operator has no way to
 * see why. The second is worse, and harder to diagnose.
 */
export const DEFAULT_OVERLAP_MS = 7 * 24 * 60 * 60 * 1000;

export class RotationRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RotationRefused";
  }
}

/** One key an agent should accept, and why it is in the set. */
export type AcceptedKey = {
  readonly keyId: "current" | "previous";
  readonly publicKey: KeyObject;
  /** Raw 32 bytes, which is what Go's ed25519.PublicKey is. */
  readonly raw: Buffer;
};

export type RotationState = {
  /** Unix milliseconds of the last rotation, or null if the key has never rotated. */
  readonly rotatedAt: number | null;
  /** When the outgoing key stops being accepted, or null when there is no overlap. */
  readonly overlapEndsAt: number | null;
  readonly hasPrevious: boolean;
};

function pathsIn(dir: string): { current: string; previous: string; stamp: string } {
  return {
    current: join(dir, CURRENT_FILE),
    previous: join(dir, PREVIOUS_FILE),
    stamp: join(dir, ROTATED_AT_FILE),
  };
}

/**
 * Refuse a file anybody but the owner can read.
 *
 * Checked on every read rather than only at rotation. A key whose mode was widened
 * after it was written is exactly as exposed as one written wrongly, and the moment
 * somebody notices is the moment it is read.
 */
function assertOwnerOnly(path: string): void {
  const mode = statSync(path).mode & 0o777;
  if ((mode & GROUP_AND_OTHER) !== 0) {
    throw new RotationRefused(
      `${path} is mode ${mode.toString(8).padStart(4, "0")}, which grants access outside the ` +
        `owner. An instruction signing key readable by anyone else lets them forge any ` +
        `instruction to any host. Run: chmod 600 ${path}`,
    );
  }
}

/** The 32 raw bytes of an Ed25519 public key, from a private key PEM. */
function rawPublic(privateKeyPem: string): { publicKey: KeyObject; raw: Buffer } {
  const publicKey = createPublicKey(privateKeyPem);
  // The last 32 bytes of an Ed25519 SPKI structure are the key. Taken this way rather
  // than by parsing DER, because the agent needs raw bytes and a full ASN.1 parse here
  // would be a second implementation of something Node already did.
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return { publicKey, raw: Buffer.from(raw) };
}

export function rotationState(dir: string = secretsDir(), overlapMs = DEFAULT_OVERLAP_MS): RotationState {
  const paths = pathsIn(dir);
  const hasPrevious = existsSync(paths.previous);

  if (!existsSync(paths.stamp)) {
    return { rotatedAt: null, overlapEndsAt: null, hasPrevious };
  }

  const raw = readFileSync(paths.stamp, "utf8").trim();
  const rotatedAt = Number(raw);
  if (!Number.isInteger(rotatedAt) || rotatedAt <= 0) {
    // A stamp that cannot be read is treated as NO overlap, which retires the previous
    // key immediately. Failing the other way — assuming an open window — would keep a
    // retired key accepted for a period nobody can determine.
    throw new RotationRefused(
      `${paths.stamp} does not contain a unix millisecond timestamp (found ${JSON.stringify(raw)}). ` +
        `Without it the overlap deadline is unknown, and this refuses rather than guessing ` +
        `a window that would keep a retired key accepted.`,
    );
  }

  return { rotatedAt, overlapEndsAt: rotatedAt + overlapMs, hasPrevious };
}

/**
 * The public keys an agent should accept right now.
 *
 * Current always. Previous only while the overlap is open AND the file is there — both
 * conditions, because either one alone is a different bug: a stale file with a closed
 * window would extend acceptance past the deadline, and an open window with no file
 * would have this return a key that does not exist.
 */
export function acceptedInstructionKeys(
  dir: string = secretsDir(),
  now: number = Date.now(),
  overlapMs: number = DEFAULT_OVERLAP_MS,
): readonly AcceptedKey[] {
  const paths = pathsIn(dir);

  if (!existsSync(paths.current)) {
    throw new RotationRefused(
      `${paths.current} does not exist, so there is no key to sign or verify with. ` +
        `The application generates it on first run (C4) — start it once before rotating.`,
    );
  }
  assertOwnerOnly(paths.current);

  const keys: AcceptedKey[] = [
    { keyId: "current", ...rawPublic(readFileSync(paths.current, "utf8")) },
  ];

  const state = rotationState(dir, overlapMs);
  if (state.hasPrevious && state.overlapEndsAt !== null && now < state.overlapEndsAt) {
    assertOwnerOnly(paths.previous);
    keys.push({ keyId: "previous", ...rawPublic(readFileSync(paths.previous, "utf8")) });
  }

  return keys;
}

/**
 * Generate a new signing key, keeping the outgoing one for the overlap.
 *
 * The order is deliberate and the reverse of convenient. The outgoing key is MOVED to
 * its slot before the new one is written, so there is no instant at which the current
 * key has been replaced and the outgoing one is not yet recoverable. If the process
 * dies between the two steps, the previous file holds the only key and the stamp is
 * absent — which `acceptedInstructionKeys` reads as "no overlap", so the installation
 * refuses to verify anything rather than silently accepting a key it cannot account
 * for. That is a loud failure requiring an operator, which is the right outcome for a
 * half-completed key rotation.
 */
export function rotateInstructionKey(
  dir: string = secretsDir(),
  options: { readonly now?: number; readonly overlapMs?: number } = {},
): { readonly rotatedAt: number; readonly overlapEndsAt: number } {
  const now = options.now ?? Date.now();
  const overlapMs = options.overlapMs ?? DEFAULT_OVERLAP_MS;
  const paths = pathsIn(dir);

  if (overlapMs < MIN_OVERLAP_MS) {
    throw new RotationRefused(
      `an overlap of ${String(overlapMs)}ms is shorter than the ${String(MIN_OVERLAP_MS)}ms an ` +
        `envelope may live. An instruction signed with the outgoing key just before this ` +
        `rotation would be refused partway through its own validity window, and the operator ` +
        `would see a deploy fail for a reason nothing connects to a key change.`,
    );
  }

  if (!existsSync(paths.current)) {
    throw new RotationRefused(
      `${paths.current} does not exist, so there is nothing to rotate. The application ` +
        `generates it on first run (C4).`,
    );
  }
  assertOwnerOnly(paths.current);

  if (existsSync(paths.previous)) {
    const state = rotationState(dir, overlapMs);
    if (state.overlapEndsAt !== null && now < state.overlapEndsAt) {
      // Refused rather than chaining. Keeping two outgoing keys would mean an agent
      // accepting three, and each additional accepted key is another key that can sign
      // an instruction to every host. One overlap at a time, and the operator waits.
      throw new RotationRefused(
        `a rotation is already in progress: the previous key is accepted until ` +
          `${new Date(state.overlapEndsAt).toISOString()}. Rotating again now would leave ` +
          `THREE keys able to sign instructions to every host. Wait for the overlap to ` +
          `close, or run pruneRetiredKey first if you are certain every agent has the ` +
          `current key.`,
      );
    }
  }

  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  chmodSync(dir, DIR_MODE);

  // Outgoing first. See the note above about dying between steps.
  renameSync(paths.current, paths.previous);
  chmodSync(paths.previous, FILE_MODE);

  const { privateKey } = generateKeyPairSync("ed25519");
  writeFileSync(paths.current, privateKey.export({ type: "pkcs8", format: "pem" }).toString(), {
    mode: FILE_MODE,
  });
  chmodSync(paths.current, FILE_MODE);

  // The stamp LAST, because it is what opens the overlap. Written before the new key
  // existed, a crash would leave an open window pointing at a previous key that is
  // still the only key — an installation accepting one key while believing it accepts
  // two.
  writeFileSync(paths.stamp, `${String(now)}\n`, { mode: FILE_MODE });
  chmodSync(paths.stamp, FILE_MODE);

  return { rotatedAt: now, overlapEndsAt: now + overlapMs };
}

/**
 * Delete the outgoing key once its overlap has closed.
 *
 * Refuses while the window is open, because deleting early is what a rotation's overlap
 * exists to prevent: an agent that has not yet learned the new key would have nothing
 * it accepts, and would refuse every instruction with no way to recover except being
 * re-enrolled.
 *
 * Returns whether anything was removed, so a caller can report honestly rather than
 * claiming a cleanup that found nothing to do.
 */
export function pruneRetiredKey(
  dir: string = secretsDir(),
  options: { readonly now?: number; readonly overlapMs?: number; readonly force?: boolean } = {},
): boolean {
  const now = options.now ?? Date.now();
  const overlapMs = options.overlapMs ?? DEFAULT_OVERLAP_MS;
  const paths = pathsIn(dir);

  if (!existsSync(paths.previous)) return false;

  const state = rotationState(dir, overlapMs);
  const open = state.overlapEndsAt !== null && now < state.overlapEndsAt;

  if (open && options.force !== true) {
    throw new RotationRefused(
      `the overlap is open until ${new Date(state.overlapEndsAt ?? 0).toISOString()}. Deleting ` +
        `the outgoing key now would leave any agent that has not learned the current key with ` +
        `nothing it accepts, refusing every instruction with no recovery but re-enrolment. ` +
        `Pass force only if you have confirmed every host holds the current key.`,
    );
  }

  rmSync(paths.previous, { force: true });
  rmSync(paths.stamp, { force: true });
  return true;
}
