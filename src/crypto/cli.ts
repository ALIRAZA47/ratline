#!/usr/bin/env node --experimental-strip-types
/**
 * The instruction signing key, from an operator's terminal (RL-M2-004).
 *
 *   ./scripts/keys status    what is accepted, and until when
 *   ./scripts/keys rotate    generate a new key, keep the outgoing one for the overlap
 *   ./scripts/keys prune     delete the outgoing key once its overlap has closed
 *
 * Rotation is an operator action on a host, not an API endpoint, and that is a decision
 * rather than an omission. An endpoint that rotates the instruction signing key would
 * let anyone who reaches the dashboard replace the key that authorises every instruction
 * to every host — so the authority for it is the same as for claiming an installation:
 * shell access to the machine holding the key (RL-M1-030). C6 still applies, which is
 * why `status` prints who would have to be trusted rather than pretending nobody was.
 *
 * NO KEY MATERIAL IS EVER PRINTED. Not the private key, not the public key, not a
 * fingerprint of the private half. `status` prints the public key's fingerprint because
 * that is what an operator needs to compare against what an agent reports — and a
 * fingerprint of a PUBLIC key discloses nothing that key was not already public for.
 */

import { createHash } from "node:crypto";

import { secretsDir } from "./secrets.ts";
import {
  DEFAULT_OVERLAP_MS,
  RotationRefused,
  acceptedInstructionKeys,
  pruneRetiredKey,
  rotateInstructionKey,
  rotationState,
} from "./rotation.ts";

/** A short, stable name for a public key, for comparing against what an agent reports. */
function fingerprint(raw: Buffer): string {
  return createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

function status(dir: string): void {
  const keys = acceptedInstructionKeys(dir);
  const state = rotationState(dir);

  process.stdout.write(`secrets directory  ${dir}\n`);
  process.stdout.write(`accepted keys      ${String(keys.length)}\n\n`);

  for (const key of keys) {
    process.stdout.write(`  ${key.keyId.padEnd(9)} sha256:${fingerprint(key.raw)}\n`);
  }

  process.stdout.write("\n");
  if (state.rotatedAt === null) {
    process.stdout.write("This key has never been rotated.\n");
    return;
  }

  process.stdout.write(`last rotated       ${new Date(state.rotatedAt).toISOString()}\n`);
  if (state.overlapEndsAt !== null) {
    const open = Date.now() < state.overlapEndsAt;
    process.stdout.write(`overlap ${open ? "closes" : "closed"}     ${new Date(state.overlapEndsAt).toISOString()}\n`);
    if (open) {
      // §291: what to do next, not just what is true.
      process.stdout.write(
        `\nThe outgoing key is still accepted. Once every host holds the current key,\n` +
          `run \`./scripts/keys prune\` — or wait, and it stops being accepted on its own.\n`,
      );
    } else if (state.hasPrevious) {
      process.stdout.write(
        `\nThe outgoing key is no longer accepted but is still on disk. Remove it with\n` +
          `\`./scripts/keys prune\`.\n`,
      );
    }
  }
}

function rotate(dir: string): void {
  const before = acceptedInstructionKeys(dir).map((key) => fingerprint(key.raw));
  const { overlapEndsAt } = rotateInstructionKey(dir);
  const after = acceptedInstructionKeys(dir);

  process.stdout.write(`rotated. ${String(after.length)} key(s) now accepted:\n\n`);
  for (const key of after) {
    const mark = before.includes(fingerprint(key.raw)) ? "was current" : "new";
    process.stdout.write(`  ${key.keyId.padEnd(9)} sha256:${fingerprint(key.raw)}  (${mark})\n`);
  }

  process.stdout.write(
    `\nThe outgoing key stays accepted until ${new Date(overlapEndsAt).toISOString()}\n` +
      `(${String(Math.round(DEFAULT_OVERLAP_MS / 86_400_000))} days). Every host has to learn the\n` +
      `new key before then, or it will refuse instructions signed with it.\n\n` +
      `Nothing distributes keys yet (RL-M2-006), so today that means re-enrolling each\n` +
      `host. Do not prune early: an agent with neither key refuses everything.\n`,
  );
}

function prune(dir: string, force: boolean): void {
  const removed = pruneRetiredKey(dir, force ? { force: true } : {});
  process.stdout.write(
    removed
      ? "the outgoing key and its rotation stamp are removed.\n"
      : "nothing to remove: there is no outgoing key on disk.\n",
  );
}

function main(): void {
  const [command = "status", flag] = process.argv.slice(2);
  const dir = secretsDir();

  try {
    switch (command) {
      case "status":
        status(dir);
        return;
      case "rotate":
        rotate(dir);
        return;
      case "prune":
        // `--force` deletes the outgoing key while its overlap is still open. It exists
        // because an operator who KNOWS every host has the current key should not have
        // to wait a week with two valid keys — and it is a flag rather than the default
        // because being wrong about that bricks every agent that was behind.
        prune(dir, flag === "--force");
        return;
      default:
        // No default branch that guesses. Same rule as the operation catalogue.
        process.stderr.write(`keys: no command named "${command}".\nAvailable: status, rotate, prune\n`);
        process.exit(2);
    }
  } catch (error) {
    if (error instanceof RotationRefused) {
      process.stderr.write(`${error.message}\n`);
      process.exit(1);
    }
    throw error;
  }
}

main();
