/**
 * The first-run bootstrap token (RL-M1-030).
 *
 * ## The problem this solves, which is not the obvious one
 *
 * Somebody has to create the first organization and its first owner, and at
 * that moment there is no actor, no grant and no tenant. The obvious gate is
 * "allow it while the database is empty" — and row-level security makes that
 * question unanswerable from inside the application. A context is bound to one
 * tenant; a bound context cannot see whether any OTHER organization exists. C3
 * is working exactly as intended and it takes the easy answer away.
 *
 * Reaching around it would mean a `SECURITY DEFINER` function, or a second
 * connection as a privileged role, to count rows the application is not
 * supposed to see. Both are holes in C3 opened for a convenience, and both stay
 * open forever afterwards.
 *
 * ## The gate that is actually correct
 *
 * A single-use token, generated on first boot into the secrets directory that
 * C4 already governs, and required by the bootstrap endpoint.
 *
 * The operator reads it off the server's filesystem, which means the authority
 * to create the first organization is HOST ACCESS rather than network access.
 * That is the right authority: whoever can read `/etc/ratline/secrets` already
 * owns the installation, and whoever cannot should not be able to claim it by
 * being first to reach the port. It also survives the case "database is not
 * empty but this installation has never been claimed", which the empty-database
 * gate gets wrong in the dangerous direction.
 *
 * ## Why it is NOT a SECRET_SPEC entry
 *
 * `secrets.ts` says adding a spec is all that is needed, and that is true for
 * every secret whose rule is "must exist". This one's rule is "must exist
 * exactly once": present on a fresh install, absent forever after it is spent,
 * and its absence is the normal steady state rather than a refusal to boot.
 * Filing it as a spec would make a bootstrapped installation refuse to start.
 *
 * The spent marker is what makes "forever" true. Deleting the token alone would
 * let the next boot mint a new one — reopening the endpoint on every restart,
 * which is the whole vulnerability with extra steps.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

import { secretEquals, secretsDir } from "../crypto/secrets.ts";

const TOKEN_FILE = "bootstrap.token";
/** Written when the token is spent, so a restart cannot mint another. */
const SPENT_FILE = "bootstrap.spent";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

/** 32 bytes. Not guessable, and short enough to read off a terminal. */
const TOKEN_BYTES = 32;

export function tokenPath(dir: string = secretsDir()): string {
  return join(dir, TOKEN_FILE);
}

export function spentPath(dir: string = secretsDir()): string {
  return join(dir, SPENT_FILE);
}

export const BOOTSTRAP_STATES = ["unclaimed", "claimed"] as const;
export type BootstrapState = (typeof BOOTSTRAP_STATES)[number];

/**
 * Whether this installation has been claimed.
 *
 * Derived from the spent marker alone, never from the token's presence. A
 * missing token on an unclaimed installation is a token that has not been
 * minted yet; a missing token on a claimed one is the steady state. Conflating
 * them is how the endpoint reopens.
 */
export function bootstrapState(dir: string = secretsDir()): BootstrapState {
  return existsSync(spentPath(dir)) ? "claimed" : "unclaimed";
}

/**
 * Mint the token if this installation is unclaimed and has none.
 *
 * Idempotent: called on every boot, does nothing after the first. Returns the
 * token so first boot can print it, and null when there is nothing to print.
 */
export function mintBootstrapToken(dir: string = secretsDir()): string | null {
  if (bootstrapState(dir) === "claimed") return null;

  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  chmodSync(dir, DIR_MODE);

  const path = tokenPath(dir);
  if (existsSync(path)) {
    // Already minted and not yet spent. Returned rather than regenerated: an
    // operator who wrote it down during a previous boot must not find it
    // silently invalidated by a restart.
    assertNotReadableByOthers(path);
    return readFileSync(path, "utf8").trim();
  }

  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  writeFileSync(path, `${token}\n`, { mode: FILE_MODE });
  chmodSync(path, FILE_MODE);
  return token;
}

function assertNotReadableByOthers(path: string): void {
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(
      `${path} is mode ${mode.toString(8)}. The bootstrap token is the authority to claim this ` +
        `installation; anything group- or world-readable hands that authority to every local account.`,
    );
  }
}

/**
 * Does `presented` match the live token?
 *
 * False for every reason: claimed already, never minted, wrong value. The caller
 * renders all of them identically — a response that distinguished "already
 * claimed" from "wrong token" would tell an unauthenticated caller whether the
 * installation is worth attacking.
 */
export function bootstrapTokenMatches(presented: string, dir: string = secretsDir()): boolean {
  if (bootstrapState(dir) === "claimed") return false;

  const path = tokenPath(dir);
  if (!existsSync(path)) return false;
  assertNotReadableByOthers(path);

  const expected = readFileSync(path, "utf8").trim();
  if (expected.length === 0) return false;

  // Constant-time, through the one comparison in the codebase that is. The
  // token is a secret checked against a submitted value, which is the case that
  // function exists for.
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && secretEquals(a, b);
}

/**
 * Close the endpoint, permanently.
 *
 * The marker is written BEFORE the token is removed. If the process dies
 * between the two, the installation reads as claimed with a stale token file —
 * which `bootstrapTokenMatches` refuses, because it consults the marker first.
 * The other order would leave it unclaimed with no token, and the next boot
 * would mint a fresh one and reopen the endpoint.
 */
export function spendBootstrapToken(dir: string = secretsDir()): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  writeFileSync(spentPath(dir), `claimed at ${new Date().toISOString()}\n`, { mode: FILE_MODE });
  rmSync(tokenPath(dir), { force: true });
}
