/**
 * Challenges in flight (RL-M2-005, ADR 0002 as amended by A-04).
 *
 * A-04's binding property is that a signature answering one connection cannot answer
 * another. Over HTTP there is no connection to hang that on — request and response are
 * separate exchanges — so the challenge has to live somewhere between being issued and
 * being answered, and where it lives decides what the property actually means.
 *
 * ## In memory, single use, and the limitation that implies
 *
 * A challenge is held here, keyed by an opaque handle returned to the agent, and
 * CONSUMED on first read. So "bound to the connection" becomes "bound to the exchange
 * that requested it": only the holder of the handle can answer, and only once. A
 * captured answer is worthless because its challenge is already gone.
 *
 * THE LIMITATION, stated rather than discovered: this is one process's memory. A control
 * plane running two processes behind a load balancer would issue a challenge in one and
 * receive the answer in the other, which would fail — the agent would see intermittent
 * authentication errors that look like a revoked key. Ratline is a single self-hosted
 * process today (`src/main.ts` calls `serve` once), so this is true rather than merely
 * assumed, and it is written here because the day somebody adds a second process is the
 * day this becomes a bug with a confusing symptom.
 *
 * The alternative — a challenge the control plane SIGNS, so it needs no server state —
 * would scale and would need its own replay store to stay single-use, which is the same
 * problem moved rather than solved. Recorded as the way out if a second process ever
 * arrives.
 *
 * ## Bounded, for the same reason the agent's nonce store is
 *
 * An unauthenticated caller can ask for a challenge. If issuing one allocated memory
 * that nothing reclaimed, asking repeatedly would be a denial of service with no
 * credential required at all — the cheapest possible attack on the control plane. So the
 * store has a ceiling and prunes expired entries before refusing.
 *
 * It REFUSES rather than evicting, for the reason the nonce store does: evicting the
 * oldest would let a flood choose which legitimate agent's challenge is forgotten, which
 * turns a denial of service into an authentication failure somebody has to diagnose.
 */

import { randomBytes, timingSafeEqual } from "node:crypto";

import { issueChallenge, type Challenge } from "../crypto/host_identity.ts";

/**
 * The ceiling.
 *
 * Sized against real use: one challenge per host per connection, and a challenge lives
 * 30 seconds. A thousand hosts all reconnecting at once is 1000 entries. Ten thousand is
 * an order of magnitude past that and still trivial memory, so the ceiling is only
 * reachable by something abnormal.
 */
export const MAX_IN_FLIGHT = 10_000;

export class TooManyChallenges extends Error {
  constructor(count: number) {
    super(
      `${String(count)} challenges are already in flight, which is abnormal — a challenge ` +
        `lives 30 seconds and is consumed on first use. Something is asking for them faster ` +
        `than any real fleet reconnects. Refusing rather than forgetting a legitimate agent's.`,
    );
    this.name = "TooManyChallenges";
  }
}

export type Handle = string;

export type ChallengeStore = {
  /** Issue a challenge and return the handle the agent must present with its answer. */
  issue(now?: number): { readonly handle: Handle; readonly challenge: Challenge };
  /**
   * Take the challenge for a handle, removing it.
   *
   * TAKE, not read: single use is what makes an answer unrepeatable, and a `read` that
   * left the entry behind would need every caller to remember to delete it. One of them
   * eventually would not.
   */
  take(handle: Handle, now?: number): Challenge | null;
  /** How many are in flight. For tests and for host health. */
  size(): number;
};

export function createChallengeStore(): ChallengeStore {
  const inFlight = new Map<Handle, Challenge>();

  const prune = (now: number): void => {
    for (const [handle, challenge] of inFlight) {
      if (challenge.expiresAt <= now) inFlight.delete(handle);
    }
  };

  return {
    issue(now = Date.now()) {
      if (inFlight.size >= MAX_IN_FLIGHT) {
        prune(now);
        if (inFlight.size >= MAX_IN_FLIGHT) throw new TooManyChallenges(inFlight.size);
      }

      // 32 bytes, so a handle cannot be guessed. It is not a secret in the sense the
      // challenge is — it names an entry rather than proving anything — but a guessable
      // handle would let an attacker consume another agent's challenge and turn its
      // authentication into a retry.
      const handle = randomBytes(32).toString("base64url");
      const challenge = issueChallenge(now);
      inFlight.set(handle, challenge);
      return { handle, challenge };
    },

    take(handle, now = Date.now()) {
      // Constant-time lookup would need a linear scan, and a Map get is not constant
      // time in the handle. That is acceptable here in a way it is not for the nonce:
      // the handle is 32 random bytes with no structure to learn incrementally, so
      // timing reveals only whether an entry exists — which the response says anyway.
      const found = inFlight.get(handle);
      if (found === undefined) return null;

      // Removed whether or not it is still valid. An expired challenge that stayed in
      // the map would be a slot a legitimate agent could not use, and returning it after
      // expiry is the caller's refusal to make, not ours to prevent by hiding it.
      inFlight.delete(handle);
      if (found.expiresAt <= now) return null;

      return found;
    },

    size: () => inFlight.size,
  };
}

/**
 * Compare two handles in constant time.
 *
 * Exported for the one place that needs it — a caller comparing a presented handle
 * against a known one, rather than looking it up. Kept here so there is one
 * implementation of "these two handles are equal" instead of a `===` somewhere that
 * happens to be fine until the value it compares becomes a secret.
 */
export function sameHandle(a: Handle, b: Handle): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}
