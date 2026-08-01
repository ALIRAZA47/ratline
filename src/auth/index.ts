/**
 * Authentication (RL-M1-017).
 *
 * Password hashing, session identifiers, and the lifecycle an interface drives:
 * sign in, validate, rotate, revoke.
 *
 * The split inside this directory is deliberate and is not organisational
 * tidiness:
 *
 *   - `passwords.ts` — the memory-hard hash and the constant-time comparison.
 *     Touches nothing but `node:crypto`, so it can be reasoned about, and
 *     mutation-tested, without a database.
 *   - `model.ts`     — the vocabulary shared by the logic and the queries:
 *     identifier minting, the digest, the ending reasons, the session shape.
 *   - `sessions.ts`  — the order things happen in, and why.
 *
 * Every query lives in `src/repo/sessions.ts`, because C3 keeps the database
 * handle out of reach of everything except the repository layer (ADR 0003).
 *
 * There is no interface layer yet and nothing here invents one. What an
 * interface still owes, on top of these functions: cookie attributes
 * (`HttpOnly`, `Secure`, `SameSite`, `Path`, `__Host-` prefix), CSRF
 * (RL-M1-021), rate limiting on every authentication route including password
 * reset (RL-M1-020), and a context for a request that has not authenticated yet
 * — see the header of `sessions.ts` for that last one, which is a real seam
 * rather than an oversight.
 */

export * from "./model.ts";
export * from "./passwords.ts";
export * from "./sessions.ts";
