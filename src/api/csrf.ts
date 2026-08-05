/**
 * Cross-site request forgery (RL-M1-021, threat model R-11 and R-21).
 *
 * Brief §6.7 names CSRF in the minimum security suite. The attack: a page the
 * operator did not write causes their browser to issue a state-changing request
 * to Ratline, and the browser attaches the session cookie because it always
 * does. The attacker never reads the response and does not need to — `DELETE
 * /organization` is worth issuing blind.
 *
 * The whole module is data and pure functions over the pieces of a request it
 * needs, for `src/api/routes.ts`'s reason: there is no HTTP server yet, and a
 * defence expressed as framework middleware could not be tested until one
 * existed. {@link checkCsrf} takes a method, some headers, a URL and a session,
 * and returns a verdict. A framework binds to it later and cannot change what it
 * decides.
 *
 * ## 1. Why a token at all, when SameSite exists
 *
 * `SameSite=Strict` (§4 below) already stops the browser attaching the cookie to
 * a cross-site request, so on a browser that honours it the token is redundant.
 * The token is here because the cookie attribute is enforced by the *client* and
 * this is a control plane: the population of browsers reaching a self-hosted
 * install is not one we choose, an embedded webview or a corporate browser build
 * is not something to bet the audit log on, and "the browser was supposed to
 * stop that" is not a sentence to write in an incident review. So the server
 * decides, and SameSite is the second lock rather than the only one.
 *
 * ## 2. The token is DERIVED, not stored — and there is no migration
 *
 * A per-session random token in a new table is the obvious shape. It was
 * rejected. What it buys is the ability to revoke a token independently of the
 * session, and there is no case for that: a token that outlives its session is
 * useless, and a session that outlives its token is a session whose owner cannot
 * act. Two lifetimes with one meaning is a synchronisation bug waiting to be
 * written, and it would put an extra statement on the path of every mutating
 * request.
 *
 * Instead:
 *
 *     token = base64url(HMAC-SHA256(K, session.id))
 *     K     = HKDF-SHA256(cookie secret, info = "ratline/csrf/v1")
 *
 * The properties fall out rather than being maintained:
 *
 *   - **Bound to the session, not global.** The session id is the message, so a
 *     token minted for one session verifies against no other. C4 already
 *     guarantees the key exists and has no default (`src/crypto/secrets.ts`),
 *     which is what makes this unforgeable — CloudPanel's CVE-2023-35885 is the
 *     counter-example, and it is the same key.
 *   - **Rotation invalidates it for free.** Migration 10 note 4 makes rotation a
 *     NEW ROW with a new id rather than an edit, so the token derived from the
 *     retired session simply does not verify against the successor. Nothing has
 *     to remember to rotate the token alongside the identifier, and "nothing has
 *     to remember" is the only kind of coupling that survives. See §5.
 *   - **Nothing is stored, so nothing leaks.** A database backup contains no
 *     usable CSRF token, for the same reason it contains no usable session
 *     identifier (migration 10 note 2).
 *
 * The cost, stated rather than discovered later and carried as **R-22**: the
 * token is constant for the life of a session. It is not a nonce and replay by
 * its own session is not an
 * attack — the legitimate client replays it on every request. What matters is
 * that a cross-site attacker cannot LEARN it, which is why §3 keeps it out of
 * cookies and why a token in a query string is a refusal rather than an
 * oversight (a URL reaches access logs, `Referer` headers and browser history,
 * and a leak that lasts the whole session is worth refusing loudly over).
 *
 * Rotating the cookie secret invalidates every outstanding token, which is
 * correct: it also invalidates every signed cookie, so the sessions are going
 * anyway.
 *
 * ## 3. A synchronizer token in a HEADER, not a double-submit cookie
 *
 * Double-submit — put the token in a readable cookie, have JavaScript copy it
 * into a header, compare the two — needs no server-side binding at all. Its
 * security rests entirely on the attacker being unable to write a cookie on the
 * site's domain, and on a self-hosted install that assumption is weak: Ratline
 * sits at `ratline.internal.example.com` next to whatever else the team runs,
 * and any of those neighbours can set a `Domain=.internal.example.com` cookie
 * that Ratline cannot distinguish from its own. Deriving the expected value from
 * the session server-side does not care what the attacker can write.
 *
 * The token is presented in the {@link CSRF_HEADER} request header, and only
 * there. A cross-origin page cannot add a custom header to a form POST without a
 * CORS preflight the server never answers, so requiring a header is a second,
 * independent barrier that costs nothing. The deliberate consequence: **a plain
 * `<form>` post with no JavaScript cannot be authorized.** Ratline's interface is
 * a scripted application (§6.6, ADR 0001), so this rules out a shape the product
 * does not have.
 *
 * ## 4. The cookie policy, which is where the deployment model bites
 *
 * C5 means Ratline is commonly served two ways: plain HTTP on loopback (the
 * default), and HTTPS behind a reverse proxy on a real domain. One hardcoded
 * policy is wrong for one of them, so it is derived — but NOT from the bind
 * address, and that is the important part.
 *
 * **Threat-model R-11 makes inference from the bind address actively
 * dangerous.** A control plane bound to 127.0.0.1 behind a TLS-terminating nginx
 * is the ordinary production shape, and `src/config/network.ts` reports it
 * `contained` because a local check cannot see the proxy. Deriving "loopback, so
 * drop Secure" from that would hand the *most* exposed deployment the *weakest*
 * cookie. The inference is not merely imperfect, it is anti-correlated with the
 * truth.
 *
 * So the policy is derived from something only an operator can know — the origin
 * they actually type into a browser, declared as `RATLINE_PUBLIC_ORIGIN` — and
 * the same declaration is what §6's origin check compares against. One fact,
 * stated once, used twice; there is no second setting to disagree with the first.
 *
 * `Secure` is on by default and stays on unless `RATLINE_ALLOW_INSECURE_COOKIES`
 * is set. That acknowledgement is the ONLY way to a non-Secure session cookie:
 * an argued decision an operator typed, mirroring `RATLINE_ALLOW_PUBLIC_BIND`,
 * and it carries a warning the boot path and the dashboard banner must show. A
 * deployment reached over plain HTTP on a real network therefore breaks loudly
 * — the browser will not store the cookie and the operator gets a message naming
 * the remedy — rather than being silently downgraded. Loud and broken is the
 * direction to fail in; §4's constraints exist because the quiet direction is how
 * every product in this space got its CVE.
 *
 * `SameSite` is `Strict` everywhere and is not configurable, because the only
 * use for a knob here is weakening it. The cost is real and worth naming: a link
 * from a chat alert into the dashboard arrives with no cookie and lands on the
 * sign-in page, at 2am, which is the moment §3.3 says to optimise for. The
 * remedy is the interface's, not this module's — the sign-in screen bounces an
 * already-live session through a same-site redirect, which does carry the cookie
 * — and it is listed as owed at the bottom of this file. `Lax` would remove the
 * bounce and would let a cross-site top-level GET carry the session; every route
 * in the table that changes state is a non-GET today, so `Lax` would be *nearly*
 * as good, and "nearly" is not the trade to take on the cheap half of the
 * defence.
 *
 * ADR 0016 records all of this and is `proposed`: the browser behaviour behind
 * "Secure on http://127.0.0.1" and the operator cost of `Strict` are product
 * decisions, not implementation details, and §2.6 says the owner accepts them.
 *
 * ## 5. Session rotation
 *
 * `src/auth/privilege_changes.ts` rotates a session whenever what its holder may
 * do changes. Because the token names the session ROW, rotation retires the
 * token in the same instant and by the same mechanism — there is no second
 * invalidation to get wrong. The consequence for a client is one failed request:
 * the token it holds names a session that no longer exists. That is the correct
 * failure (the alternative is a token that outlives a privilege change), and the
 * interface closes it by returning {@link csrfTokenHeader} on the rotation
 * response, which is also listed as owed below.
 *
 * ## 6. Origin, and why it is checked at all
 *
 * The token alone is sufficient against an attacker who cannot read it. The
 * origin check is cheap defence in depth against the cases where that assumption
 * cracks — a token leaked into a log, an XSS that can read the page but not
 * forge a same-origin request, a browser that mishandles preflight. It compares
 * `Origin` (falling back to `Referer`, which some deployments strip) against the
 * declared trusted set, exactly; there is no suffix matching, because
 * `ratline.example.com.attacker.test` is how suffix matching always ends.
 *
 * An unsafe request with neither header is REFUSED. Every browser sends `Origin`
 * on an unsafe method; a client that does not is not a browser, and a non-browser
 * client should be presenting an API token rather than riding a cookie session —
 * at which point CSRF does not apply to it and neither does this module.
 *
 * R-21's warning applies here unchanged and inverted: that risk is about
 * trusting a forwarded header to say where a request CAME FROM. `Origin` is
 * safe to read for this purpose precisely because we never believe a *claim of
 * trust* from it — an attacker can put anything in it, and anything that is not
 * in the operator's declared set is refused.
 *
 * ## Deliberately not done
 *
 *   - **No per-request token.** It needs server state (§2), buys nothing against
 *     an attacker who cannot read the token at all, and breaks concurrent
 *     requests and the back button. Rejected on the merits, not skipped.
 *   - **No CSRF cookie.** See §3.
 *   - **No route-level opt-out.** `isSafeMethod` in `src/api/routes.ts` is the
 *     single source of truth for what needs no token, and it is not duplicated
 *     here. A route that wants an exemption has to argue for it there, where the
 *     matrix generator can see it.
 *   - **No `Referer`-only mode and no origin allowlist wildcards.**
 */

import { createHmac, hkdfSync } from "node:crypto";
import { isIPv6 } from "node:net";

import type { Session } from "../auth/model.ts";
import type { AuthzContext } from "../authz/context.ts";
import type { AuditEvent } from "../authz/audit_events.ts";
import {
  classifyAddress,
  resolveBindAddress,
  resolvePort,
} from "../config/network.ts";
import { secretEquals } from "../crypto/secrets.ts";
import { weakSecretBytesReason } from "../crypto/weak-secrets.ts";
import { recordAudit } from "../repo/audit.ts";
import { isSafeMethod, type HttpMethod } from "./routes.ts";

/**
 * A cookie secret that cannot key anything (C4, RL-M1-054).
 *
 * Its own class rather than a plain Error so `createServer` can refuse at
 * construction with the same type the derivation throws, and so a caller can tell
 * "the secret is unusable" from any other failure — the two need different
 * responses, and only one of them is a configuration mistake.
 */
export class WeakCookieSecret extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WeakCookieSecret";
  }
}

// ---------------------------------------------------------------------------
// Where the token travels
// ---------------------------------------------------------------------------

/**
 * The request header carrying the token, and the response header handing a
 * fresh one back.
 *
 * One name for both directions so a client never has to know two. Lowercase
 * because that is how Node presents incoming header names, and comparisons here
 * are case-insensitive regardless.
 */
export const CSRF_HEADER = "x-ratline-csrf";

/**
 * The query parameter name that must NOT appear.
 *
 * There is no supported way to pass the token in a URL. This constant exists so
 * that passing one is DETECTED rather than merely ineffective: a token in a
 * query string has already reached the access log, the `Referer` of every
 * outbound link on the page, and the browser's history, and because the token
 * lasts as long as the session (§2) that leak does not expire. Refusing makes
 * the client bug visible; ignoring it would hide the leak forever.
 */
export const CSRF_PARAMETER = "csrf_token";

// ---------------------------------------------------------------------------
// The token
// ---------------------------------------------------------------------------

/** Domain separation, so this use of the cookie secret cannot collide with any other. */
const CSRF_KEY_INFO = "ratline/csrf/v1";

/** Bytes of derived key. 256 bits, matching the HMAC it keys. */
const CSRF_KEY_BYTES = 32;

/**
 * The shortest cookie secret this will accept.
 *
 * `src/crypto/secrets.ts` already refuses to boot on anything shorter, so this
 * can only fire when a caller passes something the secret store did not produce
 * — an empty buffer, a truncated read. It is checked anyway because the failure
 * it prevents is silent: HKDF is perfectly happy with a zero-length key, and the
 * result would be a token every installation on earth could compute.
 *
 * RL-M1-054: length was the ONLY thing checked here, and the sentence above says
 * why that was not enough — a 32-byte secret of all zeros is exactly "a token
 * every installation on earth could compute", and it passed. The check is now
 * `weakSecretBytesReason`, the same judgement `secrets.ts` applies to a secret
 * loaded from disk, so the two paths cannot disagree about what is acceptable.
 */
const MINIMUM_SECRET_BYTES = 32;

/**
 * The subkey. Derived rather than using the cookie secret directly so that
 * signing a cookie and minting a token are provably independent uses of one
 * stored key — a property that costs three microseconds and removes a whole
 * class of argument about cross-protocol interaction.
 */
/**
 * Refuse a cookie secret that cannot key anything (C4, RL-M1-054).
 *
 * Exported so `createServer` can apply it at construction. Both callers matter and
 * neither is redundant: this one is the derivation refusing to produce a
 * guessable token, and the construction-time one closes the window in which a
 * server built with a dead secret looks healthy until somebody signs in.
 */
export function assertUsableCookieSecret(cookieSecret: Uint8Array): void {
  const weak = weakSecretBytesReason(cookieSecret, MINIMUM_SECRET_BYTES);
  if (weak === null) return;
  throw new WeakCookieSecret(
    `the cookie secret is unusable: ${weak}. Load it through src/crypto/secrets.ts, which ` +
      `generates and refuses on the same rules — a predictable secret here is a CSRF token ` +
      `every installation on earth can compute.`,
  );
}

function csrfKey(cookieSecret: Uint8Array): Buffer {
  assertUsableCookieSecret(cookieSecret);
  return Buffer.from(hkdfSync("sha256", cookieSecret, Buffer.alloc(0), CSRF_KEY_INFO, CSRF_KEY_BYTES));
}

/**
 * The token for one session. Deterministic: the same session always yields the
 * same token, and no other session yields it.
 *
 * Takes the session ID rather than the session so that a caller cannot
 * accidentally bind to something mutable on the record — `lastSeenAt` changes on
 * every request, and a token that changed with it would be a token that never
 * verified.
 */
export function csrfTokenForSessionId(cookieSecret: Uint8Array, sessionId: string): string {
  return createHmac("sha256", csrfKey(cookieSecret)).update(sessionId, "utf8").digest("base64url");
}

/** The response header handing a session its token. */
export function csrfTokenHeader(
  cookieSecret: Uint8Array,
  session: Session,
): { readonly name: string; readonly value: string } {
  return { name: CSRF_HEADER, value: csrfTokenForSessionId(cookieSecret, session.id) };
}

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

/**
 * Reduce an origin or a full URL to a comparable origin string.
 *
 * Scheme and host lowercased, default ports dropped, everything else discarded.
 * Null for anything that is not an http(s) origin — which includes the literal
 * string `"null"` a browser sends for an opaque origin (a sandboxed iframe, some
 * redirect chains). That must not match anything, and it does not, because it
 * does not parse.
 *
 * Both sides of the comparison go through here, so the trusted set and the
 * observed header are normalised by the same code and cannot disagree about
 * whether `:443` is written down.
 */
export function normaliseOrigin(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    // Not a URL. There is nothing to salvage and guessing is how an allowlist
    // becomes a suffix match.
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const scheme = url.protocol.slice(0, -1);
  const defaultPort = scheme === "https" ? "443" : "80";
  const port = url.port === "" || url.port === defaultPort ? "" : `:${url.port}`;
  const host = url.hostname.toLowerCase();
  if (host === "") return null;
  return `${scheme}://${host}${port}`;
}

/** Whether a normalised origin names this machine. */
function isLoopbackOrigin(origin: string): boolean {
  const host = origin.replace(/^https?:\/\//, "").replace(/:\d+$/, "");
  if (host === "localhost") return true;
  return classifyAddress(host) === "loopback";
}

/**
 * The origins to assume when the operator has declared none.
 *
 * Only ever plain HTTP: an undeclared deployment is the C5 default, and if TLS
 * were terminated in front of it the operator would have had to say so for the
 * cookie policy to be right anyway (§4).
 *
 * The three loopback spellings are all included when the bind is loopback or
 * wildcard, because a browser sends whichever one the operator typed and
 * `localhost`, `127.0.0.1` and `[::1]` all reach the same listener. For any
 * other bind only that address is assumed — adding loopback there would widen
 * the trusted set to an origin the deployment does not serve.
 */
export function defaultTrustedOrigins(bind: string, port: number): readonly string[] {
  const addressClass = classifyAddress(bind);
  if (addressClass === "loopback" || addressClass === "wildcard") {
    return [`http://localhost:${port}`, `http://127.0.0.1:${port}`, `http://[::1]:${port}`];
  }
  const host = isIPv6(bind) ? `[${bind}]` : bind;
  return [`http://${host}:${port}`];
}

/**
 * The origins a state-changing request may come from.
 *
 * `RATLINE_PUBLIC_ORIGIN` is a comma-separated list, because one deployment is
 * routinely reached by more than one name — `https://ratline.example.com` for
 * everybody and `http://127.0.0.1:7712` for whoever is on the box.
 *
 * A declared origin that does not parse THROWS rather than being dropped.
 * Dropping it silently would shrink the trusted set to something that refuses
 * every request, and an operator debugging that has no way to see the typo; the
 * same reasoning `bindRefusal` applies to a malformed bind address.
 */
export function resolveTrustedOrigins(env: NodeJS.ProcessEnv = process.env): readonly string[] {
  const declared = env["RATLINE_PUBLIC_ORIGIN"];
  const candidates =
    declared === undefined || declared.trim() === ""
      ? defaultTrustedOrigins(resolveBindAddress(env), resolvePort(env))
      : declared.split(",");

  const origins: string[] = [];
  for (const candidate of candidates) {
    if (candidate.trim() === "") continue;
    const origin = normaliseOrigin(candidate);
    if (origin === null) {
      throw new Error(
        `RATLINE_PUBLIC_ORIGIN contains "${candidate.trim()}", which is not an http or https ` +
          `origin. Write it as a scheme and host, e.g. https://ratline.example.com — a value ` +
          `this cannot parse would refuse every state-changing request.`,
      );
    }
    if (!origins.includes(origin)) origins.push(origin);
  }
  return origins;
}

// ---------------------------------------------------------------------------
// The cookie policy (§4)
// ---------------------------------------------------------------------------

/** The session cookie's name without a prefix. */
export const SESSION_COOKIE_NAME = "rl_session";

/**
 * The `__Host-` prefix, which a browser enforces: it refuses to store such a
 * cookie unless it is `Secure`, `Path=/` and has no `Domain`. That last one is
 * the point — it makes the neighbour-subdomain cookie injection §3 rejects
 * double-submit over impossible for the SESSION cookie too.
 *
 * It is applied only when every trusted origin is https. On plain-HTTP loopback
 * browsers disagree about whether the prefix is honoured, and a cookie the
 * browser silently declines to store is a dashboard nobody can sign in to.
 *
 * The name therefore CHANGES with the policy, which is a feature: flipping the
 * policy does not weaken existing cookies, it stops resolving them.
 */
export const HOST_COOKIE_PREFIX = "__Host-";

export type CookiePolicy = {
  /** The session cookie's name under this policy. */
  readonly name: string;
  readonly secure: boolean;
  /** Not configurable. See §4. */
  readonly sameSite: "Strict";
  readonly httpOnly: true;
  readonly path: "/";
  /** Operator-facing headline. Non-null whenever a banner must be shown. */
  readonly warning: string | null;
};

/** Whether the operator has explicitly given up the Secure attribute. */
export function insecureCookiesAcknowledged(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env["RATLINE_ALLOW_INSECURE_COOKIES"];
  return value === "1" || value?.toLowerCase() === "true";
}

/**
 * Derive the cookie policy from the declared origins.
 *
 * The only input that can turn `Secure` off is `acknowledged`. Everything else
 * — the bind address, the exposure level, what the origins look like — can only
 * change the NAME and the WARNING, never the attribute. See §4 for why the
 * tempting inference is the wrong one.
 */
export function cookiePolicy(
  trustedOrigins: readonly string[],
  acknowledged: boolean,
): CookiePolicy {
  const base = { sameSite: "Strict", httpOnly: true, path: "/" } as const;

  if (acknowledged) {
    return {
      ...base,
      name: SESSION_COOKIE_NAME,
      secure: false,
      warning:
        "Session cookies are being sent WITHOUT the Secure attribute because " +
        "RATLINE_ALLOW_INSECURE_COOKIES is set. Anyone who can observe traffic between a " +
        "browser and this dashboard can take over a signed-in session. Unset it and " +
        "terminate TLS in front of Ratline, or reach it over a tunnel that encrypts the " +
        "transport itself (see docs/NETWORK.md).",
    };
  }

  if (trustedOrigins.length === 0) {
    return {
      ...base,
      name: SESSION_COOKIE_NAME,
      secure: true,
      warning:
        "No trusted origin is configured, so every state-changing request will be refused. " +
        "Set RATLINE_PUBLIC_ORIGIN to the origin operators type into a browser.",
    };
  }

  const cleartext = trustedOrigins.filter(
    (origin) => origin.startsWith("http://") && !isLoopbackOrigin(origin),
  );
  if (cleartext.length > 0) {
    return {
      ...base,
      name: SESSION_COOKIE_NAME,
      secure: true,
      warning:
        `RATLINE_PUBLIC_ORIGIN names ${cleartext.join(", ")}, which is plain HTTP on a real ` +
        `network. The session cookie is still marked Secure, so the browser will refuse to ` +
        `store it and nobody will be able to sign in — deliberately, because the alternative ` +
        `is sending the credential in the clear. Terminate TLS in front of Ratline and declare ` +
        `the https origin, or set RATLINE_ALLOW_INSECURE_COOKIES=1 to accept the risk in ` +
        `writing.`,
    };
  }

  const allHttps = trustedOrigins.every((origin) => origin.startsWith("https://"));
  return {
    ...base,
    name: allHttps ? `${HOST_COOKIE_PREFIX}${SESSION_COOKIE_NAME}` : SESSION_COOKIE_NAME,
    secure: true,
    // No warning for plain HTTP on loopback. That is the sanctioned C5 default,
    // the traffic never leaves the machine, and a banner that is always on is a
    // banner operators learn to look past — which is the failure mode C5's own
    // warning is written to avoid.
    warning: null,
  };
}

/**
 * The `Set-Cookie` attribute string for this policy, without a name or value.
 *
 * Rendered here rather than in a framework adapter so there is one place the
 * attributes are written and one place a test can read them. `Max-Age` is not
 * set on purpose: a session cookie's lifetime is the session's, which is
 * enforced server-side by `live_sessions` (migration 10 note 3), and a browser
 * expiry would only be a second, weaker copy of it.
 */
export function cookieAttributes(policy: CookiePolicy): string {
  const parts = [`Path=${policy.path}`, "HttpOnly", `SameSite=${policy.sameSite}`];
  if (policy.secure) parts.push("Secure");
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/**
 * Why a request was refused.
 *
 * FOR THE AUDIT LOG, NOT FOR THE RESPONSE — the same rule `SIGN_IN_REFUSALS` and
 * `RateLimitDecision.refusedBy` follow. §6.3 requires refusals to be
 * indistinguishable to the caller, so an interface renders every value here as
 * one status and one body. The distinction exists because "a cross-origin page
 * is submitting to us" and "our own client forgot the header after a rotation"
 * are different incidents.
 */
export const CSRF_REFUSALS = [
  /** No live session, so there is nothing a token could be bound to. */
  "unauthenticated",
  /** Neither `Origin` nor `Referer` was present on an unsafe method. */
  "origin-missing",
  /** An origin was present and is not in the declared trusted set. */
  "origin-untrusted",
  /** `Origin` appeared more than once — a browser never does that. */
  "origin-repeated",
  "token-missing",
  "token-repeated",
  /** The token was in the URL, where it leaks. See {@link CSRF_PARAMETER}. */
  "token-in-query",
  "token-mismatch",
] as const;

export type CsrfRefusal = (typeof CSRF_REFUSALS)[number];

/** Header names to values, as any framework can produce them. Case-insensitive. */
export type HeaderBag = Readonly<Record<string, string | readonly string[] | undefined>>;

export type CsrfRequest = {
  readonly method: HttpMethod;
  readonly headers: HeaderBag;
  /**
   * The request target as received — `/grants?x=1`, or an absolute URL. Only the
   * query string is read, and only to refuse a token hiding in it.
   */
  readonly url: string;
};

export type CsrfVerdict =
  | {
      readonly ok: true;
      /** True when the method is safe and no token was required. */
      readonly exempt: boolean;
    }
  | {
      readonly ok: false;
      readonly refusal: CsrfRefusal;
      /** What the request claimed, normalised, or null. For the audit entry. */
      readonly observedOrigin: string | null;
    };

export type CsrfOptions = {
  readonly cookieSecret: Uint8Array;
  readonly trustedOrigins: readonly string[];
};

/** Every value for one header name, flattened. Empty when it was not sent. */
function headerValues(headers: HeaderBag, name: string): readonly string[] {
  const wanted = name.toLowerCase();
  const found: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted || value === undefined) continue;
    if (typeof value === "string") found.push(value);
    else found.push(...value);
  }
  return found;
}

/** The query string, whether the URL is absolute or a bare path. */
function queryOf(url: string): URLSearchParams {
  const index = url.indexOf("?");
  return new URLSearchParams(index < 0 ? "" : url.slice(index + 1));
}

const refuse = (refusal: CsrfRefusal, observedOrigin: string | null = null): CsrfVerdict => ({
  ok: false,
  refusal,
  observedOrigin,
});

/**
 * Decide whether this request may change state. Pure; no database, no clock, no
 * framework.
 *
 * The order of the checks is the order of cost and of usefulness to an incident
 * review, not a security property — every refusal renders identically to the
 * caller, so which one fires first only changes what the audit entry says.
 */
export function checkCsrf(
  request: CsrfRequest,
  session: Session | null,
  options: CsrfOptions,
): CsrfVerdict {
  // `isSafeMethod` is the single source of truth (src/api/routes.ts), and it is
  // consulted rather than copied. A method list duplicated here is a method list
  // that eventually disagrees, and it would disagree in the direction of
  // exempting something that changes state.
  if (isSafeMethod(request.method)) return { ok: true, exempt: true };

  // Checked after the method, not before: an unauthenticated GET is an
  // authentication question, not a CSRF one.
  if (session === null) return refuse("unauthenticated");

  const origins = headerValues(request.headers, "origin");
  if (origins.length > 1) return refuse("origin-repeated");

  // `Referer` only as a fallback. Some deployments and privacy tools strip it,
  // and it carries a path we have no use for; `Origin` is the header browsers
  // send on every unsafe method and the one to believe when both are present.
  const referers = origins.length === 0 ? headerValues(request.headers, "referer") : [];
  const claimed = origins[0] ?? referers[0];
  if (claimed === undefined) return refuse("origin-missing");

  const observed = normaliseOrigin(claimed);
  if (observed === null || !options.trustedOrigins.includes(observed)) {
    return refuse("origin-untrusted", observed);
  }

  // Before the token is even looked for: a token in the URL has already leaked,
  // and accepting the request because a valid one was ALSO in the header would
  // leave the leak in place forever.
  if (queryOf(request.url).has(CSRF_PARAMETER)) return refuse("token-in-query", observed);

  const presented = headerValues(request.headers, CSRF_HEADER);
  if (presented.length > 1) return refuse("token-repeated", observed);
  const token = presented[0] ?? "";
  if (token === "") return refuse("token-missing", observed);

  const expected = csrfTokenForSessionId(options.cookieSecret, session.id);
  // Constant-time, through the one comparison in the codebase that is
  // (src/crypto/secrets.ts). The token is a secret checked against a submitted
  // value, which is exactly the case that function exists for: a byte-by-byte
  // comparison that returns early leaks the correct prefix, and this token is
  // stable for the life of the session, so an attacker gets unlimited attempts
  // at recovering it one byte at a time.
  if (!secretEquals(Buffer.from(token, "utf8"), Buffer.from(expected, "utf8"))) {
    return refuse("token-mismatch", observed);
  }

  return { ok: true, exempt: false };
}

// ---------------------------------------------------------------------------
// The audited entry point (C6)
// ---------------------------------------------------------------------------

/**
 * The audit action a refusal is recorded under. An event, not a permission.
 *
 * Typed as an `AuditEvent` (RL-M1-036), so the name is drawn from the closed
 * audit vocabulary rather than written here as a string. Nobody holds this and
 * no role could carry it — which is exactly why it cannot live in the
 * permission catalogue, and exactly why it needed a closed set of its own.
 */
export const CSRF_AUDIT_ACTION: AuditEvent = "session.csrf_rejected";

/** Attacker-controlled text going into a log people read. Bounded. */
const MAX_LOGGED_ORIGIN = 256;

export type GuardedRequest = CsrfRequest & {
  /**
   * The route template this request matched — `/grants/:grantId`, not
   * `/grants/8f2…`. The template, because a raw path carries identifiers and
   * sometimes secrets, and the audit log is handed to people during incidents
   * (ADR 0006).
   */
  readonly routeKey: string;
};

/**
 * Decide, and record a refusal. THE FUNCTION A REQUEST PATH CALLS.
 *
 * The audit write is folded into the decision rather than left to the caller,
 * for the reason `useSessionToken` folds last-seen into the session lookup
 * (`src/repo/sessions.ts`): a separate call is a call that can be forgotten — by
 * a new route, by a middleware reordering, by anyone who did not know it
 * existed. C6 says a refused attempt is auditable, and a refused CSRF attempt is
 * precisely what an incident review goes looking for, so it must not depend on
 * remembering.
 *
 * The `unauthenticated` refusal is NOT audited, and that is deliberate: there is
 * no session to attribute it to, the authentication layer refuses the request on
 * its own account and records its own entry, and writing one here would let an
 * unauthenticated caller append to the audit log at will.
 */
export async function guardCsrf(
  ctx: AuthzContext,
  request: GuardedRequest,
  session: Session | null,
  options: CsrfOptions,
): Promise<CsrfVerdict> {
  const verdict = checkCsrf(request, session, options);
  if (verdict.ok || session === null) return verdict;

  await recordAudit(ctx, {
    action: CSRF_AUDIT_ACTION,
    resourceType: "session",
    resourceId: session.id,
    decision: "deny",
    reason: verdict.refusal,
    // The presented token is NEVER recorded. It is a credential, and the audit
    // log is read by more people than hold it.
    metadata: {
      method: request.method,
      route: request.routeKey,
      origin: verdict.observedOrigin?.slice(0, MAX_LOGGED_ORIGIN) ?? null,
    },
  });

  return verdict;
}

// ---------------------------------------------------------------------------
// What the interface layer still owes — whoever builds src/api/server.ts
//
// Written here rather than in a commit message, because a check nobody calls
// checks nothing, and this list is the difference between "CSRF protection
// exists" and "state-changing requests are protected". Nothing calls any of it
// today; that is R-23, and it stays open until this list is worked through.
//
//   1. CALL `guardCsrf` ON EVERY REQUEST, AFTER RESOLVING THE SESSION AND
//      BEFORE THE HANDLER. Not per-route and not opt-in: the default has to be
//      protected, or the one route somebody forgets is the one that matters.
//      `isSafeMethod` already exempts what should be exempt.
//
//   2. SET THE COOKIE FROM `cookiePolicy`, AND SHOW ITS WARNING. The name comes
//      from the policy too — it changes with the policy on purpose (see
//      HOST_COOKIE_PREFIX), so read it rather than writing "rl_session" in a
//      handler. The warning belongs next to C5's exposure banner; both describe
//      the same deployment and an operator should see them together.
//
//   3. RETURN `csrfTokenHeader` ON EVERY AUTHENTICATED RESPONSE, and especially
//      on the sign-in and rotation responses. After a rotation the client's
//      token names a session that no longer exists (§5), so a response that does
//      not carry the new one costs the operator a failed request at the worst
//      possible moment.
//
//   4. RENDER EVERY REFUSAL IDENTICALLY. One status (403), one body. `refusal`
//      is for the log; a response that distinguished "no token" from "wrong
//      token" would tell an attacker which half of the defence they had reached.
//
//   5. BOUNCE A LIVE SESSION THROUGH A SAME-SITE REDIRECT ON THE SIGN-IN SCREEN.
//      This is the cost of SameSite=Strict (§4): a deep link from a chat alert
//      arrives with no cookie. A sign-in page that immediately redirects
//      same-site — which does carry the cookie — turns "logged out at 2am" into
//      one extra round trip. Without it, Strict is a UX regression operators
//      will ask to have removed.
//
//   6. DO NOT TRUST A FORWARDED HEADER FOR THE ORIGIN, and do not derive the
//      trusted set from `Host`. The declared origin is configuration for the
//      reason §4 gives, and R-21 is the same mistake made about source
//      addresses.
//
//   7. API TOKENS ARE NOT COOKIES. A request authenticated by an `Authorization`
//      header is not reachable by a cross-site page — the browser will not attach
//      that header on its own — so CSRF does not apply and this module should not
//      be consulted for it. Applying it anyway would break every CI client for no
//      gain.
// ---------------------------------------------------------------------------
