/**
 * Cross-site request forgery (RL-M1-021).
 *
 * Brief §6.7 names CSRF in the minimum security suite, and this file is that
 * entry. The three acceptance criteria map onto it as:
 *
 *   1. Every state-changing request requires a token bound to the session
 *                 -> "every unsafe method needs a token and GET needs none",
 *                    "a token from another session is refused",
 *                    "a token replayed after rotation is refused"
 *   2. Cookies use SameSite and Secure appropriately for the deployment model
 *                 -> the "cookie policy" section, and in particular
 *                    "the policy is not inferred from the bind address"
 *   3. A test proves a cross-origin state-changing request is rejected
 *                 -> "a cross-origin state-changing request is rejected"
 *
 * Three rules this file follows.
 *
 * **Anything touching the database runs against a real one, as `ratline_app`.**
 * The migration connection is the superuser `initdb` created, and a superuser
 * bypasses row-level security unconditionally — so an assertion written on that
 * connection would pass without exercising a policy. Repository calls go through
 * a pool pointed at `ratline_app` (`usingScratch`); raw-SQL assertions go through
 * `asApplicationRole`. Writes on the migration connection are fixture setup and
 * never the thing under test.
 *
 * **Sessions are created through the real repository, not stubbed.** The
 * property under test is that the token is bound to a session ROW, so the row
 * has to be real: `startSession` writes it through `scoped()`, and
 * `rotateSession` retires it the way a privilege change does. Most tests mint the
 * identifier directly rather than signing in, because `signIn` costs a 128 MiB
 * scrypt derivation and proves nothing extra about CSRF — one test does drive
 * the whole sign-in path, so the chain is exercised rather than assumed.
 *
 * **The forged requests are built by hand, header by header.** There is no HTTP
 * server yet (`src/api/server.ts` does not exist and must not) so a request here
 * is the record `checkCsrf` actually consumes. That is not a mock of the thing
 * under test — the module's whole interface IS that record, by the same decision
 * `src/api/routes.ts` makes about the route table.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Client } from "pg";

import {
  checkCsrf,
  cookieAttributes,
  cookiePolicy,
  CSRF_AUDIT_ACTION,
  CSRF_HEADER,
  CSRF_PARAMETER,
  csrfTokenForSessionId,
  csrfTokenHeader,
  defaultTrustedOrigins,
  guardCsrf,
  HOST_COOKIE_PREFIX,
  insecureCookiesAcknowledged,
  normaliseOrigin,
  resolveTrustedOrigins,
  SESSION_COOKIE_NAME,
  type CsrfOptions,
  type CsrfRequest,
  type CsrfVerdict,
  type HeaderBag,
} from "../../src/api/csrf.ts";
import { HTTP_METHODS, isSafeMethod, type HttpMethod } from "../../src/api/routes.ts";
import { mintSessionToken, sessionTokenDigest, type Session } from "../../src/auth/model.ts";
import { rotateSession, signIn, validateSession } from "../../src/auth/sessions.ts";
import { contextForRequest, contextForServiceIdentity, type AuthzContext } from "../../src/authz/context.ts";
import { hashPassword } from "../../src/auth/passwords.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { listAudit } from "../../src/repo/audit.ts";
import { startSession } from "../../src/repo/sessions.ts";
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

/** A fixture key of the right shape. Nothing in `src/` may contain one; a test may. */
const COOKIE_SECRET = randomBytes(32);
const OTHER_COOKIE_SECRET = randomBytes(32);

/** The origin the fixture deployment is reached at. */
const TRUSTED = "https://ratline.example.com";
const ATTACKER = "https://deploys.attacker.test";

const OPTIONS: CsrfOptions = { cookieSecret: COOKIE_SECRET, trustedOrigins: [TRUSTED] };

const PASSPHRASE = "correct horse battery staple";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type Tenant = { readonly orgId: string; readonly ownerId: string; readonly signInIdentityId: string };

async function seedTenant(client: Client, slug: string): Promise<Tenant> {
  const { orgId, userId } = await seedOrganization(client, slug);
  const identity = await client.query<{ id: string }>(
    "insert into service_identities (org_id, name) values ($1, 'sign-in') returning id",
    [orgId],
  );
  return { orgId, ownerId: userId, signInIdentityId: identity.rows[0]?.id ?? "" };
}

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

const requestCtx = (orgId: string, userId: string): AuthzContext =>
  contextForRequest({ orgId, userId, requestId: `rl-${randomUUID()}` });

const signInCtx = (tenant: Tenant): AuthzContext =>
  contextForServiceIdentity({
    orgId: tenant.orgId,
    serviceIdentityId: tenant.signInIdentityId,
    name: "sign-in",
    requestId: `rl-${randomUUID()}`,
  });

/** See the header: the pool is the unprivileged role, once per scratch database. */
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

/**
 * A real session row, without paying for a password derivation.
 *
 * The identifier is minted by the same function sign-in uses and the row is
 * written by the same repository call, so the session is indistinguishable from
 * one a sign-in produced — which is what lets `rotateSession` operate on it.
 */
async function newSession(
  ctx: AuthzContext,
  userId: string,
): Promise<{ session: Session; token: string }> {
  const token = mintSessionToken();
  const session = await startSession(ctx, {
    userId,
    tokenDigest: sessionTokenDigest(token),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    rotatedFrom: null,
    userAgent: "fixture",
    ip: null,
  });
  return { session, token };
}

// ---------------------------------------------------------------------------
// Building requests
// ---------------------------------------------------------------------------

type RequestOverrides = {
  readonly method?: HttpMethod;
  readonly origin?: string | null;
  readonly referer?: string | null;
  readonly token?: string | null;
  readonly url?: string;
  readonly extraHeaders?: HeaderBag;
};

/** A request as a framework would hand one over. Nothing is defaulted silently. */
function request(overrides: RequestOverrides = {}): CsrfRequest {
  const headers: Record<string, string | readonly string[]> = {};
  const origin = overrides.origin === undefined ? TRUSTED : overrides.origin;
  if (origin !== null) headers["origin"] = origin;
  if (overrides.referer != null) headers["referer"] = overrides.referer;
  if (overrides.token != null) headers[CSRF_HEADER] = overrides.token;
  return {
    method: overrides.method ?? "POST",
    url: overrides.url ?? "/grants",
    headers: { ...headers, ...overrides.extraHeaders },
  };
}

/** The refusal, or a failed assertion naming what was allowed instead. */
function refusalOf(verdict: CsrfVerdict): string {
  if (verdict.ok) assert.fail(`expected a refusal, the request was allowed (exempt=${verdict.exempt})`);
  return verdict.refusal;
}

// ---------------------------------------------------------------------------
// Acceptance 3 — THE cross-origin test
// ---------------------------------------------------------------------------

test("a cross-origin state-changing request is rejected", { skip }, async () => {
  // The attack, played out against a real session in a real database: the
  // operator is signed in, an attacker's page in another tab causes their
  // browser to POST to Ratline, and the browser attaches the session cookie
  // because it always does. The forged request therefore carries a VALID
  // session — that is what makes it dangerous — and everything else the
  // attacker could control.
  //
  // Two forms are asserted. The realistic one, where the attacker has no token
  // because they cannot read one. And the stronger one, where they somehow hold
  // a valid token: the origin check must refuse it anyway, or the two halves of
  // the defence are really one half twice.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session, token } = await newSession(ctx, aliceId);

      // The control. Everything identical except where the request came from —
      // otherwise this test could pass because the request was malformed.
      assert.deepEqual(
        checkCsrf(request({ origin: TRUSTED, token: csrfTokenForSessionId(COOKIE_SECRET, session.id) }), session, OPTIONS),
        { ok: true, exempt: false },
        "the same request from our own origin has to be allowed, or this proves nothing",
      );

      assert.equal(
        refusalOf(checkCsrf(request({ origin: ATTACKER }), session, OPTIONS)),
        "origin-untrusted",
        "a cross-origin POST carrying a live session was allowed — this is CSRF",
      );

      assert.equal(
        refusalOf(
          checkCsrf(
            request({ origin: ATTACKER, token: csrfTokenForSessionId(COOKIE_SECRET, session.id) }),
            session,
            OPTIONS,
          ),
        ),
        "origin-untrusted",
        "a leaked token must not buy a cross-origin request",
      );

      // A neighbour that merely starts the same way. Suffix matching is how an
      // origin allowlist always fails, so it is pinned rather than assumed.
      assert.equal(
        refusalOf(checkCsrf(request({ origin: `${TRUSTED}.attacker.test` }), session, OPTIONS)),
        "origin-untrusted",
      );

      // An opaque origin — what a sandboxed iframe and some redirect chains
      // send. It is the literal string "null" and must match nothing.
      assert.equal(refusalOf(checkCsrf(request({ origin: "null" }), session, OPTIONS)), "origin-untrusted");

      // And the session the forgery rode in on is untouched by any of it.
      assert.notEqual(await validateSession(ctx, token), null);
    });
  });
});

test("an unsafe request with no origin at all is refused", { skip }, async () => {
  // Every browser sends `Origin` on an unsafe method. A client that does not is
  // not a browser, and a non-browser client should be presenting an API token
  // rather than riding a cookie session. Failing closed here is free.
  //
  // `Referer` is accepted as a fallback because some deployments and privacy
  // tools strip `Origin`; it is only consulted when `Origin` is absent.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session } = await newSession(ctx, aliceId);
      const token = csrfTokenForSessionId(COOKIE_SECRET, session.id);

      assert.equal(
        refusalOf(checkCsrf(request({ origin: null, token }), session, OPTIONS)),
        "origin-missing",
      );

      assert.deepEqual(
        checkCsrf(request({ origin: null, referer: `${TRUSTED}/projects/7`, token }), session, OPTIONS),
        { ok: true, exempt: false },
        "a Referer from our own origin should stand in when Origin was stripped",
      );

      assert.equal(
        refusalOf(
          checkCsrf(request({ origin: null, referer: `${ATTACKER}/x`, token }), session, OPTIONS),
        ),
        "origin-untrusted",
      );

      // Origin wins when both are present, so a forged Referer buys nothing.
      assert.equal(
        refusalOf(
          checkCsrf(request({ origin: ATTACKER, referer: `${TRUSTED}/x`, token }), session, OPTIONS),
        ),
        "origin-untrusted",
      );

      // A repeated Origin is not something a browser produces.
      assert.equal(
        refusalOf(
          checkCsrf(
            request({ origin: null, token, extraHeaders: { origin: [TRUSTED, ATTACKER] } }),
            session,
            OPTIONS,
          ),
        ),
        "origin-repeated",
      );
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 1 — a token, bound to the session
// ---------------------------------------------------------------------------

test("every unsafe method needs a token and GET needs none", { skip }, async () => {
  // `isSafeMethod` in src/api/routes.ts is the single source of truth for which
  // methods are exempt, and it is CONSULTED here rather than copied. A duplicated
  // list is a list that eventually disagrees, and it would disagree in the
  // direction of exempting something that changes state.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session } = await newSession(ctx, aliceId);
      const token = csrfTokenForSessionId(COOKIE_SECRET, session.id);

      let unsafeSeen = 0;
      for (const method of HTTP_METHODS) {
        const withoutToken = checkCsrf(request({ method, token: null }), session, OPTIONS);
        const withToken = checkCsrf(request({ method, token }), session, OPTIONS);

        if (isSafeMethod(method)) {
          assert.deepEqual(withoutToken, { ok: true, exempt: true }, `${method} should need no token`);
          continue;
        }
        unsafeSeen += 1;
        assert.equal(refusalOf(withoutToken), "token-missing", `${method} was allowed with no token`);
        assert.deepEqual(withToken, { ok: true, exempt: false }, `${method} should pass with a token`);
      }
      assert.ok(unsafeSeen >= 4, "the route table should have more than one state-changing method");

      // An empty header is a missing token, not an empty one that might match.
      assert.equal(refusalOf(checkCsrf(request({ token: "" }), session, OPTIONS)), "token-missing");
      assert.equal(
        refusalOf(checkCsrf(request({ token: null, extraHeaders: { [CSRF_HEADER]: [token, token] } }), session, OPTIONS)),
        "token-repeated",
      );
    });
  });
});

test("a token from another session is refused", { skip }, async () => {
  // The binding, which is the whole of acceptance 1. Two live sessions exist at
  // once — the ordinary case of a laptop and a phone — and each token works for
  // exactly one of them. A token that were global, or derived from the user
  // rather than the session, would pass one of these four assertions and fail
  // the property.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");
    const bobId = await addMember(client, acme.orgId, "bob@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const laptop = await newSession(ctx, aliceId);
      const phone = await newSession(ctx, aliceId);
      const bob = await newSession(requestCtx(acme.orgId, bobId), bobId);

      const laptopToken = csrfTokenForSessionId(COOKIE_SECRET, laptop.session.id);
      const phoneToken = csrfTokenForSessionId(COOKIE_SECRET, phone.session.id);
      const bobToken = csrfTokenForSessionId(COOKIE_SECRET, bob.session.id);

      assert.notEqual(laptopToken, phoneToken, "two sessions must not share a token");

      assert.deepEqual(checkCsrf(request({ token: laptopToken }), laptop.session, OPTIONS), {
        ok: true,
        exempt: false,
      });
      assert.equal(
        refusalOf(checkCsrf(request({ token: phoneToken }), laptop.session, OPTIONS)),
        "token-mismatch",
        "the same person's other session bought a request it should not have",
      );
      assert.equal(
        refusalOf(checkCsrf(request({ token: bobToken }), laptop.session, OPTIONS)),
        "token-mismatch",
        "another member's token bought a request",
      );
      assert.equal(
        refusalOf(checkCsrf(request({ token: laptopToken }), bob.session, OPTIONS)),
        "token-mismatch",
      );
    });
  });
});

test("a token replayed after the session rotates is refused", { skip }, async () => {
  // src/auth/privilege_changes.ts rotates a session whenever what its holder may
  // do changes. The token names the session ROW and rotation is a new row
  // (migration 10 note 4), so the retired token stops verifying by the same
  // mechanism that retired the identifier — there is no second invalidation to
  // forget.
  //
  // This is the case a stored per-user token would get wrong: the identifier
  // would rotate, the token would not, and a demoted operator would keep a
  // working CSRF token across the privilege change.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const before = await newSession(ctx, aliceId);
      const staleToken = csrfTokenForSessionId(COOKIE_SECRET, before.session.id);

      assert.deepEqual(checkCsrf(request({ token: staleToken }), before.session, OPTIONS), {
        ok: true,
        exempt: false,
      });

      const rotated = await rotateSession(ctx, before.token, "privilege-change");
      assert.notEqual(rotated, null, "a live identifier should rotate");
      const after = rotated?.session ?? before.session;
      assert.notEqual(after.id, before.session.id, "rotation must produce a new row");

      assert.equal(
        refusalOf(checkCsrf(request({ token: staleToken }), after, OPTIONS)),
        "token-mismatch",
        "a token minted before a privilege change still works after it",
      );

      const freshToken = csrfTokenForSessionId(COOKIE_SECRET, after.id);
      assert.notEqual(freshToken, staleToken);
      assert.deepEqual(checkCsrf(request({ token: freshToken }), after, OPTIONS), {
        ok: true,
        exempt: false,
      });

      // And the retired session is genuinely dead, so the stale token names
      // nothing that could be revived.
      assert.equal(await validateSession(ctx, before.token), null);
    });
  });
});

test("a token supplied in the query string is refused, even alongside a valid one", { skip }, async () => {
  // A URL reaches the access log, the `Referer` of every outbound link on the
  // page, and browser history. The token lasts as long as the session, so that
  // leak does not expire — which is why this is a refusal rather than the token
  // simply being ignored. Ignoring it would hide the leak forever; refusing makes
  // the client bug visible the first time somebody tries it.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session } = await newSession(ctx, aliceId);
      const token = csrfTokenForSessionId(COOKIE_SECRET, session.id);

      assert.equal(
        refusalOf(checkCsrf(request({ url: `/grants?${CSRF_PARAMETER}=${token}`, token: null }), session, OPTIONS)),
        "token-in-query",
      );
      assert.equal(
        refusalOf(checkCsrf(request({ url: `/grants?${CSRF_PARAMETER}=${token}`, token }), session, OPTIONS)),
        "token-in-query",
        "a header token must not excuse one that has already leaked into a URL",
      );
      assert.equal(
        refusalOf(
          checkCsrf(
            { method: "POST", url: `https://ratline.example.com/grants?a=1&${CSRF_PARAMETER}=x&b=2`, headers: { origin: TRUSTED, [CSRF_HEADER]: token } },
            session,
            OPTIONS,
          ),
        ),
        "token-in-query",
        "an absolute URL hides the query no better than a relative one",
      );

      // An unrelated query string is not a problem.
      assert.deepEqual(checkCsrf(request({ url: "/grants?page=2", token }), session, OPTIONS), {
        ok: true,
        exempt: false,
      });
    });
  });
});

test("a request with no session is refused, whatever token it carries", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session } = await newSession(ctx, aliceId);
      const token = csrfTokenForSessionId(COOKIE_SECRET, session.id);

      assert.equal(refusalOf(checkCsrf(request({ token }), null, OPTIONS)), "unauthenticated");
      // But a safe method with no session is not a CSRF question at all.
      assert.deepEqual(checkCsrf(request({ method: "GET" }), null, OPTIONS), { ok: true, exempt: true });
    });
  });
});

test("the whole chain works from a real sign-in", { skip }, async () => {
  // The other tests mint identifiers directly to avoid a 128 MiB derivation each.
  // This one pays for it once, so the binding is exercised against a session that
  // came out of `signIn` rather than out of a fixture helper.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    await addMember(client, acme.orgId, "alice@acme.example", await hashPassword(PASSPHRASE));

    await usingScratch(database, async () => {
      const result = await signIn(signInCtx(acme), {
        email: "alice@acme.example",
        password: PASSPHRASE,
      });
      assert.equal(result.ok, true);
      if (!result.ok) return;

      const header = csrfTokenHeader(COOKIE_SECRET, result.session);
      assert.equal(header.name, CSRF_HEADER);
      assert.deepEqual(checkCsrf(request({ token: header.value }), result.session, OPTIONS), {
        ok: true,
        exempt: false,
      });
      assert.equal(refusalOf(checkCsrf(request({ origin: ATTACKER, token: header.value }), result.session, OPTIONS)), "origin-untrusted");
    });
  });
});

// ---------------------------------------------------------------------------
// C6 — a refused attempt is auditable
// ---------------------------------------------------------------------------

test("a refused request is audited, with the actor and without the token", { skip }, async () => {
  // A refused CSRF attempt is exactly what an incident review goes looking for,
  // so it is written through `guardCsrf` rather than left to a caller to
  // remember — the reasoning `useSessionToken` gives for folding last-seen into
  // the session lookup.
  await withMigratedDatabase(async (client, database) => {
    const acme = await seedTenant(client, "acme");
    const globex = await seedTenant(client, "globex");
    const aliceId = await addMember(client, acme.orgId, "alice@acme.example");
    let sessionId = "";

    await usingScratch(database, async () => {
      const ctx = requestCtx(acme.orgId, aliceId);
      const { session } = await newSession(ctx, aliceId);
      sessionId = session.id;
      const token = csrfTokenForSessionId(COOKIE_SECRET, session.id);

      const verdict = await guardCsrf(
        ctx,
        { ...request({ origin: ATTACKER }), routeKey: "DELETE /grants/:grantId" },
        session,
        OPTIONS,
      );
      assert.equal(refusalOf(verdict), "origin-untrusted");

      // An allowed request writes nothing. The audit log is for decisions worth
      // reviewing, and "a request was well formed" is every request.
      const allowed = await guardCsrf(
        ctx,
        { ...request({ token }), routeKey: "POST /grants" },
        session,
        OPTIONS,
      );
      assert.equal(allowed.ok, true);

      // Neither does an unauthenticated one: there is no session to attribute it
      // to, and a write here would let an unauthenticated caller append to the
      // audit log at will.
      assert.equal(
        refusalOf(await guardCsrf(ctx, { ...request({ token }), routeKey: "POST /grants" }, null, OPTIONS)),
        "unauthenticated",
      );

      // Read as the tenant's OWNER rather than as Alice. RL-M1-043 gated
      // listAudit, and a plain member reading the audit log was only ever
      // possible because it was ungated.
      const entries = await listAudit(requestCtx(acme.orgId, acme.ownerId), {
        action: CSRF_AUDIT_ACTION,
      });
      assert.equal(entries.length, 1, "exactly one refusal should have been recorded");
      const entry = entries[0];
      assert.equal(entry?.decision, "deny");
      assert.equal(entry?.reason, "origin-untrusted");
      assert.equal(entry?.resourceType, "session");
      assert.equal(entry?.resourceId, session.id);
      assert.equal(entry?.actorType, "user");
      assert.equal(entry?.actorId, aliceId, "C6: the entry names who was acting");
    });

    // The metadata carries what an incident needs and not the credential.
    // Asserted as the unprivileged role, with the tenant bound the way the
    // application binds it.
    await asApplicationRole(database, async (app) => {
      await app.query("begin");
      await setTenant(app, acme.orgId);
      const rows = await app.query<{ metadata: unknown; action: string }>(
        "select action, metadata from audit_entries where action = $1",
        [CSRF_AUDIT_ACTION],
      );
      assert.equal(rows.rows.length, 1);
      const metadata = JSON.stringify(rows.rows[0]?.metadata ?? {});
      assert.match(metadata, /"origin":"https:\/\/deploys\.attacker\.test"/);
      assert.match(metadata, /"route":"DELETE \/grants\/:grantId"/);
      assert.ok(
        !metadata.includes(csrfTokenForSessionId(COOKIE_SECRET, sessionId)),
        "the presented token reached the audit log",
      );
      await app.query("rollback");

      // And the entry is tenant-scoped like everything else: another tenant
      // cannot read this organization's refusals.
      await app.query("begin");
      await setTenant(app, globex.orgId);
      const other = await app.query("select 1 from audit_entries where action = $1", [CSRF_AUDIT_ACTION]);
      assert.equal(other.rows.length, 0, "a CSRF refusal is visible from another tenant");
      await app.query("rollback");
    });
  });
});

// ---------------------------------------------------------------------------
// The token itself
// ---------------------------------------------------------------------------

test("the token is keyed by the installation's cookie secret", () => {
  const sessionId = randomUUID();
  const mine = csrfTokenForSessionId(COOKIE_SECRET, sessionId);

  assert.equal(mine, csrfTokenForSessionId(COOKIE_SECRET, sessionId), "the same inputs must agree");
  assert.notEqual(
    mine,
    csrfTokenForSessionId(OTHER_COOKIE_SECRET, sessionId),
    "another installation must not be able to compute our tokens",
  );
  assert.notEqual(mine, csrfTokenForSessionId(COOKIE_SECRET, randomUUID()));
  assert.match(mine, /^[A-Za-z0-9_-]{43}$/, "256 bits, base64url, no padding");

  // C4's failure mode reached through the back door: HKDF is perfectly happy
  // with a zero-length key, and the result would be a token every installation
  // on earth could compute. A caller cannot get there by accident.
  //
  // RL-M1-054 widened this check from length to the full weak-secret judgement,
  // so the wording moved from "needs at least 32 bytes of cookie secret" to
  // weak-secrets.ts's own "at least 32 are required". Asserted on the new text
  // rather than loosened to /32/, because the sentence an operator reads is part
  // of the fix — and the length case must keep reporting LENGTH now that the same
  // function also reports entropy. The entropy half is in
  // test/security/cookie_secret_entropy.test.ts.
  assert.throws(() => csrfTokenForSessionId(Buffer.alloc(0), sessionId), /cookie secret/);
  assert.throws(() => csrfTokenForSessionId(randomBytes(31), sessionId), /at least 32 are required/);
});

test("the token comparison is constant-time, and that is a property of the source", () => {
  // THE HONEST TEST, in the shape test/security/session_fixation.test.ts uses for
  // the password comparison. Swapping `secretEquals` for `===` on the two strings
  // is functionally identical: every assertion in this file about which requests
  // are allowed passes either way, because both answer the same question. Only
  // the time taken differs, and a timing assertion precise enough to see it would
  // be too flaky to keep.
  //
  // It matters more here than almost anywhere: the token is stable for the life
  // of the session (ADR 0016), so an attacker who can measure the comparison gets
  // unlimited attempts at recovering one byte at a time.
  //
  // This is not complete, and saying so matters: `Buffer.compare(a, b) < 1` would
  // also be non-constant-time and would also pass. It catches the mutation
  // somebody actually makes.
  const source = readFileSync(join(ROOT, "src", "api", "csrf.ts"), "utf8");

  assert.match(
    source,
    /import \{ secretEquals \} from "\.\.\/crypto\/secrets\.ts"/,
    "the one constant-time comparison in the codebase should be the one used here",
  );

  const start = source.indexOf("export function checkCsrf");
  assert.ok(start > 0, "checkCsrf should exist");
  const body = source.slice(start, source.indexOf("\n}", start));

  assert.match(body, /secretEquals\(/, "the token comparison must be the constant-time one");
  assert.doesNotMatch(
    body,
    /(token|presented)\s*[=!]==\s*expected|expected\s*[=!]==\s*(token|presented)/,
    "the token is compared with a strict-equality operator; a secret comparison must not use one",
  );
});

test("the safe-method list is not duplicated here", () => {
  // src/api/routes.ts owns which methods change state, and says so in a comment
  // pointing at this task. A second list in this module is a second list to keep
  // in step, and it would drift in the direction of exempting something.
  const source = readFileSync(join(ROOT, "src", "api", "csrf.ts"), "utf8");
  assert.match(source, /import \{ isSafeMethod, type HttpMethod \} from "\.\/routes\.ts"/);
  assert.doesNotMatch(
    source,
    /"(GET|POST|PUT|PATCH|DELETE)"/,
    "an HTTP method is written down in csrf.ts; consult isSafeMethod instead",
  );
});

// ---------------------------------------------------------------------------
// Acceptance 2 — the cookie policy
// ---------------------------------------------------------------------------

test("the policy is not inferred from the bind address", () => {
  // THE R-11 TEST, and the reason acceptance 2 says "appropriately for the
  // deployment model" rather than naming attributes.
  //
  // A control plane bound to 127.0.0.1 behind a TLS-terminating reverse proxy is
  // the ordinary production shape, and src/config/network.ts reports it
  // `contained` because a local check cannot see the proxy. A policy that
  // reasoned "loopback bind, so drop Secure" would hand the MOST exposed
  // deployment the WEAKEST cookie. That inference must be impossible, not merely
  // avoided — so the bind address is not an input here at all.
  const behindProxy = cookiePolicy(
    resolveTrustedOrigins({ RATLINE_BIND_ADDRESS: "127.0.0.1", RATLINE_PUBLIC_ORIGIN: TRUSTED }),
    false,
  );
  assert.equal(behindProxy.secure, true);
  assert.equal(behindProxy.name, `${HOST_COOKIE_PREFIX}${SESSION_COOKIE_NAME}`);
  assert.equal(behindProxy.warning, null);

  // And the same bind with no declaration is the C5 default: still Secure.
  const loopback = cookiePolicy(resolveTrustedOrigins({ RATLINE_BIND_ADDRESS: "127.0.0.1" }), false);
  assert.equal(loopback.secure, true, "Secure must be the default, not something a bind address removes");
});

test("Secure comes off only when an operator says so in writing", () => {
  const origins = [TRUSTED];

  const secure = cookiePolicy(origins, false);
  assert.equal(secure.secure, true);
  assert.equal(secure.warning, null);

  const relaxed = cookiePolicy(origins, true);
  assert.equal(relaxed.secure, false, "the acknowledgement is the only way here");
  assert.notEqual(relaxed.warning, null, "a relaxation nobody is told about is a silent downgrade");
  assert.match(relaxed.warning ?? "", /RATLINE_ALLOW_INSECURE_COOKIES/);
  assert.equal(relaxed.name, SESSION_COOKIE_NAME, "__Host- requires Secure; the name must change with it");

  // Only these exact values acknowledge. A typo must not disable a defence.
  assert.equal(insecureCookiesAcknowledged({ RATLINE_ALLOW_INSECURE_COOKIES: "1" }), true);
  assert.equal(insecureCookiesAcknowledged({ RATLINE_ALLOW_INSECURE_COOKIES: "true" }), true);
  assert.equal(insecureCookiesAcknowledged({ RATLINE_ALLOW_INSECURE_COOKIES: "TRUE" }), true);
  assert.equal(insecureCookiesAcknowledged({ RATLINE_ALLOW_INSECURE_COOKIES: "yes" }), false);
  assert.equal(insecureCookiesAcknowledged({ RATLINE_ALLOW_INSECURE_COOKIES: "0" }), false);
  assert.equal(insecureCookiesAcknowledged({}), false);
});

test("plain HTTP on a real network breaks loudly rather than downgrading", () => {
  // docs/NETWORK.md recommends a Tailscale or LAN address, which is reached over
  // plain HTTP. The cookie stays Secure — so the browser refuses to store it and
  // nobody signs in — and the warning names both remedies. Loud and broken beats
  // quietly sending the session credential in the clear.
  const tailnet = cookiePolicy(resolveTrustedOrigins({ RATLINE_PUBLIC_ORIGIN: "http://100.64.1.2:7712" }), false);
  assert.equal(tailnet.secure, true);
  assert.equal(tailnet.name, SESSION_COOKIE_NAME);
  assert.match(tailnet.warning ?? "", /100\.64\.1\.2/);
  assert.match(tailnet.warning ?? "", /RATLINE_ALLOW_INSECURE_COOKIES/);

  // Loopback over plain HTTP is the sanctioned default and gets no banner: a
  // warning that is always on is a warning operators learn to look past, which
  // is the failure mode C5's own warning is written to avoid.
  const loopback = cookiePolicy(["http://127.0.0.1:7712"], false);
  assert.equal(loopback.secure, true);
  assert.equal(loopback.warning, null);
  assert.equal(loopback.name, SESSION_COOKIE_NAME, "__Host- is not applied on plain-HTTP loopback");

  // No origin at all refuses everything, and says so.
  const none = cookiePolicy([], false);
  assert.equal(none.secure, true);
  assert.match(none.warning ?? "", /RATLINE_PUBLIC_ORIGIN/);
});

test("the rendered cookie attributes carry SameSite, HttpOnly and Secure", () => {
  const https = cookieAttributes(cookiePolicy([TRUSTED], false));
  assert.match(https, /(^|; )Secure(;|$)/);
  assert.match(https, /(^|; )HttpOnly(;|$)/);
  assert.match(https, /(^|; )SameSite=Strict(;|$)/);
  assert.match(https, /(^|; )Path=\/(;|$)/);
  assert.doesNotMatch(https, /Max-Age|Expires/, "session lifetime is enforced server-side, not by the browser");
  assert.doesNotMatch(https, /Domain=/, "a Domain would share the cookie with every neighbouring subdomain");

  const relaxed = cookieAttributes(cookiePolicy([TRUSTED], true));
  assert.doesNotMatch(relaxed, /Secure/);
  assert.match(relaxed, /SameSite=Strict/, "SameSite is not configurable and does not follow Secure");
});

// ---------------------------------------------------------------------------
// Origins
// ---------------------------------------------------------------------------

test("origins are normalised the same way on both sides of the comparison", () => {
  assert.equal(normaliseOrigin("HTTPS://Ratline.Example.COM"), TRUSTED);
  assert.equal(normaliseOrigin("https://ratline.example.com:443"), TRUSTED);
  assert.equal(normaliseOrigin("http://ratline.example.com:80"), "http://ratline.example.com");
  assert.equal(normaliseOrigin("https://ratline.example.com/some/path?q=1"), TRUSTED);
  assert.equal(normaliseOrigin("http://[::1]:7712"), "http://[::1]:7712");

  // Anything that is not an http(s) origin matches nothing.
  for (const bad of ["null", "", "  ", "file:///etc/passwd", "javascript:alert(1)", "ratline.example.com"]) {
    assert.equal(normaliseOrigin(bad), null, `"${bad}" should not normalise to an origin`);
  }
});

test("the trusted set is declared, defaulted from the bind, and never guessed", () => {
  assert.deepEqual(defaultTrustedOrigins("127.0.0.1", 7712), [
    "http://localhost:7712",
    "http://127.0.0.1:7712",
    "http://[::1]:7712",
  ]);
  // A wildcard bind serves loopback too, so the same three apply.
  assert.deepEqual(defaultTrustedOrigins("0.0.0.0", 7712).length, 3);
  // Any other bind gets only itself: adding loopback would widen the set to an
  // origin the deployment does not serve.
  assert.deepEqual(defaultTrustedOrigins("100.64.1.2", 7712), ["http://100.64.1.2:7712"]);
  assert.deepEqual(defaultTrustedOrigins("fd00::1", 7712), ["http://[fd00::1]:7712"]);

  assert.deepEqual(resolveTrustedOrigins({}), [
    "http://localhost:7712",
    "http://127.0.0.1:7712",
    "http://[::1]:7712",
  ]);
  assert.deepEqual(
    resolveTrustedOrigins({ RATLINE_PUBLIC_ORIGIN: `${TRUSTED}, http://127.0.0.1:7712 ` }),
    [TRUSTED, "http://127.0.0.1:7712"],
    "one deployment is routinely reached by more than one name",
  );
  assert.deepEqual(resolveTrustedOrigins({ RATLINE_PUBLIC_ORIGIN: `${TRUSTED},${TRUSTED}:443` }), [TRUSTED]);

  // A typo throws rather than shrinking the set. Dropped silently it would
  // refuse every state-changing request with nothing to show the operator.
  assert.throws(
    () => resolveTrustedOrigins({ RATLINE_PUBLIC_ORIGIN: "ratline.example.com" }),
    /RATLINE_PUBLIC_ORIGIN/,
  );
  assert.throws(() => resolveTrustedOrigins({ RATLINE_PUBLIC_ORIGIN: `${TRUSTED},nonsense` }), /nonsense/);
});
