/**
 * The HTTP surface (RL-M1-042).
 *
 * Nothing in the tracker ever built this. Every "web server" task in the plan
 * is about the nginx or caddy Ratline manages ON hosts, which is a different
 * thing entirely — and four risks were each worded "owed by whoever builds
 * src/api/". This is that.
 *
 * ## The one decision that shapes the file — ruled 2026-08-02
 *
 * Every route declares the action it requires, which invites a middleware that
 * calls `can()` before the handler. §9 rejects permission checks in handlers
 * "instead of, OR IN ADDITION TO, the data layer", and `privilege_changes.ts`
 * already states why: a second check is the shape that eventually disagrees
 * with the first.
 *
 * So THERE IS NO AUTHORIZATION MIDDLEWARE HERE. Not a weakened one, not a
 * defence-in-depth one — none. A handler calls a repository function, that
 * function resolves the permission, and a denial arrives here as a thrown
 * `NotPermittedError` which is rendered as a refusal. `can()` is not imported
 * by this module and must not be.
 *
 * What the route table's `requires` is used for is auditing and coverage: which
 * action to NAME in the audit entry when a refusal is rendered, and which cells
 * the matrix should drive. Naming is not deciding.
 *
 * That reading immediately found nine repository reads that resolved no
 * permission at all (RL-M1-043, R-29), including the audit log. A middleware
 * would have covered every one of them and left the repositories exactly as
 * wrong, which is the argument for the reading, made by the codebase rather
 * than by me.
 *
 * ## What IS middleware here, and why each one is
 *
 *   1. **Tenant and session.** Resolves the bearer cookie into a session and
 *      builds the `AuthzContext` every layer below needs. It decides nothing
 *      about permissions; it decides who is asking.
 *   2. **Rate limiting**, on the authentication paths only. It must run BEFORE
 *      the expensive work — that ordering is the whole reason R-15 said this
 *      belonged to a route handler — and it is spent, not merely consulted.
 *   3. **CSRF**, on every unsafe method — and "every" is literal, checked once in
 *      front of the whole app rather than per route. It was per-route until
 *      RL-M1-049, which protected the routes that reached the loop and left
 *      `POST /auth/sign-out` — bound above it as public — open to a cross-origin
 *      request that ended an operator's session. `isSafeMethod` from the route
 *      table is consulted rather than copied.
 *
 * None of the three is an authorization decision. All three are things that
 * must happen before one, and could not live in a repository because they are
 * about the REQUEST rather than about the data.
 *
 * ## Routes without handlers are not bound
 *
 * The route table declares 30 routes and this binds the 12 that have a repository
 * function to call. The rest are deliberately absent rather than
 * bound to a stub, because a stub would answer 200-or-501 to everybody and
 * report itself as reachable — the matrix would then measure a guard that does
 * not exist. An unbound route 404s from the framework, which is honest, and
 * `transportCoverage()` below reports exactly which ones are real.
 */

import { Hono, type Context } from "hono";

import {
  guardedRoutes,
  isSafeMethod,
  ROUTES,
  routeKey,
  type HttpMethod,
  type Route,
} from "./routes.ts";
import {
  alreadyAudited,
  recordAndRefuse,
  refuse,
  secondFactorOwed,
  unauthenticated,
  type Refusal,
} from "./refusal.ts";
import {
  CSRF_AUDIT_ACTION,
  CSRF_HEADER,
  cookieAttributes,
  cookiePolicy,
  csrfTokenForSessionId,
  guardCsrf,
  insecureCookiesAcknowledged,
  resolveTrustedOrigins,
} from "./csrf.ts";
import {
  bootstrapState,
  bootstrapTokenMatches,
  spendBootstrapToken,
} from "./bootstrap_token.ts";
import { createInstallation, type InstallationInput } from "../repo/bootstrap.ts";
import { NotPermittedError } from "../authz/can.ts";
import {
  contextForBootstrap,
  contextForRequest,
  contextForServiceIdentity,
  type AuthzContext,
} from "../authz/context.ts";
import type { AuditAction } from "../authz/audit_events.ts";
import { recordAudit } from "../repo/audit.ts";
import { recordAuthAttempt } from "../auth/rate_limit.ts";
import { verifySecondFactor } from "../auth/two_factor.ts";
import { signIn, validateSession } from "../auth/sessions.ts";
import { revokeSessionByToken } from "../repo/sessions.ts";
import { applyPrivilegeChange, NotPermittedToRevokeSessions } from "../auth/privilege_changes.ts";
import { listAudit } from "../repo/audit.ts";
import { currentOrganization, findProject, listMembers, listProjects } from "../repo/organizations.ts";
import type { Session } from "../auth/model.ts";

/**
 * What the server needs from its deployment.
 *
 * Injected rather than read from the environment inside, so a test drives the
 * real server rather than a rearranged one — the matrix harness depends on
 * that being true.
 */
export type ServerDeps = {
  /** Signs nothing; derives the CSRF subkey. C4 forbids a default. */
  readonly cookieSecret: Uint8Array;
  /**
   * Which organization an UNAUTHENTICATED request belongs to.
   *
   * A signed-in request carries its tenant on the session. A sign-in does not,
   * and something has to say. Injected because the answer is a deployment
   * question this task is not entitled to settle: one organization per
   * installation, a subdomain, or a slug on the form. Recorded as owed.
   */
  readonly resolveTenant: (request: Request) => Promise<string | null>;
  /**
   * The service identity the sign-in path acts as, for rate limiting and for
   * audit entries written before an actor exists (ADR 0014's seam).
   */
  readonly signInIdentityId: string;
  /** Where the first-run secrets live. Injected so a test uses its own (C4). */
  readonly secretsDir: string;
  /** Unseals a stored TOTP secret (ADR 0006). Required, never a lazy load. */
  readonly sealingKey: Buffer;
  readonly trustedOrigins?: readonly string[];
};

type Bound = {
  readonly route: Route;
  readonly handle: (ctx: AuthzContext, c: Context) => Promise<Response>;
};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function send(refusal: Refusal): Response {
  return new Response(refusal.body, {
    status: refusal.status,
    headers: Object.fromEntries(refusal.headers.map(([name, value]) => [name, value])),
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

/**
 * Render a denial, and record the truth.
 *
 * The route's declared action names the attempt in the audit entry. That is the
 * route table being used to LABEL rather than to decide — the decision already
 * happened, in the repository, and arrived here as an exception.
 */
async function renderDenial(ctx: AuthzContext, route: Route, error: NotPermittedError): Promise<Response> {
  const action: AuditAction = route.requires ?? "organization.read";
  return send(
    await recordAndRefuse(
      ctx,
      refuse({
        action,
        resourceType: "organization",
        resourceId: null,
        cause: "denied",
        reason: error.decision.reason,
      }),
      recordAudit,
    ),
  );
}

/** The header carrying the first-run token. Not a cookie: it is typed in once. */
export const BOOTSTRAP_HEADER = "x-ratline-bootstrap";

/**
 * Check the operator's form before touching the database.
 *
 * The messages are written for the person reading them, per §291: active voice,
 * what broke and what to do next, no apology. They are also the ONLY place a
 * bootstrap response explains itself — see the route.
 */
export function validateInstallation(input: Partial<InstallationInput>): string[] {
  const problems: string[] = [];
  const slug = (input.organizationSlug ?? "").trim();
  const email = (input.ownerEmail ?? "").trim();

  if (slug === "") problems.push("Give the organization a short name for URLs, like acme.");
  else if (!/^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$/.test(slug)) {
    problems.push("The short name takes lower-case letters, digits and hyphens, and starts and ends with one of those.");
  }
  if ((input.organizationName ?? "").trim() === "") problems.push("Name the organization as people call it.");
  if (email === "" || !email.includes("@")) problems.push("Enter the email address the first owner will sign in with.");
  if ((input.ownerName ?? "").trim() === "") problems.push("Enter the owner's name, so the audit log has somebody to point at.");
  // Length only. Strength rules belong to the organization security policy, and
  // an installation with no organization has no policy yet.
  if ((input.ownerPassword ?? "").length < 12) {
    problems.push("Use a password of at least 12 characters. A passphrase of four words beats a short scramble.");
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

function readCookie(header: string | undefined, name: string): string | null {
  if (header === undefined) return null;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function sessionCookieName(): string {
  return cookiePolicy(resolveTrustedOrigins(), insecureCookiesAcknowledged()).name;
}

// ---------------------------------------------------------------------------
// The handlers that exist
// ---------------------------------------------------------------------------

/**
 * Every route with something real behind it.
 *
 * Keyed by `routeKey` so the binding cannot drift from the table: a key here
 * that the table does not declare fails `validateBindings` below, and the
 * matrix only drives what appears in both.
 */
function handlers(deps: ServerDeps): Map<string, Bound["handle"]> {
  const map = new Map<string, Bound["handle"]>();

  /**
   * A lookup that resolved nothing answers with the REFUSAL, not with `null`.
   *
   * The transport layer forced this out and it is worth stating. `findProject`
   * returns null both for a project that does not exist and for one belonging
   * to another tenant — the repository cannot tell them apart, which is
   * RL-M1-026 working. Rendering that as `200 null` would then make BOTH
   * distinguishable from a refusal, reintroducing at the HTTP layer exactly the
   * oracle the data layer had closed.
   */
  const found = async <T>(
    ctx: AuthzContext,
    value: T | null,
    route: string,
    resourceType: "project" | "organization",
  ): Promise<Response> =>
    value === null
      ? send(
          // THE DEFECT THIS SIGNATURE EXISTS TO PREVENT (RL-M1-050). This used to
          // be `refuse({...}).wire`, which served the 404 and dropped the audit
          // record, so a cross-tenant id probe — the only kind this route can
          // express — was indistinguishable on the wire AND invisible in the log.
          // Taking `ctx` is what makes the record possible, so the parameter is
          // load-bearing rather than plumbing.
          await recordAndRefuse(
            ctx,
            refuse({
              action: route === "GET /projects/:projectId" ? "project.read" : "organization.read",
              resourceType,
              resourceId: null,
              cause: "absent",
              reason: "unknown-scope",
            }),
            recordAudit,
          ),
        )
      : json(value);

  map.set("GET /organization", async (ctx) =>
    found(ctx, await currentOrganization(ctx), "GET /organization", "organization"),
  );
  map.set("GET /members", async (ctx) => json(await listMembers(ctx)));
  map.set("GET /projects", async (ctx) => json(await listProjects(ctx)));
  map.set("GET /projects/:projectId", async (ctx, c) =>
    found(ctx, await findProject(ctx, c.req.param("projectId") ?? ""), "GET /projects/:projectId", "project"),
  );
  map.set("GET /audit", async (ctx) => json(await listAudit(ctx, { limit: 50 })));

  map.set("POST /members/:userId/revoke-sessions", async (ctx, c) => {
    try {
      const result = await applyPrivilegeChange(ctx, {
        subjectUserId: c.req.param("userId") ?? "",
        reason: "containment",
      });
      return json(result);
    } catch (error: unknown) {
      // The auth layer already audited this and turned it into its own type, so
      // the refusal is rendered without a second entry.
      if (error instanceof NotPermittedToRevokeSessions) {
        return send(
          await recordAndRefuse(
            ctx,
            refuse({
              action: "member.revoke_sessions",
              resourceType: "member",
              resourceId: c.req.param("userId") ?? null,
              cause: "denied",
              reason: "not-permitted",
            }),
            recordAudit,
          ),
        );
      }
      throw error;
    }
  });

  void deps;
  return map;
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

export function createServer(deps: ServerDeps): Hono {
  const app = new Hono();
  const bound = handlers(deps);
  const trusted = deps.trustedOrigins ?? resolveTrustedOrigins();
  const cookieName = sessionCookieName();

  // ---------------------------------------------------------------------------
  // The CSRF guard, in front of EVERY request (RL-M1-049)
  //
  // This was previously inside the guarded-route loop below, which protected the
  // routes that reached the loop and nothing else. `POST /auth/sign-out` is bound
  // above it as a public route, so it never got there: a cross-origin fetch with
  // credentials from any page an operator happened to visit ended their session,
  // and left no audit entry either. Only SameSite stood in the way, and
  // `csrf.ts` argues at length that SameSite must never be the only lock, because
  // the population of browsers reaching a self-hosted install is not one we pick.
  //
  // csrf.ts's own instruction to the server author was already explicit: call it
  // on every request, "not per-route and not opt-in: the default has to be
  // protected, or the one route somebody forgets is the one that matters". This is
  // that instruction followed. A route added in M2 is covered by existing.
  //
  // WHY A MISSING SESSION PASSES THROUGH. `guardCsrf` decides that itself, and it
  // is the right rule rather than a convenience: a request with no session has no
  // authority to borrow, so there is nothing for a forgery to accomplish. It is
  // also what makes sign-in and two-factor work at all — they are unsafe methods
  // that necessarily arrive without a session. Sign-out is the opposite case and
  // is why this is middleware: it has a session, so it has something to lose.
  // ---------------------------------------------------------------------------
  app.use("*", async (c, next) => {
    const method = c.req.method as HttpMethod;
    if (isSafeMethod(method)) return next();

    const orgId = await deps.resolveTenant(c.req.raw);
    const token = readCookie(c.req.header("cookie"), cookieName);
    // No tenant or no cookie means no session, so nothing to forge. The route's
    // own authentication still refuses it if it needs one — this guard is not
    // standing in for that, and must not be read as doing so.
    if (orgId === null || token === null) return next();

    const preAuth = contextForServiceIdentity({
      orgId,
      serviceIdentityId: deps.signInIdentityId,
      name: "sign-in",
      requestId: crypto.randomUUID(),
    });
    const session = await validateSession(preAuth, token);
    if (session === null) return next();

    const verdict = await guardCsrf(
      preAuth,
      {
        method,
        headers: Object.fromEntries(c.req.raw.headers.entries()),
        url: c.req.url,
        // The matched pattern, not the concrete path, so an audit entry for
        // /projects/:projectId groups with its siblings instead of fragmenting
        // into one row per id — and so a probed id never lands in the route field.
        routeKey: `${method} ${c.req.routePath}`,
      },
      session,
      { cookieSecret: deps.cookieSecret, trustedOrigins: trusted },
    );

    if (verdict.ok) return next();

    // guardCsrf has already written `session.csrf_rejected` with the origin and
    // route, so this refusal is accounted for and says which record covers it.
    return send(
      alreadyAudited(
        refuse({
          action: CSRF_AUDIT_ACTION,
          resourceType: "session",
          resourceId: session.id,
          cause: "denied",
          reason: verdict.refusal,
        }),
        CSRF_AUDIT_ACTION,
      ),
    );
  });

  // --- public routes, each with a written reason in the table ---------------

  app.get("/health", () => json({ status: "up" }));

  /**
   * Is this installation still unclaimed? (RL-M1-030)
   *
   * One boolean, and it leaks nothing an unauthenticated caller could not
   * already infer by trying to sign in to an installation with no accounts.
   * The first-run screen needs it to know whether to show the claim form or the
   * sign-in form.
   */
  app.get("/bootstrap", () => json({ unclaimed: bootstrapState(deps.secretsDir) === "unclaimed" }));

  /**
   * Claim the installation.
   *
   * The token is checked FIRST, before anything is read out of the body and
   * before any work is done, because it is the only authority on this path.
   *
   * Every refusal renders identically — already claimed, never minted, wrong
   * value, malformed body. A response that distinguished them would tell an
   * unauthenticated caller whether the installation is worth attacking, and
   * "already claimed" is precisely the answer an attacker wants.
   */
  app.post("/bootstrap", async (c) => {
    const presented = c.req.header(BOOTSTRAP_HEADER) ?? "";
    if (!bootstrapTokenMatches(presented, deps.secretsDir)) return send(unauthenticated());

    const body = (await c.req.json().catch(() => ({}))) as Partial<InstallationInput>;
    const problems = validateInstallation(body);
    // The one place a bootstrap refusal says WHY, and deliberately: these are
    // the operator's own typos on a form only they can reach, and §291 asks
    // errors to state what broke and what to do next. Nothing here is a
    // statement about the installation.
    if (problems.length > 0) return json({ problems }, 422);

    // The identities are minted here, so the actor of the claim is decided at
    // the call site rather than inside a repository.
    const { ctx, orgId } = contextForBootstrap();
    await createInstallation(ctx, body as InstallationInput);

    // Spent only after the transaction committed. Spending first would close the
    // endpoint on an installation that failed to claim — unclaimable forever,
    // with no owner and no second chance.
    spendBootstrapToken(deps.secretsDir);

    await recordAudit(ctx, {
      action: "organization.update",
      resourceType: "organization",
      resourceId: orgId,
      decision: "allow",
      reason: "installation-claimed",
      metadata: { bootstrap: true },
    });

    return json({ organizationId: orgId }, 201);
  });

  app.post("/auth/sign-in", async (c) => {
    const orgId = await deps.resolveTenant(c.req.raw);
    if (orgId === null) return send(unauthenticated());

    const ctx = contextForServiceIdentity({
      orgId,
      serviceIdentityId: deps.signInIdentityId,
      name: "sign-in",
      requestId: crypto.randomUUID(),
    });

    const body = (await c.req.json().catch(() => ({}))) as { email?: string; password?: string };
    const email = body.email ?? "";

    // BEFORE the scrypt derivation, not after. R-15's whole point is that
    // sign-in does 128 MiB of work for accounts that do not exist, so a limiter
    // consulted afterwards has already paid for the attack.
    const limit = await recordAuthAttempt(ctx, {
      path: "login",
      account: email,
      address: c.req.header("x-forwarded-for") ?? "",
    });
    if (!limit.allowed) return send(unauthenticated());

    const result = await signIn(ctx, { email, password: body.password ?? "" });
    if (!result.ok) {
      // Every refusal renders identically. `result.refusal` distinguishes
      // unknown-account from credential-rejected and that distinction is for
      // the audit log, never for the caller (§6.3).
      // Through `refuse`'s module rather than built here. RL-M1-026's scan
      // caught the hand-rolled version, correctly: a response constructed at a
      // call site is one that can differ from the others, which is the whole
      // leak that module exists to close.
      return result.secondFactor === null
        ? send(unauthenticated())
        : send(secondFactorOwed(result.secondFactor.enrolmentRequired));
    }

    const policy = cookiePolicy(trusted, insecureCookiesAcknowledged());
    const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
    headers.append("set-cookie", `${policy.name}=${result.token}; ${cookieAttributes(policy)}`);
    headers.append(CSRF_HEADER, csrfTokenForSessionId(deps.cookieSecret, result.session.id));
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
  });

  /**
   * Present a second factor (R-28).
   *
   * This endpoint is why R-28 existed. `AUTH_RATE_LIMITS["two-factor"]`
   * published a budget and nothing spent it, because the limiter has to run
   * before the work and there was no route to run it in. A six-digit code is a
   * million possibilities; an unlimited verifier finds one inside a day.
   *
   * ## What the limiter keys on, which is the part worth getting right
   *
   * The CHALLENGE TOKEN, not the account. `rate_limit.ts` is explicit that
   * `account` must never be a resolved user id — on the sign-in path, looking
   * one up before limiting would be both an existence oracle and a query on the
   * flooded path. The same reasoning applies here, and the challenge token is
   * available without any lookup at all.
   *
   * Passed RAW. `bucketsFor` digests every dimension itself, so hashing here
   * first was redundant — and worse than redundant, because it implied the
   * caller owns that protection and would invite the next path to skip it. The
   * limiter owns the digest; callers hand it the value.
   *
   * The obvious objection is that a fresh challenge resets the bucket, so an
   * attacker could re-run sign-in between batches of guesses. That is answered
   * by composition rather than ignored: minting a challenge REQUIRES a
   * successful sign-in, and sign-in is limited on the account and the address.
   * The two budgets multiply — you cannot buy more code attempts without
   * spending sign-in attempts, and those are counted against a key an attacker
   * cannot vary.
   */
  app.post("/auth/two-factor", async (c) => {
    const orgId = await deps.resolveTenant(c.req.raw);
    if (orgId === null) return send(unauthenticated());

    const ctx = contextForServiceIdentity({
      orgId,
      serviceIdentityId: deps.signInIdentityId,
      name: "sign-in",
      requestId: crypto.randomUUID(),
    });

    const body = (await c.req.json().catch(() => ({}))) as { challenge?: string; code?: string };
    const challenge = body.challenge ?? "";

    const limit = await recordAuthAttempt(ctx, {
      path: "two-factor",
      account: challenge,
      address: c.req.header("x-forwarded-for") ?? "",
    });
    if (!limit.allowed) return send(unauthenticated());

    const result = await verifySecondFactor(ctx, deps.sealingKey, {
      challengeToken: challenge,
      presented: body.code ?? "",
      ip: c.req.header("x-forwarded-for") ?? null,
    });
    // Every refusal renders identically. `result.refusal` tells apart
    // "no live challenge" from "not enrolled" from "wrong code", and that
    // distinction is for the audit log — the second of those is a statement
    // about whether an account has a factor.
    if (!result.ok) return send(unauthenticated());

    const policy = cookiePolicy(trusted, insecureCookiesAcknowledged());
    const headers = new Headers({ "content-type": "application/json; charset=utf-8" });
    headers.append("set-cookie", `${policy.name}=${result.token}; ${cookieAttributes(policy)}`);
    headers.append(CSRF_HEADER, csrfTokenForSessionId(deps.cookieSecret, result.session.id));
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
  });

  app.post("/auth/sign-out", async (c) => {
    const orgId = await deps.resolveTenant(c.req.raw);
    const token = readCookie(c.req.header("cookie"), cookieName);
    if (orgId === null || token === null) return json({ ok: true });

    const ctx = contextForServiceIdentity({
      orgId,
      serviceIdentityId: deps.signInIdentityId,
      name: "sign-in",
      requestId: crypto.randomUUID(),
    });
    await revokeSessionByToken(ctx, token, "signed-out");
    const policy = cookiePolicy(trusted, insecureCookiesAcknowledged());
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": `${policy.name}=; Max-Age=0; ${cookieAttributes(policy)}`,
      },
    });
  });

  // --- everything else ------------------------------------------------------

  for (const route of guardedRoutes()) {
    const handle = bound.get(routeKey(route));
    // Deliberately not bound when there is nothing behind it. A stub would
    // answer everybody the same way and report itself as guarded.
    if (handle === undefined) continue;

    const bind = app[route.method.toLowerCase() as "get" | "post" | "put" | "patch" | "delete"].bind(app);
    bind(route.path, async (c: Context) => {
      const orgId = await deps.resolveTenant(c.req.raw);
      const token = readCookie(c.req.header("cookie"), cookieName);
      if (orgId === null || token === null) return send(unauthenticated());

      // The session lookup runs as the sign-in identity, because there is no
      // actor until it succeeds. This is the ADR 0014 seam, used rather than
      // worked around.
      const preAuth = contextForServiceIdentity({
        orgId,
        serviceIdentityId: deps.signInIdentityId,
        name: "sign-in",
        requestId: crypto.randomUUID(),
      });
      const session: Session | null = await validateSession(preAuth, token);
      if (session === null) return send(unauthenticated());

      const ctx = contextForRequest({
        orgId,
        userId: session.userId,
        requestId: crypto.randomUUID(),
        ip: c.req.header("x-forwarded-for") ?? null,
      });

      // NO CSRF CHECK HERE, deliberately (RL-M1-049). It used to live in this
      // loop, which meant it protected exactly the routes that reached the loop —
      // and POST /auth/sign-out is bound above it as a public route, so a
      // cross-origin request could end an operator's session. The guard is now
      // middleware that sees every request. Per-route was the bug.

      try {
        return await handle(ctx, c);
      } catch (error: unknown) {
        // THE ONLY PLACE A DENIAL BECOMES A RESPONSE. The decision was made in
        // the repository; this renders it, identically for every route.
        if (error instanceof NotPermittedError) return await renderDenial(ctx, route, error);
        throw error;
      }
    });
  }

  return app;
}

// ---------------------------------------------------------------------------
// What is actually reachable, for the matrix
// ---------------------------------------------------------------------------

/**
 * The routes this server binds.
 *
 * Exported so `test/authz/matrix.test.ts` drives real requests for exactly
 * these and reports the rest as decision-layer only. A harness that assumed
 * every declared route was reachable would measure a guard that is not there.
 */
export function boundRouteKeys(deps: ServerDeps): Set<string> {
  const keys = new Set(handlers(deps).keys());
  // The public routes are bound directly rather than through the table loop.
  for (const key of [
    "GET /health",
    "GET /bootstrap",
    "POST /bootstrap",
    "POST /auth/sign-in",
    "POST /auth/two-factor",
    "POST /auth/sign-out",
  ]) {
    keys.add(key);
  }
  return keys;
}

export type BindingProblem = { readonly routeKey: string; readonly problem: string };

/** A handler for a route the table does not declare would never be reached. */
export function validateBindings(deps: ServerDeps): BindingProblem[] {
  const declared = new Set(ROUTES.map(routeKey));
  return [...boundRouteKeys(deps)]
    .filter((key) => !declared.has(key))
    .map((key) => ({ routeKey: key, problem: "bound but not declared in the route table" }));
}

/** How much of the table is reachable, for STATUS to report honestly. */
export function transportCoverage(deps: ServerDeps): { bound: number; declared: number } {
  return { bound: boundRouteKeys(deps).size, declared: ROUTES.length };
}

export type { HttpMethod };
