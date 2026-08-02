/**
 * The route table (RL-M1-024).
 *
 * Brief §6.3's acceptance gate: "The matrix is generated from the route table
 * so a new endpoint without matrix coverage fails CI."
 *
 * That sentence forces a shape. If routes are declared by calling a framework —
 * `app.get("/sites/:id", handler)` — then the set of routes is only knowable by
 * running the framework and introspecting it, and the action each one requires
 * is knowable only by reading the handler. Neither is something a test can
 * check exhaustively, so "a new endpoint without coverage fails CI" becomes
 * "someone notices in review".
 *
 * So the route table is DATA, declared here, and the HTTP framework binds to it
 * rather than defining it. Three things follow:
 *
 *   1. Every route names the action it requires, in the same vocabulary the
 *      permission catalogue uses — an action that is not in the catalogue does
 *      not typecheck.
 *   2. The matrix generator reads this array. Adding a route adds matrix rows
 *      automatically; there is no second list to keep in step.
 *   3. A route that genuinely needs no permission has to say so explicitly and
 *      say why. `requires: null` with no `publicReason` does not typecheck.
 *
 * This module deliberately contains no handlers and no framework import. It is
 * the contract; `src/api/server.ts` will bind Hono to it (ADR 0001) without
 * being able to add a route the matrix cannot see.
 */

import { isAction, type Action } from "../authz/catalogue.ts";

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Methods that must not change state, and so need no CSRF token (RL-M1-021). */
const SAFE_METHODS: ReadonlySet<HttpMethod> = new Set(["GET"]);

/**
 * How a route's scope is worked out from the request.
 *
 * `can()` needs a scope node, and where that comes from differs per route. This
 * is declared rather than inferred so the matrix generator knows which
 * own/other-tenant/nonexistent cases to build for each route (RL-M1-025).
 */
export const SCOPE_SOURCES = [
  /** The acting context's own organization. No identifier in the path. */
  "organization",
  /** A path parameter naming a hierarchy node — a project or environment. */
  "path-node",
  /** A path parameter naming a resource whose scope node is looked up. */
  "path-resource",
] as const;
export type ScopeSource = (typeof SCOPE_SOURCES)[number];

type BaseRoute = {
  readonly method: HttpMethod;
  /** Path template with `:name` parameters, e.g. `/projects/:projectId`. */
  readonly path: string;
  readonly summary: string;
  readonly scope: ScopeSource;
  /** The path parameter naming the scope or resource, when there is one. */
  readonly scopeParam?: string;
};

/** A route that requires a permission — almost all of them. */
export type GuardedRoute = BaseRoute & {
  readonly requires: Action;
  readonly publicReason?: never;
};

/**
 * A route that requires none.
 *
 * `publicReason` is mandatory, so an unguarded route is an argued decision
 * rather than a forgotten annotation. The matrix still covers these: it asserts
 * they are reachable without a grant, which is the property they claim.
 */
export type PublicRoute = BaseRoute & {
  readonly requires: null;
  readonly publicReason: string;
};

export type Route = GuardedRoute | PublicRoute;

/**
 * Every route the API serves.
 *
 * Nothing is bound to a handler here on purpose. A route can be declared before
 * it is implemented — and the matrix will demand coverage for it either way,
 * which is the right direction to fail.
 */
export const ROUTES: readonly Route[] = [
  // --- unauthenticated ------------------------------------------------------
  {
    method: "POST",
    path: "/auth/sign-in",
    summary: "Exchange an email and password for a session",
    scope: "organization",
    requires: null,
    publicReason:
      "Signing in is how an actor comes to exist. Requiring a permission would " +
      "need an actor to check it against, and there is not one yet — the " +
      "pre-authentication context seam ADR 0014 records.",
  },
  {
    method: "POST",
    path: "/auth/sign-out",
    summary: "End the current session",
    scope: "organization",
    requires: null,
    publicReason:
      "Ending your own session must never be refused. A sign-out that can fail " +
      "authorization is one an operator cannot use when they most need to.",
  },
  {
    method: "GET",
    path: "/health",
    summary: "Liveness, for a load balancer or an operator",
    scope: "organization",
    requires: null,
    publicReason:
      "Reports only that the process is up. It reveals no tenant data, and " +
      "gating it would make an outage indistinguishable from a permission error.",
  },

  // --- organization ---------------------------------------------------------
  { method: "GET", path: "/organization", summary: "Read the current organization", scope: "organization", requires: "organization.read" },
  { method: "PATCH", path: "/organization", summary: "Update the organization", scope: "organization", requires: "organization.update" },
  { method: "DELETE", path: "/organization", summary: "Delete the organization", scope: "organization", requires: "organization.delete" },
  { method: "PUT", path: "/organization/security-policy", summary: "Set organization-wide security policy", scope: "organization", requires: "organization.manage_security_policy" },

  // --- members and grants ---------------------------------------------------
  { method: "GET", path: "/members", summary: "List members", scope: "organization", requires: "member.read" },
  { method: "POST", path: "/members", summary: "Invite a member", scope: "organization", requires: "member.invite" },
  { method: "DELETE", path: "/members/:userId", summary: "Remove a member", scope: "organization", requires: "member.remove", scopeParam: "userId" },
  { method: "POST", path: "/members/:userId/revoke-sessions", summary: "Sign a member out everywhere", scope: "organization", requires: "member.revoke_sessions", scopeParam: "userId" },
  { method: "GET", path: "/grants", summary: "List grants", scope: "organization", requires: "grant.read" },
  { method: "POST", path: "/grants", summary: "Create a grant or a deny", scope: "organization", requires: "grant.create" },
  { method: "DELETE", path: "/grants/:grantId", summary: "Revoke a grant", scope: "organization", requires: "grant.revoke", scopeParam: "grantId" },

  // --- projects and environments -------------------------------------------
  { method: "GET", path: "/projects", summary: "List projects", scope: "organization", requires: "project.read" },
  { method: "POST", path: "/projects", summary: "Create a project", scope: "organization", requires: "project.create" },
  { method: "GET", path: "/projects/:projectId", summary: "Read a project", scope: "path-node", scopeParam: "projectId", requires: "project.read" },
  { method: "PATCH", path: "/projects/:projectId", summary: "Update a project", scope: "path-node", scopeParam: "projectId", requires: "project.update" },
  { method: "DELETE", path: "/projects/:projectId", summary: "Delete a project", scope: "path-node", scopeParam: "projectId", requires: "project.delete" },
  { method: "GET", path: "/environments/:environmentId", summary: "Read an environment", scope: "path-node", scopeParam: "environmentId", requires: "environment.read" },

  // --- secrets: the name/value split has to survive into the routes ---------
  { method: "GET", path: "/environments/:environmentId/secrets", summary: "List secret names", scope: "path-node", scopeParam: "environmentId", requires: "secret.read_name" },
  { method: "GET", path: "/environments/:environmentId/secrets/:key/value", summary: "Reveal a secret value", scope: "path-node", scopeParam: "environmentId", requires: "secret.read_value" },
  { method: "PUT", path: "/environments/:environmentId/secrets/:key", summary: "Set a secret", scope: "path-node", scopeParam: "environmentId", requires: "secret.create" },

  // --- audit ----------------------------------------------------------------
  { method: "GET", path: "/audit", summary: "Read the audit log", scope: "organization", requires: "audit_log.read" },

  // --- API tokens -----------------------------------------------------------
  { method: "GET", path: "/tokens", summary: "List every API token in the organization", scope: "organization", requires: "api_token.read_any" },
  { method: "POST", path: "/tokens", summary: "Issue an API token for yourself", scope: "organization", requires: "api_token.manage_own" },
  { method: "DELETE", path: "/tokens/:tokenId", summary: "Revoke anyone's API token", scope: "organization", requires: "api_token.revoke_any", scopeParam: "tokenId" },
];

/** A stable identifier for one route, used as the matrix row key. */
export function routeKey(route: Route): string {
  return `${route.method} ${route.path}`;
}

export function isSafeMethod(method: HttpMethod): boolean {
  return SAFE_METHODS.has(method);
}

/** Routes that require a permission. */
export function guardedRoutes(routes: readonly Route[] = ROUTES): GuardedRoute[] {
  return routes.filter((route): route is GuardedRoute => route.requires !== null);
}

/** Routes that deliberately require none. */
export function publicRoutes(routes: readonly Route[] = ROUTES): PublicRoute[] {
  return routes.filter((route): route is PublicRoute => route.requires === null);
}

export type RouteProblem = { readonly route: string; readonly problem: string };

/**
 * Check the table's own integrity.
 *
 * Run by the matrix generator before it builds anything, because a matrix
 * generated from a malformed table would be exhaustive over the wrong set.
 */
export function validateRoutes(routes: readonly Route[] = ROUTES): RouteProblem[] {
  const problems: RouteProblem[] = [];
  const seen = new Set<string>();

  for (const route of routes) {
    const key = routeKey(route);
    const add = (problem: string): void => void problems.push({ route: key, problem });

    if (seen.has(key)) add("declared twice");
    seen.add(key);

    if (!route.path.startsWith("/")) add("path must start with /");
    if (route.summary.trim() === "") add("needs a summary; it is what the matrix report shows");

    if (route.requires !== null && !isAction(route.requires)) {
      // Unreachable through the types, and checked anyway: a cast, a stored
      // custom role, or a future generated table could all bring a name here
      // that the catalogue does not know.
      // `route.requires` narrows to never here — the types already exclude it,
      // which is why this branch exists only for values that arrived by cast.
      add(`requires "${String(route.requires)}", which is not in the catalogue`);
    }
    if (route.requires === null && route.publicReason.trim() === "") {
      add("an unguarded route must say why it is unguarded");
    }

    const params = [...route.path.matchAll(/:([A-Za-z][A-Za-z0-9]*)/g)].map((m) => m[1]);
    if (route.scope !== "organization") {
      if (route.scopeParam === undefined) {
        add(`scope "${route.scope}" needs a scopeParam naming the path parameter`);
      } else if (!params.includes(route.scopeParam)) {
        add(`scopeParam "${route.scopeParam}" is not a parameter of the path`);
      }
    }
    if (route.scopeParam !== undefined && !params.includes(route.scopeParam)) {
      add(`scopeParam "${route.scopeParam}" is not a parameter of the path`);
    }
  }

  return problems;
}
