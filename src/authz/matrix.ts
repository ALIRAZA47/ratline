/**
 * The authorization matrix, generated from the route table (RL-M1-024).
 *
 * Brief §6.3's acceptance gate: "an exhaustive authorization matrix test — every
 * role × every endpoint × own-resource / other-team-resource /
 * nonexistent-resource ... The matrix is generated from the route table so a new
 * endpoint without matrix coverage fails CI."
 *
 * Generated, not written. A hand-maintained matrix is a second list that drifts
 * from the first, and it drifts in the direction of omission: the endpoint
 * someone forgot to add is exactly the one nobody tested. Here, adding a route
 * adds its rows the moment it is declared — before a handler exists, which is
 * the right direction to fail.
 *
 * THE THREE SUBJECTS matter as much as the roles, and the third is the one
 * usually missed:
 *
 *   own            a resource in the actor's own tenant
 *   other-tenant   a REAL resource belonging to somebody else
 *   nonexistent    an identifier that names nothing
 *
 * `other-tenant` is the IDOR case — a valid identifier the caller should not
 * reach. `nonexistent` exists to be compared against it: §6.3 requires the two
 * to be indistinguishable, and that is only checkable if both are generated for
 * every route (RL-M1-026).
 */

import { ALL_DEFAULT_ROLES } from "./roles.ts";
import { ROUTES, routeKey, validateRoutes, type Route } from "../api/routes.ts";

export const MATRIX_SUBJECTS = ["own", "other-tenant", "nonexistent"] as const;
export type MatrixSubject = (typeof MATRIX_SUBJECTS)[number];

export type MatrixCell = {
  readonly routeKey: string;
  readonly method: string;
  readonly path: string;
  readonly roleKey: string;
  readonly subject: MatrixSubject;
  /** The action the route requires, or null for a deliberately unguarded one. */
  readonly action: string | null;
  /**
   * What the matrix expects, derived from the route and the role rather than
   * recorded by hand — a hand-written expectation is a second opinion about the
   * permission model, and the whole point is that there is only one.
   */
  readonly expected: "allow" | "deny";
  /** Why, so a failing cell reports something a human can act on. */
  readonly because: string;
};

/**
 * What SHOULD happen for one role on one route against one subject.
 *
 * The rule is short on purpose. Anything longer would be a reimplementation of
 * `can()`, and a matrix that reimplements the thing it tests agrees with it by
 * construction — including when both are wrong.
 */
function expectationFor(
  route: Route,
  roleKey: string,
  roleActions: readonly string[],
  subject: MatrixSubject,
): { expected: "allow" | "deny"; because: string } {
  if (route.requires === null) {
    return {
      expected: "allow",
      because: `unguarded route: ${route.publicReason.split(".")[0] ?? "declared public"}`,
    };
  }

  // A resource in another tenant, or none at all, is refused whatever the role
  // holds. This is the row that catches an IDOR, and it is deliberately
  // independent of the role: an Owner must not reach another tenant either.
  if (subject !== "own") {
    return {
      expected: "deny",
      because:
        subject === "other-tenant"
          ? "a resource in another tenant is unreachable regardless of role"
          : "an identifier that names nothing is unreachable regardless of role",
    };
  }

  if (roleActions.includes(route.requires)) {
    return { expected: "allow", because: `${roleKey} carries ${route.requires}` };
  }
  return { expected: "deny", because: `${roleKey} does not carry ${route.requires}` };
}

export class MatrixGenerationError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`the route table is not fit to generate a matrix from:\n  ${problems.join("\n  ")}`);
    this.name = "MatrixGenerationError";
    this.problems = problems;
  }
}

/**
 * Build every cell.
 *
 * Refuses outright if the route table is malformed. A matrix generated from a
 * broken table would be exhaustive over the wrong set, which is worse than no
 * matrix because it reports coverage it does not have.
 */
export function generateMatrix(routes: readonly Route[] = ROUTES): MatrixCell[] {
  const problems = validateRoutes(routes);
  if (problems.length > 0) {
    throw new MatrixGenerationError(problems.map((p) => `${p.route}: ${p.problem}`));
  }

  const cells: MatrixCell[] = [];
  for (const route of routes) {
    for (const role of ALL_DEFAULT_ROLES) {
      for (const subject of MATRIX_SUBJECTS) {
        const { expected, because } = expectationFor(route, role.key, role.actions, subject);
        cells.push({
          routeKey: routeKey(route),
          method: route.method,
          path: route.path,
          roleKey: role.key,
          subject,
          action: route.requires,
          expected,
          because,
        });
      }
    }
  }
  return cells;
}

/** Every route the matrix covers. Compared against the route table by the harness. */
export function coveredRoutes(cells: readonly MatrixCell[]): Set<string> {
  return new Set(cells.map((cell) => cell.routeKey));
}

/**
 * Routes declared but not covered.
 *
 * Always empty while the matrix is generated from the same table — which is the
 * point, and is exactly why the harness asserts it rather than assuming it. If
 * this is ever non-empty, generation has been bypassed.
 */
export function uncoveredRoutes(
  cells: readonly MatrixCell[],
  routes: readonly Route[] = ROUTES,
): string[] {
  const covered = coveredRoutes(cells);
  return routes.map(routeKey).filter((key) => !covered.has(key));
}

export type MatrixSummary = {
  readonly routes: number;
  readonly roles: number;
  readonly cells: number;
  readonly expectedAllow: number;
  readonly expectedDeny: number;
};

export function summariseMatrix(cells: readonly MatrixCell[]): MatrixSummary {
  return {
    routes: coveredRoutes(cells).size,
    roles: new Set(cells.map((c) => c.roleKey)).size,
    cells: cells.length,
    expectedAllow: cells.filter((c) => c.expected === "allow").length,
    expectedDeny: cells.filter((c) => c.expected === "deny").length,
  };
}
