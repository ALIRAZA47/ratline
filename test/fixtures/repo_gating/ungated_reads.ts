/**
 * FIXTURE — every export here except `listSitesGated` MUST be reported by the
 * repository-gating scan (RL-M1-052, acceptance 3).
 *
 * It lives outside `src/` so the real scan never reads it and the EXEMPT list in
 * test/security/repository_gating.test.ts never has to mention it. That test
 * points the scan at this directory on purpose and asserts it fires.
 *
 * Do not add permission checks to these functions and do not "tidy" the shapes:
 * the findings are the point. If this file ever scans clean, the scan has
 * stopped seeing a shape it is supposed to see — which is what RL-M1-052 was,
 * and it looked exactly like a passing gate for a whole session.
 *
 * It still has to typecheck, because tsconfig.json includes test/ ** /*.ts.
 */

import { require as requirePermission } from "../../../src/authz/can.ts";
import type { AuthzContext } from "../../../src/authz/context.ts";
import { organizationScopeRef } from "../../../src/repo/scope.ts";

/**
 * The shape RL-M1-052 exists about: non-async, because it only returns the
 * promise it already has. Invisible to the old `export async function` pattern.
 */
export function listSitesNotAsync(ctx: AuthzContext): Promise<string[]> {
  return Promise.resolve([ctx.orgId]);
}

/** The shape the scan always saw, kept so a fix cannot narrow it by accident. */
export async function listSitesAsync(ctx: AuthzContext): Promise<string[]> {
  return Promise.resolve([ctx.orgId]);
}

export function listSitesGatedOnlyInAComment(ctx: AuthzContext): Promise<string[]> {
  // This body names requirePermission(ctx, "site.read") and calls nothing. The
  // gate is a string match, so stripping comments is the only thing standing
  // between "explains the check it should do" and "counts as having done it".
  return Promise.resolve([ctx.orgId]);
}

/** Genuinely gated, so the fixture proves the scan discriminates. */
export async function listSitesGated(ctx: AuthzContext): Promise<string[]> {
  await requirePermission(ctx, "project.read", await organizationScopeRef(ctx));
  return [ctx.orgId];
}
