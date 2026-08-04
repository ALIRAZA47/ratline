/**
 * FIXTURE — an ungated repository export one directory down (RL-M1-052).
 *
 * The gating scan globbed `src/repo/*.ts` while scoped_repository.test.ts globbed
 * `src/repo/** /*.ts`, so a repository module in a subdirectory would have been
 * made to take an AuthzContext by one scan and never asked for a permission by
 * the other. There are no subdirectories in src/repo today, which is exactly why
 * the difference needed a fixture rather than a comment: without this file the
 * widened glob would be an untested change.
 *
 * As with its sibling, the finding is the point. Do not gate it.
 */

import type { AuthzContext } from "../../../../src/authz/context.ts";

export function listSitesInASubdirectory(ctx: AuthzContext): Promise<string[]> {
  return Promise.resolve([ctx.orgId]);
}
