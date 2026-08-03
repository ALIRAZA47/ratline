/**
 * Where a tenant-wide permission question is asked (RL-M1-039).
 *
 * `can()` needs a scope node for every decision, and the commonest one is "the
 * organization itself" — the root of the tenant's hierarchy, which every other
 * node inherits from. Three repositories needed it and each grew its own copy:
 * `api_tokens.ts`, `sessions.ts`, and then `two_factor.ts`, each one noting in a
 * comment that the previous copies existed.
 *
 * Three copies of a scope lookup is three chances for one of them to resolve the
 * wrong node, and the direction that mistake takes is not symmetric. A node too
 * far DOWN the tree makes a legitimate grant stop working, which is an outage
 * somebody notices immediately. A node too far UP makes a narrow grant reach
 * further than intended, which is a privilege escalation nobody notices at all —
 * and the organization root is the top of the tree, so every wrong answer here
 * is the second kind.
 *
 * So it lives once, and the three call sites import it.
 *
 * `organizationScopeRef` exists as well as `organizationScopeNode` because the
 * call sites all wrote `organizationScope(await organizationScopeNode(ctx))`,
 * which duplicated a second thing — the `ScopeRef` construction — and left three
 * more places for a `resourceId` to be filled in wrongly. `ScopeRef`'s own
 * documentation is explicit that passing a resource id when the question is not
 * about a resource silently widens the answer; there is now one place that can
 * happen instead of three.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import type { ScopeRef } from "./authorization.ts";

/**
 * The tenant's root scope node.
 *
 * No tenant predicate in the query: row-level security confines it to one
 * organization, which has exactly one node of this kind. Adding one anyway
 * would be a second tenant filter of the sort `scoped()` exists to make
 * unnecessary — and a second filter that disagreed with row-level security
 * would be the one believed.
 *
 * (Phrased without quoting the predicate, because `scoped_repository.test.ts`
 * scans source text and does not read comments differently from code. That is
 * the right trade — a scanner that tried to tell them apart would be a second
 * parser to get wrong — so prose here must not spell out the thing it forbids.)
 *
 * Throws rather than returning null. A tenant with no root node cannot answer a
 * permission question at all, so there is nothing sensible for a caller to do
 * with the absence, and returning null would invite `?? someFallback`.
 */
export async function organizationScopeNode(ctx: AuthzContext): Promise<string> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>("select id from scope_nodes where kind = 'organization'");
    const row = rows[0];
    if (row === undefined) {
      throw new Error("this organization has no root scope node; the tenant is not usable");
    }
    return row.id;
  });
}

/**
 * The organization-wide `ScopeRef`, ready to hand to `can()` or `require()`.
 *
 * `resourceId` is null and cannot be anything else, because this is by
 * definition not a question about a specific resource. That is the whole reason
 * it is a function here rather than an object literal at each call site.
 */
export async function organizationScopeRef(ctx: AuthzContext): Promise<ScopeRef> {
  return { scopeNodeId: await organizationScopeNode(ctx), resourceId: null };
}
