/**
 * Organization and membership queries (RL-M1-007).
 *
 * The shape every repository module follows:
 *
 *   - `ctx: AuthzContext` is the FIRST parameter of every exported function.
 *   - Nothing here writes a tenant predicate by hand. `scoped()` binds the
 *     tenant for the transaction and row-level security applies it, so a
 *     forgotten `where org_id = ...` changes nothing about what comes back.
 *   - A row that does not exist and a row in another tenant both return `null`.
 *     Not by mapping an error — the query genuinely cannot see the row, so the
 *     caller has nothing to distinguish. That is what makes RL-M1-026's
 *     indistinguishable-404 requirement structural rather than a response
 *     formatting rule.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import { require as requirePermission } from "../authz/can.ts";
import { organizationScopeRef } from "./scope.ts";

export type Organization = {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly createdAt: Date;
};

export type Member = {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly joinedAt: Date;
};

type OrganizationRow = { id: string; slug: string; name: string; created_at: Date };
type MemberRow = { user_id: string; email: string; name: string; joined_at: Date };

const toOrganization = (row: OrganizationRow): Organization => ({
  id: row.id,
  slug: row.slug,
  name: row.name,
  createdAt: row.created_at,
});

/**
 * The organization this context is scoped to, or null.
 *
 * Note there is no `id` parameter: a context names exactly one tenant, so
 * "which organization" is not a question a caller gets to ask. An
 * organization-by-id lookup would be the unscoped read C3 forbids.
 */
export async function currentOrganization(ctx: AuthzContext): Promise<Organization | null> {
  await requirePermission(ctx, "organization.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<OrganizationRow>("select id, slug, name, created_at from organizations");
    const row = rows[0];
    return row === undefined ? null : toOrganization(row);
  });
}

/** Members of the current tenant. */
export async function listMembers(ctx: AuthzContext): Promise<Member[]> {
  await requirePermission(ctx, "member.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<MemberRow>(
      `select m.user_id, u.email::text as email, u.name, m.created_at as joined_at
       from memberships m
       join users u on u.id = m.user_id
       order by u.email`,
    );
    return rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      name: row.name,
      joinedAt: row.joined_at,
    }));
  });
}

/**
 * One member by user id, or null.
 *
 * This is the `findById` shape C3 is written about, and it is safe for a reason
 * worth being precise about: the `where` clause below narrows, it does not
 * authorize. Delete it and this function returns the whole tenant's membership
 * — never another tenant's. `test/security/scoped_repository.test.ts` proves
 * that by running the query with the predicate removed.
 */
export async function findMember(ctx: AuthzContext, userId: string): Promise<Member | null> {
  await requirePermission(ctx, "member.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<MemberRow>(
      `select m.user_id, u.email::text as email, u.name, m.created_at as joined_at
       from memberships m
       join users u on u.id = m.user_id
       where m.user_id = $1`,
      [userId],
    );
    const row = rows[0];
    return row === undefined
      ? null
      : { userId: row.user_id, email: row.email, name: row.name, joinedAt: row.joined_at };
  });
}

/** Projects in the current tenant, newest first. */
export async function listProjects(
  ctx: AuthzContext,
): Promise<{ id: string; slug: string; name: string }[]> {
  await requirePermission(ctx, "project.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string; slug: string; name: string }>(
      "select id, slug::text as slug, name from projects order by created_at desc",
    );
    return rows.map((row) => ({ id: row.id, slug: row.slug, name: row.name }));
  });
}

/**
 * A project by id, or null when it does not exist OR belongs to another tenant.
 * The caller cannot tell which, because neither can the query.
 */
export async function findProject(
  ctx: AuthzContext,
  projectId: string,
): Promise<{ id: string; slug: string; name: string } | null> {
  // Resolved at ORGANIZATION scope rather than at the project's own node, which
  // is wider than it needs to be and is the safe direction: a grant made at the
  // project would also satisfy an organization-scoped check by inheritance, so
  // narrowing this later can only refuse more. Narrowing it properly means
  // resolving the project's scope node first, which is a read this function is
  // about to perform — the ordering is RL-M1-042's business, not this fix's.
  await requirePermission(ctx, "project.read", await organizationScopeRef(ctx));
  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string; slug: string; name: string }>(
      "select id, slug::text as slug, name from projects where id = $1",
      [projectId],
    );
    return rows[0] ?? null;
  });
}

/**
 * The organization's name and one member's email, for the label an
 * authenticator application shows (RL-M1-019, exempted by RL-M1-043).
 *
 * ## Why this is not gated, argued rather than assumed
 *
 * Enrolling a second factor happens at the WORST moment to require a
 * permission: a person forced into enrolment at their first sign-in may hold no
 * grants at all, and a member who has just had their factor reset is in the
 * same position. Gating the label behind `organization.read` and `member.read`
 * made exactly those people unable to enrol — which the two-factor suite caught
 * the moment those reads were gated.
 *
 * What it returns is not privileged either way. Every member of a tenant knows
 * which organization they are in; the email belongs to the person being
 * enrolled. The caller has already proven the right to enrol them —
 * `startEnrolment` resolved the subject and refused if it could not — so this
 * runs after the decision rather than instead of it.
 *
 * It is deliberately narrow: two fields, no list, no lookup by anything but the
 * id the enrolment already returned. A wider read here would be the exemption
 * quietly becoming a bypass.
 */
export async function enrolmentLabel(
  ctx: AuthzContext,
  userId: string,
): Promise<{ organizationName: string; email: string }> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ name: string; email: string }>(
      `select o.name, u.email::text as email
       from organizations o
       join memberships m on m.org_id = o.id
       join users u on u.id = m.user_id
       where m.user_id = $1`,
      [userId],
    );
    const row = rows[0];
    return {
      organizationName: row?.name ?? "Ratline",
      email: row?.email ?? userId,
    };
  });
}
