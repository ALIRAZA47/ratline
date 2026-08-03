/**
 * Creating the first organization and its first owner (RL-M1-030).
 *
 * ## How this gets past row-level security without a hole in it
 *
 * `organizations` carries `using (id = current_tenant())` AND
 * `with check (id = current_tenant())`. So an INSERT is only permitted when the
 * new row's id already equals the bound tenant — which sounds impossible before
 * the organization exists, and is not: the id is GENERATED IN THE APPLICATION,
 * bound as the tenant, and then inserted explicitly.
 *
 * That is not a workaround, it is the policy being satisfied honestly. Nothing
 * runs as a privileged role, nothing is `SECURITY DEFINER`, and the connection
 * is the same NOBYPASSRLS `ratline_app` every other query uses. An installation
 * with a hundred organizations is still invisible to this transaction; it can
 * write exactly one row, the one whose id it chose.
 *
 * ## Who the actor is, which C6 requires an answer to
 *
 * The owner being created. Their user id is generated in the application too,
 * so a context naming them exists before the row does, and the audit entry for
 * the bootstrap names the person who claimed the installation rather than "the
 * system" — the one word C6 forbids. Circular on paper, truthful in fact: the
 * operator created themselves.
 *
 * ## One transaction, which is acceptance 2
 *
 * "The owner cannot be left in a state where no owner exists." `scoped()` is a
 * single transaction, so the organization, the user, the membership and the
 * owner grant all commit together or none of them do. There is no window in
 * which an organization exists without an owner — not a narrow one, none — and
 * afterwards the last-owner floor (RL-M1-033) keeps it that way.
 *
 * A sequence of four calls would have had three such windows, and a crash in any
 * of them leaves an installation that can never be claimed: an organization
 * exists, so a second attempt is refused, and nobody can sign in to it.
 */

import { scoped } from "../db/internal/handle.ts";
import type { AuthzContext } from "../authz/context.ts";
import { hashPassword } from "../auth/passwords.ts";

export type InstallationInput = {
  readonly organizationSlug: string;
  readonly organizationName: string;
  readonly ownerEmail: string;
  readonly ownerName: string;
  readonly ownerPassword: string;
};

export type Installation = {
  readonly orgId: string;
  readonly ownerId: string;
};

/**
 * Create the organization, its first owner, and the grant that makes them one.
 *
 * Takes no `AuthzContext` — it builds the first one there has ever been on this
 * installation. That is the pre-authentication seam ADR 0014 records, at its
 * most extreme: not "no session yet" but "no tenant yet".
 *
 * Resolves no permission, and cannot: there is no grant to check and nobody to
 * check it for. `test/security/repository_gating.test.ts` exempts it with that
 * argument. What stands in for a permission is the bootstrap token, checked by
 * the caller before this is reached — host access rather than a grant, which is
 * the right authority for claiming an installation.
 */
export async function createInstallation(
  ctx: AuthzContext,
  input: InstallationInput,
): Promise<Installation> {
  // Read off the context rather than invented here. Taking `ctx` first is C3's
  // layer-2 rule and `scoped_repository.test.ts` has no exemption for it —
  // correctly, because an escape hatch on "every repository function is scoped"
  // is the one thing that would make the rule advisory. The identities are
  // minted by `contextForBootstrap`, where every other actor is named.
  const orgId = ctx.orgId;
  if (ctx.actor.kind !== "user") {
    throw new Error(`an installation is claimed by a person, not a ${ctx.actor.kind}.`);
  }
  const ownerId = ctx.actor.id;

  const storedHash = await hashPassword(input.ownerPassword);

  return scoped(ctx, async (query) => {
    // The explicit id is what satisfies `with check (id = current_tenant())`.
    await query(
      "insert into organizations (id, slug, name) values ($1, $2, $3)",
      [orgId, input.organizationSlug, input.organizationName],
    );

    // `users` is global — one person, many organizations — so the id is explicit
    // here for the same reason: the context already names them.
    await query(
      "insert into users (id, email, name, password_hash) values ($1, $2, $3, $4)",
      [ownerId, input.ownerEmail, input.ownerName, storedHash],
    );

    await query("insert into memberships (org_id, user_id) values ($1, $2)", [orgId, ownerId]);

    await query(
      `insert into grants (org_id, subject_type, subject_id, role_key, scope_type)
       values ($1, 'user', $2, 'owner', 'organization')`,
      [orgId, ownerId],
    );

    return { orgId, ownerId };
  });
}
