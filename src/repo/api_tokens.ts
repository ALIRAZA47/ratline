/**
 * API tokens (RL-M1-032).
 *
 * Brief §6.3: "API tokens carry a subset of the issuing user's permissions and
 * never more. Scoped, expiring, revocable, with last-used tracking and an
 * obvious revoke-all."
 *
 * This module writes and reads tokens. It does not decide anything: the ceiling
 * that makes a token a *subset* is `can()`, evaluated on every use, and the
 * checks below call that same function rather than reasoning about permissions
 * themselves. That division is the point — §6.3 allows exactly one decision
 * function, and an issue-time check written as its own comparison of role sets
 * would be a second one, free to disagree with the first.
 *
 * ## Why the check happens twice, and why the second time is the one that counts
 *
 * At ISSUE time a grant the issuer does not hold is refused, so a token cannot
 * be created carrying more than the person creating it. That is the half that is
 * easy and the half that is not sufficient: the issuer can be demoted five
 * minutes later, and nothing about the token's rows changes when they are. So
 * `can()` re-asks the issuing user's authority on every decision (threat model
 * R-12). The issue-time refusal is here for the operator's sake — a token that
 * silently carried nothing would be a support ticket — not for the attacker's.
 *
 * ## The secret
 *
 * The plaintext is generated here, returned exactly once, and never stored. What
 * goes to the database is a SHA-256 digest, and migration 7 constrains the
 * column so that a plaintext token cannot be written into it even by hand. There
 * is no function in this module that returns a stored secret, because there is
 * nothing stored to return.
 */

import { createHash, randomBytes } from "node:crypto";

import { scoped } from "../db/internal/handle.ts";
import { require as requirePermission } from "../authz/can.ts";
import { ALL_DEFAULT_ROLES } from "../authz/roles.ts";
import type { Action } from "../authz/catalogue.ts";
import type { AuthzContext } from "../authz/context.ts";
import type { ScopeRef } from "./authorization.ts";

/**
 * One thing a token is allowed to do: a role, at a place in the hierarchy.
 *
 * The scope is a {@link ScopeRef} — the shape `can()` takes — rather than the
 * `(scope_type, scope_id)` pair the `grants` table stores, because the question
 * asked at issue time and the question asked at use time have to be the same
 * question. The mapping to columns happens once, below, against the node's own
 * kind, so a caller cannot label a project node "organization" and widen the
 * grant by mislabelling it.
 */
export type ApiTokenGrantInput = {
  readonly roleKey: string;
  readonly scopeNodeId: string;
  /** The resource, when the grant is about one. Null otherwise — never omitted. */
  readonly resourceId: string | null;
};

export type IssueApiTokenInput = {
  /** Operator-facing label: "CI deploys", "laptop". Not a secret. */
  readonly name: string;
  /** Mandatory. §6.3 lists "expiring" as part of what a token is. */
  readonly expiresAt: Date;
  readonly grants: readonly ApiTokenGrantInput[];
};

/** A token as anyone may see it. There is no field here for the secret. */
export type ApiToken = {
  readonly id: string;
  readonly name: string;
  readonly issuedBy: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  readonly lastUsedAt: Date | null;
};

export type IssuedApiToken = {
  readonly token: ApiToken;
  /**
   * The plaintext, the only time it exists outside the caller's memory.
   *
   * Show it once and forget it. It is not recoverable, by design and by schema:
   * what the database holds is a digest, and a digest is not reversible.
   */
  readonly secret: string;
};

type TokenRow = {
  id: string;
  name: string;
  issued_by: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  last_used_at: Date | null;
};

const toApiToken = (row: TokenRow): ApiToken => ({
  id: row.id,
  name: row.name,
  issuedBy: row.issued_by,
  createdAt: row.created_at,
  expiresAt: row.expires_at,
  revokedAt: row.revoked_at,
  lastUsedAt: row.last_used_at,
});

/** The columns a token is described by. Never `token_hash`. */
const TOKEN_COLUMNS = "id, name, issued_by, created_at, expires_at, revoked_at, last_used_at";

// ---------------------------------------------------------------------------
// The secret
// ---------------------------------------------------------------------------

/**
 * 256 bits from the platform's cryptographic source (brief §6.7: prefer the
 * standard library). Enough that the digest below needs no work factor: there is
 * no dictionary to attack, so a password KDF would buy nothing and cost a
 * hashing round on every authenticated request.
 */
const SECRET_BYTES = 32;

/** So an operator who finds one in a log knows what they are looking at. */
const SECRET_PREFIX = "rlt_";

function mintSecret(): string {
  return `${SECRET_PREFIX}${randomBytes(SECRET_BYTES).toString("base64url")}`;
}

/**
 * What gets stored. Hex, lowercase, 64 characters — the shape migration 7's
 * CHECK constrains the column to, so the "store only a hash" rule is enforced by
 * the database rather than by this function being called.
 */
function digestOf(secret: string): string {
  return createHash("sha256").update(secret, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The actions a role carries.
 *
 * An unrecognised role throws rather than returning nothing. An empty list would
 * make the ceiling check below vacuous — every one of zero actions is permitted
 * — so the failure mode of a typo'd or unknown role key would be a token issued
 * with no check at all. That is the one direction this must not fail in.
 */
function actionsCarriedBy(roleKey: string): readonly Action[] {
  const role = ALL_DEFAULT_ROLES.find((candidate) => candidate.key === roleKey);
  if (role === undefined) {
    throw new Error(
      `"${roleKey}" is not a role. A token cannot be given a role whose actions are unknown, ` +
        `because there would be nothing to check its issuer against.`,
    );
  }
  return role.actions;
}

/** The tenant's root hierarchy node, which organization-scope questions ask about. */
async function organizationScopeNode(ctx: AuthzContext): Promise<string> {
  return scoped(ctx, async (query) => {
    // No tenant predicate: row-level security confines this to one organization,
    // which has exactly one root node.
    const rows = await query<{ id: string }>("select id from scope_nodes where kind = 'organization'");
    const row = rows[0];
    if (row === undefined) {
      throw new Error("this organization has no root scope node; the tenant is not usable");
    }
    return row.id;
  });
}

const organizationScope = (scopeNodeId: string): ScopeRef => ({ scopeNodeId, resourceId: null });

/**
 * Map a {@link ScopeRef} onto the `(scope_type, scope_id)` pair the table stores.
 *
 * The kind is read from the node rather than taken from the caller. A caller who
 * could name the scope type could write `('organization', null)` against a
 * project node and silently widen the grant to the whole tenant — and the
 * issue-time check would have passed, because it was asked about the project.
 */
async function scopeColumns(
  ctx: AuthzContext,
  grant: ApiTokenGrantInput,
): Promise<{ scopeType: string; scopeId: string | null }> {
  if (grant.resourceId !== null) {
    // A resource is the fifth level of §6.3's hierarchy and owns no node, so it
    // is matched by identity. Nothing inherits from it.
    return { scopeType: "resource", scopeId: grant.resourceId };
  }
  return scoped(ctx, async (query) => {
    const rows = await query<{ kind: string }>("select kind from scope_nodes where id = $1", [
      grant.scopeNodeId,
    ]);
    const kind = rows[0]?.kind;
    if (kind === undefined) {
      // Unreachable through issueApiToken, which asks can() about this node
      // first and is refused with `unknown-scope` when it does not exist. Kept
      // because "unreachable" is a claim about today's callers.
      throw new Error(`scope node ${grant.scopeNodeId} does not exist in this organization`);
    }
    // An organization-scope grant covers the whole tenant and names no node.
    return kind === "organization"
      ? { scopeType: "organization", scopeId: null }
      : { scopeType: kind, scopeId: grant.scopeNodeId };
  });
}

/** Who issued this token, or null when it is absent or belongs to another tenant. */
async function issuerOf(ctx: AuthzContext, tokenId: string): Promise<string | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ issued_by: string }>("select issued_by from api_tokens where id = $1", [
      tokenId,
    ]);
    return rows[0]?.issued_by ?? null;
  });
}

/**
 * Managing your own tokens escalates nothing, because a token never carries more
 * than you hold; reaching someone else's is administration. The catalogue splits
 * the actions on exactly that line (`api_token.manage_own` against
 * `api_token.read_any` / `api_token.revoke_any`), and `can()` cannot make the
 * distinction itself: it decides about an action at a scope and has no notion of
 * a row belonging to someone.
 *
 * So the comparison below is the only thing this module decides, and it is a
 * question about data — "is this row yours" — not about permissions. Which
 * action that answer selects, and whether the actor holds it, is `can()`'s.
 */
function isSelf(ctx: AuthzContext, userId: string): boolean {
  return ctx.actor.kind === "user" && ctx.actor.id === userId;
}

// ---------------------------------------------------------------------------
// Issuing
// ---------------------------------------------------------------------------

/**
 * Issue a token, refusing any grant its issuer does not currently hold.
 *
 * The issuer is the acting user, never a named third party: "a subset of the
 * issuing user's permissions" has no meaning if the issuer and the actor can be
 * different people, and admin-issues-for-someone-else would be a way to mint a
 * credential whose ceiling is somebody else's. It follows that a token cannot
 * issue another token, which is the delegation chain closing itself.
 *
 * @param resolveActions which actions a role carries. A parameter for the reason
 * `can()`'s role resolver is one: custom roles (RL-M5-001) come from the
 * database, and a second issue-time path for them would be the duplicated
 * permission logic §6.3 forbids.
 */
export async function issueApiToken(
  ctx: AuthzContext,
  input: IssueApiTokenInput,
  resolveActions: (roleKey: string) => readonly Action[] = actionsCarriedBy,
): Promise<IssuedApiToken> {
  if (ctx.actor.kind !== "user") {
    throw new Error(
      `only a user may issue an API token; this context acts as a ${ctx.actor.kind}. ` +
        `A token's permissions are bounded by the issuing user's, so an issuer that is not ` +
        `a user has no ceiling to be bounded by.`,
    );
  }
  const issuedBy = ctx.actor.id;

  // Issuing is itself an action, checked in the data layer rather than left to a
  // route handler (brief §9).
  await requirePermission(ctx, "api_token.manage_own", organizationScope(await organizationScopeNode(ctx)));

  // THE CEILING, AT ISSUE TIME.
  //
  // Asked one catalogued action at a time, against the same `can()` every
  // request goes through. A cheaper shape suggests itself — compare the issuer's
  // roles with the token's and require containment — and it is wrong in both
  // directions: it ignores denies, and it cannot see that two different roles
  // may carry the same action. Permissions intersect at the level of actions,
  // which is the level the catalogue is written at.
  //
  // The cost is one decision per action in the role, at issue time only. That is
  // the right place to be slow: issuing a token is rare, using one is not.
  for (const grant of input.grants) {
    const scope: ScopeRef = { scopeNodeId: grant.scopeNodeId, resourceId: grant.resourceId };
    const actions = resolveActions(grant.roleKey);
    if (actions.length === 0) {
      throw new Error(
        `role "${grant.roleKey}" carries no actions, so there is nothing to check its issuer ` +
          `against. Refusing rather than issuing a token whose ceiling was never tested.`,
      );
    }
    for (const action of actions) {
      // Throws NotPermittedError, carrying the decision and its reason, so the
      // caller can say WHICH permission the issuer lacked.
      await requirePermission(ctx, action, scope);
    }
  }

  // The columns are resolved before the write so the transaction below holds
  // only the inserts; nothing here can widen a grant, because the scope type
  // comes from the node itself.
  const columns = await Promise.all(input.grants.map((grant) => scopeColumns(ctx, grant)));

  const secret = mintSecret();
  const token = await scoped(ctx, async (query) => {
    const rows = await query<TokenRow>(
      // `current_tenant()` rather than a parameter: the tenant comes from the
      // transaction, so there is no argument a caller could get wrong and no
      // way to aim this insert at another organization. Row-level security
      // would refuse it anyway; this makes the attempt unwriteable.
      `insert into api_tokens (org_id, issued_by, name, token_hash, expires_at)
       values (current_tenant(), $1, $2, $3, $4)
       returning ${TOKEN_COLUMNS}`,
      [issuedBy, input.name, digestOf(secret), input.expiresAt],
    );
    const row = rows[0];
    if (row === undefined) throw new Error("the API token was not written");

    for (const [index, grant] of input.grants.entries()) {
      const column = columns[index];
      if (column === undefined) throw new Error("scope columns were not resolved for every grant");
      await query(
        // No expiry of its own: the token's expiry is asked once per request,
        // the way "may this actor act at all" is. See migration 7.
        `insert into grants (org_id, subject_type, subject_id, role_key, scope_type, scope_id, granted_by)
         values (current_tenant(), 'api_token', $1, $2, $3, $4, $5)`,
        [row.id, grant.roleKey, column.scopeType, column.scopeId, issuedBy],
      );
    }
    return toApiToken(row);
  });

  return { token, secret };
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/**
 * The live token this secret names, or null.
 *
 * Null for a secret that matches nothing, for a revoked or expired token, and
 * for a token in another tenant — the caller cannot tell which, because neither
 * can the query. Lookup is by digest, so the secret is never compared against
 * anything stored: there is nothing stored to compare it against.
 */
export async function findApiTokenBySecret(ctx: AuthzContext, secret: string): Promise<ApiToken | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<TokenRow>(
      // The liveness view, never the table: reading the table here is the one
      // mistake that would let a revoked token authenticate. The view carries no
      // `revoked_at`, because a row that has one is not in it.
      `select id, name, issued_by, created_at, expires_at, null::timestamptz as revoked_at, last_used_at
       from live_api_tokens where token_hash = $1`,
      [digestOf(secret)],
    );
    const row = rows[0];
    return row === undefined ? null : toApiToken(row);
  });
}

/**
 * Every token a person holds, live or not, newest first.
 *
 * Revoked and expired tokens are included on purpose: "inspect" means seeing
 * that the token you revoked on Tuesday is revoked, not seeing it vanish.
 */
export async function listApiTokensIssuedBy(ctx: AuthzContext, userId: string): Promise<ApiToken[]> {
  await requirePermission(
    ctx,
    isSelf(ctx, userId) ? "api_token.manage_own" : "api_token.read_any",
    organizationScope(await organizationScopeNode(ctx)),
  );
  return scoped(ctx, async (query) => {
    const rows = await query<TokenRow>(
      `select ${TOKEN_COLUMNS} from api_tokens where issued_by = $1 order by created_at desc, id`,
      [userId],
    );
    return rows.map(toApiToken);
  });
}

// ---------------------------------------------------------------------------
// Use, and the end of it
// ---------------------------------------------------------------------------

/**
 * Record that this token was used, and return when.
 *
 * §6.3 asks for last-used tracking, which is how a stale token is spotted and
 * how a compromised one is recognised after the fact. Null when the token is
 * absent, revoked or expired — a dead token has no use to record.
 *
 * Not gated by `can()` and not called from it. This is the authentication path
 * noting a fact about the request it is already serving, not an action anyone
 * takes; `can()` holds no writes at all, and a decision function that wrote a
 * row would make every permission check a write.
 */
export async function recordApiTokenUse(ctx: AuthzContext, tokenId: string): Promise<Date | null> {
  return scoped(ctx, async (query) => {
    const rows = await query<{ last_used_at: Date }>(
      `update api_tokens set last_used_at = statement_timestamp()
       where id = $1 and exists (select 1 from live_api_tokens live where live.id = api_tokens.id)
       returning last_used_at`,
      [tokenId],
    );
    return rows[0]?.last_used_at ?? null;
  });
}

/**
 * Revoke one token. True when it was live and is not any more.
 *
 * False for a token that is absent, in another tenant, or already revoked —
 * revocation is idempotent, and a caller that could tell "already revoked" from
 * "never existed" would have an oracle for other people's token ids.
 */
export async function revokeApiToken(ctx: AuthzContext, tokenId: string): Promise<boolean> {
  const issuer = await issuerOf(ctx, tokenId);
  if (issuer === null) return false;

  await requirePermission(
    ctx,
    isSelf(ctx, issuer) ? "api_token.manage_own" : "api_token.revoke_any",
    organizationScope(await organizationScopeNode(ctx)),
  );

  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(
      `update api_tokens set revoked_at = statement_timestamp()
       where id = $1 and revoked_at is null
       returning id`,
      [tokenId],
    );
    return rows.length > 0;
  });
}

/**
 * Revoke every token a person holds, and say how many were live.
 *
 * §6.3 asks for "an obvious revoke-all", and this is the shape it takes when
 * someone's laptop is missing: one call, no list to work through, no token left
 * behind because it was not on the screen. It is deliberately not filtered by
 * expiry — a token that has already lapsed is left alone, which costs nothing
 * and keeps the returned count meaning "credentials this killed".
 */
export async function revokeApiTokensIssuedBy(ctx: AuthzContext, userId: string): Promise<number> {
  await requirePermission(
    ctx,
    isSelf(ctx, userId) ? "api_token.manage_own" : "api_token.revoke_any",
    organizationScope(await organizationScopeNode(ctx)),
  );

  return scoped(ctx, async (query) => {
    const rows = await query<{ id: string }>(
      `update api_tokens set revoked_at = statement_timestamp()
       where issued_by = $1 and revoked_at is null
       returning id`,
      [userId],
    );
    return rows.length;
  });
}
