/**
 * Every repository read resolves a permission, or says why not (RL-M1-043).
 *
 * ## What went wrong, and why nothing noticed
 *
 * `listAudit` performed no permission check. `audit_log.read` is held by Owner
 * and Admin only, so every authenticated member of a tenant — Viewer, Billing,
 * anyone — could read the entire audit log. `listMembers`, `findMember`,
 * `listProjects`, `findProject` and both audit-verification reads were the same.
 * Row-level security still confined them to one tenant, so it was a
 * within-tenant privilege gap rather than a cross-tenant one, and nothing
 * called them over HTTP because there is no server. That is the only reason it
 * was not live.
 *
 * It went unnoticed because C3's three layers all held. The raw handle was
 * unreachable, the context was branded, RLS was forced — and none of those
 * layers has an opinion about WHICH member of a tenant is asking. That is the
 * question `can()` answers, and these functions never asked it.
 *
 * ## Why this is a test rather than six fixes
 *
 * The six checks are the easy part and they are not the point. Nothing stopped
 * the seventh read from being written the same way, and nothing would have
 * stopped it a year from now. So the rule is enforced here: an exported
 * repository function either resolves a permission or appears on the list
 * below with an argument for why it does not.
 *
 * The exemptions are real and some are load-bearing — a pre-authentication
 * lookup cannot check a permission because there is no actor yet. A list that
 * has to be argued into is a different thing from a rule nobody applies.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * Exported repository functions that legitimately resolve no permission.
 *
 * Every entry needs a reason that would survive review. "It is only called from
 * somewhere safe" is not one: the export is what makes it reachable, and the
 * next caller is not the one you are thinking of.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  // --- writes that follow a decision already made ---------------------------
  recordAudit:
    "Writes the record OF a decision. Gating it would mean a denial could not be " +
    "audited unless the denied actor could read audit, which inverts C6.",

  // --- pre-authentication, where there is no actor to check -----------------
  createInstallation:
    "Builds the first AuthzContext there has ever been on this installation — not " +
    "'no session yet' but 'no tenant yet'. There is no grant to check and nobody to " +
    "check it for. What stands in for a permission is the bootstrap token, checked " +
    "before this is reached: host access rather than a grant, which is the right " +
    "authority for claiming an installation (RL-M1-030).",
  findPasswordCredential:
    "Runs before an actor exists. Requiring a permission would need somebody to " +
    "check it against, and the whole point is that nobody is authenticated yet (ADR 0014).",
  startSession:
    "Creates the credential authentication produces. The same pre-authentication " +
    "seam as findPasswordCredential: there is nobody to check until this succeeds.",
  useSessionToken:
    "Resolves a bearer token into a session. This IS the authentication step; a " +
    "permission check here would need the session it is in the middle of establishing.",
  updatePasswordHash:
    "Self-writes need no permission — a person securing their own account must not " +
    "depend on grants they may have just lost. Non-self writes DO resolve " +
    "member.reset_password inside the function (RL-M1-034).",

  // --- the permission mechanism itself --------------------------------------
  //
  // These three cannot resolve a permission because they are what resolving a
  // permission is made of. `require()` calls checkFreshness on every gated
  // action (RL-M1-037), so a permission check inside them would be infinitely
  // recursive — not merely awkward, impossible.
  readReauthPolicy:
    "Reads the organization's own re-authentication policy, and is called BY " +
    "require() on every gated action. Gating it would be circular. It reads no " +
    "tenant data beyond the policy row, which row-level security already confines.",
  checkFreshness:
    "The freshness half of require() itself. Same circularity, and it reads only " +
    "the acting session's own timestamp.",
  markAuthenticated:
    "Moves the timestamp that grants privilege, so it is the one here that needed " +
    "real defending. There is no permission that should let one person refresh " +
    "another's authentication — proving a password is something only its owner can " +
    "do — so the UPDATE is scoped to ctx.actor.id in the statement. The predicate " +
    "IS the check, and unlike a caller-side one it cannot be skipped.",

  // --- reads of your own credentials ----------------------------------------
  listOwnSessions:
    "Your own sessions, and only ever your own — the function takes no subject. " +
    "Reading them is not authority over anyone else, and listing SOMEBODY else's " +
    "is a separate action the catalogue does not yet have.",
  revokeSessionById:
    "Ends one of your own sessions. Anyone else's goes through revokeSessionsOfUser, " +
    "which resolves member.revoke_sessions inside itself.",
  revokeSessionByToken:
    "Ends the session whose token was presented. Holding the bearer credential IS " +
    "the authorization, and signing yourself out must never be refusable.",
  replaceSession:
    "Rotates the caller's own session, which is part of the authentication path " +
    "rather than an action over anybody. Requiring a grant would break sign-in for " +
    "an account whose grants were just revoked, which is when rotation matters most.",
  countOwnRecoveryCodes:
    "Counts your own remaining codes and returns no code. Takes no subject, so it " +
    "cannot be aimed at anyone else.",

  // --- two-factor, which runs at the worst moment to require a grant --------
  readSecurityPolicy:
    "Consulted by sign-in to decide whether a factor is owed, which happens before a " +
    "session exists. Gating it would make the policy unenforceable against exactly " +
    "the people it is meant to bind.",
  readSecondFactorRequirement:
    "The same pre-session seam, returning one boolean about the person signing in " +
    "and nothing about anybody else.",
  startChallenge:
    "Issued by the sign-in path to somebody who has proven a password and holds no " +
    "session. There is no actor yet to resolve a permission against (ADR 0014).",
  findLiveChallenge:
    "Resolves a presented challenge token. Holding the token is the proof, and the " +
    "token is single-use and expires in five minutes.",
  startEnrolment:
    "Somebody forced into enrolment at first sign-in holds no grants. Gating this " +
    "would make exactly the people who must enrol unable to.",
  findPendingEnrolment:
    "The caller's own enrolment, read mid-flow by the same subject startEnrolment " +
    "already resolved. Returns the sealed secret, never a usable one.",
  findConfirmedEnrolment:
    "The caller's own factor, consulted while verifying a code they just presented. " +
    "Gating it would mean needing a session to establish a session.",
  confirmEnrolment:
    "Completes the enrolment above for the same subject it resolved, and refuses to " +
    "write over a confirmed factor as a property of its own INSERT predicate.",
  redeemChallenge:
    "Spends a challenge the caller presented, and the recovery-code path inside " +
    "it — holding the credential is the proof, and there is no session yet to " +
    "check a permission against.",
  enrolmentLabel:
    "Two fields for an authenticator label — the organization's name and the " +
    "enrolling member's own email — after startEnrolment has already resolved the " +
    "right to enrol them. Argued in the function itself (RL-M1-043).",

  // --- API tokens, resolved before the actor they name exists ---------------
  findApiTokenBySecret:
    "Resolves a presented secret into a token. This IS the authentication step for " +
    "an api_token actor; a permission check would need the actor it is establishing.",
  recordApiTokenUse:
    "Stamps last-used on the token that just authenticated. Gating it would mean a " +
    "token could authenticate and not be recorded as having done so.",

  // --- rate limiting, which must work for unauthenticated callers -----------
  countAuthAttempts:
    "Spends a rate-limit budget against callers who have not authenticated, which is " +
    "the entire point of it. Keyed by a digest rather than by a person.",
  readAuthRateLimits:
    "Reads the same digest-keyed buckets without spending them. Holds no tenant data " +
    "beyond a count and a window.",
  clearAuthRateLimit:
    "Clears one digest-keyed bucket. An operator affordance over a counter, not over " +
    "anybody's data — and a bucket nobody can clear is a lockout nobody can lift.",
  pruneAuthRateLimits:
    "Deletes buckets whose window has passed. Housekeeping over counters that hold no " +
    "tenant data, run by the queue rather than by a person.",

  // --- one-line delegations to a gated function -----------------------------
  lastAuditVerification:
    "Calls listAuditVerifications, which resolves audit_log.read. The permission is " +
    "resolved one frame down; adding a second check here is the duplication §9 rejects.",

  // --- scope resolution, which every check is built on ----------------------
  organizationScopeNode:
    "Resolves the node a permission check is asked ABOUT. Gating it would need a " +
    "permission check, which would need a scope node.",
  organizationScopeRef:
    "The same root node in ScopeRef form. Gating the thing a permission check is asked " +
    "ABOUT would need a permission check, which would need a scope node.",

  // --- the decision path itself ---------------------------------------------
  resolveGrantDecision:
    "Part of can() itself — it IS the permission resolution. Gating it would require " +
    "resolving a permission in order to resolve a permission.",
  hasAllowingGrant:
    "Explains a denial can() has already made, so that an operator can tell 'ask for " +
    "access' from 'somebody took it away'. It never decides anything.",
  findActorStatus:
    "Answers 'may this actor act at all', which every permission check runs before it " +
    "resolves anything. Part of can(), like the two above.",
  scopeNodeExists:
    "Answers whether a scope node is visible in this tenant, which can() asks before " +
    "resolving grants against it. Part of can(), like the three above.",
};

type Exported = { readonly file: string; readonly name: string; readonly body: string };

/** Every exported function in src/repo, with its body. */
function exportedRepositoryFunctions(): Exported[] {
  const found: Exported[] = [];
  for (const file of globSync("src/repo/*.ts", { cwd: ROOT })) {
    const path = relative(ROOT, join(ROOT, file)).replaceAll("\\", "/");
    if (path.endsWith("index.ts")) continue;
    const source = readFileSync(join(ROOT, file), "utf8");

    const pattern = /export async function (\w+)\s*\(/g;
    for (const match of source.matchAll(pattern)) {
      const name = match[1] ?? "";
      const start = match.index ?? 0;
      // To the next export, or the end. Crude and sufficient: the question is
      // only whether a permission is resolved somewhere inside.
      const next = source.indexOf("\nexport ", start + 1);
      found.push({ file: path, name, body: source.slice(start, next === -1 ? source.length : next) });
    }
  }
  return found;
}

test("the scan finds the repository layer at all", () => {
  // A walk that found nothing would make every assertion below vacuous, and it
  // would look like a clean bill of health.
  const found = exportedRepositoryFunctions();
  assert.ok(found.length > 25, `only ${String(found.length)} exported repository functions found`);
  assert.ok(found.some((f) => f.name === "listAudit"), "listAudit is missing — the walk is broken");
});

test("every exported repository function checks a permission or is exempted", () => {
  const ungated: string[] = [];
  for (const fn of exportedRepositoryFunctions()) {
    if (Object.hasOwn(EXEMPT, fn.name)) continue;
    if (/requirePermission\s*\(/.test(fn.body)) continue;
    ungated.push(`${fn.file}: ${fn.name}`);
  }

  assert.deepEqual(
    ungated,
    [],
    "these read or write tenant data without resolving a permission. Add the check, or add " +
      "the function to EXEMPT with an argument that would survive review — 'it is only called " +
      "from somewhere safe' is not one, because the export is what makes it reachable.",
  );
});

test("every exemption still exists, and carries a real argument", () => {
  // The other direction of drift. An exemption for a function nobody has any
  // more is a hole waiting for somebody to reuse the name.
  const names = new Set(exportedRepositoryFunctions().map((fn) => fn.name));
  const stale = Object.keys(EXEMPT).filter((name) => !names.has(name));
  assert.deepEqual(stale, [], "exemptions for functions that no longer exist");

  for (const [name, reason] of Object.entries(EXEMPT)) {
    assert.ok(reason.length > 40, `${name}'s exemption is too short to be an argument`);
  }
});

test("the audit log is not one of the exemptions", () => {
  // Named specifically because it is the one that was wrong, and because it is
  // the read whose absence of a check is hardest to notice: nothing fails, the
  // caller simply sees everything.
  assert.ok(!Object.hasOwn(EXEMPT, "listAudit"));
  assert.ok(!Object.hasOwn(EXEMPT, "listMembers"));
  assert.ok(!Object.hasOwn(EXEMPT, "listProjects"));
  assert.ok(!Object.hasOwn(EXEMPT, "verifyAuditChain"));
  assert.ok(!Object.hasOwn(EXEMPT, "listAuditVerifications"));
  assert.ok(!Object.hasOwn(EXEMPT, "runAuditVerification"));
});
