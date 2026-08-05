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

import { codeOf } from "../support/source_scan.ts";

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

/**
 * `async` is OPTIONAL, and that option is the whole of RL-M1-052.
 *
 * This was `export async function (\w+)\s*\(`, so
 * `export function listSites(ctx: AuthzContext, …)` — non-async because it only
 * returns the promise `scoped()` already hands it — was invisible here while
 * `scoped_repository.test.ts` saw it perfectly well. All 45 exports happened to
 * be async, so nothing was broken; the next repository read written the shorter
 * way would have needed no permission, needed no {@link EXEMPT} entry, and left
 * every guard in this file green. That is RL-M1-043's nine ungated reads,
 * reintroduced through the door its own fix left open.
 */
const EXPORTED_FUNCTION = /export\s+(?:async\s+)?function\s+(\w+)\s*\(/g;

/** Any exported `const` — callable or not. See the completeness test below. */
const EXPORTED_CONST = /export\s+const\s+(\w+)\b/g;

/** A body that resolves a permission. */
const RESOLVES_PERMISSION = /requirePermission\s*\(/;

/**
 * Every exported function in a repository directory, with its body.
 *
 * `dir` is a parameter so the scan can be pointed at a fixture and watched to
 * FIRE (acceptance 3). A scanner nobody has seen fire is a scanner nobody has
 * tested, and this one spent a session matching a shape the codebase did not
 * use — which looked exactly like a clean bill of health.
 *
 * Comments are stripped first, through the shared helper (RL-M1-041). The gate
 * is `requirePermission(` appearing somewhere in a body, so a body that merely
 * DISCUSSES requiring a permission would otherwise satisfy it — and the bodies
 * here are heavily commented precisely because the subject is what they may and
 * may not skip.
 */
function exportedRepositoryFunctions(dir = "src/repo"): Exported[] {
  const found: Exported[] = [];
  // `**` rather than `*`: this globbed only the top level while
  // scoped_repository.test.ts globbed the whole tree, so a repository placed in
  // a subdirectory would have been required to take a context by one scan and
  // never asked for a permission by this one.
  for (const file of globSync(`${dir}/**/*.ts`, { cwd: ROOT })) {
    const path = relative(ROOT, join(ROOT, file)).replaceAll("\\", "/");
    if (path.endsWith("index.ts")) continue;
    const code = codeOf(readFileSync(join(ROOT, file), "utf8"));

    for (const match of code.matchAll(EXPORTED_FUNCTION)) {
      const name = match[1] ?? "";
      const start = match.index ?? 0;
      // To the next export, or the end. Crude and sufficient: the question is
      // only whether a permission is resolved somewhere inside.
      const next = code.indexOf("\nexport ", start + 1);
      found.push({ file: path, name, body: code.slice(start, next === -1 ? code.length : next) });
    }
  }
  return found;
}

/** The exported functions in `dir` that neither resolve a permission nor are exempt. */
function ungatedIn(dir: string): string[] {
  return exportedRepositoryFunctions(dir)
    .filter((fn) => !Object.hasOwn(EXEMPT, fn.name) && !RESOLVES_PERMISSION.test(fn.body))
    .map((fn) => `${fn.file}: ${fn.name}`);
}

test("the scan finds the repository layer at all", () => {
  // A walk that found nothing would make every assertion below vacuous, and it
  // would look like a clean bill of health.
  const found = exportedRepositoryFunctions();
  assert.ok(found.length > 25, `only ${String(found.length)} exported repository functions found`);
  assert.ok(found.some((f) => f.name === "listAudit"), "listAudit is missing — the walk is broken");
});

test("every exported repository function checks a permission or is exempted", () => {
  assert.deepEqual(
    ungatedIn("src/repo"),
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

// ---------------------------------------------------------------------------
// The scan can see the shapes it claims to (RL-M1-052)
// ---------------------------------------------------------------------------

/**
 * Deliberately ungated exports, outside `src/` so the real scan never reads them
 * and {@link EXEMPT} never has to mention them.
 */
const FIXTURE = "test/fixtures/repo_gating";

/** Just the function names the scan reported for a directory. */
function ungatedNamesIn(dir: string): string[] {
  return ungatedIn(dir).map((label) => label.slice(label.indexOf(": ") + 2));
}

test("the scan reports a repository export that is not async", () => {
  // THE acceptance. Pointed at the fixture rather than at src/repo, because
  // src/repo is (correctly) clean and a clean scan proves nothing about what the
  // scan can see. With the old `export async function` pattern the fixture's
  // non-async export was invisible and this file scanned CLEAN — which is
  // indistinguishable from a green gate.
  const reported = ungatedNamesIn(FIXTURE);
  assert.ok(
    reported.includes("listSitesNotAsync"),
    `a non-async ungated export was not reported. Reported: ${JSON.stringify(reported)}`,
  );
  assert.ok(reported.includes("listSitesAsync"), "the async shape must still be reported");
});

test("the scan reaches a repository module in a subdirectory", () => {
  // The other half of the same blind spot: this scan globbed one level while
  // scoped_repository.test.ts globbed the tree, so a nested repository would have
  // been required to take a context and never asked for a permission.
  assert.ok(
    ungatedNamesIn(FIXTURE).includes("listSitesInASubdirectory"),
    "an ungated export one directory down was not reported",
  );
});

test("a permission named only in a comment does not satisfy the gate", () => {
  // Acceptance 2, behaviourally rather than structurally. The gate is a string
  // match for `requirePermission(` somewhere in a body, so without codeOf a
  // function that merely explains which permission it OUGHT to resolve counts as
  // having resolved one — and these bodies are heavily commented exactly because
  // the subject is what they may skip.
  assert.ok(
    ungatedNamesIn(FIXTURE).includes("listSitesGatedOnlyInAComment"),
    "a body whose only requirePermission( is inside a comment was treated as gated",
  );
});

test("a genuinely gated export in the fixture is not reported", () => {
  // The other direction, so the two tests above cannot be passing because the
  // scan reports everything it sees.
  assert.ok(
    !ungatedNamesIn(FIXTURE).includes("listSitesGated"),
    "a function that does resolve a permission must not be reported",
  );
});

test("every exported callable in the repository layer is a function declaration", () => {
  // What makes the scan COMPLETE rather than merely wider. It reads `function`
  // declarations, and `export const listSites = (ctx) => …` is just as exported
  // and just as ungatable. Chasing every callable-const form with a regex is a
  // second parser to get wrong, so the SHAPE is constrained instead: keep
  // repository exports as function declarations and the scan sees all of them by
  // construction. Failing here is loud; being missed by the scan is silent.
  const offenders: string[] = [];
  for (const file of globSync("src/repo/**/*.ts", { cwd: ROOT })) {
    const path = relative(ROOT, join(ROOT, file)).replaceAll("\\", "/");
    if (path.endsWith("index.ts")) continue;
    const code = codeOf(readFileSync(join(ROOT, file), "utf8"));

    for (const match of code.matchAll(EXPORTED_CONST)) {
      const start = match.index ?? 0;
      // To the end of the statement. A data constant's declaration has no `;`
      // inside it, and an arrow reaches its `=>` before the first one — so this
      // stops well short of any later non-exported helper, which slicing to the
      // next `export` would have swallowed and reported as a false positive.
      const ends = [code.indexOf(";", start), code.indexOf("\nexport ", start + 1)]
        .filter((at) => at !== -1)
        .sort((a, b) => a - b);
      const declaration = code.slice(start, ends[0] ?? code.length);
      if (/=>|\bfunction\b/.test(declaration)) offenders.push(`${path}: ${match[1] ?? ""}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "these export a callable as a const, which the permission scan does not read. Write it as " +
      "`export function name(ctx: AuthzContext, …)` so the gate applies, or teach the scan the " +
      "new form — but do not leave it exported and unread.",
  );
});
