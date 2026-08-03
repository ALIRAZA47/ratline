/**
 * Claiming an installation (RL-M1-030).
 *
 * In `test/security/` because the failure mode is total: an open bootstrap
 * endpoint lets anyone who can reach the port create an organization and make
 * themselves its owner. Every other control in the product is downstream of
 * this one — there is no permission model to defeat if you can mint your own
 * tenant with yourself as Owner.
 *
 * ## Why a token rather than "the database is empty"
 *
 * Because row-level security makes "is the database empty" unanswerable from
 * inside the application, and reaching around it means a `SECURITY DEFINER`
 * function or a privileged connection counting rows the application is not
 * meant to see. C3 takes the easy answer away, correctly.
 *
 * A single-use token on the server's filesystem makes the authority HOST ACCESS
 * rather than network access, which is the right authority: whoever can read
 * the secrets directory already owns the installation. It also gets right the
 * case the empty-database gate gets wrong in the dangerous direction — a
 * database that is not empty but was never claimed.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createServer, validateInstallation, BOOTSTRAP_HEADER, type ServerDeps } from "../../src/api/server.ts";
import {
  bootstrapState,
  bootstrapTokenMatches,
  mintBootstrapToken,
  spendBootstrapToken,
  spentPath,
  tokenPath,
} from "../../src/api/bootstrap_token.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { signIn } from "../../src/auth/sessions.ts";
import { contextForRequest } from "../../src/authz/context.ts";
import { can } from "../../src/authz/can.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";

const skip = skipWithoutDatabase;

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "rl-bootstrap-"));
}

const OWNER_PASSWORD = "correct-horse-battery-staple-4471";

const CLAIM = {
  organizationSlug: "acme",
  organizationName: "Acme Rigging",
  ownerEmail: "ali@acme.example",
  ownerName: "Ali",
  ownerPassword: OWNER_PASSWORD,
};

function serverFor(dir: string, orgId: string | null = null): ReturnType<typeof createServer> {
  const deps: ServerDeps = {
    cookieSecret: new Uint8Array(32).fill(7),
    sealingKey: Buffer.alloc(32, 9),
    resolveTenant: () => Promise.resolve(orgId),
    signInIdentityId: "00000000-0000-4000-8000-000000000000",
    secretsDir: dir,
    trustedOrigins: ["http://127.0.0.1:7712"],
  };
  return createServer(deps);
}

async function usingScratch(database: string, fn: () => Promise<void>): Promise<void> {
  await asApplicationRole(database, () => Promise.resolve(undefined));
  const url = new URL(DATABASE_URL);
  url.pathname = `/${database}`;
  url.username = "ratline_app";
  url.password = "";
  connect({ connectionString: url.toString() });
  try {
    await fn();
  } finally {
    await disconnect();
  }
}

async function claim(
  app: ReturnType<typeof createServer>,
  token: string,
  body: unknown = CLAIM,
): Promise<{ status: number; text: string }> {
  const response = await app.request("/bootstrap", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://127.0.0.1:7712",
      [BOOTSTRAP_HEADER]: token,
    },
    body: JSON.stringify(body),
  });
  // Read the body ONCE and hand back both. A Response body can only be
  // consumed once, and using `await response.text()` as an assertion message
  // beside `response.json()` is how that bites — the message consumes it and
  // the parse fails with "Body has already been read", which reads like a
  // product bug and is not one.
  return { status: response.status, text: await response.text() };
}

// ---------------------------------------------------------------------------
// The token's own lifecycle
// ---------------------------------------------------------------------------

test("a fresh installation mints a token, and minting twice returns the same one", () => {
  // An operator who wrote the token down during a previous boot must not find
  // it silently invalidated by a restart.
  const dir = freshDir();
  const first = mintBootstrapToken(dir);
  assert.ok(first !== null && first.length >= 40);
  assert.equal(mintBootstrapToken(dir), first);
  assert.equal(bootstrapState(dir), "unclaimed");
});

test("the token file is not readable by anybody else", () => {
  const dir = freshDir();
  mintBootstrapToken(dir);
  const mode = readFileSync(tokenPath(dir), "utf8").length > 0;
  assert.ok(mode);
  // Loosening it is refused rather than tolerated: this file is the authority
  // to claim the installation, so group- or world-readable hands that authority
  // to every local account.
  chmodSync(tokenPath(dir), 0o644);
  assert.throws(() => bootstrapTokenMatches("anything", dir), /hands that authority/);
});

test("spending it closes the endpoint permanently, across restarts", () => {
  // The property the whole design turns on. Deleting the token alone would let
  // the next boot mint a fresh one and reopen the endpoint — the vulnerability
  // with extra steps.
  const dir = freshDir();
  const token = mintBootstrapToken(dir) ?? "";
  spendBootstrapToken(dir);

  assert.equal(bootstrapState(dir), "claimed");
  assert.equal(existsSync(tokenPath(dir)), false);
  assert.ok(existsSync(spentPath(dir)));
  assert.equal(bootstrapTokenMatches(token, dir), false, "the spent token still works");
  assert.equal(mintBootstrapToken(dir), null, "a restart minted a second token");
  assert.equal(bootstrapTokenMatches(mintBootstrapToken(dir) ?? "", dir), false);
});

test("a stale token file left beside the spent marker is refused", () => {
  // The crash window: the marker is written BEFORE the token is removed, so a
  // process that dies between them leaves both files. The marker has to win.
  const dir = freshDir();
  const token = mintBootstrapToken(dir) ?? "";
  writeFileSync(spentPath(dir), "claimed\n", { mode: 0o600 });
  assert.ok(existsSync(tokenPath(dir)), "the fixture needs both files present");
  assert.equal(bootstrapTokenMatches(token, dir), false);
});

test("an empty or wrong token never matches", () => {
  const dir = freshDir();
  const token = mintBootstrapToken(dir) ?? "";
  assert.equal(bootstrapTokenMatches("", dir), false);
  assert.equal(bootstrapTokenMatches(`${token}x`, dir), false);
  assert.equal(bootstrapTokenMatches(token.slice(0, -1), dir), false);
  assert.equal(bootstrapTokenMatches(token, dir), true);
});

test("a never-minted installation refuses everything", () => {
  const dir = freshDir();
  assert.equal(bootstrapTokenMatches("", dir), false);
  assert.equal(bootstrapTokenMatches("guess", dir), false);
});

// ---------------------------------------------------------------------------
// Acceptance 1 — empty database to an organization with one owner
// ---------------------------------------------------------------------------

test("a claim creates an organization whose owner can sign in and act", { skip }, async () => {
  await withMigratedDatabase(async (client, database) => {
    const dir = freshDir();
    const token = mintBootstrapToken(dir) ?? "";

    let orgId = "";
    await usingScratch(database, async () => {
      const response = await claim(serverFor(dir), token);
      assert.equal(response.status, 201, response.text);
      orgId = (JSON.parse(response.text) as { organizationId: string }).organizationId;
    });

    // Read back outside the request, as an operator would see it.
    const rows = await client.query<{ slug: string; owners: string }>(
      `select o.slug,
              (select count(*)::text from grants g
                where g.org_id = o.id and g.role_key = 'owner' and g.effect = 'allow') as owners
       from organizations o where o.id = $1`,
      [orgId],
    );
    assert.equal(rows.rows[0]?.slug, "acme");
    assert.equal(rows.rows[0]?.owners, "1");

    await usingScratch(database, async () => {
      const anonymous = contextForRequest({
        orgId,
        userId: "00000000-0000-4000-8000-000000000001",
        requestId: "r-signin",
      });
      const result = await signIn(anonymous, { email: CLAIM.ownerEmail, password: OWNER_PASSWORD });
      assert.ok(result.ok, "the owner created by the claim cannot sign in");

      // And they are really an Owner, not merely a member.
      const node = await client.query<{ id: string }>(
        "select id from scope_nodes where org_id = $1 and kind = 'organization'",
        [orgId],
      );
      const ctx = contextForRequest({
        orgId,
        userId: result.session.userId,
        requestId: "r-check",
        sessionId: result.session.id,
      });
      const decision = await can(ctx, "organization.delete", {
        scopeNodeId: node.rows[0]?.id ?? "",
        resourceId: null,
      });
      assert.equal(decision.allowed, true, "the first owner does not hold an Owner's permissions");
    });
  });
});

test("the claim is audited against the owner, never the system", { skip }, async () => {
  // C6 forbids an action by "the system", and this is the one action with the
  // strongest excuse for it — there is no actor until it succeeds. The answer is
  // that the owner is the actor of their own creation, which is truthful.
  await withMigratedDatabase(async (client, database) => {
    const dir = freshDir();
    const token = mintBootstrapToken(dir) ?? "";
    await usingScratch(database, async () => {
      assert.equal((await claim(serverFor(dir), token)).status, 201);
    });

    const entries = await client.query<{ actor_type: string; actor_id: string; reason: string }>(
      "select actor_type, actor_id, reason from audit_entries where reason = 'installation-claimed'",
    );
    assert.equal(entries.rows.length, 1);
    assert.equal(entries.rows[0]?.actor_type, "user");
    const owner = await client.query<{ id: string }>("select id from users where email = $1", [
      CLAIM.ownerEmail,
    ]);
    assert.equal(entries.rows[0]?.actor_id, owner.rows[0]?.id);
  });
});

// ---------------------------------------------------------------------------
// Acceptance 2 — no state where an organization has no owner
// ---------------------------------------------------------------------------

test("a claim that fails part-way leaves nothing behind", { skip }, async () => {
  // The window a sequence of four inserts would have had three of. A crash
  // between them leaves an organization nobody can sign in to and a second
  // attempt cannot fix — the installation would be permanently unclaimable.
  //
  // Forced by taking the email an existing row already holds, so the users
  // INSERT fails after the organizations INSERT has already run.
  await withMigratedDatabase(async (client, database) => {
    await client.query("insert into users (email, name) values ($1, 'Squatter')", [CLAIM.ownerEmail]);

    const dir = freshDir();
    const token = mintBootstrapToken(dir) ?? "";
    await usingScratch(database, async () => {
      // The handler throws, the framework renders a 500. What matters is not the
      // status — it is what the database and the token look like afterwards.
      const response = await claim(serverFor(dir), token);
      assert.equal(response.status, 500, "the duplicate email should have failed the claim");
    });

    const orgs = await client.query<{ n: string }>("select count(*)::text as n from organizations");
    assert.equal(orgs.rows[0]?.n, "0", "the organization survived a failed claim");
    assert.equal(
      bootstrapState(dir),
      "unclaimed",
      "the token was spent on a claim that failed — the installation is now unclaimable",
    );
  });
});

// ---------------------------------------------------------------------------
// The endpoint closes, and every refusal looks the same
// ---------------------------------------------------------------------------

test("a second claim is refused, and looks exactly like a wrong token", { skip }, async () => {
  // "Already claimed" is precisely the answer an attacker wants: it says the
  // installation is live and worth attacking. So it is byte-identical to a
  // wrong guess.
  await withMigratedDatabase(async (client, database) => {
    const dir = freshDir();
    const token = mintBootstrapToken(dir) ?? "";
    await usingScratch(database, async () => {
      const app = serverFor(dir);
      assert.equal((await claim(app, token)).status, 201);

      const second = await claim(app, token, { ...CLAIM, organizationSlug: "globex" });
      const guess = await claim(serverFor(dir), "not-the-token", { ...CLAIM, organizationSlug: "globex" });

      assert.equal(second.status, 401);
      assert.equal(guess.status, 401);
      assert.equal(second.text, guess.text, "the two refusals differ");
    });

    const orgs = await client.query<{ n: string }>("select count(*)::text as n from organizations");
    assert.equal(orgs.rows[0]?.n, "1", "a second organization was created");
    void client;
  });
});

test("the unclaimed flag flips, so the first-run screen knows which form to show", { skip }, async () => {
  await withMigratedDatabase(async (_client, database) => {
    const dir = freshDir();
    const token = mintBootstrapToken(dir) ?? "";
    await usingScratch(database, async () => {
      const app = serverFor(dir);
      const before = await app.request("/bootstrap");
      assert.deepEqual(await before.json(), { unclaimed: true });

      assert.equal((await claim(app, token)).status, 201);

      const after = await app.request("/bootstrap");
      assert.deepEqual(await after.json(), { unclaimed: false });
    });
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the copy
// ---------------------------------------------------------------------------

test("a malformed claim says what broke and what to do next", () => {
  // §291: "active voice, plain nouns from the operator's world, buttons named
  // for what happens. Errors state what broke and what to do next." This is the
  // one place a bootstrap response explains itself, and it is safe to: these are
  // the operator's own typos on a form only they can reach.
  const problems = validateInstallation({});
  assert.ok(problems.length >= 5, "every empty field should be named");
  for (const problem of problems) {
    assert.match(problem, /^[A-Z]/, `not a sentence: ${problem}`);
    assert.match(problem, /[.]$/, `not a sentence: ${problem}`);
    // No apology, no blame, no machine vocabulary.
    for (const banned of ["sorry", "oops", "invalid", "error", "failed", "must not", "illegal"]) {
      assert.ok(
        !problem.toLowerCase().includes(banned),
        `"${banned}" is not the operator's word: ${problem}`,
      );
    }
  }
});

test("the messages tell the operator the shape they need, not the regex", () => {
  const [slugProblem] = validateInstallation({ ...CLAIM, organizationSlug: "Acme Rigging!" });
  assert.ok(slugProblem);
  assert.match(slugProblem, /lower-case letters, digits and hyphens/);
  assert.ok(!slugProblem.includes("^"), "a regex is not an explanation");

  const password = validateInstallation({ ...CLAIM, ownerPassword: "short" });
  assert.match(password.join(" "), /at least 12 characters/);
  assert.match(password.join(" "), /passphrase/, "say what to do, not only what is wrong");
});

test("a good claim has nothing to say about it", () => {
  assert.deepEqual(validateInstallation(CLAIM), []);
});
