/**
 * Unauthorized and nonexistent are the same response (RL-M1-026).
 *
 * Brief §6.3: "Nonexistent and unauthorized must be indistinguishable in the
 * response." §6.4 asks the same of cross-tenant probing.
 *
 * ## What is being asserted, and at which layer
 *
 * There is no HTTP server yet, so "the response" means the value `refuse()`
 * hands the adapter. That is the honest limit of this suite and it is stated
 * rather than implied — the same disclosure `test/authz/matrix.test.ts` makes.
 * It is also not much of a limit here: the response is a frozen constant, so
 * anything downstream that changed it per-request would have to construct its
 * own, and the last test in this file is the one that notices.
 *
 * ## Why the tests are shaped like this
 *
 * Asserting that two particular responses match is the weak version — it passes
 * on the day it is written and says nothing about the response added next year.
 * So the assertions here are about the SHAPE:
 *
 *   - every combination of resource type, cause and decision reason produces
 *     ONE distinct byte string, so there is no input that can move it;
 *   - the bytes contain nothing about the request, checked by looking for the
 *     inputs in the output rather than by reading it;
 *   - the audit record does carry the truth, because a refusal that told
 *     nobody anything would satisfy §6.3 and leave the system unoperatable;
 *   - nothing else in src/ constructs a refusal, which is the only assertion
 *     that survives someone adding a handler.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  REFUSAL_CAUSES,
  auditRecordFor,
  refuse,
  refusalWireWithoutAuditForTests,
  serialiseRefusal,
  unauthenticated,
  type RefusalCause,
} from "../../src/api/refusal.ts";

/**
 * The wire response of a pending refusal (RL-M1-050).
 *
 * `refuse()` no longer hands out `{ wire, audit }`, because taking `.wire` and
 * dropping `.audit` is exactly what let a cross-tenant probe go unrecorded. This
 * file is the one place that legitimately needs the response without an audit
 * entry: it PROVES the response is a single frozen constant whatever caused it,
 * which cannot be shown without holding the constant.
 *
 * The unpleasant name is the guarantee. `refusal_accounting.test.ts` scans `src/`
 * and fails if it appears there, so the exemption is enforced rather than
 * requested, and this alias keeps that visible on every line below.
 */
const wireOf = refusalWireWithoutAuditForTests;
import {
  ACTION_CATALOGUE,
  ALL_ACTIONS,
  RESOURCE_TYPES,
  type Action,
  type ResourceType,
} from "../../src/authz/catalogue.ts";
import { DECISION_REASONS } from "../../src/authz/can.ts";
import { contextForRequest } from "../../src/authz/context.ts";
import { connect, disconnect } from "../../src/db/internal/handle.ts";
import { listAudit, recordAudit } from "../../src/repo/audit.ts";
import {
  asApplicationRole,
  DATABASE_URL,
  seedOrganization,
  skipWithoutDatabase,
  withMigratedDatabase,
} from "../support/db.ts";
import { codeOf } from "../support/source_scan.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const skip = skipWithoutDatabase;

/**
 * A real action for each resource type.
 *
 * Was `${resourceType}.read` until RL-M1-036 typed the field, which caught it
 * immediately: `secret.read` does not exist, because §6.3 splits it into
 * `secret.read_name` and `secret.read_value`. The invented name had been
 * flowing into an audit record that would have been unsearchable.
 */
function someActionFor(resourceType: ResourceType): Action {
  const action = ALL_ACTIONS.find((candidate) => ACTION_CATALOGUE[candidate].resource === resourceType);
  if (action === undefined) throw new Error(`${resourceType} has no actions; the catalogue is malformed`);
  return action;
}

/** Every way a caller could try to make the refusal say something. */
function everyTruth(): { resourceType: ResourceType; cause: RefusalCause; reason: string; resourceId: string | null }[] {
  const truths = [];
  for (const resourceType of RESOURCE_TYPES) {
    for (const cause of REFUSAL_CAUSES) {
      for (const reason of DECISION_REASONS) {
        truths.push({
          resourceType,
          cause,
          reason,
          // Half the cases carry a real identifier and half do not, because
          // "we resolved it but you may not have it" and "there was nothing to
          // resolve" are precisely the two states being made to look alike.
          resourceId: cause === "denied" ? randomUUID() : null,
        });
      }
    }
  }
  return truths;
}

// ---------------------------------------------------------------------------
// Acceptance 1 and 3 — identical, byte for byte, across every resource type
// ---------------------------------------------------------------------------

test("every refusal is the same bytes, whatever caused it", () => {
  const distinct = new Set<string>();
  let compared = 0;

  for (const truth of everyTruth()) {
    const wire = wireOf(refuse({ action: someActionFor(truth.resourceType), ...truth }));
    distinct.add(serialiseRefusal(wire).toString("base64"));
    compared += 1;
  }

  assert.equal(
    distinct.size,
    1,
    `${String(distinct.size)} distinct responses across ${String(compared)} refusals — ` +
      `any difference is an existence oracle`,
  );
  // Guards against the test passing because nothing ran: an empty loop also
  // produces a set of size zero, and zero is not one, but a single-element
  // RESOURCE_TYPES would give a vacuous pass.
  assert.ok(compared > 100, `only ${String(compared)} combinations were tried`);
});

test("a denied request and an absent one are the same object, not merely equal", () => {
  // Reference identity is stronger than deep equality and cheaper to keep: two
  // structurally identical objects can drift apart, one shared frozen constant
  // cannot. If this ever fails, someone has started building responses.
  const denied = refuse({
    action: "site.read",
    resourceType: "site",
    resourceId: randomUUID(),
    cause: "denied",
    reason: "no-grant",
  });
  const absent = refuse({
    action: "site.read",
    resourceType: "site",
    resourceId: null,
    cause: "absent",
    reason: "unknown-scope",
  });
  assert.equal(wireOf(denied), wireOf(absent));
  assert.equal(wireOf(denied).status, 404, "403 would assert the resource exists");
});

test("the response is 404 and says nothing else", () => {
  const id = randomUUID();
  const wire = wireOf(refuse({
    action: "secret.read_value",
    resourceType: "secret",
    resourceId: id,
    cause: "denied",
    reason: "explicit-deny",
  }));
  const bytes = serialiseRefusal(wire).toString("utf8");

  // Looking for the inputs in the output, rather than reading the output and
  // judging it. The words that must not appear are the ones a helpful message
  // would use.
  for (const leak of [id, "secret", "read_value", "explicit-deny", "denied", "forbidden", "permission"]) {
    assert.ok(!bytes.includes(leak), `the refusal leaks "${leak}":\n${bytes}`);
  }
});

test("no header varies, including the ones nobody thinks of as content", () => {
  const refusalForHeaders = refuse({
    action: "host.read",
    resourceType: "host",
    resourceId: null,
    cause: "absent",
    reason: "unknown-scope",
  });
  const names = wireOf(refusalForHeaders).headers.map(([name]: readonly [string, string]) => name);

  assert.deepEqual(names, [...names].sort(), "header order is part of the bytes");
  assert.deepEqual(names, names.map((n) => n.toLowerCase()));
  // A WWW-Authenticate on the 404 branch would say "you are not signed in
  // enough for this", which is a statement about the resource.
  assert.ok(!names.includes("www-authenticate"));
  assert.ok(names.includes("cache-control"), "a cached refusal is a refusal that outlives the grant that fixes it");
});

test("401 is a different answer to a different question", () => {
  // Distinguishing "no session" from "no permission" is safe: the first is
  // decided before an identifier is read. The type enforces it — unauthenticated()
  // takes no arguments — and this pins the pair apart so a later refactor
  // cannot quietly route denials into it.
  const anonymous = unauthenticated();
  const deniedPending = refuse({
    action: "site.read",
    resourceType: "site",
    resourceId: randomUUID(),
    cause: "denied",
    reason: "no-grant",
  });
  const denied = wireOf(deniedPending);

  assert.equal(anonymous.status, 401);
  assert.notEqual(anonymous.status, denied.status);
  assert.notEqual(serialiseRefusal(anonymous).toString(), serialiseRefusal(denied).toString());
  assert.equal(unauthenticated(), unauthenticated(), "also a constant");
});

// ---------------------------------------------------------------------------
// The other half of the trade — the operator must lose nothing
// ---------------------------------------------------------------------------

test("the truth the response withholds reaches the audit log", { skip }, async () => {
  // Indistinguishability is only affordable because nothing is actually lost:
  // the caller learns nothing, the operator learns everything. A test that
  // checked only the first half would be satisfied by a system that silently
  // dropped refusals on the floor, which is the version that cannot be
  // investigated after an incident.
  await withMigratedDatabase(async (client, database) => {
    const { orgId, userId } = await seedOrganization(client);
    await asApplicationRole(database, () => Promise.resolve(undefined));

    const url = new URL(DATABASE_URL);
    url.pathname = `/${database}`;
    url.username = "ratline_app";
    url.password = "";
    connect({ connectionString: url.toString() });

    try {
      const ctx = contextForRequest({ orgId, userId, requestId: `r-${randomUUID()}` });
      const targetId = randomUUID();

      const denied = refuse({
        action: "secret.read_value",
        resourceType: "secret",
        resourceId: targetId,
        cause: "denied",
        reason: "explicit-deny",
      });
      const absent = refuse({
        action: "secret.read_value",
        resourceType: "secret",
        resourceId: null,
        cause: "absent",
        reason: "unknown-scope",
      });

      await recordAudit(ctx, auditRecordFor(denied));
      await recordAudit(ctx, auditRecordFor(absent));

      const entries = await listAudit(ctx, { limit: 10 });
      const reasons = entries.map((e) => e.reason);
      assert.ok(reasons.includes("explicit-deny"), "the operator must be able to tell these apart");
      assert.ok(reasons.includes("unknown-scope"));

      const causes = entries.map((e) => e.metadata["refusal_cause"]);
      assert.ok(causes.includes("denied"));
      assert.ok(causes.includes("absent"));
      for (const entry of entries) assert.equal(entry.decision, "deny");
    } finally {
      await disconnect();
    }
  });
});

// ---------------------------------------------------------------------------
// The assertion that survives the next handler
// ---------------------------------------------------------------------------


test("nothing else in src/ builds a refusal of its own", () => {
  // The real risk is not that this module is wrong; it is that a handler
  // written next month returns its own 404 with a friendlier message, and every
  // test above still passes because they only ever look at this module.
  //
  // So: the status codes appear in exactly one file. A handler that wants to
  // refuse has to come through refuse(), which cannot be made to vary.
  const offenders: string[] = [];
  for (const file of globSync("src/**/*.ts", { cwd: ROOT })) {
    const path = join(ROOT, file);
    if (relative(ROOT, path) === join("src", "api", "refusal.ts")) continue;

    // The browser client is exempt, with an argument (RL-M1-059). This scan exists so
    // no SERVER module can build a refusal that differs from refusal.ts's — the leak
    // being that two constructions drift. `src/web/**` runs in a browser and cannot
    // construct a response at all; it READS a status the server already chose, and it
    // must, because a client that cannot tell "sign in" from "refused" would show a
    // signed-out operator an error and a refused one a login form.
    //
    // Narrow on purpose: the exemption is the directory that cannot serve, not a list
    // of files somebody appends to. If a server module ever moves under src/web, this
    // stops protecting it — which is why the assertion below also names what it covers.
    if (file.startsWith("src/web/")) continue;
    const code = codeOf(readFileSync(path, "utf8"));
    for (const status of ["401", "403", "404"]) {
      if (new RegExp(`\\b${status}\\b`).test(code)) offenders.push(`${file} mentions ${status}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "a refusal built anywhere but src/api/refusal.ts can differ from the one built there, " +
      "which is the whole leak. Route it through refuse() instead.",
  );
});

test("the refusal cannot be constructed without the branded type", () => {
  // Documented as a compile-time property, asserted here as a runtime one:
  // the object handed out is frozen, so even a caller holding a reference
  // cannot bend it into a per-request message.
  const wire = wireOf(refuse({
    action: "site.read",
    resourceType: "site",
    resourceId: null,
    cause: "absent",
    reason: "unknown-scope",
  }));
  assert.ok(Object.isFrozen(wire));
  assert.ok(Object.isFrozen(wire.headers));
  assert.throws(() => {
    (wire as { status: number }).status = 403;
  });
});
