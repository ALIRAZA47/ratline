/**
 * The dependency audit decides correctly, and says enough to act on (RL-M1-060).
 *
 * ## What is tested here and what is not
 *
 * `scripts/audit-deps` shells out to `npm audit`, so the end-to-end behaviour needs
 * a registry and a lockfile with a real advisory in it. That was verified by hand
 * and recorded on the task: with hono pinned at ^4.12.33 the check exited 1 and
 * named GHSA-8j4g-w8fx-2239, its affected range and its fix; after the bump to
 * ^4.13.0 it exited 0.
 *
 * What is tested HERE is everything that decides. The classification and the
 * wording are pure functions over two parsed reports, in `scripts/dependency_audit
 * .ts`, precisely so they are reachable without a network call — a check testable
 * only through the registry is a check that goes untested, and this one's job is to
 * be trusted when it is red.
 *
 * The reports below are real `npm audit --json` output, trimmed: the hono advisory
 * as this repository actually saw it, and a transitive development advisory of the
 * shape npm produces for one.
 *
 * ## Why acceptance 2 has no live demonstration
 *
 * A development-only advisory cannot be conjured on demand — it requires a
 * devDependency that happens to be vulnerable today, which is not a state to
 * arrange deliberately or to depend on. So the production/development split is
 * driven here, with the production-only report standing in for what
 * `npm audit --omit=dev` returns. That is the same input the real script passes,
 * and the substitution is the only thing separating this from the live path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  blocking,
  classify,
  describeFix,
  render,
  SEVERITIES,
  type AuditReport,
  type Vulnerability,
} from "../../scripts/dependency_audit.ts";

/** The hono advisory exactly as `npm audit --json` reported it here. */
const HONO: AuditReport = {
  vulnerabilities: {
    hono: {
      name: "hono",
      severity: "moderate",
      isDirect: true,
      via: [
        {
          title: "Hono: ReDoS in CORS middleware via Access-Control-Request-Headers",
          url: "https://github.com/advisories/GHSA-8j4g-w8fx-2239",
          severity: "moderate",
          range: "<4.12.34",
        },
      ],
      range: "<4.12.34",
      fixAvailable: true,
    },
  },
};

/** A development-only advisory, transitive, with a named fix. */
const DEV_ONLY: AuditReport = {
  vulnerabilities: {
    "some-bundler": {
      name: "some-bundler",
      severity: "high",
      isDirect: true,
      via: ["tar-fs"],
      range: ">=6.0.0 <6.4.1",
      fixAvailable: { name: "some-bundler", version: "6.4.1", isSemVerMajor: false },
    },
    "tar-fs": {
      name: "tar-fs",
      severity: "high",
      isDirect: false,
      via: [
        {
          title: "tar-fs can extract outside the specified directory",
          url: "https://github.com/advisories/GHSA-pq67-2wwv-3xjx",
          severity: "high",
          range: "<2.1.2",
        },
      ],
      range: "<2.1.2",
      fixAvailable: { name: "some-bundler", version: "6.4.1", isSemVerMajor: true },
    },
  },
};

function merge(...reports: readonly AuditReport[]): AuditReport {
  const vulnerabilities: Record<string, Vulnerability> = {};
  for (const report of reports) {
    for (const [name, vulnerability] of Object.entries(report.vulnerabilities ?? {})) {
      vulnerabilities[name] = vulnerability;
    }
  }
  return { vulnerabilities };
}

// ---------------------------------------------------------------------------
// Acceptance 1 — a production advisory stops the build
// ---------------------------------------------------------------------------

test("acceptance 1: a production advisory is blocking", () => {
  const findings = classify(HONO, HONO);

  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.package, "hono");
  assert.equal(findings[0]?.scope, "production");
  assert.deepEqual(
    blocking(findings).map((f) => f.package),
    ["hono"],
    "an advisory in code that serves requests must fail the build",
  );
});

test("acceptance 1: severity does not decide — a low production advisory still blocks", () => {
  // Deliberate. `--audit-level` exists and is not used: a low-severity advisory in
  // a request-serving dependency is still a published hole in the control plane,
  // and the decision about whether to accept it belongs to a person writing a
  // reason down, not to a threshold in a script.
  const low = merge({
    vulnerabilities: {
      "some-lib": { name: "some-lib", severity: "low", via: [{ title: "t", url: "u", range: "<1" }] },
    },
  });
  assert.equal(blocking(classify(low, low)).length, 1);
});

// ---------------------------------------------------------------------------
// Acceptance 2 — a development advisory is reported and does not block
// ---------------------------------------------------------------------------

test("acceptance 2: a development-only advisory does not fail the build", () => {
  // Present in the full report, absent from the production-only one: that is what
  // "reachable only through devDependencies" looks like in npm's own answer.
  const findings = classify(DEV_ONLY, { vulnerabilities: {} });

  assert.equal(findings.length, 2);
  for (const finding of findings) {
    assert.equal(finding.scope, "development", `${finding.package} is dev-only in this report`);
  }
  assert.deepEqual(blocking(findings), [], "build tooling must not stop the pipeline");
});

test("acceptance 2: a development advisory is still REPORTED, in full", () => {
  // The other half, and the one that makes the exemption defensible rather than a
  // hole: not failing is not the same as not saying.
  const text = render(classify(DEV_ONLY, { vulnerabilities: {} }));

  assert.match(text, /development dependencies — 2 advisory package\(s\)/);
  assert.match(text, /do NOT fail the build/);
  assert.match(text, /tar-fs can extract outside the specified directory/);
  assert.match(text, /GHSA-pq67-2wwv-3xjx/);
  assert.match(text, /dependency audit: 0 production, 2 development/);
});

test("acceptance 2: the two scopes are judged separately in one run", () => {
  const findings = classify(merge(HONO, DEV_ONLY), HONO);

  assert.deepEqual(
    findings.filter((f) => f.scope === "production").map((f) => f.package),
    ["hono"],
  );
  assert.deepEqual(
    findings.filter((f) => f.scope === "development").map((f) => f.package).sort(),
    ["some-bundler", "tar-fs"],
  );
  assert.deepEqual(blocking(findings).map((f) => f.package), ["hono"]);

  const text = render(findings);
  assert.match(text, /production dependencies —/);
  assert.match(text, /development dependencies —/);
  assert.match(text, /dependency audit: 1 production, 2 development/);
});

test("a package that is BOTH is production, because that is the worse answer", () => {
  // The case the npm-resolution split exists for: a direct devDependency that is
  // also a transitive production one. If it appears in the production-only report
  // at all, it serves requests.
  const findings = classify(merge(HONO, DEV_ONLY), merge(HONO, { vulnerabilities: { "tar-fs": DEV_ONLY.vulnerabilities?.["tar-fs"] ?? {} } }));
  const tar = findings.find((f) => f.package === "tar-fs");
  assert.equal(tar?.scope, "production");
  assert.deepEqual(blocking(findings).map((f) => f.package).sort(), ["hono", "tar-fs"]);
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the advisory and the fix are named
// ---------------------------------------------------------------------------

test("acceptance 3: the report names the advisory, not just a count", () => {
  const text = render(classify(HONO, HONO));

  assert.match(text, /hono {2}\[moderate\]/, "the package and its severity");
  assert.match(text, /ReDoS in CORS middleware/, "the advisory's title");
  assert.match(text, /GHSA-8j4g-w8fx-2239/, "the advisory's identifier, so it can be looked up");
  assert.match(text, /affects <4\.12\.34/, "the range, so a reader can tell whether they are in it");
});

test("acceptance 3: the report names the fix", () => {
  assert.match(
    render(classify(HONO, HONO)),
    /fix: a fixed version exists — raise the range in package\.json/,
    "npm answers a bare true for a direct dependency; say what to do rather than echoing it",
  );
  assert.match(
    render(classify(DEV_ONLY, { vulnerabilities: {} })),
    /fix: upgrade some-bundler to 6\.4\.1/,
    "when npm names a version, name it",
  );
  assert.match(
    render(classify(DEV_ONLY, { vulnerabilities: {} })),
    /a MAJOR upgrade — read its changelog/,
    "a major bump is not a fix somebody should apply without looking",
  );
});

test("no fix available is still an instruction", () => {
  // The case where a count would be actively misleading: there is nothing to run,
  // and a reader needs to know that rather than to go looking for a command.
  assert.match(
    describeFix({ name: "stuck", fixAvailable: false }),
    /no fix is published yet — pin around it, drop the dependency, or accept it deliberately/,
  );
  assert.equal(describeFix({ name: "stuck" }), describeFix({ name: "stuck", fixAvailable: false }));
});

test("a vulnerability with no advisory says so instead of printing an empty line", () => {
  const odd: AuditReport = { vulnerabilities: { mystery: { name: "mystery", severity: "high" } } };
  const text = render(classify(odd, odd));
  assert.match(text, /listed no advisory/);
  assert.match(text, /run `npm audit` directly/);
});

test("a transitive finding names what it comes through", () => {
  // Without this the report tells somebody that a package they never installed is
  // vulnerable, and not which of their own dependencies to change.
  const text = render(classify(DEV_ONLY, { vulnerabilities: {} }));
  assert.match(text, /reached through tar-fs/);
});

// ---------------------------------------------------------------------------
// Shape
// ---------------------------------------------------------------------------

test("a clean audit says so plainly", () => {
  assert.equal(
    render(classify({ vulnerabilities: {} }, { vulnerabilities: {} })),
    "dependency audit: no known advisories in production or development.",
  );
  assert.deepEqual(classify({}, {}), [], "an absent vulnerabilities key is not a crash");
});

test("findings are ordered worst first, then alphabetically", () => {
  // Stable output between runs, and the thing to read at the top. A report whose
  // order changes with object-key iteration is a report nobody diffs.
  const report: AuditReport = {
    vulnerabilities: {
      zeta: { name: "zeta", severity: "low" },
      alpha: { name: "alpha", severity: "critical" },
      beta: { name: "beta", severity: "low" },
      gamma: { name: "gamma", severity: "high" },
    },
  };
  assert.deepEqual(
    classify(report, report).map((f) => f.package),
    ["alpha", "gamma", "beta", "zeta"],
  );
});

test("an unknown severity sorts ABOVE critical, not below it", () => {
  // This test was written expecting the opposite and was right to fail. An
  // unrecognised severity means the script does not know how bad the finding is,
  // and the bottom of a list is the one place an unknown quantity must not go.
  // Sorting it first costs a reader a glance; sorting it last costs them the
  // finding. Pinned here so a future tidy-up of `rank` cannot quietly invert it.
  const report: AuditReport = {
    vulnerabilities: {
      weird: { name: "weird", severity: "apocalyptic" },
      known: { name: "known", severity: "critical" },
    },
  };
  assert.deepEqual(classify(report, report).map((f) => f.package), ["weird", "known"]);
  assert.equal(classify(report, report)[0]?.severity, "apocalyptic");
  assert.equal(SEVERITIES.includes("critical"), true);
});

test("a missing severity is reported as unknown rather than dropped", () => {
  const report: AuditReport = { vulnerabilities: { nameless: { name: "nameless" } } };
  const findings = classify(report, report);
  assert.equal(findings[0]?.severity, "unknown");
  assert.equal(findings[0]?.scope, "production");
  assert.equal(blocking(findings).length, 1, "not knowing the severity is not a reason to pass it");
});
