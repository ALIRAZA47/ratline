/**
 * Reading `npm audit` (RL-M1-060).
 *
 * ## Why this exists
 *
 * `npm audit` reported that hono <4.12.34 carries a ReDoS advisory in its CORS
 * middleware (GHSA-8j4g-w8fx-2239) while package.json pinned ^4.12.33. Nothing
 * imports that middleware, so it was not exploitable — and nothing in CI would
 * ever have said so. The pipeline lints, typechecks, tests, migrates and builds the
 * agent, and never once asks whether a dependency has a published vulnerability.
 * It was found because somebody happened to install something else.
 *
 * ## Production advisories fail the build; development advisories do not
 *
 * The split is the design rather than a convenience, because the two carry
 * genuinely different risk:
 *
 *   - A production advisory is in code that serves requests. It is the control
 *     plane's own attack surface, so it stops the pipeline.
 *   - A development advisory is in a linter, a bundler or a type package. It can
 *     matter — a compromised build tool is a supply-chain problem — but the
 *     exposure is a developer's machine and CI rather than an operator's
 *     installation, and a fix is frequently unavailable on the day it lands.
 *
 * Failing on a devDependency advisory would mean a red pipeline nobody can act on,
 * which trains people to ignore the check. A check people ignore is worse than no
 * check, because it also occupies the space a working one would go in. So
 * development advisories are printed in full on every run and the exit status
 * ignores them.
 *
 * ## The split is npm's answer, not ours
 *
 * `npm audit --omit=dev` resolves the tree without devDependencies. Anything
 * vulnerable in the full report but absent from that one is reachable only through
 * development tooling. Deriving it any other way — reading package.json's two
 * sections, walking the lockfile — would re-implement npm's resolution and
 * disagree with it eventually, most likely for a package that is both a direct
 * devDependency and a transitive production one.
 *
 * ## Every finding names the advisory and its fix
 *
 * A count is a signal that something is wrong and no help at all in fixing it —
 * the same argument `scripts/ci-metrics.ts` makes for printing failing test names
 * rather than "374/592 passed". Each finding carries the package, the severity, the
 * advisory title, its URL, the vulnerable range, and what to do about it.
 *
 * This module is separate from `scripts/audit-deps.ts` so the decision that
 * matters — which advisories stop the build — can be tested without a registry.
 * A check reachable only through a network call is a check that goes untested.
 */

/** One entry of `npm audit --json`'s `via` array, when it is an advisory. */
export type Advisory = {
  readonly title?: string;
  readonly url?: string;
  readonly severity?: string;
  readonly range?: string;
};

/** One vulnerable package as `npm audit --json` reports it (report version 2). */
export type Vulnerability = {
  readonly name?: string;
  readonly severity?: string;
  readonly isDirect?: boolean;
  /** Advisory objects, or the NAMES of other vulnerable packages it comes through. */
  readonly via?: readonly (Advisory | string)[];
  readonly range?: string;
  readonly fixAvailable?: boolean | { name?: string; version?: string; isSemVerMajor?: boolean };
};

export type AuditReport = {
  readonly vulnerabilities?: Readonly<Record<string, Vulnerability>>;
};

/** Severities in the order npm ranks them, worst last. */
export const SEVERITIES = ["info", "low", "moderate", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type Finding = {
  readonly package: string;
  readonly severity: string;
  /** "production" when the package is reachable without devDependencies. */
  readonly scope: "production" | "development";
  /** One line per advisory, each naming its title, URL and affected range. */
  readonly advisories: readonly string[];
  /** What to do, in words. Never empty — "no fix exists" is an instruction too. */
  readonly fix: string;
};

/** Human-readable, and honest when npm does not name a target version. */
export function describeFix(vulnerability: Vulnerability): string {
  const fix = vulnerability.fixAvailable;
  if (fix === undefined || fix === false) {
    return (
      "no fix is published yet — pin around it, drop the dependency, or accept it " +
      "deliberately with a written reason"
    );
  }
  if (fix === true) {
    // npm answers a bare `true` for a direct dependency: it means "a satisfying
    // version exists" without saying which. The vulnerable range is the useful
    // half, and it is printed with the advisory.
    return "a fixed version exists — raise the range in package.json past the affected one";
  }
  const name = fix.name ?? vulnerability.name ?? "the package";
  const version = fix.version ?? "a newer version";
  const major = fix.isSemVerMajor === true ? " (a MAJOR upgrade — read its changelog)" : "";
  return `upgrade ${name} to ${version}${major}`;
}

/** The advisories behind one vulnerable package, as lines a person can act on. */
export function describeAdvisories(vulnerability: Vulnerability): string[] {
  const lines: string[] = [];
  for (const via of vulnerability.via ?? []) {
    if (typeof via === "string") {
      // A transitive link: this package is vulnerable because `via` is. Kept,
      // because the chain is what says which dependency to change.
      lines.push(`reached through ${via}`);
      continue;
    }
    const title = via.title ?? "an advisory with no title";
    const url = via.url ?? "no advisory URL";
    const range = via.range ?? vulnerability.range ?? "an unstated range";
    lines.push(`${title} — ${url} — affects ${range}`);
  }
  // Never silently empty. A vulnerability with no `via` is a report shape this has
  // not seen, and saying so beats printing a package name with nothing after it.
  if (lines.length === 0) {
    lines.push(
      "npm reported this package as vulnerable but listed no advisory — " +
        "run `npm audit` directly to read the raw report",
    );
  }
  return lines;
}

/**
 * Worst severity first, then alphabetical, so output is stable between runs.
 *
 * A severity npm reports that this does not recognise ranks ABOVE critical, so it
 * appears at the very top. That direction was chosen after a test caught it going
 * the other way by accident: an unrecognised severity means the script does not
 * know how bad the finding is, and burying an unknown quantity at the bottom of a
 * list is the one place it must not go. Sorting it first costs a reader a glance;
 * sorting it last costs them the finding.
 */
function rank(severity: string): number {
  const at = SEVERITIES.indexOf(severity as Severity);
  return at === -1 ? SEVERITIES.length : at;
}

/** Turn the full report and the production-only report into findings. */
export function classify(full: AuditReport, productionOnly: AuditReport): Finding[] {
  const production = new Set(Object.keys(productionOnly.vulnerabilities ?? {}));
  const findings: Finding[] = [];

  for (const [name, vulnerability] of Object.entries(full.vulnerabilities ?? {})) {
    findings.push({
      package: name,
      severity: vulnerability.severity ?? "unknown",
      scope: production.has(name) ? "production" : "development",
      advisories: describeAdvisories(vulnerability),
      fix: describeFix(vulnerability),
    });
  }

  return findings.sort(
    (a, b) => rank(b.severity) - rank(a.severity) || a.package.localeCompare(b.package),
  );
}

/** The findings that stop the build. Exactly the production ones, at any severity. */
export function blocking(findings: readonly Finding[]): Finding[] {
  return findings.filter((f) => f.scope === "production");
}

/**
 * The whole report as text, ready to print.
 *
 * A string rather than a series of console.log calls so a test can read what an
 * operator would read. The wording is part of the check: acceptance 3 asks for the
 * advisory and the fix, and a test that only counted findings would let the
 * sentences rot.
 */
export function render(findings: readonly Finding[]): string {
  if (findings.length === 0) {
    return "dependency audit: no known advisories in production or development.";
  }

  const lines: string[] = [];
  for (const scope of ["production", "development"] as const) {
    const subset = findings.filter((f) => f.scope === scope);
    if (subset.length === 0) continue;

    const consequence =
      scope === "production"
        ? "in code that serves requests, so they fail the build"
        : "in build and test tooling only, so they are reported and do NOT fail the build";
    lines.push("", `${scope} dependencies — ${String(subset.length)} advisory package(s), ${consequence}.`);
    for (const finding of subset) {
      lines.push("", `  ${finding.package}  [${finding.severity}]`);
      for (const advisory of finding.advisories) lines.push(`      ${advisory}`);
      lines.push(`      fix: ${finding.fix}`);
    }
  }

  const stopped = blocking(findings).length;
  lines.push(
    "",
    `dependency audit: ${String(stopped)} production, ` +
      `${String(findings.length - stopped)} development.`,
  );
  return lines.join("\n");
}
