/**
 * The shell's structure (RL-M1-028).
 *
 * Everything here runs in `node --test` with no build step, which is the point
 * of putting the structure in `.ts` rather than in JSX: React's JSX is not
 * erasable, so a `.tsx` file cannot be imported by the test runner at all. The
 * rendering layer is verified in a real browser instead — see the task notes —
 * and everything that can be decided without a browser is decided here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { globSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  activeNavItem,
  breadcrumb,
  chipStyle,
  ENVIRONMENT_KINDS,
  NAVIGATION,
  NAV_MARKS,
  tensionAppearance,
  TENSION_STATES,
  visibleNavigation,
} from "../../src/web/lib/shell/navigation.ts";
import { isAction } from "../../src/authz/catalogue.ts";
import { DEFAULT_ROLES } from "../../src/authz/roles.ts";
import { findToken, tokenNames } from "../../src/web/lib/design/tokens.ts";
import { FONT_CSS_IMPORTS } from "../../src/web/lib/design/fonts.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

// ---------------------------------------------------------------------------
// The rail
// ---------------------------------------------------------------------------

test("the rail is DESIGN §4's five items, in §4's order", () => {
  // Pinned verbatim. §4 promises the rail "never moves" and muscle memory is
  // the entire argument for it; reordering is a behaviour change disguised as a
  // preference, so it should show up in review as a diff of this line.
  assert.deepEqual(
    NAVIGATION.map((item) => item.label),
    ["Hosts", "Sites", "Deploys", "Audit", "Team"],
  );
  assert.deepEqual(
    NAVIGATION.map((item) => item.id),
    [...NAV_MARKS],
    "every item needs a mark and every mark needs an item",
  );
});

test("every rail item names a catalogued permission", () => {
  // The type system already enforces this. Asserted anyway for the same reason
  // the route table asserts it: a cast, or a generated rail, could bring a name
  // here that the catalogue does not know.
  for (const item of NAVIGATION) {
    assert.ok(isAction(item.requires), `${item.label} requires ${item.requires}, which is not an action`);
  }
});

test("the rail asks only for read permissions", () => {
  // A rail item is a link to a list. If reaching one required a mutating
  // permission, an operator who may look but not touch would lose the ability
  // to look — which is the failure mode where people start sharing accounts.
  for (const item of NAVIGATION) {
    assert.match(item.requires, /\.read$/, `${item.label} gates navigation on ${item.requires}`);
  }
});

test("a Viewer can reach something, and Billing deliberately cannot", () => {
  // §6.3 gives Billing "no infrastructure visibility whatsoever". That is a
  // stronger statement than "few items", so it is asserted as emptiness — and
  // Viewer is asserted non-empty beside it, because a filter that returned
  // nothing for everybody would satisfy the Billing half on its own.
  const viewer = visibleNavigation([...DEFAULT_ROLES.viewer.actions]);
  assert.ok(viewer.length > 0, "a Viewer with read permissions sees nothing — the filter is inverted");

  const billing = visibleNavigation([...DEFAULT_ROLES.billing.actions]);
  assert.deepEqual(billing, [], "Billing must have no infrastructure visibility at all (§6.3)");
});

test("an actor holding nothing sees an empty rail rather than a full one", () => {
  // Fail closed. A filter written as "hide what is explicitly denied" rather
  // than "show what is explicitly held" passes every test above and shows
  // everything to somebody with no grants.
  assert.deepEqual(visibleNavigation([]), []);
});

test("the active item is matched on a path segment, not a prefix", () => {
  // `/sites` must claim `/sites/42` and must not claim `/sites-archive`.
  // Getting this wrong puts the lashing on the wrong item, and the rail is the
  // one thing §4 promises never moves.
  assert.equal(activeNavItem("/sites")?.id, "sites");
  assert.equal(activeNavItem("/sites/42")?.id, "sites");
  assert.equal(activeNavItem("/sites/42/deploys")?.id, "sites");
  assert.equal(activeNavItem("/sites-archive"), null, "a longer name must not borrow another item's lashing");
  assert.equal(activeNavItem("/"), null);
  assert.equal(activeNavItem("/nothing-here"), null);
});

// ---------------------------------------------------------------------------
// Breadcrumb
// ---------------------------------------------------------------------------

test("the breadcrumb walks the path and the last crumb is not a link", () => {
  assert.deepEqual(breadcrumb("/acme/marketing-www"), [
    { label: "acme", href: "/acme" },
    { label: "marketing-www", href: null },
  ]);
  assert.deepEqual(breadcrumb("/"), []);
});

test("a labelled segment renders its name and an unlabelled one renders itself", () => {
  // The failure this prevents is a uuid in the top bar. §4's example is
  // `acme / marketing-www`, which is two slugs; an id reaching the breadcrumb
  // unlabelled would be technically correct and unreadable.
  const crumbs = breadcrumb("/acme/9f2c1e/settings", { "9f2c1e": "marketing-www" });
  assert.deepEqual(
    crumbs.map((crumb) => crumb.label),
    ["acme", "marketing-www", "settings"],
  );
  assert.deepEqual(
    crumbs.map((crumb) => crumb.href),
    ["/acme", "/acme/9f2c1e", null],
    "the href keeps the real segment; only the label is renamed",
  );
});

// ---------------------------------------------------------------------------
// The environment chip — the 2026-08-02 ruling on §10.1
// ---------------------------------------------------------------------------

test("production is distinguished by form AND by the reserved hue", () => {
  const production = chipStyle("production");
  assert.equal(production.filled, true);
  assert.equal(production.hueToken, "--env-production");
  assert.ok(findToken(production.hueToken), "the chip names a token that does not exist");
  assert.ok(findToken(production.labelToken));
});

test("form alone still distinguishes production, with the hue removed", () => {
  // The ruling's third requirement. A monochrome display, a colour-deficient
  // reader and a photograph of a screen all lose the hue; the fill has to carry
  // it on its own, so `filled` must differ even where `hueToken` is ignored.
  const others = ENVIRONMENT_KINDS.filter((kind) => kind !== "production");
  assert.ok(others.length > 0);
  for (const kind of others) {
    assert.equal(chipStyle(kind).filled, false, `${kind} must not be filled — only production is`);
  }
});

test("no environment but production may name the reserved hue", () => {
  // Requirement one of the ruling, enforced here as well as by the token scan,
  // because this is the layer that would introduce a second use.
  for (const kind of ENVIRONMENT_KINDS) {
    if (kind === "production") continue;
    assert.equal(chipStyle(kind).hueToken, null, `${kind} reaches for the production hue`);
  }
});

test("every non-production environment is drawn identically", () => {
  // Deliberate. §4 asks only that production be unmissable, and giving staging
  // its own treatment is how the second palette starts.
  const styles = ENVIRONMENT_KINDS.filter((kind) => kind !== "production").map(chipStyle);
  for (const style of styles) assert.deepEqual(style, styles[0]);
});

// ---------------------------------------------------------------------------
// The tension line, DESIGN §5
// ---------------------------------------------------------------------------

test("at rest the line is a slack rope and says so", () => {
  const rest = tensionAppearance([], false);
  assert.equal(rest.state, "rest");
  assert.equal(rest.colorToken, "--tension-rest");
  assert.equal(rest.travelling, false);
  assert.ok(findToken(rest.colorToken));
});

test("the worst operation in flight wins", () => {
  // §5: "One element, one meaning everywhere: something is under load right
  // now." A failure during a deploy must not be painted as a deploy, so the
  // input is every operation and severity decides — not arrival order.
  const deploying = { state: "working", label: "Deploying marketing-www" } as const;
  const failing = { state: "fail", label: "Deploy failed" } as const;
  const warning = { state: "attention", label: "Certificate expiring" } as const;

  assert.equal(tensionAppearance([deploying, failing], false).state, "fail");
  assert.equal(tensionAppearance([failing, deploying], false).state, "fail", "order must not matter");
  assert.equal(tensionAppearance([deploying, warning], false).state, "attention");
  assert.equal(tensionAppearance([deploying], false).state, "working");
});

test("the line names the operation, because motion carries nothing on its own", () => {
  const appearance = tensionAppearance([{ state: "working", label: "Deploying marketing-www" }], false);
  assert.equal(appearance.announcement, "Deploying marketing-www");
  assert.ok(tensionAppearance([], false).announcement.length > 0, "rest must announce something too");
});

test("reduced motion stops the travel and keeps the meaning", () => {
  // §5: "the travel and pulse stop; the line stays solid in the status colour".
  // Both halves asserted, because the easy mistake is to switch the whole line
  // off with the animation and lose the state with it.
  const operations = [{ state: "fail", label: "Deploy failed" }] as const;
  const moving = tensionAppearance(operations, false);
  const still = tensionAppearance(operations, true);

  assert.equal(moving.travelling, true);
  assert.equal(still.travelling, false);
  assert.equal(still.state, moving.state, "reduced motion must not change what the line means");
  assert.equal(still.colorToken, moving.colorToken, "the line stays solid in the status colour");
  assert.equal(still.announcement, moving.announcement);
});

test("every tension state paints a token that exists", () => {
  for (const state of TENSION_STATES) {
    const appearance =
      state === "rest"
        ? tensionAppearance([], false)
        : tensionAppearance([{ state, label: "x" }], false);
    assert.ok(
      findToken(appearance.colorToken),
      `tension state ${state} paints ${appearance.colorToken}, which is not a token`,
    );
  }
});

// ---------------------------------------------------------------------------
// The rendering layer, checked without running it
// ---------------------------------------------------------------------------
//
// `node --test` cannot import a .tsx file — JSX is not erasable syntax — so the
// components are verified two ways instead: in a real browser for anything
// about focus and motion, and by reading their source here for the things a
// browser would only reveal by looking wrong.

function browserSources(): { path: string; source: string }[] {
  return globSync("src/web/app/**/*.{tsx,ts,html}", { cwd: ROOT }).map((file) => ({
    path: relative(ROOT, join(ROOT, file)).replaceAll("\\", "/"),
    source: readFileSync(join(ROOT, file), "utf8"),
  }));
}

test("every custom property the shell references is a real token", () => {
  // The typo this catches is invisible: `var(--text-body)` where the token is
  // `--text-base` resolves to nothing, CSS falls back to the inherited value,
  // and the result is a page that looks almost right. Eight of these were
  // written while building the shell and none of them threw.
  const known = new Set(tokenNames());
  const files = browserSources();
  assert.ok(files.length >= 3, "the scan found almost nothing — the walk is broken");

  const unknown: string[] = [];
  for (const { path, source } of files) {
    for (const match of source.matchAll(/var\((--[a-z0-9-]+)\)/g)) {
      const name = match[1] ?? "";
      if (!known.has(name)) unknown.push(`${path}: var(${name})`);
    }
  }

  assert.deepEqual(
    unknown,
    [],
    "these resolve to nothing at runtime and fall back to the inherited value, " +
      "which looks almost right and is not",
  );
});

test("the shell's font imports are exactly the registry's", () => {
  // They cannot be generated — a bundler resolves import specifiers statically
  // — so the list exists twice and this is what keeps the copies honest. A
  // missing weight falls back silently in development and is wrong in the
  // built bundle.
  const main = browserSources().find((file) => file.path.endsWith("main.tsx"));
  assert.ok(main, "main.tsx is missing");

  const imported = [...main.source.matchAll(/import "([^"]+\.css)";/g)].map((match) => match[1]);
  assert.deepEqual(imported, [...FONT_CSS_IMPORTS]);
});

test("the shell announces its state rather than only drawing it", () => {
  // §1's corollary generalised: nothing may be carried by appearance alone.
  // The active rail item, the current breadcrumb and the tension line all need
  // a non-visual form, and all three are easy to drop in a refactor that only
  // looks at the rendering.
  const shell = browserSources().find((file) => file.path.endsWith("Shell.tsx"));
  assert.ok(shell);
  for (const marker of ['aria-current={active ? "page" : undefined}', 'aria-current="page"', 'role="status"', 'aria-live="polite"']) {
    assert.ok(shell.source.includes(marker), `the shell no longer carries ${marker}`);
  }
  for (const label of ['aria-label="Sections"', 'aria-label="Breadcrumb"']) {
    assert.ok(shell.source.includes(label), `a landmark lost its name: ${label}`);
  }
});
