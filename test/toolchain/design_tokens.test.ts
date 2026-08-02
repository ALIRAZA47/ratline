/**
 * Guards the design tokens (RL-M1-027) against the plan they implement.
 *
 * The three acceptance criteria are each checked here rather than asserted in a
 * commit message:
 *
 *   1. Palette, type scale, spacing and status colours exist as tokens, with no
 *      hard-coded values in components. Checked by transcribing DESIGN.md §2
 *      and §3 into this file as an independent copy of the spec, and by walking
 *      every source file under `src/web/` looking for literals.
 *   2. Dark and light both render. Checked by requiring identical token sets in
 *      both modes and by holding both to the contrast targets in DESIGN.md §8.
 *   3. Fonts are self-hosted. Checked by reading the vendored `@fontsource`
 *      stylesheets off disk, resolving every `url()` they contain, and failing
 *      if any of them points at a remote origin or at a file that is not there.
 *
 * The values below are typed out again on purpose. A test that imports the same
 * constant it is checking proves only that assignment works; these are read
 * from DESIGN.md and cross-checked against the document's own text, so drifting
 * away from the plan is what fails.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AUDIT_EXEMPTIONS,
  CONTRAST_TARGET,
  DURATION,
  ENVIRONMENT,
  FONT_ASSETS,
  FONT_PACKAGES,
  FONT_STACK,
  LAYOUT,
  MODES,
  REDUCED_MOTION_MAX,
  REDUCED_MOTION_OVERRIDES,
  SPACE,
  STATUS,
  STATUS_HUE,
  STATUS_ORDER,
  SURFACE,
  TOKENS,
  TYPE_SCALE,
  auditSource,
  contrastRatio,
  findToken,
  flatten,
  formatFindings,
  hueAngle,
  hueDistance,
  parseHex,
  saturation,
  renderBaseCss,
  renderDesignStylesheet,
  renderReducedMotionCss,
  renderTokensCss,
  survivesReducedMotion,
  tokenValue,
  type Mode,
  type StatusId,
  type Token,
} from "../../src/web/lib/design/index.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

const DESIGN_MD = readFileSync(join(ROOT, "docs", "DESIGN.md"), "utf8");

// --- DESIGN.md §2, transcribed independently --------------------------------

const EXPECTED_SURFACE: Record<string, { dark: string; light: string }> = {
  tar: { dark: "#14110F", light: "#FBF8F4" },
  pitch: { dark: "#1E1A17", light: "#FFFFFF" },
  hemp: { dark: "#D8B98A", light: "#8A6F45" },
  chalk: { dark: "#EDE7DF", light: "#1A1613" },
  chalkDim: { dark: "#9A918A", light: "#5E564F" },
};

const EXPECTED_STATUS: Record<string, { glyph: string; dark: string; light: string }> = {
  healthy: { glyph: "●", dark: "#4FB477", light: "#1F7A46" },
  working: { glyph: "◐", dark: "#59A5D8", light: "#1D6FA5" },
  attention: { glyph: "▲", dark: "#E0A33E", light: "#8A5A00" },
  fail: { glyph: "✕", dark: "#FF6369", light: "#C0272D" },
  idle: { glyph: "○", dark: "#7A736C", light: "#8A837C" },
};

/** DESIGN.md §3: "Scale, 13px base because density wins". */
const EXPECTED_TYPE_SCALE = [11, 12, 13, 15, 18, 24, 32];

// --- colour arithmetic ------------------------------------------------------
//
// The contrast assertions further down are only worth anything if the function
// computing them is right, so it is pinned against known values first.

test("contrast arithmetic matches the WCAG reference points", () => {
  assert.equal(Math.round(contrastRatio("#000000", "#FFFFFF")), 21);
  assert.equal(contrastRatio("#FFFFFF", "#FFFFFF"), 1);
  // Order must not matter — callers should not have to know which is the background.
  assert.equal(contrastRatio("#14110F", "#EDE7DF"), contrastRatio("#EDE7DF", "#14110F"));
  // Mid grey on white is the canonical 4.54:1 sample.
  assert.ok(Math.abs(contrastRatio("#767676", "#FFFFFF") - 4.54) < 0.01);
});

test("hex parsing refuses anything it would have to guess at", () => {
  assert.deepEqual(parseHex("#14110F"), { r: 0x14, g: 0x11, b: 0x0f });
  for (const bad of ["14110F", "#1411", "#GGGGGG", "#14110FF", "", "red"]) {
    assert.throws(() => parseHex(bad), TypeError, `should have rejected ${JSON.stringify(bad)}`);
  }
});

// --- acceptance 1: the tokens exist and match the plan ----------------------

test("the palette is DESIGN.md §2 exactly, in both modes", () => {
  const names = Object.keys(EXPECTED_SURFACE).sort();
  assert.deepEqual(Object.keys(SURFACE).sort(), names, "DESIGN.md §2 names five palette values");

  for (const [name, expected] of Object.entries(EXPECTED_SURFACE)) {
    const actual = SURFACE[name as keyof typeof SURFACE];
    assert.equal(actual.dark, expected.dark, `${name} dark`);
    assert.equal(actual.light, expected.light, `${name} light`);
    // Cross-check this file's copy of the spec against the document itself, so
    // a stale expectation here cannot quietly bless a stale token.
    assert.ok(DESIGN_MD.includes(expected.dark), `${expected.dark} is not in DESIGN.md`);
    assert.ok(DESIGN_MD.includes(expected.light), `${expected.light} is not in DESIGN.md`);
  }
});

test("the type scale is DESIGN.md §3 exactly, with 13 as the base", () => {
  const sizes = Object.entries(TYPE_SCALE)
    .filter(([name]) => name !== "log")
    .map(([, step]) => step.size)
    .sort((a, b) => a - b);
  assert.deepEqual(sizes, EXPECTED_TYPE_SCALE);
  assert.equal(TYPE_SCALE.base.size, 13, "13px base because density wins");
  // DESIGN.md §6 states the log surface outright: "JetBrains Mono 12.5/18".
  assert.equal(TYPE_SCALE.log.size, 12.5);
  assert.equal(TYPE_SCALE.log.leading, 18);
  for (const [name, step] of Object.entries(TYPE_SCALE)) {
    assert.ok(step.leading >= step.size, `${name} line box is smaller than its type`);
  }
});

test("the spacing scale and the fixed dimensions of the shroud are tokens", () => {
  assert.ok(Object.keys(SPACE).length >= 6, "a spacing scale exists");
  for (const [name, value] of Object.entries(SPACE)) {
    assert.ok(Number.isInteger(value) && value > 0, `${name} is a positive whole number of pixels`);
  }
  // DESIGN.md §4 and §5 state each of these outright.
  assert.equal(LAYOUT.railWidth, 200, "§4: the rail is 200px and never collapses");
  assert.equal(LAYOUT.topBarHeight, 44, "§4: the top bar is 44px");
  assert.equal(LAYOUT.tensionLineHeight, 2, "§5: the tension line is a 2px rule");
  assert.equal(LAYOUT.factsWidth, 280, "§4: the facts column is 280px");
  assert.equal(LAYOUT.rowHeight, 32, "§4: 32px table rows — row density is the point");
  assert.equal(LAYOUT.focusRingOffset, 2, "§8: a visible focus ring at 2px offset");
});

test("every group in acceptance 1 is represented in the token registry", () => {
  const groups = new Set(TOKENS.map((token) => token.group));
  for (const required of ["surface", "status", "type", "space", "layout"]) {
    assert.ok(groups.has(required as Token["group"]), `no tokens in group ${required}`);
  }
  for (const token of TOKENS) {
    assert.match(token.name, /^--[a-z][a-z0-9-]*$/, `${token.name} is not a well-formed custom property`);
    assert.ok(token.description.length > 0, `${token.name} has no description`);
  }
  const names = TOKENS.map((token) => token.name);
  assert.equal(new Set(names).size, names.length, "duplicate token names");
});

// --- DESIGN.md §1's corollary: status is never colour alone -----------------

test("every status carries a glyph and a label, not just a colour", () => {
  assert.deepEqual(Object.keys(STATUS).sort(), Object.keys(STATUS_HUE).sort(), "a hue with no status record");
  assert.deepEqual([...STATUS_ORDER].sort(), Object.keys(STATUS).sort(), "STATUS_ORDER is not exhaustive");
  assert.equal(new Set(STATUS_ORDER).size, STATUS_ORDER.length, "a status is listed twice");

  const glyphs = new Set<string>();
  for (const id of STATUS_ORDER) {
    const token = STATUS[id];
    const expected = EXPECTED_STATUS[id];
    assert.ok(expected !== undefined, `${id} is not a status DESIGN.md §2 defines`);
    assert.equal(token.glyph, expected.glyph, `${id} glyph`);
    assert.ok(token.label.length > 0, `${id} has no label`);
    assert.ok(token.meaning.length > 0, `${id} has no stated meaning`);
    assert.ok(DESIGN_MD.includes(token.glyph), `the ${id} glyph is not in DESIGN.md`);
    assert.ok(!glyphs.has(token.glyph), `${id} reuses a glyph — the glyph must disambiguate`);
    glyphs.add(token.glyph);

    const colour = STATUS_HUE[id];
    assert.equal(colour.dark, expected.dark, `${id} dark`);
    assert.equal(colour.light, expected.light, `${id} light`);
    assert.ok(findToken(token.colorToken) !== undefined, `${token.colorToken} is not emitted`);
  }
  assert.equal(glyphs.size, 5, "DESIGN.md §2 defines five statuses");
});

// --- acceptance 2: dark and light both render -------------------------------

test("every colour token defines both modes with the same names", () => {
  const perMode = new Map<Mode, string[]>();
  for (const mode of MODES) {
    perMode.set(
      mode,
      TOKENS.filter((token) => token.kind === "color")
        .filter((token) => tokenValue(token, mode).length > 0)
        .map((token) => token.name)
        .sort(),
    );
  }
  const dark = perMode.get("dark");
  const light = perMode.get("light");
  assert.ok(dark !== undefined && light !== undefined);
  assert.ok(dark.length >= 15, "suspiciously few colour tokens");
  assert.deepEqual(dark, light, "dark and light must define the same token names");
});

test("the emitted stylesheet carries a complete set of custom properties per mode", () => {
  const css = renderTokensCss();
  for (const token of TOKENS) {
    assert.ok(css.includes(`${token.name}:`), `${token.name} never reaches the stylesheet`);
  }
  // Dark is the default (brief §6.6); light arrives by system preference and by
  // an explicit override, and the override has to come last to win the tie.
  assert.match(css, /^:root \{\n {2}color-scheme: dark;/, "dark must be the :root default");
  assert.ok(css.includes("@media (prefers-color-scheme: light)"));
  const mediaAt = css.indexOf("@media (prefers-color-scheme: light)");
  const overrideAt = css.indexOf(':root[data-theme="light"]');
  assert.ok(overrideAt > mediaAt, "the forced-theme block must come after the media query to win on source order");
  assert.ok(css.includes(':root[data-theme="dark"]'), "forcing dark must also be possible");

  const opens = (css.match(/\{/g) ?? []).length;
  const closes = (css.match(/\}/g) ?? []).length;
  assert.equal(opens, closes, "unbalanced braces in the emitted stylesheet");

  // Each themed block must set every colour token, or a mode inherits a value
  // from the other one and renders wrong in exactly one place.
  const colourNames = TOKENS.filter((token) => token.kind === "color").map((token) => token.name);
  for (const block of [':root[data-theme="light"]', ':root[data-theme="dark"]']) {
    const start = css.indexOf(block);
    const body = css.slice(start, css.indexOf("\n}", start));
    for (const name of colourNames) {
      assert.ok(body.includes(`${name}:`), `${block} is missing ${name}`);
    }
  }
});

// --- acceptance 2 continued: DESIGN.md §8 contrast targets ------------------

test("every colour meets the contrast target DESIGN.md §8 sets for its role", () => {
  let checks = 0;
  const failures: string[] = [];

  for (const token of TOKENS) {
    if (token.kind !== "color" || token.translucent) continue;
    const rule = token.contrast;
    if (rule.kind === "surface" || rule.kind === "decorative") continue;

    const target = rule.kind === "text" ? CONTRAST_TARGET.text : CONTRAST_TARGET.mark;
    for (const referenceName of rule.on) {
      const reference = findToken(referenceName);
      assert.ok(reference !== undefined, `${token.name} contrasts against unknown token ${referenceName}`);
      assert.ok(reference.kind === "color" && !reference.translucent, `${referenceName} has no opaque value`);

      for (const mode of MODES) {
        const ratio = contrastRatio(token.value[mode], reference.value[mode]);
        checks += 1;
        if (ratio < target) {
          failures.push(
            `${token.name} on ${referenceName} in ${mode}: ${ratio.toFixed(2)}:1 < ${String(target)}:1 (${rule.kind})`,
          );
        }
      }
    }
  }

  assert.ok(checks >= 24, `only ${String(checks)} contrast checks ran — the rules are not being walked`);
  assert.deepEqual(failures, [], `contrast targets from DESIGN.md §8 not met:\n${failures.join("\n")}`);
});

test("the four operational statuses clear body-text contrast in both modes", () => {
  // DESIGN.md §2 justifies the lighter red specifically so that "body-size text
  // clears 4.5:1 on --tar". That claim is checked directly, not inferred.
  const operational: StatusId[] = ["healthy", "working", "attention", "fail"];
  for (const id of operational) {
    for (const mode of MODES) {
      for (const surface of [SURFACE.tar, SURFACE.pitch]) {
        const ratio = contrastRatio(STATUS_HUE[id][mode], surface[mode]);
        assert.ok(ratio >= CONTRAST_TARGET.text, `${id} in ${mode} is ${ratio.toFixed(2)}:1`);
      }
    }
  }
  // Idle is the documented exception: a mark, never body text. If it ever did
  // clear 4.5:1 the comment in palette.ts would be wrong, so assert both bounds.
  for (const mode of MODES) {
    const ratio = contrastRatio(STATUS_HUE.idle[mode], SURFACE.tar[mode]);
    assert.ok(ratio >= CONTRAST_TARGET.mark, `idle in ${mode} falls below the 3:1 mark floor`);
    assert.ok(ratio < CONTRAST_TARGET.text, `idle in ${mode} now clears 4.5:1 — update the mark-only rule`);
  }
});

// --- the reserved production hue, DESIGN.md §10.1 as ruled 2026-08-02 -------
//
// §1 was amended from "colour means status" to "colour means status OR
// production". The amendment is safe only while two things hold, and neither is
// the kind of thing that stays true by being written down.

test("the production hue is not confusable with any status hue", () => {
  // The failure this prevents is precise: an operator glancing at a production
  // chip and reading it as a status, or the reverse. That is a question about
  // distance on the colour wheel, so it is measured as one.
  const MINIMUM_SEPARATION = 60;

  for (const mode of MODES) {
    const production = ENVIRONMENT.production[mode];

    for (const id of STATUS_ORDER) {
      const status = STATUS_HUE[id][mode];

      // `idle` is a warm grey at ~6% saturation, where a hue angle is an
      // artefact of rounding — comparing angles with it would be meaningless
      // and would pass for the wrong reason. What separates production from
      // idle is that one is saturated and the other is not, so that is what is
      // asserted.
      if (saturation(status) < 0.2) {
        assert.ok(
          saturation(production) > saturation(status) * 3,
          `${id} in ${mode} is a near-grey and production must not be`,
        );
        continue;
      }

      const distance = hueDistance(production, status);
      assert.ok(
        distance >= MINIMUM_SEPARATION,
        `production (${String(Math.round(hueAngle(production)))}°) is ${String(Math.round(distance))}° ` +
          `from ${id} (${String(Math.round(hueAngle(status)))}°) in ${mode} — under ${String(MINIMUM_SEPARATION)}°, ` +
          `a chip and a status become confusable at a glance`,
      );
    }
  }
});

test("the production chip is legible and visible in both modes", () => {
  // Two different requirements that happen to share a number, asserted apart so
  // that a palette change breaking one is not hidden by the other still holding.
  const label = findToken("--env-production-on");
  const chip = findToken("--env-production");
  assert.ok(label?.kind === "color" && !label.translucent);
  assert.ok(chip?.kind === "color" && !chip.translucent);

  for (const mode of MODES) {
    const fill = chip.value[mode];
    // Visible: the chip must stand off both surfaces at the non-text floor.
    for (const surface of [SURFACE.tar, SURFACE.pitch]) {
      const ratio = contrastRatio(fill, surface[mode]);
      assert.ok(
        ratio >= CONTRAST_TARGET.mark,
        `the production chip is ${ratio.toFixed(2)}:1 against its surface in ${mode}`,
      );
    }
    // Legible: the label on it is body text and clears the body-text bar.
    const onFill = contrastRatio(label.value[mode], fill);
    assert.ok(
      onFill >= CONTRAST_TARGET.text,
      `the production label is ${onFill.toFixed(2)}:1 on the chip in ${mode}`,
    );
  }
});

test("nothing but the environment chip may use the production hue", () => {
  // Requirement one of the §10.1 ruling, and the whole basis of amending §1: a
  // hue used in one place has one meaning. Enforced by scanning rather than by
  // convention, because a convention is exactly what would decay into a
  // second use.
  //
  // WHEN THE CHIP IS BUILT (RL-M1-028) this allowlist gains its component file
  // and nothing else. It gets stricter as the interface grows, never looser.
  const ALLOWED = [
    "src/web/lib/design/palette.ts",
    "src/web/lib/design/tokens.ts",
    "src/web/lib/design/index.ts",
  ];

  const needles = [
    "--env-production",
    ENVIRONMENT.production.dark,
    ENVIRONMENT.production.light,
    ENVIRONMENT.production.dark.toLowerCase(),
    ENVIRONMENT.production.light.toLowerCase(),
  ];

  const offenders: string[] = [];
  for (const file of sourceFiles(join(ROOT, "src", "web"))) {
    const relativePath = relative(ROOT, file).replaceAll("\\", "/");
    if (ALLOWED.includes(relativePath)) continue;
    const source = readFileSync(file, "utf8");
    for (const needle of needles) {
      if (source.includes(needle)) offenders.push(`${relativePath} uses ${needle}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "the production hue has escaped the environment chip. DESIGN.md §1 admits it as a " +
      "SECOND meaning for saturated colour on the condition that it has exactly one use; " +
      "a second use means the amendment no longer holds and colour has stopped being " +
      "unambiguous.",
  );
});

test("the environment group is a group, not a colour smuggled into another one", () => {
  // A token filed under "status" would be measured, rendered and reviewed as a
  // status — which is the confusion §1 is about, expressed in the registry
  // rather than on screen.
  const environment = TOKENS.filter((token) => token.group === "environment");
  assert.deepEqual(
    environment.map((token) => token.name),
    ["--env-production", "--env-production-on"],
    "the environment group has changed — §1 admits ONE production hue and no more",
  );
  for (const token of TOKENS) {
    if (token.group === "environment") continue;
    assert.ok(
      !token.name.startsWith("--env-"),
      `${token.name} is named as an environment token but filed under ${token.group}`,
    );
  }
});

test("the hairline stays a hairline and the hover stays felt rather than seen", () => {
  // DESIGN.md §2: hairlines are hemp at 12%, hover is chalk at 4%. Both are
  // deliberately below any contrast floor; what matters is that they are
  // visible at all against their own surface, and that they do not creep up
  // into the range where they start competing with status colour.
  for (const mode of MODES) {
    const hairline = flatten(SURFACE.hemp[mode], 0.12, SURFACE.tar[mode]);
    const ratio = contrastRatio(hairline, SURFACE.tar[mode]);
    assert.ok(ratio > 1.05, `the ${mode} hairline is invisible at ${ratio.toFixed(2)}:1`);
    assert.ok(ratio < 2, `the ${mode} hairline at ${ratio.toFixed(2)}:1 is a border, not a hairline`);
  }
});

// --- DESIGN.md §8: reduced motion -------------------------------------------

test("reduced motion removes every transition over 120ms and keeps the rest", () => {
  assert.equal(REDUCED_MOTION_MAX, 120, "DESIGN.md §8 sets the threshold at 120ms");

  const dropped = new Set(REDUCED_MOTION_OVERRIDES.map((override) => override.name));
  let over = 0;
  for (const [name, value] of Object.entries(DURATION)) {
    const tokenName = `--duration-${name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
    if (value > REDUCED_MOTION_MAX) {
      over += 1;
      assert.ok(dropped.has(tokenName), `${tokenName} is ${String(value)}ms and must be dropped`);
      assert.equal(survivesReducedMotion(value), false);
    } else {
      assert.ok(!dropped.has(tokenName), `${tokenName} is ${String(value)}ms and must survive`);
      assert.equal(survivesReducedMotion(value), true);
    }
  }
  assert.ok(over >= 2, "no long durations exist to be dropped — the rule is untested");

  const css = renderReducedMotionCss();
  assert.ok(css.includes("@media (prefers-reduced-motion: reduce)"));
  for (const override of REDUCED_MOTION_OVERRIDES) {
    assert.ok(css.includes(`${override.name}: 0ms;`), `${override.name} is not zeroed`);
  }
});

// --- acceptance 3: the fonts are self-hosted --------------------------------

test("the font packages are runtime dependencies, not dev-only", () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
    dependencies?: Record<string, string>;
  };
  const dependencies = pkg.dependencies ?? {};
  for (const name of FONT_PACKAGES) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(dependencies, name),
      `${name} must be in dependencies — the fonts ship with the interface`,
    );
  }
  assert.equal(FONT_PACKAGES.length, 3, "one package per face in DESIGN.md §3");
});

test("no font stylesheet reaches the network", () => {
  // This is the whole of acceptance criterion 3. Brief C5 assumes an air-gapped
  // VPN; DESIGN.md §3 says a font CDN "would break exactly when someone needs
  // the tool most". So: every rule, every URL, resolved off disk.
  let urls = 0;

  for (const asset of FONT_ASSETS) {
    for (const specifier of asset.cssImports) {
      const cssPath = join(ROOT, "node_modules", specifier);
      assert.ok(existsSync(cssPath), `${specifier} is not vendored — run npm install`);
      const css = readFileSync(cssPath, "utf8");

      assert.ok(css.includes("@font-face"), `${specifier} declares no @font-face rules`);
      assert.ok(
        css.includes(`font-family: '${asset.family}'`),
        `${specifier} does not register the family ${asset.family} that the font stack names`,
      );

      for (const match of css.matchAll(/url\(([^)]+)\)/g)) {
        const raw = match[1];
        assert.ok(raw !== undefined);
        const url = raw.trim().replace(/^['"]|['"]$/g, "");
        urls += 1;
        assert.ok(
          !/^(?:[a-z]+:)?\/\//i.test(url),
          `${specifier} loads ${url} from a remote origin — the interface would break offline`,
        );
        assert.ok(url.startsWith("./"), `${specifier} references ${url}, which is not package-relative`);
        const fontPath = join(dirname(cssPath), url.slice(2));
        assert.ok(existsSync(fontPath), `${specifier} references ${url}, which is not on disk`);
        assert.ok(statSync(fontPath).size > 0, `${url} is an empty file`);
      }
    }
  }

  assert.ok(urls >= 12, `only ${String(urls)} font URLs checked — the walk is not finding the rules`);
});

test("the display face is the Expanded width DESIGN.md §3 asks for", () => {
  const display = FONT_ASSETS.find((asset) => asset.role === "display");
  assert.ok(display !== undefined);
  const specifier = display.cssImports[0];
  assert.ok(specifier !== undefined);
  const css = readFileSync(join(ROOT, "node_modules", specifier), "utf8");
  // Without a width axis this renders at normal width, which is precisely the
  // silent substitution DESIGN.md §10 warns is expensive to discover late.
  assert.match(css, /font-stretch:\s*\d+% \d+%/, "the display stylesheet carries no width axis");
  assert.ok(FONT_STACK.display.includes(display.family), "the font stack does not name the family it loads");
});

test("mono ligatures are off — `!=` must look like two characters", () => {
  const base = renderBaseCss();
  assert.ok(base.includes("font-variant-ligatures: none"), "standard ligatures are still on");
  assert.ok(base.includes('font-feature-settings: "liga" 0, "calt" 0'), "contextual alternates are still on");
  assert.ok(base.includes("font-family: var(--font-mono)"), "the mono rule does not use the mono token");
});

// --- acceptance 1 continued: no hard-coded values in components -------------

const SCANNED_EXTENSIONS = [".ts", ".tsx", ".js", ".css", ".svelte", ".html"];

function sourceFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const full = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      found.push(...sourceFiles(full));
    } else if (SCANNED_EXTENSIONS.some((extension) => entry.name.endsWith(extension))) {
      found.push(full);
    }
  }
  return found;
}

test("nothing under src/web hard-codes a colour or a type value", () => {
  const files = sourceFiles(join(ROOT, "src", "web"));
  assert.ok(files.length >= 5, "the scan found almost nothing — the walk is broken, not the tree clean");

  const findings = files.flatMap((file) =>
    auditSource(relative(ROOT, file).replaceAll("\\", "/"), readFileSync(file, "utf8")),
  );

  assert.deepEqual(
    findings.map((finding) => `${finding.file}:${String(finding.line)} ${finding.rule}`),
    [],
    `hard-coded design values — use a token from src/web/lib/design:\n${formatFindings(findings)}`,
  );
});

test("the audit actually detects each thing it claims to detect", () => {
  // A guard that has only ever run over a clean tree has proved nothing. Every
  // rule is exercised against a fixture that should trip it, and against one
  // that should not.
  const cases: { source: string; rule: string }[] = [
    { source: "const brand = \"#3B82F6\";", rule: "hex-colour" },
    { source: "  background: #fff;", rule: "hex-colour" },
    { source: "  box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.4);", rule: "colour-function" },
    { source: "  border-color: color-mix(in srgb, black, white);", rule: "colour-function" },
    { source: "  color: red;", rule: "literal-colour-declaration" },
    { source: "  background: white;", rule: "literal-colour-declaration" },
    { source: "  fill: currentColor;", rule: "literal-colour-declaration" },
    { source: "  font-family: Inter, sans-serif;", rule: "literal-type-declaration" },
    { source: "  font-size: 14px;", rule: "literal-type-declaration" },
  ];

  for (const { source, rule } of cases) {
    const findings = auditSource("src/web/routes/Example.svelte", source);
    assert.ok(
      findings.some((finding) => finding.rule === rule),
      `the audit missed ${rule} in ${JSON.stringify(source)}`,
    );
  }

  const clean = [
    "  color: var(--chalk);",
    "  background-color: var(--tar);",
    "  font-family: var(--font-body);",
    "  font-size: var(--text-base);",
    "  color-scheme: dark;",
    "  line-height: 1;",
    "  gap: var(--space-sm);",
    '  const anchor = "#L42";',
  ].join("\n");
  assert.deepEqual(auditSource("src/web/routes/Example.svelte", clean), [], "false positive on token-based CSS");
});

test("only the two declared source-of-truth files may write a colour", () => {
  assert.deepEqual(
    AUDIT_EXEMPTIONS.map((exemption) => exemption.path).sort(),
    ["src/web/lib/design/color.ts", "src/web/lib/design/palette.ts"],
    "the set of files allowed to name a colour has changed",
  );
  // The exemption is per-rule, not blanket: palette.ts may hold hexes and still
  // may not emit a hard-coded font size.
  const findings = auditSource(
    "src/web/lib/design/palette.ts",
    ['const brand = "#14110F";', 'const css = "font-size: 14px;";'].join("\n"),
  );
  assert.deepEqual(
    findings.map((finding) => finding.rule),
    ["literal-type-declaration"],
    "the exemption is wider than it should be",
  );
});

test("the audit reads context, not just characters", () => {
  // The two false-positive classes that make a guard like this get switched
  // off: a doc comment that mentions a colour, and a TypeScript annotation
  // that happens to be spelled like a CSS property.
  const commentary = [
    "/** Mixes #14110F with rgba(0, 0, 0, 0.4). */",
    "// background: red;",
    "/* font-size: 14px; */",
  ].join("\n");
  assert.deepEqual(auditSource("src/web/lib/design/tokens.ts", commentary), [], "comments are documentation");

  const annotations = "export function paint(background: string, color: string): void {}";
  assert.deepEqual(auditSource("src/web/lib/design/tokens.ts", annotations), [], "type annotations are not CSS");

  // But the same text inside a string, which is how a .ts file emits CSS, is
  // still caught.
  const emitted = 'const rule = "background: red;";';
  assert.deepEqual(
    auditSource("src/web/lib/design/tokens.ts", emitted).map((finding) => finding.rule),
    ["literal-colour-declaration"],
  );

  // And a Svelte component's prop types are code, while its markup is style.
  const component = [
    "<script lang=\"ts\">",
    "  export let background: string;",
    "</script>",
    "<style>",
    "  .card { background: pink; }",
    "</style>",
  ].join("\n");
  const findings = auditSource("src/web/lib/Card.svelte", component);
  assert.deepEqual(
    findings.map((finding) => finding.line),
    [5],
    "only the stylesheet line should be reported",
  );
});

// --- the stylesheet as a whole ----------------------------------------------

test("the full stylesheet is self-consistent and references only tokens", () => {
  const css = renderDesignStylesheet();
  const declared = new Set(TOKENS.map((token) => token.name));
  declared.add("--status-color"); // set by the [data-status] rules, not a token

  const referenced = [...css.matchAll(/var\((--[a-z0-9-]+)\)/g)].map((match) => match[1]);
  assert.ok(referenced.length >= 15, "the stylesheet barely references any tokens");
  for (const name of referenced) {
    assert.ok(name !== undefined);
    assert.ok(declared.has(name), `the stylesheet references ${name}, which no token defines`);
  }

  // Every status is reachable from CSS by id, so a component never names a hue.
  for (const id of STATUS_ORDER) {
    assert.ok(css.includes(`[data-status="${id}"]`), `${id} has no CSS hook`);
  }
});
