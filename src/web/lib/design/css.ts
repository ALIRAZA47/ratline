/**
 * CSS emission (RL-M1-027).
 *
 * The tokens are defined once, in TypeScript, and this module is the only thing
 * that turns them into custom properties. Nothing hand-writes a custom property
 * declaration anywhere else in the codebase, so the stylesheet and the
 * TypeScript API cannot disagree about what a token is worth.
 *
 * Dark is the default, per brief §6.6 ("Dark mode default, light mode fully
 * supported"), and light arrives three ways: the system preference, an explicit
 * `data-theme` on the root element, or neither — in which case dark wins.
 */

import { MODES, type Mode } from "./color.ts";
import { STATUS_ORDER, STATUS } from "./status.ts";
import { REDUCED_MOTION_OVERRIDES, TOKENS, tokenValue, type Token } from "./tokens.ts";

const INDENT = "  ";

function declarations(tokens: readonly Token[], mode: Mode, indent: string): string {
  return tokens.map((token) => `${indent}${token.name}: ${tokenValue(token, mode)};`).join("\n");
}

/** Tokens whose value differs between modes. Scalars are emitted once. */
function themedTokens(): readonly Token[] {
  return TOKENS.filter((token) => token.kind === "color");
}

function invariantTokens(): readonly Token[] {
  return TOKENS.filter((token) => token.kind === "scalar");
}

/**
 * The custom-property blocks.
 *
 * Order is load-bearing. `:root:not([data-theme="dark"])` inside the media
 * query and `:root[data-theme="light"]` have identical specificity, so the
 * explicit override has to come last to win. An operator who has forced a theme
 * gets the theme they forced, whatever the laptop thinks.
 */
export function renderTokensCss(): string {
  const themed = themedTokens();
  const blocks: string[] = [];

  blocks.push(
    [
      ":root {",
      `${INDENT}color-scheme: dark;`,
      "",
      declarations(invariantTokens(), "dark", INDENT),
      "",
      declarations(themed, "dark", INDENT),
      "}",
    ].join("\n"),
  );

  blocks.push(
    [
      "@media (prefers-color-scheme: light) {",
      `${INDENT}:root:not([data-theme="dark"]) {`,
      `${INDENT}${INDENT}color-scheme: light;`,
      "",
      declarations(themed, "light", `${INDENT}${INDENT}`),
      `${INDENT}}`,
      "}",
    ].join("\n"),
  );

  blocks.push(
    [
      ':root[data-theme="light"] {',
      `${INDENT}color-scheme: light;`,
      "",
      declarations(themed, "light", INDENT),
      "}",
    ].join("\n"),
  );

  blocks.push(
    [
      ':root[data-theme="dark"] {',
      `${INDENT}color-scheme: dark;`,
      "",
      declarations(themed, "dark", INDENT),
      "}",
    ].join("\n"),
  );

  return blocks.join("\n\n");
}

/**
 * Reduced motion, DESIGN.md §8.
 *
 * Implemented by zeroing the long duration tokens rather than by the usual
 * blanket `transition-duration: 0 !important` on every element, because §8 asks
 * for transitions *over* 120ms to be removed, not all of them. Anything built
 * on the tokens gets this for free; anything that hard-codes a duration does
 * not, which is one more reason not to hard-code one.
 *
 * The tension line keeps its colour and its lashings here. §5: "No information
 * is carried by motion alone."
 */
export function renderReducedMotionCss(): string {
  const overrides = REDUCED_MOTION_OVERRIDES.map(
    (override) => `${INDENT}${INDENT}${override.name}: ${override.value};`,
  ).join("\n");

  return [
    "@media (prefers-reduced-motion: reduce) {",
    `${INDENT}:root {`,
    overrides,
    `${INDENT}}`,
    "}",
  ].join("\n");
}

/**
 * Status colour plumbing.
 *
 * A component sets `data-status` and gets the right hue; it never names a
 * colour. The glyph is deliberately NOT injected with `content:` — DESIGN.md
 * §1's corollary requires the glyph to be information, and generated content is
 * not reliably exposed to assistive technology. Render `STATUS[id].glyph` as
 * real text next to a real label.
 */
export function renderStatusCss(): string {
  const mappings = STATUS_ORDER.map(
    (id) => `[data-status="${id}"] {\n${INDENT}--status-color: var(${STATUS[id].colorToken});\n}`,
  );

  return [
    ...mappings,
    [
      ".rl-status {",
      `${INDENT}color: var(--status-color);`,
      `${INDENT}display: inline-flex;`,
      `${INDENT}align-items: baseline;`,
      `${INDENT}gap: var(--space-xs);`,
      "}",
    ].join("\n"),
    [
      ".rl-status__glyph {",
      `${INDENT}font-variant-emoji: text;`,
      `${INDENT}line-height: 1;`,
      "}",
    ].join("\n"),
  ].join("\n\n");
}

/**
 * Base element styles.
 *
 * Small on purpose: this sets the defaults every screen inherits, and stops
 * there. Component styling belongs with components (RL-M1-028), but the
 * defaults have to live with the tokens or the first screen built will
 * re-declare them.
 */
export function renderBaseCss(): string {
  return [
    [
      "html {",
      `${INDENT}background-color: var(--tar);`,
      "}",
    ].join("\n"),
    [
      "body {",
      `${INDENT}margin: 0;`,
      `${INDENT}background-color: var(--tar);`,
      `${INDENT}color: var(--chalk);`,
      `${INDENT}font-family: var(--font-body);`,
      `${INDENT}font-size: var(--text-base);`,
      `${INDENT}font-weight: var(--weight-body);`,
      `${INDENT}line-height: var(--leading-base);`,
      // DESIGN.md §3: "Numerals are tabular everywhere a number can change."
      // Global rather than opt-in, because the failure mode is a counter
      // jittering under someone's gaze while they wait for a deploy.
      `${INDENT}font-variant-numeric: tabular-nums;`,
      `${INDENT}-webkit-font-smoothing: antialiased;`,
      "}",
    ].join("\n"),
    [
      "/* Screen titles, status counts, section heads. The wdth axis at 125 is",
      "   the Expanded instance; `font-stretch` drives it on a variable font. */",
      ".rl-display {",
      `${INDENT}font-family: var(--font-display);`,
      `${INDENT}font-stretch: var(--display-stretch);`,
      `${INDENT}font-weight: var(--weight-display);`,
      "}",
    ].join("\n"),
    [
      "/* Logs, identifiers, terminal output. Ligatures off: `!=` must look",
      "   like two characters (DESIGN.md §3). */",
      ".rl-mono {",
      `${INDENT}font-family: var(--font-mono);`,
      `${INDENT}font-weight: var(--weight-mono);`,
      `${INDENT}font-variant-ligatures: none;`,
      `${INDENT}font-feature-settings: "liga" 0, "calt" 0;`,
      "}",
    ].join("\n"),
    [
      "/* DESIGN.md §8: focus is never suppressed. */",
      ":focus-visible {",
      `${INDENT}outline: var(--focus-ring-width) solid var(--focus-ring);`,
      `${INDENT}outline-offset: var(--focus-ring-offset);`,
      "}",
    ].join("\n"),
    [
      "hr, .rl-hairline {",
      `${INDENT}border: 0;`,
      `${INDENT}border-top: var(--hairline-width) solid var(--rule-hairline);`,
      "}",
    ].join("\n"),
  ].join("\n\n");
}

/**
 * The complete design stylesheet.
 *
 * The `@font-face` rules are not included: they ship inside the vendored
 * `@fontsource` packages and are pulled in by importing the specifiers in
 * `FONT_CSS_IMPORTS`, which keeps the `.woff2` URLs relative to their own
 * package and therefore local. See `fonts.ts`.
 */
/**
 * The tension line's travel, DESIGN.md §5 (RL-M1-028).
 *
 * "a slow travelling highlight along its length. The line reads as a rope under
 * strain."
 *
 * Emitted here rather than as an inline style on the component, and the reason
 * is the reduced-motion half of §5. An inline `animation` cannot be overridden
 * by a media query, so a component that animated inline would depend entirely
 * on its own JavaScript noticing the preference — one mechanism, and the wrong
 * one, because it does not apply until React has mounted. As a class it is off
 * in the stylesheet before the first frame AND off in the hook, and the two
 * agree because the hook only ever removes the class.
 *
 * The highlight is a moving gradient over the line's own colour, so removing
 * the animation leaves the line SOLID in that colour rather than blank — §5's
 * "no information is carried by motion alone", enforced by the shape of the
 * rule rather than by remembering.
 */
export function renderTensionCss(): string {
  return [
    "@keyframes ratline-tension-travel {",
    `${INDENT}from { background-position: -100% 0; }`,
    `${INDENT}to { background-position: 200% 0; }`,
    "}",
    "",
    ".rl-tension {",
    `${INDENT}height: var(--tension-line-height);`,
    `${INDENT}background: var(--tension-color, var(--tension-rest));`,
    "}",
    "",
    ".rl-tension[data-travelling=\"true\"] {",
    `${INDENT}background-image: linear-gradient(`,
    `${INDENT}${INDENT}90deg,`,
    `${INDENT}${INDENT}transparent 0%,`,
    `${INDENT}${INDENT}var(--chalk) 45%,`,
    `${INDENT}${INDENT}transparent 60%`,
    `${INDENT});`,
    `${INDENT}background-size: 50% 100%;`,
    `${INDENT}background-repeat: no-repeat;`,
    `${INDENT}animation: ratline-tension-travel var(--duration-tension-travel) var(--easing-standard) infinite;`,
    "}",
    "",
    "@media (prefers-reduced-motion: reduce) {",
    `${INDENT}/* §5: "the travel and pulse stop; the line stays solid in the status`,
    `${INDENT}   colour". The gradient goes with the animation, so what remains is the`,
    `${INDENT}   flat background above — the state survives, the movement does not. */`,
    `${INDENT}.rl-tension[data-travelling=\"true\"] {`,
    `${INDENT}${INDENT}background-image: none;`,
    `${INDENT}${INDENT}animation: none;`,
    `${INDENT}}`,
    "}",
  ].join("\n");
}

export function renderDesignStylesheet(): string {
  return [
    renderTokensCss(),
    renderStatusCss(),
    renderBaseCss(),
    renderTensionCss(),
    renderReducedMotionCss(),
  ].join("\n\n");
}

/** Every mode the stylesheet emits a complete set of colour tokens for. */
export const EMITTED_MODES = MODES;
