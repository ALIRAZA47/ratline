/**
 * The token registry (RL-M1-027).
 *
 * One list, assembled from the modules that own each decision, and the single
 * source of truth for both TypeScript and CSS. `css.ts` emits custom properties
 * from this array and nothing else, so the two cannot drift: a token added here
 * appears in the stylesheet automatically, and a token that exists in the
 * stylesheet but not here cannot exist at all.
 *
 * Every colour token declares what it must contrast against. That turns
 * DESIGN.md §8 —
 *
 *   > Body text meets 4.5:1 in both modes; large text and marks meet 3:1.
 *
 * — from a sentence in a document into an assertion the test suite walks. If
 * someone retunes a hex in `palette.ts`, the contrast test tells them what they
 * broke rather than leaving it to be discovered by a colour-blind operator at
 * 2am.
 */

import type { Hex, Mode, Themed } from "./color.ts";
import { withAlpha } from "./color.ts";
import { ALPHA, ENVIRONMENT, STATUS_FILL, STATUS_HUE, SURFACE } from "./palette.ts";
import { STATUS, STATUS_ORDER } from "./status.ts";
import {
  DISPLAY_STRETCH,
  FONT_STACK,
  FONT_WEIGHT,
  TYPE_SCALE,
} from "./typography.ts";
import { LAYOUT, RADIUS, SPACE, px } from "./space.ts";
import { DURATION, EASING, REDUCED_MOTION_MAX, ms, survivesReducedMotion } from "./motion.ts";

export type TokenGroup =
  | "surface"
  | "status"
  | "environment"
  | "type"
  | "space"
  | "layout"
  | "motion";

/** WCAG thresholds, straight from DESIGN.md §8. */
export const CONTRAST_TARGET = {
  /** Body-size text. */
  text: 4.5,
  /** Large text, glyphs, marks and non-text UI. */
  mark: 3,
} as const;

/**
 * What a colour has to contrast against, and how hard.
 *
 * `surface` means the token is a background and is itself the reference.
 * `decorative` means the token carries no information on its own — a 12%
 * hairline is not required to clear anything, and pretending otherwise would
 * mean darkening it until it stopped being a hairline.
 */
export type ContrastRule =
  | { readonly kind: "surface" }
  | { readonly kind: "decorative" }
  | { readonly kind: "text"; readonly on: readonly string[] }
  | { readonly kind: "mark"; readonly on: readonly string[] };

interface TokenBase {
  /** CSS custom property name, including the leading `--`. */
  readonly name: string;
  readonly group: TokenGroup;
  readonly description: string;
}

export interface OpaqueColorToken extends TokenBase {
  readonly kind: "color";
  readonly translucent: false;
  readonly value: Themed<Hex>;
  readonly contrast: ContrastRule;
}

export interface TranslucentColorToken extends TokenBase {
  readonly kind: "color";
  readonly translucent: true;
  readonly value: Themed<string>;
  /** The opaque palette colour this was mixed from. */
  readonly base: Themed<Hex>;
  readonly alpha: number;
}

export interface ScalarToken extends TokenBase {
  readonly kind: "scalar";
  /** Mode-invariant: a length, a number, a duration, a family stack. */
  readonly value: string;
}

export type Token = OpaqueColorToken | TranslucentColorToken | ScalarToken;
export type ColorToken = OpaqueColorToken | TranslucentColorToken;

/** The two surfaces every foreground colour is measured against. */
const SURFACES = ["--tar", "--pitch"] as const;

function opaque(
  name: string,
  group: TokenGroup,
  value: Themed<Hex>,
  contrast: ContrastRule,
  description: string,
): OpaqueColorToken {
  return { kind: "color", translucent: false, name, group, value, contrast, description };
}

function translucent(
  name: string,
  group: TokenGroup,
  base: Themed<Hex>,
  alpha: number,
  description: string,
): TranslucentColorToken {
  return {
    kind: "color",
    translucent: true,
    name,
    group,
    base,
    alpha,
    value: { dark: withAlpha(base.dark, alpha), light: withAlpha(base.light, alpha) },
    description,
  };
}

function scalar(name: string, group: TokenGroup, value: string, description: string): ScalarToken {
  return { kind: "scalar", name, group, value, description };
}

/** `tensionTravel` -> `tension-travel`. */
function kebab(camel: string): string {
  return camel.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

// --- surfaces and text, DESIGN.md §2 ---------------------------------------

const surfaceTokens: readonly Token[] = [
  opaque("--tar", "surface", SURFACE.tar, { kind: "surface" }, "Page canvas"),
  opaque("--pitch", "surface", SURFACE.pitch, { kind: "surface" }, "Cards, rails, raised surfaces"),
  opaque("--chalk", "surface", SURFACE.chalk, { kind: "text", on: SURFACES }, "Primary text"),
  opaque("--chalk-dim", "surface", SURFACE.chalkDim, { kind: "text", on: SURFACES }, "Secondary text, labels"),
  // Linework, active markers and the focus ring — non-text by definition, so
  // the 3:1 floor for non-text UI applies rather than the 4.5:1 body-text one.
  // In light mode this sits at 4.47:1 on the canvas; close enough to read, but
  // it is not approved for body text and the rule here says so.
  opaque("--hemp", "surface", SURFACE.hemp, { kind: "mark", on: SURFACES }, "Rope linework, active markers"),
  opaque("--focus-ring", "surface", SURFACE.hemp, { kind: "mark", on: SURFACES }, "Focus ring, DESIGN.md §8"),
  translucent("--rule-hairline", "surface", SURFACE.hemp, ALPHA.hairline, "Hairline rules — hemp at 12%"),
  translucent("--surface-hover", "surface", SURFACE.chalk, ALPHA.hover, "Row and control hover — chalk at 4%"),
  translucent("--tension-rest", "surface", SURFACE.hemp, ALPHA.hairline, "Tension line at rest — a slack rope"),
];

// --- status, DESIGN.md §2 ---------------------------------------------------

/**
 * Text on a filled `--st-fail` surface — the break-glass banner in §2, which is
 * full-bleed and "meant to be uncomfortable".
 *
 * Derived, not stated in DESIGN.md. It resolves to `--tar` in each mode, which
 * is not a coincidence worth trusting blindly: in dark mode `--st-fail` is the
 * light red and needs dark text (6.48:1), in light mode it is the dark red and
 * needs light text (5.56:1). Both directions land on that mode's canvas
 * colour, and the contrast rule below is measured against `--st-fail` so the
 * test would catch it if a palette change broke the coincidence.
 */
const failOn: Themed<Hex> = { dark: SURFACE.tar.dark, light: SURFACE.tar.light };

const statusTokens: readonly Token[] = [
  ...STATUS_ORDER.map((id) => {
    const token = STATUS[id];
    // Idle is the one status that does not reach 4.5:1 — DESIGN.md pitches it
    // as the absence of activity, and §8 allows marks at 3:1. Its label text
    // renders in `--chalk-dim`, never in the status colour.
    const contrast: ContrastRule =
      id === "idle" ? { kind: "mark", on: SURFACES } : { kind: "text", on: SURFACES };
    return opaque(token.colorToken, "status", STATUS_HUE[id], contrast, `${token.label} — ${token.meaning}`);
  }),
  opaque(
    "--st-fail-mark",
    "status",
    STATUS_FILL.failMark,
    { kind: "mark", on: SURFACES },
    "Darker red for large marks and fills, DESIGN.md §2",
  ),
  opaque(
    "--st-fail-on",
    "status",
    failOn,
    { kind: "text", on: ["--st-fail"] },
    "Text on a filled --st-fail surface, e.g. the break-glass banner",
  ),
];

// --- environment, DESIGN.md §10.1 as ruled 2026-08-02 ------------------------

/**
 * Text on the filled production chip.
 *
 * Derived, like `--st-fail-on` and for the same reason. It resolves to `--tar`
 * in each mode because the two production values invert — light violet in dark
 * mode wants dark text, dark violet in light mode wants light text — and both
 * directions land on that mode's canvas colour. That is a coincidence the
 * contrast rule below measures rather than trusts, so retuning the hue breaks a
 * test instead of quietly producing an unreadable chip.
 */
const productionOn: Themed<Hex> = { dark: SURFACE.tar.dark, light: SURFACE.tar.light };

const environmentTokens: readonly Token[] = [
  opaque(
    "--env-production",
    "environment",
    ENVIRONMENT.production,
    // A fill, so the 3:1 non-text floor is what applies to it against the
    // surfaces. It clears far more than that, because the same value also has
    // to carry the label — see below.
    { kind: "mark", on: SURFACES },
    "The one reserved production hue — the filled environment chip, and nothing else",
  ),
  opaque(
    "--env-production-on",
    "environment",
    productionOn,
    { kind: "text", on: ["--env-production"] },
    "Label on the filled production chip",
  ),
];

// --- type, DESIGN.md §3 -----------------------------------------------------

const typeTokens: readonly Token[] = [
  scalar("--font-display", "type", FONT_STACK.display, "Display face — Archivo Expanded"),
  scalar("--font-body", "type", FONT_STACK.body, "Body and UI face — Public Sans"),
  scalar("--font-mono", "type", FONT_STACK.mono, "Mono face — JetBrains Mono, ligatures off"),
  scalar("--display-stretch", "type", DISPLAY_STRETCH, "Archivo wdth axis at its widest — the Expanded instance"),
  ...Object.entries(FONT_WEIGHT).map(([name, weight]) =>
    scalar(`--weight-${kebab(name)}`, "type", String(weight), `Font weight ${String(weight)}`),
  ),
  ...Object.entries(TYPE_SCALE).flatMap(([name, step]) => [
    scalar(`--text-${kebab(name)}`, "type", px(step.size), `Type scale step ${String(step.size)}px`),
    scalar(`--leading-${kebab(name)}`, "type", px(step.leading), `Line box for the ${name} step`),
  ]),
];

// --- space and layout, DESIGN.md §4 -----------------------------------------

const spaceTokens: readonly Token[] = [
  ...Object.entries(SPACE).map(([name, value]) =>
    scalar(`--space-${kebab(name)}`, "space", px(value), `Spacing step ${String(value)}px`),
  ),
  ...Object.entries(RADIUS).map(([name, value]) =>
    scalar(`--radius-${kebab(name)}`, "space", px(value), `Corner radius ${String(value)}px`),
  ),
];

const layoutTokens: readonly Token[] = Object.entries(LAYOUT).map(([name, value]) =>
  scalar(`--${kebab(name)}`, "layout", px(value), `Fixed dimension from DESIGN.md §4`),
);

// --- motion, DESIGN.md §5 and §8 --------------------------------------------

const motionTokens: readonly Token[] = [
  ...Object.entries(DURATION).map(([name, value]) =>
    scalar(`--duration-${kebab(name)}`, "motion", ms(value), `Duration ${String(value)}ms`),
  ),
  ...Object.entries(EASING).map(([name, value]) =>
    scalar(`--easing-${kebab(name)}`, "motion", value, "Decelerating curve — arrive and settle"),
  ),
  scalar(
    "--reduced-motion-max",
    "motion",
    ms(REDUCED_MOTION_MAX),
    "Transitions longer than this are removed under prefers-reduced-motion, DESIGN.md §8",
  ),
];

/**
 * The token overrides that implement DESIGN.md §8's reduced-motion rule:
 * "removes … every transition over 120ms". Note *over* — the 80ms and 120ms
 * steps survive, because a control that changes state with no transition at all
 * reads as a glitch rather than as calm. Computed here, where the millisecond
 * values still exist, so `css.ts` never has to re-derive a token name.
 */
export const REDUCED_MOTION_OVERRIDES: readonly { readonly name: string; readonly value: string }[] =
  Object.entries(DURATION)
    .filter(([, value]) => !survivesReducedMotion(value))
    .map(([name]) => ({ name: `--duration-${kebab(name)}`, value: ms(DURATION.instant) }));

/** Every token, in emission order. */
export const TOKENS: readonly Token[] = [
  ...surfaceTokens,
  ...statusTokens,
  ...environmentTokens,
  ...typeTokens,
  ...spaceTokens,
  ...layoutTokens,
  ...motionTokens,
];

export function isColorToken(token: Token): token is ColorToken {
  return token.kind === "color";
}

export function tokenNames(): readonly string[] {
  return TOKENS.map((token) => token.name);
}

export function findToken(name: string): Token | undefined {
  return TOKENS.find((token) => token.name === name);
}

/** The CSS value of a token in a given mode. Scalars are mode-invariant. */
export function tokenValue(token: Token, mode: Mode): string {
  return token.kind === "scalar" ? token.value : token.value[mode];
}

/**
 * The opaque colour a token resolves to in a mode, for contrast maths.
 * Translucent tokens have no opaque form on their own and return `undefined`;
 * flatten them over a surface first.
 */
export function opaqueValue(token: Token, mode: Mode): Hex | undefined {
  return token.kind === "color" && !token.translucent ? token.value[mode] : undefined;
}
