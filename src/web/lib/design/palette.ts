/**
 * The palette — transcribed from DESIGN.md §2 (RL-M1-027).
 *
 * THIS IS THE ONLY FILE IN THE REPOSITORY ALLOWED TO CONTAIN A COLOUR LITERAL.
 * `test/toolchain/design_tokens.test.ts` fails the build if a hex value, an
 * `rgb()`/`hsl()` call, or a bare colour keyword appears anywhere else under
 * `src/web/`. Everything downstream — tokens, CSS custom properties,
 * components — refers to these by name.
 *
 * The organising rule from DESIGN.md §1 governs every addition here:
 *
 *   > Colour means status. Nothing else is allowed to be saturated.
 *
 * There is no brand accent. If a new saturated value is proposed and it does
 * not carry operational meaning, the answer is no.
 */

import type { Hex, Themed } from "./color.ts";

/**
 * The five named surface and text values. Warm near-black rather than the
 * blue-grey slate every admin panel ships with (DESIGN.md §2).
 *
 * Everything else in the interface is one of these at an opacity, or a status
 * colour. `chalkDim` is `--chalk-dim` in CSS.
 */
export const SURFACE = {
  /** Page canvas. */
  tar: { dark: "#14110F", light: "#FBF8F4" },
  /** Cards, rails, raised surfaces. */
  pitch: { dark: "#1E1A17", light: "#FFFFFF" },
  /** Rope linework, active markers, focus rings. Non-text by definition. */
  hemp: { dark: "#D8B98A", light: "#8A6F45" },
  /** Primary text. */
  chalk: { dark: "#EDE7DF", light: "#1A1613" },
  /** Secondary text, labels. */
  chalkDim: { dark: "#9A918A", light: "#5E564F" },
} as const satisfies Record<string, Themed<Hex>>;

export type SurfaceName = keyof typeof SURFACE;

/**
 * The status hues, DESIGN.md §2. Keyed by status id; `status.ts` pairs each one
 * with its glyph and label, and the type system requires that pairing to be
 * total — a hue added here without a glyph will not compile.
 *
 * `fail` is deliberately the lighter red so body-size text clears 4.5:1 on the
 * canvas; the darker mark red lives in {@link STATUS_FILL}.
 */
export const STATUS_HUE = {
  /** Running, succeeded, valid. */
  healthy: { dark: "#4FB477", light: "#1F7A46" },
  /** Deploying, provisioning, building. */
  working: { dark: "#59A5D8", light: "#1D6FA5" },
  /** Degraded, expiring, needs action. */
  attention: { dark: "#E0A33E", light: "#8A5A00" },
  /** Failed, down, revoked. */
  fail: { dark: "#FF6369", light: "#C0272D" },
  /**
   * Never deployed, disabled, unknown.
   *
   * The only status hue that does NOT reach 4.5:1 — it sits at 4.03:1 on the
   * dark canvas and 3.53:1 on the light one, which DESIGN.md §8 permits for
   * marks but not for body text. Use it for the `○` glyph; set the label
   * beside it in `--chalk-dim`. The token table records this as a mark role and
   * the test enforces the 3:1 floor rather than pretending it clears 4.5:1.
   */
  idle: { dark: "#7A736C", light: "#8A837C" },
} as const satisfies Record<string, Themed<Hex>>;

/**
 * The darker red DESIGN.md §2 reserves for "large marks and fills where
 * contrast is not the constraint" — the break-glass banner, a failed knot on
 * the deploy spine.
 *
 * DESIGN.md gives a single value with no light-mode counterpart, so the same
 * value is used in both modes. It clears the 3:1 mark floor on all four
 * surfaces (4.80 / 4.42 dark, 3.70 / 3.91 light), which is the bar that applies
 * to it. Recorded as an open question in the task report.
 */
export const STATUS_FILL = {
  failMark: { dark: "#E5484D", light: "#E5484D" },
} as const satisfies Record<string, Themed<Hex>>;

/**
 * Alpha recipes, DESIGN.md §2 and §5.
 *
 * "Hairlines are `--hemp` at 12%; hover is `--chalk` at 4%." Held as numbers
 * so the composited colour stays computable, rather than as a second set of
 * pre-mixed hexes that would silently stop tracking the palette.
 */
export const ALPHA = {
  /** Hairline rules, and the tension line at rest. */
  hairline: 0.12,
  /** Row and control hover. */
  hover: 0.04,
} as const;
