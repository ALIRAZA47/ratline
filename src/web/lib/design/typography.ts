/**
 * Type — DESIGN.md §3.
 *
 * Three faces, all self-hosted. DESIGN.md §3 is explicit about why:
 *
 *   > Self-hosted, all of it. C5 means the dashboard must work on an air-gapped
 *   > VPN with no external origin reachable — a font CDN would break exactly
 *   > when someone needs the tool most.
 *
 * The actual `@font-face` rules and `.woff2` files come from the vendored
 * `@fontsource` packages; see `fonts.ts`, which is where that claim is made
 * concrete and where the test proves no rule points at a remote origin.
 */

/**
 * Family stacks.
 *
 * The fallbacks matter more than they look: the first paint on a cold cache,
 * and any environment where a `.woff2` fails to load, still has to be legible
 * at 2am. Each stack falls back to a face with comparable metrics rather than
 * to a generic that would reflow the whole table.
 *
 * `Archivo Variable` is the family name the variable `@fontsource` package
 * registers; the Expanded look is the `wdth` axis at {@link DISPLAY_STRETCH},
 * not a separate family.
 */
export const FONT_STACK = {
  /** Screen titles, status counts, section heads. §3: "reads as signage". */
  display: "'Archivo Variable', 'Archivo', 'Helvetica Neue', Arial, sans-serif",
  /** Everything else. Built for dense government forms, holds up at 13px. */
  body: "'Public Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  /** Logs, identifiers, terminal output. */
  mono: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
} as const;

export type FontRole = keyof typeof FONT_STACK;

/**
 * The Expanded width, as a `font-stretch` percentage.
 *
 * Archivo's `wdth` axis runs 62–125; 125 is its widest instance, which is what
 * DESIGN.md means by "Archivo Expanded". §3 calls the expansion "the
 * signature", so this is not a detail to lose in a substitution.
 */
export const DISPLAY_STRETCH = "125%";

/**
 * Weights, DESIGN.md §3. Two per face, no more — a third weight is a decision
 * nobody remembers making and it shows up as inconsistency under pressure.
 */
export const FONT_WEIGHT = {
  display: 600,
  displayStrong: 700,
  body: 400,
  bodyStrong: 500,
  mono: 400,
  monoStrong: 700,
} as const;

export interface TypeStep {
  /** Font size in CSS pixels. */
  readonly size: number;
  /** Line box in CSS pixels. */
  readonly leading: number;
}

/**
 * The scale, DESIGN.md §3: `11 / 12 / 13 / 15 / 18 / 24 / 32`, 13px base
 * "because density wins". Tables and logs sit at 12–13.
 *
 * Sizes are transcribed exactly. Line heights are NOT in DESIGN.md — only the
 * log's 12.5/18 is stated (§6) — so the rest are derived on a 4px vertical
 * rhythm, which is the same unit the layout dimensions in §4 land on (200 rail,
 * 44 top bar, 280 facts, 32 row). Recorded as a derivation in the task report.
 */
export const TYPE_SCALE = {
  /** 11 — dense labels, table column heads, timestamps. */
  xs: { size: 11, leading: 16 },
  /** 12 — table body, secondary text. */
  sm: { size: 12, leading: 16 },
  /** 13 — base. Body and UI. */
  base: { size: 13, leading: 20 },
  /** 15 — emphasis, card titles. */
  md: { size: 15, leading: 24 },
  /** 18 — section heads. */
  lg: { size: 18, leading: 24 },
  /** 24 — screen titles. */
  xl: { size: 24, leading: 32 },
  /** 32 — status counts, the number you read from across a room. */
  xxl: { size: 32, leading: 40 },
  /**
   * 12.5/18 — the log surface, stated outright in DESIGN.md §6. Deliberately
   * off the scale: the half-pixel is what fits the line count the virtualiser
   * needs without dropping to 12, and 18 is a fixed row height the virtualiser
   * can multiply.
   */
  log: { size: 12.5, leading: 18 },
} as const satisfies Record<string, TypeStep>;

export type TypeStepName = keyof typeof TYPE_SCALE;

/**
 * Ligatures are actively wrong in logs — DESIGN.md §3: "`!=` must look like two
 * characters". `font-variant-ligatures: none` covers the standard sets; the
 * explicit `liga`/`calt` pair covers the contextual alternates JetBrains Mono
 * uses for its arrow forms, which `none` alone does not always disable.
 */
export const MONO_LIGATURES_OFF = {
  "font-variant-ligatures": "none",
  "font-feature-settings": '"liga" 0, "calt" 0',
} as const;

/**
 * DESIGN.md §3: "Numerals are tabular everywhere a number can change." Applied
 * globally rather than per-component, because the failure mode — a counter
 * jittering as it ticks — is exactly the thing an operator is staring at.
 */
export const TABULAR_NUMERALS = "tabular-nums";
