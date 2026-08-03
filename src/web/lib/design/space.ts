/**
 * Spacing, radii and the fixed dimensions of "the shroud" — DESIGN.md §4.
 *
 * The layout dimensions here are transcribed from DESIGN.md and are not
 * negotiable per-screen: §4's whole argument is that the structure "never
 * moves, so muscle memory survives a stressful night". A component that wants a
 * 220px rail is a component that has misunderstood the design.
 *
 * The spacing scale itself is NOT specified in DESIGN.md. It is derived here on
 * a 4px base unit, which is the unit every dimension DESIGN.md does state lands
 * on — 200, 44, 280, 32 — with a 2px step retained for the hairline-scale
 * details (§4's rules, §5's tension line). Recorded as a derivation in the task
 * report.
 */

/**
 * The spacing scale, in CSS pixels. Eight steps; if a ninth is needed, that is
 * a signal the layout is wrong rather than that the scale is short.
 */
export const SPACE = {
  /** 2 — optical nudges, glyph-to-label gaps. */
  xxs: 2,
  /** 4 — inside a chip, between a glyph and its label. */
  xs: 4,
  /** 8 — inside a control, between related rows. */
  sm: 8,
  /** 12 — table cell padding, list item padding. */
  md: 12,
  /** 16 — inside a card, between fields. */
  lg: 16,
  /** 24 — between cards, section padding. */
  xl: 24,
  /** 32 — between major regions. */
  xxl: 32,
  /** 48 — page-level breathing room, empty states. */
  xxxl: 48,
} as const;

export type SpaceName = keyof typeof SPACE;

/**
 * Corner radii. DESIGN.md does not specify these; derived, and kept small
 * deliberately — a heavily rounded incident tool reads as consumer software.
 * The pill exists because DESIGN.md §6 names one ("a `Resume tail` pill").
 */
export const RADIUS = {
  /** 2 — chips, inputs, small controls. */
  sm: 2,
  /** 4 — cards, panels, the pinned failure summary. */
  md: 4,
  /** Fully round ends. Pills only. */
  pill: 999,
} as const;

export type RadiusName = keyof typeof RADIUS;

/**
 * The fixed structure. Every value here is stated in DESIGN.md §4, §5 or §8
 * except where the comment says otherwise.
 */
export const LAYOUT = {
  /** §4: "Rail, 200px, always visible, never collapses into a hamburger." */
  railWidth: 200,
  /** §4: "Top bar, 44px". */
  topBarHeight: 44,
  /** §5: "A 2px rule directly beneath the top bar". */
  tensionLineHeight: 2,
  /** §4: the lashing marking the active rail item — "a 2px `--hemp` vertical bar". */
  lashingWidth: 2,
  /** §4: the facts column that never scrolls away. */
  factsWidth: 280,
  /** §4: "Tables: 32px rows". Row density is the point. */
  rowHeight: 32,
  /** Derived. §4 says "hairline rules" without a width; 1px is the thinnest that renders. */
  hairlineWidth: 1,
  /** Derived. §8 states the 2px offset but not the ring width; matched to the offset. */
  focusRingWidth: 2,
  /** §8: "a visible `--hemp` focus ring at 2px offset". */
  focusRingOffset: 2,
} as const;

export type LayoutName = keyof typeof LAYOUT;

/** Render a numeric token as a CSS length. */
export function px(value: number): string {
  return `${String(value)}px`;
}
