/**
 * Motion — DESIGN.md §5 and §8.
 *
 * The rule that governs everything here is §8:
 *
 *   > `prefers-reduced-motion` removes the tension line's travel, log
 *   > auto-scroll easing, and every transition over 120ms.
 *
 * So 120ms is not a taste preference, it is the threshold that decides whether
 * an animation survives reduced motion. Durations at or below
 * {@link REDUCED_MOTION_MAX} are kept; anything above it is dropped to zero.
 *
 * And §5: "No information is carried by motion alone." The tension line under
 * reduced motion stays solid in the status colour and keeps its lashings. The
 * animation is emphasis, never the signal.
 */

/**
 * Durations in milliseconds. DESIGN.md fixes only the 120ms threshold; the
 * travel and pulse periods are derived — slow enough to read as strain rather
 * than as a loading spinner, which is the distinction §5 is drawing. Recorded
 * as a derivation in the task report.
 */
export const DURATION = {
  /** No transition. State changes that must be believed instantly. */
  instant: 0,
  /** 80 — hover, focus, chip state. Survives reduced motion. */
  fast: 80,
  /** 120 — the threshold itself. Panels, disclosure. Survives reduced motion. */
  base: 120,
  /** 240 — the largest non-essential transition. Dropped under reduced motion. */
  slow: 240,
  /** 2400 — one pass of the tension line's travelling highlight. Dropped. */
  tensionTravel: 2400,
  /** 1600 — one cycle of the running step's pulse on the deploy spine. Dropped. */
  pulse: 1600,
} as const;

export type DurationName = keyof typeof DURATION;

/**
 * The §8 cut-off. Anything longer is removed, not merely shortened, under
 * `prefers-reduced-motion: reduce`.
 */
export const REDUCED_MOTION_MAX = 120;

/**
 * Standard easing. A decelerating curve: things arrive and settle rather than
 * bouncing, which is the wrong register for a tool people open when something
 * is broken. Derived; DESIGN.md does not specify easing.
 */
export const EASING = {
  standard: "cubic-bezier(0.2, 0, 0, 1)",
} as const;

export type EasingName = keyof typeof EASING;

/** True if this duration survives `prefers-reduced-motion: reduce` per §8. */
export function survivesReducedMotion(durationMs: number): boolean {
  return durationMs <= REDUCED_MOTION_MAX;
}

/** Render a duration token as a CSS time. */
export function ms(value: number): string {
  return `${String(value)}ms`;
}
