/**
 * Colour primitives for the design system (RL-M1-027).
 *
 * This module holds no colour values — only the arithmetic. It exists so that
 * the alpha recipes DESIGN.md §2 states ("hairlines are `--hemp` at 12%; hover
 * is `--chalk` at 4%") are computed from the five named palette values rather
 * than hand-mixed into a second set of hexes that can drift, and so the
 * contrast targets in DESIGN.md §8 are checkable by machine instead of by
 * assertion in a document.
 */

/** A six-digit sRGB hex colour, `#RRGGBB`. */
export type Hex = `#${string}`;

/** The two modes. Dark is the default; brief §6.6 requires both to work. */
export const MODES = ["dark", "light"] as const;

export type Mode = (typeof MODES)[number];

/** A value that differs between modes. */
export type Themed<T = Hex> = { readonly [M in Mode]: T };

export interface Rgb {
  readonly r: number;
  readonly g: number;
  readonly b: number;
}

const HEX_PATTERN = /^#([0-9a-fA-F]{6})$/;

/**
 * Parse `#RRGGBB` into 0–255 channels.
 *
 * Deliberately strict: three-digit and eight-digit forms are rejected rather
 * than guessed at, because a silently misparsed colour is a contrast bug that
 * no test would catch.
 */
export function parseHex(value: string): Rgb {
  const match = HEX_PATTERN.exec(value);
  const digits = match?.[1];
  if (digits === undefined) {
    throw new TypeError(`expected a six-digit hex colour, #RRGGBB, received ${JSON.stringify(value)}`);
  }
  return {
    r: Number.parseInt(digits.slice(0, 2), 16),
    g: Number.parseInt(digits.slice(2, 4), 16),
    b: Number.parseInt(digits.slice(4, 6), 16),
  };
}

function toHexDigits(channel: number): string {
  const clamped = Math.min(255, Math.max(0, Math.round(channel)));
  return clamped.toString(16).padStart(2, "0");
}

/** Render channels back to `#RRGGBB`, upper case to match DESIGN.md's table. */
export function toHex({ r, g, b }: Rgb): Hex {
  return `#${toHexDigits(r)}${toHexDigits(g)}${toHexDigits(b)}`.toUpperCase() as Hex;
}

/** WCAG 2.2 §relative luminance. The 0.03928 threshold is the one the spec states. */
export function relativeLuminance(value: string): number {
  const { r, g, b } = parseHex(value);
  const channel = (raw: number): number => {
    const s = raw / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/**
 * WCAG contrast ratio between two opaque colours, 1–21.
 *
 * Order-independent, so callers do not have to know which is the background.
 */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const lighter = Math.max(la, lb);
  const darker = Math.min(la, lb);
  return (lighter + 0.05) / (darker + 0.05);
}

function assertAlpha(alpha: number): void {
  if (!Number.isFinite(alpha) || alpha < 0 || alpha > 1) {
    throw new RangeError(`alpha must be between 0 and 1, received ${String(alpha)}`);
  }
}

/**
 * `rgb(r g b / a)` for a palette colour at partial opacity.
 *
 * Emitted as a literal rather than `color-mix()` or `rgb(from …)` so the value
 * is resolvable by any consumer, including a headless renderer in a test, and
 * so the composited result stays computable for contrast checks.
 */
export function withAlpha(value: string, alpha: number): string {
  assertAlpha(alpha);
  const { r, g, b } = parseHex(value);
  return `rgb(${String(r)} ${String(g)} ${String(b)} / ${String(alpha)})`;
}

/**
 * Flatten a translucent foreground over an opaque background.
 *
 * Needed because contrast is only defined for opaque colours: to check what a
 * hairline actually looks like against the canvas, it has to be composited
 * first.
 */
export function flatten(foreground: string, alpha: number, background: string): Hex {
  assertAlpha(alpha);
  const fg = parseHex(foreground);
  const bg = parseHex(background);
  return toHex({
    r: fg.r * alpha + bg.r * (1 - alpha),
    g: fg.g * alpha + bg.g * (1 - alpha),
    b: fg.b * alpha + bg.b * (1 - alpha),
  });
}
