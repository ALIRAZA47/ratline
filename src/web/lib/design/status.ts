/**
 * The status language — DESIGN.md §2, "used identically everywhere".
 *
 * The corollary in DESIGN.md §1 is what this module exists to make
 * unavoidable:
 *
 *   > Status is never colour alone. Every status carries a glyph as well,
 *   > because roughly one in twelve men has a red/green deficiency and
 *   > incidents are not the moment to find out.
 *
 * So a status is not a colour here. It is a record of glyph + label + colour
 * token, and the type system will not let one be added without all three. A
 * component that wants to show status asks for the whole record; there is no
 * API that hands back only the hue.
 */

import { STATUS_HUE } from "./palette.ts";

/**
 * Derived from the palette so the two cannot drift: adding a hue without a
 * glyph fails to compile, and a glyph without a hue is not a valid key.
 */
export type StatusId = keyof typeof STATUS_HUE;

export interface StatusToken {
  readonly id: StatusId;
  /** Never optional. This is the point of the module. */
  readonly glyph: string;
  /** The word an operator reads. Colour plus glyph plus text label, §8. */
  readonly label: string;
  /** What the status actually means, for tooltips and for reviewers. */
  readonly meaning: string;
  /** The CSS custom property carrying this status's colour. */
  readonly colorToken: `--st-${StatusId}`;
}

export const STATUS = {
  healthy: {
    id: "healthy",
    glyph: "●", // ● filled circle
    label: "Healthy",
    meaning: "Running, succeeded, valid",
    colorToken: "--st-healthy",
  },
  working: {
    id: "working",
    glyph: "◐", // ◐ half-filled circle
    label: "Working",
    meaning: "Deploying, provisioning, building",
    colorToken: "--st-working",
  },
  attention: {
    id: "attention",
    glyph: "▲", // ▲ filled triangle
    label: "Attention",
    meaning: "Degraded, expiring, needs action",
    colorToken: "--st-attention",
  },
  fail: {
    id: "fail",
    glyph: "✕", // ✕ multiplication x
    label: "Failed",
    meaning: "Failed, down, revoked",
    colorToken: "--st-fail",
  },
  idle: {
    id: "idle",
    glyph: "○", // ○ hollow circle
    label: "Idle",
    meaning: "Never deployed, disabled, unknown",
    colorToken: "--st-idle",
  },
} as const satisfies Record<StatusId, StatusToken>;

/**
 * Presentation order: most operationally urgent reading first is wrong here —
 * this is the order the legend and the status filters list them in, which
 * matches DESIGN.md §2's table so an operator who has read the docs finds them
 * where they expect.
 */
export const STATUS_ORDER = ["healthy", "working", "attention", "fail", "idle"] as const satisfies readonly StatusId[];

export function statusToken(id: StatusId): StatusToken {
  return STATUS[id];
}

/**
 * The accessible name for a status, for `aria-label` and for the text that must
 * accompany the glyph. Exported so no component invents its own wording.
 */
export function statusDescription(id: StatusId): string {
  const token = STATUS[id];
  return `${token.label} — ${token.meaning}`;
}
