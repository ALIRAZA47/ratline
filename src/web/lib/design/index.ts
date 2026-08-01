/**
 * Ratline design tokens — RL-M1-027, implementing `docs/DESIGN.md`.
 *
 * THE RULE THIS DIRECTORY EXISTS TO ENFORCE
 *
 *   Every colour, type size, space and duration in the interface comes from
 *   here. Nothing outside `src/web/lib/design/` writes a colour, a font family
 *   or a font size as a literal. `test/toolchain/design_tokens.test.ts` fails
 *   the build if it does.
 *
 * And the organising rule those tokens encode, DESIGN.md §1:
 *
 *   > Colour means status. Nothing else is allowed to be saturated.
 *
 * There is no brand accent colour. A saturated hue on screen means something
 * operational is true. Its corollary is enforced by the shape of the API:
 * `status.ts` will not hand back a hue without the glyph and label that must
 * accompany it, because status is never colour alone.
 *
 * HOW IT FITS TOGETHER
 *
 *   palette.ts     the only file containing a colour literal
 *   color.ts       colour arithmetic — alpha, luminance, contrast
 *   status.ts      glyph + label + colour, indivisible
 *   typography.ts  three faces, the 13px-base scale
 *   space.ts       spacing, radii, the fixed dimensions of the shroud
 *   motion.ts      durations and the 120ms reduced-motion threshold
 *   fonts.ts       the vendored @fontsource assets — no network at runtime
 *   tokens.ts      one registry, assembled from all of the above
 *   css.ts         the registry emitted as custom properties
 *   audit.ts       the guard that keeps literals out of components
 *
 * Consumers import from this file. `tokens.ts` and `css.ts` are the seam a
 * component should not need to cross.
 */

export type { Hex, Mode, Rgb, Themed } from "./color.ts";
export { MODES, contrastRatio, flatten, parseHex, relativeLuminance, toHex, withAlpha } from "./color.ts";

export type { SurfaceName } from "./palette.ts";
export { ALPHA, STATUS_FILL, STATUS_HUE, SURFACE } from "./palette.ts";

export type { StatusId, StatusToken } from "./status.ts";
export { STATUS, STATUS_ORDER, statusDescription, statusToken } from "./status.ts";

export type { FontRole, TypeStep, TypeStepName } from "./typography.ts";
export {
  DISPLAY_STRETCH,
  FONT_STACK,
  FONT_WEIGHT,
  MONO_LIGATURES_OFF,
  TABULAR_NUMERALS,
  TYPE_SCALE,
} from "./typography.ts";

export type { LayoutName, RadiusName, SpaceName } from "./space.ts";
export { LAYOUT, RADIUS, SPACE, px } from "./space.ts";

export type { DurationName, EasingName } from "./motion.ts";
export { DURATION, EASING, REDUCED_MOTION_MAX, ms, survivesReducedMotion } from "./motion.ts";

export type { FontAsset } from "./fonts.ts";
export { FONT_ASSETS, FONT_CSS_IMPORTS, FONT_PACKAGES } from "./fonts.ts";

export type { ColorToken, ContrastRule, OpaqueColorToken, ScalarToken, Token, TokenGroup, TranslucentColorToken } from "./tokens.ts";
export {
  CONTRAST_TARGET,
  REDUCED_MOTION_OVERRIDES,
  TOKENS,
  findToken,
  isColorToken,
  opaqueValue,
  tokenNames,
  tokenValue,
} from "./tokens.ts";

export {
  EMITTED_MODES,
  renderBaseCss,
  renderDesignStylesheet,
  renderReducedMotionCss,
  renderStatusCss,
  renderTokensCss,
} from "./css.ts";

export type { AuditRule, Finding } from "./audit.ts";
export { AUDIT_EXEMPTIONS, auditSource, formatFindings } from "./audit.ts";
