/**
 * Self-hosted font assets — DESIGN.md §3 and §10, brief C5.
 *
 * This module is the whole of acceptance criterion 3: "fonts are self-hosted so
 * the interface works with no internet access". The `.woff2` files ship inside
 * the vendored `@fontsource` packages, every `@font-face` rule points at a
 * relative path within its own package, and nothing here resolves an external
 * origin. `test/toolchain/design_tokens.test.ts` reads the vendored CSS off
 * disk and fails the build if a remote URL, or a missing font file, ever
 * appears.
 *
 * Three packages, one face each, all OFL-1.1 — which is what DESIGN.md §10
 * means by "open-licensed and self-hostable".
 */

import type { FontRole } from "./typography.ts";

export interface FontAsset {
  /** npm package the `@font-face` rules and `.woff2` files come from. */
  readonly packageName: string;
  /** The family name those rules register, as written in the font stack. */
  readonly family: string;
  readonly role: FontRole;
  readonly license: string;
  /** One line, per brief §6.7's rule on dependencies. */
  readonly justification: string;
  /**
   * Module specifiers the application imports to install the `@font-face`
   * rules. Weight-scoped rather than the package's `index.css`, which would
   * pull all nine weights and their italics for a design that uses two.
   */
  readonly cssImports: readonly string[];
}

export const FONT_ASSETS = [
  {
    packageName: "@fontsource-variable/archivo",
    family: "Archivo Variable",
    role: "display",
    license: "OFL-1.1",
    justification:
      "Self-hosted Archivo with the wdth axis, the only packaged source of the Expanded width DESIGN.md §3 calls the signature.",
    // The two-axis file: `wght` 100-900 AND `wdth` 62-125. The `wght.css`
    // entry carries no width axis and would silently render at normal width,
    // which is precisely the substitution DESIGN.md §10 warns is expensive.
    cssImports: ["@fontsource-variable/archivo/wdth.css"],
  },
  {
    packageName: "@fontsource/public-sans",
    family: "Public Sans",
    role: "body",
    license: "OFL-1.1",
    justification:
      "Self-hosted Public Sans 400/500, the body face DESIGN.md §3 selects for holding up at 13px in a dense table.",
    cssImports: ["@fontsource/public-sans/400.css", "@fontsource/public-sans/500.css"],
  },
  {
    packageName: "@fontsource/jetbrains-mono",
    family: "JetBrains Mono",
    role: "mono",
    license: "OFL-1.1",
    justification:
      "Self-hosted JetBrains Mono 400/700 for log and terminal output, with the ligatures DESIGN.md §3 requires off.",
    // Not the `latin-*` subsets: DESIGN.md §3 chose this face partly for "wide
    // language coverage for terminal output", and `unicode-range` means the
    // browser still only fetches the subsets a given log actually needs.
    cssImports: ["@fontsource/jetbrains-mono/400.css", "@fontsource/jetbrains-mono/700.css"],
  },
] as const satisfies readonly FontAsset[];

/**
 * Every stylesheet the application must import for the interface to render with
 * its intended type. Order is irrelevant; completeness is not.
 */
export const FONT_CSS_IMPORTS: readonly string[] = FONT_ASSETS.flatMap((asset) => asset.cssImports);

/** The npm packages that carry the vendored `.woff2` files. */
export const FONT_PACKAGES: readonly string[] = FONT_ASSETS.map((asset) => asset.packageName);
