/**
 * The guard behind "no hard-coded values in components" (RL-M1-027, AC1).
 *
 * `docs/PLAN.md` §7 puts the rule next to the directory itself — `lib/design/`
 * holds "tokens from DESIGN.md; no hard-coded colour anywhere else" — and a
 * rule stated in a plan is a rule until the first hurried Friday. This module
 * makes it mechanical: the test suite walks every source file under `src/web/`
 * and fails the build on a literal that should have been a token.
 *
 * It is a pure function over source text with no filesystem access, so the
 * detector itself is unit-testable against fixtures. That matters: a guard that
 * only ever runs over a clean tree proves nothing about whether it can detect
 * anything, so the test exercises both directions.
 *
 * CONTEXT, AND WHY IT IS NOT A NAIVE GREP
 *
 * A style declaration and a TypeScript type annotation look identical to a
 * regular expression — `background: string` in a function signature is not a
 * CSS rule, and a doc comment that mentions a colour is documentation, not a
 * component hard-coding one. So the source is projected into two views first:
 * code, and the text that could actually become style. Declaration rules run
 * only over the second. False negatives from a heuristic are recoverable in
 * review; false positives train people to disable the check.
 */

export type AuditRule =
  /** A colour that should have been `var(--tar)`. */
  | "hex-colour"
  /** The same, spelled as a colour function. */
  | "colour-function"
  /** A colour declaration whose value names no token. */
  | "literal-colour-declaration"
  /** Type set outside the scale — a family or a size written by hand. */
  | "literal-type-declaration";

export interface Finding {
  /** Repository-relative path, as given to {@link auditSource}. */
  readonly file: string;
  /** 1-based. */
  readonly line: number;
  readonly rule: AuditRule;
  readonly snippet: string;
}

/**
 * The two files allowed to write colour, and what each is allowed to write.
 *
 * `palette.ts` is where DESIGN.md §2 is transcribed. `color.ts` is where the
 * `rgb()` syntax is constructed from those values. Nothing else, anywhere,
 * gets to name a colour — including the rest of `lib/design/`.
 */
export const AUDIT_EXEMPTIONS: readonly { readonly path: string; readonly rules: readonly AuditRule[] }[] = [
  { path: "src/web/lib/design/palette.ts", rules: ["hex-colour"] },
  { path: "src/web/lib/design/color.ts", rules: ["colour-function"] },
];

/** Valid CSS hex lengths only, so `#app` and `#L42` are not false positives. */
const HEX_LITERAL = /#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})\b/;

const COLOUR_FUNCTION = /\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color-mix)\s*\(/;

/**
 * A colour declaration whose value contains no `var(`.
 *
 * The property must be followed immediately by its colon, which is what keeps
 * `color-scheme: dark` and `background-image: url(…)` out of the net.
 */
const COLOUR_DECLARATION =
  /(?:^|[;{\s])(?:background-color|border-color|outline-color|background|color|fill|stroke)\s*:\s*([^;{}]+)/;

/**
 * Type declarations that must come from the scale. Restricted to family and
 * size deliberately: a unitless `line-height: 1` on a glyph is a legitimate
 * optical fix, not a type-scale violation.
 */
const TYPE_DECLARATION = /(?:^|[;{\s])(?:font-family|font-size)\s*:\s*([^;{}]+)/;

/** Files where the whole document is style, rather than code containing style. */
const MARKUP_EXTENSIONS = [".css", ".svelte", ".html", ".htm"];

const SCRIPT_BLOCK = /<script\b[^>]*>[\s\S]*?<\/script>/gi;

interface Projection {
  /** Everything outside comments. Scanned for colour literals. */
  readonly code: readonly string[];
  /** Only what could reach a stylesheet. Scanned for declarations. */
  readonly style: readonly string[];
}

/** Replace a span with spaces so every later line number stays where it was. */
function blank(text: string): string {
  return text.replace(/[^\n]/g, " ");
}

/**
 * Split a TypeScript or JavaScript source into code and string-literal text.
 *
 * A deliberately small scanner: line and block comments are dropped entirely,
 * and the contents of `'`, `"` and backtick literals become the style
 * projection, because a `.ts` file can only emit CSS by way of a string. It
 * does not attempt to distinguish a regular expression literal from division,
 * which is the one place it can be fooled; the consequence is a missed finding,
 * never a false one.
 */
function scanScript(source: string): Projection {
  const lineCount = source.split("\n").length;
  const code: string[] = new Array<string>(lineCount).fill("");
  const style: string[] = new Array<string>(lineCount).fill("");

  let line = 0;
  let index = 0;
  let state: "code" | "line-comment" | "block-comment" | "string" = "code";
  let quote = "";

  const emit = (target: string[], char: string): void => {
    const existing = target[line] ?? "";
    target[line] = existing + char;
  };

  while (index < source.length) {
    const char = source[index] ?? "";
    const next = source[index + 1] ?? "";

    if (char === "\n") {
      if (state === "line-comment") state = "code";
      line += 1;
      index += 1;
      continue;
    }

    if (state === "line-comment") {
      index += 1;
      continue;
    }

    if (state === "block-comment") {
      if (char === "*" && next === "/") {
        state = "code";
        index += 2;
        continue;
      }
      index += 1;
      continue;
    }

    if (state === "string") {
      if (char === "\\") {
        index += 2;
        continue;
      }
      if (char === quote) {
        state = "code";
        index += 1;
        continue;
      }
      emit(style, char);
      index += 1;
      continue;
    }

    if (char === "/" && next === "/") {
      state = "line-comment";
      index += 2;
      continue;
    }
    if (char === "/" && next === "*") {
      state = "block-comment";
      index += 2;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      state = "string";
      quote = char;
      index += 1;
      continue;
    }

    emit(code, char);
    index += 1;
  }

  return { code, style };
}

/**
 * Project a markup or stylesheet source.
 *
 * `/* … *\/` and `<!-- … -->` are removed. `<script>` bodies stay in the code
 * projection — they are scanned for colour literals — but leave the style
 * projection, so a component's prop types are not mistaken for CSS.
 */
function scanMarkup(source: string): Projection {
  const withoutComments = source
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/<!--[\s\S]*?-->/g, blank);
  const code = withoutComments.split("\n");
  const style = withoutComments.replace(SCRIPT_BLOCK, blank).split("\n");
  return { code, style };
}

function exemptRules(file: string): readonly AuditRule[] {
  const normalised = file.replaceAll("\\", "/");
  for (const exemption of AUDIT_EXEMPTIONS) {
    if (normalised === exemption.path || normalised.endsWith(`/${exemption.path}`)) {
      return exemption.rules;
    }
  }
  return [];
}

function isMarkup(file: string): boolean {
  const normalised = file.toLowerCase();
  return MARKUP_EXTENSIONS.some((extension) => normalised.endsWith(extension));
}

/**
 * Report every hard-coded design value in one source file.
 *
 * Applies to `.ts`, `.css`, `.svelte`, `.html` — anything under `src/web/`
 * that can carry a style. The caller decides which files to feed it.
 */
export function auditSource(file: string, source: string): readonly Finding[] {
  const exempt = new Set(exemptRules(file));
  const { code, style } = isMarkup(file) ? scanMarkup(source) : scanScript(source);
  const findings: Finding[] = [];
  const lineCount = Math.max(code.length, style.length);

  for (let index = 0; index < lineCount; index++) {
    const codeText = code[index] ?? "";
    const styleText = style[index] ?? "";
    const anyText = `${codeText} ${styleText}`;

    const record = (rule: AuditRule, snippet: string): void => {
      if (exempt.has(rule)) return;
      findings.push({ file, line: index + 1, rule, snippet: snippet.trim() });
    };

    const hex = HEX_LITERAL.exec(anyText);
    if (hex !== null) record("hex-colour", hex[0]);

    if (COLOUR_FUNCTION.test(anyText)) record("colour-function", anyText);

    const colourValue = COLOUR_DECLARATION.exec(styleText)?.[1];
    if (colourValue !== undefined && !colourValue.includes("var(")) {
      record("literal-colour-declaration", styleText);
    }

    const typeValue = TYPE_DECLARATION.exec(styleText)?.[1];
    if (typeValue !== undefined && !typeValue.includes("var(")) {
      record("literal-type-declaration", styleText);
    }
  }

  return findings;
}

/** One line per finding, for an assertion message someone can act on. */
export function formatFindings(findings: readonly Finding[]): string {
  return findings.map((f) => `${f.file}:${String(f.line)} [${f.rule}] ${f.snippet}`).join("\n");
}
