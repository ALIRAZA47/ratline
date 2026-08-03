/**
 * One rule about comments, for every test that scans source text (RL-M1-041).
 *
 * Several suites enforce a rule by reading the repository rather than by
 * running it — no raw database handle outside `src/repo/`, no colour literal
 * outside `palette.ts`, no refusal built outside `refusal.ts`, no type
 * assertion past the audit vocabulary, no `require()` naming an action the
 * catalogue does not declare. They are among the most valuable tests here,
 * because they are the only ones that survive somebody adding a new file.
 *
 * They disagreed about comments. One stripped them; four did not. Nobody chose
 * that — it accreted — and the cost was paid four times in one session, always
 * the same way: a comment written to explain WHY a pattern is avoided contains
 * the pattern, and the scanner flags the explanation.
 *
 * ## The rule, and the argument against it
 *
 * **Comments are stripped.** The case against is real and worth stating rather
 * than dismissing: a scanner that tries to tell comments from code is a second
 * parser to get wrong, and it would get it wrong in the direction of missing a
 * violation — a line of real code swallowed by a mis-parsed comment boundary is
 * a rule silently switched off.
 *
 * What decides it is that the other cost is not hypothetical. A rule that
 * forbids its own explanation pushes authors toward vaguer comments in exactly
 * the files that most need precise ones, and it does so invisibly: the author
 * rewrites the sentence and never learns why. Four times, in files whose whole
 * purpose is to be explicit about a hazard.
 *
 * So the parser risk is answered directly rather than accepted: `codeOf` is
 * tested against a fixture containing every construct that could fool it — a
 * URL with `//` in a string, a regex holding `/*`, an apostrophe inside a
 * comment, a template literal spanning lines. If it ever removes real code, the
 * fixture test fails rather than a rule going quiet.
 */

/**
 * Source with comments removed and everything else left exactly where it was.
 *
 * Newlines inside removed comments are PRESERVED, so a line number computed
 * from the result still points at the right line of the original. A scanner
 * that reported a match on line 40 of a file whose comments had been collapsed
 * would send somebody to the wrong place, which is worse than not reporting a
 * line at all.
 */
export function codeOf(source: string): string {
  let out = "";
  let index = 0;

  type Mode = "code" | "line-comment" | "block-comment" | "single" | "double" | "template";
  let mode: Mode = "code";

  while (index < source.length) {
    const two = source.slice(index, index + 2);
    const one = source[index] ?? "";

    if (mode === "code") {
      if (two === "//") { mode = "line-comment"; index += 2; continue; }
      if (two === "/*") { mode = "block-comment"; index += 2; continue; }
      if (one === "'") mode = "single";
      else if (one === '"') mode = "double";
      else if (one === "`") mode = "template";
      out += one;
      index += 1;
      continue;
    }

    if (mode === "line-comment") {
      // The newline itself is code again, and is kept.
      if (one === "\n") { mode = "code"; out += one; }
      index += 1;
      continue;
    }

    if (mode === "block-comment") {
      if (two === "*/") { mode = "code"; index += 2; continue; }
      // Line structure survives the removal.
      if (one === "\n") out += one;
      index += 1;
      continue;
    }

    // Inside a string. Nothing here is a comment, and an escape consumes the
    // next character whatever it is — `"\\"` ends the string, `"\""` does not.
    if (one === "\\") {
      out += source.slice(index, index + 2);
      index += 2;
      continue;
    }
    if (
      (mode === "single" && one === "'") ||
      (mode === "double" && one === '"') ||
      (mode === "template" && one === "`")
    ) {
      mode = "code";
    }
    out += one;
    index += 1;
  }

  return out;
}

/** Every match of `pattern` in the code of `source`, with a 1-based line number. */
export function scanCode(
  source: string,
  pattern: RegExp,
): { readonly text: string; readonly line: number }[] {
  const code = codeOf(source);
  const found: { text: string; line: number }[] = [];
  for (const match of code.matchAll(pattern)) {
    const at = match.index ?? 0;
    found.push({ text: match[0], line: code.slice(0, at).split("\n").length });
  }
  return found;
}
