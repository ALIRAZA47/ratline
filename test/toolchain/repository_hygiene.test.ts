/**
 * Source files must actually be in the repository (RL-M1-048).
 *
 * ## The defect this exists because of
 *
 * `.gitignore` contained `build/`. Git matches an unanchored pattern at every
 * depth, so it excluded `agent/internal/build/` — the Go package that reports the
 * agent's version and commit. Nothing complained: `git add -A` skips ignored
 * paths silently, the local `go build` kept working because the files were on
 * disk, `go test ./...` passed, and the commit went out with a package missing.
 * The first CI run on a clean checkout failed with "no required module provides
 * package .../internal/build".
 *
 * Every layer that could have caught it was looking at the working tree. Only a
 * fresh clone can see the difference between "the file exists" and "the file is
 * in the repository", and that is what this test reconstructs — cheaply, by
 * asking git what it is ignoring rather than by cloning.
 *
 * ## Why it is not narrower
 *
 * The obvious fix was to anchor that one pattern, and that is done. But `build`
 * is an ordinary name for a source directory and so are `dist`, `bin`, `lib` and
 * `target`, and the next unanchored pattern would fail the same way — after a
 * commit, on somebody else's machine, with an error naming a missing package
 * rather than a gitignore rule.
 *
 * ## What it does not catch, stated rather than implied
 *
 * Only files that are NOT yet tracked. Git ignores nothing that is already in the
 * index, so a rule added today which would have excluded a file committed last
 * week has no effect and this test sees nothing — correctly, because there is
 * nothing wrong. The window it covers is the one the defect happened in: source
 * that is new, on disk, and silently never added.
 *
 * Verified by mutation. Adding an unanchored `probe/` to .gitignore alongside an
 * untracked `src/probe/thing.ts` makes the first test fail and name `src/probe/`;
 * removing the pattern makes it pass again.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { relative, resolve } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Directories that hold source, as opposed to output or dependencies. */
const SOURCE_TREES = ["src", "test", "agent", "scripts", "tools", "docs"];

/** Extensions that are source rather than an artefact. */
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".go", ".sql", ".md", ".yaml", ".yml", ".css", ".mod"];

function git(...args: string[]): string {
  return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
}

test("no source file is excluded from the repository by a gitignore rule", () => {
  // `--others --ignored` lists untracked files, restricted to the ignored ones.
  // --exclude-standard so the answer is what git would really do rather than
  // what the .gitignore file alone says.
  const ignored = git("ls-files", "--others", "--ignored", "--exclude-standard", "--directory")
    .split("\n")
    .filter((line) => line.length > 0);

  const offenders: string[] = [];

  for (const path of ignored) {
    const [top] = path.split("/");
    if (top === undefined || !SOURCE_TREES.includes(top)) continue;

    // A `dist/` inside a source tree is genuine build output — agent/dist is
    // where scripts/agent puts the binaries — so it is exempt by name rather
    // than by guesswork about what the directory contains.
    if (path.split("/").includes("dist")) continue;
    if (path.includes("node_modules")) continue;

    // A directory entry (git collapses fully-ignored directories with a trailing
    // slash) is reported whatever it holds, because an ignored source directory
    // is exactly the case that went wrong and its contents are invisible here.
    if (path.endsWith("/")) {
      offenders.push(path);
      continue;
    }

    if (SOURCE_EXTENSIONS.some((extension) => path.endsWith(extension))) offenders.push(path);
  }

  assert.deepEqual(
    offenders,
    [],
    `these source paths are ignored by git, so they are not in the repository:\n` +
      offenders.map((p) => `  ${p}`).join("\n") +
      `\n\nRun \`git check-ignore -v <path>\` to find the rule. It is most likely an ` +
      `unanchored pattern — \`build/\` matches at every depth, \`/build/\` matches only at ` +
      `the root. A local build will keep working off the untracked files, so this will not ` +
      `show up again until somebody clones.`,
  );
});

test("every Go package the agent imports is tracked", () => {
  // Belt and braces on the test above, from the other direction: rather than
  // asking what is ignored, ask whether the thing that broke is present. This
  // one would have failed on the bad commit even if the gitignore rule had been
  // written some way the scan above did not anticipate.
  const tracked = new Set(
    git("ls-files", "agent")
      .split("\n")
      .filter((line) => line.endsWith(".go")),
  );

  const imported = new Set<string>();
  for (const file of tracked) {
    const source = git("show", `:${file}`);
    for (const match of source.matchAll(/"github\.com\/ALIRAZA47\/ratline\/agent\/([^"]+)"/g)) {
      const dir = match[1];
      if (dir !== undefined) imported.add(dir);
    }
  }

  const missing = [...imported].filter(
    (dir) => ![...tracked].some((file) => file.startsWith(`agent/${dir}/`)),
  );

  assert.deepEqual(
    missing,
    [],
    `the agent imports these packages but no tracked .go file lives in them:\n` +
      missing.map((d) => `  agent/${d}`).join("\n") +
      `\n\nThe files may exist on this machine and still be missing from the repository. ` +
      `Check \`git check-ignore -v agent/${missing[0] ?? "…"}\`.`,
  );

  // The scan is only meaningful if it found imports at all. An empty set would
  // pass vacuously, which is how this kind of test rots after a refactor.
  assert.ok(
    imported.size > 0,
    "no internal agent imports were found, so this test verified nothing. " +
      "Either the import path changed or agent/**/*.go is no longer tracked.",
  );

  // `relative` keeps the paths readable if this ever runs from elsewhere.
  assert.ok(tracked.size > 0, `no tracked Go files under ${relative(ROOT, "agent")}`);
});
