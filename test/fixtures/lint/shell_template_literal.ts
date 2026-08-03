/**
 * FIXTURE — this file MUST fail lint. RL-M1-008, acceptance 4.
 *
 * C2: no shell command is ever constructed by string interpolation. Four
 * violations, one per shape `ratline/no-shell-template-literal` detects:
 *
 *   1. `restart`       — interpolatedArgument: an interpolated template handed
 *                        straight to a call named like a process launcher.
 *   2. `build`         — commandVariable: an interpolated template landing in a
 *                        binding whose name reads as a command.
 *   3. `remoteListing` — shellInvocation: the literal text is a shell/ssh
 *                        invocation. Nothing executes it here; C2 says
 *                        "anywhere", and this is the anywhere.
 *   4. `inspect`       — interpolatedArgument again, through a tagged template,
 *                        which is how a shell string is written in JavaScript
 *                        today and would otherwise sail past.
 *
 * `execSync` and `$` are defined locally on purpose. Importing the real ones
 * would also trip the process-spawning ban and this fixture would then be
 * proving two rules at once, so a failure would not say which one broke.
 *
 * Excluded from `npm run lint` by the top-level `ignores`; linted deliberately
 * by test/security/lint_rules.test.ts.
 */

/** Stand-in for child_process.execSync — matched by NAME, which is the point. */
function execSync(command: string): string {
  return command;
}

/** Stand-in for a zx/execa-style shell tag. */
function $(strings: TemplateStringsArray, ...values: string[]): string {
  return strings.raw.join("|") + values.join(",");
}

export function restart(unit: string): string {
  return execSync(`systemctl restart ${unit}`);
}

export function build(siteRoot: string): string {
  const command = `npm ci && npm run build --prefix ${siteRoot}`;
  return command;
}

export function remoteListing(host: string, remotePath: string): string {
  const line = `ssh ${host} ls ${remotePath}`;
  return line;
}

export function inspect(target: string): string {
  return $`ls -la ${target}`;
}
