/**
 * Boot preflight (RL-M1-022).
 *
 * Every check that must pass before Ratline serves a request lives here, and
 * the process exits non-zero with an operator-facing message if any fails.
 * Nothing downstream is allowed to "handle" a missing secret by carrying on.
 *
 * Run directly to check a host without starting anything:
 *
 *     ./scripts/preflight
 *
 * The API server (later) imports {@link preflight} and calls it before it
 * binds. RL-M1-023 adds the C5 bind-address and public-reachability checks to
 * this same function.
 */

import { loadSecrets, SecretRefusal, secretsDir, type LoadOptions, type Secrets } from "./crypto/secrets.ts";

export type PreflightOptions = LoadOptions & {
  readonly dir?: string;
};

/**
 * Returns the loaded secrets, or throws {@link SecretRefusal}.
 *
 * Deliberately has no "skip checks" option. A flag to bypass preflight is a
 * flag someone sets in production at 2am.
 */
export function preflight(options: PreflightOptions = {}): Secrets {
  const dir = options.dir ?? secretsDir();
  return loadSecrets(dir, options);
}

/** Entry point. Exits 0 when the host is ready to serve, 1 otherwise. */
function main(): void {
  try {
    const dir = secretsDir();
    preflight({ dir });
    process.stderr.write(`preflight ok — secrets loaded from ${dir}\n`);
  } catch (error) {
    if (error instanceof SecretRefusal) {
      // Refusal text names files and reasons, never values.
      process.stderr.write(`${error.report()}\n`);
      process.exit(1);
    }
    throw error;
  }
}

// Only run when executed directly, so importing this module for `preflight`
// does not exit the importer.
if (process.argv[1] !== undefined && import.meta.filename === process.argv[1]) {
  main();
}
