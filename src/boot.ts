/**
 * Boot preflight (RL-M1-022, RL-M1-023).
 *
 * Every check that must pass before Ratline serves a request lives here, and
 * the process exits non-zero with an operator-facing message if any fails.
 * Nothing downstream is allowed to "handle" a missing secret or an unintended
 * public bind by carrying on.
 *
 * Run directly to check a host without starting anything:
 *
 *     ./scripts/preflight
 *
 * The API server (later) imports {@link preflight} and calls it before it
 * binds, then renders {@link Preflight.exposure} as the non-dismissable banner
 * C5 requires.
 */

import {
  loadSecrets,
  SecretRefusal,
  secretsDir,
  type LoadOptions,
  type Secrets,
} from "./crypto/secrets.ts";
import {
  assessExposure,
  bindRefusal,
  globalInterfaces,
  publicBindAcknowledged,
  resolveBindAddress,
  resolvePort,
  type Exposure,
  type Interface,
} from "./config/network.ts";

export type PreflightOptions = LoadOptions & {
  readonly dir?: string;
  readonly env?: NodeJS.ProcessEnv;
  /** Injectable so exposure logic is testable without a particular host. */
  readonly interfaces?: readonly Interface[];
};

export type Preflight = {
  readonly secrets: Secrets;
  readonly bind: string;
  readonly port: number;
  readonly exposure: Exposure;
};

/** Thrown when the configured bind must not be used. */
export class BindRefusal extends Error {
  readonly reason: string;
  readonly remedy: string;

  constructor(reason: string, remedy: string) {
    super("Ratline refuses to start: the dashboard would be publicly reachable.");
    this.name = "BindRefusal";
    this.reason = reason;
    this.remedy = remedy;
  }

  report(): string {
    return [
      "Ratline refuses to start.",
      "",
      this.reason,
      "",
      this.remedy,
      "",
    ].join("\n");
  }
}

/**
 * Returns everything the server needs, or throws.
 *
 * Deliberately has no "skip checks" option. A flag to bypass preflight is a
 * flag someone sets in production at 2am.
 */
export function preflight(options: PreflightOptions = {}): Preflight {
  const env = options.env ?? process.env;
  const dir = options.dir ?? secretsDir(env);

  // Secrets first: a host with no usable secrets cannot serve at any address,
  // so reporting the bind problem too would be noise.
  const secrets = loadSecrets(dir, options);

  const bind = resolveBindAddress(env);
  const port = resolvePort(env);
  const exposure = assessExposure(bind, options.interfaces ?? globalInterfaces());

  const refusal = bindRefusal(exposure, publicBindAcknowledged(env));
  if (refusal !== null) throw new BindRefusal(refusal.reason, refusal.remedy);

  return { secrets, bind, port, exposure };
}

/** Entry point. Exits 0 when the host is ready to serve, 1 otherwise. */
function main(): void {
  try {
    const result = preflight();
    const { exposure } = result;

    process.stderr.write(`preflight ok — secrets loaded from ${secretsDir()}\n`);
    process.stderr.write(`listening address ${result.bind}:${result.port} (${exposure.level})\n`);

    if (exposure.warning !== null) {
      // Acknowledged exposure is still reported on every boot. C5 calls for a
      // warning that cannot be dismissed, and a one-time acknowledgement that
      // silenced it forever would be a dismissal with extra steps.
      const acknowledged = publicBindAcknowledged();
      process.stderr.write(
        `\n!! ${exposure.warning}\n\n${exposure.caveat}\n\n` +
          (acknowledged
            ? "Acknowledged via RATLINE_ALLOW_PUBLIC_BIND. This warning stays visible in the dashboard.\n"
            : "This warning stays visible in the dashboard.\n"),
      );
    }
  } catch (error) {
    // Refusal text names files, addresses and remedies — never a secret value.
    if (error instanceof SecretRefusal || error instanceof BindRefusal) {
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
