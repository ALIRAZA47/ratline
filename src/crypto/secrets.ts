/**
 * The secret store (C4, RL-M1-022).
 *
 * C4: "No default signing key, cookie secret, encryption key or admin
 * password. First run generates them and the application refuses to boot
 * without them."
 *
 * Three properties, in order of importance:
 *
 *   1. Nothing here has a default. Every secret is either generated from the
 *      system CSPRNG on first run, or the process refuses to start.
 *   2. A secret that exists but is weak, truncated, or readable by other users
 *      on the host is treated as absent-and-worse: the process refuses to
 *      start rather than quietly using it.
 *   3. Values never reach a log, an error message, or a JSON serialisation.
 *      Refusal messages name the *file* and the *reason*, never the content.
 *
 * There is deliberately no admin password here. The first owner is created by
 * the interactive bootstrap (RL-M1-030); generating a default administrator
 * credential is precisely the CloudPanel failure C4 exists to prevent.
 */

import {
  createPrivateKey,
  generateKeyPairSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { weakSecretReason } from "./weak-secrets.ts";

export type SecretName = "cookie" | "kek" | "instruction-signing";

type SecretSpec = {
  readonly name: SecretName;
  readonly file: string;
  readonly kind: "random" | "ed25519";
  readonly minBytes: number;
  readonly purpose: string;
};

/**
 * Every secret the control plane holds. Adding one here is all that is needed:
 * it is generated on first run, validated on every run, and covered by the
 * security test automatically.
 */
export const SECRET_SPECS: readonly SecretSpec[] = [
  {
    name: "cookie",
    file: "cookie.key",
    kind: "random",
    minBytes: 32,
    purpose: "signs session cookies",
  },
  {
    name: "kek",
    file: "kek.key",
    kind: "random",
    minBytes: 32,
    purpose: "wraps per-secret data keys (ADR 0006)",
  },
  {
    name: "instruction-signing",
    file: "instruction-signing.pem",
    kind: "ed25519",
    minBytes: 0,
    purpose: "signs agent instruction envelopes (ADR 0002)",
  },
];

/** Directory mode 0700, file mode 0600. Anything looser is a refusal. */
const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const GROUP_AND_OTHER = 0o077;

export type SecretProblem = {
  readonly file: string;
  readonly purpose: string;
  readonly reason: string;
  readonly remedy: string;
};

/**
 * Thrown instead of starting. Carries every problem found, not just the first,
 * so an operator fixes them in one pass rather than one restart at a time.
 */
export class SecretRefusal extends Error {
  readonly problems: readonly SecretProblem[];

  constructor(problems: readonly SecretProblem[]) {
    super(`Ratline refuses to start: ${problems.length} secret problem(s).`);
    this.name = "SecretRefusal";
    this.problems = problems;
  }

  /** Operator-facing text. Never contains a secret value. */
  report(): string {
    const lines = [
      `Ratline refuses to start. ${this.problems.length} secret problem(s):`,
      "",
    ];
    for (const p of this.problems) {
      lines.push(`  ${p.file}  (${p.purpose})`);
      lines.push(`    problem: ${p.reason}`);
      lines.push(`    fix:     ${p.remedy}`);
      lines.push("");
    }
    lines.push("No secret has a default value, by design. See docs/decisions/0006.");
    return lines.join("\n");
  }
}

/**
 * Loaded secrets. `toJSON` is overridden so an accidental `JSON.stringify` of a
 * config object — in a log line, an error report, a metrics payload — cannot
 * spill key material.
 */
export type Secrets = {
  readonly cookie: Buffer;
  readonly kek: Buffer;
  readonly instructionSigning: KeyObject;
  toJSON(): string;
};

export type LoadOptions = {
  /**
   * When false, missing secrets are a refusal rather than being generated.
   * Set this in any context where silently minting new keys would be wrong —
   * a container whose volume failed to mount would otherwise generate fresh
   * secrets on every restart and invalidate every session.
   */
  readonly generateIfMissing?: boolean;
  /** Where to report what was generated. Defaults to stderr. */
  readonly onGenerate?: (message: string) => void;
};

/** Resolve the secrets directory. Never has a default *value*, only a default *location*. */
export function secretsDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env["RATLINE_SECRETS_DIR"];
  if (configured !== undefined && configured !== "") return configured;
  return env["NODE_ENV"] === "production" ? "/etc/ratline/secrets" : ".ratline/secrets";
}

function modeOf(path: string): number {
  return statSync(path).mode & 0o777;
}

function ensureDir(dir: string, problems: SecretProblem[]): boolean {
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: DIR_MODE });
    chmodSync(dir, DIR_MODE);
    return true;
  }
  const mode = modeOf(dir);
  if ((mode & GROUP_AND_OTHER) !== 0) {
    problems.push({
      file: dir,
      purpose: "secrets directory",
      reason: `mode is ${mode.toString(8).padStart(4, "0")}; it is readable or writable by other users on this host`,
      remedy: `chmod 700 ${dir}`,
    });
    return false;
  }
  return true;
}

function generate(spec: SecretSpec): string {
  if (spec.kind === "ed25519") {
    const { privateKey } = generateKeyPairSync("ed25519");
    return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  }
  // 32 bytes from the system CSPRNG. Not a seeded PRNG, not a timestamp.
  return `${randomBytes(Math.max(spec.minBytes, 32)).toString("base64")}\n`;
}

function decodeRandom(raw: string): Buffer {
  return Buffer.from(raw.trim(), "base64");
}

/**
 * Load every secret, generating any that are missing on first run.
 *
 * Throws {@link SecretRefusal} — it never returns partially-valid secrets, and
 * it never falls back to a default.
 */
export function loadSecrets(dir: string = secretsDir(), options: LoadOptions = {}): Secrets {
  const generateIfMissing = options.generateIfMissing ?? true;
  const report = options.onGenerate ?? ((m: string) => process.stderr.write(`${m}\n`));

  const problems: SecretProblem[] = [];
  const raw = new Map<SecretName, string>();
  const generated: SecretSpec[] = [];

  const dirUsable = ensureDir(dir, problems);

  for (const spec of SECRET_SPECS) {
    const path = join(dir, spec.file);

    if (!existsSync(path)) {
      if (!dirUsable) continue;
      if (!generateIfMissing) {
        problems.push({
          file: path,
          purpose: spec.purpose,
          reason: "the secret is missing and generation is disabled",
          remedy: "restore the secrets volume, or start once with generation enabled to create it",
        });
        continue;
      }
      writeFileSync(path, generate(spec), { mode: FILE_MODE });
      chmodSync(path, FILE_MODE);
      generated.push(spec);
    }

    if (!existsSync(path)) continue;

    const mode = modeOf(path);
    if ((mode & GROUP_AND_OTHER) !== 0) {
      problems.push({
        file: path,
        purpose: spec.purpose,
        reason: `mode is ${mode.toString(8).padStart(4, "0")}; other users on this host can read it`,
        remedy: `chmod 600 ${path}`,
      });
      continue;
    }

    const content = readFileSync(path, "utf8");

    if (spec.kind === "ed25519") {
      let key: KeyObject;
      try {
        key = createPrivateKey(content);
      } catch (cause) {
        problems.push({
          file: path,
          purpose: spec.purpose,
          reason: `it is not a readable private key (${(cause as Error).message})`,
          remedy: `remove the file and restart to generate a new key, then re-enrol agents`,
        });
        continue;
      }
      if (key.asymmetricKeyType !== "ed25519") {
        problems.push({
          file: path,
          purpose: spec.purpose,
          reason: `it is a ${String(key.asymmetricKeyType)} key; an ed25519 key is required`,
          remedy: `remove the file and restart to generate a new key, then re-enrol agents`,
        });
        continue;
      }
      // A placeholder PEM would already have failed to parse, so the weak-value
      // check does not apply here.
      raw.set(spec.name, content);
      continue;
    }

    const decoded = decodeRandom(content);
    const weak = weakSecretReason(content, decoded, spec.minBytes);
    if (weak !== null) {
      problems.push({
        file: path,
        purpose: spec.purpose,
        reason: weak,
        remedy: `remove the file and restart; Ratline will generate a strong one`,
      });
      continue;
    }
    raw.set(spec.name, content);
  }

  if (problems.length > 0) throw new SecretRefusal(problems);

  if (generated.length > 0) {
    report(
      `Ratline generated ${generated.length} secret(s) in ${dir}:\n` +
        generated.map((s) => `  ${s.file} — ${s.purpose}`).join("\n") +
        `\nBack this directory up. Losing it means re-enrolling every agent and ` +
        `losing every stored secret value.`,
    );
  }

  const cookie = decodeRandom(raw.get("cookie") ?? "");
  const kek = decodeRandom(raw.get("kek") ?? "");
  const instructionSigning = createPrivateKey(raw.get("instruction-signing") ?? "");

  return Object.freeze({
    cookie,
    kek,
    instructionSigning,
    toJSON: () => "[secrets redacted]",
  });
}

/**
 * Constant-time comparison, for anywhere a secret is checked against a
 * submitted value. Length is leaked; content is not.
 */
export function secretEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
