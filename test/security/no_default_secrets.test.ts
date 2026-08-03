/**
 * C4 — no default secrets (RL-M1-022).
 *
 * CloudPanel's CVE-2023-35885 was exploited in the wild because a shipped
 * default signing key let anyone forge a cookie. This suite asserts both
 * halves of the defence: that we ship no default, and that we refuse to run
 * with a weak one an operator supplied.
 *
 * Note on `node:child_process`: RL-M1-008 will ban it in control-plane code
 * (C2). That ban is scoped to `src/**` — spawning the real process is the only
 * honest way to test "the application exits", and brief §9 forbids mocking the
 * thing under test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, globSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadSecrets, SecretRefusal, SECRET_SPECS, secretsDir } from "../../src/crypto/secrets.ts";
import { KNOWN_DEFAULT_TOKENS } from "../../src/crypto/weak-secrets.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function freshDir(): string {
  return mkdtempSync(join(tmpdir(), "ratline-secrets-"));
}
function withDir(fn: (dir: string) => void): void {
  const dir = freshDir();
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
const silent = { onGenerate: () => {} };

// ---------------------------------------------------------------------------
// Acceptance 2 — first run generates from a cryptographic source, restrictively
// ---------------------------------------------------------------------------

test("first run generates every secret", () => {
  withDir((dir) => {
    const secrets = loadSecrets(dir, silent);
    assert.equal(secrets.cookie.length, 32);
    assert.equal(secrets.kek.length, 32);
    assert.equal(secrets.instructionSigning.asymmetricKeyType, "ed25519");
    for (const spec of SECRET_SPECS) {
      assert.ok(statSync(join(dir, spec.file)).isFile(), `${spec.file} was not created`);
    }
  });
});

test("generated secrets and their directory are unreadable by other users", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    assert.equal(statSync(dir).mode & 0o077, 0, "secrets directory is group- or world-accessible");
    for (const spec of SECRET_SPECS) {
      const mode = statSync(join(dir, spec.file)).mode & 0o777;
      assert.equal(mode & 0o077, 0, `${spec.file} has mode ${mode.toString(8)}`);
    }
  });
});

test("generation is not deterministic across installations", () => {
  withDir((a) => {
    withDir((b) => {
      const one = loadSecrets(a, silent);
      const two = loadSecrets(b, silent);
      // A seeded or derived generator would produce the same bytes twice, which
      // is the failure mode that makes one leaked install compromise all of them.
      assert.notEqual(one.cookie.toString("base64"), two.cookie.toString("base64"));
      assert.notEqual(one.kek.toString("base64"), two.kek.toString("base64"));
      assert.notEqual(one.cookie.toString("base64"), one.kek.toString("base64"));
    });
  });
});

test("a second run reuses the secrets rather than regenerating them", () => {
  withDir((dir) => {
    const first = loadSecrets(dir, silent);
    const second = loadSecrets(dir, silent);
    assert.equal(first.cookie.toString("base64"), second.cookie.toString("base64"));
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3 — refuse to start on missing or weak secrets
// ---------------------------------------------------------------------------

test("every known-default placeholder is refused", () => {
  for (const token of KNOWN_DEFAULT_TOKENS) {
    withDir((dir) => {
      loadSecrets(dir, silent);
      writeFileSync(join(dir, "cookie.key"), `${token}\n`, { mode: 0o600 });
      assert.throws(
        () => loadSecrets(dir, silent),
        (e: unknown) => {
          assert.ok(e instanceof SecretRefusal, `"${token}" was accepted as a cookie secret`);
          // The problem LIST, not just its length (RL-M1-046). This assertion
          // was seen to fail once and could not be reproduced in thirty-one
          // runs, and the reason the sighting taught nothing is that a bare
          // count says "2 !== 1" and stops. A second problem here would mean
          // one of the OTHER generated secrets had failed its own validation,
          // which is a product defect rather than a fixture one — so the next
          // occurrence has to name it.
          assert.deepEqual(
            e.problems.map((problem) => problem.file.split("/").at(-1)),
            ["cookie.key"],
            `expected only the cookie secret to be refused, got: ${JSON.stringify(e.problems)}`,
          );
          return true;
        },
      );
    });
  }
});

test("a truncated secret is refused", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    // Valid base64, correct alphabet, simply too short to be a 256-bit key.
    writeFileSync(join(dir, "kek.key"), `${Buffer.from("0123456789abcdef").toString("base64")}\n`, { mode: 0o600 });
    assert.throws(() => loadSecrets(dir, silent), SecretRefusal);
  });
});

test("a zero-entropy secret of the correct length is refused", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    writeFileSync(join(dir, "kek.key"), `${Buffer.alloc(32, 0x41).toString("base64")}\n`, { mode: 0o600 });
    assert.throws(() => loadSecrets(dir, silent), SecretRefusal);
  });
});

test("a counting-sequence secret of the correct length is refused", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    const counting = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
    writeFileSync(join(dir, "kek.key"), `${counting.toString("base64")}\n`, { mode: 0o600 });
    assert.throws(() => loadSecrets(dir, silent), SecretRefusal);
  });
});

test("a secret readable by other users is refused rather than used", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    chmodSync(join(dir, "cookie.key"), 0o644);
    assert.throws(
      () => loadSecrets(dir, silent),
      (e: unknown) => e instanceof SecretRefusal && /other users/.test(e.problems[0]?.reason ?? ""),
    );
  });
});

test("a missing secret is refused when generation is disabled", () => {
  withDir((dir) => {
    assert.throws(
      () => loadSecrets(dir, { ...silent, generateIfMissing: false }),
      (e: unknown) => e instanceof SecretRefusal && e.problems.length === SECRET_SPECS.length,
      "a container with an unmounted secrets volume must not mint fresh keys",
    );
  });
});

test("a malformed signing key is refused", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    writeFileSync(join(dir, "instruction-signing.pem"), "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n", { mode: 0o600 });
    assert.throws(() => loadSecrets(dir, silent), SecretRefusal);
  });
});

test("all problems are reported at once, not one restart at a time", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    writeFileSync(join(dir, "cookie.key"), "changeme\n", { mode: 0o600 });
    chmodSync(join(dir, "kek.key"), 0o644);
    try {
      loadSecrets(dir, silent);
      assert.fail("expected a refusal");
    } catch (e) {
      assert.ok(e instanceof SecretRefusal);
      assert.equal(e.problems.length, 2);
    }
  });
});

// ---------------------------------------------------------------------------
// Secret values must never leave the process
// ---------------------------------------------------------------------------

test("a refusal report never contains the secret value", () => {
  withDir((dir) => {
    loadSecrets(dir, silent);
    const planted = "changeme-A7Fq93kdneutralPLANTED";
    writeFileSync(join(dir, "cookie.key"), `${planted}\n`, { mode: 0o600 });
    try {
      loadSecrets(dir, silent);
      assert.fail("expected a refusal");
    } catch (e) {
      assert.ok(e instanceof SecretRefusal);
      const text = `${e.report()}\n${e.message}\n${e.stack ?? ""}`;
      assert.ok(!text.includes(planted), "the refusal leaked the secret value");
      assert.ok(text.includes("cookie.key"), "the refusal should name the file");
    }
  });
});

test("serialising the secrets object cannot spill key material", () => {
  withDir((dir) => {
    const secrets = loadSecrets(dir, silent);
    const serialised = JSON.stringify({ config: "x", secrets });
    assert.ok(!serialised.includes(secrets.cookie.toString("base64")));
    assert.ok(!serialised.includes(secrets.kek.toString("base64")));
    assert.match(serialised, /redacted/);
  });
});

// ---------------------------------------------------------------------------
// Acceptance 3, end to end — the process exits rather than serving
// ---------------------------------------------------------------------------

test("the process exits non-zero with an actionable message", () => {
  withDir((dir) => {
    const ok = spawnSync(process.execPath, ["--experimental-strip-types", join(ROOT, "src", "boot.ts")], {
      env: { ...process.env, RATLINE_SECRETS_DIR: dir },
      encoding: "utf8",
    });
    assert.equal(ok.status, 0, `first run should succeed, got: ${ok.stderr}`);

    writeFileSync(join(dir, "cookie.key"), "changeme\n", { mode: 0o600 });
    const refused = spawnSync(process.execPath, ["--experimental-strip-types", join(ROOT, "src", "boot.ts")], {
      env: { ...process.env, RATLINE_SECRETS_DIR: dir },
      encoding: "utf8",
    });
    assert.equal(refused.status, 1, "the process must exit non-zero");
    assert.match(refused.stderr, /refuses to start/);
    assert.match(refused.stderr, /cookie\.key/, "name the offending file");
    assert.match(refused.stderr, /fix:/, "tell the operator what to do next");
  });
});

// ---------------------------------------------------------------------------
// Acceptance 1 and 4 — nothing in the shipped tree is a default secret
// ---------------------------------------------------------------------------

/**
 * The one module allowed to contain placeholder tokens, because defining them
 * is its job. The count is asserted so this cannot quietly grow into a general
 * amnesty.
 */
const PLACEHOLDER_DEFINITION_FILES = ["src/crypto/weak-secrets.ts"];

function shippedSources(): string[] {
  return globSync(["src/**/*.ts", "scripts/**/*.ts"], { cwd: ROOT })
    .map((p) => p.split("\\").join("/"))
    .filter((p) => !p.endsWith(".test.ts"));
}

/** String literals in a source file, with the identifier they are assigned to. */
function literalAssignments(source: string): { identifier: string; value: string }[] {
  const found: { identifier: string; value: string }[] = [];
  const re = /\b([A-Za-z_$][\w$]*)\s*[:=]\s*(['"`])((?:\\.|(?!\2)[^\\])*)\2/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    found.push({ identifier: m[1] ?? "", value: m[3] ?? "" });
  }
  return found;
}

/**
 * Does this identifier name something that holds a credential?
 *
 * "token" cannot be matched bare. `colorToken`, `designToken` and `tokenScale`
 * are ordinary names in a design system, and flagging them would train whoever
 * hits it to add an exclusion rather than to look. So a token counts only when
 * it is the whole name or is credential-qualified. The unambiguous words below
 * are matched anywhere.
 */
function isSecretIsh(identifier: string): boolean {
  const flat = identifier.toLowerCase().replace(/[^a-z0-9]/g, "");
  const unambiguous = /(secret|password|passwd|apikey|privatekey|signingkey|credential|passphrase|kek)/;
  if (unambiguous.test(flat)) return true;
  if (/^(token|tokens|salt|nonce)$/.test(flat)) return true;
  if (/(api|access|auth|bearer|refresh|session|csrf|webhook|deploy|registry)tokens?$/.test(flat)) return true;
  if (/(password|secret|key)salt$/.test(flat)) return true;
  return false;
}
const SECRET_ISH = { test: isSecretIsh };

test("the secret-shaped-identifier detector is neither blind nor trigger-happy", () => {
  // This guards the scanner itself. It was loosened once, because it flagged
  // `colorToken` in the design system — a real false positive that would have
  // taught the next person to add an exclusion instead of looking. Loosening a
  // security check is only safe if the things it must still catch are pinned.
  const mustCatch = [
    "cookieSecret", "SESSION_SECRET", "adminPassword", "apiKey", "API_KEY",
    "privateKey", "signingKey", "webhookSecret", "kek", "credentials",
    "token", "tokens", "accessToken", "refreshToken", "authToken",
    "deployToken", "registryToken", "csrfToken", "passphrase", "salt",
  ];
  const mustIgnore = [
    "colorToken", "designTokens", "tokenScale", "spacingToken", "tokenName",
    "displayFont", "statusId", "bindAddress", "migrationId", "checksum",
    "resourceType", "scopeLevel", "actionName", "roleName", "assaltedName",
  ];
  for (const name of mustCatch) {
    assert.ok(SECRET_ISH.test(name), `"${name}" must be treated as secret-shaped`);
  }
  for (const name of mustIgnore) {
    assert.ok(!SECRET_ISH.test(name), `"${name}" must not be treated as secret-shaped`);
  }
});

test("the exclusion list stays a single file", () => {
  assert.equal(
    PLACEHOLDER_DEFINITION_FILES.length,
    1,
    "only the module that defines placeholder tokens may contain them",
  );
});

test("no secret-shaped constant is assigned in the shipped tree", () => {
  const findings: string[] = [];
  for (const file of shippedSources()) {
    if (PLACEHOLDER_DEFINITION_FILES.includes(file)) continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const { identifier, value } of literalAssignments(source)) {
      if (!SECRET_ISH.test(identifier)) continue;
      if (value.length < 8) continue;
      // Env var names and paths are how you *locate* a secret, not a secret.
      if (/^[A-Z][A-Z0-9_]*$/.test(value)) continue;
      if (value.includes("/") || value.includes(".")) continue;
      findings.push(`${file}: ${identifier} = "${value}"`);
    }
  }
  assert.deepEqual(findings, [], `secret-shaped literals found:\n${findings.join("\n")}`);
});

test("no committed key material anywhere in the shipped tree", () => {
  // Long base64 or hex runs are what an accidentally-pasted real key looks like.
  const base64ish = /^[A-Za-z0-9+/]{32,}={0,2}$/;
  const hexish = /^[0-9a-fA-F]{32,}$/;
  const findings: string[] = [];
  for (const file of shippedSources()) {
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const { value } of literalAssignments(source)) {
      if (base64ish.test(value) || hexish.test(value)) {
        findings.push(`${file}: ${value.slice(0, 12)}… (${value.length} chars)`);
      }
    }
  }
  assert.deepEqual(findings, [], `possible committed key material:\n${findings.join("\n")}`);
});

test("no placeholder token is shipped outside its definition module", () => {
  const findings: string[] = [];
  for (const file of shippedSources()) {
    if (PLACEHOLDER_DEFINITION_FILES.includes(file)) continue;
    const source = readFileSync(join(ROOT, file), "utf8");
    for (const { identifier, value } of literalAssignments(source)) {
      const flat = value.toLowerCase().replace(/[^a-z0-9]/g, "");
      for (const token of KNOWN_DEFAULT_TOKENS) {
        if (flat.includes(token) && SECRET_ISH.test(identifier)) {
          findings.push(`${file}: ${identifier} contains "${token}"`);
        }
      }
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

test("no environment example file ships a populated secret", () => {
  const examples = globSync([".env.example", "**/.env.example", "**/*.env.sample"], { cwd: ROOT })
    .filter((p) => !p.includes("node_modules"));
  const findings: string[] = [];
  for (const file of examples) {
    for (const line of readFileSync(join(ROOT, file), "utf8").split("\n")) {
      const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
      const key = m?.[1];
      const value = m?.[2]?.trim() ?? "";
      if (key === undefined || value === "") continue;
      if (SECRET_ISH.test(key)) findings.push(`${file}: ${key} has a value`);
    }
  }
  assert.deepEqual(findings, [], findings.join("\n"));
});

test("no secret is stored inside the repository", () => {
  // The default dev location is under .ratline/, which .gitignore excludes.
  // If that ever changes, secrets would be committed on the next `git add`.
  const dir = secretsDir({ NODE_ENV: "development" });
  const rel = relative(ROOT, resolve(ROOT, dir));
  const gitignore = readFileSync(join(ROOT, ".gitignore"), "utf8");
  assert.ok(
    gitignore.split("\n").some((line) => line.trim() === ".ratline/"),
    `${rel} holds generated secrets and must be gitignored`,
  );
  assert.equal(secretsDir({ NODE_ENV: "production" }), "/etc/ratline/secrets");
});

// ---------------------------------------------------------------------------
// Generation is not occasionally wrong (RL-M1-046)
// ---------------------------------------------------------------------------

test("a freshly generated set validates every time, not almost every time", () => {
  // The hypothesis behind RL-M1-046, tested directly rather than waited for.
  //
  // "every known-default placeholder is refused" asserts that exactly ONE
  // problem is reported. It was seen to fail once and did not reproduce in
  // thirty-one runs. The only reading of that failure which is a PRODUCT defect
  // rather than a fixture one is that generation occasionally emits a secret
  // that fails its own validation — an ed25519 key that does not parse, or a
  // random key that happens to trip a weak-secret rule.
  //
  // So: generate and validate many times. A one-in-N defect shows up here as a
  // failure with the offending problem named, in seconds, rather than as a
  // flake somewhere else once a fortnight.
  const rounds = 60;
  for (let i = 0; i < rounds; i++) {
    withDir((dir) => {
      loadSecrets(dir, silent);
      // The second call validates what the first one wrote. Anything it
      // complains about was generated wrong.
      const loaded = loadSecrets(dir, silent);
      assert.ok(loaded.cookie.length >= 32, `round ${String(i)}: the cookie key came back short`);
      assert.ok(loaded.kek.length >= 32, `round ${String(i)}: the wrapping key came back short`);
    });
  }
});
