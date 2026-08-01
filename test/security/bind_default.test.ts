/**
 * C5 — the dashboard assumes it is not internet-exposed (RL-M1-023).
 *
 * Roughly 52,000 Coolify instances were on the public internet in January 2026.
 * The defence is that loopback is the default and that leaving it is a
 * deliberate act, so this suite is mostly about what the code *refuses*.
 *
 * Every exposure test injects its own interface list, so the results do not
 * depend on the machine running them — and, per ADR 0011, nothing here touches
 * the network.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  assessExposure,
  bindRefusal,
  classifyAddress,
  DEFAULT_BIND_ADDRESS,
  globalInterfaces,
  publicBindAcknowledged,
  resolveBindAddress,
  resolvePort,
  type Interface,
} from "../../src/config/network.ts";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const NONE: readonly Interface[] = [];
const PUBLIC: readonly Interface[] = [{ name: "eth0", address: "203.0.113.10" }];

// ---------------------------------------------------------------------------
// Acceptance 1 — loopback by default, leaving it is deliberate
// ---------------------------------------------------------------------------

test("the default bind address is loopback", () => {
  assert.equal(DEFAULT_BIND_ADDRESS, "127.0.0.1");
  assert.equal(resolveBindAddress({}), "127.0.0.1");
  assert.equal(resolveBindAddress({ RATLINE_BIND_ADDRESS: "" }), "127.0.0.1");
  assert.equal(resolveBindAddress({ RATLINE_BIND_ADDRESS: "   " }), "127.0.0.1");
});

test("the default is contained and warns about nothing", () => {
  const exposure = assessExposure(DEFAULT_BIND_ADDRESS, PUBLIC);
  assert.equal(exposure.level, "contained");
  assert.equal(exposure.warning, null);
  assert.equal(bindRefusal(exposure, false), null);
});

test("a public bind is not acknowledged unless explicitly set", () => {
  assert.equal(publicBindAcknowledged({}), false);
  assert.equal(publicBindAcknowledged({ RATLINE_ALLOW_PUBLIC_BIND: "" }), false);
  assert.equal(publicBindAcknowledged({ RATLINE_ALLOW_PUBLIC_BIND: "0" }), false);
  assert.equal(publicBindAcknowledged({ RATLINE_ALLOW_PUBLIC_BIND: "no" }), false);
  assert.equal(publicBindAcknowledged({ RATLINE_ALLOW_PUBLIC_BIND: "1" }), true);
  assert.equal(publicBindAcknowledged({ RATLINE_ALLOW_PUBLIC_BIND: "true" }), true);
});

test("an invalid port falls back to the default rather than binding something surprising", () => {
  assert.equal(resolvePort({}), 7712);
  assert.equal(resolvePort({ RATLINE_BIND_PORT: "0" }), 7712);
  assert.equal(resolvePort({ RATLINE_BIND_PORT: "99999" }), 7712);
  assert.equal(resolvePort({ RATLINE_BIND_PORT: "-1" }), 7712);
  assert.equal(resolvePort({ RATLINE_BIND_PORT: "abc" }), 7712);
  assert.equal(resolvePort({ RATLINE_BIND_PORT: "8080" }), 8080);
});

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

test("addresses are classified correctly", () => {
  const cases: [string, string][] = [
    ["127.0.0.1", "loopback"],
    ["127.10.20.30", "loopback"],
    ["::1", "loopback"],
    ["0.0.0.0", "wildcard"],
    ["::", "wildcard"],
    ["[::]", "wildcard"],
    ["", "wildcard"],
    ["10.0.0.5", "private"],
    ["172.16.0.1", "private"],
    ["172.31.255.254", "private"],
    ["192.168.1.10", "private"],
    ["100.64.0.1", "carrier-grade-nat"],
    ["100.127.255.254", "carrier-grade-nat"],
    ["169.254.1.1", "link-local"],
    ["fe80::1", "link-local"],
    ["fd00::1", "unique-local"],
    ["203.0.113.10", "global"],
    ["8.8.8.8", "global"],
    ["2606:4700::1111", "global"],
    ["::ffff:127.0.0.1", "loopback"],
    ["::ffff:8.8.8.8", "global"],
    ["not-an-ip", "invalid"],
    ["999.1.1.1", "invalid"],
    ["10.0.0", "invalid"],
  ];
  for (const [address, expected] of cases) {
    assert.equal(classifyAddress(address), expected, `${address} should be ${expected}`);
  }
});

test("addresses adjacent to a private range are not mistaken for private", () => {
  // 172.15/16 and 172.32/16 sit just outside RFC1918; off-by-one here would
  // silently treat a public address as safe.
  assert.equal(classifyAddress("172.15.0.1"), "global");
  assert.equal(classifyAddress("172.32.0.1"), "global");
  assert.equal(classifyAddress("100.63.255.255"), "global");
  assert.equal(classifyAddress("100.128.0.0"), "global");
  assert.equal(classifyAddress("192.169.1.1"), "global");
  assert.equal(classifyAddress("11.0.0.1"), "global");
});

// ---------------------------------------------------------------------------
// Acceptance 2 — exposure is detected and warned about
// ---------------------------------------------------------------------------

test("a globally routable bind is exposed, warned about, and refused", () => {
  const exposure = assessExposure("203.0.113.10", NONE);
  assert.equal(exposure.level, "exposed");
  assert.notEqual(exposure.warning, null);
  const refusal = bindRefusal(exposure, false);
  assert.notEqual(refusal, null);
  assert.match(refusal?.remedy ?? "", /Tailscale/);
});

test("a wildcard on a host with a public address is exposed and names it", () => {
  const exposure = assessExposure("0.0.0.0", PUBLIC);
  assert.equal(exposure.level, "exposed");
  assert.match(exposure.warning ?? "", /203\.0\.113\.10/);
  assert.match(exposure.warning ?? "", /eth0/);
  assert.notEqual(bindRefusal(exposure, false), null);
});

test("a wildcard is refused even when no public address exists today", () => {
  // "No public address right now" is a fact about this afternoon, not about the
  // deployment. A DHCP lease or a cloud migration exposes it with no further
  // change, and nobody re-reads the boot log afterwards.
  const exposure = assessExposure("0.0.0.0", NONE);
  assert.notEqual(exposure.warning, null, "a wildcard bind must always warn");
  assert.notEqual(
    bindRefusal(exposure, false),
    null,
    "a wildcard must require acknowledgement regardless of current interfaces",
  );
});

test("VPN and LAN addresses are allowed without ceremony", () => {
  // These are the recommended setups. Demanding acknowledgement for them would
  // train operators to set the acknowledgement variable permanently.
  for (const address of ["10.0.0.5", "192.168.1.10", "172.20.0.4", "100.64.0.1", "fd00::1"]) {
    const exposure = assessExposure(address, PUBLIC);
    assert.equal(exposure.level, "network", `${address} should be network-level`);
    assert.equal(exposure.warning, null, `${address} should not warn`);
    assert.equal(bindRefusal(exposure, false), null, `${address} should not be refused`);
  }
});

test("acknowledgement permits the bind but never clears the warning", () => {
  for (const address of ["203.0.113.10", "0.0.0.0"]) {
    const exposure = assessExposure(address, PUBLIC);
    assert.equal(bindRefusal(exposure, true), null, `${address} should be allowed once acknowledged`);
    assert.notEqual(
      exposure.warning,
      null,
      "C5 requires a non-dismissable warning; acknowledgement must not silence it",
    );
  }
});

test("an invalid bind address is refused rather than guessed at", () => {
  const exposure = assessExposure("not-an-ip", NONE);
  const refusal = bindRefusal(exposure, false);
  assert.notEqual(refusal, null);
  // Acknowledging a public bind must not smuggle a malformed one through.
  assert.notEqual(bindRefusal(exposure, true), null);
});

test("every assessment carries the caveat about what it cannot see", () => {
  for (const address of ["127.0.0.1", "10.0.0.1", "0.0.0.0", "203.0.113.10", "bogus"]) {
    const exposure = assessExposure(address, PUBLIC);
    assert.match(exposure.caveat, /reverse proxy/i, `${address} must state the blind spot`);
    assert.match(exposure.caveat, /NAT/i);
  }
});

test("loopback interfaces are never counted as globally routable", () => {
  const found = globalInterfaces({
    lo0: [{ address: "127.0.0.1", internal: true }],
    utun3: [{ address: "100.64.1.2", internal: false }],
    eth0: [{ address: "203.0.113.10", internal: false }],
  });
  assert.deepEqual(
    found.map((i) => i.address),
    ["203.0.113.10"],
  );
});

// ---------------------------------------------------------------------------
// ADR 0011 — the check must not phone home
// ---------------------------------------------------------------------------

test("exposure assessment makes no outbound connection", () => {
  const source = readFileSync(join(ROOT, "src", "config", "network.ts"), "utf8");
  const forbidden = ["node:http", "node:https", "node:dns", "node:dgram", "node:tls", "fetch(", "XMLHttpRequest"];
  for (const token of forbidden) {
    assert.ok(
      !source.includes(token),
      `network.ts references ${token}; ADR 0011 forbids an outbound probe — it would phone home from every install and fail on the isolated networks C5 protects`,
    );
  }
});

// ---------------------------------------------------------------------------
// End to end — the process refuses rather than serving
// ---------------------------------------------------------------------------

function runPreflight(env: Record<string, string>): { status: number | null; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "ratline-bind-"));
  try {
    const result = spawnSync(
      process.execPath,
      ["--experimental-strip-types", join(ROOT, "src", "boot.ts")],
      { env: { ...process.env, RATLINE_SECRETS_DIR: dir, ...env }, encoding: "utf8" },
    );
    return { status: result.status, stderr: result.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the process refuses a wildcard bind and explains the alternatives", () => {
  const result = runPreflight({ RATLINE_BIND_ADDRESS: "0.0.0.0", RATLINE_ALLOW_PUBLIC_BIND: "" });
  assert.equal(result.status, 1, "must exit non-zero");
  assert.match(result.stderr, /refuses to start/);
  assert.match(result.stderr, /Tailscale/, "name a safer setup");
  assert.match(result.stderr, /ssh -L/, "give a command they can run now");
  assert.match(result.stderr, /docs\/NETWORK\.md/);
});

test("the process starts on the default and reports containment", () => {
  const result = runPreflight({});
  assert.equal(result.status, 0);
  assert.match(result.stderr, /127\.0\.0\.1:7712/);
  assert.match(result.stderr, /contained/);
});

test("an acknowledged public bind starts but still prints the warning", () => {
  const result = runPreflight({ RATLINE_BIND_ADDRESS: "0.0.0.0", RATLINE_ALLOW_PUBLIC_BIND: "1" });
  assert.equal(result.status, 0);
  assert.match(result.stderr, /!!/, "the warning must still appear");
  assert.match(result.stderr, /Acknowledged via RATLINE_ALLOW_PUBLIC_BIND/);
});

test("the boot report does not claim acknowledgement that was not given", () => {
  // A warning that misdescribes the operator's own configuration is worse than
  // none: it teaches them the text is boilerplate.
  const result = runPreflight({ RATLINE_BIND_ADDRESS: "10.0.0.1" });
  assert.equal(result.status, 0);
  assert.ok(
    !result.stderr.includes("Acknowledged via"),
    "an unacknowledged bind must not be reported as acknowledged",
  );
});

// ---------------------------------------------------------------------------
// Acceptance 3 — the documentation exists and covers the named setups
// ---------------------------------------------------------------------------

test("the network documentation covers VPN, Tailscale and address allowlists", () => {
  const doc = readFileSync(join(ROOT, "docs", "NETWORK.md"), "utf8");
  for (const topic of [/tailscale/i, /wireguard|vpn/i, /allowlist/i, /reverse proxy/i, /ssh tunnel|ssh -L/i]) {
    assert.match(doc, topic, `docs/NETWORK.md must cover ${String(topic)}`);
  }
});
