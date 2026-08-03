/**
 * Bind address and exposure assessment (C5, RL-M1-023).
 *
 * C5: "The dashboard assumes it is not internet-exposed. Bind to localhost by
 * default. Detect public reachability and show a loud, non-dismissable
 * warning."
 *
 * Everything here is a pure function over an address string and a list of host
 * interfaces. There is no network call, by decision — see ADR 0011. An outbound
 * probe would phone home from every install and would fail on exactly the
 * isolated networks C5 is written to protect.
 *
 * The blind spot is deliberate and stated everywhere the result is shown: local
 * classification cannot see a NAT port-forward or an upstream reverse proxy. A
 * process bound to 127.0.0.1 behind a public nginx is fully exposed and this
 * module will report `contained`. Saying so is the difference between a warning
 * an operator trusts and one that teaches them to stop looking.
 */

import { isIPv4, isIPv6 } from "node:net";
import { networkInterfaces } from "node:os";

export type AddressClass =
  | "loopback"
  | "wildcard"
  | "private"
  | "carrier-grade-nat"
  | "link-local"
  | "unique-local"
  | "global"
  | "invalid";

/** How reachable the dashboard is, as far as can be known without a network call. */
export type ExposureLevel = "contained" | "network" | "exposed";

export type Interface = { readonly name: string; readonly address: string };

export type Exposure = {
  readonly level: ExposureLevel;
  readonly bind: string;
  readonly addressClass: AddressClass;
  /** Globally routable addresses on this host. Only meaningful for a wildcard bind. */
  readonly globalInterfaces: readonly Interface[];
  /** Operator-facing headline. Non-null whenever the interface must show a banner. */
  readonly warning: string | null;
  /** What this check cannot see. Always present, always shown with the result. */
  readonly caveat: string;
};

export const DEFAULT_BIND_ADDRESS = "127.0.0.1";
export const DEFAULT_PORT = 7712;

const CAVEAT =
  "This is determined from the bind address and this host's interfaces, with no " +
  "outbound connection (ADR 0011). It cannot see a NAT port-forward, a cloud load " +
  "balancer, or a reverse proxy in front of Ratline — any of which makes the " +
  "dashboard reachable regardless of what is reported here.";

function ipv4Octets(address: string): readonly number[] | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/**
 * Classify an address without touching the network.
 *
 * Carrier-grade NAT (100.64.0.0/10) is called out separately because that is
 * the range Tailscale allocates from, and binding to a Tailscale address is the
 * setup we recommend rather than one to warn about.
 */
export function classifyAddress(raw: string): AddressClass {
  const address = raw.trim().toLowerCase();

  if (address === "" || address === "0.0.0.0" || address === "::" || address === "[::]") {
    return "wildcard";
  }

  const bare = address.startsWith("[") && address.endsWith("]") ? address.slice(1, -1) : address;

  if (isIPv4(bare)) {
    const octets = ipv4Octets(bare);
    if (octets === null) return "invalid";
    const [a = 0, b = 0] = octets;
    if (a === 127) return "loopback";
    if (a === 10) return "private";
    if (a === 172 && b >= 16 && b <= 31) return "private";
    if (a === 192 && b === 168) return "private";
    if (a === 100 && b >= 64 && b <= 127) return "carrier-grade-nat";
    if (a === 169 && b === 254) return "link-local";
    return "global";
  }

  if (isIPv6(bare)) {
    if (bare === "::1") return "loopback";
    // IPv4-mapped (::ffff:a.b.c.d) carries the v4 semantics.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(bare);
    if (mapped?.[1] !== undefined) return classifyAddress(mapped[1]);
    if (/^fe[89ab]/.test(bare)) return "link-local";
    if (/^f[cd]/.test(bare)) return "unique-local";
    return "global";
  }

  return "invalid";
}

/** Globally routable addresses configured on this host. */
export function globalInterfaces(
  interfaces: NodeJS.Dict<{ address: string; internal: boolean }[]> = networkInterfaces(),
): readonly Interface[] {
  const found: Interface[] = [];
  for (const [name, addresses] of Object.entries(interfaces)) {
    for (const entry of addresses ?? []) {
      if (entry.internal) continue;
      if (classifyAddress(entry.address) === "global") {
        found.push({ name, address: entry.address });
      }
    }
  }
  return found;
}

/** Resolve the configured bind address. Loopback unless deliberately changed. */
export function resolveBindAddress(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env["RATLINE_BIND_ADDRESS"];
  if (configured === undefined || configured.trim() === "") return DEFAULT_BIND_ADDRESS;
  return configured.trim();
}

export function resolvePort(env: NodeJS.ProcessEnv = process.env): number {
  const configured = env["RATLINE_BIND_PORT"];
  if (configured === undefined || configured.trim() === "") return DEFAULT_PORT;
  const port = Number(configured);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return DEFAULT_PORT;
  return port;
}

export function publicBindAcknowledged(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env["RATLINE_ALLOW_PUBLIC_BIND"];
  return value === "1" || value?.toLowerCase() === "true";
}

/**
 * Assess how exposed the dashboard is. Pure: pass the interface list to test
 * any host shape without one.
 */
export function assessExposure(
  bind: string,
  interfaces: readonly Interface[] = globalInterfaces(),
): Exposure {
  const addressClass = classifyAddress(bind);
  const base = { bind, addressClass, caveat: CAVEAT } as const;

  switch (addressClass) {
    case "invalid":
      return {
        ...base,
        level: "exposed",
        globalInterfaces: [],
        warning: `"${bind}" is not a valid IP address. Ratline will not guess what you meant.`,
      };

    case "loopback":
      return { ...base, level: "contained", globalInterfaces: [], warning: null };

    case "private":
    case "carrier-grade-nat":
    case "unique-local":
    case "link-local":
      // The recommended shape: reachable over a VPN or LAN, not from the internet.
      return { ...base, level: "network", globalInterfaces: [], warning: null };

    case "global":
      return {
        ...base,
        level: "exposed",
        globalInterfaces: [{ name: "configured", address: bind }],
        warning:
          `The dashboard is bound to ${bind}, a globally routable address. ` +
          `Anyone who can reach this host can reach the login page.`,
      };

    case "wildcard": {
      // A wildcard is only as exposed as the interfaces underneath it.
      const global = interfaces;
      if (global.length === 0) {
        return {
          ...base,
          level: "network",
          globalInterfaces: [],
          warning:
            `The dashboard is bound to every interface on this host. No globally ` +
            `routable address is configured right now, but one appearing later ` +
            `would expose the dashboard with no further change.`,
        };
      }
      return {
        ...base,
        level: "exposed",
        globalInterfaces: global,
        warning:
          `The dashboard is bound to every interface, and this host has a globally ` +
          `routable address (${global.map((i) => `${i.address} on ${i.name}`).join(", ")}). ` +
          `The login page is reachable from the internet.`,
      };
    }
  }
}

/** Guidance shown on refusal and alongside any exposure warning. */
export const SAFER_SETUPS =
  "Recommended instead:\n" +
  "  - Bind to a Tailscale address (100.64.0.0/10) and reach it over the tailnet.\n" +
  "  - Bind to a WireGuard or private LAN address (10/8, 172.16/12, 192.168/16).\n" +
  "  - Keep the loopback default and use an SSH tunnel:\n" +
  "      ssh -L 7712:127.0.0.1:7712 you@host\n" +
  "  - If it must be reachable directly, put an IP allowlist in front of it.\n" +
  "See docs/NETWORK.md.";

export type BindRefusal = { readonly reason: string; readonly remedy: string };

/**
 * Returns a refusal when this bind must not be allowed, or null when it may
 * proceed. Public and wildcard binds require an explicit acknowledgement;
 * private and VPN addresses do not, because those are the recommended setups.
 */
export function bindRefusal(exposure: Exposure, acknowledged: boolean): BindRefusal | null {
  if (exposure.addressClass === "invalid") {
    return {
      reason: `RATLINE_BIND_ADDRESS is "${exposure.bind}", which is not a valid IP address.`,
      remedy: `Set it to a valid address, or unset it to use the ${DEFAULT_BIND_ADDRESS} default.`,
    };
  }
  // A wildcard always needs acknowledgement, even when this host has no
  // globally routable address today. "No public address right now" is a fact
  // about this afternoon, not about the deployment: a DHCP lease, a cloud
  // migration or an added interface exposes it with no further change, and
  // nobody re-reads the boot log afterwards. Binding 0.0.0.0 without a second
  // thought is precisely the path of least resistance C5 exists to close.
  const needsAcknowledgement = exposure.level === "exposed" || exposure.addressClass === "wildcard";
  if (!needsAcknowledgement) return null;
  if (acknowledged) return null;

  return {
    reason: `${exposure.warning ?? "This bind exposes the dashboard."}\n\n${exposure.caveat}`,
    remedy:
      `${SAFER_SETUPS}\n\n` +
      `If you have an allowlist or equivalent control in front of this and still\n` +
      `want to proceed, set RATLINE_ALLOW_PUBLIC_BIND=1. The warning stays visible\n` +
      `in the dashboard for as long as the exposure lasts.`,
  };
}
