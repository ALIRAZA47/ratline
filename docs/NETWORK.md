# Reaching the Ratline dashboard

**Task:** RL-M1-023 · **Constraint:** C5 · **Decision:** [ADR 0011](decisions/0011-exposure-detection-without-phoning-home.md)

Ratline binds the dashboard to `127.0.0.1:7712` and assumes it is not on the
public internet. That default is the whole point: roughly 52,000 Coolify
instances were sitting on the public internet in January 2026, and almost none
of those operators chose that deliberately.

This page covers how to reach the dashboard safely from somewhere else.

---

## The short version

| You want | Do this |
| --- | --- |
| Occasional access from your laptop | [SSH tunnel](#ssh-tunnel) — nothing to install |
| Your whole team, on any network | [Tailscale](#tailscale) |
| Your own VPN already exists | [WireGuard](#wireguard) |
| Direct access, no VPN possible | [IP allowlist](#ip-allowlist) — least preferred |

**Do not** put the dashboard on a public address without one of the above in
front of it. Ratline will refuse to start if you try, and the refusal explains
why.

---

## SSH tunnel

Nothing to install and nothing to configure on the host. The dashboard stays on
loopback and you forward a port over the SSH session you already have.

```bash
ssh -L 7712:127.0.0.1:7712 you@your-host
```

Then open `http://127.0.0.1:7712` on your own machine. Close the SSH session and
access ends with it.

This is the right answer for a single operator. It scales badly to a team, which
is what the next two sections are for.

## Tailscale

Puts every team member and every host on one private network with no port
forwarding and no firewall rules.

1. Install Tailscale on the control plane host and join your tailnet.
2. Find the host's tailnet address — it will be in `100.64.0.0/10`:

```bash
tailscale ip -4
```

3. Bind Ratline to that address:

```bash
RATLINE_BIND_ADDRESS=100.101.102.103
```

Ratline treats `100.64.0.0/10` as a private network and starts without
complaint. No acknowledgement variable is needed, because this is a setup we
recommend rather than one to warn about.

Use Tailscale ACLs to control who on the tailnet can reach port 7712. That is a
second layer under Ratline's own permissions, not a replacement for them.

## WireGuard

If you already run WireGuard, bind to the host's address on the VPN interface:

```bash
RATLINE_BIND_ADDRESS=10.8.0.1
```

Any RFC1918 address (`10/8`, `172.16/12`, `192.168/16`) or IPv6 unique-local
address (`fd00::/8`) is accepted without acknowledgement.

Check what the interface actually holds before you set this:

```bash
ip -brief address show wg0
```

## IP allowlist

Least preferred, because it fails open in ways the others do not: a changed
office address, a misordered firewall rule, or an IPv6 path around an IPv4 rule
all silently expose the dashboard.

If you must:

1. Put a reverse proxy or firewall in front, restricted to known addresses.
2. Bind Ratline to loopback and have the proxy connect to it — **do not** bind
   Ratline to the public address itself.

```bash
# nftables: allow only the office, drop the rest
nft add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 443 accept
nft add rule inet filter input tcp dport 443 drop
```

Test it from an address that should be blocked. An allowlist nobody has tested
from the outside is a comment, not a control.

---

## What Ratline checks at boot

The bind address is classified locally, with **no outbound network call** — see
[ADR 0011](decisions/0011-exposure-detection-without-phoning-home.md) for why a
probe would be the wrong design for a self-hosted tool.

| Bind address | Level | Behaviour |
| --- | --- | --- |
| `127.0.0.1`, `::1` | contained | Starts silently. The default. |
| `10/8`, `172.16/12`, `192.168/16`, `fd00::/8` | network | Starts silently. LAN or VPN. |
| `100.64.0.0/10` | network | Starts silently. Tailscale. |
| `169.254/16`, `fe80::/10` | network | Starts silently. Link-local. |
| Any globally routable address | exposed | **Refuses to start** without acknowledgement. |
| `0.0.0.0`, `::` | exposed | **Refuses to start** without acknowledgement. |
| Anything unparseable | — | **Refuses to start.** No guessing. |

A wildcard bind is refused even on a host with no public address today, because
that is a fact about this afternoon: a DHCP lease, an added interface or a cloud
migration exposes it with no further change, and nobody re-reads the boot log
afterwards.

To proceed anyway, having put a control in front of it:

```bash
RATLINE_ALLOW_PUBLIC_BIND=1
```

This permits the bind. **It does not clear the warning** — the banner stays
visible in the dashboard and the message is printed on every boot for as long as
the exposure lasts. C5 calls for a warning that cannot be dismissed, and an
acknowledgement that silenced it would be a dismissal with extra steps.

### What this check cannot see

Local classification cannot detect:

- a NAT port-forward from a router to this host,
- a cloud load balancer or ingress in front of the process,
- **a reverse proxy on the same host**.

A dashboard bound to `127.0.0.1` behind a public nginx is fully reachable from
the internet, and Ratline will report `contained`. If you run a proxy in front,
you own that exposure and the allowlist section above applies to you.

We would rather state this than let `contained` be read as `verified private`.

---

## The agent endpoint is different

Managed hosts dial *out* to the control plane (ADR 0002), so the agent endpoint
and the dashboard have **separate exposure policies**:

- **Dashboard** — loopback by default, reached over VPN or a tunnel. This page.
- **Agent endpoint** — may face the internet, because it requires a valid client
  certificate at the TLS handshake and rejects everything else before any
  application code runs.

No managed host ever listens on a Ratline port; the connection is always
outbound from the host. The agent endpoint arrives in M2 and this section will
grow with it.

---

## Configuration reference

| Variable | Default | Meaning |
| --- | --- | --- |
| `RATLINE_BIND_ADDRESS` | `127.0.0.1` | Dashboard bind address. |
| `RATLINE_BIND_PORT` | `7712` | Dashboard port. Invalid values fall back to the default rather than binding something surprising. |
| `RATLINE_ALLOW_PUBLIC_BIND` | unset | Permits an exposed bind. Never silences the warning. |
| `RATLINE_SECRETS_DIR` | `/etc/ratline/secrets` in production | Where generated secrets live. See [ADR 0006](decisions/0006-secrets-and-envelope-encryption.md). |

Check a host without starting anything:

```bash
./scripts/preflight
```
