/**
 * What the dashboard renders, decided by asking the server (RL-M1-058).
 *
 * Before this, `main.tsx` rendered the shell unconditionally with `marketing-www` as
 * placeholder data, so opening the dashboard showed a frame around a site that does
 * not exist and the rail led nowhere. The entry screens in `FirstRun.tsx` already
 * talked to the API; nothing routed to them.
 *
 * The gate has four states and each renders something different, because collapsing
 * any two of them misleads:
 *
 *   - **asking** — a blank frame, not a sign-in form. Showing the form first and
 *     replacing it if a session turns out to exist would flash a password field at
 *     somebody already signed in, which trains people to type into whatever appears.
 *   - **signed-out** — `Entry`, which asks the server whether this installation has
 *     been claimed and picks the claim form or the sign-in form. That decision is the
 *     server's, not ours.
 *   - **signed-in** — the shell, with the organization the server returned.
 *   - **unreachable** — an explicit failure, NOT a sign-in form. Rendering the form
 *     when the server cannot be reached invites an operator to type a password into a
 *     page that cannot deliver it, which is how a transient outage becomes a
 *     credential typed into something unknown.
 */

import { useEffect, useState } from "react";

import { Shell } from "./Shell.tsx";
import { Entry } from "./FirstRun.tsx";
import { ExposureBanner } from "./ExposureBanner.tsx";
import { resolveEntry, readExposure, type Entry as EntryState } from "../lib/session.ts";
import type { EnvironmentKind } from "../lib/shell/navigation.ts";

export function App(): React.JSX.Element {
  const [state, setState] = useState<EntryState | null>(null);
  const exposure = readExposure();

  useEffect(() => {
    let live = true;
    void resolveEntry().then((resolved) => {
      if (live) setState(resolved);
    });
    return () => {
      live = false;
    };
  }, []);

  // The banner is OUTSIDE the switch, so it renders in every state including the
  // failure ones. C5 asks for a warning that cannot be dismissed, and one that only
  // appears on the signed-in path is absent exactly when somebody is poking at a
  // dashboard they should not be able to reach.
  const banner = exposure === null ? null : <ExposureBanner exposure={exposure} />;

  if (state === null) {
    return (
      <div style={{ background: "var(--tar)", minHeight: "100vh", color: "var(--chalk)" }}>
        {banner}
      </div>
    );
  }

  if (state.kind === "unreachable") {
    return (
      <div
        style={{
          background: "var(--tar)",
          minHeight: "100vh",
          color: "var(--chalk)",
          padding: "var(--space-6, 32px)",
          fontFamily: "var(--font-body)",
        }}
      >
        {banner}
        <h1 style={{ fontSize: "1.25rem", margin: "0 0 12px" }}>
          Ratline cannot reach its own API
        </h1>
        {/* §291: what broke, and what to do next. No apology, no reassurance. */}
        <p style={{ color: "var(--chalk-dim)", maxWidth: "60ch", lineHeight: 1.5 }}>
          {state.detail}. The dashboard is being served, so the process is running — the
          request for your organization did not succeed. Check the server output for a
          database or migration error before signing in again.
        </p>
      </div>
    );
  }

  if (state.kind === "signed-out") {
    return (
      <div style={{ background: "var(--tar)", minHeight: "100vh" }}>
        {banner}
        <Entry />
      </div>
    );
  }

  // Signed in. The environment is not yet a property of anything the API returns —
  // RL-M1-040 built the chip and no endpoint reports which environment an
  // installation is. Defaulted to production, which is the safe direction: the chip
  // reserves its hue for production, so being wrong this way over-warns rather than
  // under-warns. Recorded on RL-M1-058 rather than inferred from the slug.
  const environment: EnvironmentKind = "production";

  return (
    <div style={{ background: "var(--tar)", minHeight: "100vh" }}>
      {banner}
      <Shell
        environment={environment}
        path="/audit"
        labels={{ [state.organization.slug]: state.organization.name }}
      />
    </div>
  );
}
