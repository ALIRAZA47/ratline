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
import { screenFor } from "./screens.tsx";
import { resolveEntry, readExposure, type Entry as EntryState } from "../lib/session.ts";
import type { EnvironmentKind } from "../lib/shell/navigation.ts";

export function App(): React.JSX.Element {
  const [state, setState] = useState<EntryState | null>(null);
  /**
   * The current path, from the address bar (RL-M1-059).
   *
   * `history.pushState` and `popstate` rather than a router library: five destinations
   * and no nested routes do not earn a dependency (§6.7), and the browser already
   * implements back and bookmarking correctly. `dashboard.ts` serves index.html for
   * any unclaimed path, which is what makes a bookmark to /audit work on a cold load.
   */
  const [path, setPath] = useState(globalThis.location.pathname);
  const exposure = readExposure();

  useEffect(() => {
    const onPop = () => setPath(globalThis.location.pathname);
    globalThis.addEventListener("popstate", onPop);
    return () => globalThis.removeEventListener("popstate", onPop);
  }, []);

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
          padding: "var(--space-lg)",
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
  const Screen = screenFor(path === "/" ? "/audit" : path);

  return (
    <div
      style={{ background: "var(--tar)", minHeight: "100vh" }}
      // Rail navigation, intercepted here rather than in the Rail component, so the
      // rail stays a presentation of data and has no opinion about history. A click
      // with a modifier key is left alone — an operator opening a destination in a new
      // tab is doing something reasonable and a router that swallows that is a router
      // people fight.
      onClick={(event) => {
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey) return;
        const anchor = (event.target as HTMLElement).closest("a");
        const href = anchor?.getAttribute("href");
        if (anchor === null || href === null || href === undefined) return;
        if (!href.startsWith("/") || href.startsWith("//")) return;
        event.preventDefault();
        globalThis.history.pushState(null, "", href);
        setPath(href);
      }}
    >
      {banner}
      <Shell
        environment={environment}
        path={path === "/" ? "/audit" : path}
        labels={{ [state.organization.slug]: state.organization.name }}
      >
        <Screen />
      </Shell>
    </div>
  );
}
