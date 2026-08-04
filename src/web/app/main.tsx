/**
 * Browser entry (RL-M1-028).
 *
 * Two jobs and no decisions: install the stylesheet the design tokens generate,
 * and mount the shell. Anything that could be decided here is decided in
 * `src/web/lib/shell/navigation.ts` instead, where the test runner can reach it
 * without a build step.
 *
 * THE FONT IMPORTS BELOW MUST MATCH `FONT_CSS_IMPORTS` EXACTLY. They cannot be
 * generated from it — a bundler resolves `import` specifiers statically, and a
 * loop over an array produces nothing it can see — so the list is written twice
 * and `test/toolchain/shell_structure.test.ts` asserts the two agree. The
 * failure that guards against is a face that renders in development, where a
 * missing weight falls back silently, and is wrong in the built bundle.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "@fontsource-variable/archivo/wdth.css";
import "@fontsource/public-sans/400.css";
import "@fontsource/public-sans/500.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/700.css";

import { renderDesignStylesheet } from "../lib/design/css.ts";
import { App } from "./App.tsx";
import { Shell } from "./Shell.tsx";
import { ClaimForm, Entry, SignInForm } from "./FirstRun.tsx";
import type { EnvironmentKind, Operation } from "../lib/shell/navigation.ts";

// Emitted from the token registry rather than kept as a `.css` file, so a token
// added in TypeScript cannot be missing from the stylesheet. Appended during
// module evaluation, before React mounts anything.
const style = document.createElement("style");
style.textContent = renderDesignStylesheet();
document.head.append(style);

const mount = document.querySelector("#ratline");
if (mount === null) throw new Error("the mount point is missing from index.html");

/**
 * The dev harness, still here and now strictly opt-in (RL-M1-058).
 *
 * Every branch below requires an explicit query parameter. WITHOUT one, `<App />`
 * renders and asks the server where we stand — which is the real behaviour, and until
 * this commit was unreachable: the default rendered the shell with `marketing-www` as
 * placeholder data, so opening the dashboard showed a frame around a site that does
 * not exist.
 *
 * Kept rather than deleted because the states it reaches are still worth looking at
 * and several are hard to produce for real: `?state=fail` needs a failing operation,
 * `?screen=claim` needs an unclaimed installation, `?env=staging` needs an endpoint
 * that reports the environment and none exists yet. They are review tools, and now
 * they cannot be what an operator sees by accident.
 */
const params = new URLSearchParams(globalThis.location.search);

const HARNESS_SCREENS: Readonly<Record<string, React.JSX.Element>> = {
  entry: <Entry />,
  claim: <ClaimForm />,
  signin: <SignInForm />,
};

const screen = params.get("screen");
const forced = screen === null ? undefined : HARNESS_SCREENS[screen];

/** `?path=` or `?state=` or `?env=` asks for the shell with made-up data. */
function harnessShell(): React.JSX.Element | undefined {
  const path = params.get("path");
  const state = params.get("state");
  const env = params.get("env");
  if (path === null && state === null && env === null) return undefined;

  const operations: Operation[] =
    state === "working" || state === "attention" || state === "fail"
      ? [{ state, label: `Demonstrating the ${state} state` }]
      : [];

  return (
    <Shell
      environment={(env ?? "production") as EnvironmentKind}
      path={path ?? "/sites/marketing-www"}
      operations={operations}
      labels={{ "marketing-www": "marketing-www" }}
    />
  );
}

const harness = forced ?? harnessShell();

createRoot(mount).render(
  <StrictMode>{harness ?? <App />}</StrictMode>,
);
