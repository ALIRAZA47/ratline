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
import { Shell } from "./Shell.tsx";
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
 * A dev harness, and openly one.
 *
 * There is no router and no API yet, so the shell has nothing to get its state
 * from. Reading it off the query string means the browser checks this task's
 * acceptance depends on are REPRODUCIBLE — `?state=fail`, `?env=staging` — and
 * that nobody has to edit a file and reload to see the tension line under load.
 *
 * This block goes away when routing arrives (RL-M1-030). It is deliberately the
 * only place in `src/web/app` that reads anything, so removing it later cannot
 * break a component.
 */
const params = new URLSearchParams(globalThis.location.search);
const environment = (params.get("env") ?? "production") as EnvironmentKind;
const state = params.get("state");
const operations: Operation[] =
  state === "working" || state === "attention" || state === "fail"
    ? [{ state, label: `Demonstrating the ${state} state` }]
    : [];

createRoot(mount).render(
  <StrictMode>
    <Shell
      environment={environment}
      path={params.get("path") ?? "/sites/marketing-www"}
      operations={operations}
      labels={{ "marketing-www": "marketing-www" }}
    />
  </StrictMode>,
);
