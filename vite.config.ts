/**
 * The browser bundle (RL-M1-028).
 *
 * This is the ONLY build step in the project, and it exists because of one
 * fact: React's JSX is not erasable syntax, so `node --experimental-strip-types`
 * refuses a `.tsx` file and `--experimental-transform-types` refuses it too.
 * ADR 0001 chose no-build-step partly on SvelteKit's behalf; the 2026-08-02
 * ruling chose React, and this is the bill for it.
 *
 * The bill is kept small on purpose. Vite compiles `src/web/app/**` and nothing
 * else — the control plane, the repositories, the migrations, the design tokens
 * and the shell's structure all still run unbuilt, which is why the test suite
 * can reach them without a bundler in the loop.
 *
 * No dev-server proxy is configured. There is no API to proxy to yet
 * (`src/api/server.ts` does not exist), and a proxy pointing at a port nobody
 * listens on is a configuration that looks finished and is not.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "src/web/app",
  plugins: [react()],
  server: {
    // C5: the dashboard binds to loopback. The dev server is not the product,
    // but defaulting it the other way would train the habit the constraint
    // exists to prevent.
    host: "127.0.0.1",
    port: 7712,
    strictPort: true,
  },
  build: {
    outDir: "../../../dist/web",
    emptyOutDir: true,
  },
});
