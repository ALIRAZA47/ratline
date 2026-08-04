/**
 * The task board's build (RL-M1-061).
 *
 * A SECOND Vite root rather than another entry in the product's config, deliberately.
 * `vite.config.ts` builds `src/web/app`, which is Ratline's dashboard — a thing operators
 * see. This is internal tooling, and giving them one config would mean a change to the
 * board's build could break the product's, and that a `dist/web` deploy could ship the
 * board's assets alongside the dashboard's.
 *
 * No new dependencies: React and Vite are already here for the product. The board reuses
 * them rather than earning a second UI stack (§6.7).
 */
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: "tools/board",
  base: "./",
  plugins: [react()],
  build: {
    // Into .ratline/, which is gitignored. The board is a local view, not a document —
    // a committed build would churn on every status change and be stale in every branch
    // that had not rebuilt it.
    outDir: "../../.ratline/board",
    emptyOutDir: true,
  },
});
