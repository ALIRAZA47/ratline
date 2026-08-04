/**
 * The board's entry point (RL-M1-061).
 *
 * The data arrives on `window` from `data.js`, which `./scripts/tasks board` writes and
 * `index.html` loads before this module. A `fetch` would be cleaner and does not work from
 * `file://`, which is where this page is opened — so the awkward global is the price of the
 * board being a file somebody can double-click.
 *
 * A missing or malformed payload REFUSES with an instruction rather than rendering an empty
 * board. An empty board looks like a tracker with no tasks in it, which is the one thing it
 * must never be mistaken for.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Board, type BoardData } from "./board.tsx";
import "./board.css";

declare global {
  // eslint-disable-next-line no-var
  var __RATLINE_BOARD__: BoardData | undefined;
}

const mount = document.getElementById("board");
if (mount === null) throw new Error("no #board element to render into");

const data = globalThis.__RATLINE_BOARD__;

if (data === undefined || !Array.isArray(data.tasks)) {
  mount.innerHTML =
    '<div class="refusal">' +
    "<h1>No board data</h1>" +
    "<p>This page loads <code>data.js</code>, which is written by the tracker rather than " +
    "bundled — so the build can stay put while the data changes. It is missing or unreadable.</p>" +
    "<p>Run <code>./scripts/tasks board</code> and reload.</p>" +
    "</div>";
} else {
  createRoot(mount).render(
    <StrictMode>
      <Board data={data} />
    </StrictMode>,
  );
}
