/**
 * Serving the built dashboard (RL-M1-057).
 *
 * The route table declares 30 API routes and the server bound every one it has a
 * repository for — and nothing served a single byte of HTML, so a browser reaching
 * the root got a framework 404. `src/web/app` has existed since RL-M1-022 and
 * `npm run build:web` has always produced `dist/web`; the two were simply never
 * connected. The same shape as the three RL-M1-055 found: built, tested, never wired.
 *
 * ## Why this is not `serveStatic("*")`
 *
 * A catch-all static handler registered alongside 30 API routes is two bugs waiting
 * to happen. It can shadow an API route — Hono matches in registration order, so a
 * static handler that answers `/audit` from a file named `audit` would silently
 * replace the audit endpoint — and it can serve a file outside the build directory if
 * a path traversal survives normalisation.
 *
 * So this module answers only paths it recognises, from a manifest built by reading
 * the directory once at startup:
 *
 *   - A path in the manifest is served from the manifest's own record of it. Nothing
 *     is resolved from the request, so there is no traversal to defeat: the request
 *     selects a key in a map, and a key that is not in the map is not served.
 *   - Any path that collides with a declared API route is REFUSED at startup, loudly,
 *     rather than silently losing. A build that shipped a file called `audit` is a
 *     mistake, and a mistake that manifests as a missing audit endpoint months later
 *     is the worst possible way to find out.
 *   - Everything else falls back to index.html, because the dashboard routes on the
 *     client. That fallback is what makes a bookmark to /hosts work.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative, resolve } from "node:path";

import { ROUTES } from "./routes.ts";

/**
 * Content types, by extension.
 *
 * An allow-list rather than a lookup library. A file whose extension is not here is
 * not served at all, which means the build cannot start shipping a type nobody
 * considered — and `application/octet-stream` as a fallback would let it.
 */
const CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".woff2": "font/woff2",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

export type Asset = {
  readonly body: Buffer;
  readonly contentType: string;
  /**
   * Whether this asset may be cached forever.
   *
   * True only for content-hashed files. Vite names them `index-DhclLIu3.js`, so the
   * name changes whenever the bytes do and an immutable cache is safe. index.html is
   * never immutable: it is the file that points at the hashed ones, and caching it
   * would pin a browser to an old build's asset names after a deploy.
   */
  readonly immutable: boolean;
};

export type Dashboard = {
  /** Path to asset, e.g. "/assets/index-DhclLIu3.js". */
  readonly assets: ReadonlyMap<string, Asset>;
  readonly index: Asset;
};

/**
 * What the server tells the page about its own exposure (RL-M1-058).
 *
 * INJECTED into the HTML rather than fetched, and that placement is the decision. C5
 * wants a warning that cannot be dismissed, so it must survive the two cases a fetch
 * would not: before anyone signs in, and when the API is failing. A warning that needs
 * a working session to appear is absent exactly when somebody is most likely to be
 * poking at an exposed dashboard.
 */
export type ExposureNotice = {
  readonly level: string;
  readonly warning: string | null;
  readonly caveat: string | null;
};

/**
 * The index with the exposure notice inlined.
 *
 * `JSON.stringify` inside a `<script type="application/json">` block, with `<` escaped.
 * The notice is server-authored and contains no user input, but escaping it anyway is
 * the difference between "this string happens to be safe" and "this cannot inject" —
 * and the second is the only one that survives somebody later putting a hostname in it.
 */
export function indexWithExposure(index: Asset, notice: ExposureNotice): Asset {
  const payload = JSON.stringify(notice).replaceAll("<", "\\u003c");
  const html = index.body
    .toString("utf8")
    .replace(
      "</head>",
      `<script type="application/json" id="ratline-exposure">${payload}</script></head>`,
    );

  return { ...index, body: Buffer.from(html, "utf8") };
}

export class DashboardUnavailable extends Error {
  constructor(directory: string, cause: string) {
    super(
      `The dashboard is not built, so there is nothing to serve at the root.\n` +
        `  looked in: ${directory}\n` +
        `  ${cause}\n\n` +
        `Run \`npm run build:web\` and start again. The API still works without it.`,
    );
    this.name = "DashboardUnavailable";
  }
}

/** Every path the API claims, so a static file can never take one. */
function apiPaths(): ReadonlySet<string> {
  const claimed = new Set<string>();
  for (const route of ROUTES) {
    // The pattern's first segment is what matters: `/projects/:projectId` claims
    // `/projects`, and a file called `projects` would shadow the collection route.
    const [, first] = route.path.split("/");
    if (first !== undefined && first !== "") claimed.add(`/${first}`);
  }
  return claimed;
}

/**
 * Read the build output once, at startup.
 *
 * Read into memory rather than served from disk per request, and the reason is not
 * performance. A handler that opens a file named by the request is a handler that can
 * be made to open the wrong file; a handler that looks up a key in a map built before
 * any request arrived cannot. The dashboard is a few hundred kilobytes, so the cost of
 * holding it is not worth a traversal bug.
 */
export function loadDashboard(directory: string): Dashboard {
  const root = resolve(directory);

  let entries: readonly string[];
  try {
    if (!statSync(root).isDirectory()) throw new Error("not a directory");
    entries = walk(root, root);
  } catch (cause) {
    throw new DashboardUnavailable(
      root,
      cause instanceof Error ? cause.message : "cannot be read",
    );
  }

  const claimed = apiPaths();
  const assets = new Map<string, Asset>();
  const collisions: string[] = [];

  for (const absolute of entries) {
    const path = `/${relative(root, absolute).split("\\").join("/")}`;
    const extension = extname(path).toLowerCase();
    const contentType = CONTENT_TYPES[extension];

    // Unknown extension: not served, and not an error either. A build that emits a
    // .txt licence file should not stop the server, it should just not be reachable.
    if (contentType === undefined) continue;

    const [, first] = path.split("/");
    if (first !== undefined && claimed.has(`/${first}`)) {
      collisions.push(path);
      continue;
    }

    assets.set(path, {
      body: readFileSync(absolute),
      contentType,
      // Vite content-hashes everything under assets/. index.html is not hashed and
      // must not be immutable.
      immutable: path.startsWith("/assets/") && path !== "/index.html",
    });
  }

  if (collisions.length > 0) {
    // Refused at startup rather than losing quietly. A file that shadows an API
    // route manifests as an endpoint that stopped existing, which is close to
    // undiagnosable from the outside.
    throw new Error(
      `the dashboard build contains ${String(collisions.length)} file(s) whose path collides ` +
        `with an API route: ${collisions.join(", ")}.\n` +
        `Serving them would shadow the endpoint. Rename them in src/web/app, or the ` +
        `endpoint disappears and nothing says so.`,
    );
  }

  const index = assets.get("/index.html");
  if (index === undefined) {
    throw new DashboardUnavailable(root, "there is no index.html in the build output");
  }

  return { assets, index };
}

function walk(root: string, directory: string): readonly string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory()) {
      found.push(...walk(root, absolute));
      continue;
    }
    if (entry.isFile()) found.push(absolute);
  }
  return found;
}

/**
 * The asset for a request path, or the index for anything unrecognised.
 *
 * `null` only when the path belongs to the API, so the caller can let the real route
 * answer. Everything else gets the index, because the dashboard routes on the client
 * and a bookmark to a client route must not 404.
 */
export function assetFor(dashboard: Dashboard, path: string): Asset | null {
  const claimed = apiPaths();
  const [, first] = path.split("/");
  if (first !== undefined && claimed.has(`/${first}`)) return null;

  return dashboard.assets.get(path) ?? dashboard.index;
}

/**
 * The headers an asset is served with.
 *
 * `nosniff` on everything: without it a browser may decide a file the allow-list
 * called text/css is really HTML and execute it. The dashboard is served from the same
 * origin as the API and holds the session cookie, so a mis-sniffed asset is a script
 * running with the operator's session.
 */
export function headersFor(asset: Asset): Record<string, string> {
  return {
    "content-type": asset.contentType,
    "x-content-type-options": "nosniff",
    "cache-control": asset.immutable
      ? "public, max-age=31536000, immutable"
      : // The index must be revalidated, or a browser keeps pointing at an old
        // build's hashed asset names after a deploy and the dashboard breaks in a
        // way that clears itself only when somebody hard-reloads.
        "no-cache",
  };
}
