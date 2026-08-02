/**
 * The shell's structure, as data (RL-M1-028).
 *
 * The same shape `src/api/routes.ts` uses, for the same reason and with one
 * extra one.
 *
 * THE REASON THAT CARRIES OVER: a navigation rail declared by writing JSX is
 * only knowable by rendering it. "Every rail item names the permission it
 * needs" then becomes something a reviewer checks, and the item somebody adds
 * next year is the one nobody checks.
 *
 * THE REASON SPECIFIC TO HERE: React's JSX is not erasable, so
 * `node --experimental-strip-types` refuses a `.tsx` file outright and the test
 * runner cannot import one. That is a real consequence of the 2026-08-02 ruling
 * — ADR 0001 chose no-build-step partly on SvelteKit's behalf — and the way to
 * pay it honestly is to keep everything testable out of the compiled layer. So
 * the structure lives here, in plain TypeScript, and `src/web/app/**` renders it
 * without deciding anything.
 *
 * ## Every rail item names a permission
 *
 * `requires` is an `Action` from the catalogue, so an invented name does not
 * compile — the same guarantee the route table gets. It is not decoration: a
 * rail that shows Hosts to somebody who cannot open a host is an interface that
 * teaches people their permissions by disappointing them, and §6.6's "an
 * operations console should feel like an instrument" is incompatible with a
 * control that does nothing.
 *
 * Filtering happens in `visibleNavigation`, which takes the actions the actor
 * actually holds. It is NOT an authorization check and must never be mistaken
 * for one — `can()` at the data layer is the only thing that refuses anything
 * (C3, §9). Hiding a link the caller could still reach by typing the URL is a
 * courtesy; the refusal underneath it is the security.
 */

import type { Action } from "../../../authz/catalogue.ts";
import { STATUS } from "../design/status.ts";

/**
 * The rail's marks. Line drawings, not pictograms, and named rather than
 * inlined as SVG here so `palette`-scanning stays meaningful and the icon set
 * is enumerable — an item referring to a mark that does not exist is a test
 * failure, not a blank square in the rail.
 */
export const NAV_MARKS = ["hosts", "sites", "deploys", "audit", "team"] as const;
export type NavMark = (typeof NAV_MARKS)[number];

export type NavItem = {
  readonly id: NavMark;
  /** Rail label. §4 gives these five verbatim. */
  readonly label: string;
  /** Where it goes. Matches a path template in `src/api/routes.ts` where one exists. */
  readonly href: string;
  /**
   * The permission required to reach anything behind it.
   *
   * A catalogue action, so it cannot be invented. Read actions throughout: the
   * rail leads to a list, and what you may do once there is a separate
   * question the page asks.
   */
  readonly requires: Action;
};

/**
 * §4's rail, in §4's order.
 *
 * The order is not alphabetical and is not negotiable by preference: it runs
 * from the physical to the organizational — hosts, then what runs on them, then
 * what changed them, then the record of who did it, then the people. Muscle
 * memory is the whole argument for a rail that never collapses, and muscle
 * memory is destroyed by reordering.
 */
export const NAVIGATION: readonly NavItem[] = [
  { id: "hosts", label: "Hosts", href: "/hosts", requires: "host.read" },
  { id: "sites", label: "Sites", href: "/sites", requires: "site.read" },
  { id: "deploys", label: "Deploys", href: "/deploys", requires: "deployment.read" },
  { id: "audit", label: "Audit", href: "/audit", requires: "audit_log.read" },
  { id: "team", label: "Team", href: "/team", requires: "member.read" },
];

/**
 * The items an actor holding `held` should see.
 *
 * Not an authorization check. See the module header: the refusal lives at the
 * data layer and this only decides what to draw. It is a pure function of its
 * arguments so it can be tested without a browser, a session or a database.
 */
export function visibleNavigation(
  held: readonly string[],
  items: readonly NavItem[] = NAVIGATION,
): NavItem[] {
  return items.filter((item) => held.includes(item.requires));
}

/**
 * Which item a path belongs under.
 *
 * Prefix matching on a path SEGMENT, not on the raw string: `/sites` must claim
 * `/sites/42` and must not claim `/sites-archive`. Getting that wrong puts the
 * lashing on the wrong item, which is a small bug with an outsized cost — the
 * rail is the one thing §4 promises never moves.
 */
export function activeNavItem(path: string, items: readonly NavItem[] = NAVIGATION): NavItem | null {
  return items.find((item) => path === item.href || path.startsWith(`${item.href}/`)) ?? null;
}

// ---------------------------------------------------------------------------
// Breadcrumb
// ---------------------------------------------------------------------------

export type Crumb = {
  readonly label: string;
  /** Null for the last crumb — the page you are on is not a link to itself. */
  readonly href: string | null;
};

/**
 * The breadcrumb for a path, §4's `acme / marketing-www`.
 *
 * Derived from the path rather than passed in by each screen, so a screen
 * cannot forget one or invent a different separator. `labels` renames a segment
 * that has a human name — a slug is fine, an opaque id is not, and passing an
 * id through unlabelled would put a uuid in the top bar.
 */
export function breadcrumb(path: string, labels: Readonly<Record<string, string>> = {}): Crumb[] {
  const segments = path.split("/").filter((segment) => segment !== "");
  const crumbs: Crumb[] = [];
  let href = "";
  for (const [index, segment] of segments.entries()) {
    href += `/${segment}`;
    crumbs.push({
      label: labels[segment] ?? segment,
      href: index === segments.length - 1 ? null : href,
    });
  }
  return crumbs;
}

// ---------------------------------------------------------------------------
// The environment chip, DESIGN.md §10.1 as ruled 2026-08-02
// ---------------------------------------------------------------------------

export const ENVIRONMENT_KINDS = ["production", "staging", "development", "preview"] as const;
export type EnvironmentKind = (typeof ENVIRONMENT_KINDS)[number];

export type ChipStyle = {
  /** Filled for production, outlined for everything else. */
  readonly filled: boolean;
  /** The reserved hue token, or null. Exactly one environment may name it. */
  readonly hueToken: "--env-production" | null;
  readonly labelToken: string;
};

/**
 * How an environment chip is drawn.
 *
 * The ruling: production is distinguished by form AND by one reserved hue.
 * Both, and the form half is not decoration beside the hue — it is what
 * survives a monochrome display, a colour-deficient reader, and a photograph of
 * a screen, which is the same reasoning as §1's "status is never colour alone".
 *
 * Everything that is not production is drawn identically, deliberately. §4 asks
 * only that production be unmissable; giving staging its own treatment would
 * start the second palette the ruling exists to prevent.
 */
export function chipStyle(kind: EnvironmentKind): ChipStyle {
  return kind === "production"
    ? { filled: true, hueToken: "--env-production", labelToken: "--env-production-on" }
    : { filled: false, hueToken: null, labelToken: "--chalk-dim" };
}

// ---------------------------------------------------------------------------
// The tension line, DESIGN.md §5
// ---------------------------------------------------------------------------

export const TENSION_STATES = ["rest", "working", "attention", "fail"] as const;
export type TensionState = (typeof TENSION_STATES)[number];

export type TensionAppearance = {
  readonly state: TensionState;
  /** The token the 2px rule is painted in. */
  readonly colorToken: string;
  /** Whether the travelling highlight runs. False under reduced motion. */
  readonly travelling: boolean;
  /** What a screen reader is told, since motion carries nothing on its own. */
  readonly announcement: string;
};

/**
 * One live operation reduced to what the line shows.
 *
 * §5: "One element, one meaning everywhere: something is under load right now."
 * So the input is the set of operations in flight, not a screen's opinion, and
 * the worst of them wins — a failure during a deploy must not be painted as a
 * deploy.
 */
export type Operation = { readonly state: Exclude<TensionState, "rest">; readonly label: string };

const SEVERITY: readonly Exclude<TensionState, "rest">[] = ["fail", "attention", "working"];

export function tensionAppearance(
  operations: readonly Operation[],
  reducedMotion: boolean,
): TensionAppearance {
  const worst = SEVERITY.find((state) => operations.some((operation) => operation.state === state));

  if (worst === undefined) {
    return {
      state: "rest",
      colorToken: "--tension-rest",
      travelling: false,
      announcement: "Nothing running.",
    };
  }

  const leading = operations.find((operation) => operation.state === worst);
  return {
    state: worst,
    // Read out of the status registry rather than assembled from the state
    // name. The three non-rest tension states ARE status ids, and building the
    // token by hand would be a second place that has to agree with
    // `design/status.ts` about what they are called.
    colorToken: STATUS[worst].colorToken,
    // §8: reduced motion removes the travel. The line stays SOLID in the status
    // colour rather than disappearing — "no information is carried by motion
    // alone" (§5), so switching the travel off must not switch meaning off.
    travelling: !reducedMotion,
    announcement: leading?.label ?? "Something is running.",
  };
}
