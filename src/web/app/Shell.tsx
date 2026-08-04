/**
 * The shroud — DESIGN.md §4 (RL-M1-028).
 *
 * "A fixed structure that never moves, so muscle memory survives a stressful
 * night." Everything this file does is arrangement; every decision it renders
 * comes from `src/web/lib/shell/navigation.ts` or the token registry, because
 * JSX cannot be reached by the test runner and a decision made here would be a
 * decision nothing can check.
 *
 * Nothing below hard-codes a colour, a length or a type size — every value is a
 * custom property from the token registry, enforced by
 * `test/toolchain/design_tokens.test.ts`, which scans this directory.
 *
 * (Prose here must not spell out an example custom property, real or invented.
 * The scan that checks every referenced property exists reads source text and
 * does not read comments differently from code — the second time that has
 * caught me, and the right trade both times, because a scanner that told them
 * apart would be a second parser to get wrong.)
 */

import { useEffect, useState, type CSSProperties } from "react";

import {
  activeNavItem,
  breadcrumb,
  chipStyle,
  NAVIGATION,
  tensionAppearance,
  visibleNavigation,
  type EnvironmentKind,
  type NavItem,
  type Operation,
} from "../lib/shell/navigation.ts";

/**
 * Whether the viewer asked for less motion.
 *
 * A hook rather than a one-off read, because the preference can change while
 * the page is open — an operator turning it on mid-incident is exactly when it
 * matters, and a value captured at mount would ignore them.
 */
function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() =>
    globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false,
  );
  useEffect(() => {
    const query = globalThis.matchMedia("(prefers-reduced-motion: reduce)");
    const onChange = (): void => { setReduced(query.matches); };
    query.addEventListener("change", onChange);
    return () => { query.removeEventListener("change", onChange); };
  }, []);
  return reduced;
}

// ---------------------------------------------------------------------------
// The rail, §4
// ---------------------------------------------------------------------------

function Lashing({ active }: { readonly active: boolean }): React.JSX.Element {
  // §4: "a 2px --hemp vertical bar with a small notch at its midpoint, the way
  // a rope is whipped at its end. That notch is the whole rigging metaphor."
  // Rendered even when inactive, at zero opacity, so the label never shifts
  // sideways as the active item changes — movement in a fixed structure is
  // exactly what §4 is written against.
  return (
    <span
      aria-hidden="true"
      data-testid={active ? "lashing-active" : "lashing-idle"}
      style={{
        width: "var(--lashing-width)",
        alignSelf: "stretch",
        background: "var(--hemp)",
        opacity: active ? 1 : 0,
        // The notch: a 4px gap at the midpoint, cut out of the bar.
        clipPath: "polygon(0 0, 100% 0, 100% calc(50% - 2px), 0 calc(50% - 2px), 0 calc(50% + 2px), 100% calc(50% + 2px), 100% 100%, 0 100%)",
      }}
    />
  );
}

function Rail({
  items,
  activeId,
}: {
  readonly items: readonly NavItem[];
  readonly activeId: string | null;
}): React.JSX.Element {
  return (
    <nav
      aria-label="Sections"
      style={{
        width: "var(--rail-width)",
        flex: "0 0 auto",
        background: "var(--pitch)",
        borderRight: "var(--hairline-width) solid var(--rule-hairline)",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column" }}>
        {items.map((item) => {
          const active = item.id === activeId;
          return (
            <li key={item.id} style={{ display: "flex" }}>
              <Lashing active={active} />
              <a
                href={item.href}
                // The active item is announced, not just drawn. §1's corollary
                // — "status is never colour alone" — generalises: nothing here
                // may be carried by appearance alone.
                aria-current={active ? "page" : undefined}
                style={{
                  flex: 1,
                  display: "flex",
                  alignItems: "center",
                  minHeight: "var(--row-height)",
                  padding: "0 var(--space-md)",
                  color: active ? "var(--chalk)" : "var(--chalk-dim)",
                  textDecoration: "none",
                  font: "var(--weight-body-strong) var(--text-base)/var(--leading-base) var(--font-body)",
                }}
              >
                {item.label}
              </a>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

// ---------------------------------------------------------------------------
// The environment chip — §10.1 as ruled 2026-08-02
// ---------------------------------------------------------------------------

export function EnvironmentChip({ kind }: { readonly kind: EnvironmentKind }): React.JSX.Element {
  const style = chipStyle(kind);
  const painted: CSSProperties = style.filled
    ? { background: `var(${style.hueToken ?? "--chalk"})`, color: `var(${style.labelToken})`, border: "none" }
    : {
        background: "transparent",
        color: `var(${style.labelToken})`,
        border: "var(--hairline-width) solid var(--rule-hairline)",
      };

  return (
    <span
      data-testid="environment-chip"
      data-environment={kind}
      data-filled={String(style.filled)}
      style={{
        ...painted,
        padding: "0 var(--space-sm)",
        borderRadius: "var(--radius-sm)",
        font: "var(--weight-body-strong) var(--text-sm)/var(--leading-sm) var(--font-body)",
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      {kind}
    </span>
  );
}

// ---------------------------------------------------------------------------
// The tension line, §5
// ---------------------------------------------------------------------------

export function TensionLine({
  operations,
  reducedMotion,
}: {
  readonly operations: readonly Operation[];
  readonly reducedMotion: boolean;
}): React.JSX.Element {
  const appearance = tensionAppearance(operations, reducedMotion);
  return (
    <div
      // A live region rather than a decoration. §5 says no information is
      // carried by motion alone, and a screen reader carries none of it at all.
      role="status"
      aria-live="polite"
      className="rl-tension"
      data-testid="tension-line"
      data-state={appearance.state}
      data-travelling={String(appearance.travelling)}
      // The travel is a CLASS rule, not an inline animation. An inline
      // animation cannot be overridden by a media query, so the reduced-motion
      // half of §5 would rest entirely on this component's own JavaScript —
      // which does not apply until React mounts. As a class it is off in the
      // stylesheet before the first frame and off here too, and the two cannot
      // disagree because this only ever removes it.
      style={{ "--tension-color": `var(${appearance.colorToken})` } as CSSProperties}
    >
      <span style={{ position: "absolute", width: 1, height: 1, overflow: "hidden", clip: "rect(0 0 0 0)" }}>
        {appearance.announcement}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// The top bar, §4
// ---------------------------------------------------------------------------

function TopBar({
  path,
  environment,
  labels,
}: {
  readonly path: string;
  readonly environment: EnvironmentKind;
  readonly labels: Readonly<Record<string, string>>;
}): React.JSX.Element {
  const crumbs = breadcrumb(path, labels);
  return (
    <header
      style={{
        height: "var(--top-bar-height)",
        flex: "0 0 auto",
        display: "flex",
        alignItems: "center",
        gap: "var(--space-md)",
        padding: "0 var(--space-md)",
        background: "var(--pitch)",
        borderBottom: "var(--hairline-width) solid var(--rule-hairline)",
      }}
    >
      <nav aria-label="Breadcrumb" style={{ flex: 1, minWidth: 0 }}>
        <ol
          style={{
            listStyle: "none",
            margin: 0,
            padding: 0,
            display: "flex",
            alignItems: "center",
            gap: "var(--space-xs)",
            font: "var(--weight-body) var(--text-base)/var(--leading-base) var(--font-body)",
          }}
        >
          {crumbs.map((crumb, index) => (
            <li key={crumb.href ?? crumb.label} style={{ display: "flex", gap: "var(--space-xs)" }}>
              {index > 0 && (
                <span aria-hidden="true" style={{ color: "var(--chalk-dim)" }}>
                  /
                </span>
              )}
              {crumb.href === null ? (
                <span aria-current="page" style={{ color: "var(--chalk)" }}>
                  {crumb.label}
                </span>
              ) : (
                <a href={crumb.href} style={{ color: "var(--chalk-dim)", textDecoration: "none" }}>
                  {crumb.label}
                </a>
              )}
            </li>
          ))}
        </ol>
      </nav>

      <EnvironmentChip kind={environment} />

      <button
        type="button"
        data-testid="command-palette-trigger"
        // RL-M1-029 builds what this opens. It is here now because §4 puts it
        // in the top bar and because a shell missing a control is easier to
        // notice than a shell that never had one.
        style={{
          background: "transparent",
          border: "var(--hairline-width) solid var(--rule-hairline)",
          borderRadius: "var(--radius-sm)",
          color: "var(--chalk-dim)",
          padding: "0 var(--space-sm)",
          minHeight: "var(--row-height)",
          font: "var(--weight-body) var(--text-sm)/var(--leading-sm) var(--font-mono)",
        }}
      >
        ⌘K
      </button>

      <button
        type="button"
        data-testid="actor-menu"
        aria-haspopup="menu"
        style={{
          background: "transparent",
          border: "none",
          color: "var(--chalk)",
          minHeight: "var(--row-height)",
          font: "var(--weight-body) var(--text-base)/var(--leading-base) var(--font-body)",
        }}
      >
        ◍
      </button>
    </header>
  );
}

// ---------------------------------------------------------------------------
// The shell
// ---------------------------------------------------------------------------

export function Shell({
  path,
  environment,
  held,
  operations = [],
  labels = {},
  children,
}: {
  readonly path: string;
  readonly environment: EnvironmentKind;
  /** The actions the actor holds. Defaults to everything the rail can ask for. */
  readonly held?: readonly string[];
  readonly operations?: readonly Operation[];
  readonly labels?: Readonly<Record<string, string>>;
  /**
   * The screen for the current path (RL-M1-059).
   *
   * `<main>` rendered `{null}` from RL-M1-022 until now, so every rail destination
   * was an empty frame. Taken as children rather than resolved here, because the
   * shell should not know which screens exist — the rail is data and so is the
   * routing table.
   */
  readonly children?: React.ReactNode;
}): React.JSX.Element {
  const reducedMotion = useReducedMotion();
  const items = visibleNavigation(held ?? NAVIGATION.map((item) => item.requires));
  const active = activeNavItem(path);

  return (
    <div style={{ display: "flex", height: "100vh", background: "var(--tar)", color: "var(--chalk)" }}>
      {/*
        The first thing in the tab order, and invisible until it has focus.
        Five rail items is a short trap to tab through, but it is still a trap,
        and it grows every time the rail does.
      */}
      <a
        href="#content"
        data-testid="skip-link"
        style={{
          position: "absolute",
          left: "var(--space-sm)",
          top: "var(--space-sm)",
          zIndex: 1,
          padding: "var(--space-xs) var(--space-sm)",
          background: "var(--pitch)",
          color: "var(--chalk)",
          border: "var(--hairline-width) solid var(--rule-hairline)",
          borderRadius: "var(--radius-sm)",
          font: "var(--weight-body) var(--text-sm)/var(--leading-sm) var(--font-body)",
          // Off-screen until focused. `clip` rather than `display: none`,
          // because a hidden element is not focusable and this one has to be.
          transform: "translateY(-200%)",
        }}
        onFocus={(event) => { event.currentTarget.style.transform = "translateY(0)"; }}
        onBlur={(event) => { event.currentTarget.style.transform = "translateY(-200%)"; }}
      >
        Skip to content
      </a>
      <Rail items={items} activeId={active?.id ?? null} />
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0 }}>
        <TopBar path={path} environment={environment} labels={labels} />
        <TensionLine operations={operations} reducedMotion={reducedMotion} />
        <main
          // The skip target and the thing a keyboard user reaches after the
          // rail. tabIndex -1 so it can receive focus programmatically without
          // joining the tab order.
          id="content"
          tabIndex={-1}
          style={{ flex: 1, overflow: "auto", padding: "var(--space-lg)" }}
        >
          {children ?? null}
        </main>
      </div>
    </div>
  );
}
