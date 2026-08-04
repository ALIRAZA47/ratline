/**
 * The C5 exposure warning, in the interface (RL-M1-058).
 *
 * C5: "Detect public reachability and show a loud, non-dismissable warning." The
 * detection has existed since RL-M1-023 and the warning reached stderr only — so an
 * operator who opened a browser and never read the container logs saw nothing at all.
 * `docs/gates/M1.md` recorded that acceptance as unverifiable without a rendered
 * dashboard; this is the rendered dashboard.
 *
 * ## Non-dismissable means there is no dismiss control
 *
 * Not "a dismiss control that reopens", not "collapsed by default". There is no
 * button, no close icon, and no local-storage key — because every one of those is a
 * thing somebody can click once and then never see again, which is precisely what C5
 * forbids. It costs a strip of vertical space on every screen, permanently, and that
 * cost is the feature: an operator who finds it annoying is being annoyed into fixing
 * the exposure.
 *
 * The caveat is shown alongside the warning rather than behind a disclosure, because
 * it is the part that keeps the warning honest: the check reads interfaces and cannot
 * see a NAT port-forward, a load balancer or a reverse proxy. A warning that presented
 * itself as complete would be worse than none.
 */

import type { Exposure } from "../lib/session.ts";

export function ExposureBanner({ exposure }: { readonly exposure: Exposure }): React.JSX.Element | null {
  // Nothing to say when the bind is loopback and no warning was produced. The absence
  // of a banner is the "this is fine" state; a green "not exposed" badge would be one
  // more thing to habituate to.
  if (exposure.warning === null) return null;

  return (
    <div
      // `alert` rather than `status`: a screen reader should interrupt for this. It is
      // the one thing on the page that changes what an operator should do next.
      role="alert"
      style={{
        background: "var(--st-fail)",
        color: "var(--st-fail-on)",
        borderBottom: "2px solid var(--st-fail-mark)",
        padding: "10px 16px",
        fontFamily: "var(--font-body)",
        fontSize: "0.8125rem",
        lineHeight: 1.45,
        display: "flex",
        gap: "12px",
        alignItems: "flex-start",
      }}
    >
      <span aria-hidden="true" style={{ fontWeight: 700, flexShrink: 0 }}>
        !!
      </span>
      <span>
        <strong style={{ fontWeight: 600 }}>{exposure.warning}</strong>
        {exposure.caveat === null ? null : (
          <span style={{ display: "block", marginTop: "4px", opacity: 0.85 }}>
            {exposure.caveat}
          </span>
        )}
      </span>
    </div>
  );
}
