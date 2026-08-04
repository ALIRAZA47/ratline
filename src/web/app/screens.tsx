/**
 * The screens behind the rail (RL-M1-059).
 *
 * The shell has had five rail destinations since RL-M1-022 and nothing behind any of
 * them. Three have a bound endpoint and get a real screen. Two do not exist yet, and
 * they get a state that says so and names the task — because §291 asks empty states
 * to invite action rather than apologise, and "Hosts" rendering an empty table would
 * claim there are no hosts when the truth is that Ratline cannot manage one yet.
 *
 * | Rail     | Endpoint                | State                                  |
 * | -------- | ----------------------- | -------------------------------------- |
 * | Hosts    | none                    | not built — RL-M2-005 reports inventory |
 * | Sites    | `GET /projects`         | real, and honest that these are PROJECTS |
 * | Deploys  | none                    | not built — M3                          |
 * | Audit    | `GET /audit`            | real                                    |
 * | Team     | `GET /members`          | real                                    |
 *
 * ## Sites shows projects, and says so
 *
 * The rail says Sites; the only bound read is `GET /projects`. A project CONTAINS
 * sites — sites arrive in M3 — so rendering projects under a heading that says "Sites"
 * would be a quiet mislabelling of the data model, and the kind that survives because
 * it looks plausible. The screen names what it is listing instead.
 *
 * ## Every screen distinguishes four outcomes
 *
 * Loading, empty, refused and failed are four different things and each needs a
 * different sentence. Collapsing "the server refused you" into "there is nothing here"
 * is the specific mistake that makes a permissions problem look like an empty account,
 * and an operator then goes looking for data that was never missing.
 */

import { useEffect, useState } from "react";

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

type Load<T> =
  | { readonly kind: "loading" }
  | { readonly kind: "ready"; readonly value: T }
  /** The server refused. §6.3 makes 404 and 403 identical, so this covers both. */
  | { readonly kind: "refused" }
  | { readonly kind: "failed"; readonly detail: string };

/**
 * Read a JSON collection from the API.
 *
 * A 401 is NOT handled here. It means the session ended mid-session, and the right
 * response is to send the operator back to sign in rather than show one pane's error —
 * so it is reported as `failed` and `App` re-probes. Handling it locally would leave
 * four other panes still rendering as though signed in.
 */
function useCollection<T>(path: string): Load<T> {
  const [state, setState] = useState<Load<T>>({ kind: "loading" });

  useEffect(() => {
    let live = true;
    setState({ kind: "loading" });

    void (async () => {
      try {
        const response = await fetch(path, {
          credentials: "same-origin",
          headers: { accept: "application/json" },
        });
        if (!live) return;

        if (response.status === 403 || response.status === 404) {
          setState({ kind: "refused" });
          return;
        }
        if (!response.ok) {
          setState({ kind: "failed", detail: `the server answered ${String(response.status)}` });
          return;
        }
        setState({ kind: "ready", value: (await response.json()) as T });
      } catch (cause) {
        if (!live) return;
        setState({
          kind: "failed",
          detail: cause instanceof Error ? cause.message : "the request failed",
        });
      }
    })();

    return () => {
      live = false;
    };
  }, [path]);

  return state;
}

// ---------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------

const pane: React.CSSProperties = {
  padding: "24px 28px",
  fontFamily: "var(--font-body)",
  color: "var(--chalk)",
  overflowY: "auto",
  height: "100%",
};

const heading: React.CSSProperties = {
  fontFamily: "var(--font-display, var(--font-body))",
  fontSize: "1.125rem",
  fontWeight: 600,
  margin: "0 0 4px",
};

const note: React.CSSProperties = {
  color: "var(--chalk-dim)",
  fontSize: "0.8125rem",
  margin: "0 0 20px",
  maxWidth: "72ch",
  lineHeight: 1.5,
};

function Pane({
  title,
  note: subtitle,
  children,
}: {
  readonly title: string;
  readonly note: string;
  readonly children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div style={pane}>
      <h1 style={heading}>{title}</h1>
      <p style={note}>{subtitle}</p>
      {children}
    </div>
  );
}

/** The four outcomes, rendered. Each says something different on purpose. */
function Outcome<T>({
  load,
  empty,
  children,
}: {
  readonly load: Load<T>;
  readonly empty: React.ReactNode;
  readonly children: (value: T) => React.JSX.Element;
}): React.JSX.Element {
  if (load.kind === "loading") {
    return <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem" }}>Reading…</p>;
  }
  if (load.kind === "refused") {
    // NOT "nothing here". §6.3 makes unauthorized and nonexistent indistinguishable,
    // so this is honest about not knowing which — and saying "empty" would make a
    // permissions problem look like an empty account.
    return (
      <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem", maxWidth: "72ch", lineHeight: 1.5 }}>
        The server did not return this. Either your role does not hold the permission or
        there is nothing to return — the response is deliberately the same for both, so
        this screen cannot tell you which. Ask an Owner or Admin to check your grants.
      </p>
    );
  }
  if (load.kind === "failed") {
    return (
      <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem", maxWidth: "72ch", lineHeight: 1.5 }}>
        This did not load: {load.detail}. The dashboard reached the server, so the
        process is running — check the server output for a database error.
      </p>
    );
  }
  if (Array.isArray(load.value) && load.value.length === 0) return <>{empty}</>;
  return children(load.value);
}

const table: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: "0.8125rem",
};
const th: React.CSSProperties = {
  textAlign: "left",
  padding: "6px 10px 6px 0",
  color: "var(--chalk-dim)",
  fontWeight: 500,
  borderBottom: "1px solid var(--seam, #2a2724)",
  whiteSpace: "nowrap",
};
const td: React.CSSProperties = {
  padding: "7px 10px 7px 0",
  borderBottom: "1px solid var(--seam, #2a2724)",
  verticalAlign: "top",
};
const mono: React.CSSProperties = { ...td, fontFamily: "var(--font-mono)", fontSize: "0.75rem" };

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

type AuditEntry = {
  readonly id: string;
  readonly seq: string;
  readonly hash: string;
  readonly prevHash: string;
  readonly actorType: string;
  readonly actorId: string;
  readonly actorLabel: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly decision: string;
  readonly reason: string;
  readonly at: string;
};

export function AuditScreen(): React.JSX.Element {
  const load = useCollection<readonly AuditEntry[]>("/audit");

  return (
    <Pane
      title="Audit"
      note="Every privileged action, hash-chained. Each entry carries the hash of the one before it, so removing or re-timing an entry breaks the chain from that point on."
    >
      <Outcome
        load={load}
        empty={
          // Invites action rather than apologising (§291). An empty audit log on a
          // claimed installation is close to impossible — claiming writes one — so this
          // is a state worth being suspicious about rather than reassuring about.
          <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem", maxWidth: "72ch" }}>
            No entries. Claiming an installation writes one, so an empty log on a claimed
            installation is worth investigating rather than accepting.
          </p>
        }
      >
        {(entries) => (
          <table style={table}>
            <thead>
              <tr>
                <th style={th}>Seq</th>
                <th style={th}>Action</th>
                <th style={th}>Actor</th>
                <th style={th}>Resource</th>
                <th style={th}>Decision</th>
                <th style={th}>Reason</th>
                <th style={th}>Chain</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <td style={mono}>{entry.seq}</td>
                  <td style={td}>{entry.action}</td>
                  <td style={td}>
                    {entry.actorLabel === "" ? entry.actorType : `${entry.actorType} · ${entry.actorLabel}`}
                  </td>
                  <td style={td}>{entry.resourceType}</td>
                  <td
                    style={{
                      ...td,
                      // Deny is the colour that matters. A log where every row reads the
                      // same is a log nobody scans.
                      color: entry.decision === "deny" ? "var(--rust-text, #d98a72)" : "var(--chalk)",
                    }}
                  >
                    {entry.decision}
                  </td>
                  <td style={td}>{entry.reason}</td>
                  <td style={mono} title={`hash ${entry.hash}\nprev ${entry.prevHash}`}>
                    {entry.hash.slice(0, 8)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Outcome>
    </Pane>
  );
}

// ---------------------------------------------------------------------------
// Team
// ---------------------------------------------------------------------------

type Member = {
  readonly userId: string;
  readonly email: string;
  readonly name: string;
  readonly roles?: readonly string[];
};

export function TeamScreen(): React.JSX.Element {
  const load = useCollection<readonly Member[]>("/members");

  return (
    <Pane
      title="Team"
      note="Everyone with a membership in this organization. Roles are compositions of raw permissions, and a role's name is a label for that composition rather than a level."
    >
      <Outcome
        load={load}
        empty={
          <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem" }}>
            No members. The account that claimed this installation should be here, so an
            empty list means something is wrong rather than unconfigured.
          </p>
        }
      >
        {(members) => (
          <table style={table}>
            <thead>
              <tr>
                <th style={th}>Name</th>
                <th style={th}>Email</th>
                <th style={th}>Roles</th>
              </tr>
            </thead>
            <tbody>
              {members.map((member) => (
                <tr key={member.userId}>
                  <td style={td}>{member.name}</td>
                  <td style={td}>{member.email}</td>
                  <td style={td}>
                    {member.roles === undefined || member.roles.length === 0
                      ? // Not "none": the endpoint may not return roles yet, and printing
                        // "none" would assert an authorization fact this screen did not
                        // read. Saying so is the honest form.
                        "not reported by this endpoint"
                      : member.roles.join(", ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Outcome>
    </Pane>
  );
}

// ---------------------------------------------------------------------------
// Projects, which the rail calls Sites
// ---------------------------------------------------------------------------

type Project = {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
};

export function SitesScreen(): React.JSX.Element {
  const load = useCollection<readonly Project[]>("/projects");

  return (
    <Pane
      title="Projects"
      // The heading says Projects while the rail says Sites, deliberately. A project
      // contains sites and sites arrive in M3; rendering projects under "Sites" would
      // be a quiet mislabelling of the data model, and the kind that survives because
      // it looks plausible.
      note="The rail calls this Sites; what exists today is projects, which contain sites. Sites themselves arrive in M3 — until then this is the scope a permission is granted over, not something deployed."
    >
      <Outcome
        load={load}
        empty={
          <p style={{ color: "var(--chalk-dim)", fontSize: "0.8125rem", maxWidth: "72ch" }}>
            No projects yet. A project is the scope most permissions are granted over, so
            creating one is the first step after adding a team — though the endpoint that
            creates one is not bound yet.
          </p>
        }
      >
        {(projects) => (
          <table style={table}>
            <thead>
              <tr>
                <th style={th}>Name</th>
                <th style={th}>Slug</th>
                <th style={th}>Id</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => (
                <tr key={project.id}>
                  <td style={td}>{project.name}</td>
                  <td style={mono}>{project.slug}</td>
                  <td style={mono}>{project.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Outcome>
    </Pane>
  );
}

// ---------------------------------------------------------------------------
// The two that do not exist yet
// ---------------------------------------------------------------------------

/**
 * A destination with no capability behind it.
 *
 * NOT an empty table. "Hosts" showing zero rows claims there are no hosts, when the
 * truth is that Ratline cannot manage one yet — and a claim about the world is worse
 * than an admission about the software. It names the task, so a reader can find out
 * when it changes.
 */
function NotBuilt({
  title,
  what,
  task,
}: {
  readonly title: string;
  readonly what: string;
  readonly task: string;
}): React.JSX.Element {
  return (
    <Pane title={title} note={what}>
      <p
        style={{
          color: "var(--chalk-dim)",
          fontSize: "0.8125rem",
          maxWidth: "72ch",
          lineHeight: 1.5,
          borderLeft: "2px solid var(--seam, #2a2724)",
          paddingLeft: "12px",
        }}
      >
        There is no endpoint behind this yet, so this screen is showing you nothing
        rather than showing you an empty list — the difference matters, because an empty
        list would say there are none. Tracked as <strong>{task}</strong>.
      </p>
    </Pane>
  );
}

export function HostsScreen(): React.JSX.Element {
  return (
    <NotBuilt
      title="Hosts"
      what="The machines Ratline manages. Each runs an unprivileged agent that performs only enumerated operations, and a separate root helper that re-validates every argument."
      task="RL-M2-005"
    />
  );
}

export function DeploysScreen(): React.JSX.Element {
  return (
    <NotBuilt
      title="Deploys"
      what="Releases, their logs, and rollback. A release is atomic and rollback is a symlink swap, which is why it is expected to complete in under a second."
      task="M3"
    />
  );
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/**
 * The screen for a path.
 *
 * A table rather than a switch with a default, for the reason ADR 0002 gives about the
 * operation catalogue: a default branch answers for paths nobody considered. An unknown
 * path falls back to Audit, which is the least destructive place to land and the one
 * most likely to explain what happened.
 */
export const SCREENS: Readonly<Record<string, () => React.JSX.Element>> = {
  "/hosts": HostsScreen,
  "/sites": SitesScreen,
  "/deploys": DeploysScreen,
  "/audit": AuditScreen,
  "/team": TeamScreen,
};

export function screenFor(path: string): () => React.JSX.Element {
  const exact = SCREENS[path];
  if (exact !== undefined) return exact;

  // `/sites/marketing-www` should render the Sites screen, not fall back.
  for (const [href, screen] of Object.entries(SCREENS)) {
    if (path.startsWith(`${href}/`)) return screen;
  }
  return AuditScreen;
}
