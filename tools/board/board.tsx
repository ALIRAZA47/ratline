/**
 * The task board (RL-M1-061).
 *
 * Columns are statuses; swimlanes group the cards. Two groupings are offered and both are
 * real fields rather than invented ones — which is the decision worth stating, because a
 * board like this invites a taxonomy nobody agreed to.
 *
 * ## "User story" means milestone here, and that is honest rather than a substitution
 *
 * `docs/tasks.yaml` has no `story` field. What it has is `milestone`, and a milestone in
 * this project is already story-shaped: `docs/milestones.yaml` gives each one a `goal` and
 * a set of `exit_criteria`, which is exactly what a user story carries. So a swimlane is a
 * milestone and shows its goal.
 *
 * Inventing stories by pattern-matching task titles was the alternative, and it would have
 * produced groupings that look authoritative and answer to nothing. Adding a real `story`
 * field is a tracker schema change touching 188 tasks and belongs to whoever decides the
 * taxonomy — noted on the task rather than done quietly here.
 *
 * ## "Priority" means risk
 *
 * Also not invented. `risk` is low/medium/high and is what the brief uses to decide what
 * needs a security suite before it can close — so it is the field that actually changes
 * what happens to a task, which is what a priority is for.
 */

import { useMemo, useState } from "react";

// ---------------------------------------------------------------------------
// The data, as `./scripts/tasks board` writes it
// ---------------------------------------------------------------------------

export type BoardTask = {
  readonly id: string;
  readonly title: string;
  readonly milestone: string;
  readonly status: string;
  readonly owner: string;
  readonly estimate: string;
  readonly risk: string;
  readonly dependsOn: readonly string[];
  readonly acceptance: number;
  readonly acceptanceMet: number;
  readonly latestNote: string;
};

export type BoardData = {
  readonly generatedAt: string;
  readonly commit: string;
  readonly dirty: boolean;
  readonly statuses: readonly string[];
  readonly milestones: readonly { readonly id: string; readonly name: string; readonly goal: string }[];
  readonly tasks: readonly BoardTask[];
};

/** Columns, left to right, as work moves. */
const COLUMN_ORDER = ["todo", "ready", "in-progress", "blocked", "review", "done", "dropped"];

const RISK_ORDER = ["high", "medium", "low"];

const HUE: Readonly<Record<string, string>> = {
  todo: "var(--todo)",
  ready: "var(--ready)",
  "in-progress": "var(--progress)",
  blocked: "var(--blocked)",
  review: "var(--review)",
  done: "var(--done)",
  dropped: "var(--dropped)",
  high: "var(--blocked)",
  medium: "var(--progress)",
  low: "var(--todo)",
};

type Grouping = "milestone" | "risk";

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

function Card({ task, data }: { readonly task: BoardTask; readonly data: BoardData }): React.JSX.Element {
  const [open, setOpen] = useState(false);

  // Only dependencies that are NOT finished. Listing every one is noise; the outstanding
  // ones are the reason a card is not moving, which is the question a board answers.
  const waitingOn = task.dependsOn.filter((id) => {
    const dependency = data.tasks.find((candidate) => candidate.id === id);
    return dependency !== undefined && dependency.status !== "done" && dependency.status !== "dropped";
  });

  const partial = task.acceptanceMet > 0 && task.acceptanceMet < task.acceptance;

  return (
    <article className="card" data-risk={task.risk}>
      <button
        type="button"
        className="card-head"
        aria-expanded={open}
        onClick={() => setOpen((was) => !was)}
      >
        <span className="card-id">{task.id}</span>
        <span className="card-title">{task.title}</span>
      </button>

      <div className="card-meta">
        {/* Partial acceptance is the state worth seeing at a glance: a card whose
            acceptance is half met is either in flight or was closed dishonestly, and both
            deserve a second look. */}
        {task.acceptance > 0 && (
          <span className={partial ? "chip chip-part" : "chip"}>
            {task.acceptanceMet}/{task.acceptance}
          </span>
        )}
        {task.risk === "high" && <span className="chip chip-risk">high risk</span>}
        <span className="chip chip-quiet">{task.estimate}</span>
        {task.owner === "human" && <span className="chip chip-human">human</span>}
      </div>

      {waitingOn.length > 0 && (
        <p className="waiting">
          waiting on <span className="mono">{waitingOn.join(" ")}</span>
        </p>
      )}

      {open && task.latestNote !== "" && <p className="note">{task.latestNote}</p>}
      {open && task.latestNote === "" && <p className="note">No notes yet.</p>}
    </article>
  );
}

// ---------------------------------------------------------------------------
// Columns and lanes
// ---------------------------------------------------------------------------

function Column({
  status,
  tasks,
  data,
}: {
  readonly status: string;
  readonly tasks: readonly BoardTask[];
  readonly data: BoardData;
}): React.JSX.Element {
  return (
    <section className="column" aria-label={`${status}, ${String(tasks.length)} tasks`}>
      <h3 className="column-head">
        <span className="dot" style={{ background: HUE[status] ?? "var(--todo)" }} />
        {status}
        <span className="column-count">{tasks.length}</span>
      </h3>
      <div className="column-body">
        {tasks.length === 0 ? (
          // An empty column says nothing rather than apologising (§291). A "no tasks!"
          // message in six columns per lane is six pieces of noise per row.
          <p className="column-empty" aria-hidden="true">
            —
          </p>
        ) : (
          tasks.map((task) => <Card key={task.id} task={task} data={data} />)
        )}
      </div>
    </section>
  );
}

function Lane({
  title,
  subtitle,
  tasks,
  data,
  columns,
}: {
  readonly title: string;
  readonly subtitle: string;
  readonly tasks: readonly BoardTask[];
  readonly data: BoardData;
  readonly columns: readonly string[];
}): React.JSX.Element {
  const [open, setOpen] = useState(true);
  const done = tasks.filter((task) => task.status === "done").length;

  return (
    <section className="lane">
      <header className="lane-head">
        <button type="button" className="lane-toggle" aria-expanded={open} onClick={() => setOpen((was) => !was)}>
          <span aria-hidden="true">{open ? "▾" : "▸"}</span>
          <span className="lane-title">{title}</span>
        </button>
        <span className="lane-progress">
          {done} of {tasks.length} done
        </span>
        {subtitle !== "" && <p className="lane-goal">{subtitle}</p>}
      </header>

      {open && (
        <div className="lane-columns">
          {columns.map((status) => (
            <Column
              key={status}
              status={status}
              tasks={tasks.filter((task) => task.status === status)}
              data={data}
            />
          ))}
        </div>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// The board
// ---------------------------------------------------------------------------

export function Board({ data }: { readonly data: BoardData }): React.JSX.Element {
  const [grouping, setGrouping] = useState<Grouping>("milestone");
  const [query, setQuery] = useState("");
  const [hideDone, setHideDone] = useState(false);

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return data.tasks.filter((task) => {
      if (hideDone && (task.status === "done" || task.status === "dropped")) return false;
      if (needle === "") return true;
      return `${task.id} ${task.title} ${task.latestNote}`.toLowerCase().includes(needle);
    });
  }, [data.tasks, query, hideDone]);

  // Only columns that hold something, so a board is not mostly empty columns. Computed
  // from what is VISIBLE rather than from the whole tracker, or filtering would leave
  // columns behind with nothing in them.
  const columns = useMemo(
    () => COLUMN_ORDER.filter((status) => visible.some((task) => task.status === status)),
    [visible],
  );

  const lanes = useMemo(() => {
    if (grouping === "risk") {
      return RISK_ORDER.filter((risk) => visible.some((task) => task.risk === risk)).map((risk) => ({
        key: risk,
        title: `${risk} risk`,
        subtitle:
          risk === "high"
            ? "A high-risk task cannot close without a security-suite artifact — that is what the label changes."
            : "",
        tasks: visible.filter((task) => task.risk === risk),
      }));
    }

    return data.milestones
      .filter((milestone) => visible.some((task) => task.milestone === milestone.id))
      .map((milestone) => ({
        key: milestone.id,
        title: `${milestone.id} — ${milestone.name}`,
        subtitle: milestone.goal,
        tasks: visible.filter((task) => task.milestone === milestone.id),
      }));
  }, [grouping, visible, data.milestones]);

  return (
    <>
      <header className="page-head">
        <h1>Ratline — task board</h1>
        <p className="stamp">
          Generated {new Date(data.generatedAt).toLocaleString()} from commit{" "}
          <code>{data.commit}</code>. A snapshot — run <code>./scripts/tasks board</code> to
          refresh. <code>docs/tasks.yaml</code> is the source of truth.
        </p>
        {data.dirty && (
          // Loud, and in the header. A board built from an edited-but-uncommitted tracker
          // is showing state nobody else can see.
          <p className="dirty">
            docs/tasks.yaml has uncommitted changes, so this board shows state that is not
            in any commit.
          </p>
        )}
      </header>

      <div className="controls">
        <div className="group" role="group" aria-label="Group by">
          {(["milestone", "risk"] as const).map((option) => (
            <button
              key={option}
              type="button"
              className="toggle"
              aria-pressed={grouping === option}
              onClick={() => setGrouping(option)}
            >
              {option === "milestone" ? "By story (milestone)" : "By priority (risk)"}
            </button>
          ))}
        </div>

        <input
          type="search"
          value={query}
          placeholder="Filter by id, title or note…"
          aria-label="Filter tasks"
          onChange={(event) => setQuery(event.target.value)}
        />

        <label className="check">
          <input type="checkbox" checked={hideDone} onChange={(event) => setHideDone(event.target.checked)} />
          Hide done
        </label>

        <span className="tally">
          {visible.length} of {data.tasks.length} shown
        </span>
      </div>

      {lanes.length === 0 ? (
        <p className="nothing">
          Nothing matches. Clear the filter, or check the id — {data.tasks.length} tasks are
          loaded.
        </p>
      ) : (
        lanes.map((lane) => (
          <Lane
            key={lane.key}
            title={lane.title}
            subtitle={lane.subtitle}
            tasks={lane.tasks}
            data={data}
            columns={columns}
          />
        ))
      )}

      <footer className="page-foot">
        <p>
          Swimlanes are <strong>milestones</strong>, not a separate story field —
          <code>docs/tasks.yaml</code> has none, and a milestone already carries a goal and
          exit criteria, which is what a story is. Priority is <strong>risk</strong>, which is
          the field that decides whether a task needs a security suite before it can close.
          Neither grouping is invented.
        </p>
      </footer>
    </>
  );
}
