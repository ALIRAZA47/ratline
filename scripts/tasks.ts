#!/usr/bin/env node --experimental-strip-types
/**
 * Ratline work-tracking CLI.  See docs/BRIEF.md §2.3.
 *
 * Zero dependencies, standard library only.  Runs on Node >= 22.6 via native
 * type stripping (`node --experimental-strip-types`), unflagged on >= 22.18.
 * Use the `scripts/tasks` wrapper, which locates a suitable Node for you.
 *
 * ---------------------------------------------------------------------------
 * YAML SUBSET
 * ---------------------------------------------------------------------------
 * docs/tasks.yaml and docs/milestones.yaml are written in a deliberately small
 * subset of YAML so this tool needs no parser dependency.  The subset is real
 * YAML — any conforming parser will read these files identically — but not all
 * of YAML is accepted here.  `validate` rejects anything outside it, with a
 * line number, rather than silently misreading it.
 *
 *   - Top level is a sequence of mappings.  Each item begins `- key: value`
 *     at column 0.  Subsequent keys of that item are indented exactly 2.
 *   - Scalar:        `  title: Generate the vhost`
 *   - Flow sequence: `  depends_on: [RL-M2-009, RL-M2-011]`   (or `[]`)
 *   - Block sequence: `  acceptance:` then items indented exactly 4: `    - text`
 *   - Block scalar:  `  notes: |` then content indented at least 4.
 *   - `# comments` and blank lines are preserved on write.
 *
 * Mutating commands perform targeted line surgery rather than reserialising
 * the document, so hand-written comments, ordering and formatting survive.
 * ---------------------------------------------------------------------------
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TASKS_PATH = join(ROOT, "docs", "tasks.yaml");
const MILESTONES_PATH = join(ROOT, "docs", "milestones.yaml");
const DECISIONS_DIR = join(ROOT, "docs", "decisions");
const RISKS_PATH = join(ROOT, "docs", "RISKS.md");
const STATUS_PATH = join(ROOT, "docs", "STATUS.md");
const METRICS_PATH = join(ROOT, ".ratline", "metrics.json");
const CI_STATUS_PATH = join(ROOT, ".ratline", "ci-status.json");
const FINDINGS_PATH = join(ROOT, ".ratline", "security-findings.json");

const STATUSES = ["todo", "ready", "in-progress", "blocked", "review", "done", "dropped"] as const;
const OWNERS = ["agent", "human"] as const;
const ESTIMATES = ["S", "M", "L", "XL"] as const;
const RISKS = ["low", "medium", "high"] as const;

type Status = (typeof STATUSES)[number];

/** A path counts as security-test coverage for a `risk: high` task. */
const SECURITY_TEST_PATTERNS = [
  /^test\/security\//,
  /^test\/authz\//,
  /_security_test\.(ts|go)$/,
  /\.security\.test\.ts$/,
  /^src\/authz\/.*\.test\.ts$/,
];

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type Field = {
  key: string;
  kind: "scalar" | "flow" | "block-seq" | "block-scalar";
  scalar: string;
  list: string[];
  text: string;
  keyLine: number;
  endLine: number; // inclusive
};

type Item = {
  fields: Map<string, Field>;
  startLine: number;
  endLine: number; // inclusive
};

type ParseError = { line: number; message: string };

const KEY_RE = /^(- |  )([A-Za-z_][A-Za-z0-9_]*):(?:[ ]+(.*))?$/;
const LIST_ITEM_RE = /^ {4}- (.*)$/;
const isBlank = (s: string) => s.trim() === "";
const isComment = (s: string) => s.trimStart().startsWith("#");

/** Strip one layer of matching surrounding quotes. */
function unquote(raw: string): string {
  const s = raw.trim();
  if (s.length >= 2 && ((s[0] === '"' && s.at(-1) === '"') || (s[0] === "'" && s.at(-1) === "'"))) {
    return s.slice(1, -1).replace(/\\"/g, '"');
  }
  return s;
}

function parse(lines: string[], errors: ParseError[]): Item[] {
  const items: Item[] = [];
  let cur: Item | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (isBlank(line) || isComment(line)) continue;

    if (line.startsWith("- ")) {
      cur = { fields: new Map(), startLine: i, endLine: i };
      items.push(cur);
    } else if (!line.startsWith("  ")) {
      errors.push({ line: i, message: `expected a new item ("- key: value") or an indented key, got: ${line}` });
      continue;
    }

    const m = KEY_RE.exec(line);
    if (!m) {
      errors.push({ line: i, message: `not a key line in the accepted YAML subset: ${line}` });
      continue;
    }
    if (!cur) {
      errors.push({ line: i, message: `key outside of any item: ${line}` });
      continue;
    }

    // KEY_RE always captures group 2 when it matches; the defaults keep the
    // types honest without an assertion.
    const key = m[2] ?? "";
    const rawValue = (m[3] ?? "").trim();
    if (cur.fields.has(key)) errors.push({ line: i, message: `duplicate key "${key}"` });

    const field: Field = { key, kind: "scalar", scalar: "", list: [], text: "", keyLine: i, endLine: i };

    if (rawValue === "|") {
      field.kind = "block-scalar";
      const body: string[] = [];
      let j = i + 1;
      for (; j < lines.length; j++) {
        const l = lines[j] ?? "";
        if (isBlank(l)) { body.push(""); continue; }
        if (!l.startsWith("    ")) break;
        body.push(l.slice(4));
      }
      while (body.length && body.at(-1) === "") body.pop();
      field.text = body.join("\n");
      field.endLine = j - 1;
      i = j - 1;
    } else if (rawValue.startsWith("[")) {
      field.kind = "flow";
      if (!rawValue.endsWith("]")) {
        errors.push({ line: i, message: `unterminated flow sequence for "${key}" (must fit on one line)` });
      }
      const inner = rawValue.slice(1, rawValue.endsWith("]") ? -1 : undefined).trim();
      field.list = inner === "" ? [] : inner.split(",").map(unquote).filter((s) => s !== "");
    } else if (rawValue === "") {
      // Block sequence, or a genuinely empty scalar.
      let j = i + 1;
      const collected: string[] = [];
      for (; j < lines.length; j++) {
        const l = lines[j] ?? "";
        if (isBlank(l) || isComment(l)) continue;
        const li = LIST_ITEM_RE.exec(l);
        if (!li) break;
        collected.push(unquote(li[1] ?? ""));
      }
      if (collected.length > 0) {
        field.kind = "block-seq";
        field.list = collected;
        field.endLine = j - 1;
        i = j - 1;
      } else {
        field.scalar = "";
      }
    } else {
      field.scalar = unquote(rawValue);
    }

    cur.fields.set(key, field);
    cur.endLine = Math.max(cur.endLine, field.endLine);
  }

  return items;
}

// ---------------------------------------------------------------------------
// Domain view over parsed items
// ---------------------------------------------------------------------------

type Task = {
  id: string;
  title: string;
  milestone: string;
  status: Status;
  owner: string;
  estimate: string;
  risk: string;
  depends_on: string[];
  blocks: string[];
  acceptance: string[];
  acceptance_met: number[];
  artifacts: string[];
  decisions: string[];
  notes: string;
  started_at: string;
  blocked_at: string;
  done_at: string;
  item: Item;
};

const s = (it: Item, k: string) => it.fields.get(k)?.scalar ?? "";
const l = (it: Item, k: string) => it.fields.get(k)?.list ?? [];

function toTask(it: Item): Task {
  return {
    id: s(it, "id"),
    title: s(it, "title"),
    milestone: s(it, "milestone"),
    status: s(it, "status") as Status,
    owner: s(it, "owner"),
    estimate: s(it, "estimate"),
    risk: s(it, "risk"),
    depends_on: l(it, "depends_on"),
    blocks: l(it, "blocks"),
    acceptance: l(it, "acceptance"),
    acceptance_met: l(it, "acceptance_met").map(Number).filter((n) => Number.isInteger(n)),
    artifacts: l(it, "artifacts"),
    decisions: l(it, "decisions"),
    notes: it.fields.get("notes")?.text ?? "",
    started_at: s(it, "started_at"),
    blocked_at: s(it, "blocked_at"),
    done_at: s(it, "done_at"),
    item: it,
  };
}

type Doc = { lines: string[]; tasks: Task[]; errors: ParseError[] };

function loadTasks(): Doc {
  if (!existsSync(TASKS_PATH)) die(`missing ${rel(TASKS_PATH)}`);
  const lines = readFileSync(TASKS_PATH, "utf8").split("\n");
  const errors: ParseError[] = [];
  const tasks = parse(lines, errors).map(toTask);
  return { lines, tasks, errors };
}

type Milestone = { id: string; name: string; goal: string; exit_criteria: string[]; exit_met: number[] };

function loadMilestones(): Milestone[] {
  if (!existsSync(MILESTONES_PATH)) return [];
  const lines = readFileSync(MILESTONES_PATH, "utf8").split("\n");
  const errors: ParseError[] = [];
  const items = parse(lines, errors);
  if (errors.length) {
    for (const e of errors) console.error(`${rel(MILESTONES_PATH)}:${e.line + 1}: ${e.message}`);
    die("milestones.yaml failed to parse");
  }
  return items.map((it) => {
    const criteria = l(it, "exit_criteria");
    const rawMet = l(it, "exit_met");

    // `.filter(Number.isInteger)` used to be the whole check, and DISCARDING a
    // bad entry is what made it dangerous. Writing the criteria' prose into
    // `exit_met` — the obvious mistake, because the criteria are right above it —
    // produced NaN for every line, filtered them all away, and left `[]`. The
    // gate report then said "both criteria met" while STATUS.md rendered
    // "0 of 2 met" from the same file, and `tasks validate` reported 0 warnings.
    //
    // A malformed tracker must fail the build on its own merits (brief §2.3), so
    // an entry that is not a valid index is now an error rather than a silence.
    const met: number[] = [];
    for (const entry of rawMet) {
      const index = Number(entry);
      if (!Number.isInteger(index) || index < 1 || index > criteria.length) {
        die(
          `${rel(MILESTONES_PATH)}: ${s(it, "id")} exit_met contains ${JSON.stringify(entry)}, ` +
            `which is not an exit-criterion index. exit_met holds 1-based NUMBERS pointing into ` +
            `exit_criteria (this milestone has ${criteria.length}), not the criteria themselves. ` +
            `Write \`exit_met: [1, 2]\`.`,
        );
      }
      if (met.includes(index)) {
        die(`${rel(MILESTONES_PATH)}: ${s(it, "id")} lists exit criterion ${index} twice.`);
      }
      met.push(index);
    }

    return {
      id: s(it, "id"),
      name: s(it, "name"),
      goal: s(it, "goal"),
      exit_criteria: criteria,
      exit_met: met,
    };
  });
}

// ---------------------------------------------------------------------------
// Line surgery — mutations preserve everything they do not touch
// ---------------------------------------------------------------------------

/** Keys written as simple scalars, in canonical order. Used to place inserts. */
const SCALAR_ORDER = [
  "id", "title", "milestone", "status", "owner", "estimate",
  "risk", "started_at", "blocked_at", "done_at",
];

function setScalar(doc: Doc, id: string, key: string, value: string): void {
  const task = requireTask(doc, id);
  const existing = task.item.fields.get(key);
  if (existing && existing.kind === "scalar") {
    doc.lines[existing.keyLine] = `  ${key}: ${value}`;
    return;
  }
  if (existing) die(`cannot set "${key}" on ${id}: it is a ${existing.kind}, not a scalar`);

  // Insert after the latest canonical scalar key that sorts before this one.
  const want = SCALAR_ORDER.indexOf(key);
  let anchor = task.item.startLine;
  for (const [k, f] of task.item.fields) {
    const idx = SCALAR_ORDER.indexOf(k);
    if (idx !== -1 && (want === -1 || idx < want)) anchor = Math.max(anchor, f.endLine);
  }
  doc.lines.splice(anchor + 1, 0, `  ${key}: ${value}`);
}

function setFlowList(doc: Doc, id: string, key: string, values: (string | number)[]): void {
  const task = requireTask(doc, id);
  const existing = task.item.fields.get(key);
  const rendered = `  ${key}: [${values.join(", ")}]`;
  if (existing) {
    if (existing.kind === "block-seq") die(`cannot rewrite "${key}" on ${id}: it is a block sequence`);
    doc.lines.splice(existing.keyLine, existing.endLine - existing.keyLine + 1, rendered);
    return;
  }
  doc.lines.splice(task.item.endLine + 1, 0, rendered);
}

function appendNote(doc: Doc, id: string, text: string): void {
  const task = requireTask(doc, id);
  const body = text.split("\n").map((t) => `    ${t}`);
  const notes = task.item.fields.get("notes");
  if (notes && notes.kind === "block-scalar") {
    doc.lines.splice(notes.endLine + 1, 0, ...body);
  } else if (notes) {
    die(`cannot append a note to ${id}: "notes" is a ${notes.kind}, expected a block scalar`);
  } else {
    doc.lines.splice(task.item.endLine + 1, 0, "  notes: |", ...body);
  }
}

function save(doc: Doc): void {
  writeFileSync(TASKS_PATH, doc.lines.join("\n"), "utf8");
}

/** Re-read from disk. Mutations shift line numbers, so never batch without this. */
function reload(): Doc {
  const doc = loadTasks();
  if (doc.errors.length) {
    for (const e of doc.errors) console.error(`${rel(TASKS_PATH)}:${e.line + 1}: ${e.message}`);
    die("tasks.yaml no longer parses after the edit — nothing further was written");
  }
  return doc;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

type Problem = { level: "error" | "warn"; where: string; message: string };

function validateDoc(doc: Doc): Problem[] {
  const p: Problem[] = [];
  const err = (where: string, message: string) => p.push({ level: "error", where, message });
  const warn = (where: string, message: string) => p.push({ level: "warn", where, message });

  for (const e of doc.errors) err(`${rel(TASKS_PATH)}:${e.line + 1}`, e.message);

  const byId = new Map<string, Task>();
  const adrs = new Set(
    existsSync(DECISIONS_DIR)
      ? readdirSync(DECISIONS_DIR).filter((f) => f.endsWith(".md")).map((f) => f.slice(0, 4))
      : [],
  );

  for (const t of doc.tasks) {
    const at = `${TASKS_PATH.split("/").pop()}:${t.item.startLine + 1}`;
    const where = t.id ? `${t.id} (${at})` : at;

    // -- shape
    if (!/^RL-M[0-7]-\d{3}$/.test(t.id)) { err(where, `bad id "${t.id}"; expected RL-M<n>-NNN`); continue; }
    if (byId.has(t.id)) err(where, `duplicate id ${t.id}`);
    byId.set(t.id, t);

    for (const k of ["title", "milestone", "status", "owner", "estimate", "risk"]) {
      if (!t.item.fields.has(k)) err(where, `missing required key "${k}"`);
    }
    if (t.title.length > 90) warn(where, `title is ${t.title.length} chars; keep it under 90`);
    if (!STATUSES.includes(t.status)) err(where, `bad status "${t.status}"`);
    if (!OWNERS.includes(t.owner as never)) err(where, `bad owner "${t.owner}"`);
    if (!ESTIMATES.includes(t.estimate as never)) err(where, `bad estimate "${t.estimate}"`);
    if (!RISKS.includes(t.risk as never)) err(where, `bad risk "${t.risk}"`);
    if (t.id.slice(3, 5) !== t.milestone) err(where, `id milestone "${t.id.slice(3, 5)}" != milestone "${t.milestone}"`);

    // -- YAML-subset hygiene: list entries that a strict parser would choke on
    for (const key of ["acceptance", "artifacts"]) {
      const f = t.item.fields.get(key);
      if (!f) continue;
      for (const raw of f.list) {
        if (/^[[{*&!%@`>|]/.test(raw) || /: /.test(raw)) {
          const orig = doc.lines[f.keyLine + 1 + f.list.indexOf(raw)] ?? "";
          if (!/^\s*- ["']/.test(orig)) {
            err(where, `${key} entry must be quoted (starts with a YAML indicator or contains ": "): ${raw}`);
          }
        }
      }
    }

    // -- brief §2.2 rules
    if (t.estimate === "XL" && t.status !== "todo" && t.status !== "dropped") {
      err(where, `XL is not a valid resting state (status "${t.status}") — split it before starting`);
    }
    const needsAcceptance: Status[] = ["ready", "in-progress", "blocked", "review", "done"];
    if (needsAcceptance.includes(t.status) && t.acceptance.length === 0) {
      err(where, `status "${t.status}" requires at least one acceptance line (Definition of Ready)`);
    }
    for (const n of t.acceptance_met) {
      if (n < 1 || n > t.acceptance.length) err(where, `acceptance_met references line ${n}, which does not exist`);
    }
    if (t.status === "done" && t.acceptance_met.length !== t.acceptance.length) {
      err(where, `done with ${t.acceptance_met.length}/${t.acceptance.length} acceptance lines met`);
    }
    if (t.status === "dropped" && t.notes.trim() === "") {
      err(where, `dropped tasks must carry a note explaining why`);
    }
    if (t.status === "blocked" && !/blocked/i.test(t.notes)) {
      err(where, `blocked tasks must record the blocking reason in notes`);
    }
    if (t.risk === "high" && t.status === "done") {
      const covered = t.artifacts.some((a) => SECURITY_TEST_PATTERNS.some((re) => re.test(a)));
      if (!covered) err(where, `risk: high cannot be done without a security-suite artifact (see brief §2.2)`);
    }
    for (const d of t.decisions) {
      const padded = String(d).padStart(4, "0");
      if (!adrs.has(padded)) err(where, `references ADR ${padded}, which has no file in docs/decisions/`);
    }
  }

  // -- graph
  for (const t of byId.values()) {
    const where = t.id;
    for (const d of t.depends_on) {
      const dep = byId.get(d);
      if (!dep) { err(where, `depends_on references unknown task ${d}`); continue; }
      if (dep.status === "dropped") warn(where, `depends_on ${d}, which is dropped`);
      if (!dep.blocks.includes(t.id)) err(where, `depends_on ${d}, but ${d}.blocks does not list ${t.id}`);
      if (t.status === "in-progress" && dep.status !== "done") {
        err(where, `in-progress while dependency ${d} is "${dep.status}" (Definition of Ready)`);
      }
    }
    for (const b of t.blocks) {
      const blocked = byId.get(b);
      if (!blocked) { err(where, `blocks references unknown task ${b}`); continue; }
      if (!blocked.depends_on.includes(t.id)) err(where, `blocks ${b}, but ${b}.depends_on does not list ${t.id}`);
    }
  }

  // -- cycles
  const state = new Map<string, 0 | 1 | 2>();
  const stack: string[] = [];
  const walk = (id: string): void => {
    if (state.get(id) === 2) return;
    if (state.get(id) === 1) {
      err(id, `dependency cycle: ${[...stack.slice(stack.indexOf(id)), id].join(" -> ")}`);
      return;
    }
    state.set(id, 1);
    stack.push(id);
    for (const d of byId.get(id)?.depends_on ?? []) if (byId.has(d)) walk(d);
    stack.pop();
    state.set(id, 2);
  };
  for (const id of byId.keys()) walk(id);

  return p;
}

// ---------------------------------------------------------------------------
// External signals
// ---------------------------------------------------------------------------

function readJson<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch (e) {
    console.error(`warning: ${rel(path)} is not valid JSON (${(e as Error).message}); treating as absent`);
    return null;
  }
}

type Metrics = {
  unit?: { passed: number; total: number };
  integration?: { passed: number; total: number };
  authz_matrix?: { passed: number; total: number };
  /**
   * The matrix's CELLS, which is the number §6.3 is asking about — role ×
   * endpoint × subject. `authz_matrix` above counts test cases, of which there
   * are a dozen; this counts the hundreds of decisions they make.
   */
  authz_matrix_cells?: {
    executed: boolean;
    cells?: number;
    passed?: number;
    failed?: number;
    routes?: number;
    roles?: number;
    verified_by?: { transport: number; decision: number; declaration: number };
    note?: string;
  };
  authz_coverage_pct?: number;
  can_branch_coverage_pct?: number;
  measured_at?: string;
};
type CiStatus = { status: "green" | "red" | "unknown"; commit?: string; at?: string };
type Findings = { critical: number; high: number; medium: number; low?: number; at?: string };

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

function cmdList(args: Args): void {
  const { tasks } = loadTasks();
  const want = (k: string, v: string) => { const o = args.opt(k); return o === undefined || o === v; };
  const rows = tasks.filter(
    (t) =>
      want("milestone", t.milestone) &&
      want("status", t.status) &&
      want("owner", t.owner) &&
      want("risk", t.risk),
  );
  if (args.flag("json")) {
    console.log(JSON.stringify(rows.map(({ item, ...rest }) => rest), null, 2));
    return;
  }
  if (rows.length === 0) { console.log("no matching tasks"); return; }
  const w = Math.max(...rows.map((t) => t.id.length));
  for (const t of rows) {
    const met = t.acceptance.length ? ` ${t.acceptance_met.length}/${t.acceptance.length}` : "";
    const flag = t.risk === "high" ? " !" : "  ";
    console.log(`${t.id.padEnd(w)}${flag} ${t.status.padEnd(11)} ${t.estimate.padEnd(2)}${met.padEnd(5)} ${t.title}`);
  }
  console.log(`\n${rows.length} task(s)`);
}

function cmdNext(args: Args): void {
  const { tasks } = loadTasks();
  const byId = new Map(tasks.map((t) => [t.id, t]));
  const ready = tasks.filter(
    (t) =>
      (t.status === "todo" || t.status === "ready") &&
      t.acceptance.length > 0 &&
      t.estimate !== "XL" &&
      t.depends_on.every((d) => byId.get(d)?.status === "done") &&
      (!args.opt("milestone") || t.milestone === args.opt("milestone")),
  );
  if (ready.length === 0) { console.log("nothing is ready — check blocked tasks and dependencies"); return; }
  console.log("Ready to start (dependencies met, acceptance defined):\n");
  for (const t of ready) console.log(`  ${t.id}  ${t.estimate}  ${t.risk === "high" ? "!" : " "} ${t.title}`);
}

function cmdAdd(args: Args): void {
  const doc = loadTasks();
  const milestone = required(args.opt("milestone"), "--milestone");
  if (!/^M[0-7]$/.test(milestone)) die(`bad --milestone "${milestone}"`);
  const title = required(args.opt("title"), "--title");
  const seq = doc.tasks.filter((t) => t.milestone === milestone).reduce((mx, t) => Math.max(mx, Number(t.id.slice(6))), 0);
  const id = `RL-${milestone}-${String(seq + 1).padStart(3, "0")}`;

  const block = [
    `- id: ${id}`,
    `  title: ${title}`,
    `  milestone: ${milestone}`,
    `  status: todo`,
    `  owner: ${args.opt("owner") ?? "agent"}`,
    `  estimate: ${args.opt("estimate") ?? "M"}`,
    `  depends_on: []`,
    `  blocks: []`,
    `  risk: ${args.opt("risk") ?? "low"}`,
    `  acceptance:`,
    `    - TODO define acceptance before this task can start`,
    `  artifacts: []`,
    `  decisions: []`,
  ];
  while (doc.lines.length && isBlank(doc.lines.at(-1)!)) doc.lines.pop();
  doc.lines.push(...block, "");
  save(doc);
  console.log(`added ${id}`);
}

function cmdStart(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const doc = loadTasks();
  const t = requireTask(doc, id);
  const byId = new Map(doc.tasks.map((x) => [x.id, x]));

  if (t.status === "done") die(`${id} is already done`);
  if (t.acceptance.length === 0) die(`${id} has no acceptance lines — Definition of Ready not met`);
  if (t.estimate === "XL") die(`${id} is XL — split it before starting (brief §2.2)`);
  const unmet = t.depends_on.filter((d) => byId.get(d)?.status !== "done");
  if (unmet.length) die(`${id} depends on unfinished work: ${unmet.join(", ")}`);

  setScalar(doc, id, "status", "in-progress");
  save(doc);
  const d2 = reload();
  setScalar(d2, id, "started_at", today());
  save(d2);
  console.log(`${id} -> in-progress`);
  if (t.risk === "high") {
    console.log(`  ! risk: high — this task needs a security-suite artifact before it can be marked done.`);
  }
}

function cmdBlock(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const reason = required(args.opt("reason"), "--reason");
  const doc = loadTasks();
  const prior = requireTask(doc, id);

  setScalar(doc, id, "status", "blocked");
  save(doc);
  let d = reload();
  if (!prior.blocked_at) { setScalar(d, id, "blocked_at", today()); save(d); d = reload(); }
  appendNote(d, id, `${today()} — blocked: ${reason}`);
  save(d);
  console.log(`${id} -> blocked`);

  const since = prior.blocked_at || today();
  if (daysBetween(since, today()) >= 1 || prior.status === "blocked") {
    ensureRiskEntry(id, reason, since);
    console.log(`  logged to ${rel(RISKS_PATH)} (blocked since ${since})`);
    console.log(`  brief §2.10: two consecutive blocked sessions is a stop-and-ask condition.`);
  }
}

function cmdUnblock(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const doc = loadTasks();
  requireTask(doc, id);
  setScalar(doc, id, "status", args.opt("status") ?? "in-progress");
  save(doc);
  const d = reload();
  appendNote(d, id, `${today()} — unblocked: ${args.opt("reason") ?? "resolved"}`);
  save(d);
  console.log(`${id} -> ${args.opt("status") ?? "in-progress"}`);
}

function cmdCheck(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const n = Number(required(args.positional[1], "<acceptance-line-number>"));
  const doc = loadTasks();
  const t = requireTask(doc, id);
  if (!Number.isInteger(n) || n < 1 || n > t.acceptance.length) {
    die(`${id} has ${t.acceptance.length} acceptance line(s); ${n} is out of range`);
  }
  const met = new Set(t.acceptance_met);
  if (args.flag("uncheck")) met.delete(n); else met.add(n);
  setFlowList(doc, id, "acceptance_met", [...met].sort((a, b) => a - b));
  save(doc);
  console.log(`${id} acceptance ${n} ${args.flag("uncheck") ? "uncleared" : "met"} (${met.size}/${t.acceptance.length})`);
  t.acceptance.forEach((a, i) => console.log(`  [${met.has(i + 1) ? "x" : " "}] ${i + 1}. ${a}`));
}

/**
 * Move a task to `review`: the work is built and everything checkable has been
 * checked, but something outside this machine has to confirm it before it can
 * honestly be called done. Closing such a task with `--no-ci` would assert more
 * than is known.
 */
function cmdReview(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const reason = required(args.opt("reason"), '--reason "what still needs confirming"');
  const doc = loadTasks();
  const t = requireTask(doc, id);
  if (t.acceptance.length === 0) die(`${id} has no acceptance lines`);

  setScalar(doc, id, "status", "review");
  save(doc);
  appendNote(reload(), id, `${today()} — in review: ${reason}`);
  save(reload());
  console.log(`${id} -> review (${t.acceptance_met.length}/${t.acceptance.length} acceptance verified)`);
}

function cmdNote(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const text = required(args.positional.slice(1).join(" ") || args.opt("text"), "<text>");
  const doc = loadTasks();
  requireTask(doc, id);
  appendNote(doc, id, `${today()} — ${text}`);
  save(doc);
  console.log(`noted on ${id}`);
}

function cmdDone(args: Args): void {
  const id = required(args.positional[0], "<task-id>");
  const doc = loadTasks();
  const t = requireTask(doc, id);

  const missing = t.acceptance.map((_, i) => i + 1).filter((n) => !t.acceptance_met.includes(n));
  if (missing.length) {
    console.error(`${id} cannot be done — unmet acceptance lines:`);
    for (const n of missing) console.error(`  [ ] ${n}. ${t.acceptance[n - 1]}`);
    console.error(`\nCheck them off with:  tasks check ${id} <n>`);
    process.exit(1);
  }

  if (t.risk === "high") {
    const covered = t.artifacts.some((a) => SECURITY_TEST_PATTERNS.some((re) => re.test(a)));
    if (!covered) {
      die(`${id} is risk: high and lists no security-suite artifact.\n` +
          `  Add the test path to "artifacts" (test/security/**, test/authz/**, *_security_test.go, *.security.test.ts).`);
    }
  }

  const ci = readJson<CiStatus>(CI_STATUS_PATH);
  if (ci?.status !== "green") {
    const why = ci ? `CI is "${ci.status}"` : `no CI status at ${rel(CI_STATUS_PATH)}`;
    if (!args.opt("no-ci")) {
      die(`${id} cannot be done — ${why}.\n` +
          `  Once CI runs it writes that file. To close a task before CI exists, pass:\n` +
          `    tasks done ${id} --no-ci "<reason, recorded in the task notes>"`);
    }
    console.log(`  ! closing without CI: ${args.opt("no-ci")}`);
  }

  setScalar(doc, id, "status", "done");
  save(doc);
  let d = reload();
  setScalar(d, id, "done_at", today());
  save(d);
  if (args.opt("no-ci")) {
    d = reload();
    appendNote(d, id, `${today()} — closed without CI verification: ${args.opt("no-ci")}`);
    save(d);
  }
  console.log(`${id} -> done`);

  const unblocked = reload().tasks.filter(
    (x) => x.depends_on.includes(id) && x.depends_on.every((dep) => dep === id || dependencyDone(dep)),
  );
  if (unblocked.length) console.log(`  now ready: ${unblocked.map((x) => x.id).join(", ")}`);
}

function dependencyDone(id: string): boolean {
  return loadTasks().tasks.find((t) => t.id === id)?.status === "done";
}

/**
 * `blocks` is the inverse of `depends_on`. The brief's schema carries both so a
 * task shows its downstream impact without a query, but keeping two directions
 * consistent by hand is busywork that produces exactly the kind of stale
 * tracker the brief forbids. Author `depends_on`; derive `blocks` from it.
 */
function cmdSyncBlocks(args: Args): void {
  let doc = loadTasks();
  const ids = new Set(doc.tasks.map((t) => t.id));
  const wanted = new Map<string, string[]>(doc.tasks.map((t) => [t.id, []]));
  let dangling = 0;

  for (const t of doc.tasks) {
    for (const d of t.depends_on) {
      if (!ids.has(d)) { console.error(`warn: ${t.id} depends_on unknown task ${d}`); dangling++; continue; }
      wanted.get(d)!.push(t.id);
    }
  }
  if (dangling && !args.flag("force")) die(`${dangling} dangling dependency reference(s); fix them or pass --force`);

  let changed = 0;
  for (const [id, list] of wanted) {
    const current = doc.tasks.find((t) => t.id === id)!.blocks;
    const next = list.sort();
    if (current.length === next.length && current.every((v, i) => v === next[i])) continue;
    setFlowList(doc, id, "blocks", next);
    save(doc);
    doc = reload();
    changed++;
  }
  console.log(changed === 0 ? "blocks already consistent with depends_on" : `updated blocks on ${changed} task(s)`);
}

function cmdValidate(): void {
  // milestones.yaml is validated too, and it was not before. `validate` read only
  // tasks.yaml, so a malformed `exit_met` passed with "0 warning(s)" and the
  // damage showed up as a gate report and a STATUS.md that disagreed about
  // whether a milestone's exit criteria were met — both generated from this file.
  //
  // Loading it is the whole check: loadMilestones() rejects a bad index itself.
  // Calling it here is what puts that rejection in front of CI (brief §2.3, a
  // malformed tracker fails the build on its own merits).
  loadMilestones();

  const doc = loadTasks();
  const problems = validateDoc(doc);
  const errors = problems.filter((p) => p.level === "error");
  const warns = problems.filter((p) => p.level === "warn");

  for (const w of warns) console.error(`warn  ${w.where}: ${w.message}`);
  for (const e of errors) console.error(`ERROR ${e.where}: ${e.message}`);

  if (errors.length) {
    console.error(`\ntasks.yaml is invalid: ${errors.length} error(s), ${warns.length} warning(s)`);
    process.exit(1);
  }
  console.log(`tasks.yaml OK — ${doc.tasks.length} tasks, ${warns.length} warning(s)`);
}

function cmdRender(args: Args): void {
  const doc = loadTasks();
  if (validateDoc(doc).some((p) => p.level === "error")) {
    die("refusing to render from an invalid tasks.yaml — run `tasks validate`");
  }
  const milestones = loadMilestones();
  const metrics = readJson<Metrics>(METRICS_PATH);
  const findings = readJson<Findings>(FINDINGS_PATH);
  const ci = readJson<CiStatus>(CI_STATUS_PATH);
  const now = today();

  const out: string[] = [];
  const pct = (n: number, d: number) => (d === 0 ? 0 : Math.round((n / d) * 100));
  const bar = (n: number, d: number) => {
    const filled = Math.round((pct(n, d) / 100) * 24);
    return `\`${"#".repeat(filled)}${"-".repeat(24 - filled)}\``;
  };

  out.push(
    `# Ratline — status`,
    ``,
    `<!-- GENERATED BY \`scripts/tasks render\`. Do not hand-edit; your changes will be overwritten. -->`,
    `Generated ${now}.`,
    ``,
    `## Milestones`,
    ``,
    `| Milestone | Progress | Done | Total | Open high-risk |`,
    `| --- | --- | ---: | ---: | ---: |`,
  );

  const order = ["M0", "M1", "M2", "M3", "M4", "M5", "M6", "M7"];
  for (const m of order) {
    const inM = doc.tasks.filter((t) => t.milestone === m && t.status !== "dropped");
    if (inM.length === 0) continue;
    const done = inM.filter((t) => t.status === "done").length;
    const hi = inM.filter((t) => t.risk === "high" && t.status !== "done").length;
    const name = milestones.find((x) => x.id === m)?.name ?? "";
    out.push(`| **${m}** ${name} | ${bar(done, inM.length)} ${pct(done, inM.length)}% | ${done} | ${inM.length} | ${hi} |`);
  }

  // Current milestone = lowest with unfinished, non-dropped work.
  const current =
    order.find((m) => doc.tasks.some((t) => t.milestone === m && t.status !== "done" && t.status !== "dropped")) ?? order.at(-1)!;
  const cm = milestones.find((x) => x.id === current);

  out.push(``, `## Current milestone — ${current}${cm ? `: ${cm.name}` : ""}`, ``);
  if (cm?.goal) out.push(cm.goal, ``);
  if (cm?.exit_criteria.length) {
    out.push(`### Exit criteria`, ``);
    cm.exit_criteria.forEach((c, i) => out.push(`- [${cm.exit_met.includes(i + 1) ? "x" : " "}] ${c}`));
    out.push(``, `${cm.exit_met.length} of ${cm.exit_criteria.length} met.`, ``);
  }

  const age = (from: string) => (from ? `${daysBetween(from, now)}d` : "—");
  const section = (title: string, rows: Task[], stamp: (t: Task) => string) => {
    out.push(`## ${title}`, ``);
    if (rows.length === 0) { out.push(`_None._`, ``); return; }
    out.push(`| Task | Age | Owner | Risk | Acceptance | Title |`, `| --- | ---: | --- | --- | ---: | --- |`);
    for (const t of rows) {
      out.push(
        `| \`${t.id}\` | ${stamp(t)} | ${t.owner} | ${t.risk === "high" ? "**high**" : t.risk} | ` +
        `${t.acceptance_met.length}/${t.acceptance.length} | ${t.title} |`,
      );
    }
    out.push(``);
  };

  section("In progress", doc.tasks.filter((t) => t.status === "in-progress"), (t) => age(t.started_at));
  section("Blocked", doc.tasks.filter((t) => t.status === "blocked"), (t) => age(t.blocked_at));
  section("In review", doc.tasks.filter((t) => t.status === "review"), (t) => age(t.started_at));

  const uncovered = doc.tasks.filter(
    (t) => t.risk === "high" && t.status !== "done" && t.status !== "dropped" &&
      !t.artifacts.some((a) => SECURITY_TEST_PATTERNS.some((re) => re.test(a))),
  );
  out.push(`## Open high-risk tasks without security-test coverage`, ``);
  if (uncovered.length === 0) {
    out.push(`_None._`, ``);
  } else {
    out.push(`These cannot be marked \`done\` until they name a security-suite artifact (brief §2.2).`, ``);
    for (const t of uncovered) out.push(`- \`${t.id}\` (${t.milestone}, ${t.status}) — ${t.title}`);
    out.push(``);
  }

  out.push(`## Test health`, ``);
  if (!metrics) {
    out.push(
      `_Not yet measured._ \`scripts/tasks render\` reads \`.ratline/metrics.json\`, which CI writes.`,
      `Until the control plane has a test suite (M1), this section stays empty by design rather than`,
      `reporting invented numbers.`,
      ``,
    );
  } else {
    const row = (label: string, v?: { passed: number; total: number }) =>
      v ? `| ${label} | ${v.passed} / ${v.total} | ${pct(v.passed, v.total)}% |` : `| ${label} | not measured | — |`;
    out.push(`| Suite | Passing | Rate |`, `| --- | ---: | ---: |`);
    out.push(row("Unit", metrics.unit));
    out.push(row("Integration", metrics.integration));
    out.push(row("Authorization matrix", metrics.authz_matrix));
    out.push(
      `| \`src/authz/**\` line coverage | ${metrics.authz_coverage_pct ?? "—"}% | must be 100% |`,
      `| \`can()\` branch coverage | ${metrics.can_branch_coverage_pct ?? "—"}% | must be 100% |`,
      ``,
      `Measured ${metrics.measured_at ?? "unknown"}.`,
      ``,
    );

    // The matrix reports separately, because a pass rate on its own would be
    // misleading in a specific way: it says nothing about WHICH LAYER verified
    // the cells, and while there is no HTTP server every one of them is
    // verified below the route. That number belongs on the page, not in a
    // commit message nobody rereads.
    const cells = metrics.authz_matrix_cells;
    out.push(`### Authorization matrix (role × endpoint × subject)`, ``);
    if (!cells || !cells.executed) {
      out.push(`**Not executed.** ${cells?.note ?? "No result was written. It is unknown, not green."}`, ``);
    } else {
      const by = cells.verified_by;
      out.push(
        `| | |`, `| --- | ---: |`,
        `| Cells passing | ${cells.passed ?? 0} / ${cells.cells ?? 0} |`,
        `| Endpoints × roles | ${cells.routes ?? 0} × ${cells.roles ?? 0} |`,
        `| Verified end to end (real request) | ${by?.transport ?? 0} |`,
        `| Verified at the decision layer (\`can()\`) | ${by?.decision ?? 0} |`,
        `| Unguarded by declaration, nothing to decide | ${by?.declaration ?? 0} |`,
        ``,
      );
      if ((by?.transport ?? 0) === 0) {
        out.push(
          `> No cell is verified end to end. Either there is no HTTP server, or the harness`,
          `> has stopped driving it — both mean a route that forgets to consult the data`,
          `> layer would not be caught here.`,
          ``,
        );
      } else if ((by?.decision ?? 0) > 0) {
        out.push(
          `> The remainder is verified one layer down, against \`can()\` with real grants and`,
          `> row-level security. Two things are not expressible as a request: a route the`,
          `> server does not bind, and a cross-tenant subject on a route with no identifier`,
          `> in its path — the tenant comes from the session, so a URL cannot name another.`,
          ``,
        );
      }
    }
  }

  out.push(`## Security findings`, ``);
  if (!findings) {
    out.push(`_Not yet measured._ CI writes \`.ratline/security-findings.json\`. **Critical and high must be 0 at every gate.**`, ``);
  } else {
    const gate = findings.critical === 0 && findings.high === 0 ? "PASS" : "**FAIL — gate blocked**";
    out.push(
      `| Severity | Open |`, `| --- | ---: |`,
      `| Critical | ${findings.critical} |`, `| High | ${findings.high} |`, `| Medium | ${findings.medium} |`,
      ``, `Gate check (critical + high must be zero): ${gate}`, ``,
    );
  }

  out.push(
    `## Build`, ``,
    ci ? `CI: **${ci.status}**${ci.commit ? ` at \`${ci.commit.slice(0, 8)}\`` : ""}${ci.at ? ` (${ci.at})` : ""}` : `CI: _no status recorded yet._`,
    ``,
    `## Totals`, ``,
    `| Status | Count |`, `| --- | ---: |`,
  );
  for (const st of STATUSES) {
    const n = doc.tasks.filter((t) => t.status === st).length;
    if (n) out.push(`| ${st} | ${n} |`);
  }
  out.push(`| **all** | **${doc.tasks.length}** |`, ``);

  const rendered = out.join("\n");

  if (args.flag("check")) {
    if (!existsSync(STATUS_PATH)) die(`${rel(STATUS_PATH)} does not exist — run \`tasks render\``);
    const drift = trackerDrift(readFileSync(STATUS_PATH, "utf8"), rendered);
    if (drift.length) {
      console.error(`${rel(STATUS_PATH)} is stale or was hand-edited. Sections that differ:`);
      for (const section of drift) console.error(`  - ${section}`);
      console.error(`\nRun \`./scripts/tasks render\` and commit the result.`);
      process.exit(1);
    }
    console.log(`${rel(STATUS_PATH)} is current`);
    return;
  }

  writeFileSync(STATUS_PATH, rendered, "utf8");
  console.log(`wrote ${rel(STATUS_PATH)} — ${doc.tasks.length} tasks, current milestone ${current}`);
}

/**
 * Sections of STATUS.md derived from CI artefacts rather than from tasks.yaml.
 * They legitimately change on every run — timestamps, machine-specific counts —
 * so comparing them would make the currency check fail for the wrong reason.
 * "STATUS.md is current" means "the tracker-derived content is current".
 */
const VOLATILE_SECTIONS = new Set(["Test health", "Security findings", "Build"]);

/** Names of the tracker-derived sections whose content differs between two renders. */
function trackerDrift(committed: string, fresh: string): string[] {
  const sections = (doc: string): Map<string, string> => {
    const map = new Map<string, string>();
    let name = "(preamble)";
    let body: string[] = [];
    for (const line of doc.split("\n")) {
      const heading = /^## (.+)$/.exec(line);
      if (heading) {
        map.set(name, body.join("\n").trim());
        name = heading[1] ?? "";
        body = [];
        continue;
      }
      // The generation stamp moves with the clock, not with the tracker.
      if (/^Generated \d{4}-\d{2}-\d{2}\.$/.test(line)) continue;
      body.push(line);
    }
    map.set(name, body.join("\n").trim());
    return map;
  };

  const a = sections(committed);
  const b = sections(fresh);
  const names = new Set([...a.keys(), ...b.keys()]);
  const drift: string[] = [];
  for (const name of names) {
    if (VOLATILE_SECTIONS.has(name)) continue;
    if (a.get(name) !== b.get(name)) drift.push(name);
  }
  return drift;
}

function ensureRiskEntry(id: string, reason: string, since: string): void {
  mkdirSync(dirname(RISKS_PATH), { recursive: true });
  const header = "# Ratline — open risks\n\nBlocked tasks are appended here automatically by `tasks block` (brief §2.3).\n";
  const body = existsSync(RISKS_PATH) ? readFileSync(RISKS_PATH, "utf8") : header;
  if (body.includes(`<!-- risk:${id} -->`)) return;
  const entry =
    `\n## ${id} — blocked since ${since} <!-- risk:${id} -->\n\n` +
    `- **Reason:** ${reason}\n- **Owner:** unassigned — assign before the next gate\n` +
    `- **Likelihood:** unassessed\n- **Mitigation:** unassessed\n`;
  writeFileSync(RISKS_PATH, body.replace(/\s*$/, "\n") + entry, "utf8");
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/**
 * Options and flags are exposed as accessors rather than bare records. A record
 * indexed by an arbitrary string hands back `string | undefined` at every call
 * site under `noPropertyAccessFromIndexSignature`; an accessor states that once.
 */
type Args = {
  cmd: string;
  positional: string[];
  opt(name: string): string | undefined;
  flag(name: string): boolean;
};

function parseArgv(argv: string[]): Args {
  const [cmd = "help", ...rest] = argv;
  const positional: string[] = [];
  const opts = new Map<string, string>();
  const flags = new Set<string>();

  for (let i = 0; i < rest.length; i++) {
    const a = rest[i] ?? "";
    if (!a.startsWith("--")) { positional.push(a); continue; }
    const key = a.slice(2);
    const next = rest[i + 1];
    if (next !== undefined && !next.startsWith("--")) { opts.set(key, next); i++; } else { flags.add(key); }
  }

  return { cmd, positional, opt: (n) => opts.get(n), flag: (n) => flags.has(n) };
}

function requireTask(doc: Doc, id: string): Task {
  const t = doc.tasks.find((x) => x.id === id);
  if (!t) die(`no such task: ${id}`);
  return t;
}
function required<T>(v: T | undefined, what: string): T {
  if (v === undefined || v === "") die(`missing required argument ${what}`);
  return v;
}
function die(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(1);
}
function rel(p: string): string {
  return p.startsWith(ROOT) ? p.slice(ROOT.length + 1) : p;
}
function today(): string {
  return new Date().toISOString().slice(0, 10);
}
function daysBetween(a: string, b: string): number {
  const ms = Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`);
  return Number.isNaN(ms) ? 0 : Math.max(0, Math.round(ms / 86_400_000));
}

const HELP = `Ratline task tracker — source of truth is docs/tasks.yaml (brief §2).

  tasks list [--milestone M2] [--status in-progress] [--owner agent] [--risk high] [--json]
  tasks next [--milestone M2]              tasks whose dependencies are met
  tasks add --milestone M2 --title "..." [--estimate M] [--risk low] [--owner agent]
  tasks start <id>                         enforces the Definition of Ready
  tasks check <id> <n> [--uncheck]         mark acceptance line n met
  tasks note <id> <text>                   append a dated note
  tasks review <id> --reason "..."         built and locally verified, needs outside confirmation
  tasks block <id> --reason "..."          also writes docs/RISKS.md
  tasks unblock <id> [--reason "..."] [--status ready]
  tasks done <id> [--no-ci "<reason>"]     requires all acceptance met + green CI
  tasks sync-blocks                        derive "blocks" from "depends_on"
  tasks validate                           schema, graph, cycles, brief rules (runs in CI)
  tasks render [--check]                   regenerates docs/STATUS.md (--check: fail if stale)
`;

function main(): void {
  const args = parseArgv(process.argv.slice(2));
  switch (args.cmd) {
    case "list": return cmdList(args);
    case "next": return cmdNext(args);
    case "add": return cmdAdd(args);
    case "start": return cmdStart(args);
    case "check": return cmdCheck(args);
    case "note": return cmdNote(args);
    case "review": return cmdReview(args);
    case "block": return cmdBlock(args);
    case "unblock": return cmdUnblock(args);
    case "done": return cmdDone(args);
    case "sync-blocks": return cmdSyncBlocks(args);
    case "validate": return cmdValidate();
    case "render": return cmdRender(args);
    case "help": case "--help": case "-h": console.log(HELP); return;
    default:
      console.error(`unknown command "${args.cmd}"\n`);
      console.error(HELP);
      process.exit(1);
  }
}

main();
