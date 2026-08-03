# `src/ops` — the operation catalogue

The complete, closed set of operations an agent will ever execute, with typed
arguments. **There is no operation that carries a shell command.** This is the
property that satisfies C1 (ADR 0002).

Agent-side types are generated from this schema so the two sides cannot drift,
and the fuzz corpus (RL-M2-027) is enumerated from it so a new field cannot be
added without coverage.

Adding an operation costs a catalogue entry, generated types on both sides,
argument validators in the agent *and* independently in the privileged helper,
and fuzz coverage. That friction is the feature.
