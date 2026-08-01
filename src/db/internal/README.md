# `src/db/internal` — the only place the database handle exists

This directory constructs the Drizzle client. **Nothing outside `src/repo/` may
import from here**, enforced by lint (RL-M1-008) with a fixture proving the rule
fires.

The only export intended for use is `scoped(ctx, table)`, which injects the
tenant predicate. There is no exported unscoped read, so a repository function
cannot reach the database without a tenant. See ADR 0003.

This is layer 1 of three. Layer 2 is the branded `AuthzContext` required by every
repository signature; layer 3 is Postgres row-level security, which holds even if
1 and 2 are both wrong.
