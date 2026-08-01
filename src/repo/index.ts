/**
 * The repository layer — the only importer of `src/db/internal/`.
 *
 * Everything outside this directory reaches data through these exports. Nothing
 * outside it may import the handle, which RL-M1-008 enforces with a lint rule
 * and a fixture proving the rule fires.
 *
 * Two rules hold across every module here, and both are tested rather than
 * documented and hoped for:
 *
 *   1. `ctx: AuthzContext` is the first parameter of every exported function.
 *   2. Absent and forbidden are the same answer — `null` — because the query
 *      cannot see the difference either.
 */

export * from "./organizations.ts";
export * from "./audit.ts";
