/**
 * FIXTURE — the file no test loads, for test/toolchain/coverage_gate.test.ts.
 *
 * Its role is to exist on disk and be absent from a coverage report, which is
 * what an unimported file really looks like: not 0%, not there. See
 * `decides.ts` in this directory for why the pair lives here and not under
 * `src/authz/`.
 */

export const NOT_LOADED = "this file's path is the fixture; its contents are not";
