/**
 * Re-export point for the database handle.
 *
 * IMPORTING THIS FROM ANYWHERE OUTSIDE src/repo/ IS A BUG. RL-M1-008 makes it a
 * lint failure; until then it is a review failure. See handle.ts for why.
 */

export { scoped, connect, disconnect, assertNotPrivileged } from "./handle.ts";
export type { ScopedQuery, PoolOptions, Row } from "./handle.ts";
