/**
 * FIXTURE — this file MUST fail lint. RL-M1-008, acceptance 4.
 *
 * C3 layer 1: nothing outside src/repo/ may import the raw database handle.
 * This file is outside src/repo/ and imports it twice — once by the module that
 * defines it, once by the re-export point — so `no-restricted-imports` fires
 * twice.
 *
 * It is excluded from `npm run lint` by the top-level `ignores` in
 * eslint.config.js and linted deliberately by
 * test/security/lint_rules.test.ts. Do not "fix" the imports below: the failure
 * is the point. If this file ever passes lint, the rule that makes an unscoped
 * read unwritable has stopped working.
 *
 * It still has to typecheck, because tsconfig.json includes test/**\/*.ts, so
 * the imported bindings are real and referenced.
 */

import { scoped } from "../../../src/db/internal/handle.ts";
import { connect } from "../../../src/db/internal/index.ts";

export const reachedTheHandle = { scoped, connect };
