/**
 * The Ratline ESLint plugin (RL-M1-008).
 *
 * Rules that encode a hard constraint from the brief and have nowhere else to
 * live. Everything enforceable with a stock rule is configured in
 * eslint.config.js instead — a custom rule is a maintenance cost, so it needs to
 * be earning something.
 *
 * Each rule here is paired with a fixture under test/fixtures/lint/ that
 * violates it, and test/security/lint_rules.test.ts runs ESLint over those
 * fixtures and asserts the rule fired. A rule with no failing fixture is a
 * comment with extra steps.
 */

import noShellTemplateLiteral from "./no-shell-template-literal.js";

export default {
	meta: {
		name: "eslint-plugin-ratline",
		version: "0.0.0",
	},
	rules: {
		"no-shell-template-literal": noShellTemplateLiteral,
	},
};
