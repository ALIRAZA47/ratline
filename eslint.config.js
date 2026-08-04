// Ratline lint configuration.
//
// This file is load-bearing, not cosmetic. Several of the brief's hard
// constraints are enforced here because a lint rule catches at review time what
// a convention only catches at incident time:
//
//   RL-M1-001 — no `any` in application code.
//   RL-M1-008 — no raw database handle outside src/repo/ (C3),
//               no process-spawning modules in the control plane (C2),
//               no shell construction by template literal (C2).
//
// RL-M1-008's three rules are below. Each has a fixture under
// test/fixtures/lint/ that violates it, and test/security/lint_rules.test.ts
// runs ESLint over those fixtures and asserts the rule fired — so deleting a
// rule here turns a test red rather than quietly widening what is writable.
//
// Read this before editing a `files:` scope below: `no-restricted-imports` takes
// ONE options object per file. A later config block does not merge with an
// earlier one, it REPLACES it. That is why every scope is composed from the
// `restrictedImports()` helper rather than adding restrictions block by block —
// written the naive way, giving src/** its process-spawning ban would have
// silently removed its database-handle ban.

import tseslint from "typescript-eslint";

import ratline from "./tools/eslint/index.js";

// --- C3 layer 1: the raw database handle is unreachable ---------------------
// ADR 0003. src/db/internal/ holds the only connection in the process and the
// only thing that runs SQL. Reaching it from outside src/repo/ is how an
// unscoped read gets written, so the import itself is what fails.
//
// Patterns match the import SOURCE STRING, not a resolved path, so both the
// full form (`../../src/db/internal/handle.ts`) and the sibling form
// (`./internal/handle.ts`, reachable only from inside src/db/) are listed.
const DB_HANDLE_GROUP = {
	group: ["**/db/internal", "**/db/internal/**", "./internal", "./internal/**"],
	message:
		"src/db/internal/ is the raw database handle (C3, ADR 0003 layer 1). Only src/repo/ may " +
		"import it. Everything else reaches data through a repository function that takes an " +
		"AuthzContext — if the query you want does not exist yet, add it to src/repo/.",
};

// --- C2: the control plane executes no processes at all ---------------------
// ADR 0005: "The control plane executes no processes at all. A lint rule bans
// importing any process-spawning module in control plane code." That is the
// strongest available form of C2 — there is no command to inject into, safe or
// otherwise. Work that must happen on a host goes through an enumerated, typed
// agent operation.
const SPAWN_MESSAGE =
	"The control plane executes no processes (C2, ADR 0005). Nothing under src/ may import a " +
	"process-spawning module — that is what makes command injection structurally impossible " +
	"here rather than merely unlikely. Host-side work goes through a typed agent operation.";

const PROCESS_SPAWN_PATHS = [
	{ name: "child_process", message: SPAWN_MESSAGE },
	{ name: "node:child_process", message: SPAWN_MESSAGE },
];

// Not exhaustive and not meant to be: the standard-library door above is the
// one that matters. This list means a spawning dependency added later fails on
// its first import rather than on review, and §6.7 already requires a written
// justification for every new dependency.
const PROCESS_SPAWN_GROUP = {
	group: ["execa", "zx", "shelljs", "cross-spawn", "node-pty", "sudo-prompt"],
	message: SPAWN_MESSAGE,
};

/** Compose the complete `no-restricted-imports` options for one file scope. */
const restrictedImports = ({ dbHandle = false, processSpawning = false }) => {
	const patterns = [];
	if (dbHandle) patterns.push(DB_HANDLE_GROUP);
	if (processSpawning) patterns.push(PROCESS_SPAWN_GROUP);
	return [
		"error",
		{
			paths: processSpawning ? PROCESS_SPAWN_PATHS : [],
			patterns,
		},
	];
};

export default tseslint.config(
	{
		ignores: [
			"node_modules/**",
			"docs/**",
			".ratline/**",
			"agent/**",

			// The documentation site. Hand-written HTML, CSS and vanilla JS with no
			// build step and no dependencies, deliberately — a docs site does not earn
			// one under §6.7. It is therefore not part of the typed project, and this
			// config's rules are type-aware: without this line every file there fails
			// with "was not found by the project service", which is what the first CI
			// run after it appeared did.
			//
			// Adding it to tsconfig instead would be the wrong fix. That would put
			// documentation markup inside the program `tsc --noEmit` checks and make
			// the control plane's typecheck depend on a page's script.
			"docs-site/**",

			// Scratch git worktrees for delegated agents. They contain complete
			// checkouts, so without this the sweep lints another branch's
			// work-in-progress and `npm run lint` fails on code that is not in
			// this tree at all.
			".claude/**",

			// Purpose-built violations. `npm run lint` must not fail on files
			// whose entire job is to fail lint. test/security/lint_rules.test.ts
			// lints them explicitly through the ESLint Node API with
			// `ignore: false`, against this same config — so they are excluded
			// from the sweep without being excluded from enforcement.
			"test/fixtures/lint/**",
		],
	},

	...tseslint.configs.recommendedTypeChecked,

	{
		plugins: { ratline },
		languageOptions: {
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
		rules: {
			// --- brief §6.7: no `any` in application code -----------------------
			"@typescript-eslint/no-explicit-any": "error",

			// `no-explicit-any` alone is not enough. Values can arrive as `any` from
			// JSON.parse or an untyped dependency and spread silently. These rules
			// stop an implicit `any` from propagating without ever being written.
			"@typescript-eslint/no-unsafe-assignment": "error",
			"@typescript-eslint/no-unsafe-member-access": "error",
			"@typescript-eslint/no-unsafe-call": "error",
			"@typescript-eslint/no-unsafe-return": "error",
			"@typescript-eslint/no-unsafe-argument": "error",

			// --- brief §9: silent catch blocks ----------------------------------
			"no-empty": ["error", { allowEmptyCatch: false }],

			// Omitting a field by rest-destructuring is the idiom, not a mistake.
			"@typescript-eslint/no-unused-vars": [
				"error",
				{ ignoreRestSiblings: true, argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
			],

			// --- C2: no shell command built by string interpolation --------------
			// RL-M1-008. The custom rule; see tools/eslint/no-shell-template-literal.js
			// for exactly what it does and does not detect. It applies everywhere,
			// including tests and scripts: C2 says "anywhere", and a test that
			// builds a shell string is teaching the pattern.
			"ratline/no-shell-template-literal": "error",

			// --- C3: the database handle is not importable here ------------------
			// The default for every file. src/** widens this to add the C2 import
			// ban; src/repo/, src/db/internal/ and test/** narrow it. See below.
			"no-restricted-imports": restrictedImports({ dbHandle: true }),

			// --- correctness ------------------------------------------------------
			// node:test's `test()` returns a promise the runner owns; awaiting it at
			// the top level is wrong. Allow those specifically rather than disabling
			// the rule, which is one of the few that catches real production bugs.
			"@typescript-eslint/no-floating-promises": [
				"error",
				{
					allowForKnownSafeCalls: [
						{
							from: "package",
							package: "node:test",
							name: ["test", "it", "describe", "suite", "before", "after", "beforeEach", "afterEach"],
						},
					],
				},
			],
			"@typescript-eslint/await-thenable": "error",
			"@typescript-eslint/no-misused-promises": "error",
			"@typescript-eslint/switch-exhaustiveness-check": "error",
			eqeqeq: ["error", "always", { null: "ignore" }],
			"no-console": "off",
		},
	},

	{
		// The control plane. Both import bans apply.
		files: ["src/**/*.ts"],
		rules: {
			"no-restricted-imports": restrictedImports({ dbHandle: true, processSpawning: true }),
		},
	},

	{
		// The two directories the handle exists for. They still may not spawn.
		files: ["src/repo/**/*.ts", "src/db/internal/**/*.ts"],
		rules: {
			"no-restricted-imports": restrictedImports({ processSpawning: true }),
		},
	},

	{
		// Tests may import the handle, and may spawn.
		//
		// The handle: the rule protects a production invariant — that no request
		// path can reach an unscoped query. A test importing the handle cannot
		// leak a tenant's data to anyone; it can only assert things about it, and
		// test/security/scoped_repository.test.ts has to import it to prove the
		// tenant does not outlive its transaction and that the app refuses a
		// BYPASSRLS role. Banning it here would leave two options, and both are
		// worse: mock the handle, which §9 forbids outright ("a test that mocks
		// the thing it is supposed to be testing"), or carry an eslint-disable in
		// the security suite, which teaches that the disable is routine. The
		// argument the other way is real — a test is code, and an exemption is a
		// hole — but the hole is in the test tree, where nothing is served to a
		// user, and layer 3 (row-level security) is not exempt from anything.
		//
		// Spawning: test/security/no_default_secrets.test.ts and
		// bind_default.test.ts spawn the real boot path, because "the application
		// exits" and "the socket is bound to 127.0.0.1" cannot be observed any
		// other honest way.
		files: ["test/**/*.ts"],
		rules: { "no-restricted-imports": "off" },
	},

	{
		// The fixtures are deliberately NOT covered by the test/** exemption
		// above, and carry exactly the configuration src/** carries. A fixture
		// living in an exempt directory would prove nothing at all, and the
		// acceptance criterion is that each rule has a fixture proving it FIRES.
		// lint_rules.test.ts asserts this block and the src/** block resolve to
		// identical options, so the fixtures cannot drift into testing a
		// configuration that governs nothing real.
		files: ["test/fixtures/lint/**/*.ts"],
		rules: {
			"no-restricted-imports": restrictedImports({ dbHandle: true, processSpawning: true }),
		},
	},

	{
		// scripts/ is repository tooling, not application code. It still may not
		// use `any`, but it reads JSON and YAML from disk, where a checked cast at
		// the boundary is the correct shape rather than a smell.
		files: ["scripts/**/*.ts"],
		rules: {
			"@typescript-eslint/no-unsafe-assignment": "off",
			"@typescript-eslint/no-unsafe-member-access": "off",
			"@typescript-eslint/no-unsafe-call": "off",
			"@typescript-eslint/no-unsafe-argument": "off",
		},
	},

	{
		// eslint.config.js and the plugin it loads are JavaScript, and outside the
		// tsconfig project.
		files: ["eslint.config.js", "tools/eslint/**/*.js"],
		...tseslint.configs.disableTypeChecked,
	},
);
