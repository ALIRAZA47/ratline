// Ratline lint configuration.
//
// This file is load-bearing, not cosmetic. Several of the brief's hard
// constraints are enforced here because a lint rule catches at review time what
// a convention only catches at incident time:
//
//   RL-M1-001 (this task) — no `any` in application code.
//   RL-M1-008 (later)     — no raw database handle outside src/repo/,
//                           no process-spawning modules in the control plane,
//                           no shell construction by template literal.
//
// RL-M1-008's rules are deliberately NOT here yet; they land with the code they
// police, alongside fixtures proving each one fires.

import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["node_modules/**", "docs/**", ".ratline/**", "agent/**"],
  },

  ...tseslint.configs.recommendedTypeChecked,

  {
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
    // eslint.config.js is JavaScript and outside the tsconfig project.
    files: ["eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
