/**
 * ratline/no-shell-template-literal — C2, enforced where the mistake is typed.
 *
 * C2: "No shell command is ever constructed by string interpolation. All remote
 * execution uses argv arrays with explicit arguments. No `sh -c` with any
 * user-derived data, anywhere. Add a lint rule and a CI check that fails the
 * build on template-literal shell construction."
 *
 * Three detectors, each reported with its own message id so a failure says
 * which shape it matched:
 *
 *   1. interpolatedArgument — a template literal WITH an interpolation passed
 *      directly to a call whose callee is named like a process launcher
 *      (`exec`, `execSync`, `spawn`, `spawnSync`, `execFile`, `execFileSync`,
 *      the `execa` family, or a `$` tag). Tagged templates count.
 *
 *   2. commandVariable — a template literal WITH an interpolation assigned to a
 *      binding, property or class field whose NAME reads as a command
 *      (`cmd`, `command`, `shellCommand`, `script`, …).
 *
 *   3. shellInvocation — a template literal WITH an interpolation whose own
 *      literal text reads as a shell or remote-execution invocation
 *      (`sh`, `bash`, `ssh`, `sudo …`, `/bin/sh`, …), wherever it appears.
 *      This is the "anywhere" half of C2: the string does not have to reach a
 *      call in this file to be the wrong thing to have built.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS RULE CANNOT SEE. Read this before trusting it.
 * ---------------------------------------------------------------------------
 *
 * It is a syntactic rule over one file. It has no type information, no taint
 * tracking and no cross-module view. Specifically it does NOT catch:
 *
 *   - Concatenation. `"git checkout " + ref`, `[a, b].join(" ")`,
 *     `parts.concat(ref)`, `util.format`, `String.raw` — none are template
 *     literals, none are seen. This is the single largest gap, and it is the
 *     reason this rule is one control among several rather than the control.
 *   - Indirection through a binding. `const c = "..." ; exec(c)` is invisible
 *     unless `c` happens to be named like a command (detector 2).
 *   - Aliased or computed callees. `const e = execSync; e(x)`,
 *     `cp["exec"](x)`, `handlers[name](x)` all match no name.
 *   - `spawn("sh", ["-c", userInput])`. Every argument is explicit, so nothing
 *     is interpolated — yet it is the exact `sh -c` shape C2 names. Nothing
 *     syntactic distinguishes it from a legitimate argv call. It is prevented
 *     instead by the import ban (`src/**` cannot reach `child_process` at all)
 *     and, on the agent side, by RL-M2-028 in Go, which ESLint never sees.
 *   - `{ shell: true }` passed to `spawn`. Same reasoning as above.
 *   - Anything outside the linted tree: the Go agent, SQL, systemd units,
 *     shell scripts under scripts/, and any dependency's own code.
 *
 * It also over-reports on purpose, in two ways:
 *
 *   - It does not ask whether the interpolated value is user-derived. It cannot
 *     know, and §9 lists "any string-interpolated shell command, however 'safe'
 *     the input looks" as an anti-pattern. Constant-only interpolation is
 *     flagged too.
 *   - Detector 2 keys on a name, not on what the value is used for. ADR 0005
 *     stores a user's build command as FILE CONTENT and executes the file by
 *     argv — legitimate, and a variable named `command` holding that text will
 *     be flagged here. The intended answer is an `eslint-disable-next-line`
 *     carrying the reason, which is a visible review point, rather than a
 *     silently permissive rule.
 *
 * A template literal with NO interpolation is never reported: nothing is being
 * constructed, so there is nothing for an attacker to steer.
 */

/**
 * Callee names that launch a process. Matched by NAME — `exec(x)` and
 * `child_process.exec(x)` both match, `cp["exec"](x)` does not.
 */
const LAUNCHER_NAMES = new Set([
	// node:child_process
	"exec",
	"execSync",
	"execFile",
	"execFileSync",
	"spawn",
	"spawnSync",
	// the usual third-party wrappers, listed so the rule survives a dependency
	// being added later without also needing to be remembered
	"execa",
	"execaSync",
	"execaCommand",
	"execaCommandSync",
	"$",
	// names we are likely to give our own helpers
	"sh",
	"shell",
]);

/** Words in an identifier that mean "this holds a command". */
const COMMAND_WORDS = new Set([
	"cmd",
	"cmds",
	"cmdline",
	"command",
	"commands",
	"commandline",
	"shellcommand",
	"shell",
	"script",
	"scripts",
	"invocation",
]);

/**
 * Trailing words that mean the binding holds something ABOUT a command rather
 * than the command itself. `scriptPath` and `commandName` are not commands.
 */
const NOT_THE_COMMAND_ITSELF = new Set([
	"path",
	"paths",
	"file",
	"filename",
	"dir",
	"directory",
	"url",
	"uri",
	"id",
	"name",
	"names",
	"label",
	"count",
	"length",
	"index",
	"regex",
	"pattern",
	"type",
	"kind",
]);

/**
 * A shell or remote-execution program at the head of a word. Deliberately
 * anchored so that "selfish" and "pushed" do not match "fish" and "sh".
 */
const SHELL_INVOCATION =
	/(?:^|[\s;&|(])(?:sudo\s+)?(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|fish|ssh|scp|su|eval)(?=\s|$)/;

/** `SHELL_COMMAND` / `shellCommand` / `shell-command` -> ["shell", "command"]. */
function splitWords(name) {
	return name
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.split(/[^A-Za-z0-9]+/)
		.filter((word) => word.length > 0)
		.map((word) => word.toLowerCase());
}

function looksLikeACommandName(name) {
	const words = splitWords(name);
	const last = words.at(-1);
	if (last === undefined || NOT_THE_COMMAND_ITSELF.has(last)) return false;
	return words.some((word) => COMMAND_WORDS.has(word));
}

/**
 * `RE.exec(s)` is a RegExp method, not child_process.exec. Only `exec` collides,
 * and only as a member call, so the exclusion is kept that narrow.
 */
function isRegExpExec(callee) {
	if (callee.type !== "MemberExpression") return false;
	if (callee.computed || callee.property.type !== "Identifier") return false;
	if (callee.property.name !== "exec") return false;
	const object = callee.object;
	if (object.type === "Literal" && Object.hasOwn(object, "regex")) return true;
	return (
		object.type === "Identifier" &&
		/(?:^|[^a-z])(?:re|regex|regexp|pattern)$/i.test(object.name)
	);
}

/** The name a callee is written with, or null if it is computed or dynamic. */
function calleeName(callee) {
	if (callee.type === "Identifier") return callee.name;
	if (
		callee.type === "MemberExpression" &&
		!callee.computed &&
		callee.property.type === "Identifier"
	) {
		return callee.property.name;
	}
	return null;
}

function isInterpolated(node) {
	return node.type === "TemplateLiteral" && node.expressions.length > 0;
}

/**
 * The literal text the author actually wrote, with a NUL where each
 * interpolation sits so that two halves of a word cannot join across one and
 * fabricate a match.
 */
function staticText(templateLiteral) {
	// The join uses NUL rather than a space: a space would fabricate the very
	// word boundary SHELL_INVOCATION looks for, so `bru${x}sh ` would read as
	// an `sh` invocation that nobody wrote.
	return templateLiteral.quasis
		.map((quasi) => quasi.value.cooked ?? quasi.value.raw)
		.join("\u0000");
}

/** The name written on the left of an assignment, or null. */
function assignedName(target) {
	if (target.type === "Identifier") return target.name;
	if (target.type === "PrivateIdentifier") return target.name;
	if (target.type === "Literal" && typeof target.value === "string") return target.value;
	if (
		target.type === "MemberExpression" &&
		!target.computed &&
		target.property.type === "Identifier"
	) {
		return target.property.name;
	}
	return null;
}

/** @type {import("eslint").Rule.RuleModule} */
export default {
	meta: {
		type: "problem",
		docs: {
			description:
				"Disallow constructing a shell command with a template literal (hard constraint C2)",
		},
		schema: [],
		messages: {
			interpolatedArgument:
				"`{{callee}}` is being handed a command built by string interpolation. C2 forbids this: pass an argv array whose elements are explicit arguments, so no value can become syntax. (A template literal INSIDE the argv array is a single argument's value and is fine.)",
			commandVariable:
				"`{{name}}` is a command built by string interpolation, which C2 forbids however safe the input looks. Build an argv array instead. If this is command TEXT written to a file and executed by path (ADR 0005), disable this line explicitly and say so.",
			shellInvocation:
				"This template literal interpolates into what reads as a shell invocation (`{{matched}}`). C2 allows no `sh -c` with any user-derived data, anywhere — even if this string is never executed in this file.",
		},
	},

	create(context) {
		/** Detector 3 — applies to every interpolated template literal. */
		function checkShellInvocation(node) {
			const match = SHELL_INVOCATION.exec(staticText(node));
			if (match === null) return;
			context.report({
				node,
				messageId: "shellInvocation",
				data: { matched: match[0].trim() },
			});
		}

		/** Detector 1 — direct arguments of a launcher call. */
		function checkLauncherCall(node) {
			if (isRegExpExec(node.callee)) return;
			const name = calleeName(node.callee);
			if (name === null || !LAUNCHER_NAMES.has(name)) return;
			for (const argument of node.arguments) {
				// Only DIRECT arguments. An interpolated template inside an
				// ArrayExpression argument is one argv element — a value, not
				// syntax — which is the shape C2 asks for.
				if (isInterpolated(argument)) {
					context.report({
						node: argument,
						messageId: "interpolatedArgument",
						data: { callee: name },
					});
				}
			}
		}

		/** Detector 2 — an interpolated template landing in a command-ish name. */
		function checkCommandName(target, value) {
			if (!isInterpolated(value)) return;
			const name = assignedName(target);
			if (name === null || !looksLikeACommandName(name)) return;
			context.report({ node: value, messageId: "commandVariable", data: { name } });
		}

		return {
			TemplateLiteral(node) {
				if (node.expressions.length > 0) checkShellInvocation(node);
			},

			CallExpression: checkLauncherCall,
			NewExpression: checkLauncherCall,

			TaggedTemplateExpression(node) {
				if (isRegExpExec(node.tag)) return;
				const name = calleeName(node.tag);
				if (name === null || !LAUNCHER_NAMES.has(name)) return;
				if (!isInterpolated(node.quasi)) return;
				context.report({
					node: node.quasi,
					messageId: "interpolatedArgument",
					data: { callee: name },
				});
			},

			VariableDeclarator(node) {
				if (node.init !== null && node.init !== undefined) {
					checkCommandName(node.id, node.init);
				}
			},
			AssignmentExpression(node) {
				checkCommandName(node.left, node.right);
			},
			Property(node) {
				if (!node.computed) checkCommandName(node.key, node.value);
			},
			PropertyDefinition(node) {
				if (!node.computed && node.value !== null && node.value !== undefined) {
					checkCommandName(node.key, node.value);
				}
			},
		};
	},
};
