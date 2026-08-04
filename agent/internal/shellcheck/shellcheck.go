// Package shellcheck fails the build when the agent constructs a shell command
// (RL-M2-028, hard constraint C2).
//
// C2: "No shell command is ever constructed by string interpolation. All remote
// execution uses argv arrays with explicit arguments. No `sh -c` with any
// user-derived data, anywhere. Add a lint rule and a CI check that fails the build
// on template-literal shell construction."
//
// # Why this is an AST walk and not a grep
//
// The TypeScript side enforces C2 with lint rules over real syntax, and a grep here
// would be strictly weaker in both directions. It would miss `exec.Command(shell,
// "-c", …)` where `shell` is a variable holding "/bin/sh", and it would fire on the
// word "bash" inside a comment explaining why bash is forbidden — which happened
// four separate times on the TypeScript side before RL-M1-041 stripped comments
// before scanning. go/ast gives comments for free: they are not expressions, so a
// walk over expressions never sees them.
//
// # What is forbidden, and what is merely watched
//
// REFUSED OUTRIGHT: naming a shell interpreter as the program of an os/exec call.
// There is no legitimate reason for this agent to invoke one. Every privileged
// operation goes to privd as an enumerated request (ADR 0004), and every
// unprivileged one is a syscall or a file write.
//
// REFUSED UNLESS ANNOTATED: a formatted string — Sprintf, concatenation, a template
// — reaching an os/exec argument. This is narrower than "never", because a legitimate
// case exists: `--port=8080` is a formatted argument and is not an injection, since
// argv carries no shell to inject into. What makes it dangerous is the reviewer's
// attention, not the runtime, so the annotation buys attention: it must name a reason,
// and `grep` lists every one.
//
// The distinction matters. A rule that forbade all formatting would be worked around
// by building the string one statement earlier, and a rule that allowed all of it
// would be no rule at all.
package shellcheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Annotation permits a formatted process argument. It must be followed by a reason.
//
//	//ratline:allow-formatted-arg the port is an int64 from the catalogue, not text
const Annotation = "//ratline:allow-formatted-arg"

// Shells whose invocation is refused outright, by base name.
//
// KNOWN LIMITATION, stated rather than glossed: this catches a shell named by a
// STRING LITERAL in any argument position. It does not catch one named through a
// variable — `shell := "/bin/sh"; exec.Command(shell, "-c", x)` passes, because a
// bare identifier is not evidence of anything and flagging every identifier would put
// an annotation on every exec call in the agent, at which point nobody reads them.
//
// Closing that would need type-and-flow analysis, which go/ast alone does not give.
// What limits the damage is that the agent has no exec calls at all outside its own
// build test, and TestTheAgentSourceIsClean fails the build if one appears — so the
// gap is reachable only by somebody deliberately routing a shell name through a
// variable, which is no longer a mistake. Worth revisiting if the agent ever grows a
// legitimate reason to launch a process.
var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "csh": true,
	"fish": true, "cmd": true, "cmd.exe": true, "powershell": true, "pwsh": true,
}

// Finding is one violation.
type Finding struct {
	File   string
	Line   int
	Rule   string
	Detail string
}

func (finding Finding) String() string {
	return fmt.Sprintf("%s:%d: [%s] %s", finding.File, finding.Line, finding.Rule, finding.Detail)
}

// Scan walks every .go file under root and returns what it found.
//
// Test files are included. A test that shells out is still the agent shipping code
// that knows how, and a fixture proving the check works belongs in testdata rather
// than in a compiled test — which is why the fixtures below are .go.txt.
func Scan(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// testdata is where the fixtures live. They are deliberate violations, so
			// scanning them here would make the check permanently red.
			if entry.Name() == "testdata" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		found, err := ScanFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, found...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(findings, func(a, b int) bool {
		if findings[a].File != findings[b].File {
			return findings[a].File < findings[b].File
		}
		return findings[a].Line < findings[b].Line
	})
	return findings, nil
}

// ScanFile parses one file and reports its violations.
func ScanFile(path string) ([]Finding, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ScanSource(path, source)
}

// ScanSource is ScanFile over bytes, so fixtures need not be compilable packages on
// disk under a real import path.
func ScanSource(name string, source []byte) ([]Finding, error) {
	fileSet := token.NewFileSet()
	// ParseComments so the annotations are available. The AST walk itself never
	// visits them, which is the point: prose explaining a hazard cannot trip a check
	// that only looks at expressions.
	parsed, err := parser.ParseFile(fileSet, name, source, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", name, err)
	}

	permitted := annotatedLines(fileSet, parsed)
	var findings []Finding

	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}

		target, ok := execTarget(call)
		if !ok {
			return true
		}

		line := fileSet.Position(call.Lparen).Line

		for index, argument := range call.Args {
			// os/exec's variadic forms put the program first and its arguments after.
			// CommandContext puts the context first, which execTarget has already
			// accounted for by reporting where the program sits.
			if index < target.programAt {
				continue
			}

			// ANY position, not only the program. The fixture caught this: the check
			// first looked at the program argument alone, so
			// `exec.Command("/usr/bin/env", "sh", "-c", x)` passed cleanly — "env" is
			// not a shell and the shell was one slot further along. `nice`, `setsid`,
			// `timeout` and `sudo` all have the same shape. The agent has no reason to
			// pass a shell's name as data, so scanning every position costs nothing and
			// closes a family of bypasses rather than one instance.
			{
				if shell, ok := shellLiteral(argument); ok {
					findings = append(findings, Finding{
						File: name, Line: line, Rule: "shell-interpreter",
						Detail: fmt.Sprintf(
							"%s names %q. The agent has no legitimate reason to run a shell: "+
								"privileged work goes to privd as an enumerated request (ADR 0004) and "+
								"unprivileged work is a syscall or a file write. C2 forbids this outright "+
								"and there is no annotation that permits it",
							target.name, shell,
						),
					})
					continue
				}
			}

			if formatted(argument) {
				if permitted[line] {
					continue
				}
				findings = append(findings, Finding{
					File: name, Line: line, Rule: "formatted-process-argument",
					Detail: fmt.Sprintf(
						"argument %d of %s is built by formatting or concatenation. argv carries no "+
							"shell to inject into, so this is not automatically a vulnerability — which "+
							"is exactly why it needs a reviewer's attention rather than a runtime "+
							"check. If the value is genuinely safe, say why:\n"+
							"      %s <reason>",
						index, target.name, Annotation,
					),
				})
			}
		}
		return true
	})

	return findings, nil
}

// annotatedLines maps the line an annotation applies to.
//
// An annotation applies to the line after it, or to its own line when written as a
// trailing comment. Both spellings, because a long exec call reads better with the
// reason above it and a short one reads better with the reason beside it.
func annotatedLines(fileSet *token.FileSet, file *ast.File) map[int]bool {
	permitted := map[int]bool{}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			text := strings.TrimSpace(comment.Text)
			if !strings.HasPrefix(text, Annotation) {
				continue
			}
			// A bare annotation permits nothing. The reason IS the review: an
			// unexplained escape hatch is the thing this rule exists to prevent
			// somebody adding quietly.
			if strings.TrimSpace(strings.TrimPrefix(text, Annotation)) == "" {
				continue
			}
			line := fileSet.Position(comment.Slash).Line
			permitted[line] = true
			permitted[line+1] = true
		}
	}
	return permitted
}

type execCall struct {
	name string
	// programAt is the index of the program argument.
	programAt int
}

// execTarget reports whether a call runs a process, and where its program sits.
func execTarget(call *ast.CallExpr) (execCall, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return execCall{}, false
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok {
		return execCall{}, false
	}

	switch packageName.Name {
	case "exec":
		switch selector.Sel.Name {
		case "Command":
			return execCall{name: "exec.Command", programAt: 0}, true
		case "CommandContext":
			// (ctx, name, args...)
			return execCall{name: "exec.CommandContext", programAt: 1}, true
		case "LookPath":
			return execCall{name: "exec.LookPath", programAt: 0}, true
		}
	case "syscall":
		switch selector.Sel.Name {
		case "Exec", "ForkExec", "StartProcess":
			return execCall{name: "syscall." + selector.Sel.Name, programAt: 0}, true
		}
	case "os":
		if selector.Sel.Name == "StartProcess" {
			return execCall{name: "os.StartProcess", programAt: 0}, true
		}
	}
	return execCall{}, false
}

// shellLiteral reports whether the expression is a string literal naming a shell.
func shellLiteral(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	// By base name, so "/bin/sh", "/usr/bin/env" and "sh" are all reached. A path is
	// not what makes it a shell.
	if shells[filepath.Base(value)] {
		return value, true
	}
	return "", false
}

// formatted reports whether the expression is built rather than written.
//
// Deliberately does NOT flag a plain identifier. A variable holding a validated slug
// is the normal, correct way to pass an argument, and flagging it would mean every
// exec call in the agent carries an annotation — at which point the annotations stop
// being read, which is worse than not having them.
func formatted(expression ast.Expr) bool {
	switch node := expression.(type) {
	case *ast.BinaryExpr:
		// String concatenation. Numeric addition reaching an exec argument would be a
		// type error, so any + here is on strings.
		return node.Op == token.ADD
	case *ast.CallExpr:
		selector, ok := node.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		packageName, ok := selector.X.(*ast.Ident)
		if !ok {
			return false
		}
		if packageName.Name == "fmt" && strings.HasPrefix(selector.Sel.Name, "Sprint") {
			return true
		}
		if packageName.Name == "strings" && (selector.Sel.Name == "Join" || selector.Sel.Name == "Replace" ||
			selector.Sel.Name == "ReplaceAll") {
			return true
		}
		return false
	case *ast.BasicLit:
		// A raw string literal spanning lines is how a shell script gets embedded.
		// A single-line literal is a fixed argument and is fine.
		if node.Kind == token.STRING && strings.Contains(node.Value, "\n") {
			return true
		}
		return false
	}
	return false
}
