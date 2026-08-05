// Package listencheck proves that no managed host gains an inbound port from Ratline
// (RL-M2-006, ADR 0002).
//
// ADR 0002 chose the dial direction before it chose anything else, because it is the
// decision that sets the fleet's attack surface: "No managed host listens on a Ratline
// port; an integration test asserts this after provisioning." A control plane that dialled
// agents would need every host to open one new pre-authentication service, multiplied by
// the size of the fleet.
//
// # Two halves, because one of them can only be proven on a host
//
// Scan is a BUILD-TIME check. It walks the agent module's own source and refuses any call
// that can open a listening network socket. Its claim is the strong one, because it holds
// for every host and every configuration at once: the binaries contain no code that could
// bind a port, so there is no combination of arguments, environment or attacker input that
// makes them.
//
// Listening is a RUNTIME check against /proc, for a real Linux host. Its claim is narrower
// — this process, on this machine, right now — and it is the one an integration test can
// point at a provisioned host. It exists because the source check answers "could it?" and
// provisioning also installs unit files, packages and a web server, and a check that
// reads the kernel's own socket table cannot be argued with.
//
// Neither replaces the other. The build check would miss a listener opened by something
// the agent installs; the /proc check would miss a listener that only opens under
// conditions the test did not produce.
//
// # Why an AST walk and not a grep
//
// The same reasoning as agent/internal/shellcheck, and the same evidence for it: a grep
// fires on the word "Listen" inside a comment explaining why listening is forbidden — a
// paragraph this very file contains several of. go/ast never visits comments as
// expressions, so prose about a hazard cannot trip the check on it.
package listencheck

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

// Annotation permits a listener whose family this check could not determine. It must be
// followed by a reason.
//
//	//ratline:allow-listener systemd hands privd a unix socket on fd 3 (ADR 0004)
const Annotation = "//ratline:allow-listener"

// Network families this check refuses, by the string the standard library uses.
var refusedNetworks = map[string]bool{
	"tcp": true, "tcp4": true, "tcp6": true,
	"udp": true, "udp4": true, "udp6": true,
	"ip": true, "ip4": true, "ip6": true,
}

// Network families this check permits.
//
// A unix-domain socket is not a port. privd is reached over one BY DESIGN (ADR 0004) —
// the agent asks it for privileged work over a socket in the filesystem, protected by peer
// credentials and file mode, reachable by nothing off the host. Refusing these would make
// the check unable to distinguish "the fleet exposes nothing new" from "the two components
// on a host cannot talk", which are not remotely the same property.
var permittedNetworks = map[string]bool{
	"unix": true, "unixgram": true, "unixpacket": true,
}

// Calls that can produce a listener, by selector name.
//
// Matched on the selector alone rather than on package-and-selector, because the receiver
// is often a value: `(&net.ListenConfig{}).Listen(...)` and `server.ListenAndServe()` are
// both listeners and neither has "net" or "http" in the call expression. In a module with
// no dependencies there is nothing else these names can mean, and the ones that could
// plausibly mean something else are the annotatable ones rather than the outright refusals.
var listenerCalls = map[string]bool{
	"Listen": true, "ListenPacket": true, "ListenConfig": true,
	"ListenTCP": true, "ListenUDP": true, "ListenIP": true, "ListenMulticastUDP": true,
	"ListenUnix": true, "ListenUnixgram": true,
	"ListenAndServe": true, "ListenAndServeTLS": true,
	"Serve": true, "ServeTLS": true,
	"NewListener": true, "FileListener": true, "FilePacketConn": true,
	"Bind": true,
}

// Selectors that name a network family in themselves, so no literal argument is needed to
// classify them.
var refusedBySelector = map[string]bool{
	"ListenTCP": true, "ListenUDP": true, "ListenIP": true, "ListenMulticastUDP": true,
	"ListenAndServe": true, "ListenAndServeTLS": true, "ServeTLS": true,
}

var permittedBySelector = map[string]bool{
	"ListenUnix": true, "ListenUnixgram": true,
}

// Rule names, so a test can assert WHICH rule fired rather than counting findings.
const (
	// RuleNetworkListener is a listener on a network family, refused outright.
	RuleNetworkListener = "network-listener"
	// RuleUnclassifiedListener is a listener whose family this check cannot determine.
	// Refused unless annotated with a reason.
	RuleUnclassifiedListener = "unclassified-listener"
)

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

// Scan walks every non-test .go file under root and returns what it found.
//
// # Test files are excluded, and that is a narrower rule than shellcheck's
//
// shellcheck scans test files, because a test that shells out is still the agent carrying
// code that knows how. The argument does not transfer. A test file is not compiled into
// either binary — `go build` excludes it — so including them here would enforce something
// other than the property, and it would forbid the only honest way to test a client: a
// real server on a real socket. agent/internal/transport's suite binds loopback listeners
// on purpose, because a fake control plane that did not actually listen would make the
// handshake test a conversation with a mock.
//
// What closes the gap is the toolchain rather than this scan: production code cannot
// reference a symbol declared in a _test.go file, so a listener hidden in one cannot be
// reached from `run`.
func Scan(root string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// testdata holds deliberate violations, so scanning it would make the check
			// permanently red. dist holds build output.
			if entry.Name() == "testdata" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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

// ScanSource is ScanFile over bytes, so fixtures need not be compilable packages on disk
// under a real import path.
func ScanSource(name string, source []byte) ([]Finding, error) {
	fileSet := token.NewFileSet()
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
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		selected := selector.Sel.Name
		if !listenerCalls[selected] {
			return true
		}

		line := fileSet.Position(call.Lparen).Line
		called := callName(selector)

		// A literal network argument classifies the call, whatever the selector is. This
		// is what makes `net.Listen("unix", path)` and `net.Listen("tcp", addr)` different
		// findings rather than one rule with an exception nobody can read.
		refused, permittedFamily := networksIn(call)
		switch {
		case permittedFamily != "":
			return true
		case refused != "":
			findings = append(findings, Finding{
				File: name, Line: line, Rule: RuleNetworkListener,
				Detail: fmt.Sprintf(
					"%s listens on %q. ADR 0002 says no managed host listens on a Ratline "+
						"port, because a control plane that dialled agents would add one "+
						"pre-authentication service to every host in the fleet. The agent dials "+
						"OUT; there is no annotation that permits this",
					called, refused),
			})
			return true
		case refusedBySelector[selected]:
			findings = append(findings, Finding{
				File: name, Line: line, Rule: RuleNetworkListener,
				Detail: fmt.Sprintf(
					"%s opens a network listener by its own name. The agent dials out and "+
						"nothing in it serves; ADR 0002 forbids this outright", called),
			})
			return true
		case permittedBySelector[selected]:
			return true
		}

		// Everything left is a listener whose family this check cannot see: a variable
		// network, a file descriptor from socket activation, a raw bind. This is precisely
		// the gap shellcheck documents and cannot close — `shell := "/bin/sh"` defeats it —
		// and it CAN be closed here, because the agent has so few of these that requiring a
		// written reason for each costs nothing.
		if permitted[line] {
			return true
		}
		findings = append(findings, Finding{
			File: name, Line: line, Rule: RuleUnclassifiedListener,
			Detail: fmt.Sprintf(
				"%s opens a listener and this check cannot tell which family from the source. "+
					"A unix socket is fine — privd is reached over one (ADR 0004) — and a network "+
					"port is not. Say which, and why:\n      %s <reason>",
				called, Annotation),
		})
		return true
	})

	sort.Slice(findings, func(a, b int) bool { return findings[a].Line < findings[b].Line })
	return findings, nil
}

// networksIn reports the network families named by string literals in a call.
func networksIn(call *ast.CallExpr) (refused, permitted string) {
	for _, argument := range call.Args {
		literal, ok := argument.(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			continue
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			continue
		}
		if permittedNetworks[value] {
			return "", value
		}
		if refusedNetworks[value] {
			refused = value
		}
	}
	return refused, ""
}

// callName renders a selector for a message, best effort.
func callName(selector *ast.SelectorExpr) string {
	if identifier, ok := selector.X.(*ast.Ident); ok {
		return identifier.Name + "." + selector.Sel.Name
	}
	return "a call to " + selector.Sel.Name
}

// annotatedLines maps the line an annotation applies to.
//
// Both spellings shellcheck accepts — above the call or beside it — and the same rule that a
// bare annotation permits nothing, because an unexplained escape hatch is the thing these
// checks exist to stop somebody adding quietly.
//
// # One deliberate difference from shellcheck's version
//
// shellcheck permits the annotation's own line and the one after it. That breaks when the
// reason wraps, which is not hypothetical: the first reason written for privd's socket
// activation ran to two lines, the annotation stopped applying, and the build failed with a
// message about an unclassified listener directly beneath a comment classifying it. So the
// permitted line is the one after the whole comment GROUP — go/ast already groups adjacent
// comment lines — and a wrapped reason works the way anybody would expect it to.
func annotatedLines(fileSet *token.FileSet, file *ast.File) map[int]bool {
	permitted := map[int]bool{}
	for _, group := range file.Comments {
		annotated := false
		for _, comment := range group.List {
			text := strings.TrimSpace(comment.Text)
			if !strings.HasPrefix(text, Annotation) {
				continue
			}
			if strings.TrimSpace(strings.TrimPrefix(text, Annotation)) == "" {
				continue
			}
			annotated = true
			// The annotation's own line, for the trailing spelling.
			permitted[fileSet.Position(comment.Slash).Line] = true
		}
		if annotated {
			permitted[fileSet.Position(group.End()).Line+1] = true
		}
	}
	return permitted
}
