// C2 enforced over the agent's own source (RL-M2-028).
//
// Three things are checked, and the order reflects which would be worst to get wrong:
//
//  1. The check FIRES on deliberate violations. A scanner nobody has proven fires is
//     a scanner nobody has tested, and this repository has already shipped one of
//     those — RL-M1-041's eight invented CSS token names passed a scan that resolved
//     nothing.
//  2. The check does NOT fire on correct code. A check that reports everything is as
//     useless as one that reports nothing, and it is the version that gets disabled
//     rather than fixed.
//  3. The agent's real source is clean.
//
// Only the third is the build gate. The first two are what make the third mean
// something.
package shellcheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The module root, relative to this package.
const moduleRoot = "../.."

// TestTheCheckFiresOnEveryDeliberateViolation is acceptance 3.
//
// The fixture annotates each violation with `// want: <rule>`, so the fixture states
// what it expects and this test compares rather than counting. A count would pass
// with the right total and the wrong lines.
func TestTheCheckFiresOnEveryDeliberateViolation(t *testing.T) {
	path := filepath.Join("testdata", "violations.go.txt")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	findings, err := ScanSource(path, source)
	if err != nil {
		t.Fatalf("scanning the fixture: %v", err)
	}

	expected := wantedRules(t, source)
	if len(expected) == 0 {
		t.Fatal("the fixture declares no `want:` markers, so this test verified nothing")
	}

	// Group findings by rule so a violation reported under the wrong rule is visible.
	got := map[string]int{}
	for _, finding := range findings {
		got[finding.Rule]++
	}
	want := map[string]int{}
	for _, rule := range expected {
		want[rule]++
	}

	for rule, count := range want {
		if got[rule] != count {
			t.Errorf("rule %q fired %d time(s), the fixture expects %d", rule, got[rule], count)
		}
	}
	for rule, count := range got {
		if want[rule] == 0 {
			t.Errorf("rule %q fired %d time(s) and the fixture does not expect it", rule, count)
		}
	}

	if t.Failed() {
		t.Log("what the scan actually reported:")
		for _, finding := range findings {
			t.Logf("  %s", finding)
		}
	}

	// Acceptance 1 specifically: a shell interpreter must be refused OUTRIGHT, with
	// no annotation that permits it. Asserted by rule name, so relaxing it to the
	// annotatable rule would fail here rather than pass quietly.
	shells := 0
	for _, finding := range findings {
		if finding.Rule == "shell-interpreter" {
			shells++
			if strings.Contains(finding.Detail, Annotation) {
				t.Errorf("the shell-interpreter refusal offers an annotation as a way out:\n  %s",
					finding)
			}
		}
	}
	if shells == 0 {
		t.Error("no shell invocation was reported, and the fixture contains several")
	}
}

// A marker may list several rules, because one line can violate more than one:
// `exec.Command("sh", "-c", "useradd "+slug)` names a shell AND builds an argument,
// and reporting only the first would hide the second from a reader fixing it.
var wantMarker = regexp.MustCompile(`//\s*want:\s*(.+)`)

func wantedRules(t *testing.T, source []byte) []string {
	t.Helper()
	var rules []string
	for _, match := range wantMarker.FindAllStringSubmatch(string(source), -1) {
		rules = append(rules, strings.Fields(match[1])...)
	}
	return rules
}

// TestTheCheckIsSilentOnCorrectCode is the half that keeps the check usable.
func TestTheCheckIsSilentOnCorrectCode(t *testing.T) {
	path := filepath.Join("testdata", "clean.go.txt")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	findings, err := ScanSource(path, source)
	if err != nil {
		t.Fatalf("scanning the fixture: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("the check fired on code that is correct:")
		for _, finding := range findings {
			t.Errorf("  %s", finding)
		}
		t.Error("A check that reports everything is as useless as one that reports nothing, " +
			"and it is the version that gets disabled rather than fixed.")
	}
}

// TestTheAgentSourceIsClean is the build gate.
func TestTheAgentSourceIsClean(t *testing.T) {
	findings, err := Scan(moduleRoot)
	if err != nil {
		t.Fatalf("scanning the agent: %v", err)
	}

	if len(findings) == 0 {
		return
	}

	t.Errorf("C2 violations in the agent (%d):", len(findings))
	for _, finding := range findings {
		t.Errorf("  %s", finding)
	}
}

// TestTheScanReachesTheWholeModule guards against the gate above passing because it
// looked at nothing.
//
// The obvious failure is a wrong relative path: Scan("../..") from a package that
// moved would walk an empty tree, return no findings, and report the agent clean.
// That is the shape of vacuous pass this project has hit twice — once in
// `scripts/host verify`, which concluded "root ssh: refused (C1 holds)" because no
// key file existed.
func TestTheScanReachesTheWholeModule(t *testing.T) {
	var seen int
	err := filepath.WalkDir(moduleRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "testdata" || entry.Name() == "dist") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") {
			seen++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	// A floor, not an exact count: an exact one would fail on every new file and be
	// updated without thought, which defeats the purpose.
	if seen < 8 {
		t.Fatalf("only %d .go files found under %s — the scan is looking in the wrong place, "+
			"so TestTheAgentSourceIsClean is passing on an empty tree", seen, moduleRoot)
	}

	// And the scanner must be able to parse all of them. A parse error returned as a
	// findings-less success would be the same vacuous pass by another route.
	for _, name := range []string{"internal/protocol/validate.go", "cmd/ratline-agent/main.go"} {
		if _, err := ScanFile(filepath.Join(moduleRoot, name)); err != nil {
			t.Errorf("the scanner cannot read %s: %v", name, err)
		}
	}
}

// TestAnAnnotationWithoutAReasonPermitsNothing pins acceptance 2's "and reviewed".
func TestAnAnnotationWithoutAReasonPermitsNothing(t *testing.T) {
	// The annotation exists to buy a reviewer's attention. A bare one buys none, so it
	// must not work — otherwise the escape hatch is "add a magic comment", which is
	// exactly the quiet workaround the rule exists to prevent.
	cases := map[string]bool{
		"bare":              false,
		"with a reason":     true,
		"whitespace only":   false,
		"different comment": false,
	}
	bodies := map[string]string{
		"bare":              Annotation,
		"with a reason":     Annotation + " the port is a bounded int64 from the catalogue",
		"whitespace only":   Annotation + "   ",
		"different comment": "// just a normal comment",
	}

	for name, shouldPermit := range cases {
		t.Run(name, func(t *testing.T) {
			source := fmt.Sprintf(`package fixture

import (
	"fmt"
	"os/exec"
)

func f(port int64) {
	%s
	exec.Command("runtime", fmt.Sprintf("--port=%%d", port))
}
`, bodies[name])

			findings, err := ScanSource("inline.go", []byte(source))
			if err != nil {
				t.Fatalf("scanning: %v", err)
			}

			permitted := len(findings) == 0
			if permitted != shouldPermit {
				t.Errorf("annotation %q permitted=%v, want %v (findings: %v)",
					bodies[name], permitted, shouldPermit, findings)
			}
		})
	}
}

// TestTheRuleNamesAShellByBaseNameNotByPath makes the interpreter rule's reach
// explicit, because "/bin/sh" and "sh" and "/usr/local/bin/sh" are one hazard.
func TestTheRuleNamesAShellByBaseNameNotByPath(t *testing.T) {
	for _, program := range []string{"sh", "/bin/sh", "/usr/bin/bash", "/opt/weird/path/zsh", "dash"} {
		source := fmt.Sprintf(`package fixture

import "os/exec"

func f(x string) {
	exec.Command(%q, "-c", x)
}
`, program)

		findings, err := ScanSource("inline.go", []byte(source))
		if err != nil {
			t.Fatalf("scanning: %v", err)
		}

		found := false
		for _, finding := range findings {
			if finding.Rule == "shell-interpreter" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q was not reported as a shell interpreter", program)
		}
	}
}
