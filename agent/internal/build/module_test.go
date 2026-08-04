package build

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheAgentModuleRequiresNothing turns "dependency-free" from a description
// into a property.
//
// Acceptance 1 of RL-M2-001 says the binary has no runtime dependency on the
// host, which artifact_test.go establishes for the link step. This is the other
// half: no dependency on anybody's code either. The agent is an unprivileged
// process running on somebody else's machine beside a root helper, and every
// module it pulls in is a path onto that machine from a repository neither we nor
// the operator controls.
//
// Adding a dependency is allowed — §6.7 says prefer the standard library, not
// never leave it. This test makes it a decision with a diff, which is the only
// part that was ever at risk.
func TestTheAgentModuleRequiresNothing(t *testing.T) {
	path := filepath.Join(moduleRoot, "go.mod")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	for number, line := range strings.Split(string(raw), "\n") {
		// Comments stripped before the scan. go.mod's own commentary explains
		// why there is no require block, and the word "require" appears in that
		// explanation — a scanner that reads its own documentation as a
		// violation is a scanner people delete. The TypeScript side learned this
		// four separate times (RL-M1-041) and the fix transfers unchanged.
		code := line
		if at := strings.Index(code, "//"); at >= 0 {
			code = code[:at]
		}
		code = strings.TrimSpace(code)

		if code == "require" || strings.HasPrefix(code, "require ") || strings.HasPrefix(code, "require(") {
			t.Errorf("go.mod:%d introduces a dependency: %q\n\n"+
				"The agent is deliberately stdlib-only. If this one is genuinely needed, say so "+
				"in the commit body (§6.7 wants a one-line justification) and update this test's "+
				"reasoning — but do not delete the test, because an agent that can gain a "+
				"dependency without a diff is one that will.", number+1, code)
		}
	}
}

// TestTheAgentModuleHasNoVendoredCodeEither closes the door the test above
// leaves open: `go mod vendor` puts dependencies in the tree without a require
// line surviving in every layout, and a vendor directory is a dependency that
// reviews as "just files".
func TestTheAgentModuleHasNoVendoredCodeEither(t *testing.T) {
	for _, name := range []string{"vendor", "go.sum"} {
		if _, err := os.Stat(filepath.Join(moduleRoot, name)); err == nil {
			t.Errorf("agent/%s exists, so this module is no longer stdlib-only", name)
		}
	}
}
