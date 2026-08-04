// Layer 1 of two. These tests construct Info values directly and check how each
// shape is reported. They prove the rendering, and they cannot prove that the
// toolchain actually stamps anything — a `go test` binary is not a main package,
// so Go records no VCS data for it and Current() legitimately returns Unknown
// here. artifact_test.go builds real main packages and proves the stamping.
//
// Splitting it this way is the point. A single test calling Current() and
// asserting "commit is not unknown" would fail for a correct reason and get
// weakened until it passed.
package build

import (
	"strings"
	"testing"
)

func TestTraceableRequiresACommitAndACleanTree(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want bool
	}{
		{"committed and clean", Info{Commit: strings.Repeat("a", 40)}, true},
		{"committed but dirty", Info{Commit: strings.Repeat("a", 40), Modified: true}, false},
		{"no revision recorded", Info{Commit: Unknown}, false},
		// Belt and braces: Unknown is the documented sentinel, but a future
		// change to Current() that forgets to set it must not read as traceable.
		{"empty revision", Info{Commit: ""}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.info.Traceable(); got != c.want {
				t.Errorf("Traceable() = %v, want %v for %+v", got, c.want, c.info)
			}
		})
	}
}

func TestDescribeEndsWithWhatToDoWhenTheTreeWasDirty(t *testing.T) {
	info := Info{Version: "1.2.3", Commit: strings.Repeat("b", 40), Modified: true}

	got := info.Describe("ratline-agent")

	// The failure this guards against is a dirty build installed on a host and
	// nobody noticing, so the test is about what the operator is told, not about
	// a boolean they never see.
	for _, want := range []string{
		"uncommitted changes",
		"cannot be traced to a commit",
		"scripts/agent build",
		"Enrolment refuses an untraceable agent",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() omits %q:\n%s", want, got)
		}
	}
}

func TestDescribeSaysNothingAlarmingAboutACleanBuild(t *testing.T) {
	info := Info{Version: "1.2.3", Commit: strings.Repeat("c", 40), Built: "2026-08-04T00:00:00Z"}

	got := info.Describe("ratline-privd")

	if strings.Contains(got, "cannot be traced") {
		t.Errorf("a clean build should carry no warning:\n%s", got)
	}
	if !strings.Contains(got, "ratline-privd 1.2.3") {
		t.Errorf("Describe() should lead with the program and version:\n%s", got)
	}
	// The full commit, not the abbreviation: this is the form somebody pastes
	// into `git show`.
	if !strings.Contains(got, strings.Repeat("c", 40)) {
		t.Errorf("Describe() should carry the full commit:\n%s", got)
	}
}

func TestDescribeExplainsAnAbsentRevisionDifferentlyFromADirtyOne(t *testing.T) {
	// Two different problems with two different fixes: one was built outside a
	// checkout, the other from a checkout with unsaved work. Collapsing them
	// into one message would send the operator looking for changes that are not
	// there.
	absent := Info{Version: "0.0.0-dev", Commit: Unknown}.Describe("ratline-agent")

	if !strings.Contains(absent, "outside a git checkout") {
		t.Errorf("an absent revision should name its own cause:\n%s", absent)
	}
	if strings.Contains(absent, "uncommitted changes") {
		t.Errorf("an absent revision is not a dirty tree:\n%s", absent)
	}
}

func TestLineAttachesDirtyToTheCommitItInvalidates(t *testing.T) {
	commit := strings.Repeat("d", 40)
	line := Info{Version: "1.0.0", Commit: commit, Modified: true}.Line()

	if !strings.Contains(line, commit[:12]+"-dirty") {
		t.Errorf("Line() = %q, want the -dirty suffix on the commit itself", line)
	}
	if strings.Contains(line, commit) {
		t.Errorf("Line() = %q, want the commit abbreviated for a log line", line)
	}
}

func TestShortCommitLeavesUnknownAlone(t *testing.T) {
	// Slicing a sentinel to 12 characters is how "unknown" becomes "unknown"
	// truncated to something that looks like a hash.
	if got := (Info{Commit: Unknown}).ShortCommit(); got != Unknown {
		t.Errorf("ShortCommit() = %q, want %q", got, Unknown)
	}
}

func TestCurrentAlwaysFillsEveryField(t *testing.T) {
	// Whatever the toolchain gave us, no field may render as an empty string:
	// an empty commit in a log line reads as a formatting bug, and an empty one
	// in the enrolment handshake would have to be special-cased there instead.
	got := Current()

	for name, value := range map[string]string{
		"Version":  got.Version,
		"Commit":   got.Commit,
		"Built":    got.Built,
		"Go":       got.Go,
		"Platform": got.Platform,
	} {
		if value == "" {
			t.Errorf("Current().%s is empty; every field must say something", name)
		}
	}
}
