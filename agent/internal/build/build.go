// Package build answers the question "what exactly is running on this host?"
//
// ## Why the commit is not injected with -ldflags
//
// The obvious scaffold puts `var commit string` here and stamps it with
// `-ldflags "-X ...=$(git rev-parse HEAD)"`. That works, and it fails silently:
// `go build ./cmd/ratline-agent` without the flags produces a binary that
// reports an empty commit, and an empty string renders as nothing rather than as
// a complaint. The binary an operator sideloads while debugging is exactly the
// binary built without the release script.
//
// Go embeds VCS information itself, so the commit comes from
// `debug.ReadBuildInfo()` instead. It cannot be forgotten, because nobody has to
// remember it — it is on by default for main packages built inside a checkout.
// -ldflags is still used for the one thing git does not know, the release name.
//
// ## Why `modified` is reported rather than ignored
//
// C6 requires every privileged action to be attributable. An agent built from a
// tree with uncommitted changes cannot be traced to source: the parent commit
// describes code that is not what is running. Reporting that parent commit alone
// would be the most misleading of the three options, because it looks precise.
// So a dirty build says so, and `Traceable` returns false — which is what the
// `version` command escalates to a warning rather than a footnote.
package build

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the release name, injected at link time by `scripts/agent build`.
// Left as this literal on purpose: a developer build should read as an
// unreleased build, not as a release whose name went missing.
var Version = "0.0.0-dev"

// Unknown is what the fields say when the toolchain gave us nothing. It is a
// word rather than an empty string so that it survives being formatted into a
// log line, a JSON field, or a support ticket.
const Unknown = "unknown"

// Info is everything this binary can truthfully say about its own provenance.
type Info struct {
	// Version is the release name, or "0.0.0-dev" for an unreleased build.
	Version string
	// Commit is the full git revision, or Unknown outside a checkout.
	Commit string
	// Modified reports uncommitted changes in the tree the binary was built
	// from. When true, Commit describes the parent of the real source.
	Modified bool
	// Built is the commit timestamp, not the time of the build: two builds of
	// one commit should be indistinguishable, and a wall-clock stamp is the
	// usual reason reproducible builds are not.
	Built string
	// Go is the toolchain that produced the binary.
	Go string
	// Platform is the target it was produced for, e.g. "linux/amd64".
	Platform string
}

// Current reads this binary's own provenance.
func Current() Info {
	info := Info{
		Version:  Version,
		Commit:   Unknown,
		Built:    Unknown,
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}

	// Absent when the binary was built with -buildvcs=false, from outside a
	// repository, or as a test binary — Go stamps VCS data onto main packages,
	// and `go test` does not build one. That last case is why the unit tests
	// here assert how Unknown is *handled* and the artifact test asserts the
	// commit is really present: only the second one builds a main package.
	raw, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	for _, setting := range raw.Settings {
		switch setting.Key {
		case "vcs.revision":
			if setting.Value != "" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if setting.Value != "" {
				info.Built = setting.Value
			}
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		}
	}

	return info
}

// Traceable reports whether this binary can be tied to source that still exists.
//
// False means an operator holding this binary cannot obtain the code that
// produced it — either the commit is unknown, or the tree carried changes that
// were never committed anywhere. Both are fine on a laptop and neither belongs
// on a managed host, so enrolment refuses an untraceable agent (RL-M2-002).
func (i Info) Traceable() bool {
	return i.Commit != Unknown && i.Commit != "" && !i.Modified
}

// ShortCommit is the commit abbreviated for a log line, or Unknown.
func (i Info) ShortCommit() string {
	if i.Commit == Unknown || len(i.Commit) < 12 {
		return i.Commit
	}
	return i.Commit[:12]
}

// Line is the one-line form, for logs and for the enrolment handshake.
//
// The "-dirty" suffix is glued to the commit rather than put in its own field
// because a reader scanning a log finds it attached to the thing it invalidates.
func (i Info) Line() string {
	commit := i.ShortCommit()
	if i.Modified {
		commit += "-dirty"
	}
	return fmt.Sprintf("%s %s (%s, %s, %s)", Version, commit, i.Built, i.Go, i.Platform)
}

// Describe is the operator-facing form printed by the `version` command.
//
// Aligned keys, plain nouns, no banner. When the build is not traceable it ends
// with what is wrong and what to do about it, which is the brief's rule for
// error copy (§291) and applies here because an untraceable binary on a host is
// an error that has not been noticed yet.
func (i Info) Describe(program string) string {
	commit := i.Commit
	if i.Modified {
		commit += " (tree had uncommitted changes)"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", program, i.Version)
	fmt.Fprintf(&b, "  commit    %s\n", commit)
	fmt.Fprintf(&b, "  committed %s\n", i.Built)
	fmt.Fprintf(&b, "  built by  %s\n", i.Go)
	fmt.Fprintf(&b, "  target    %s\n", i.Platform)

	if !i.Traceable() {
		b.WriteString("\n")
		if i.Modified {
			b.WriteString("This build cannot be traced to a commit: the tree had uncommitted\n")
			b.WriteString("changes, so the commit above is the parent of the real source.\n")
		} else {
			b.WriteString("This build cannot be traced to a commit: no revision was recorded,\n")
			b.WriteString("which happens when it was built outside a git checkout.\n")
		}
		b.WriteString("Rebuild with scripts/agent build from a clean checkout before\n")
		b.WriteString("installing it on a host. Enrolment refuses an untraceable agent.\n")
	}

	return b.String()
}
