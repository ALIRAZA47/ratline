// Layer 2 of two. These tests build the real binaries and inspect the real
// artefacts, because acceptance 1 of RL-M2-001 — "no runtime dependency on the
// host" — is a property of a file, and no amount of source inspection
// establishes it.
//
// ## Why the ELF is parsed rather than CGO_ENABLED trusted
//
// `CGO_ENABLED=0` is the instruction, not the outcome. It can be overridden by a
// GOFLAGS environment variable, defeated by a future import of a package that
// forces cgo, or silently ignored by a build script that forgets to export it.
// "Statically linked" has a precise definition in the file format — no PT_INTERP
// segment naming a dynamic loader, no DT_NEEDED entries naming shared objects —
// and debug/elf is in the standard library, so the definition is what gets
// checked. This also runs on a Mac, which is where these binaries are
// cross-compiled and where `ldd` does not exist.
//
// ## What each check can and cannot establish
//
//   - the linux/amd64 and linux/arm64 artefacts: staticness and target
//     architecture, structurally. They are not executed, because this test host
//     is a Mac.
//   - the host artefact: that `version` actually runs and prints a real commit.
//     It says nothing about the linux builds.
//
// Neither one alone is acceptance 1. Recording which is which is the same
// discipline as the authorization matrix reporting its verification layer per
// cell rather than emitting one number.
package build

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The module root, relative to this package's directory.
const moduleRoot = "../.."

var commands = []string{"ratline-agent", "ratline-privd"}

// buildFor compiles one command for one target and returns the artefact path.
func buildFor(t *testing.T, command, goos, goarch string) string {
	t.Helper()

	out := filepath.Join(t.TempDir(), command)
	cmd := exec.Command("go", "build", "-trimpath", "-o", out, "./cmd/"+command)
	cmd.Dir = moduleRoot
	// Appended to the inherited environment so a stray GOFLAGS or CC in the
	// developer's shell cannot quietly turn cgo back on: these come last and
	// therefore win.
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS="+goos,
		"GOARCH="+goarch,
	)

	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s for %s/%s: %v\n%s", command, goos, goarch, err, combined)
	}
	return out
}

func TestLinuxBinariesHaveNoRuntimeDependencyOnTheHost(t *testing.T) {
	// Both architectures the brief targets. arm64 is not decorative — a Graviton
	// or Ampere host is a normal thing to manage, and a build that only ever ran
	// on amd64 discovers its cgo dependency on somebody else's server.
	targets := []struct {
		goarch  string
		machine elf.Machine
	}{
		{"amd64", elf.EM_X86_64},
		{"arm64", elf.EM_AARCH64},
	}

	for _, command := range commands {
		for _, target := range targets {
			t.Run(command+"/"+target.goarch, func(t *testing.T) {
				path := buildFor(t, command, "linux", target.goarch)

				file, err := elf.Open(path)
				if err != nil {
					t.Fatalf("opening the built artefact as an ELF: %v", err)
				}
				defer file.Close()

				if file.Machine != target.machine {
					t.Errorf("built for machine %v, want %v — the cross-compile did not take effect",
						file.Machine, target.machine)
				}

				// PT_INTERP names the dynamic loader. Its presence is the
				// definition of "this binary needs something from the host to
				// start", and its absence is what lets one artefact run on
				// Debian, Alpine and a distroless container alike.
				for _, prog := range file.Progs {
					if prog.Type == elf.PT_INTERP {
						t.Errorf("%s carries a PT_INTERP segment, so it requires a dynamic loader "+
							"on the host — it is not static", command)
					}
				}

				libraries, err := file.ImportedLibraries()
				if err != nil {
					t.Fatalf("reading DT_NEEDED entries: %v", err)
				}
				if len(libraries) != 0 {
					t.Errorf("%s requires shared libraries %v; a managed host is not "+
						"guaranteed to have them", command, libraries)
				}

				// Belt and braces on the two checks above: a static binary has
				// no dynamic symbol table at all. If this ever passes while the
				// checks above also pass, something is stranger than a missed
				// build flag.
				if _, err := file.DynamicSymbols(); err == nil {
					t.Errorf("%s has a dynamic symbol table, which a statically linked "+
						"binary does not", command)
				}
			})
		}
	}
}

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestTheBuiltBinaryReportsItsVersionAndCommit(t *testing.T) {
	// Built and run for this host, because acceptance 3 says the binary
	// *reports* its version — which is behaviour, and behaviour has to be
	// executed. The linux artefacts above cannot be run here.
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			path := buildFor(t, command, runtime.GOOS, runtime.GOARCH)

			output, err := exec.Command(path, "version").CombinedOutput()
			if err != nil {
				t.Fatalf("running `%s version`: %v\n%s", command, err, output)
			}
			text := string(output)

			if !strings.Contains(text, command+" "+Version) {
				t.Errorf("`%s version` does not lead with the program and version:\n%s", command, text)
			}

			// The real assertion of this file: Go stamped a real revision into a
			// binary nobody passed -ldflags to. If this fails, every binary the
			// release script does not touch is unattributable, which is the
			// failure the ldflags approach hides.
			commit := commitFrom(t, text)
			if !fullCommit.MatchString(commit) {
				t.Errorf("`%s version` reported commit %q, want a 40-character revision. "+
					"Go stamps this automatically for main packages built inside a checkout; "+
					"if it is %q the build lost its VCS information",
					command, commit, Unknown)
			}

			// The tree is usually dirty while this is being developed, so the
			// clean case is not asserted here — build_test.go covers both
			// renderings. What is asserted is that dirty is *reported*, never
			// swallowed, whenever it is true.
			if strings.Contains(text, "uncommitted changes") &&
				!strings.Contains(text, "cannot be traced to a commit") {
				t.Errorf("`%s version` mentioned uncommitted changes without saying what "+
					"they mean:\n%s", command, text)
			}
		})
	}
}

// commitFrom pulls the revision out of the `version` output.
func commitFrom(t *testing.T, text string) string {
	t.Helper()

	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "commit" {
			return fields[1]
		}
	}
	t.Fatalf("no `commit` line in the version output:\n%s", text)
	return ""
}

func TestTheAgentRefusesAnUnknownCommandRatherThanIgnoringIt(t *testing.T) {
	// The catalogue rule from ADR 0002, checked on the real binary: an operation
	// that is not in the table is refused. A binary that exits 0 on a mistyped
	// command is one an install script cannot detect a mistake with.
	path := buildFor(t, "ratline-agent", runtime.GOOS, runtime.GOARCH)

	output, err := exec.Command(path, "connct").CombinedOutput()
	if err == nil {
		t.Fatalf("`ratline-agent connct` exited 0; an unknown command must be refused:\n%s", output)
	}

	text := string(output)
	if !strings.Contains(text, `no command named "connct"`) {
		t.Errorf("the refusal does not name what was asked for:\n%s", text)
	}
	if !strings.Contains(text, "version") {
		t.Errorf("the refusal does not list what is available, which is what an operator "+
			"who mistyped needs:\n%s", text)
	}
}

func TestRunRefusesUntilThereIsATransport(t *testing.T) {
	// The scaffold's most important behaviour. A `run` that blocked forever
	// doing nothing would install cleanly, satisfy a readiness check, and
	// present as a healthy host that never receives an instruction.
	path := buildFor(t, "ratline-agent", runtime.GOOS, runtime.GOARCH)

	output, err := exec.Command(path, "run").CombinedOutput()
	if err == nil {
		t.Fatalf("`ratline-agent run` exited 0 without a transport:\n%s", output)
	}
	if !strings.Contains(string(output), "RL-M2-002") {
		t.Errorf("the refusal should name the task that will fix it:\n%s", output)
	}
}

func TestPrivdOpensNoSocketYet(t *testing.T) {
	// A root process that listens before it validates is the vulnerability class
	// this entire design exists to avoid, so `serve` must fail rather than
	// accept anything.
	path := buildFor(t, "ratline-privd", runtime.GOOS, runtime.GOARCH)

	output, err := exec.Command(path, "serve").CombinedOutput()
	if err == nil {
		t.Fatalf("`ratline-privd serve` exited 0; it must not present as a working "+
			"privileged helper:\n%s", output)
	}
	if !strings.Contains(string(output), "RL-M2-008") {
		t.Errorf("the refusal should name the task that will fix it:\n%s", output)
	}
}
