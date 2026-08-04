package cli

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func table(ran *string) []Command {
	return []Command{
		{Name: "version", Summary: "report the version", Run: func(args []string, out io.Writer) error {
			*ran = "version:" + strings.Join(args, ",")
			return nil
		}},
		{Name: "run", Summary: "serve operations", Run: func([]string, io.Writer) error {
			return errors.New("no transport yet")
		}},
	}
}

type capture struct {
	out strings.Builder
	err strings.Builder
}

func dispatch(t *testing.T, args ...string) (int, string, string, string) {
	t.Helper()
	var ran string
	var c capture
	code := Dispatch("ratline-agent", table(&ran), args, &c.out, &c.err)
	return code, c.out.String(), c.err.String(), ran
}

func TestAnUnknownCommandIsRefusedAndNamesWhatExists(t *testing.T) {
	code, out, errOut, ran := dispatch(t, "provision")

	if code != ExitUsage {
		t.Errorf("exit code = %d, want %d for an unknown command", code, ExitUsage)
	}
	if ran != "" {
		t.Errorf("a command ran (%q) for an unknown name; there must be no default branch", ran)
	}
	if !strings.Contains(errOut, `no command named "provision"`) {
		t.Errorf("stderr does not name what was asked for: %q", errOut)
	}
	if !strings.Contains(errOut, "run") || !strings.Contains(errOut, "version") {
		t.Errorf("stderr does not list the available commands: %q", errOut)
	}
	if out != "" {
		// A refusal on stdout gets swallowed by a pipeline that only checks
		// stdout for data, which is how an install script reports success.
		t.Errorf("the refusal went to stdout: %q", out)
	}
}

func TestNoArgumentsIsNotSuccess(t *testing.T) {
	code, _, errOut, ran := dispatch(t)

	// The failure this prevents: a systemd unit with Type=oneshot invoking the
	// binary with no arguments, getting exit 0, and recording a successful start
	// for a process that never connected to anything. The dashboard would then
	// show a healthy host on the strength of a clean exit.
	if code != ExitUsage {
		t.Errorf("exit code = %d for no arguments, want %d — exit 0 would let an init "+
			"system record a successful start for a process that did nothing", code, ExitUsage)
	}
	if ran != "" {
		t.Errorf("a command ran (%q) with no arguments", ran)
	}
	if !strings.Contains(errOut, "version") {
		t.Errorf("usage should list the commands: %q", errOut)
	}
}

func TestExplicitHelpSucceedsAndGoesToStdout(t *testing.T) {
	// The mirror of the case above, and the reason usage is not simply always an
	// error: somebody who asked for help got what they asked for, and they are
	// probably piping it to a pager.
	code, out, _, _ := dispatch(t, "--help")

	if code != ExitOK {
		t.Errorf("exit code = %d for --help, want %d", code, ExitOK)
	}
	if !strings.Contains(out, "version") {
		t.Errorf("--help should list the commands on stdout: %q", out)
	}
}

func TestVersionSpellingsAllReachTheSameCommand(t *testing.T) {
	for _, spelling := range []string{"version", "--version", "-version", "-v"} {
		t.Run(spelling, func(t *testing.T) {
			code, _, errOut, ran := dispatch(t, spelling)

			if code != ExitOK {
				t.Errorf("exit code = %d for %q, want %d (stderr: %q)", code, spelling, ExitOK, errOut)
			}
			if !strings.HasPrefix(ran, "version:") {
				t.Errorf("%q ran %q, want the version command", spelling, ran)
			}
		})
	}
}

func TestAFailingCommandExitsOneAndSaysWhy(t *testing.T) {
	code, out, errOut, _ := dispatch(t, "run")

	// Distinct from ExitUsage: an init system restarting on failure should not
	// treat "you asked for a command that does not exist" the same as "the
	// command tried and failed".
	if code != ExitFailure {
		t.Errorf("exit code = %d for a failing command, want %d", code, ExitFailure)
	}
	if !strings.Contains(errOut, "ratline-agent: no transport yet") {
		t.Errorf("stderr should carry the program name and the error: %q", errOut)
	}
	if out != "" {
		t.Errorf("a failure wrote to stdout: %q", out)
	}
}

func TestArgumentsAfterTheCommandReachIt(t *testing.T) {
	// The command's own arguments, not the process's: a command must not have to
	// know it was dispatched, or every one of them re-implements the skip.
	_, _, _, ran := dispatch(t, "version", "--format", "json")

	if ran != "version:--format,json" {
		t.Errorf("the command received %q, want its own arguments only", ran)
	}
}
