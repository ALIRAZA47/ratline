// Command ratline-agent runs on a managed host and does what the control plane
// asks, within an enumerated catalogue of operations (ADR 0002).
//
// It is unprivileged. Anything requiring root goes to ratline-privd over a unix
// socket, and privd re-validates every argument from scratch rather than
// trusting this process (ADR 0004). That split is what makes C1 survive a
// compromise of this binary, so it is worth stating in the first commit that
// creates it: nothing here should ever grow a privileged path.
//
// RL-M2-001 is the scaffold. The transport, enrolment and operation catalogue
// arrive in RL-M2-002 onward, which is why `run` exists and refuses.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ALIRAZA47/ratline/agent/internal/build"
	"github.com/ALIRAZA47/ratline/agent/internal/cli"
)

const program = "ratline-agent"

func main() {
	os.Exit(cli.Dispatch(program, commands(), os.Args[1:], os.Stdout, os.Stderr))
}

func commands() []cli.Command {
	return []cli.Command{
		{
			Name:    "version",
			Summary: "report the version, commit and target of this binary",
			Run: func(_ []string, out io.Writer) error {
				fmt.Fprint(out, build.Current().Describe(program))
				return nil
			},
		},
		{
			Name:    "run",
			Summary: "connect to the control plane and serve operations",
			Run:     runAgent,
		},
	}
}

// runAgent refuses, loudly, until RL-M2-002 gives it a transport.
//
// The alternative — a `run` that blocks forever doing nothing — is worse than
// its absence. It would install cleanly, satisfy a systemd readiness check, and
// present as a healthy host that never receives an instruction. An unimplemented
// command that says so cannot be mistaken for a working one.
func runAgent(_ []string, _ io.Writer) error {
	return errors.New(
		"this build cannot connect yet: the agent transport lands in RL-M2-002. " +
			"Until then only `version` does anything, and this host should not be enrolled",
	)
}
