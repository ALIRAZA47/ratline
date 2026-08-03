// Command ratline-privd performs the privileged operations the agent may not,
// and distrusts the agent while doing it (ADR 0004).
//
// It runs as root, socket-activated, with no network access at all — see
// PLAN.md's trust boundary B4. The agent asks over a unix socket; privd
// identifies the caller by peer credentials and re-validates every argument from
// scratch, on the assumption that the agent is already compromised. That
// assumption is the reason this is a separate binary rather than a function.
//
// RL-M2-001 is the scaffold. The socket, the peer-credential check and the
// operation set arrive in RL-M2-008.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ALIRAZA47/ratline/agent/internal/build"
	"github.com/ALIRAZA47/ratline/agent/internal/cli"
)

const program = "ratline-privd"

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
			Name:    "serve",
			Summary: "accept privileged operation requests on the systemd socket",
			Run:     serve,
		},
	}
}

// serve refuses until RL-M2-008.
//
// The refusal matters more here than in the agent. A root process that starts,
// listens, and accepts requests it does not yet validate is the exact shape of
// the vulnerability class this whole design exists to avoid, and a placeholder
// that answers is indistinguishable from one that answers correctly. So there is
// no listener in this binary at all — not a stubbed one, none.
func serve(_ []string, _ io.Writer) error {
	return errors.New(
		"this build has no privileged operations and opens no socket: privd lands in " +
			"RL-M2-008. It is installed early so the agent never has to run as root " +
			"in the meantime",
	)
}
