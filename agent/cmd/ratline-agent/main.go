// Command ratline-agent runs on a managed host and does what the control plane
// asks, within an enumerated catalogue of operations (ADR 0002).
//
// It is unprivileged. Anything requiring root goes to ratline-privd over a unix
// socket, and privd re-validates every argument from scratch rather than
// trusting this process (ADR 0004). That split is what makes C1 survive a
// compromise of this binary, so it is worth stating in the first commit that
// creates it: nothing here should ever grow a privileged path.
//
// RL-M2-001 was the scaffold, whose `run` refused because there was no transport.
// RL-M2-006 gives it one: `run` now dials the control plane, proves this host's
// identity and keeps the connection re-made across restarts and outages. What it
// still does not do is CARRY anything — receiving instructions is RL-M2-012
// onward — so a connected agent is a host the control plane can see and not yet
// one it can instruct.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ALIRAZA47/ratline/agent/internal/build"
	"github.com/ALIRAZA47/ratline/agent/internal/cli"
	"github.com/ALIRAZA47/ratline/agent/internal/transport"
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

// runAgent dials the control plane and stays connected (RL-M2-006).
//
// Configuration errors are reported and exit non-zero; everything else is retried
// forever with jittered backoff, because a host that gives up is a host somebody
// has to visit. The distinction is deliberate and it is drawn in transport.New:
// what can be checked at startup is checked there, so systemd records "this agent
// is misconfigured" once rather than logging a failed dial every minute for it.
//
// SIGTERM and SIGINT end the loop cleanly. Without that, a systemd stop would wait
// out its timeout and escalate to SIGKILL, and the agent would acquire the habit of
// being killed — which is a bad habit for a process that later flushes a nonce
// store on the way out.
func runAgent(_ []string, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// The log goes to the command's own output stream rather than to stderr directly, so
	// that a test can read it and an operator gets it in the journal either way.
	config, err := transport.ConfigFromEnvironment(os.Getenv, out)
	if err != nil {
		return err
	}

	client, err := transport.New(config)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "%s: connecting to %s as host %s\n",
		program, config.ControlPlane, config.HostID)

	if err := client.Run(ctx); err != nil {
		if errors.Is(err, transport.ErrStopped) {
			// A requested stop is a success. Returning the error would exit non-zero and
			// make systemd record a failed unit for a clean shutdown, which is the sort of
			// noise that trains operators to ignore unit states.
			fmt.Fprintf(out, "%s: stopped\n", program)
			return nil
		}
		return err
	}
	return nil
}
