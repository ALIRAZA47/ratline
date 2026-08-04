// Package cli dispatches subcommands from a table, and refuses anything not in
// it.
//
// This is the same rule ADR 0002 puts on the operation catalogue — "an operation
// not in the catalogue is refused; there is no default branch" — applied to the
// command line, with one implementation so the rule is a property of the code
// rather than a habit repeated in two mains. The command line is a much smaller
// attack surface than the instruction envelope, but the argument for writing it
// this way is the same and the cost here is nothing.
package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Command is one thing a binary can be asked to do.
type Command struct {
	// Name is what the operator types. No aliases: two spellings of one command
	// are two things to keep working, and `version` is short already.
	Name string
	// Summary is one line, lower case, no full stop — it is rendered in a list.
	Summary string
	// Run does the work. Returning an error makes the process exit non-zero with
	// the error on stderr; printing to out is the success path.
	Run func(args []string, out io.Writer) error
}

// Exit codes. Distinct because an init system and an operator's shell both read
// them, and "it failed" and "you asked for something that does not exist" call
// for different responses.
const (
	// ExitOK means the command ran and did what it said.
	ExitOK = 0
	// ExitFailure means the command ran and failed.
	ExitFailure = 1
	// ExitUsage means no command ran, because the request did not name one.
	ExitUsage = 2
)

// Dispatch runs the named command and returns the process exit code.
//
// Invoked with no arguments it prints usage and returns ExitUsage, deliberately
// not ExitOK. `ratline-agent` with no arguments has not been told to do
// anything, and a zero exit would let a systemd unit with Type=oneshot record a
// successful start for a process that did nothing at all — the failure mode
// where the dashboard says the host is fine because the agent exited cleanly
// without ever connecting.
func Dispatch(program string, commands []Command, args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(errOut, usage(program, commands))
		return ExitUsage
	}

	// `--version` and `-v` are what people type, and the flag package is not
	// involved yet, so they are normalised here rather than becoming aliases in
	// the table. Everything else is matched exactly.
	name := args[0]
	switch name {
	case "--version", "-version", "-v":
		name = "version"
	case "--help", "-help", "-h":
		name = "help"
	}

	if name == "help" {
		fmt.Fprint(out, usage(program, commands))
		return ExitOK
	}

	for _, command := range commands {
		if command.Name != name {
			continue
		}
		if err := command.Run(args[1:], out); err != nil {
			fmt.Fprintf(errOut, "%s: %v\n", program, err)
			return ExitFailure
		}
		return ExitOK
	}

	// No default branch, which is the whole point of the package. The refusal
	// names what was asked for and what exists, because an operator who
	// mistyped needs the list and one who is on the wrong binary needs to see
	// that immediately.
	fmt.Fprintf(errOut, "%s: no command named %q.\n", program, args[0])
	fmt.Fprintf(errOut, "Available: %s\n", strings.Join(names(commands), ", "))
	return ExitUsage
}

func names(commands []Command) []string {
	out := make([]string, 0, len(commands))
	for _, command := range commands {
		out = append(out, command.Name)
	}
	sort.Strings(out)
	return out
}

func usage(program string, commands []Command) string {
	width := 0
	for _, command := range commands {
		if len(command.Name) > width {
			width = len(command.Name)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s — one of these commands:\n\n", program)
	sorted := make([]Command, len(commands))
	copy(sorted, commands)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Name < sorted[b].Name })
	for _, command := range sorted {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, command.Name, command.Summary)
	}
	return b.String()
}
