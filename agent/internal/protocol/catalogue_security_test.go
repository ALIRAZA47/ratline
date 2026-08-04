// The catalogue's security properties, asserted on the agent's side (RL-M2-002).
//
// The tracker declared this artefact as test/security/agent_operation_catalogue_security_test.go.
// That path cannot work: Go requires a _test.go file to sit in the package it
// tests, and test/ is outside the agent module entirely, so a file there would
// never be compiled or run — it would be a security suite that silently does
// nothing, which is worse than an inconvenient path. The artefact is recorded at
// its real location instead, and the TypeScript half lives at
// test/security/agent_operation_catalogue.test.ts.
package protocol

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// Acceptance 4: "A test asserts the agent rejects an operation name outside the
// catalogue."
func TestAnOperationOutsideTheCatalogueIsRefused(t *testing.T) {
	// Names chosen to cover the ways a caller might expect a fall-through: a
	// plausible-looking operation, a near miss on a real one, an empty name, and
	// the shapes somebody would try if they were looking for a command runner.
	for _, name := range []string{
		"host.shell.run",
		"exec",
		"site.user.creat",   // one character off a real operation
		"site.user.create ", // trailing space
		"SITE.USER.CREATE",  // case
		"",
		"*",
		"../site.user.create",
	} {
		t.Run(name, func(t *testing.T) {
			operation, err := Lookup(name)

			if err == nil {
				t.Fatalf("Lookup(%q) succeeded and returned %+v; there must be no default branch",
					name, operation)
			}
			if !errors.Is(err, ErrUnknownOperation) {
				t.Errorf("Lookup(%q) failed with %v, want ErrUnknownOperation so a caller can "+
					"distinguish an unknown name from a malformed argument", name, err)
			}
			if operation.Name != "" {
				t.Errorf("Lookup(%q) returned a non-zero operation %+v alongside its error; a "+
					"caller ignoring the error must not receive something usable", name, operation)
			}

			// Accept is the entry point the transport will use, so the refusal has to
			// hold there too rather than only in Lookup.
			if _, err := Accept(name, Arguments{}); err == nil {
				t.Errorf("Accept(%q) succeeded", name)
			}
		})
	}
}

// Acceptance 3: "There is no operation that accepts a free-form command."
//
// Asserted against the argument VOCABULARY rather than against the operation list.
// Reviewing the list would miss a `string` argument named `options`, which is a
// free-form command with better manners; the property that actually holds is that
// no kind can express one.
func TestNoArgumentKindCanExpressAFreeFormCommand(t *testing.T) {
	forbidden := []string{"command", "cmd", "shell", "script", "args", "argv", "flags", "env", "text", "raw"}

	for name := range ArgumentKinds {
		for _, word := range forbidden {
			if strings.Contains(strings.ToLower(name), word) {
				t.Errorf("argument kind %q contains %q. No kind may name a free-form command "+
					"or an argument list (RL-M2-002 acceptance 3, ADR 0002)", name, word)
			}
		}
	}

	for _, operation := range Operations {
		for _, spec := range operation.Args {
			for _, word := range forbidden {
				if strings.Contains(strings.ToLower(spec.Name), word) {
					t.Errorf("operation %q has an argument named %q, which contains %q",
						operation.Name, spec.Name, word)
				}
			}
		}
	}
}

// Every kind must actually constrain something. This is the load-bearing half of
// the test above: a kind called `site_slug` with no pattern, no enumeration and no
// validator accepts anything at all, and its name would keep the scan above happy.
func TestEveryArgumentKindConstrainsItsValues(t *testing.T) {
	for name, kind := range ArgumentKinds {
		constrained := kind.Pattern != "" || len(kind.OneOf) > 0 || kind.Validator != "" ||
			kind.Bounded || kind.GoType == "bool"

		if !constrained {
			t.Errorf("argument kind %q constrains nothing: no pattern, no enumeration, no "+
				"validator, no bounds. Such a kind accepts free-form input", name)
		}

		// A string kind with no length limit is unbounded input, which is a denial
		// of service against the host this runs on regardless of what it contains.
		if kind.GoType == "string" && kind.MaxBytes == 0 {
			t.Errorf("argument kind %q is a string with no MaxBytes", name)
		}
	}
}

// The patterns must be RE2-compatible, because this half of the catalogue is Go.
//
// A pattern using lookahead compiles in the control plane and fails here — and the
// failure would arrive at runtime, on a host, as an agent that refuses every
// instruction using that kind. Caught here instead, in the language that cannot
// take it.
func TestEveryPatternCompilesUnderRE2(t *testing.T) {
	for name, kind := range ArgumentKinds {
		if kind.Pattern == "" {
			continue
		}

		expression, err := regexp.Compile(kind.Pattern)
		if err != nil {
			t.Errorf("argument kind %q has a pattern Go cannot compile: %v", name, err)
			continue
		}

		// Anchored at both ends. An unanchored pattern matches a substring, so
		// `^rl-[a-z]+` without `$` accepts "rl-web; rm -rf /" — the value passes
		// validation and carries whatever follows.
		if !strings.HasPrefix(kind.Pattern, "^") || !strings.HasSuffix(kind.Pattern, "$") {
			t.Errorf("argument kind %q pattern %q is not anchored at both ends; an unanchored "+
				"pattern validates a substring and lets the rest through",
				name, kind.Pattern)
		}

		// The pattern must reject the empty string, or `required` means nothing.
		if expression.MatchString("") {
			t.Errorf("argument kind %q accepts the empty string", name)
		}
	}
}

func TestArgumentsAreRejectedRatherThanIgnoredOrDefaulted(t *testing.T) {
	slug, err := Lookup("site.file.write")
	if err != nil {
		t.Fatalf("site.file.write is missing from the catalogue: %v", err)
	}

	cases := []struct {
		name string
		args Arguments
		want string
	}{
		{"missing one", Arguments{"slug": "blog"}, "requires argument"},
		{"none at all", Arguments{}, "requires argument"},
		{
			"an argument the operation does not declare",
			Arguments{"slug": "blog", "path": "index.html", "owner": "root"},
			"has no argument",
		},
		{"a slug that is not one", Arguments{"slug": "Blog!", "path": "index.html"}, "does not match"},
		{"a traversal in the path", Arguments{"slug": "blog", "path": "../../etc/passwd"}, "does not match"},
		{"an absolute path", Arguments{"slug": "blog", "path": "/etc/passwd"}, "does not match"},
		{"a leading hyphen, which looks like a flag", Arguments{"slug": "-rf", "path": "x"}, "does not match"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Validate(slug, c.args)
			if err == nil {
				t.Fatalf("Validate accepted %v", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("Validate(%v) said %q, want it to mention %q", c.args, err, c.want)
			}
		})
	}
}

func TestTheAgentRefusesToPerformAPrivilegedOperationItself(t *testing.T) {
	// Refused up front rather than attempted. Attempting it fails on file
	// permissions somewhere deep in the work, and a permissions failure is
	// indistinguishable from a misconfigured host — so the operator gets sent to
	// look at ownership instead of at the instruction that should not have arrived.
	privileged := 0
	for _, operation := range Operations {
		if operation.Performer != "privd" {
			continue
		}
		privileged++

		if _, err := Accept(operation.Name, Arguments{}); !errors.Is(err, ErrNotPerformable) {
			t.Errorf("Accept(%q) returned %v, want ErrNotPerformable — the agent must not "+
				"attempt a root operation", operation.Name, err)
		}
	}

	if privileged == 0 {
		t.Fatal("no privileged operations in the catalogue, so this test verified nothing")
	}
}

func TestAValidInstructionIsAccepted(t *testing.T) {
	// The other direction, so none of the above passes by refusing everything —
	// which is the way a validator most often breaks without anybody noticing.
	operation, err := Accept("site.file.write", Arguments{"slug": "blog", "path": "posts/index.html"})
	if err != nil {
		t.Fatalf("a well-formed instruction was refused: %v", err)
	}
	if operation.Name != "site.file.write" {
		t.Errorf("Accept returned %q", operation.Name)
	}

	// And the count, so a future Validate that returns early is caught. Asserting
	// "no error" alone would pass for a Validate that checked nothing at all.
	checked, err := Validate(operation, Arguments{"slug": "blog", "path": "posts/index.html"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if checked != len(operation.Args) {
		t.Errorf("Validate checked %d of %d arguments", checked, len(operation.Args))
	}
}

func TestNumbersAreNotNormalisedIntoAcceptance(t *testing.T) {
	provision, err := Lookup("runtime.provision")
	if err != nil {
		t.Fatalf("runtime.provision is missing: %v", err)
	}

	// A value that round-trips differently than it arrived is a value the control
	// plane and the agent can disagree about — and the instruction was signed over
	// the bytes, not over the parsed number.
	for _, port := range []string{"0080", " 80", "80 ", "+80", "-80", "8e1", "0", "65536", ""} {
		if _, err := Validate(provision, Arguments{"runtime": "node", "port": port}); err == nil {
			t.Errorf("port %q was accepted", port)
		}
	}

	for _, port := range []string{"1", "80", "8080", "65535"} {
		if _, err := Validate(provision, Arguments{"runtime": "node", "port": port}); err != nil {
			t.Errorf("port %q was refused: %v", port, err)
		}
	}
}

func TestARejectionDoesNotEchoTheRejectedValue(t *testing.T) {
	// A rejected argument is attacker-controlled and the message reaches a log.
	// Echoing it back is how a rejection becomes an injection into whatever reads
	// the log next.
	marker := "eNtRoPy-MaRkEr-9f3a2b"
	write, err := Lookup("site.file.write")
	if err != nil {
		t.Fatalf("site.file.write is missing: %v", err)
	}

	_, err = Validate(write, Arguments{"slug": marker + "!!", "path": "x"})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("the refusal echoed the rejected value:\n%v", err)
	}
}
