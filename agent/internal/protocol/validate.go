// Package protocol is the agent's half of the operation catalogue (RL-M2-002).
//
// The catalogue's data is generated from src/agent/catalogue.ts into
// catalogue_gen.go, and CI fails if the two disagree. THE VALIDATION IS NOT
// GENERATED. ADR 0004 is explicit that duplicating validation across the trust
// boundary is deliberate — "if it lived only in the agent, privd would be a
// confused deputy and the boundary would be decorative" — and the same argument
// applies one level up: the agent must assume the control plane is compromised, so
// checking code it inherited from the control plane would be checking nothing.
//
// What generation buys is agreement about WHAT to check. What hand-writing buys is
// that the checking actually happens here.
//
// # There is no default branch
//
// ADR 0002: "An operation not in the catalogue is refused — there is no default
// branch, and no operation accepts a free-form command." Lookup returns an error
// rather than a zero Operation, so a caller cannot fall through to a generic
// handler by ignoring a second return value it forgot to check.
package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"unicode/utf8"
)

// ErrUnknownOperation is returned for a name absent from the catalogue.
//
// A distinct error rather than a message, because the caller's response to it is
// different in kind: an unknown operation means the control plane asked for
// something this agent version does not have, which is a version mismatch or an
// attack, and either way is not retried.
var ErrUnknownOperation = errors.New("operation is not in the catalogue")

// ErrNotPerformable is returned when the agent is asked to perform an operation
// belonging to privd.
//
// Refused up front rather than attempted. Attempting it would fail on file
// permissions somewhere deep in the work, and a permissions failure is
// indistinguishable from a misconfigured host — so the operator would be sent to
// look at ownership instead of at the instruction that should never have been
// routed here.
var ErrNotPerformable = errors.New("operation belongs to the privileged helper, not the agent")

var (
	byName     map[string]Operation
	byNameOnce sync.Once

	// Patterns are compiled once, at first use rather than in an init function, so
	// a bad pattern surfaces as an error from Lookup instead of a panic during
	// process start. An agent that dies at start is a host that reports nothing.
	patterns     map[string]*regexp.Regexp
	patternsErr  error
	patternsOnce sync.Once
)

func index() map[string]Operation {
	byNameOnce.Do(func() {
		byName = make(map[string]Operation, len(Operations))
		for _, operation := range Operations {
			byName[operation.Name] = operation
		}
	})
	return byName
}

func compiled() (map[string]*regexp.Regexp, error) {
	patternsOnce.Do(func() {
		patterns = make(map[string]*regexp.Regexp)
		for name, kind := range ArgumentKinds {
			if kind.Pattern == "" {
				continue
			}
			expression, err := regexp.Compile(kind.Pattern)
			if err != nil {
				// The catalogue's patterns are RE2-compatible by rule, and the
				// TypeScript test suite rejects lookahead and backreferences for
				// exactly this reason. Reaching here means that rule was broken, so
				// the message says so rather than reporting a regexp problem the
				// reader has no context for.
				patternsErr = fmt.Errorf(
					"argument kind %q has a pattern Go cannot compile: %w. "+
						"Patterns must be RE2-compatible — no lookahead, no backreferences — "+
						"because this half of the catalogue is Go",
					name, err,
				)
				return
			}
			patterns[name] = expression
		}
	})
	return patterns, patternsErr
}

// Lookup returns the operation with this name.
//
// The error is the point: there is no variant that returns a usable zero value, so
// there is nothing for a caller to accidentally proceed with.
func Lookup(name string) (Operation, error) {
	operation, ok := index()[name]
	if !ok {
		return Operation{}, fmt.Errorf("%q: %w", name, ErrUnknownOperation)
	}
	return operation, nil
}

// Arguments is one instruction's arguments, before they have been checked.
//
// A map of strings rather than a typed struct per operation, because this is what
// arrives off the wire. Validate turns it into something trustworthy; nothing
// should read it directly.
type Arguments map[string]string

// Validate checks an operation's arguments against the catalogue.
//
// Order matters and is the opposite of convenient. The operation is resolved
// first, then the performer, then arguments — and unexpected arguments are
// rejected before expected ones are checked, so an instruction carrying an extra
// field is refused rather than silently having it ignored. An ignored extra field
// is how a payload aimed at a future version of the agent gets accepted by this
// one.
//
// Returns the number of arguments checked, so a caller can assert the count is
// what it expected instead of trusting that Validate looked at everything.
func Validate(operation Operation, arguments Arguments) (int, error) {
	expressions, err := compiled()
	if err != nil {
		return 0, err
	}

	expected := make(map[string]ArgumentSpec, len(operation.Args))
	for _, spec := range operation.Args {
		expected[spec.Name] = spec
	}

	// Unexpected first. An instruction with an argument this operation does not
	// declare is malformed, and accepting it while ignoring the field would make
	// the catalogue advisory.
	for name := range arguments {
		if _, ok := expected[name]; !ok {
			return 0, fmt.Errorf(
				"operation %q has no argument %q; it takes %d argument(s) and every one is required",
				operation.Name, name, len(operation.Args),
			)
		}
	}

	checked := 0
	for _, spec := range operation.Args {
		value, present := arguments[spec.Name]
		if !present {
			// Absent is refused rather than defaulted. A default is a decision made
			// on behalf of an operator who did not make it, on a host they own.
			return checked, fmt.Errorf(
				"operation %q requires argument %q (%s)",
				operation.Name, spec.Name, kindWhy(spec.Kind),
			)
		}

		if err := validateValue(expressions, spec, value); err != nil {
			return checked, fmt.Errorf("operation %q argument %q: %w", operation.Name, spec.Name, err)
		}
		checked++
	}

	return checked, nil
}

func kindWhy(kind string) string {
	if k, ok := ArgumentKinds[kind]; ok {
		return k.Why
	}
	return kind
}

func validateValue(expressions map[string]*regexp.Regexp, spec ArgumentSpec, value string) error {
	kind, ok := ArgumentKinds[spec.Kind]
	if !ok {
		// A spec naming a kind that does not exist can only happen if
		// catalogue_gen.go was hand-edited, which its header forbids. Refusing is
		// the only safe reading: an unknown kind cannot be checked, and an
		// unchecked argument must not proceed.
		return fmt.Errorf("unknown argument kind %q — catalogue_gen.go is inconsistent", spec.Kind)
	}

	// Length before pattern, because a regexp is applied to whatever it is given
	// and a multi-megabyte value should be refused on sight rather than matched.
	if kind.MaxBytes > 0 && len(value) > kind.MaxBytes {
		return fmt.Errorf("%d bytes exceeds the %d allowed for %s", len(value), kind.MaxBytes, spec.Kind)
	}

	// Well-formed UTF-8 for everything. A value that is not gets refused before it
	// can reach a file, a log line or an error message, where invalid sequences
	// have a habit of being interpreted by whatever reads them next.
	if !utf8.ValidString(value) {
		return errors.New("not valid UTF-8")
	}

	switch kind.GoType {
	case "string":
		return validateString(expressions, spec.Kind, kind, value)
	case "int64":
		return validateNumber(kind, value)
	case "bool":
		if value != "true" && value != "false" {
			return fmt.Errorf("%q is not a boolean; expected \"true\" or \"false\"", value)
		}
		return nil
	default:
		return fmt.Errorf("argument kind %q has unsupported Go type %q", spec.Kind, kind.GoType)
	}
}

func validateString(
	expressions map[string]*regexp.Regexp,
	kindName string,
	kind ArgumentKind,
	value string,
) error {
	if len(kind.OneOf) > 0 {
		for _, allowed := range kind.OneOf {
			if value == allowed {
				return nil
			}
		}
		return fmt.Errorf("%q is not one of %v", value, kind.OneOf)
	}

	if kind.Pattern != "" {
		expression, ok := expressions[kindName]
		if !ok {
			return fmt.Errorf("kind %q declares a pattern that was never compiled", kindName)
		}
		if !expression.MatchString(value) {
			// The value is NOT quoted back in full. A rejected argument is
			// attacker-controlled, this message reaches a log, and echoing an
			// arbitrary blob into a log line is how a rejection becomes an
			// injection into whatever reads the log.
			return fmt.Errorf("does not match the required form for %s (%s)", kindName, kind.Why)
		}
		return nil
	}

	if kind.Validator != "" {
		// A content blob. It is inert here on purpose: nothing in this package
		// executes it, writes it or interprets it. RL-M2-008 has privd run the named
		// parser and refuse on a non-zero exit before anything is installed, which
		// is where the real check belongs — the parser is the authority on its own
		// format, and reimplementing systemd's unit grammar here would be a second
		// opinion nobody should trust.
		//
		// So the guarantee at this layer is exactly: bounded length, valid UTF-8,
		// and a named parser recorded as owed. Anything stronger stated here would
		// be a claim this code does not support.
		if value == "" {
			return fmt.Errorf("is empty; %s expects content for %s to parse", kindName, kind.Validator)
		}
		return nil
	}

	return fmt.Errorf(
		"argument kind %q constrains nothing: it has no pattern, no enumeration and no "+
			"validator. Every kind must constrain its values, or the catalogue accepts "+
			"free-form input, which RL-M2-002 acceptance 3 forbids",
		kindName,
	)
}

func validateNumber(kind ArgumentKind, value string) error {
	var parsed int64
	// Parsed by hand rather than with strconv.Atoi so a leading plus, a leading
	// zero, whitespace and an empty string are all refused rather than normalised.
	// "0080" and " 80" both mean 80 to Atoi; neither should be accepted from a
	// signed instruction, because a value that round-trips differently than it
	// arrived is a value two parties can disagree about.
	if value == "" {
		return errors.New("is empty")
	}
	for index, digit := range value {
		if digit < '0' || digit > '9' {
			return fmt.Errorf("is not a decimal number (byte %d)", index)
		}
		if index == 0 && digit == '0' && len(value) > 1 {
			return errors.New("has a leading zero")
		}
		parsed = parsed*10 + int64(digit-'0')
		if parsed > 1<<32 {
			// Bailing out before overflow rather than after. A value long enough to
			// wrap int64 would otherwise land inside the bounds check as a small
			// number, which is the one arithmetic bug in this file that would be
			// exploitable rather than merely wrong.
			return errors.New("is too large")
		}
	}

	if kind.Bounded && (parsed < kind.Min || parsed > kind.Max) {
		return fmt.Errorf("%d is outside %d..%d", parsed, kind.Min, kind.Max)
	}
	return nil
}

// PerformableByAgent reports whether the unprivileged agent may perform this
// operation itself.
func PerformableByAgent(operation Operation) bool {
	return operation.Performer == "agent"
}

// Accept resolves and validates an instruction's operation in one step, refusing
// anything the agent must not perform itself.
//
// This is the function the transport should call (RL-M2-003). Having one entry
// point means the three refusals — unknown name, wrong performer, bad argument —
// cannot be reordered or skipped by a caller assembling them in the wrong order.
func Accept(name string, arguments Arguments) (Operation, error) {
	operation, err := Lookup(name)
	if err != nil {
		return Operation{}, err
	}

	if !PerformableByAgent(operation) {
		return Operation{}, fmt.Errorf(
			"%q: %w — route it over the privd socket instead",
			name, ErrNotPerformable,
		)
	}

	if _, err := Validate(operation, arguments); err != nil {
		return Operation{}, err
	}

	return operation, nil
}
