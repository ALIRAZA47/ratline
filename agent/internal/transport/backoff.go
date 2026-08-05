// Package transport holds the agent's outbound connection to the control plane
// (RL-M2-006, ADR 0002 as amended by A-04).
//
// # The agent dials out, and nothing here ever listens
//
// ADR 0002 chose the dial direction before it chose anything else, because it is the
// decision that sets the fleet's attack surface: a control plane that dials agents needs
// every managed host to open an inbound port, which is one new pre-authentication
// service multiplied by the number of hosts. Dialling out adds nothing to the host and
// works behind network address translation, which is where most hosts actually are.
//
// So this package contains no listener, and that is a property rather than an
// observation — agent/internal/listencheck fails the build if any code the agent links
// can open a network port.
//
// # What a connection is here, and what it is not
//
// The control plane's agent surface is HTTP: POST /agent/challenge then
// POST /agent/authenticate. A "connection" is therefore an authenticated exchange rather
// than a socket held open, and the identity proof is per-exchange because A-04's binding
// property makes it so — the challenge is consumed on first use, so every reconnection
// needs a fresh one and a captured answer is worth nothing.
//
// What this package does NOT do is carry instructions. Receiving and verifying an
// instruction envelope is RL-M2-012 onward; the envelope verification it will use is
// already in agent/internal/protocol. Keeping them separate is deliberate: the reconnect
// loop is availability code, the envelope path is authorisation code, and the second must
// not inherit the first's willingness to retry.
package transport

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
)

// Backoff is how long the agent waits before dialling again.
//
// # Why the jitter is not optional
//
// Every agent in a fleet loses its connection at the same instant when the control plane
// restarts. Un-jittered exponential backoff means they all return at the same instant
// too, and then again one interval later, and the fleet spends the outage delivering a
// synchronised load spike to a process that is trying to come up. That is a denial of
// service the operator inflicted on themselves by deploying, and it gets worse as the
// fleet grows — which is the wrong direction for a property to scale.
//
// # Full jitter, and the floor that is deliberately absent
//
// The delay is uniform over [0, interval), where interval doubles per attempt up to Max.
// This is "full jitter", which measures best for total contention: the retries of N
// agents spread evenly across the window instead of stacking at its edge.
//
// A floor — never wait less than some minimum — is the obvious hardening and is left out
// on purpose. Its cost is that the earliest any agent can return is the floor, so the
// distribution acquires a leading edge that every agent shares, which is a smaller
// version of the spike the jitter exists to remove. Its benefit would be preventing a
// tight retry loop, and that is already prevented by the interval doubling on every
// failure: a run of small draws is possible, a run of small draws forever is not, because
// the window it is drawn from is twice as wide each time.
type Backoff struct {
	// First is the width of the window for the first retry.
	First time.Duration
	// Max is the widest window. Reached by doubling and never exceeded.
	Max time.Duration
	// Random returns a value in [0,1). Injectable so a test can assert the shape of the
	// distribution rather than sampling it and hoping; nil means math/rand/v2, which is
	// seeded from the runtime and needs no seeding here.
	Random func() float64
}

// Defaults, sized against a control plane restart rather than against nothing.
//
// A restart of a Node process behind a migration takes single-digit seconds, so a first
// window of one second means most agents are back before an operator has switched
// windows. A ceiling of one minute bounds how long a host stays dark after a longer
// outage — a host reporting nothing is a host an operator cannot act on, so the ceiling
// is a health property and not only a politeness one.
const (
	DefaultFirstBackoff = 1 * time.Second
	DefaultMaxBackoff   = 60 * time.Second
)

// maxShift caps the doubling so the interval arithmetic cannot overflow.
//
// This is the whole reason Delay does not simply write First << (attempt-1). A
// time.Duration is an int64 of nanoseconds; shifting one left 63 times makes it negative,
// and a negative duration passed to time.After or time.NewTimer fires IMMEDIATELY. So an
// agent whose control plane had been down long enough to reach attempt 64 would stop
// backing off altogether and reconnect in a tight loop — the exact failure the jitter
// exists to prevent, arriving only after a long outage, which is precisely when the
// control plane can least afford it. A test drives the attempt count past the overflow
// point for that reason.
const maxShift = 62

// Delay is how long to wait before attempt number `attempt`.
//
// Attempts are 1-based and count RETRIES: Delay(1) is the wait before the second dial,
// because the first needs no wait. Anything at or below zero returns zero rather than
// erroring — a caller asking "how long before the attempt I am already making" gets the
// honest answer.
func (backoff Backoff) Delay(attempt int) time.Duration {
	first, ceiling := backoff.bounds()
	if attempt <= 0 {
		return 0
	}

	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}

	interval := first
	if shift > 0 {
		// Compared BEFORE shifting, not clamped after. `first << shift` is the value
		// that overflows, so a check on its result is a check on a number that has
		// already gone wrong. ceiling>>shift with shift <= 62 is always well defined.
		if first > ceiling>>shift {
			interval = ceiling
		} else {
			interval = first << shift
		}
	}
	if interval > ceiling {
		interval = ceiling
	}

	fraction := backoff.random()
	// A random source outside [0,1) is a bug in the source, and clamping is the response
	// that keeps this function total. Returning an error instead would push a decision
	// into every caller for a case none of them can do anything about.
	switch {
	case fraction < 0:
		fraction = 0
	case fraction >= 1:
		// Not 1.0: the window is half-open so that Delay never returns exactly Max, which
		// keeps "the delay is below the ceiling" a property a test can assert without a
		// boundary argument.
		fraction = 0.999999
	}

	return time.Duration(fraction * float64(interval))
}

func (backoff Backoff) bounds() (first, ceiling time.Duration) {
	first, ceiling = backoff.First, backoff.Max
	// Zero means unset, which is the common case for a zero-valued struct in a test. A
	// negative value is a mistake, and treating it as the default rather than as "no wait"
	// is the safe direction: "no wait" is an agent hammering the control plane.
	if first <= 0 {
		first = DefaultFirstBackoff
	}
	if ceiling <= 0 {
		ceiling = DefaultMaxBackoff
	}
	if ceiling < first {
		// A ceiling below the floor would otherwise make every window Max, silently
		// discarding the growth. Clamping the FIRST window down to the ceiling keeps the
		// stated invariant — no delay exceeds Max — and makes the misconfiguration
		// visible as a constant delay rather than as a subtly missing curve.
		first = ceiling
	}
	return first, ceiling
}

func (backoff Backoff) random() float64 {
	if backoff.Random != nil {
		return backoff.Random()
	}
	return rand.Float64()
}

// Attempts counts consecutive failures and turns them into waits.
//
// Held by the reconnect loop so that "reset on success" is one call rather than a
// convention the loop has to remember. The counter matters as much as the curve: an agent
// that reset it on every error would never leave the first window, and one that never
// reset it would still be waiting a minute between attempts a week after the outage
// ended.
type Attempts struct {
	backoff Backoff
	count   int
}

// NewAttempts starts a fresh counter.
func NewAttempts(backoff Backoff) *Attempts {
	return &Attempts{backoff: backoff}
}

// Failed records a failure and returns how long to wait before trying again.
func (attempts *Attempts) Failed() time.Duration {
	// Saturating, so a very long outage does not wrap the counter into a negative
	// attempt number and hand Delay something it reads as "no wait at all".
	if attempts.count < maxShift+1 {
		attempts.count++
	}
	return attempts.backoff.Delay(attempts.count)
}

// Succeeded clears the counter, so the next failure starts from the first window again.
func (attempts *Attempts) Succeeded() { attempts.count = 0 }

// Count is how many consecutive failures have been recorded. For logging and tests.
func (attempts *Attempts) Count() int { return attempts.count }

// Wait sleeps for a delay, or returns early if the context ends first.
//
// A plain time.Sleep would make an agent ignore shutdown for up to Max — a systemd stop
// would time out and escalate to SIGKILL, which is a bad habit for a process that will
// later hold state worth flushing.
func Wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		// Still checked, because a zero delay must not be a licence to keep going after
		// shutdown was requested.
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrStopped, ctx.Err())
		default:
			return nil
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: %w", ErrStopped, ctx.Err())
	case <-timer.C:
		return nil
	}
}

// ErrStopped means the caller asked the loop to stop, which is not a failure.
var ErrStopped = errors.New("the agent was asked to stop")
