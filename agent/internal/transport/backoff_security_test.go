// The reconnect wait, tested for the property the fleet depends on (RL-M2-006,
// acceptance 2).
//
// This is a *_security_test.go and not a plain one, which needs a word of justification
// because backoff reads like availability code. It is availability code, and the failure
// it prevents is a denial of service the fleet performs on its own control plane: every
// agent loses its connection at the same instant when the control plane restarts, and
// without jitter every agent returns at the same instant too. The larger the fleet, the
// worse the spike — a property that scales the wrong way is a vulnerability with a
// capacity-planning disguise.
//
// The overflow test is the one that would be easiest to leave out and the one most likely
// to matter. A negative time.Duration makes time.NewTimer fire immediately, so a wait
// computed by shifting past 63 bits stops being a wait at all — and it happens only after
// a long outage, which is exactly when the control plane can least afford an unthrottled
// fleet.
package transport

import (
	"context"
	"math"
	"testing"
	"time"
)

// TestNoDelayEverExceedsTheCeilingOrGoesNegative drives the attempt count far past the
// point where naive shifting overflows.
//
// 1000 attempts is not a realistic number of consecutive failures; 64 is, for a host that
// was switched off over a long weekend while the control plane moved. Both are covered by
// the same loop because the boundary is what matters, not the plausibility.
//
// # The attempt list, and a hole this test used to have
//
// It originally sampled 1, 2, 10, 31, 32, 62, 63, 64, 65, 128, 1000 and MaxInt32, which
// looks thorough and MISSED the overflow entirely: mutating the clamp to run after the
// shift instead of before it left this test green, and only two other tests caught it. With
// a first window of one second — 10^9 nanoseconds, whose low nine bits are zero — shifting
// left 62 places shifts every set bit off the end and yields exactly ZERO, which is neither
// negative nor above the ceiling. The overflow into a negative duration happens in the
// thirties and forties, which the list stepped straight over.
//
// So the range 33..50 is walked exhaustively, and a zero delay is now a failure in its own
// right. A wait of nothing is the same outcome as a negative wait — an agent dialling in a
// tight loop — and only one of the two is obvious when you read it.
func TestNoDelayEverExceedsTheCeilingOrGoesNegative(t *testing.T) {
	t.Parallel()

	backoff := Backoff{
		First: time.Second,
		Max:   time.Minute,
		// Fixed at the top of the window, so this test measures the WINDOW and not the
		// jitter. A random source here would make an overflow show up one run in a
		// thousand, which is the same as not testing it.
		Random: func() float64 { return 0.999999 },
	}

	attempts := []int{1, 2, 10, 31, 32, 62, 63, 64, 65, 128, 1000, math.MaxInt32}
	for attempt := 33; attempt <= 50; attempt++ {
		attempts = append(attempts, attempt)
	}

	for _, attempt := range attempts {
		delay := backoff.Delay(attempt)
		if delay < 0 {
			t.Errorf("attempt %d produced a NEGATIVE delay of %s. time.NewTimer fires "+
				"immediately on a negative duration, so this agent would reconnect in a tight "+
				"loop — after a long outage, when the control plane can least afford it",
				attempt, delay)
		}
		if delay <= 0 {
			t.Errorf("attempt %d produced no wait at all (%s). The window is never narrower "+
				"than First, so a zero here means the interval arithmetic lost the value — an "+
				"overflow that shifted every bit off the end, most likely", attempt, delay)
		}
		if delay > backoff.Max {
			t.Errorf("attempt %d produced %s, which is above the %s ceiling",
				attempt, delay, backoff.Max)
		}
	}
}

// TestTheWindowGrowsExponentiallyAndThenStops is the "exponential" half of acceptance 2.
func TestTheWindowGrowsExponentiallyAndThenStops(t *testing.T) {
	t.Parallel()

	backoff := Backoff{
		First:  100 * time.Millisecond,
		Max:    800 * time.Millisecond,
		Random: func() float64 { return 0.999999 },
	}

	// Each expectation is the window, and the delay is a hair under it because the window
	// is half-open. Compared with a tolerance of one part in a thousand rather than for
	// equality, since the jitter multiplies by a float.
	for attempt, want := range map[int]time.Duration{
		1: 100 * time.Millisecond,
		2: 200 * time.Millisecond,
		3: 400 * time.Millisecond,
		4: 800 * time.Millisecond,
		5: 800 * time.Millisecond, // capped
		9: 800 * time.Millisecond, // still capped, several doublings later
	} {
		got := backoff.Delay(attempt)
		if got > want || got < want-want/1000 {
			t.Errorf("attempt %d waited %s, want just under %s", attempt, got, want)
		}
	}
}

// TestTheFIRSTRetryIsJitteredToo is the case a floor would break, and the case that
// matters most.
//
// A control plane restart drops every connection in the fleet simultaneously, so the FIRST
// retry is the one that arrives as a spike. A backoff that jitters only from the second
// attempt onward would look correct in a test that sampled attempt 5 and would deliver the
// whole fleet at t=First.
func TestTheFIRSTRetryIsJitteredToo(t *testing.T) {
	t.Parallel()

	backoff := Backoff{First: time.Second, Max: time.Minute}

	seen := map[time.Duration]int{}
	const draws = 200
	for range draws {
		seen[backoff.Delay(1)]++
	}

	// A deterministic first retry would produce exactly one distinct value. The threshold
	// is generous because the assertion is "not a constant", not "uniformly distributed".
	if len(seen) < draws/2 {
		t.Errorf("%d draws of the first retry produced only %d distinct delays. If it is a "+
			"constant, every agent in the fleet returns at the same instant after a control "+
			"plane restart, which is the spike the jitter exists to remove", draws, len(seen))
	}
}

// TestTheJitterSpreadsAcrossTheWholeWindow asserts the shape, not merely the variation.
//
// "Full jitter" means uniform over [0, window). A source that jittered only the top decile
// would pass the test above and would still deliver the fleet in a narrow band.
func TestTheJitterSpreadsAcrossTheWholeWindow(t *testing.T) {
	t.Parallel()

	backoff := Backoff{First: time.Second, Max: time.Minute}
	window := 4 * time.Second // attempt 3: 1s << 2

	lowest, highest := time.Duration(math.MaxInt64), time.Duration(0)
	for range 1000 {
		delay := backoff.Delay(3)
		if delay < lowest {
			lowest = delay
		}
		if delay > highest {
			highest = delay
		}
	}

	// A thousand uniform draws over four seconds land within the first and last 5% with
	// overwhelming probability — the chance of missing a 5% tail 1000 times is 0.95^1000,
	// which is about 5e-23. So this is not a flaky assertion dressed up as a statistical
	// one.
	if lowest > window/20 {
		t.Errorf("the lowest of 1000 draws was %s, more than a twentieth of the %s window: "+
			"the delay is not spread across the whole window", lowest, window)
	}
	if highest < window-window/20 {
		t.Errorf("the highest of 1000 draws was %s, well under the %s window", highest, window)
	}
	if highest >= window {
		t.Errorf("a draw of %s reached or exceeded the %s window, which should be half-open",
			highest, window)
	}
}

// TestTwoAgentsDoNotAgreeOnWhenToReturn is the lockstep property stated as the fleet sees
// it, rather than as a distribution.
func TestTwoAgentsDoNotAgreeOnWhenToReturn(t *testing.T) {
	t.Parallel()

	// Two independently constructed backoffs with the default source, which is what two
	// agents on two hosts have.
	first := Backoff{First: time.Second, Max: time.Minute}
	second := Backoff{First: time.Second, Max: time.Minute}

	agreements := 0
	for attempt := 1; attempt <= 50; attempt++ {
		if first.Delay(attempt) == second.Delay(attempt) {
			agreements++
		}
	}
	// Nanosecond-resolution draws colliding even once would be surprising; allowing a
	// couple keeps the test from being the flakiest thing in the suite for no gain.
	if agreements > 2 {
		t.Errorf("two agents agreed on %d of 50 waits. They are meant to be independent — "+
			"a shared or missing random source is the likely cause", agreements)
	}
}

// TestAMisconfiguredBackoffStillBacksOff covers the values a hand-written unit file
// produces: an empty variable, a negative one, a ceiling below the floor.
//
// The dangerous direction is a configuration that means "no wait", because that is an
// agent hammering the control plane, and an operator who typed `0` meant "as fast as
// possible" rather than "denial of service" and should get neither.
func TestAMisconfiguredBackoffStillBacksOff(t *testing.T) {
	t.Parallel()

	atTop := func() float64 { return 0.999999 }

	cases := map[string]Backoff{
		"zero values":         {Random: atTop},
		"negative first":      {First: -time.Second, Max: time.Minute, Random: atTop},
		"negative ceiling":    {First: time.Second, Max: -time.Minute, Random: atTop},
		"ceiling below first": {First: time.Minute, Max: time.Second, Random: atTop},
	}

	for name, backoff := range cases {
		delay := backoff.Delay(1)
		if delay <= 0 {
			t.Errorf("%s produced a first wait of %s, which is an agent that does not back "+
				"off at all", name, delay)
		}
		// And the ceiling still holds, whatever was configured.
		if capped := backoff.Delay(40); capped <= 0 || capped > DefaultMaxBackoff {
			t.Errorf("%s produced %s at attempt 40; it must be positive and no more than %s",
				name, capped, DefaultMaxBackoff)
		}
	}
}

// TestARandomSourceOutsideItsRangeCannotProduceAnUnboundedWait covers a source that
// misbehaves rather than a configuration that does.
func TestARandomSourceOutsideItsRangeCannotProduceAnUnboundedWait(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]func() float64{
		"always negative":  func() float64 { return -5 },
		"always above one": func() float64 { return 12 },
		"not a number":     func() float64 { return math.NaN() },
	} {
		backoff := Backoff{First: time.Second, Max: time.Minute, Random: source}
		delay := backoff.Delay(5)
		if delay < 0 || delay > backoff.Max {
			t.Errorf("a %s source produced %s, outside [0, %s]", name, delay, backoff.Max)
		}
	}
}

// TestTheAttemptCounterResetsOnlyOnSuccess is the other half of "survives a restart": a
// counter that never reset would leave the fleet a minute apart from every proof for the
// rest of the day.
func TestTheAttemptCounterResetsOnlyOnSuccess(t *testing.T) {
	t.Parallel()

	attempts := NewAttempts(Backoff{First: time.Second, Max: time.Minute,
		Random: func() float64 { return 0.999999 }})

	for expected := 1; expected <= 4; expected++ {
		attempts.Failed()
		if attempts.Count() != expected {
			t.Fatalf("after %d failures the counter says %d", expected, attempts.Count())
		}
	}
	if got := attempts.Failed(); got < 8*time.Second {
		t.Errorf("the fifth failure waited %s; the window should have doubled four times", got)
	}

	attempts.Succeeded()
	if attempts.Count() != 0 {
		t.Fatalf("a success left the counter at %d", attempts.Count())
	}
	if got := attempts.Failed(); got > time.Second {
		t.Errorf("the first failure after a success waited %s, so the counter did not reset", got)
	}
}

// TestTheAttemptCounterSaturates keeps a very long outage from wrapping the counter into a
// negative attempt number, which Delay reads as "no wait at all".
func TestTheAttemptCounterSaturates(t *testing.T) {
	t.Parallel()

	attempts := NewAttempts(Backoff{First: time.Second, Max: time.Minute,
		Random: func() float64 { return 0.999999 }})

	for range 5000 {
		if delay := attempts.Failed(); delay <= 0 || delay > time.Minute {
			t.Fatalf("failure %d produced %s", attempts.Count(), delay)
		}
	}
	if attempts.Count() < 0 {
		t.Errorf("the counter went negative at %d", attempts.Count())
	}
}

// TestWaitStopsWhenTheContextDoes is why the loop can be shut down.
//
// A plain time.Sleep would make a systemd stop wait out its timeout and escalate to
// SIGKILL for up to the ceiling — a minute of an operator watching `systemctl stop` hang.
func TestWaitStopsWhenTheContextDoes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	err := Wait(ctx, time.Minute)
	if err == nil {
		t.Fatal("Wait returned nil after a cancelled context, so a stop would be ignored")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("Wait took %s to notice a cancelled context", elapsed)
	}

	// And a zero delay is not a licence to continue after a stop was requested.
	if err := Wait(ctx, 0); err == nil {
		t.Error("Wait(ctx, 0) returned nil after cancellation, so a zero backoff would let the " +
			"loop keep dialling through a shutdown")
	}

	// A live context waits and returns nil.
	if err := Wait(context.Background(), time.Millisecond); err != nil {
		t.Errorf("Wait on a live context returned %v", err)
	}
}
