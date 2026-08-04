// The replay store's own properties (RL-M2-007).
//
// The store was built under RL-M2-003, because `Verify` cannot be tested without
// one — an envelope's nonce check needs somewhere to remember nonces. What RL-M2-003
// did not test was the store on its own terms, and one of its three acceptance
// criteria is exactly that: "the store is bounded so it cannot grow without limit".
// A constant named MaxRememberedNonces is not a bound; a bound is what happens when
// the constant is reached.
//
// The restart case lives in envelope_test.go's TestReplayAfterRestartIsRefused,
// because it is a property of the whole verification path rather than of the store,
// and testing it through Verify is what makes it the property ADR 0002 asks for.
package protocol

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedClock(at time.Time) func() time.Time {
	return func() time.Time { return at }
}

func TestTheStoreRefusesWhenFullRatherThanForgettingALiveNonce(t *testing.T) {
	// This is the acceptance criterion, and the assertion is about WHICH failure
	// happens. Evicting the oldest entry would also keep the store bounded, and would
	// be a security failure dressed as availability: an attacker able to flood would
	// choose which live nonce gets forgotten, and then replay the envelope carrying
	// it. Refusing is a denial of service. Between the two, refusing is correct.
	now := time.UnixMilli(1_770_000_000_000)
	// A small bound, exercising the same code path. Reaching the production bound
	// here costs 10,000 fsyncs — 95 seconds, more than the rest of the suite
	// combined — and would prove nothing the small case does not.
	// TestTheProductionBoundIsWhatItClaims pins the constant separately.
	const bound = 8
	store := OpenNonceStoreAt(filepath.Join(t.TempDir(), "nonces"), fixedClock(now)).WithLimit(bound)

	// Every entry live, so pruning cannot make room.
	expires := now.Add(time.Minute)
	for index := 0; index < bound; index++ {
		fresh, err := store.Remember(fmt.Sprintf("live-%d", index), expires)
		if err != nil {
			t.Fatalf("filling the store failed at %d: %v", index, err)
		}
		if !fresh {
			t.Fatalf("entry %d reported as already seen while filling", index)
		}
	}

	size, err := store.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != bound {
		t.Fatalf("store holds %d entries, want %d", size, bound)
	}

	// One more, with nothing expired.
	fresh, err := store.Remember("one-too-many", expires)
	if !errors.Is(err, ErrStoreFull) {
		t.Fatalf("got (%v, %v), want ErrStoreFull", fresh, err)
	}
	if fresh {
		t.Error("Remember reported the nonce as fresh while also refusing it")
	}

	// The refusal must say what an operator can act on: not "full", but that this is
	// abnormal and what the alternative would have cost.
	for _, phrase := range []string{"flooding", "forgetting a live nonce"} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("the refusal does not mention %q:\n%v", phrase, err)
		}
	}

	// And the live entries are all still there. A store that refused the new one
	// while quietly dropping an old one would pass every assertion above.
	if again, err := store.Remember("live-0", expires); err != nil || again {
		t.Errorf("live-0 was forgotten while the store was refusing new entries "+
			"(fresh=%v, err=%v). That is the eviction this test exists to rule out", again, err)
	}
}

func TestSpaceIsReclaimedOnlyByExpiry(t *testing.T) {
	// The other half: the bound must not be a permanent ceiling. Once entries expire
	// they are dropped, and the store accepts again — otherwise one burst would wedge
	// a host until somebody deleted a file by hand.
	start := time.UnixMilli(1_770_000_000_000)
	clock := start
	const bound = 8
	store := OpenNonceStoreAt(filepath.Join(t.TempDir(), "nonces"),
		func() time.Time { return clock }).WithLimit(bound)

	shortExpiry := start.Add(time.Second)
	for index := 0; index < bound; index++ {
		if _, err := store.Remember(fmt.Sprintf("short-%d", index), shortExpiry); err != nil {
			t.Fatalf("filling failed at %d: %v", index, err)
		}
	}

	if _, err := store.Remember("blocked", start.Add(time.Minute)); !errors.Is(err, ErrStoreFull) {
		t.Fatalf("expected ErrStoreFull while every entry is live, got %v", err)
	}

	// Move past the expiry of everything in the store.
	clock = shortExpiry.Add(time.Millisecond)

	fresh, err := store.Remember("accepted-after-expiry", clock.Add(time.Minute))
	if err != nil {
		t.Fatalf("the store did not reclaim space after its entries expired: %v", err)
	}
	if !fresh {
		t.Error("the new nonce was reported as already seen")
	}
}

func TestAnExpiredButUnprunedNonceIsStillRefused(t *testing.T) {
	// Presence is presence. An expired entry that has not yet been pruned still means
	// "this nonce was used", and treating it as fresh would open a replay window
	// exactly as wide as the gap between expiry and the next prune — a window whose
	// size is an implementation detail of the pruning schedule, which is the worst
	// possible thing for a security boundary to depend on.
	//
	// Note this is deliberately NOT symmetrical with Verify's behaviour: Verify would
	// have refused the envelope as expired long before reaching the nonce check. The
	// store is defensive on its own account, because it must not depend on its caller
	// having checked.
	start := time.UnixMilli(1_770_000_000_000)
	clock := start
	store := OpenNonceStoreAt(filepath.Join(t.TempDir(), "nonces"), func() time.Time { return clock })

	if _, err := store.Remember("used-once", start.Add(time.Second)); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	// Past expiry, but far too few appends to have triggered a prune.
	clock = start.Add(time.Hour)

	fresh, err := store.Remember("used-once", clock.Add(time.Minute))
	if err != nil {
		t.Fatalf("Remember: %v", err)
	}
	if fresh {
		t.Error("an expired-but-unpruned nonce was accepted as fresh, which is a replay window " +
			"as wide as the gap between expiry and the next prune")
	}
}

func TestCheckingAndRecordingAreOneOperation(t *testing.T) {
	// A `Seen` then `Record` pair has a window between them, and two envelopes
	// carrying the same nonce arriving concurrently would both pass the check before
	// either recorded — a replay the store would then report as having prevented.
	//
	// Run under -race in CI, where a missing lock is detected rather than inferred
	// from a count.
	store := OpenNonceStoreAt(filepath.Join(t.TempDir(), "nonces"),
		fixedClock(time.UnixMilli(1_770_000_000_000)))
	expires := time.UnixMilli(1_770_000_060_000)

	const racers = 64
	var wait sync.WaitGroup
	accepted := make(chan bool, racers)

	for index := 0; index < racers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fresh, err := store.Remember("contended", expires)
			if err != nil {
				t.Errorf("Remember: %v", err)
				return
			}
			accepted <- fresh
		}()
	}
	wait.Wait()
	close(accepted)

	count := 0
	for fresh := range accepted {
		if fresh {
			count++
		}
	}

	if count != 1 {
		t.Errorf("%d of %d concurrent callers were told the nonce was fresh, want exactly 1. "+
			"More than one means the check and the record are not atomic, so a replay "+
			"arriving concurrently would be accepted twice", count, racers)
	}
}

func TestARolledBackAppendDoesNotLeaveTheNonceRemembered(t *testing.T) {
	// If the map kept an entry the file never received, a restart would forget it
	// while this process believed it was recorded — so the honest answer to "can I
	// rule out replay?" would have been no, and the store would have said yes.
	//
	// The write is made to fail by pointing the store at a path whose parent is a
	// FILE, so MkdirAll cannot create the directory.
	directory := t.TempDir()
	blocker := filepath.Join(directory, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("setting up: %v", err)
	}

	store := OpenNonceStoreAt(filepath.Join(blocker, "nonces"),
		fixedClock(time.UnixMilli(1_770_000_000_000)))

	fresh, err := store.Remember("doomed", time.UnixMilli(1_770_000_060_000))
	if err == nil {
		t.Fatal("expected the append to fail")
	}
	if fresh {
		t.Error("Remember reported success for a nonce it could not persist")
	}

	size, err := store.Size()
	if err != nil {
		// Size fails for the same reason the append did, which is consistent.
		return
	}
	if size != 0 {
		t.Errorf("the store remembers %d entries after a failed write; a restart would "+
			"forget them while this process believed they were recorded", size)
	}
}

func TestACorruptLineIsSkippedRatherThanFatal(t *testing.T) {
	// The one place in this file where forgiving input is right. Refusing to start
	// because of one truncated line would take the host offline over a partial write,
	// and the cost of skipping is that one nonce is forgotten — bounded, and no worse
	// than the restart a fatal error would have caused anyway.
	path := filepath.Join(t.TempDir(), "nonces")
	expires := time.UnixMilli(1_770_000_060_000)

	content := "good-one 1770000060000\n" +
		"this-line-has-no-timestamp\n" +
		"another-bad not-a-number\n" +
		" 1770000060000\n" + // empty nonce
		"good-two 1770000060000\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("setting up: %v", err)
	}

	store := OpenNonceStoreAt(path, fixedClock(time.UnixMilli(1_770_000_000_000)))

	size, err := store.Size()
	if err != nil {
		t.Fatalf("a corrupt file made the store unusable: %v", err)
	}
	if size != 2 {
		t.Errorf("loaded %d entries, want the 2 well-formed ones", size)
	}

	// The good entries are honoured, which is what makes skipping acceptable rather
	// than merely survivable.
	for _, nonce := range []string{"good-one", "good-two"} {
		if fresh, err := store.Remember(nonce, expires); err != nil || fresh {
			t.Errorf("%q was not remembered from the file (fresh=%v, err=%v)", nonce, fresh, err)
		}
	}
}

func TestANonceContainingWhitespaceIsRefused(t *testing.T) {
	// The file format is one record per line, so a nonce containing a newline could
	// forge a record boundary and write an entry for a nonce that was never used —
	// or, with a crafted timestamp, one that is already expired.
	//
	// Envelope nonces are hex and cannot contain whitespace, but this function must
	// not depend on its caller having checked. That assumption is the shape of the
	// vulnerability class this whole design exists to avoid.
	store := OpenNonceStoreAt(filepath.Join(t.TempDir(), "nonces"),
		fixedClock(time.UnixMilli(1_770_000_000_000)))
	expires := time.UnixMilli(1_770_000_060_000)

	for _, nonce := range []string{
		"has space",
		"has\tnewline-ish",
		"forged\n0000000000000000 1770000060000",
		"",
	} {
		if _, err := store.Remember(nonce, expires); !errors.Is(err, ErrMalformed) {
			t.Errorf("nonce %q: got %v, want ErrMalformed", nonce, err)
		}
	}
}

func TestTheStoreFileIsNotWorldReadable(t *testing.T) {
	// The store reveals which instructions this host executed and when. Not secret
	// exactly, but nobody else's business on a shared machine — and on a host running
	// several sites, "nobody else" includes the site users.
	path := filepath.Join(t.TempDir(), "sub", "nonces")
	store := OpenNonceStoreAt(path, fixedClock(time.UnixMilli(1_770_000_000_000)))

	if _, err := store.Remember("x", time.UnixMilli(1_770_000_060_000)); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the nonce store is mode %04o, want 0600", mode)
	}

	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if mode := directory.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the store's directory is mode %04o, which grants access outside the owner", mode)
	}
}

func TestPruningRewritesTheFileDurably(t *testing.T) {
	// Pruning happens every pruneEvery appends and rewrites the file. Write-to-temp
	// then rename, so a crash mid-write leaves the previous complete file rather than
	// a truncated one — a truncated store forgets live nonces, which is the failure
	// this whole file exists to prevent, so the durability of the pruning path matters
	// as much as the durability of the append path.
	start := time.UnixMilli(1_770_000_000_000)
	clock := start
	directory := t.TempDir()
	path := filepath.Join(directory, "nonces")
	store := OpenNonceStoreAt(path, func() time.Time { return clock })

	// Enough appends to trigger at least one prune, all expiring quickly.
	for index := 0; index < pruneEvery+10; index++ {
		if _, err := store.Remember(fmt.Sprintf("n-%d", index), start.Add(time.Second)); err != nil {
			t.Fatalf("Remember %d: %v", index, err)
		}
	}

	// Everything expired, then one more append to trigger the prune with the new
	// clock.
	clock = start.Add(time.Hour)
	if _, err := store.Remember("after", clock.Add(time.Minute)); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	// No temporary files left behind. A rename that failed silently would leave one,
	// and a directory slowly filling with .nonces-* is the disk-exhaustion bug the
	// bound was supposed to prevent, arriving by another route.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".nonces-") {
			t.Errorf("a temporary file survived pruning: %s", entry.Name())
		}
	}

	// And the file on disk agrees with a fresh reader — the rewrite must not have
	// dropped anything still live.
	reopened := OpenNonceStoreAt(path, func() time.Time { return clock })
	if fresh, err := reopened.Remember("after", clock.Add(time.Minute)); err != nil || fresh {
		t.Errorf("a live nonce did not survive the prune-and-rewrite (fresh=%v, err=%v)", fresh, err)
	}
}

func TestTheProductionBoundIsWhatItClaims(t *testing.T) {
	// The two tests above exercise the bounding MECHANISM at a small size. This one
	// pins the value a real agent uses, so shrinking it to something that refuses
	// honest traffic — or raising it to something that is no longer a bound — is a
	// visible change rather than a silent one.
	//
	// The reasoning behind the number: one instruction per second per host, sustained
	// for one MaxValidity window, is 300 entries. Anything at least an order of
	// magnitude above that is only reachable by something abnormal.
	perSecond := int(MaxValidity / time.Second)
	if MaxRememberedNonces < perSecond*10 {
		t.Errorf("MaxRememberedNonces is %d, which is less than ten times the %d entries one "+
			"instruction per second would produce in a %s window. Honest traffic would hit "+
			"the bound", MaxRememberedNonces, perSecond, MaxValidity)
	}
	if MaxRememberedNonces > 1_000_000 {
		t.Errorf("MaxRememberedNonces is %d, which is large enough that the file is the "+
			"disk-exhaustion problem the bound exists to prevent", MaxRememberedNonces)
	}

	// A default store uses it, so the constant is not merely declared.
	store := OpenNonceStore(filepath.Join(t.TempDir(), "nonces"))
	if store.limit != MaxRememberedNonces {
		t.Errorf("a default store is bounded at %d, not MaxRememberedNonces (%d)",
			store.limit, MaxRememberedNonces)
	}

	// And a nonsense limit cannot switch bounding off. "0 means unlimited" is how an
	// unbounded store gets configured in by accident.
	for _, bad := range []int{0, -1} {
		relaxed := OpenNonceStore(filepath.Join(t.TempDir(), "n")).WithLimit(bad)
		if relaxed.limit != MaxRememberedNonces {
			t.Errorf("WithLimit(%d) set the bound to %d; it must be ignored", bad, relaxed.limit)
		}
	}
}
