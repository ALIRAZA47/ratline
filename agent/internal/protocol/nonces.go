// The replay store (RL-M2-003).
//
// ADR 0002: "Nonces persist across agent restarts for at least the validity
// window, in a bounded store. Replay after restart is tested explicitly."
//
// Both halves of that sentence are load-bearing and they pull against each other.
// PERSISTENT, because an in-memory set makes replay protection a function of the
// agent's uptime: restart it — or crash it, which an attacker may be able to
// arrange — and every instruction signed in the last five minutes becomes
// replayable. BOUNDED, because a file that only grows is a disk-exhaustion bug on
// somebody else's host, and the agent is the process least entitled to fill it.
//
// The reconciliation is that a nonce only has to be remembered until its envelope
// expires. So the store's size is a function of the instruction rate within one
// validity window rather than of uptime, and pruning is not a cleanup task bolted
// on afterwards — it is what makes the bound true.
package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxRememberedNonces bounds the store.
//
// Sized against the rate an honest control plane could reach: one instruction per
// second per host, sustained for one MaxValidity window, is 300. Ten thousand is
// well past that and still small on disk — roughly 800 KB — so the ceiling is only
// reachable by something abnormal.
//
// Reaching it REFUSES rather than evicting. Evicting the oldest entry would make
// the store forget a nonce that is still live, which is precisely the replay the
// store exists to prevent: an attacker who can flood would then choose which nonce
// gets forgotten. Refusing is a denial of service; evicting is a security failure
// dressed as availability.
const MaxRememberedNonces = 10_000

// FileNonceStore is a persistent, bounded nonce store.
//
// One file, appended to, rewritten when pruning. Not a database: the agent has no
// dependencies (RL-M2-001), and a durable append-only log of short-lived tokens is
// one of the few things a plain file is genuinely the right answer for.
type FileNonceStore struct {
	path string
	// now is injectable, and that is not a testing convenience.
	//
	// Pruning decides which nonces are still live, so the store HAS a clock whether
	// or not it admits to one. Calling time.Now() inside meant the store's notion of
	// time and Verify's injected `now` could disagree, and the disagreement was
	// invisible: the restart test failed because the store pruned against wall-clock
	// time while the envelope carried fixed stamps, which looked exactly like the
	// nonce failing to persist. A hidden clock in a security check is a hidden
	// assumption about when that check applies.
	now func() time.Time

	mutex sync.Mutex
	// seen maps nonce to its expiry. Loaded once, then maintained in memory and
	// mirrored to the file, so the common path is a map lookup and one append
	// rather than a file scan.
	seen map[string]time.Time
	// appends since the last prune, so pruning is amortised instead of happening on
	// every write.
	appends int
	loaded  bool
}

// pruneEvery is how many appends pass between prunes. Small enough that the file
// tracks the map closely, large enough that a rewrite is not on the hot path.
const pruneEvery = 256

// ErrStoreFull is returned when the bound is reached and nothing is expired.
var ErrStoreFull = errors.New("nonce store is full and no entry has expired")

// OpenNonceStore prepares a store at path. The file is created on first write.
func OpenNonceStore(path string) *FileNonceStore {
	return OpenNonceStoreAt(path, time.Now)
}

// OpenNonceStoreAt is OpenNonceStore with an explicit clock, for tests that need
// controlled time and for any caller that already has one.
func OpenNonceStoreAt(path string, now func() time.Time) *FileNonceStore {
	return &FileNonceStore{path: path, seen: make(map[string]time.Time), now: now}
}

// Remember records a nonce, returning false if it was already present.
//
// Check and record in ONE call, holding one lock. A `Seen` then `Record` pair has a
// window between them, and two envelopes carrying the same nonce arriving
// concurrently would both pass the check before either recorded — a replay that the
// store would then report as having prevented.
func (store *FileNonceStore) Remember(nonce string, expiresAt time.Time) (bool, error) {
	if nonce == "" {
		return false, fmt.Errorf("%w: empty nonce", ErrMalformed)
	}
	if strings.ContainsAny(nonce, " \t\n\r") {
		// The file format is one record per line, so a nonce containing whitespace
		// could forge a record boundary. Envelope nonces are hex and cannot, but
		// this function must not depend on its caller having checked — that is what
		// made the original vulnerability class in this codebase's ancestry.
		return false, fmt.Errorf("%w: nonce contains whitespace", ErrMalformed)
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()

	if err := store.load(); err != nil {
		return false, err
	}

	if _, present := store.seen[nonce]; present {
		// Present is present, expired or not. An expired entry that has not yet
		// been pruned still means "this nonce was used", and treating it as fresh
		// would open a window exactly as wide as the gap between expiry and pruning.
		return false, nil
	}

	if len(store.seen) >= MaxRememberedNonces {
		store.prune(store.now())
		if len(store.seen) >= MaxRememberedNonces {
			return false, fmt.Errorf(
				"%w: %d entries. Either instructions are arriving far faster than one per "+
					"second, or something is flooding this agent. Refusing rather than "+
					"forgetting a live nonce",
				ErrStoreFull, len(store.seen),
			)
		}
	}

	store.seen[nonce] = expiresAt

	if err := store.append(nonce, expiresAt); err != nil {
		// Rolled back, so the map cannot claim to have remembered something the
		// file did not. Otherwise a restart would forget it while this process
		// believed it was recorded — and the honest answer to "can I rule out
		// replay?" would have been no.
		delete(store.seen, nonce)
		return false, err
	}

	store.appends++
	if store.appends >= pruneEvery {
		store.prune(store.now())
		if err := store.rewrite(); err != nil {
			// Pruning failed, and the nonce IS recorded. Not an error for this
			// caller: the store is oversized, not wrong, and refusing a properly
			// verified instruction because a cleanup failed would trade a real
			// operation for a disk-space concern.
			return true, nil
		}
		store.appends = 0
	}

	return true, nil
}

// load reads the file once. A missing file is an empty store, not an error: the
// first instruction a freshly enrolled agent receives is the normal case.
func (store *FileNonceStore) load() error {
	if store.loaded {
		return nil
	}

	file, err := os.Open(store.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			store.loaded = true
			return nil
		}
		return fmt.Errorf("opening the nonce store: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Records are short. A long line means the file is not what this code wrote, so
	// a small limit turns corruption into an error rather than a large allocation.
	scanner.Buffer(make([]byte, 0, 4096), 4096)

	line := 0
	for scanner.Scan() {
		line++
		nonce, expires, ok := parseRecord(scanner.Text())
		if !ok {
			// A corrupt line is SKIPPED, not fatal, and this is the one place in the
			// file where forgiving input is right: refusing to start because of one
			// bad line would take the host offline over a truncated write, and the
			// cost of skipping is that one nonce is forgotten — bounded, and no worse
			// than the restart that a fatal error would cause anyway.
			continue
		}
		store.seen[nonce] = expires
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading the nonce store at line %d: %w", line, err)
	}

	// Anything already dead is dropped at load, so a long shutdown does not come
	// back as a full store.
	store.prune(store.now())
	store.loaded = true
	return nil
}

func parseRecord(text string) (string, time.Time, bool) {
	nonce, stamp, found := strings.Cut(text, " ")
	if !found || nonce == "" {
		return "", time.Time{}, false
	}
	millis, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return nonce, time.UnixMilli(millis), true
}

func (store *FileNonceStore) append(nonce string, expiresAt time.Time) error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return fmt.Errorf("creating the nonce store directory: %w", err)
	}

	// 0600: the nonce store reveals which instructions this host has executed and
	// when, which is not secret exactly, but is nobody else's business on a shared
	// machine.
	file, err := os.OpenFile(store.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening the nonce store for append: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "%s %d\n", nonce, expiresAt.UnixMilli()); err != nil {
		return fmt.Errorf("appending to the nonce store: %w", err)
	}

	// Synced before returning. Without this, "recorded" means "in the page cache",
	// and a power loss would forget nonces the agent had already acted on — which
	// is the exact window ADR 0002's persistence requirement exists to close.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("syncing the nonce store: %w", err)
	}
	return nil
}

// prune drops expired entries from the map. Caller holds the lock.
func (store *FileNonceStore) prune(now time.Time) {
	for nonce, expires := range store.seen {
		if expires.Compare(now) <= 0 {
			delete(store.seen, nonce)
		}
	}
}

// rewrite replaces the file with the current map. Caller holds the lock.
//
// Write-to-temp then rename, so a crash mid-write leaves the previous complete file
// rather than a truncated one. A truncated store forgets live nonces, which is the
// failure this whole file exists to prevent — so the durability of the pruning path
// matters as much as the durability of the append path.
func (store *FileNonceStore) rewrite() error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(store.path), ".nonces-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	// Best-effort removal if anything below fails; a successful rename makes this a
	// no-op.
	defer func() { _ = os.Remove(name) }()

	writer := bufio.NewWriter(temporary)
	for nonce, expires := range store.seen {
		if _, err := fmt.Fprintf(writer, "%s %d\n", nonce, expires.UnixMilli()); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(name, store.path)
}

// Size reports how many nonces are remembered, for tests and for host health.
func (store *FileNonceStore) Size() (int, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := store.load(); err != nil {
		return 0, err
	}
	return len(store.seen), nil
}
