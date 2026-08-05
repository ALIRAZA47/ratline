// Everywhere that is not Linux: the caller cannot be identified, so nobody is accepted
// (RL-M2-030 acceptance 3).
//
// # Why there is no darwin implementation, when there could be
//
// macOS has LOCAL_PEERCRED and getpeereid, and BSD has the same. Implementing them would be
// half an hour's work and would be the wrong thing to ship, for one reason: the agent and
// privd are built for Linux only — scripts/agent build sets GOOS=linux for both
// architectures and nothing else — so a darwin credential path would be code that runs on
// nobody's host, exercised only by the tests written to justify it. A security-critical
// syscall that production never executes is a liability with a green checkmark next to it.
//
// # What this file being a refusal buys
//
// Acceptance 3 — "a caller whose credentials cannot be read is refused rather than allowed"
// — becomes a property every developer exercises on every test run, rather than a branch
// nobody reaches. The failure mode it prevents is the one that matters most in a root
// helper: an unidentifiable caller treated as authorised because the check quietly returned
// nothing to object to.
//
// If somebody later ports privd to a BSD, the compiler names this file. That is the intended
// way to discover the decision.

//go:build !linux

package privsock

import (
	"fmt"
	"net"
	"runtime"
)

func peerOf(_ *net.UnixConn) (Peer, error) {
	return Peer{}, fmt.Errorf(
		"%s has no SO_PEERCRED implementation in this build, so privd cannot tell who is "+
			"calling and refuses everybody. The helper ships for Linux only", runtime.GOOS)
}
