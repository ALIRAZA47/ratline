// Reading the caller's identity from the kernel (RL-M2-030, ADR 0004).
//
// SO_PEERCRED gives the uid, gid and pid the kernel recorded for the process at the other
// end of a unix socket AT CONNECT TIME. It cannot be forged by the caller, it does not
// depend on anything the caller sends, and it is not affected by what the caller does after
// connecting — a process that connects and then execs something else is still recorded as
// what connected.
//
// The pid is returned for the audit trail and is deliberately NOT used in the decision. A
// pid is reusable: by the time privd looked one up in /proc, the process could have exited
// and the number been handed to something else, which is a textbook time-of-check to
// time-of-use hole. The uid is what the decision turns on, because the uid cannot be
// recycled out from under the connection.

//go:build linux

package privsock

import (
	"fmt"
	"net"
	"syscall"
)

func peerOf(connection *net.UnixConn) (Peer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, fmt.Errorf("reaching the socket's descriptor: %w", err)
	}

	var credentials *syscall.Ucred
	var sockoptErr error
	// Control rather than File(): File() dups the descriptor and puts it in blocking mode,
	// which takes the connection out of the runtime's poller for the rest of its life. This
	// borrows the descriptor for the length of one syscall and gives it back.
	if err := raw.Control(func(fd uintptr) {
		credentials, sockoptErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, fmt.Errorf("borrowing the socket's descriptor: %w", err)
	}
	if sockoptErr != nil {
		return Peer{}, fmt.Errorf("SO_PEERCRED: %w", sockoptErr)
	}

	return Peer{
		UID: int(credentials.Uid),
		GID: int(credentials.Gid),
		PID: int(credentials.Pid),
	}, nil
}
