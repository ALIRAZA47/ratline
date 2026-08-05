// Package privsock is the trust boundary between the agent and the root helper
// (RL-M2-030, ADR 0004).
//
// # What this package is for
//
// ADR 0004 puts every privileged operation behind `ratline-privd`, which runs as root and
// "identifies its caller by SO_PEERCRED rather than trusting the socket's mode alone."
// The words "rather than" carry the whole design. A file mode is a property of a
// filesystem entry: it says who may open this path today, and it is only as trustworthy as
// every directory above it and every process that can create a path. A peer credential is
// a property of the CONNECTION, supplied by the kernel, about the process on the other end.
// Only the second survives an attacker who can put a file somewhere.
//
// So the mode is still set — defence in depth, and it stops an accident before it becomes a
// refusal — but the mode is not the check.
//
// # What privd may conclude from a peer credential, and what it may not
//
// It may conclude that the caller is running as the agent's user. That is all. It may NOT
// conclude that the caller is the agent, that the agent is uncompromised, or that the
// request is legitimate — an attacker who owns the agent account passes this check by
// definition, which is the assumption ADR 0004 starts from: "on the assumption that the
// agent is already compromised." This layer decides WHO may speak. RL-M2-031 decides what
// may be said and RL-M2-032 decides whether it is true about this host, and neither is
// optional because of anything here.
//
// # Nothing in this package listens on a port
//
// A unix-domain socket in the filesystem, with no network family anywhere. privd has no
// network access at all (PLAN.md's trust boundary B4), and agent/internal/listencheck
// enforces the difference: net.Listen("unix", …) is permitted by the literal in the
// source, net.Listen("tcp", …) is refused outright.
package privsock

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
)

var (
	// ErrForbiddenPeer means the caller is not the account privd will speak to.
	ErrForbiddenPeer = errors.New("the caller is not the agent account")
	// ErrPeerUnknown means the kernel would not say who the caller is. Always a refusal.
	ErrPeerUnknown = errors.New("the caller's credentials could not be read")
	// ErrUnsafeSocketPath means the path privd was asked to listen on cannot be trusted.
	ErrUnsafeSocketPath = errors.New("the socket path is not safe to use")
	// ErrNotConfigured means Listen was called without enough to be safe.
	ErrNotConfigured = errors.New("the privileged socket is not configured")
)

// Peer is who the kernel says is on the other end.
type Peer struct {
	UID int
	GID int
	PID int
}

func (peer Peer) String() string {
	return fmt.Sprintf("uid %d, gid %d, pid %d", peer.UID, peer.GID, peer.PID)
}

// socketMode is what the socket ends up as: readable and writable by owner and group,
// nothing for anybody else. root owns it, the agent's group reaches it.
const socketMode fs.FileMode = 0o660

// directoryMode is what the socket's directory ends up as. The execute bit is what lets the
// agent traverse into it; there is no read bit for group, because listing the directory is
// not something the agent needs and a socket path is not a secret worth protecting anyway.
const directoryMode fs.FileMode = 0o710

// maxPathLength is the longest socket path this will attempt.
//
// A unix socket address is a fixed-size struct: sun_path is 108 bytes on Linux and 104 on
// macOS, including the terminator. Exceeding it produces EINVAL, which the standard library
// reports as "bind: invalid argument" — one of the least informative errors in Unix, and one
// that sends whoever reads it looking at permissions and SELinux rather than at the length of
// a string. 100 is under both limits with room for the socket's own name.
//
// The production path is /run/ratline/privd.sock, so this only ever fires for something
// unusual — a container with a deep bind mount, or a test — and firing with an explanation is
// the whole point.
const maxPathLength = 100

// Config is what Listen needs.
type Config struct {
	// Path is where the socket goes. Its directory must already exist and must not be
	// writable by anybody but its owner.
	Path string
	// AllowedUID is the only uid privd will accept a connection from: the unprivileged
	// account the agent runs as. There is deliberately no "any uid" value — see Listen.
	AllowedUID int
}

// Listener is a privileged socket that refuses callers it cannot identify.
type Listener struct {
	unix       *net.UnixListener
	path       string
	allowedUID int
}

// Listen creates the socket.
//
// # The order of operations is the security of it
//
// A socket created by net.Listen gets 0777 masked by the process umask, so between the bind
// and a later chmod there is a window in which anybody on the host can connect. Setting the
// umask around the bind would close it and is worse: umask is process-global, so a
// goroutine doing anything else with files gets it too, and "temporarily change a global to
// make one call safe" is a race waiting for a second caller.
//
// So the window is closed with the directory instead. The directory is narrowed to
// owner-only BEFORE the bind, the socket is created inside it and chmod'ed, and only then is
// the directory opened to the agent's group. During the window the socket's own mode is
// permissive and nothing can reach it, because reaching it requires traversing a directory
// that only root may enter.
func Listen(config Config) (*Listener, error) {
	if config.Path == "" {
		return nil, fmt.Errorf("%w: no socket path", ErrNotConfigured)
	}
	// No zero default, and no sentinel meaning "anybody". uid 0 is a legitimate value on a
	// host where somebody has decided the agent runs as root, and it must be typed out
	// rather than arrived at by leaving a field unset — a struct literal that forgot this
	// field would otherwise configure the most permissive policy available.
	if config.AllowedUID < 0 {
		return nil, fmt.Errorf("%w: AllowedUID is %d", ErrNotConfigured, config.AllowedUID)
	}
	if len(config.Path) > maxPathLength {
		return nil, fmt.Errorf(
			"%w: %s is %d characters, and a unix socket address holds about %d. The kernel would "+
				"answer EINVAL, which arrives as \"bind: invalid argument\" and reads like a "+
				"permission problem",
			ErrUnsafeSocketPath, config.Path, len(config.Path), maxPathLength)
	}

	directory := filepath.Dir(config.Path)
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrUnsafeSocketPath, directory, err)
	}
	if !info.IsDir() {
		// Lstat, so a symlink pointing at a directory fails here rather than being followed.
		// privd runs as root and a symlinked socket directory is somebody else choosing where
		// root writes.
		return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafeSocketPath, directory)
	}
	if mode := info.Mode().Perm(); mode&0o002 != 0 {
		// World-writable. An attacker who can write the directory can unlink the socket and
		// bind their own in its place, and then the AGENT is talking to them — which does not
		// get them root, but does let them answer "yes, the unit is installed" to a control
		// plane that believes it.
		return nil, fmt.Errorf(
			"%w: %s is mode %04o and world-writable, so anybody could replace the socket in it",
			ErrUnsafeSocketPath, directory, mode)
	}

	if err := removeStaleSocket(config.Path); err != nil {
		return nil, err
	}

	// Narrow first. See the doc comment: this is what closes the window, not a chmod race.
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("%w: narrowing %s before binding: %w", ErrUnsafeSocketPath, directory, err)
	}

	unix, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.Path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("binding %s: %w", config.Path, err)
	}

	if err := os.Chmod(config.Path, socketMode); err != nil {
		_ = unix.Close()
		return nil, fmt.Errorf("setting the mode on %s: %w", config.Path, err)
	}
	if err := os.Chmod(directory, directoryMode); err != nil {
		_ = unix.Close()
		return nil, fmt.Errorf("opening %s to the agent's group: %w", directory, err)
	}

	return &Listener{unix: unix, path: config.Path, allowedUID: config.AllowedUID}, nil
}

// removeStaleSocket clears a socket left behind by a previous run, and refuses anything else.
//
// A plain os.Remove here would be a root process deleting whatever is at a path. If that
// path were a symlink to /etc/shadow, or to a database file, privd would remove it on
// startup — a destructive primitive reachable by anybody who can create the path, which on a
// host where the directory check above passed is only root, but "only root" is exactly the
// assumption a privilege-separated design refuses to make about its own inputs.
//
// So: Lstat, and remove only if it is a socket. A regular file, a directory, or a symlink to
// any of those is a refusal that says what it found.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w: %s: %w", ErrUnsafeSocketPath, path, err)
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf(
			"%w: %s already exists and is %s rather than a socket. privd will not unlink it — "+
				"a root process that deletes whatever it finds at a path is a destructive "+
				"primitive for anybody who can create that path",
			ErrUnsafeSocketPath, path, describe(info.Mode()))
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("%w: removing the stale socket %s: %w", ErrUnsafeSocketPath, path, err)
	}
	return nil
}

func describe(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeSymlink != 0:
		return "a symbolic link"
	case mode.IsDir():
		return "a directory"
	case mode.IsRegular():
		return "a regular file"
	default:
		return fmt.Sprintf("mode %s", mode)
	}
}

// Path is where the socket is.
func (listener *Listener) Path() string { return listener.path }

// Close stops listening and removes the socket.
func (listener *Listener) Close() error { return listener.unix.Close() }

// Accept returns the next permitted connection, and the peer it belongs to.
//
// A connection from anybody else is CLOSED HERE and reported as an error. Returning it with
// an error beside it would work until one caller wrote `conn, _, err := Accept()` and used
// the connection anyway — and the one caller is a root process. So a refused connection is
// never handed out at all, and the Peer is still returned so the refusal can be recorded
// (C6: every privileged action attributable, which includes the ones that did not happen).
func (listener *Listener) Accept() (net.Conn, Peer, error) {
	connection, err := listener.unix.AcceptUnix()
	if err != nil {
		return nil, Peer{}, err
	}

	peer, credErr := peerOf(connection)
	if err := listener.permit(peer, credErr); err != nil {
		_ = connection.Close()
		return nil, peer, err
	}
	return connection, peer, nil
}

// permit is the policy, separated from the syscall that feeds it.
//
// Split out because reading a peer credential is a Linux facility and the policy is not: on
// a development machine peerOf cannot run, and without this split the decision itself would
// be untested everywhere except in a container. Now the decision is exercised by every
// `go test` on any platform, and only the syscall needs a real host.
func (listener *Listener) permit(peer Peer, credErr error) error {
	if credErr != nil {
		// UNKNOWN IS REFUSED. This is the case a build for a platform without SO_PEERCRED
		// falls into, and the case a kernel that declined to answer falls into, and they must
		// both refuse — a root helper that accepts a caller it cannot identify has no trust
		// boundary, only a socket. The same lesson listencheck records about reporting
		// "nothing found" where a check could not run, with more at stake.
		return fmt.Errorf("%w: %w", ErrPeerUnknown, credErr)
	}
	if peer.UID != listener.allowedUID {
		return fmt.Errorf(
			"%w: %s connected, and privd speaks only to uid %d. The socket's mode is not the "+
				"check — this is",
			ErrForbiddenPeer, peer, listener.allowedUID)
	}
	return nil
}
