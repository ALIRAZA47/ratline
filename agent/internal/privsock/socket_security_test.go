// The trust boundary between the agent and the root helper (RL-M2-030, ADR 0004).
//
// # What runs where, stated because half of it cannot run on a development machine
//
// EVERYWHERE: the policy (who is permitted, and what happens when the caller cannot be
// identified), the socket path safety checks, the stale-socket handling, and the mode and
// ownership the socket and its directory end up with. These are real files and real sockets
// in a real temporary directory — nothing is mocked, the argument is a path.
//
// LINUX ONLY: reading the credential itself. SO_PEERCRED is a Linux facility, so the syscall
// path is proven by cross-compiling this suite and running it on the Debian 12 integration
// host. Without that it would be code nobody had executed, which is why the acceptance
// criterion about it is not checked off on the strength of this file alone.
//
// The split is deliberate rather than convenient: Listener.permit takes the credential and
// the error that produced it, so the DECISION is exercised by every `go test` on any
// platform and only the syscall needs a host.
package privsock

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- the policy, which runs everywhere -------------------------------------------------

// TestACallerWhoseCredentialsCannotBeReadIsRefused is acceptance 3, and it is the property
// most likely to be got wrong by omission rather than by mistake.
//
// A root helper that accepts a caller it could not identify has no trust boundary, only a
// socket. Every way of failing to identify one must land on refuse: an unsupported platform,
// a kernel that declined, a descriptor that could not be borrowed.
func TestACallerWhoseCredentialsCannotBeReadIsRefused(t *testing.T) {
	t.Parallel()

	listener := &Listener{allowedUID: 1000}

	for name, credErr := range map[string]error{
		"the platform has no SO_PEERCRED": errors.New("darwin has no SO_PEERCRED implementation"),
		"the kernel declined":             errors.New("SO_PEERCRED: operation not supported"),
		"the descriptor was unreachable":  errors.New("borrowing the socket's descriptor: closed"),
	} {
		// The peer is deliberately the ALLOWED uid. A policy that looked at the uid first and
		// the error second would pass a test where the two disagreed, and would then accept
		// an unidentified caller whose zero-valued Peer happened to match a configured uid of
		// zero — which is the default a struct literal produces.
		err := listener.permit(Peer{UID: 1000, GID: 1000, PID: 42}, credErr)
		if !errors.Is(err, ErrPeerUnknown) {
			t.Errorf("%s produced %v, want ErrPeerUnknown", name, err)
		}
	}

	// And the zero Peer with a zero allowed uid — the shape a forgotten field produces — must
	// still refuse when the credential could not be read.
	zero := &Listener{allowedUID: 0}
	if err := zero.permit(Peer{}, errors.New("no credentials")); !errors.Is(err, ErrPeerUnknown) {
		t.Errorf("an unidentified caller against a zero-valued policy produced %v", err)
	}
}

// TestOnlyTheAgentAccountIsPermitted is acceptance 2 at the decision layer.
func TestOnlyTheAgentAccountIsPermitted(t *testing.T) {
	t.Parallel()

	listener := &Listener{allowedUID: 1000}

	if err := listener.permit(Peer{UID: 1000, GID: 1000, PID: 7}, nil); err != nil {
		t.Fatalf("the agent's own uid was refused: %v", err)
	}

	// root included on purpose. privd runs as root, and "root may always talk to root" is a
	// tempting shortcut that would let any root-owned process on the host drive the helper —
	// which is not a privilege escalation, but is a second path into the operation set that
	// nothing audits as the agent.
	for _, uid := range []int{0, 1, 999, 1001, 65534} {
		err := listener.permit(Peer{UID: uid, GID: 1000, PID: 7}, nil)
		if !errors.Is(err, ErrForbiddenPeer) {
			t.Errorf("uid %d produced %v, want ErrForbiddenPeer", uid, err)
		}
	}
}

// TestTheRefusalNamesTheCallerSoItCanBeAudited is C6 applied to the actions that did NOT
// happen. An operator needs to know which account tried.
func TestTheRefusalNamesTheCallerSoItCanBeAudited(t *testing.T) {
	t.Parallel()

	listener := &Listener{allowedUID: 1000}
	err := listener.permit(Peer{UID: 33, GID: 44, PID: 5555}, nil)
	if err == nil {
		t.Fatal("a forbidden peer was permitted")
	}
	for _, fragment := range []string{"uid 33", "gid 44", "pid 5555", "uid 1000"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Errorf("the refusal does not mention %q, so an operator cannot tell who tried:\n  %v",
				fragment, err)
		}
	}
}

// --- the socket and its path, which also run everywhere ---------------------------------

// shortTempDir is t.TempDir() with a path a unix socket can actually hold.
//
// A unix socket address is a fixed-size struct — 108 bytes on Linux, 104 on macOS — and
// t.TempDir() on macOS produces something like
// /var/folders/pg/xdg8bnhd…/T/TestTheNameOfTheTest1985319192/001, which is already past it
// before the socket's own name is added. The first run of this suite failed four tests with
// "bind: invalid argument" for exactly that reason, which is why Listen now refuses an
// over-long path with an explanation rather than letting the kernel answer EINVAL.
//
// /tmp rather than os.TempDir(), because os.TempDir() IS the long one on macOS. The directory
// is real — the symlink on macOS is /tmp itself, above the parent this code Lstats — and it is
// removed afterwards.
func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "rl-ps")
	if err != nil {
		t.Fatalf("making a short temporary directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestTheSocketAndItsDirectoryEndUpWithTheRightModes(t *testing.T) {
	t.Parallel()

	directory := shortTempDir(t)
	path := filepath.Join(directory, "privd.sock")

	listener, err := Listen(Config{Path: path, AllowedUID: os.Getuid()})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	socket, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat-ing the socket: %v", err)
	}
	if socket.Mode()&fs.ModeSocket == 0 {
		t.Errorf("%s is %s rather than a socket", path, socket.Mode())
	}
	if mode := socket.Mode().Perm(); mode != socketMode {
		t.Errorf("the socket is mode %04o, want %04o. Anything with a world bit set is a "+
			"channel to the root helper for every account on the host", mode, socketMode)
	}

	info, err := os.Stat(directory)
	if err != nil {
		t.Fatalf("stat-ing the directory: %v", err)
	}
	if mode := info.Mode().Perm(); mode != directoryMode {
		t.Errorf("the directory is mode %04o, want %04o", mode, directoryMode)
	}
	// The narrowing is temporary and must be undone, or the agent cannot traverse in and
	// privd is a root helper nothing can reach — a failure that presents as "every operation
	// times out" rather than as a permission error.
	if info.Mode().Perm()&0o010 == 0 {
		t.Error("the directory has no group execute bit, so the agent's group cannot traverse " +
			"into it and the socket is unreachable")
	}
}

// TestAStaleSocketIsReplacedAndNothingElseIsDeleted is the root-process hazard in this file.
//
// os.Remove before a bind is the obvious way to handle a socket left by a previous run, and
// as written by a process running as root it is a primitive that deletes whatever is at a
// path. The refusal is what keeps it from being one.
func TestAStaleSocketIsReplacedAndNothingElseIsDeleted(t *testing.T) {
	t.Parallel()

	// A genuine stale socket is replaced, or privd could not restart.
	{
		directory := shortTempDir(t)
		path := filepath.Join(directory, "privd.sock")
		first, err := Listen(Config{Path: path, AllowedUID: os.Getuid()})
		if err != nil {
			t.Fatalf("the first Listen: %v", err)
		}
		// Closed WITHOUT removing the file, which is what a killed process leaves behind.
		// net.UnixListener unlinks on Close, so the file is put back by hand to reproduce it.
		_ = first.Close()
		if err := os.WriteFile(path, nil, 0o660); err == nil {
			// A regular file at the path is a different case, tested below. What is needed here
			// is a real socket, so bind and abandon one instead.
			_ = os.Remove(path)
		}
		abandoned, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatalf("abandoning a socket at the path: %v", err)
		}
		abandoned.SetUnlinkOnClose(false)
		_ = abandoned.Close()

		second, err := Listen(Config{Path: path, AllowedUID: os.Getuid()})
		if err != nil {
			t.Fatalf("Listen did not replace a stale socket, so privd could not restart: %v", err)
		}
		_ = second.Close()
	}

	// Anything that is not a socket is refused, and — the point — still there afterwards.
	directory := shortTempDir(t)
	precious := filepath.Join(directory, "precious")
	if err := os.WriteFile(precious, []byte("not a socket\n"), 0o600); err != nil {
		t.Fatalf("writing the file: %v", err)
	}

	cases := map[string]string{
		"a regular file":  precious,
		"a directory":     mustMkdir(t, filepath.Join(directory, "adir")),
		"a symbolic link": mustSymlink(t, precious, filepath.Join(directory, "alink")),
	}
	for name, path := range cases {
		_, err := Listen(Config{Path: path, AllowedUID: os.Getuid()})
		if !errors.Is(err, ErrUnsafeSocketPath) {
			t.Errorf("%s at the socket path produced %v, want ErrUnsafeSocketPath", name, err)
		}
	}

	if _, err := os.Stat(precious); err != nil {
		t.Errorf("the file at the socket path was DELETED: %v.\n\nprivd runs as root, so a "+
			"blind unlink here is a destructive primitive for anybody who can create that path — "+
			"point it at /etc/shadow and privd removes it on startup.", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "alink")); err != nil {
		t.Errorf("the symbolic link at the socket path was deleted: %v", err)
	}
}

func mustMkdir(t *testing.T, path string) string {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	return path
}

func mustSymlink(t *testing.T, target, path string) string {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s: %v", path, err)
	}
	return path
}

// TestAWorldWritableDirectoryIsRefused stops the socket from being replaceable.
//
// An attacker who can write the directory can unlink privd's socket and bind their own. That
// does not get them root — privd is still privd — but it puts them where the AGENT thinks
// privd is, so they can answer "yes, the unit is installed" to a control plane that believes
// it, which is a lie about a host's state rather than an escalation.
func TestAWorldWritableDirectoryIsRefused(t *testing.T) {
	t.Parallel()

	directory := shortTempDir(t)
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, err := Listen(Config{Path: filepath.Join(directory, "privd.sock"), AllowedUID: os.Getuid()})
	if !errors.Is(err, ErrUnsafeSocketPath) {
		t.Errorf("a world-writable socket directory produced %v, want ErrUnsafeSocketPath", err)
	}
}

func TestASymlinkedDirectoryIsNotFollowed(t *testing.T) {
	t.Parallel()

	real := shortTempDir(t)
	elsewhere := filepath.Join(shortTempDir(t), "pointer")
	if err := os.Symlink(real, elsewhere); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// Lstat on the directory is what makes this fail. privd runs as root, and a symlinked
	// socket directory is somebody else choosing where root writes.
	_, err := Listen(Config{Path: filepath.Join(elsewhere, "privd.sock"), AllowedUID: os.Getuid()})
	if !errors.Is(err, ErrUnsafeSocketPath) {
		t.Errorf("a symlinked socket directory produced %v, want ErrUnsafeSocketPath", err)
	}
}

func TestListenRefusesAnIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	for name, config := range map[string]Config{
		"no path":       {AllowedUID: 1000},
		"negative uid":  {Path: filepath.Join(shortTempDir(t), "s.sock"), AllowedUID: -1},
		"absent parent": {Path: filepath.Join(shortTempDir(t), "nope", "s.sock"), AllowedUID: 1000},
		// Refused with an explanation rather than passed to the kernel, which would answer
		// EINVAL and have it surface as "bind: invalid argument".
		"a path longer than a unix address": {
			Path:       filepath.Join(shortTempDir(t), strings.Repeat("d", 120), "s.sock"),
			AllowedUID: 1000,
		},
	} {
		if _, err := Listen(config); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// --- the syscall, which only runs on Linux ----------------------------------------------

// TestTheKernelIdentifiesARealCaller is the half that needs a real host.
//
// On Linux it connects to a real socket and asserts the kernel reported this process's own
// uid, gid and pid — so the credential is read, not assumed. Everywhere else it asserts the
// OPPOSITE property: that peerOf refuses, which is what makes acceptance 3 true for a build
// on a platform that cannot identify its callers.
//
// Both branches are assertions. Neither is a skip, because a skipped security test is a test
// that reports nothing while looking like it reported something.
func TestTheKernelIdentifiesARealCaller(t *testing.T) {
	t.Parallel()

	directory := shortTempDir(t)
	path := filepath.Join(directory, "privd.sock")
	listener, err := Listen(Config{Path: path, AllowedUID: os.Getuid()})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan struct {
		peer Peer
		err  error
	}, 1)
	go func() {
		connection, peer, err := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- struct {
			peer Peer
			err  error
		}{peer, err}
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialling the socket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	result := <-accepted

	if runtime.GOOS != "linux" {
		if !errors.Is(result.err, ErrPeerUnknown) {
			t.Fatalf("on %s the caller cannot be identified, so Accept must refuse; it returned %v",
				runtime.GOOS, result.err)
		}
		return
	}

	if result.err != nil {
		t.Fatalf("Accept refused this process's own connection: %v", result.err)
	}
	if result.peer.UID != os.Getuid() {
		t.Errorf("the kernel reported uid %d, and this process is uid %d",
			result.peer.UID, os.Getuid())
	}
	if result.peer.GID != os.Getgid() {
		t.Errorf("the kernel reported gid %d, and this process is gid %d",
			result.peer.GID, os.Getgid())
	}
	if result.peer.PID != os.Getpid() {
		t.Errorf("the kernel reported pid %d, and this process is pid %d.\n\nThe pid is for the "+
			"audit trail and never for the decision — a pid is reusable, so looking one up in "+
			"/proc after the fact is time-of-check to time-of-use.",
			result.peer.PID, os.Getpid())
	}
}

// TestACallerFromTheWrongAccountIsRefusedAndNeverHandedOut is acceptance 2 over a real
// socket, and the API shape that keeps a mistake from mattering.
//
// The listener permits a uid this process is not, and then this process connects. On Linux
// that is a genuine end-to-end refusal: a real connection, a credential the kernel supplied,
// a real uid it did not match. Two long-lived processes under two accounts would be a
// broader test and needs privd running as a service, which is RL-M2-031 onward — what is
// proven here is that the decision is made on what the kernel said rather than on anything
// the caller sent.
//
// The second half is the API. Accept closes a refused connection itself and returns nil for
// it, because returning it alongside the error works right up until one caller writes
// `conn, _, err := Accept()` and uses it anyway — and the one caller is a root process.
func TestACallerFromTheWrongAccountIsRefusedAndNeverHandedOut(t *testing.T) {
	t.Parallel()

	directory := shortTempDir(t)
	path := filepath.Join(directory, "privd.sock")
	permitted := os.Getuid() + 12345
	listener, err := Listen(Config{Path: path, AllowedUID: permitted})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	type outcome struct {
		connection net.Conn
		peer       Peer
		err        error
	}
	accepted := make(chan outcome, 1)
	go func() {
		connection, peer, err := listener.Accept()
		accepted <- outcome{connection, peer, err}
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dialling: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	result := <-accepted

	if result.connection != nil {
		t.Error("Accept handed out a connection it refused")
	}
	if result.err == nil {
		t.Fatal("Accept returned no error for a caller from the wrong account")
	}

	if runtime.GOOS != "linux" {
		// No credential to read, so the refusal must be the unknown-caller one. Asserting
		// WHICH refusal matters: a build that refused everybody for the wrong reason would
		// look identical here.
		if !errors.Is(result.err, ErrPeerUnknown) {
			t.Errorf("on %s the refusal was %v, want ErrPeerUnknown", runtime.GOOS, result.err)
		}
		return
	}

	if !errors.Is(result.err, ErrForbiddenPeer) {
		t.Errorf("the refusal was %v, want ErrForbiddenPeer. On Linux the credential IS "+
			"readable, so refusing as unidentifiable would mean the syscall path is broken and "+
			"the boundary is holding for the wrong reason", result.err)
	}
	if result.peer.UID != os.Getuid() {
		t.Errorf("the refusal reported uid %d and this process is uid %d; the decision must be "+
			"made on what the kernel said", result.peer.UID, os.Getuid())
	}
	if result.peer.PID != os.Getpid() {
		t.Errorf("the refusal reported pid %d and this process is pid %d, so an operator could "+
			"not tell which process tried", result.peer.PID, os.Getpid())
	}
}
