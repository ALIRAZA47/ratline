// What this process is actually listening on, according to the kernel (RL-M2-006,
// acceptance 4).
//
// # Why /proc and not a command
//
// `ss -ltnp` would be shorter and would put a process launch in the agent module, which
// agent/internal/shellcheck exists to keep out and which C2 exists to make structurally
// impossible. It would also depend on iproute2 being installed, which is a dependency on
// the host that ADR 0002's bootstrap deliberately avoids. /proc is a filesystem read, it is
// always there on Linux, and it is the same data ss formats.
//
// # Why this is not mocked, and cannot be
//
// §6.7: "Mocks are not acceptable for anything that touches a host." What is split out here
// is not the host — it is the PATH. The parser and the descriptor walk are pure functions
// over real files, so the same code that reads /proc on a Debian host reads a directory of
// real symlinks and real fixture bytes in a test on any platform. Nothing is stubbed; the
// argument is a directory name.
//
// # An unsupported platform is an ERROR, never an empty answer
//
// Returning "no listening sockets" on macOS would be a security check that passes because
// it could not run, which is worse than no check at all because it reads as evidence.
// scripts/host learned this the hard way — its first version reported "root ssh: refused
// (C1 holds)" on a machine with no key file — and the lesson is the same one: a negative
// result and an unperformed test must not be spelled the same way.
package listencheck

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ErrUnsupported means this platform has no /proc to read, so nothing was checked.
var ErrUnsupported = errors.New("listening sockets can only be enumerated from /proc, which this platform does not have")

// Socket is one listening socket belonging to the process under inspection.
type Socket struct {
	// Family is "tcp", "tcp6", "udp" or "udp6".
	Family string
	// Address is the local address as /proc spells it, decoded to something readable.
	Address string
	Port    int
	// Inode ties the row back to a file descriptor this process holds.
	Inode string
}

func (socket Socket) String() string {
	return fmt.Sprintf("%s %s:%d (inode %s)", socket.Family, socket.Address, socket.Port, socket.Inode)
}

// tcpListen is the state /proc/net/tcp uses for LISTEN. Hex, as everything in that file is.
const tcpListen = "0A"

// Listening reports the network sockets this process is listening on.
//
// Unix-domain sockets are deliberately NOT reported: they are not ports, they are how the
// agent reaches privd (ADR 0004), and a check that counted them would report a correctly
// built host as a violation.
func Listening() ([]Socket, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: this is %s", ErrUnsupported, runtime.GOOS)
	}
	return ListeningIn("/proc", "self")
}

// ListeningIn is Listening against a /proc mounted somewhere else, or against a fixture.
//
// The `who` argument is "self" for this process and a numeric pid for another — which is
// what RL-M2-024's harness needs, since it inspects the agent it started rather than
// itself, and what an operator debugging a provisioned host needs.
func ListeningIn(procRoot, who string) ([]Socket, error) {
	inodes, err := socketInodes(filepath.Join(procRoot, who, "fd"))
	if err != nil {
		return nil, err
	}
	// An early return here would be an optimisation that changes the answer: a process
	// holding no socket descriptors at all is listening on nothing, and saying so requires
	// reading nothing further.
	if len(inodes) == 0 {
		return nil, nil
	}

	var listening []Socket
	for _, family := range []string{"tcp", "tcp6", "udp", "udp6"} {
		raw, err := os.ReadFile(filepath.Join(procRoot, "net", family))
		if err != nil {
			if os.IsNotExist(err) {
				// A kernel built without IPv6 has no /proc/net/tcp6. Absent is not the same
				// as unreadable: the first means there are no such sockets to have, the
				// second means the check did not happen, and only the second is a failure.
				continue
			}
			return nil, fmt.Errorf("reading /proc/net/%s: %w", family, err)
		}
		listening = append(listening, parseProcNet(family, raw, inodes)...)
	}
	return listening, nil
}

// socketInodes reads a /proc/<pid>/fd directory and collects the socket inodes.
//
// Every descriptor there is a symlink; a socket's target is "socket:[12345]". Reading the
// LINK rather than stat-ing the target matters, because the target does not exist as a
// path — stat would fail on exactly the entries this function is looking for.
func socketInodes(fdDir string) (map[string]bool, error) {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", fdDir, err)
	}

	inodes := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			// A descriptor can close between the ReadDir and the Readlink — the directory is
			// a live view of a running process. Skipping it is correct and is not a silent
			// catch: the descriptor is gone, so it is not a listening socket this process
			// holds, which is the question being asked.
			continue
		}
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			inodes[strings.TrimSuffix(inode, "]")] = true
		}
	}
	return inodes, nil
}

// parseProcNet pulls the listening rows belonging to the given inodes out of one
// /proc/net/{tcp,tcp6,udp,udp6} file.
//
// The format, which has not changed in twenty years:
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid ... inode
//	 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 ... 34567
//
// Fields are positional. local_address is hex, little-endian per four bytes for IPv4, and
// the port is hex after the colon. st is the connection state.
func parseProcNet(family string, raw []byte, inodes map[string]bool) []Socket {
	var found []Socket

	for index, line := range strings.Split(string(raw), "\n") {
		if index == 0 {
			continue // the header
		}
		fields := strings.Fields(line)
		// 10 is where the inode sits; a short line is a truncated read or a blank, and
		// either way there is nothing to conclude from it.
		if len(fields) < 10 {
			continue
		}

		local, state, inode := fields[1], fields[3], fields[9]
		if !inodes[inode] {
			continue
		}

		address, port, ok := splitProcAddress(local)
		if !ok {
			continue
		}

		if strings.HasPrefix(family, "tcp") {
			if !strings.EqualFold(state, tcpListen) {
				continue
			}
		} else if port == 0 {
			// UDP has no LISTEN state — a bound socket is reachable whether or not anything
			// has been sent to it. So the test is whether it holds a port at all, and port
			// zero means an unbound socket, which is what an outbound DNS query looks like
			// mid-flight.
			continue
		}

		found = append(found, Socket{Family: family, Address: address, Port: port, Inode: inode})
	}
	return found
}

// splitProcAddress decodes one "0100007F:1F90" into "127.0.0.1" and 8080.
//
// The address half is rendered readable rather than kept as hex because this value ends up
// in a test failure and in an operator's terminal, and "0100007F" is the sort of detail that
// gets misread as a different address than it is. The port is what the check actually turns
// on, so it is parsed rather than displayed.
func splitProcAddress(field string) (address string, port int, ok bool) {
	host, portHex, found := strings.Cut(field, ":")
	if !found {
		return "", 0, false
	}
	parsedPort, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil {
		return "", 0, false
	}

	switch len(host) {
	case 8: // IPv4, four bytes little-endian
		var octets [4]uint64
		for index := range octets {
			value, err := strconv.ParseUint(host[index*2:index*2+2], 16, 8)
			if err != nil {
				return "", 0, false
			}
			octets[index] = value
		}
		return fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0]),
			int(parsedPort), true
	case 32: // IPv6, printed as the hex groups rather than decoded
		var groups []string
		for index := 0; index < 32; index += 4 {
			groups = append(groups, host[index:index+4])
		}
		return strings.Join(groups, ":"), int(parsedPort), true
	default:
		return "", 0, false
	}
}
