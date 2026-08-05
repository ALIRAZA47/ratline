// No managed host gains an inbound port from Ratline (RL-M2-006, acceptance 1 and 4;
// ADR 0002).
//
// Four things are checked, and the order reflects which would be worst to get wrong:
//
//  1. The source check FIRES on deliberate violations. A scanner nobody has proven fires is
//     a scanner nobody has tested, and this repository has already shipped one of those —
//     RL-M1-041's eight invented CSS token names passed a scan that resolved nothing.
//  2. The source check does NOT fire on the shapes the agent and privd legitimately need. A
//     check that reports everything gets disabled rather than fixed.
//  3. The agent's real source is clean, and neither binary can bind a port.
//  4. The runtime check reads the kernel's socket table correctly, including the case that
//     matters most: an ESTABLISHED OUTBOUND connection is not a listener. That is the
//     agent's normal state, and a check that called it a violation would fail on every
//     correctly working host.
//
// Only 3 is the build gate. The others are what make it mean something.
package listencheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The module root, relative to this package.
const moduleRoot = "../.."

// --- the source check -------------------------------------------------------------------

func TestTheCheckFiresOnEveryDeliberateViolation(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "violations.go.txt")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	findings, err := ScanSource(path, source)
	if err != nil {
		t.Fatalf("scanning the fixture: %v", err)
	}

	expected := wantedRules(t, source)
	if len(expected) == 0 {
		t.Fatal("the fixture declares no `want:` markers, so this test verified nothing")
	}

	got, want := map[string]int{}, map[string]int{}
	for _, finding := range findings {
		got[finding.Rule]++
	}
	for _, rule := range expected {
		want[rule]++
	}

	for rule, count := range want {
		if got[rule] != count {
			t.Errorf("rule %q fired %d time(s), the fixture expects %d", rule, got[rule], count)
		}
	}
	for rule, count := range got {
		if want[rule] == 0 {
			t.Errorf("rule %q fired %d time(s) and the fixture does not expect it", rule, count)
		}
	}

	if t.Failed() {
		t.Log("what the scan actually reported:")
		for _, finding := range findings {
			t.Logf("  %s", finding)
		}
	}

	// A network listener must be refused OUTRIGHT, with no annotation offered. Asserted by
	// rule name and by message, so relaxing it to the annotatable rule fails here rather
	// than passing quietly.
	outright := 0
	for _, finding := range findings {
		if finding.Rule != RuleNetworkListener {
			continue
		}
		outright++
		if strings.Contains(finding.Detail, Annotation) {
			t.Errorf("the refusal of a network listener offers an annotation as a way out:\n  %s",
				finding)
		}
	}
	if outright == 0 {
		t.Error("no network listener was reported, and the fixture contains several")
	}
}

// A marker may list several rules, because one line can violate more than one.
var wantMarker = regexp.MustCompile(`//\s*want:\s*(.+)`)

func wantedRules(t *testing.T, source []byte) []string {
	t.Helper()
	var rules []string
	for _, match := range wantMarker.FindAllStringSubmatch(string(source), -1) {
		rules = append(rules, strings.Fields(match[1])...)
	}
	return rules
}

func TestTheCheckIsSilentOnWhatTheAgentActuallyNeeds(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "clean.go.txt")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	findings, err := ScanSource(path, source)
	if err != nil {
		t.Fatalf("scanning the fixture: %v", err)
	}
	for _, finding := range findings {
		t.Errorf("the check fired on code it must accept:\n  %s\n\n"+
			"Everything in that fixture is a shape the agent or privd legitimately needs: "+
			"dialling out, a unix socket to privd (ADR 0004), socket activation with a written "+
			"reason, and prose mentioning the words. A rule that fires on these is one somebody "+
			"will disable rather than fix.", finding)
	}
}

// TestNeitherBinaryCanBindAPort is the build gate and acceptance 1's negative half.
//
// The claim is stronger than any runtime observation: the binaries contain no code that can
// bind a network port, so there is no combination of arguments, environment or attacker input
// that makes them. A /proc check says "not right now"; this says "not ever".
func TestNeitherBinaryCanBindAPort(t *testing.T) {
	t.Parallel()

	findings, err := Scan(moduleRoot)
	if err != nil {
		t.Fatalf("scanning the agent module: %v", err)
	}
	for _, finding := range findings {
		t.Errorf("the agent module can open a listening socket:\n  %s", finding)
	}
	if t.Failed() {
		t.Log("ADR 0002: no managed host listens on a Ratline port, and an integration test " +
			"asserts this after provisioning. The agent dials out.")
	}
}

// TestTheScanCoversTheFilesItClaimsTo guards the way this check most plausibly rots: a walk
// that silently stops covering something.
//
// A scanner reporting zero findings is indistinguishable from a scanner that read nothing,
// and TestNeitherBinaryCanBindAPort passes in both cases. So the file list is asserted
// separately.
func TestTheScanCoversTheFilesItClaimsTo(t *testing.T) {
	t.Parallel()

	scanned := map[string]bool{}
	err := filepath.WalkDir(moduleRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "testdata" || entry.Name() == "dist") {
			return filepath.SkipDir
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			scanned[filepath.ToSlash(path)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	// The two mains are the whole point: they are what gets installed on a host.
	for _, required := range []string{
		moduleRoot + "/cmd/ratline-agent/main.go",
		moduleRoot + "/cmd/ratline-privd/main.go",
		moduleRoot + "/internal/transport/client.go",
	} {
		if !scanned[filepath.ToSlash(required)] {
			t.Errorf("%s is not covered by the scan's file selection", required)
		}
	}
	if len(scanned) < 8 {
		t.Errorf("the scan's selection found only %d files in the module, which is fewer than "+
			"exist. A walk that quietly stopped covering things would make the build gate pass "+
			"by reading nothing", len(scanned))
	}
}

// --- the runtime check ------------------------------------------------------------------

// TestAnEstablishedOutboundConnectionIsNotAListener is the case the whole runtime check
// turns on.
//
// A connected agent always holds an outbound socket to the control plane. If that counted as
// listening, acceptance 4 would fail on every correctly working host — and the temptation
// would then be to loosen the check rather than fix it.
func TestAnEstablishedOutboundConnectionIsNotAListener(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "proc-net-tcp"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	// 900004 is the outbound connection to 93.184.216.34:443 in the fixture — the shape of
	// the agent talking to its control plane; 900003 is an inbound accepted one. Neither is
	// in LISTEN state, and neither may be reported.
	//
	// The fixture's addresses are byte-reversed hex, as /proc writes them on a little-endian
	// machine: 0F02000A is 10.0.2.15 and 22D8B85D is 93.184.216.34. Two of these rows were
	// written the other way round at first, which decoded to plausible-looking wrong
	// addresses — and a wrong fixture is the thing somebody eventually "fixes" the parser
	// against.
	for _, inode := range []string{"900003", "900004"} {
		found := parseProcNet("tcp", raw, map[string]bool{inode: true})
		if len(found) != 0 {
			t.Errorf("inode %s was reported as listening: %v.\n\nAn established connection is "+
				"not a listener. The agent holds one to the control plane at all times, so this "+
				"would fail on every working host.", inode, found)
		}
	}
}

func TestALISTENSocketIsReportedWithItsAddressAndPort(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "proc-net-tcp"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	found := parseProcNet("tcp", raw, map[string]bool{"900001": true, "900002": true})
	if len(found) != 2 {
		t.Fatalf("expected the two LISTEN rows, got %v", found)
	}

	// 0100007F:1F90 is 127.0.0.1:8080 — little-endian per byte, which is the detail most
	// easily got backwards, and getting it backwards would print 127.0.0.1 as 1.0.0.127.
	if found[0].Address != "127.0.0.1" || found[0].Port != 8080 {
		t.Errorf("decoded 0100007F:1F90 as %s:%d, want 127.0.0.1:8080",
			found[0].Address, found[0].Port)
	}
	if found[1].Address != "0.0.0.0" || found[1].Port != 22 {
		t.Errorf("decoded 00000000:0016 as %s:%d, want 0.0.0.0:22",
			found[1].Address, found[1].Port)
	}
}

// TestABoundUDPSocketCountsAndAnUnboundOneDoesNot covers the family with no LISTEN state.
func TestABoundUDPSocketCountsAndAnUnboundOneDoesNot(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "proc-net-udp"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	// 900101 is bound to port 53. A UDP socket with a port is reachable whether or not
	// anything has been sent to it, so it is a listener for this check's purposes.
	bound := parseProcNet("udp", raw, map[string]bool{"900101": true})
	if len(bound) != 1 || bound[0].Port != 53 {
		t.Errorf("a UDP socket bound to port 53 was reported as %v", bound)
	}

	// 900102 holds no port, which is what an in-flight DNS query looks like.
	unbound := parseProcNet("udp", raw, map[string]bool{"900102": true})
	if len(unbound) != 0 {
		t.Errorf("an unbound UDP socket was reported as listening: %v", unbound)
	}
}

// TestOnlyThisProcessesSocketsAreConsidered is why the check can be pointed at one process
// on a host that legitimately runs sshd.
func TestOnlyThisProcessesSocketsAreConsidered(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("testdata", "proc-net-tcp"))
	if err != nil {
		t.Fatalf("reading the fixture: %v", err)
	}

	// 900002 is sshd's :22, which is a legitimate part of every managed host and belongs to
	// somebody else. An inode set that does not contain it must not report it.
	found := parseProcNet("tcp", raw, map[string]bool{"900001": true})
	for _, socket := range found {
		if socket.Port == 22 {
			t.Errorf("a socket belonging to another process was reported: %s.\n\nEvery Debian "+
				"host runs sshd, and RL-M2-010 needs it — a check that counted it would report "+
				"a correct host as a violation.", socket)
		}
	}
}

// TestTheDescriptorWalkReadsRealSymlinks uses real filesystem objects rather than a stub.
//
// A /proc file descriptor is a symlink whose target is "socket:[12345]" — a target that does
// not exist as a path. os.Symlink will create exactly that on any platform, so the code that
// reads /proc on Debian is the code being exercised here; only the directory differs. Nothing
// is mocked, which §6.7 requires of anything touching a host.
func TestTheDescriptorWalkReadsRealSymlinks(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	links := map[string]string{
		"0": "/dev/null",
		"1": "pipe:[770001]",
		"3": "socket:[900001]",
		"4": "socket:[900004]",
		"5": "/var/lib/ratline/host.key",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(directory, name)); err != nil {
			t.Fatalf("creating the symlink for fd %s: %v", name, err)
		}
	}

	inodes, err := socketInodes(directory)
	if err != nil {
		t.Fatalf("reading the descriptor directory: %v", err)
	}
	if len(inodes) != 2 || !inodes["900001"] || !inodes["900004"] {
		t.Errorf("the socket inodes were read as %v, want exactly 900001 and 900004", inodes)
	}
}

// TestATrueAnswerFromEndToEnd drives ListeningIn over a directory laid out like /proc.
func TestATrueAnswerFromEndToEnd(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatalf("building the fixture tree: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "self", "fd"), 0o755); err != nil {
		t.Fatalf("building the fixture tree: %v", err)
	}
	for _, family := range []string{"tcp", "udp"} {
		raw, err := os.ReadFile(filepath.Join("testdata", "proc-net-"+family))
		if err != nil {
			t.Fatalf("reading the fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "net", family), raw, 0o600); err != nil {
			t.Fatalf("writing the fixture: %v", err)
		}
	}

	// A process holding only its outbound connection to the control plane — the state a
	// correctly working agent is in.
	if err := os.Symlink("socket:[900004]", filepath.Join(root, "self", "fd", "3")); err != nil {
		t.Fatalf("creating the descriptor: %v", err)
	}

	found, err := ListeningIn(root, "self")
	if err != nil {
		t.Fatalf("ListeningIn: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("a process holding only an outbound connection was reported as listening on %v",
			found)
	}

	// Now give it a listener as well, and it must be found.
	if err := os.Symlink("socket:[900001]", filepath.Join(root, "self", "fd", "4")); err != nil {
		t.Fatalf("creating the descriptor: %v", err)
	}
	found, err = ListeningIn(root, "self")
	if err != nil {
		t.Fatalf("ListeningIn: %v", err)
	}
	if len(found) != 1 || found[0].Port != 8080 {
		t.Errorf("a process holding a LISTEN socket was reported as %v, want one on port 8080",
			found)
	}
}

// TestAnUnsupportedPlatformIsAnErrorAndNotAnEmptyAnswer is the lesson scripts/host records.
//
// Its first version reported "root ssh: refused (C1 holds)" on a machine with no key file —
// a check that passed because it could not run, which is worse than no check because it reads
// as evidence. So on a platform with no /proc, Listening must REFUSE rather than report
// nothing found.
func TestAnUnsupportedPlatformIsAnErrorAndNotAnEmptyAnswer(t *testing.T) {
	t.Parallel()

	found, err := Listening()

	if runtime.GOOS == "linux" {
		// On Linux it must actually work, or the test above is checking a function that
		// never runs anywhere. The test binary holds no listening socket, so the expected
		// answer is none — and an error would mean /proc could not be read.
		if err != nil {
			t.Fatalf("Listening failed on Linux: %v", err)
		}
		for _, socket := range found {
			t.Errorf("the test binary is listening on %s, which it should not be", socket)
		}
		return
	}

	if err == nil {
		t.Fatalf("Listening returned %v and no error on %s, which has no /proc. "+
			"An unperformed check must not be spelled the same way as a passing one",
			found, runtime.GOOS)
	}
	if found != nil {
		t.Errorf("Listening returned both an error and %v; a refusal must return nothing", found)
	}
}
