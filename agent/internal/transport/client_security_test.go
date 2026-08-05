// The outbound handshake, tested against a real TLS server on a real socket
// (RL-M2-006, acceptance 1, 2 and 3).
//
// # What is real here and what is not
//
// REAL: the TLS handshake, the sockets, the HTTP exchanges, the Ed25519 signature, the
// single-use challenge, the certificate trust decision, and — in the restart test — a
// listener that is genuinely closed and genuinely rebound, so the agent meets a real
// "connection refused" rather than a handler that returns 503.
//
// NOT REAL, and stated because §9 rejects a test that mocks the thing it tests: the
// control plane. The fake below verifies answers with protocol.VerifyAnswer, which is the
// AGENT's implementation, so nothing here proves the TypeScript control plane agrees with
// it. That agreement is proven separately and deliberately: identity_security_test.go
// checks committed vectors that src/crypto/host_identity.ts produced, and
// TestTheFingerprintAgreesWithTheControlPlane below pins the fingerprint both sides must
// compute. The thing under test here is the agent's client, and a fake peer is the only
// way to drive its failure paths — a real control plane cannot be asked to redirect, to
// vanish, or to present the wrong certificate on demand.
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ALIRAZA47/ratline/agent/internal/protocol"
)

const testHostID = "8f14e45f-ea8f-4b5e-9c2a-1d3b7e6a0c11"

// --- the fake control plane ------------------------------------------------------------

type fakeControlPlane struct {
	mutex  sync.Mutex
	public ed25519.PublicKey
	hostID string

	// inFlight is the challenge store, with the property that matters: an entry is TAKEN
	// on use. Modelled on src/api/challenges.ts rather than simplified, because the
	// agent's obligation to fetch a fresh challenge per connection is only testable
	// against a peer that actually consumes them.
	inFlight map[string]string

	noncesIssued    []string
	challengeCalls  int
	authenticated   int
	refused         int
	lastFingerprint string

	// failChallengesFor makes the first N challenge requests answer 503, which is what a
	// full challenge store does.
	failChallengesFor int
	// refuseEverything makes every answer a 401, which is what a revoked key looks like —
	// and what a control plane whose database has not finished starting looks like, since
	// it sends one refusal for every reason.
	refuseEverything bool
	// redirectTo makes the challenge request a 302, which must never be followed.
	redirectTo string
}

func newFakeControlPlane(public ed25519.PublicKey) *fakeControlPlane {
	return &fakeControlPlane{public: public, hostID: testHostID, inFlight: map[string]string{}}
}

func (plane *fakeControlPlane) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agent/challenge", plane.serveChallenge)
	mux.HandleFunc("POST /agent/authenticate", plane.serveAuthenticate)
	return mux
}

func (plane *fakeControlPlane) serveChallenge(writer http.ResponseWriter, _ *http.Request) {
	plane.mutex.Lock()
	defer plane.mutex.Unlock()
	plane.challengeCalls++

	if plane.redirectTo != "" {
		writer.Header().Set("location", plane.redirectTo+"/agent/challenge")
		writer.WriteHeader(http.StatusFound)
		return
	}
	if plane.failChallengesFor > 0 {
		plane.failChallengesFor--
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	nonce := make([]byte, protocol.ChallengeBytes)
	if _, err := rand.Read(nonce); err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	handleBytes := make([]byte, 16)
	if _, err := rand.Read(handleBytes); err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	handle, encoded := hex.EncodeToString(handleBytes), hex.EncodeToString(nonce)
	plane.inFlight[handle] = encoded
	plane.noncesIssued = append(plane.noncesIssued, encoded)

	writeJSON(writer, http.StatusOK, challengeResponse{
		Handle:    handle,
		Nonce:     encoded,
		ExpiresAt: time.Now().Add(30 * time.Second).UnixMilli(),
	})
}

func (plane *fakeControlPlane) serveAuthenticate(writer http.ResponseWriter, request *http.Request) {
	var body answerRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	plane.mutex.Lock()
	defer plane.mutex.Unlock()
	plane.lastFingerprint = body.Fingerprint

	// Taken, not read. This is what makes a captured answer worthless and what forces the
	// agent to fetch a fresh challenge on every reconnection.
	nonce, known := plane.inFlight[body.Handle]
	delete(plane.inFlight, body.Handle)

	ok := known &&
		!plane.refuseEverything &&
		nonce == body.Nonce &&
		body.HostID == plane.hostID &&
		protocol.VerifyAnswer(plane.public, protocol.Answer{
			HostID: body.HostID, Nonce: body.Nonce, Signature: body.Signature,
		})
	if !ok {
		plane.refused++
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	plane.authenticated++
	writeJSON(writer, http.StatusOK, authenticateResponse{HostID: plane.hostID, Authenticated: true})
}

func writeJSON(writer http.ResponseWriter, status int, body any) {
	writer.Header().Set("content-type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(body)
}

func (plane *fakeControlPlane) counts() (challenges, authenticated, refused int) {
	plane.mutex.Lock()
	defer plane.mutex.Unlock()
	return plane.challengeCalls, plane.authenticated, plane.refused
}

// --- a certificate both servers can share ----------------------------------------------

// selfSignedCertificate mints one certificate for 127.0.0.1 and writes it where the agent
// can trust it.
//
// One certificate reused by every server in this file, rather than letting httptest mint
// its own per server. Two reasons, and the second is a test that would otherwise pass for
// the wrong reason: the restart test needs the SAME identity before and after, and the
// redirect test needs the attacker's server to be TRUSTED — if the redirect target had an
// untrusted certificate, the agent would refuse it on trust grounds and the test would
// report that the redirect was refused when nothing about redirects had been exercised.
func selfSignedCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a certificate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ratline-test-control-plane"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatalf("minting the certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "control-plane-ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatalf("writing the CA file: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

// startTLS runs a server on a listener the caller owns, so a test can close the socket and
// bind the same address again — which is what a control plane restart is.
func startTLS(t *testing.T, listener net.Listener, cert tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	_ = server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	return server
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	return listener
}

// hostKey returns a deterministic-enough Ed25519 pair for a test.
func hostKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating a host key: %v", err)
	}
	return public, private
}

// connectedClient wires an agent to a fake control plane over TLS.
func connectedClient(t *testing.T, tune func(*Config)) (*Client, *fakeControlPlane, *httptest.Server) {
	t.Helper()

	public, private := hostKey(t)
	plane := newFakeControlPlane(public)
	cert, caPath := selfSignedCertificate(t)
	server := startTLS(t, listenLoopback(t), cert, plane.handler())
	t.Cleanup(server.Close)

	config := Config{
		ControlPlane: server.URL,
		HostID:       testHostID,
		Key:          private,
		CAFile:       caPath,
		Backoff:      Backoff{First: 2 * time.Millisecond, Max: 8 * time.Millisecond},
		Reproof:      5 * time.Millisecond,
	}
	if tune != nil {
		tune(&config)
	}

	client, err := New(config)
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	return client, plane, server
}

// --- acceptance 1: the agent dials out -------------------------------------------------

func TestTheAgentDialsOutAndProvesItsIdentity(t *testing.T) {
	t.Parallel()

	client, plane, _ := connectedClient(t, nil)

	hostID, err := client.Connect(context.Background())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if hostID != testHostID {
		t.Errorf("connected as %q, want %q", hostID, testHostID)
	}

	challenges, authenticated, refused := plane.counts()
	if challenges != 1 || authenticated != 1 || refused != 0 {
		t.Errorf("one handshake produced %d challenges, %d successes and %d refusals; "+
			"want 1, 1 and 0", challenges, authenticated, refused)
	}
	if plane.lastFingerprint != client.fingerprint {
		t.Errorf("the control plane was sent fingerprint %q and the client holds %q",
			plane.lastFingerprint, client.fingerprint)
	}
}

// TestEveryReconnectionFetchesAFreshChallenge is A-04's binding property from the agent's
// side.
//
// A signature answering one challenge cannot answer another, because the control plane
// consumes the challenge on first use. An agent that cached its answer would therefore
// authenticate once and be refused forever — so this test is both a security property and
// the reason the reconnect loop works at all.
func TestEveryReconnectionFetchesAFreshChallenge(t *testing.T) {
	t.Parallel()

	client, plane, _ := connectedClient(t, nil)

	for attempt := range 4 {
		if _, err := client.Connect(context.Background()); err != nil {
			t.Fatalf("connection %d: %v", attempt+1, err)
		}
	}

	plane.mutex.Lock()
	issued := append([]string(nil), plane.noncesIssued...)
	leftInFlight := len(plane.inFlight)
	plane.mutex.Unlock()

	if len(issued) != 4 {
		t.Fatalf("four connections asked for %d challenges", len(issued))
	}
	distinct := map[string]bool{}
	for _, nonce := range issued {
		distinct[nonce] = true
	}
	if len(distinct) != 4 {
		t.Errorf("four connections used %d distinct nonces. A reused nonce means a captured "+
			"answer authenticates again", len(distinct))
	}
	if leftInFlight != 0 {
		t.Errorf("%d challenges are still in flight after four completed handshakes, so they "+
			"are not being consumed", leftInFlight)
	}
}

// TestAReplayedAnswerIsRefused drives the replay directly rather than inferring it, because
// "the nonces differed" is not the same claim as "the old answer no longer works".
func TestAReplayedAnswerIsRefused(t *testing.T) {
	t.Parallel()

	public, private := hostKey(t)
	plane := newFakeControlPlane(public)
	cert, caPath := selfSignedCertificate(t)
	server := startTLS(t, listenLoopback(t), cert, plane.handler())
	t.Cleanup(server.Close)

	client, err := New(Config{
		ControlPlane: server.URL, HostID: testHostID, Key: private, CAFile: caPath,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	// Capture a real, valid handshake by doing the two halves by hand.
	challenge, handle, err := client.requestChallenge(context.Background())
	if err != nil {
		t.Fatalf("requesting a challenge: %v", err)
	}
	answer, err := protocol.AnswerChallenge(private, testHostID, challenge)
	if err != nil {
		t.Fatalf("answering: %v", err)
	}
	if _, err := client.presentAnswer(context.Background(), handle, answer); err != nil {
		t.Fatalf("the first presentation of a valid answer failed: %v", err)
	}

	// The same bytes again. Nothing about them has changed; the challenge is gone.
	_, err = client.presentAnswer(context.Background(), handle, answer)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("replaying a captured answer returned %v, want ErrRefused", err)
	}
}

// --- the refusals -----------------------------------------------------------------------

func TestTheAgentRefusesAPlaintextControlPlane(t *testing.T) {
	t.Parallel()

	_, private := hostKey(t)
	for _, address := range []string{
		"http://control.example",
		"HTTP://control.example",
		"ws://control.example",
		"control.example:8080", // no scheme at all
		"",
	} {
		_, err := New(Config{ControlPlane: address, HostID: testHostID, Key: private})
		if err == nil {
			t.Errorf("%q was accepted as a control-plane address. Over plaintext the agent "+
				"proves its identity to whoever answers", address)
			continue
		}
		if address != "" && !errors.Is(err, ErrInsecureControlPlane) && !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%q was refused with %v, which names neither the scheme nor the "+
				"configuration as the problem", address, err)
		}
	}
}

// TestTheAgentRefusesToFollowARedirect is the subtlest property in this file.
//
// The agent signs a nonce the control plane chose. If a redirect moved the challenge
// request, an attacker who can redirect it would fetch a real challenge from the real
// control plane, hand it over, collect the signature and authenticate as this host. The
// domain separator does not help — this IS an identity proof, which is precisely what the
// attacker wants.
//
// The redirect target is served with the SAME trusted certificate on purpose. With an
// untrusted one the agent would refuse it for the wrong reason and this test would pass
// while proving nothing about redirects.
func TestTheAgentRefusesToFollowARedirect(t *testing.T) {
	t.Parallel()

	public, private := hostKey(t)
	cert, caPath := selfSignedCertificate(t)

	var attackerHits atomic.Int64
	attacker := startTLS(t, listenLoopback(t), cert, http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			attackerHits.Add(1)
			writeJSON(writer, http.StatusOK, challengeResponse{
				Handle: "attacker", Nonce: strings.Repeat("a", protocol.ChallengeBytes*2),
			})
		}))
	t.Cleanup(attacker.Close)

	plane := newFakeControlPlane(public)
	plane.redirectTo = attacker.URL
	server := startTLS(t, listenLoopback(t), cert, plane.handler())
	t.Cleanup(server.Close)

	client, err := New(Config{
		ControlPlane: server.URL, HostID: testHostID, Key: private, CAFile: caPath,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	_, err = client.Connect(context.Background())
	if !errors.Is(err, ErrRedirected) {
		t.Errorf("a redirected challenge returned %v, want ErrRedirected", err)
	}
	if hits := attackerHits.Load(); hits != 0 {
		t.Errorf("the agent followed the redirect %d time(s). Whoever can redirect the "+
			"challenge request can have this host sign a nonce of their choosing, which is "+
			"an identity proof they can then replay to the real control plane", hits)
	}
}

func TestTheAgentRefusesAnUntrustedCertificate(t *testing.T) {
	t.Parallel()

	public, private := hostKey(t)
	plane := newFakeControlPlane(public)

	// The server's certificate and the CA file the agent trusts are from two separate
	// mintings, so the certificate is well-formed and simply not ours.
	serverCert, _ := selfSignedCertificate(t)
	_, otherCA := selfSignedCertificate(t)
	server := startTLS(t, listenLoopback(t), serverCert, plane.handler())
	t.Cleanup(server.Close)

	client, err := New(Config{
		ControlPlane: server.URL, HostID: testHostID, Key: private, CAFile: otherCA,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	if _, err := client.Connect(context.Background()); err == nil {
		t.Fatal("the agent authenticated to a control plane whose certificate it does not trust")
	}
	if challenges, _, _ := plane.counts(); challenges != 0 {
		t.Errorf("the untrusted server was reached %d time(s) at the application layer; the "+
			"TLS handshake should have failed first", challenges)
	}
}

// TestTheClientNeverDisablesCertificateVerification asserts on the object rather than on
// the absence of a feature, because "there is no flag for it" is only true until somebody
// adds one.
func TestTheClientNeverDisablesCertificateVerification(t *testing.T) {
	t.Parallel()

	_, private := hostKey(t)
	client, err := New(Config{
		ControlPlane: "https://control.example", HostID: testHostID, Key: private,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	transport, ok := client.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the client's transport is a %T, so this test cannot check its TLS config",
			client.http.Transport)
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("the agent's TLS configuration skips certificate verification, which makes " +
			"the whole handshake an identity proof offered to anybody on the path")
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("the minimum TLS version is %#x, below TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
	if client.http.CheckRedirect == nil {
		t.Error("the client has no redirect policy, so it follows redirects by default — see " +
			"TestTheAgentRefusesToFollowARedirect for what that costs")
	}
	if client.http.Timeout <= 0 {
		t.Error("the client has no timeout, so a stalled control plane wedges the reconnect loop")
	}
}

// --- acceptance 2: it survives a control plane restart ---------------------------------

// TestTheLoopSurvivesAControlPlaneRestart closes the listener and binds the same address
// again.
//
// A handler returning 503 would be easier and would not test this: the agent would keep
// getting an answer. What a restart actually produces is a refused connection, then a TLS
// handshake with a server that has just started, and the loop has to get through both
// without help.
func TestTheLoopSurvivesAControlPlaneRestart(t *testing.T) {
	t.Parallel()

	public, private := hostKey(t)
	plane := newFakeControlPlane(public)
	cert, caPath := selfSignedCertificate(t)

	listener := listenLoopback(t)
	address := listener.Addr().String()
	server := startTLS(t, listener, cert, plane.handler())

	logged := &syncBuffer{}
	client, err := New(Config{
		ControlPlane: "https://" + address,
		HostID:       testHostID,
		Key:          private,
		CAFile:       caPath,
		Backoff:      Backoff{First: 2 * time.Millisecond, Max: 10 * time.Millisecond},
		Reproof:      2 * time.Millisecond,
		Log:          logged,
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	waitFor(t, "the first connection", func() bool {
		_, authenticated, _ := plane.counts()
		return authenticated >= 1
	})

	// The restart. The socket goes away entirely, so the agent meets ECONNREFUSED.
	server.Close()
	_, before, _ := plane.counts()

	waitFor(t, "a failed attempt while the control plane is down", func() bool {
		return strings.Contains(logged.String(), "connection attempt")
	})

	// Back on the same address, with the same certificate, as a restarted control plane is.
	revived := rebind(t, address)
	restarted := startTLS(t, revived, cert, plane.handler())
	t.Cleanup(restarted.Close)

	waitFor(t, "reconnection after the restart", func() bool {
		_, authenticated, _ := plane.counts()
		return authenticated > before
	})

	cancel()
	if err := <-done; !errors.Is(err, ErrStopped) {
		t.Errorf("Run returned %v after cancellation, want ErrStopped", err)
	}

	// The log is the operator's only view of this, so it is asserted rather than assumed.
	if !strings.Contains(logged.String(), "waiting") {
		t.Errorf("no wait was reported while the control plane was down:\n%s", logged.String())
	}
}

// TestTheLoopKeepsTryingAfterAFlatRefusal is the decision recorded on Run: a 401 is
// indistinguishable from a control plane that has not finished starting, so exiting on one
// would turn a transient fault into a host that needs a human.
func TestTheLoopKeepsTryingAfterAFlatRefusal(t *testing.T) {
	t.Parallel()

	client, plane, _ := connectedClient(t, func(config *Config) {
		config.Backoff = Backoff{First: time.Millisecond, Max: 4 * time.Millisecond}
	})
	plane.mutex.Lock()
	plane.refuseEverything = true
	plane.mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	err := client.Run(ctx)
	if !errors.Is(err, ErrStopped) {
		t.Fatalf("Run returned %v; a refusal must not end the loop", err)
	}
	if _, _, refused := plane.counts(); refused < 3 {
		t.Errorf("the agent gave up after %d refusals. An agent that exits stops reporting, "+
			"which removes the evidence an operator would use to notice a revocation", refused)
	}
}

// TestAFullChallengeStoreIsJustAnotherRetry covers the 503 src/api/challenges.ts returns
// when the bounded store is full. It is a capacity condition, so backing off is the whole
// correct response.
func TestAFullChallengeStoreIsJustAnotherRetry(t *testing.T) {
	t.Parallel()

	client, plane, _ := connectedClient(t, func(config *Config) {
		config.Backoff = Backoff{First: time.Millisecond, Max: 4 * time.Millisecond}
	})
	plane.mutex.Lock()
	plane.failChallengesFor = 5
	plane.mutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = client.Run(ctx) }()

	waitFor(t, "a connection after five 503s", func() bool {
		_, authenticated, _ := plane.counts()
		return authenticated >= 1
	})
}

func TestRunStopsWhenAsked(t *testing.T) {
	t.Parallel()

	client, _, _ := connectedClient(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, ErrStopped) {
			t.Errorf("Run returned %v, want ErrStopped", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within two seconds of cancellation, so a systemd stop " +
			"would escalate to SIGKILL")
	}
}

// --- cross-language agreement -----------------------------------------------------------

// TestTheFingerprintAgreesWithTheControlPlane pins the value both implementations must
// produce for the committed test key.
//
// The control plane looks a host's key up BY fingerprint, so a disagreement here is not a
// cosmetic difference: every authentication fails, with a correctly registered key in
// place, and the symptom on the host is "the agent cannot authenticate" — which reads as a
// network problem or a revoked key. That is the same failure identity_security_test.go's
// vectors exist to prevent, and it needs the same treatment.
//
// The pin is a literal rather than a generated vector because adding a field to
// identity_vectors.json regenerates every signature in it (the generator mints a fresh key
// each run), which would put an unrelated wall of diff under this task. The matching
// assertion lives in test/security/host_identity.test.ts; each names the other.
func TestTheFingerprintAgreesWithTheControlPlane(t *testing.T) {
	t.Parallel()

	// The public half of test_only_private_key_pem in
	// agent/internal/protocol/testdata/identity_vectors.json.
	const publicKeyHex = "08efdafec7bb28ffa905e720010902a4fb263a4e197f50517bd0a9f647fd1083"
	// What src/crypto/host_identity.ts's fingerprint() returns for that key.
	const wantFingerprint = "2b3081d8482c9302"

	raw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decoding the vector key: %v", err)
	}

	got := Fingerprint(ed25519.PublicKey(raw))
	if got != wantFingerprint {
		t.Errorf("Fingerprint gave %q, and src/crypto/host_identity.ts gives %q for the same "+
			"key.\n\nThe control plane looks a key up by this value, so a mismatch means every "+
			"authentication fails with a correctly registered key.\n\nIf the vectors were "+
			"regenerated, both pins are stale: recompute with fingerprint() over the new key "+
			"and update this test AND test/security/host_identity.test.ts together.",
			got, wantFingerprint)
	}
}

// --- configuration ----------------------------------------------------------------------

func TestAHostKeyReadableBeyondItsOwnerIsRefused(t *testing.T) {
	t.Parallel()

	_, private := hostKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("encoding the key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666, 0o660} {
		path := filepath.Join(t.TempDir(), "host.key")
		if err := os.WriteFile(path, keyPEM, mode); err != nil {
			t.Fatalf("writing the key: %v", err)
		}
		// WriteFile applies the process umask, so the mode is set explicitly afterwards —
		// otherwise a umask of 022 would silently turn 0o666 into 0o644 and 0o640 into
		// 0o640, and one of these cases would be testing the umask.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		if _, err := LoadHostKey(path); !errors.Is(err, ErrKeyExposed) {
			t.Errorf("a key at mode %04o loaded with error %v. Anybody who can read it can "+
				"authenticate as this host", mode, err)
		}
	}

	// And the correct mode still works, or the check above would be satisfied by a
	// function that refuses everything.
	path := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	loaded, err := LoadHostKey(path)
	if err != nil {
		t.Fatalf("a key at mode 0600 was refused: %v", err)
	}
	if !loaded.Equal(private) {
		t.Error("LoadHostKey returned a different key than the one written")
	}
}

func TestTheConfigurationRefusesWhatItCannotRunWith(t *testing.T) {
	t.Parallel()

	_, private := hostKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatalf("encoding the key: %v", err)
	}
	directory := t.TempDir()
	goodKey := filepath.Join(directory, "host.key")
	if err := os.WriteFile(goodKey,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}

	// An RSA-shaped file: parses as PKCS#8, is not Ed25519, and would sign things the
	// control plane cannot verify. Refusing at load says which of the two is wrong.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating an EC key: %v", err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("encoding the EC key: %v", err)
	}
	wrongKind := filepath.Join(directory, "wrong-kind.key")
	if err := os.WriteFile(wrongKind,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}), 0o600); err != nil {
		t.Fatalf("writing the EC key: %v", err)
	}

	notPEM := filepath.Join(directory, "not-pem.key")
	if err := os.WriteFile(notPEM, []byte("this is not a key\n"), 0o600); err != nil {
		t.Fatalf("writing the junk file: %v", err)
	}

	cases := map[string]map[string]string{
		"no key path": {EnvControlPlane: "https://control.example", EnvHostID: testHostID},
		"missing key file": {
			EnvControlPlane: "https://control.example", EnvHostID: testHostID,
			EnvHostKey: filepath.Join(directory, "absent.key"),
		},
		"key of the wrong kind": {
			EnvControlPlane: "https://control.example", EnvHostID: testHostID,
			EnvHostKey: wrongKind,
		},
		"key that is not PEM": {
			EnvControlPlane: "https://control.example", EnvHostID: testHostID,
			EnvHostKey: notPEM,
		},
	}
	for name, environment := range cases {
		if _, err := ConfigFromEnvironment(fakeEnvironment(environment), nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// A complete environment works, and New then refuses the parts it owns.
	config, err := ConfigFromEnvironment(fakeEnvironment(map[string]string{
		EnvControlPlane: "https://control.example", EnvHostID: testHostID, EnvHostKey: goodKey,
	}), nil)
	if err != nil {
		t.Fatalf("a complete environment was refused: %v", err)
	}
	if _, err := New(config); err != nil {
		t.Fatalf("New refused a complete configuration: %v", err)
	}

	// No host id: enrolment has not happened, and connecting would be guessing.
	config.HostID = ""
	if _, err := New(config); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("a client with no host id was built with error %v", err)
	}

	// A CA file that is not a certificate must fail at startup, not at the first dial.
	config.HostID = testHostID
	config.CAFile = notPEM
	if _, err := New(config); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("a CA file containing no certificate was accepted with error %v", err)
	}
}

func fakeEnvironment(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// --- small helpers ----------------------------------------------------------------------

type syncBuffer struct {
	mutex sync.Mutex
	text  strings.Builder
}

func (buffer *syncBuffer) Write(p []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.text.Write(p)
}

func (buffer *syncBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.text.String()
}

// waitFor polls a condition instead of sleeping a guessed interval. A sleep long enough for
// a loaded machine is wasted on a fast one, and a sleep short enough to be quick is the
// flake somebody re-runs until it passes.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// rebind takes the address back after the listener holding it was closed.
//
// The retry is for the operating system rather than for the test: a just-closed accepted
// connection can hold the port in TIME_WAIT briefly, and a control plane restarting has
// exactly the same problem.
func rebind(t *testing.T, address string) net.Listener {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			return listener
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not bind %s again: %v", address, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
