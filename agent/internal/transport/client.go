// The outbound handshake and the loop that keeps re-making it (RL-M2-006).
//
// # Three refusals that are not obvious, stated here because they are the security of it
//
// NO PLAINTEXT. The control-plane URL must be https. TLS is what authenticates the
// SERVER — the Ed25519 challenge authenticates the host to the control plane and says
// nothing in the other direction — so over plaintext the agent would prove its identity
// to whoever answered.
//
// NO REDIRECTS. This one is easy to get wrong and is worse than it looks. The agent signs
// a nonce the control plane chose. If a redirect could move the challenge request
// elsewhere, an attacker who can redirect it would fetch a real challenge from the real
// control plane, hand it to the agent, collect the signature and authenticate as that
// host. The domain separator does not help: this IS an identity proof, which is exactly
// what the attacker wants. So the client refuses every redirect, and the refusal is a
// property with a test rather than the default of a client nobody configured.
//
// NO VERIFICATION SKIPPING. There is no option, flag or environment variable that sets
// InsecureSkipVerify. A self-hosted control plane frequently has a private or self-signed
// certificate, which is a real need and is met by trusting an operator-supplied CA file —
// a narrower answer than switching verification off, and one that still names who is
// trusted.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ALIRAZA47/ratline/agent/internal/protocol"
)

var (
	// ErrNotConfigured means the agent was asked to run without enough to run with.
	ErrNotConfigured = errors.New("the agent is not configured")
	// ErrInsecureControlPlane means the control-plane URL was not https.
	ErrInsecureControlPlane = errors.New("the control-plane address must be https")
	// ErrRedirected means the control plane tried to send the agent somewhere else.
	ErrRedirected = errors.New("the control plane redirected the agent, which is refused")
	// ErrHandshake means one exchange of the handshake failed. Always retried.
	ErrHandshake = errors.New("the handshake with the control plane failed")
	// ErrRefused means the control plane declined to authenticate this host.
	ErrRefused = errors.New("the control plane refused this host's proof of identity")
)

// requestTimeout bounds one exchange.
//
// Deliberately shorter than the challenge's 30-second life (CHALLENGE_TTL_MS in
// src/crypto/host_identity.ts): an answer that arrives after its challenge expired is
// refused, so a client that waited longer than the challenge lives would burn an attempt
// to learn something it could have known locally. Also the reason a stalled control plane
// cannot wedge the loop — without a timeout, "the connection hangs" and "the agent is
// healthy" look identical from the host.
const requestTimeout = 10 * time.Second

// Config is everything the connection needs. All of it comes from outside; nothing here
// is discovered, because an agent that guesses its own identity is an agent that can be
// made to guess wrong.
type Config struct {
	// ControlPlane is the base URL, https only. Trailing slashes are tolerated.
	ControlPlane string
	// HostID is what the control plane knows this host as, assigned at enrolment.
	HostID string
	// Key is this host's Ed25519 private key. Registered at enrolment; revocable there.
	Key ed25519.PrivateKey
	// CAFile optionally names a PEM bundle to trust IN ADDITION to the system roots.
	CAFile string
	// Backoff shapes the reconnect wait. Zero values take the defaults.
	Backoff Backoff
	// Reproof is how long an authenticated agent waits before proving itself again.
	// Zero takes DefaultReproof.
	Reproof time.Duration
	// Log receives one line per state change. Nil discards, which is what a test wants;
	// the command wires it to stderr, because an operator diagnosing a host that will not
	// connect needs to see the attempts and the waits.
	Log io.Writer
}

// DefaultReproof is how often a connected agent re-proves its identity.
//
// It is not a heartbeat and does not pretend to be — RL-M2-013 owns health reporting, and
// this interval exists because the control plane's record of "last seen" is written by
// recordHostSeen when a proof succeeds. Two minutes is short enough that an operator
// looking at a host list sees something recent and long enough that a thousand hosts cost
// the control plane eight proofs a second.
const DefaultReproof = 2 * time.Minute

// Client holds the configuration and the HTTP client, and is safe to reuse across
// reconnections. Nothing about it is per-connection except the challenge, which is
// per-connection by design and is never stored.
type Client struct {
	config      Config
	http        *http.Client
	base        string
	fingerprint string
}

// New validates the configuration and builds the client.
//
// Everything checkable is checked HERE rather than on first use. An agent installed with a
// plaintext URL or an unreadable key should fail at startup, where systemd records it and
// an operator sees it, and not on the first reconnection at three in the morning.
func New(config Config) (*Client, error) {
	if config.HostID == "" {
		return nil, fmt.Errorf("%w: no host id, so this host has not been enrolled", ErrNotConfigured)
	}
	if len(config.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: no host key, so there is nothing to prove identity with: %w",
			ErrNotConfigured, protocol.ErrNoHostKey)
	}

	base, err := controlPlaneURL(config.ControlPlane)
	if err != nil {
		return nil, err
	}

	roots, err := trustRoots(config.CAFile)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: requestTimeout,
		// See the file header. A redirect on the challenge request is an identity-proof
		// theft, so there is no redirect policy to configure — every one is an error.
		CheckRedirect: func(request *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: it pointed at %s", ErrRedirected, request.URL.Redacted())
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// MinVersion is stated rather than left to the default so that a future
				// Go release lowering it, or a build with a different default, cannot
				// quietly weaken the channel that carries the proof.
				MinVersion: tls.VersionTLS12,
				RootCAs:    roots,
			},
			// A connection per exchange is not needed, and an idle connection through a
			// NAT that has forgotten it produces a failure on the next use rather than at
			// the point the NAT forgot. Keeping the idle window well under the usual NAT
			// timeout (commonly 30–120 seconds for TCP) means the agent re-dials on its
			// own schedule instead of discovering a dead path mid-handshake.
			IdleConnTimeout:       20 * time.Second,
			TLSHandshakeTimeout:   requestTimeout,
			ResponseHeaderTimeout: requestTimeout,
		},
	}

	return &Client{
		config: config,
		http:   client,
		base:   base,
		// Computed, not configured. The control plane looks a host's key up by
		// fingerprint, so a configured one could name a key this agent does not hold —
		// which would present as an authentication failure with a correct key in place.
		fingerprint: Fingerprint(config.Key.Public().(ed25519.PublicKey)),
	}, nil
}

// Fingerprint names a public key the way the control plane does.
//
// The same value as fingerprint() in src/crypto/host_identity.ts: SHA-256 over the SPKI
// DER encoding, first eight bytes, lower-case hex. It is not a secret — it names a public
// key — but the two implementations must agree or every authentication fails with a key
// that is registered and correct, so both suites pin the value for the committed test key.
func Fingerprint(public ed25519.PublicKey) string {
	// MarshalPKIXPublicKey is the SPKI DER encoding, which is what the TypeScript side
	// exports with { type: "spki", format: "der" }. Hand-building the 44-byte Ed25519
	// SPKI prefix would work and would be one more bespoke ASN.1 encoder in a codebase
	// that already decided against those (RL-M2-005's notes).
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		// Unreachable for a correctly sized Ed25519 key, and an empty fingerprint would
		// be worse than a wrong one: it would look like "not configured" rather than like
		// a key mismatch. So the error surfaces as an obviously invalid value.
		return "unmarshalable-key"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// Connect performs one full handshake and returns the host id the control plane confirmed.
//
// One handshake is two exchanges, and it is two because the challenge must come from the
// control plane: a proof over a value the agent chose would be a proof of nothing.
func (client *Client) Connect(ctx context.Context) (string, error) {
	challenge, handle, err := client.requestChallenge(ctx)
	if err != nil {
		return "", err
	}

	answer, err := protocol.AnswerChallenge(client.config.Key, client.config.HostID, challenge)
	if err != nil {
		// A local failure, not a network one. Signing cannot fail for a well-formed
		// challenge, so this means the control plane sent something this build does not
		// understand — worth its own message, because retrying will not fix it and an
		// operator reading "handshake failed" would go looking at the network.
		return "", fmt.Errorf("%w: %w", ErrHandshake, err)
	}

	return client.presentAnswer(ctx, handle, answer)
}

// challengeResponse is what POST /agent/challenge returns.
type challengeResponse struct {
	Handle    string `json:"handle"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expiresAt"`
}

func (client *Client) requestChallenge(ctx context.Context) (protocol.Challenge, string, error) {
	// An empty JSON object rather than no body. The route reads a body with a catch, so
	// either works today; sending a well-formed one means a stricter parser later is a
	// control-plane change and not simultaneously an agent change.
	var body challengeResponse
	status, err := client.exchange(ctx, "/agent/challenge", map[string]string{}, &body)
	if err != nil {
		return protocol.Challenge{}, "", err
	}
	if status != http.StatusOK {
		// 503 is the bounded challenge store refusing (see src/api/challenges.ts), which
		// is a capacity condition and therefore exactly what backoff is for. Not
		// distinguished from any other non-200 here: the response to all of them is to
		// wait longer and try again, and a special case would be a special case with no
		// different behaviour behind it.
		return protocol.Challenge{}, "", fmt.Errorf(
			"%w: the control plane answered %d when asked for a challenge", ErrHandshake, status)
	}
	if body.Handle == "" {
		return protocol.Challenge{}, "", fmt.Errorf(
			"%w: the control plane issued a challenge with no handle to answer it with", ErrHandshake)
	}
	return protocol.Challenge{Nonce: body.Nonce}, body.Handle, nil
}

// answerRequest is what POST /agent/authenticate expects. The field names are the control
// plane's, and they are camelCase there and snake_case in protocol.Answer, which is why
// this type exists instead of sending the Answer directly.
type answerRequest struct {
	Handle      string `json:"handle"`
	HostID      string `json:"hostId"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
	Fingerprint string `json:"fingerprint"`
}

type authenticateResponse struct {
	HostID        string `json:"hostId"`
	Authenticated bool   `json:"authenticated"`
}

func (client *Client) presentAnswer(
	ctx context.Context, handle string, answer protocol.Answer,
) (string, error) {
	var body authenticateResponse
	status, err := client.exchange(ctx, "/agent/authenticate", answerRequest{
		Handle:      handle,
		HostID:      answer.HostID,
		Nonce:       answer.Nonce,
		Signature:   answer.Signature,
		Fingerprint: client.fingerprint,
	}, &body)
	if err != nil {
		return "", err
	}

	if status == http.StatusUnauthorized {
		// ONE refusal for every reason, because the control plane deliberately sends one
		// (see the comment on /agent/authenticate in src/api/server.ts). The agent must
		// not invent a distinction the response does not carry — a log line guessing
		// "probably revoked" would be read as fact by whoever is diagnosing it.
		return "", fmt.Errorf("%w: the reason is not disclosed to the host, by design. "+
			"An operator can see it in the control plane's audit trail", ErrRefused)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%w: the control plane answered %d to the proof", ErrHandshake, status)
	}
	if !body.Authenticated || body.HostID != client.config.HostID {
		// A 200 that does not confirm this host is not a success. Treating it as one would
		// mean an agent reporting itself connected on the strength of a status code.
		return "", fmt.Errorf(
			"%w: the control plane answered 200 without confirming this host", ErrHandshake)
	}
	return body.HostID, nil
}

// exchange sends one JSON request and decodes one JSON response.
func (client *Client) exchange(
	ctx context.Context, path string, request, into any,
) (int, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return 0, fmt.Errorf("%w: encoding the request for %s: %w", ErrHandshake, path, err)
	}

	httpRequest, err := http.NewRequestWithContext(
		ctx, http.MethodPost, client.base+path, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("%w: building the request for %s: %w", ErrHandshake, path, err)
	}
	httpRequest.Header.Set("content-type", "application/json")
	// Named so an operator reading the control plane's access log can tell an agent from
	// a browser. No version-specific behaviour depends on it: a control plane that
	// branched on the agent's self-description would be trusting the client to say what
	// it is.
	httpRequest.Header.Set("user-agent", "ratline-agent")

	response, err := client.http.Do(httpRequest)
	if err != nil {
		// A refused redirect arrives wrapped in a url.Error, and it is worth unwrapping
		// so the loop's log says what happened rather than "Post ... : ...".
		if errors.Is(err, ErrRedirected) {
			return 0, fmt.Errorf("%w: %w", ErrRedirected, err)
		}
		return 0, fmt.Errorf("%w: %s: %w", ErrHandshake, path, err)
	}
	defer func() {
		// Drained before closing so the connection can be reused. Bounded, because the
		// body being drained is from a party that has not authenticated itself beyond TLS
		// and an unbounded drain is somebody else's memory decision.
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		_ = response.Body.Close()
	}()

	// LimitReader, because the response is parsed before anything about the peer is
	// trusted beyond its certificate. A control plane that answered with a gigabyte would
	// otherwise be a memory exhaustion the agent volunteered for.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return response.StatusCode, fmt.Errorf(
			"%w: reading the response from %s: %w", ErrHandshake, path, err)
	}

	if response.StatusCode == http.StatusOK && into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			return response.StatusCode, fmt.Errorf(
				"%w: the control plane's answer to %s was not the JSON this build expects: %w",
				ErrHandshake, path, err)
		}
	}
	return response.StatusCode, nil
}

// maxResponseBytes bounds what the agent will read from one response. The largest real
// answer is a challenge, which is a handle, 64 hex characters and a timestamp.
const maxResponseBytes = 64 << 10

// Run holds the connection open for as long as the context lives.
//
// # It never gives up, and that is a decision
//
// Every failure is retried, including a flat refusal. The tempting alternative is to exit
// on 401 — the key is revoked, so why keep asking — and it is wrong for two reasons. A
// 401 is indistinguishable from a control plane whose database is still coming up, by
// design (the control plane sends one refusal for every reason), so exiting would turn a
// transient fault into a host that needs a human to restart it. And an agent that exits
// stops reporting, which removes the evidence an operator would use to notice the
// revocation. Backing off to the ceiling and staying there is quiet, cheap, and leaves
// the host visible.
//
// The only clean exit is the context ending, which is what a systemd stop produces.
func (client *Client) Run(ctx context.Context) error {
	attempts := NewAttempts(client.config.Backoff)
	reproof := client.config.Reproof
	if reproof <= 0 {
		reproof = DefaultReproof
	}

	for {
		hostID, err := client.Connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// The context ending mid-exchange is a stop, not a failure. Reporting it
				// as a handshake error would put a misleading line in the journal every
				// time the host reboots.
				return fmt.Errorf("%w: %w", ErrStopped, ctx.Err())
			}
			delay := attempts.Failed()
			client.logf("connection attempt %d failed: %v — waiting %s before the next",
				attempts.Count(), err, delay.Round(time.Millisecond))
			if waitErr := Wait(ctx, delay); waitErr != nil {
				return waitErr
			}
			continue
		}

		// Reset AFTER a success, so a control plane that comes back does not leave the
		// fleet waiting a minute between proofs for the rest of the day.
		if attempts.Count() > 0 {
			client.logf("connected as host %s after %d failed attempt(s)", hostID, attempts.Count())
		} else {
			client.logf("connected as host %s", hostID)
		}
		attempts.Succeeded()

		if err := Wait(ctx, reproof); err != nil {
			return err
		}
	}
}

func (client *Client) logf(format string, args ...any) {
	if client.config.Log == nil {
		return
	}
	// Errors ignored on purpose, and this is not a silent catch: the alternative is an
	// agent that stops connecting because its log destination filled up, which inverts
	// the priority between doing the work and describing it.
	_, _ = fmt.Fprintf(client.config.Log, format+"\n", args...)
}

// controlPlaneURL normalises and refuses.
func controlPlaneURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("%w: no control-plane address", ErrNotConfigured)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: the control-plane address is not a URL: %w", ErrNotConfigured, err)
	}
	if parsed.Scheme != "https" {
		// Named in the error, because the most likely cause is somebody testing against a
		// local control plane over http and the fix is a certificate plus RATLINE_CONTROL_PLANE_CA,
		// not a flag that turns this off. There is no flag that turns this off.
		return "", fmt.Errorf(
			"%w: %q has scheme %q. TLS is what authenticates the control plane to this host — "+
				"over plaintext the agent would prove its identity to whoever answered. Use https, "+
				"and RATLINE_CONTROL_PLANE_CA for a private certificate authority",
			ErrInsecureControlPlane, raw, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: the control-plane address names no host", ErrNotConfigured)
	}
	// Path preserved, because a control plane behind a reverse proxy may live under a
	// prefix. Trailing slash removed so joining does not produce a double one, which some
	// proxies treat as a different route.
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

// trustRoots returns the system roots, plus an operator-supplied bundle if there is one.
//
// ADDED to the system pool rather than replacing it. Replacing would be the tighter
// answer and is the wrong default here: an operator who supplies a CA for their own
// control plane has not asked to stop trusting the certificate their control plane might
// legitimately have from a public issuer tomorrow, and a rotation to one would otherwise
// take the fleet down.
func trustRoots(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		// nil means "use the system roots" to crypto/tls. Loading them here instead would
		// make this function fail on a host with an unreadable root store, at startup, for
		// no gain.
		return nil, nil
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the certificate authority at %s: %w",
			ErrNotConfigured, caFile, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		// A host whose system store cannot be read is a host where "trust these roots plus
		// mine" cannot be honoured. Continuing with only the supplied bundle would silently
		// narrow trust, which is safe, and silently narrowing anything is how a fleet-wide
		// outage becomes a mystery. So it refuses and says which half failed.
		return nil, fmt.Errorf("%w: the system certificate store could not be read, so %s "+
			"cannot be trusted IN ADDITION to it: %w", ErrNotConfigured, caFile, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: %s contains no certificate this build could parse",
			ErrNotConfigured, caFile)
	}
	return pool, nil
}
