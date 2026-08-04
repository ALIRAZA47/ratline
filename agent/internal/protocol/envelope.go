// Signed instruction envelopes (RL-M2-003), agent side.
//
// ADR 0002 fixes the verification order: "signature; that `target_host_id` is its
// own; that `expires_at` has not passed; that `nonce` is unseen. Then it looks the
// operation up in the catalogue and type-checks the arguments."
//
// # The order is the security property, not a style
//
// Every step before the argument check exists so that an unauthenticated party
// cannot reach the argument parsers at all. Reversing any two of them gives
// something away:
//
//   - Arguments before signature hands an attacker the whole validation surface —
//     every regexp, every length check, every parser — without a key. That is the
//     largest attack surface in the agent, reachable by anybody who can open a
//     connection.
//   - Target before signature lets an unauthenticated caller learn this host's
//     identity by sending guesses and watching which one is not rejected as
//     misaddressed.
//   - Nonce before expiry fills the replay store with entries for envelopes that
//     were already dead, which is a cheap way to exhaust a bounded store.
//   - Expiry before signature leaks the host's clock offset, which is exactly what
//     an attacker needs to aim a replay at a window.
//
// So the order is asserted by a test that reads this file, not merely written down
// here. Comments do not hold an order in place across a refactor.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// InstructionDomain separates instruction signatures from every other signature
// the same key could ever make. Includes the version, so a future layout cannot be
// verified against this one even if it happens to parse.
const InstructionDomain = "ratline-instruction-v1"

// NonceBytes is the decoded nonce length. The wire form is hex, so twice this.
const NonceBytes = 32

// MaxValidity bounds how long an instruction may live. The agent enforces it
// independently of the control plane: a signed envelope claiming a one-year window
// would otherwise require a one-year nonce store, so the ceiling is what keeps the
// replay memory this host must hold a property of THIS host rather than of whoever
// signed.
const MaxValidity = 5 * time.Minute

// MaxFutureSkew is how far ahead of local time an issue stamp may sit.
//
// Not zero, because clocks differ and refusing every instruction from a host whose
// NTP drifted by a second would be worse than useless. Not large, because the
// window between issue and expiry is what a replay has to land in, and tolerating a
// far-future issue stamp effectively extends that window at the attacker's choosing.
const MaxFutureSkew = 30 * time.Second

// Refusal reasons, distinguishable because the agent's own logs need to tell them
// apart — an operator debugging "my deploy did nothing" is asking which of these
// happened, and one generic error would make every cause look like the others.
var (
	ErrBadSignature    = errors.New("signature does not verify under any accepted key")
	ErrWrongHost       = errors.New("envelope is addressed to another host")
	ErrExpired         = errors.New("envelope has expired")
	ErrNotYetValid     = errors.New("envelope is issued too far in the future")
	ErrValidityTooLong = errors.New("envelope claims a validity window longer than this agent allows")
	ErrReplayed        = errors.New("envelope nonce has been seen before")
	ErrMalformed       = errors.New("envelope is malformed")
)

// Envelope is the wire form. Field names match src/agent/envelope.ts's wireForm.
type Envelope struct {
	Operation    string            `json:"operation"`
	Arguments    map[string]string `json:"arguments"`
	Nonce        string            `json:"nonce"`
	IssuedAt     int64             `json:"issued_at"`
	ExpiresAt    int64             `json:"expires_at"`
	TargetHostID string            `json:"target_host_id"`
	Signature    string            `json:"signature"`
	KeyID        string            `json:"key_id"`
}

// AcceptedKey is one public key the agent will verify against.
//
// A SET rather than one key, because ADR 0002 requires rotation to use an overlap
// window: "agents accept both the outgoing and incoming key for a configured
// period, so rotation never requires a flag-day".
type AcceptedKey struct {
	KeyID  string
	Public ed25519.PublicKey
}

// canonicalBytes derives the exact bytes the signature covers.
//
// Independently implemented from canonicalBytes in src/agent/envelope.ts, and the
// two are checked against each other by committed vectors — "these two functions
// agree" is not a property source review establishes.
//
// Every field is length-prefixed because concatenation without lengths is
// ambiguous, and ambiguity in signed bytes is forgery: {a: "bc"} and {ab: "c"} both
// flatten to "abc", so one signature would be valid for two different instructions.
func canonicalBytes(envelope Envelope) []byte {
	var buffer bytes.Buffer

	// Domain first, NUL-terminated, so the separator cannot be confused with the
	// beginning of a field.
	buffer.WriteString(InstructionDomain)
	buffer.WriteByte(0)

	writeField(&buffer, envelope.Operation)
	writeField(&buffer, envelope.TargetHostID)
	writeField(&buffer, envelope.Nonce)
	writeUint64(&buffer, uint64(envelope.IssuedAt))
	writeUint64(&buffer, uint64(envelope.ExpiresAt))

	// Sorted by byte value, matching the TypeScript side's default comparator.
	// sort.Strings is a byte-wise sort; a locale-aware one would make the encoding
	// depend on the machine, which shows up as an unverifiable instruction on one
	// host and nowhere else.
	names := make([]string, 0, len(envelope.Arguments))
	for name := range envelope.Arguments {
		names = append(names, name)
	}
	sort.Strings(names)

	writeUint32(&buffer, uint32(len(names)))
	for _, name := range names {
		writeField(&buffer, name)
		writeField(&buffer, envelope.Arguments[name])
	}

	return buffer.Bytes()
}

func writeField(buffer *bytes.Buffer, value string) {
	writeUint32(buffer, uint32(len(value)))
	buffer.WriteString(value)
}

func writeUint32(buffer *bytes.Buffer, value uint32) {
	var scratch [4]byte
	binary.BigEndian.PutUint32(scratch[:], value)
	buffer.Write(scratch[:])
}

func writeUint64(buffer *bytes.Buffer, value uint64) {
	var scratch [8]byte
	binary.BigEndian.PutUint64(scratch[:], value)
	buffer.Write(scratch[:])
}

// ParseEnvelope decodes the wire form without interpreting anything.
//
// Unknown fields are refused. Go's json package ignores them by default, which
// would let an envelope carry a field this agent version does not know about — and
// an ignored field is how a payload aimed at a future version gets accepted by the
// present one. It is also not covered by the signature check in a useful way: the
// signature would still verify, because canonicalBytes only covers fields it knows.
//
// Duplicate keys are a related hazard Go cannot reject directly: its decoder keeps
// the last. That is not exploitable here, because canonicalBytes is derived from
// the DECODED struct and the signature was made over one specific value — a
// duplicate therefore produces a signature mismatch rather than a smuggled field.
// Stated rather than claimed as a rejection, because it is a consequence, not a check.
func ParseEnvelope(raw []byte) (Envelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	// Exactly one JSON value. Trailing data would otherwise be ignored, and an
	// envelope followed by a second one is a request to interpret two things while
	// verifying one.
	if decoder.More() {
		return Envelope{}, fmt.Errorf("%w: trailing data after the envelope", ErrMalformed)
	}

	return envelope, nil
}

// NonceStore remembers nonces until they expire. See nonces.go.
type NonceStore interface {
	// Remember records a nonce, returning false if it was already present.
	//
	// Both effects in one call ON PURPOSE. A `Seen` then `Record` pair is two
	// operations with a window between them, and two envelopes carrying the same
	// nonce arriving concurrently would both pass the check before either recorded
	// — which is a replay that the store reports as having prevented.
	Remember(nonce string, expiresAt time.Time) (bool, error)
}

// Verify performs every check that must happen before an argument is interpreted,
// in ADR 0002's order, and then the catalogue check.
//
// Returns the operation so the caller has no reason to look it up again — a second
// lookup is a second chance to look up something different.
func Verify(
	envelope Envelope,
	keys []AcceptedKey,
	hostID string,
	nonces NonceStore,
	now time.Time,
) (Operation, error) {
	// Shape checks first, and they are not "validation" in the sense the order
	// forbids: they read no argument and decide nothing about content. They exist
	// because the steps below cannot be performed on a malformed envelope at all —
	// a signature cannot be checked against a nonce that is not 32 bytes of hex.
	if err := checkShape(envelope); err != nil {
		return Operation{}, err
	}

	// 1. SIGNATURE. Nothing above this line looked at Arguments, and nothing below
	// it runs before this returns.
	if err := verifySignature(envelope, keys); err != nil {
		return Operation{}, err
	}

	// 2. TARGET. After the signature, so an unauthenticated caller cannot discover
	// this host's identity by sending guesses and watching which is not refused as
	// misaddressed.
	if subtle.ConstantTimeCompare([]byte(envelope.TargetHostID), []byte(hostID)) != 1 {
		// The expected id is NOT named in the error. It reaches a log, and a log is
		// read by more people than hold it.
		return Operation{}, fmt.Errorf("%w", ErrWrongHost)
	}

	// 3. EXPIRY. Before the nonce, so a flood of already-dead envelopes cannot fill
	// a bounded replay store.
	if err := checkFreshness(envelope, now); err != nil {
		return Operation{}, err
	}

	// 4. NONCE. Last of the four, and recorded in the same call that checks it.
	fresh, err := nonces.Remember(envelope.Nonce, time.UnixMilli(envelope.ExpiresAt))
	if err != nil {
		// A store that cannot answer means replay cannot be ruled out, so the
		// envelope is refused. Failing open here would make the whole check
		// advisory the first time the disk filled.
		return Operation{}, fmt.Errorf("cannot rule out replay: %w", err)
	}
	if !fresh {
		return Operation{}, fmt.Errorf("%w", ErrReplayed)
	}

	// 5. Only now the catalogue and the arguments.
	operation, err := Lookup(envelope.Operation)
	if err != nil {
		return Operation{}, err
	}
	if _, err := Validate(operation, Arguments(envelope.Arguments)); err != nil {
		return Operation{}, err
	}

	return operation, nil
}

func checkShape(envelope Envelope) error {
	decoded, err := hex.DecodeString(envelope.Nonce)
	if err != nil || len(decoded) != NonceBytes {
		return fmt.Errorf("%w: nonce must be %d hex-encoded bytes", ErrMalformed, NonceBytes)
	}
	if envelope.Signature == "" {
		return fmt.Errorf("%w: no signature", ErrMalformed)
	}
	if envelope.TargetHostID == "" {
		return fmt.Errorf("%w: no target host", ErrMalformed)
	}
	if envelope.IssuedAt <= 0 || envelope.ExpiresAt <= 0 {
		return fmt.Errorf("%w: issue and expiry stamps are required", ErrMalformed)
	}
	if envelope.ExpiresAt <= envelope.IssuedAt {
		return fmt.Errorf("%w: expiry is not after issue", ErrMalformed)
	}
	return nil
}

func verifySignature(envelope Envelope, keys []AcceptedKey) error {
	if len(keys) == 0 {
		// An agent with no accepted keys must refuse everything rather than accept
		// everything. Stated as its own branch because a range over an empty slice
		// falls straight through to "no key matched", and relying on that is
		// relying on a coincidence.
		return fmt.Errorf("%w: this agent holds no instruction keys", ErrBadSignature)
	}

	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64", ErrMalformed)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrMalformed, len(signature), ed25519.SignatureSize)
	}

	message := canonicalBytes(envelope)

	// EVERY key is tried, and envelope.KeyID is not used to select one. The key id
	// is attacker-controlled: letting it choose the verification key would mean
	// naming a revoked key is enough to have it used, which is the whole of the
	// vulnerability that key rotation exists to close.
	//
	// Trying all of them is also constant in the number of keys, so an attacker
	// cannot learn which key an agent holds by timing the refusal.
	verified := false
	for _, key := range keys {
		if len(key.Public) != ed25519.PublicKeySize {
			continue
		}
		if ed25519.Verify(key.Public, message, signature) {
			verified = true
		}
	}

	if !verified {
		return fmt.Errorf("%w", ErrBadSignature)
	}
	return nil
}

func checkFreshness(envelope Envelope, now time.Time) error {
	issued := time.UnixMilli(envelope.IssuedAt)
	expires := time.UnixMilli(envelope.ExpiresAt)

	if expires.Compare(now) <= 0 {
		return fmt.Errorf("%w", ErrExpired)
	}
	if issued.Sub(now) > MaxFutureSkew {
		// A far-future issue stamp extends the replay window at the signer's
		// choosing, so the agent bounds it locally.
		return fmt.Errorf("%w", ErrNotYetValid)
	}
	if expires.Sub(issued) > MaxValidity {
		// Enforced by the agent, not merely by the control plane. A signed envelope
		// claiming a one-year window would otherwise require a one-year nonce store
		// on this host.
		return fmt.Errorf("%w: %s exceeds %s", ErrValidityTooLong, expires.Sub(issued), MaxValidity)
	}
	return nil
}
