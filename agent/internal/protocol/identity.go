// Proving this host's identity to the control plane (RL-M2-005, ADR 0002 as amended
// by A-04).
//
// The agent dials out. TLS authenticates the SERVER; the agent proves itself with an
// Ed25519 signature over a challenge the control plane issued. It was going to be an
// X.509 client certificate, and the reasoning for the change is in ADR 0002 — briefly,
// the control plane could not mint one without either spawning a process (which C2 and
// ADR 0005 forbid it) or taking a dependency heavy enough to be its own risk.
//
// # This file is the agent's half of src/crypto/host_identity.ts
//
// The two implementations must agree on the exact bytes signed, and they are checked
// against each other by committed vectors — the same arrangement as the instruction
// envelope, for the same reason: two independent implementations of a byte layout can
// each be self-consistent and still disagree, and the failure would arrive on a host as
// "the agent cannot authenticate", which reads as a network problem.
//
// # What signing a challenge does NOT authorise
//
// Nothing. It authenticates a TRANSPORT. Every instruction that arrives over that
// transport carries its own Ed25519 signature over an envelope, and Verify checks it
// independently — so a stolen host key gets an attacker a connection, not the ability to
// make this agent act. The domain separator is what keeps the two from being confused:
// a signature made here cannot verify as an instruction, and an instruction cannot be
// replayed as a proof of identity.
package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// IdentityDomain separates a proof of identity from every other signature this key could
// make. Distinct from InstructionDomain, and the test asserts they differ.
const IdentityDomain = "ratline-host-identity-v1"

// ChallengeBytes is the decoded challenge length. The wire form is hex, so twice this.
const ChallengeBytes = 32

var (
	// ErrChallengeMalformed is returned for a challenge that cannot be answered.
	ErrChallengeMalformed = errors.New("challenge is malformed")
	// ErrNoHostKey is returned when this agent has no signing key to answer with.
	ErrNoHostKey = errors.New("this agent has no host key; it has not been enrolled")
)

// challengeBytes derives the exact bytes to sign.
//
// Independently implemented from challengeBytes in src/crypto/host_identity.ts. Both
// fields are length-prefixed for the reason the envelope's are: concatenation without
// lengths is ambiguous, and ambiguity in signed bytes is forgery. Here the fields are a
// UUID and a hex string, so the ambiguity is narrow — and "narrow" is not a property to
// build a signature on.
func challengeBytes(hostID, nonce string) []byte {
	out := make([]byte, 0, len(IdentityDomain)+1+8+len(hostID)+len(nonce))
	out = append(out, IdentityDomain...)
	out = append(out, 0)

	for _, field := range []string{hostID, nonce} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		out = append(out, length[:]...)
		out = append(out, field...)
	}
	return out
}

// Challenge is what the control plane sent.
type Challenge struct {
	Nonce string `json:"nonce"`
}

// Answer is what the agent sends back.
type Answer struct {
	HostID    string `json:"host_id"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// AnswerChallenge signs a challenge with this host's key.
//
// The nonce is checked for shape before it is signed. Signing whatever arrived would
// work — a signature over the wrong bytes simply fails verification — but refusing early
// means a control plane that started sending a different format produces a clear local
// error rather than an authentication failure that looks like a revoked key.
func AnswerChallenge(key ed25519.PrivateKey, hostID string, challenge Challenge) (Answer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Answer{}, fmt.Errorf("%w", ErrNoHostKey)
	}
	if len(challenge.Nonce) != ChallengeBytes*2 {
		return Answer{}, fmt.Errorf(
			"%w: nonce is %d characters, want %d hex-encoded bytes",
			ErrChallengeMalformed, len(challenge.Nonce), ChallengeBytes*2,
		)
	}
	if !isHex(challenge.Nonce) {
		return Answer{}, fmt.Errorf("%w: nonce is not hexadecimal", ErrChallengeMalformed)
	}
	if hostID == "" {
		return Answer{}, fmt.Errorf("%w: this agent does not know its own host id", ErrNoHostKey)
	}

	signature := ed25519.Sign(key, challengeBytes(hostID, challenge.Nonce))

	return Answer{
		HostID:    hostID,
		Nonce:     challenge.Nonce,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// VerifyAnswer checks an answer against a public key.
//
// Present so the agent's own tests can drive both halves, and so a future
// agent-to-privd or agent-to-agent path has one implementation to reuse rather than a
// second one to keep in step. The control plane's copy is authoritative for a real
// connection.
func VerifyAnswer(public ed25519.PublicKey, answer Answer) bool {
	if len(public) != ed25519.PublicKeySize {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(answer.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(public, challengeBytes(answer.HostID, answer.Nonce), signature)
}

func isHex(value string) bool {
	for index := 0; index < len(value); index++ {
		c := value[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			// Lower case only. A control plane that sent upper-case hex would produce a
			// different byte string here than the one it signed against, and accepting
			// both would mean two encodings of one nonce.
			return false
		}
	}
	return true
}
