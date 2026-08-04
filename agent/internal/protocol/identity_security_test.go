// The agent's half of transport authentication (RL-M2-005, A-04).
//
// The cross-language check is the point of this file. Two independent implementations of
// a byte layout can each be self-consistent and still disagree, and the failure arrives
// on a host as "the agent cannot authenticate" — which reads as a network problem, not an
// encoding one. The vectors were produced by src/crypto/host_identity.ts; these tests
// prove Go signs the same bytes.
package protocol

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type identityVectorFile struct {
	Domain          string `json:"domain"`
	HostID          string `json:"host_id"`
	PublicKeyRawHex string `json:"public_key_raw_hex"`
	Vectors         []struct {
		Name      string `json:"name"`
		HostID    string `json:"host_id"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
		SignedHex string `json:"signed_hex"`
	} `json:"vectors"`
}

func loadIdentityVectors(t *testing.T) identityVectorFile {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "identity_vectors.json"))
	if err != nil {
		t.Fatalf("reading the vectors: %v\nRun ./scripts/gen-envelope-vectors", err)
	}

	var file identityVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing the vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the vector file is empty, so every test reading it would pass vacuously")
	}
	return file
}

func TestTheSignedBytesMatchTheControlPlane(t *testing.T) {
	file := loadIdentityVectors(t)

	if file.Domain != IdentityDomain {
		t.Fatalf("the vectors were generated for domain %q, this agent uses %q",
			file.Domain, IdentityDomain)
	}

	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			want := vector.SignedHex
			got := hex.EncodeToString(challengeBytes(vector.HostID, vector.Nonce))

			if got == want {
				return
			}

			offset := 0
			for offset < len(want) && offset < len(got) && want[offset] == got[offset] {
				offset++
			}
			t.Errorf("signed bytes differ from the control plane's at hex offset %d (byte %d)\n"+
				"  TypeScript: ...%s\n  Go:         ...%s",
				offset, offset/2,
				want[max(0, offset-16):min(len(want), offset+32)],
				got[max(0, offset-16):min(len(got), offset+32)])
		})
	}
}

func TestTheControlPlanesSignaturesVerifyHere(t *testing.T) {
	file := loadIdentityVectors(t)

	raw, err := hex.DecodeString(file.PublicKeyRawHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("the vector public key is not %d bytes of hex", ed25519.PublicKeySize)
	}
	public := ed25519.PublicKey(raw)

	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			answer := Answer{HostID: vector.HostID, Nonce: vector.Nonce, Signature: vector.Signature}
			if !VerifyAnswer(public, answer) {
				t.Error("a signature the control plane produced does not verify here")
			}
		})
	}
}

func TestAnAnswerThisAgentProducesVerifiesUnderItsOwnKey(t *testing.T) {
	// The round trip, so the two tests above cannot both pass against a broken signer
	// that happens to agree with a broken verifier.
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	nonce := strings.Repeat("ab", ChallengeBytes)
	answer, err := AnswerChallenge(private, "a-host", Challenge{Nonce: nonce})
	if err != nil {
		t.Fatalf("AnswerChallenge: %v", err)
	}

	if !VerifyAnswer(public, answer) {
		t.Error("an answer this agent produced does not verify under its own key")
	}

	// And a different key must not verify it, or the test above proves nothing.
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a second key: %v", err)
	}
	if VerifyAnswer(other, answer) {
		t.Error("an answer verified under a key that did not sign it")
	}
}

func TestAnAnswerIsNotAnInstructionAndViceVersa(t *testing.T) {
	// Domain separation, checked on this side too. The two are different keys today, and
	// "different keys today" is a property of current code rather than of the format.
	if IdentityDomain == InstructionDomain {
		t.Fatal("the identity and instruction domains are identical, so one signature could serve as both")
	}

	identity := challengeBytes("a-host", strings.Repeat("c", ChallengeBytes*2))
	instruction := canonicalBytes(Envelope{
		Operation:    "host.health.report",
		Arguments:    nil,
		Nonce:        strings.Repeat("c", 64),
		IssuedAt:     1,
		ExpiresAt:    2,
		TargetHostID: "a-host",
	})

	a, b := hex.EncodeToString(identity), hex.EncodeToString(instruction)
	if strings.HasPrefix(a, b) || strings.HasPrefix(b, a) {
		t.Error("one signed byte string is a prefix of the other, which is the shape the confusion takes")
	}
	if !strings.HasPrefix(string(identity), IdentityDomain) {
		t.Error("the signed bytes do not begin with the identity domain")
	}
	if identity[len(IdentityDomain)] != 0 {
		t.Error("the domain separator is not NUL-terminated, so it could run into a field")
	}
}

func TestAMalformedChallengeIsRefusedRatherThanSigned(t *testing.T) {
	// Signing whatever arrived would also be safe — a signature over the wrong bytes
	// simply fails verification — but refusing early means a control plane that changed
	// format produces a clear local error instead of an authentication failure that looks
	// exactly like a revoked key.
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	cases := map[string]string{
		"too short":  "abcd",
		"too long":   strings.Repeat("a", ChallengeBytes*2+2),
		"not hex":    strings.Repeat("z", ChallengeBytes*2),
		"upper case": strings.Repeat("A", ChallengeBytes*2),
		"empty":      "",
	}

	for name, nonce := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := AnswerChallenge(private, "a-host", Challenge{Nonce: nonce}); !errors.Is(err, ErrChallengeMalformed) {
				t.Errorf("got %v, want ErrChallengeMalformed", err)
			}
		})
	}
}

func TestAnAgentWithNoKeyOrNoHostIdRefusesToAnswer(t *testing.T) {
	// Fails closed, and says which is missing. An agent that answered with a zero
	// signature would be refused by the control plane for the wrong reason, and the
	// operator would go looking at revocation rather than at enrolment.
	nonce := strings.Repeat("ab", ChallengeBytes)

	if _, err := AnswerChallenge(nil, "a-host", Challenge{Nonce: nonce}); !errors.Is(err, ErrNoHostKey) {
		t.Error("an agent with no key produced an answer")
	}

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if _, err := AnswerChallenge(private, "", Challenge{Nonce: nonce}); !errors.Is(err, ErrNoHostKey) {
		t.Error("an agent that does not know its own host id produced an answer")
	}
}

func TestChangingEitherFieldChangesTheSignedBytes(t *testing.T) {
	// Length prefixes exist to remove exactly this ambiguity.
	if hex.EncodeToString(challengeBytes("ab", "c")) == hex.EncodeToString(challengeBytes("a", "bc")) {
		t.Error("two different (host, nonce) pairs sign the same bytes, so one signature covers both")
	}
	if hex.EncodeToString(challengeBytes("a", "b")) == hex.EncodeToString(challengeBytes("a", "c")) {
		t.Error("the nonce is not covered by the signed bytes")
	}
	if hex.EncodeToString(challengeBytes("a", "b")) == hex.EncodeToString(challengeBytes("b", "b")) {
		t.Error("the host id is not covered by the signed bytes")
	}
}
