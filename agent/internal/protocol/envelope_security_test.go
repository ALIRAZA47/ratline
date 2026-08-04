// Envelope verification, the agent's side (RL-M2-003).
//
// The tracker declared this artefact as test/security/envelope_verification_test.go,
// which cannot work for the same reason RL-M2-002's could not: Go requires a
// _test.go file in the package it tests, and test/ is outside the agent module, so a
// file there would never be compiled or run. Recorded at its real location.
//
// The centre of this file is TestVerificationOrder. Every other test here checks
// that a bad envelope is refused; that one checks it is refused for the RIGHT
// REASON, which is the only way the ordering requirement in ADR 0002 can be
// verified rather than asserted in a comment.
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
	"time"
)

// --- vectors ---------------------------------------------------------------

type vectorFile struct {
	Domain          string `json:"domain"`
	HostID          string `json:"host_id"`
	PublicKeyRawHex string `json:"public_key_raw_hex"`
	Vectors         []struct {
		Name         string   `json:"name"`
		Why          string   `json:"why"`
		Envelope     Envelope `json:"envelope"`
		CanonicalHex string   `json:"canonical_hex"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "envelope_vectors.json"))
	if err != nil {
		t.Fatalf("reading the vectors: %v\nRun ./scripts/gen-envelope-vectors", err)
	}

	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing the vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the vector file is empty, so every test reading it would pass vacuously")
	}
	return file
}

func publicKeyFrom(t *testing.T, file vectorFile) ed25519.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(file.PublicKeyRawHex)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("the vector public key is not %d bytes of hex", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw)
}

// TestTheCanonicalEncodingMatchesTypeScript is the cross-language check.
//
// Two independent implementations of a canonical encoding is exactly the situation
// where both sides can be self-consistent and still disagree, and the failure would
// arrive on a host as "the agent refuses every instruction" — which reads as a
// transport problem, not an encoding one. These vectors were produced by
// src/agent/envelope.ts; this test proves Go produces the same bytes.
func TestTheCanonicalEncodingMatchesTypeScript(t *testing.T) {
	file := loadVectors(t)

	if file.Domain != InstructionDomain {
		t.Fatalf("the vectors were generated for domain %q, this agent uses %q",
			file.Domain, InstructionDomain)
	}

	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			want := vector.CanonicalHex
			got := hex.EncodeToString(canonicalBytes(vector.Envelope))

			if got == want {
				return
			}

			// Report WHERE they diverge. "The bytes differ" sends the reader off to
			// reimplement one encoder to find out which; the offset and the two
			// fragments around it usually name the field immediately.
			offset := 0
			for offset < len(want) && offset < len(got) && want[offset] == got[offset] {
				offset++
			}
			t.Errorf("canonical encoding differs from TypeScript's at hex offset %d (byte %d)\n"+
				"  reason this vector exists: %s\n"+
				"  TypeScript: ...%s\n"+
				"  Go:         ...%s",
				offset, offset/2, vector.Why,
				want[max(0, offset-16):min(len(want), offset+32)],
				got[max(0, offset-16):min(len(got), offset+32)])
		})
	}
}

func TestEveryVectorVerifiesAndIsAccepted(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}

	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			// `now` inside the envelope's window, since the vectors carry fixed
			// stamps. Using time.Now() would make this test start failing on a date,
			// which is the kind of failure that gets a suite disabled.
			now := time.UnixMilli(vector.Envelope.IssuedAt).Add(time.Second)
			store := OpenNonceStore(filepath.Join(t.TempDir(), "nonces"))

			operation, err := Verify(vector.Envelope, keys, file.HostID, store, now)
			if err != nil {
				t.Fatalf("a valid envelope was refused: %v", err)
			}
			if operation.Name != vector.Envelope.Operation {
				t.Errorf("Verify returned operation %q, want %q", operation.Name, vector.Envelope.Operation)
			}
		})
	}
}

// --- the ordering requirement ---------------------------------------------

// TestVerificationOrder is the reason this file exists.
//
// ADR 0002 fixes the order: signature, target, expiry, nonce, then arguments. The
// way to test an ORDER is to present an envelope that is wrong in two ways at once
// and assert which failure is reported — a test that only checks "refused" passes
// for every possible ordering, including the dangerous ones.
func TestVerificationOrder(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope // single-argument: site.user.create slug=blog
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	t.Run("signature before arguments", func(t *testing.T) {
		// Both the signature and the arguments are wrong. If the argument error
		// surfaces, an unauthenticated caller has reached every regexp and length
		// check in the agent — the largest attack surface it has — without a key.
		broken := valid
		broken.Arguments = map[string]string{"slug": "NOT A SLUG!!"}

		_, err := Verify(broken, keys, file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)

		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature. An argument error here would mean the "+
				"argument validators are reachable without a valid signature", err)
		}
		if strings.Contains(err.Error(), "does not match") {
			t.Error("the error mentions argument validation, so arguments were interpreted first")
		}
	})

	t.Run("signature before target", func(t *testing.T) {
		// Wrong signature AND wrong host. Target-first would let an unauthenticated
		// caller find this host's identity by sending guesses and watching which one
		// stops being refused as misaddressed.
		broken := valid
		broken.Signature = forgeSignature(valid.Signature)

		_, err := Verify(broken, keys, "some-other-host", OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)

		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("got %v, want ErrBadSignature", err)
		}
	})

	t.Run("target before expiry", func(t *testing.T) {
		// Correctly signed, wrong host, and expired. Reporting expiry first would
		// leak this host's clock offset to somebody holding a valid-but-misaddressed
		// envelope, which is what a replay needs to be aimed.
		afterExpiry := time.UnixMilli(valid.ExpiresAt).Add(time.Minute)

		_, err := Verify(valid, keys, "some-other-host", OpenNonceStore(filepath.Join(t.TempDir(), "n")), afterExpiry)

		if !errors.Is(err, ErrWrongHost) {
			t.Fatalf("got %v, want ErrWrongHost", err)
		}
	})

	t.Run("expiry before nonce", func(t *testing.T) {
		// An expired envelope must not consume a slot in the bounded replay store —
		// otherwise flooding dead envelopes is a cheap way to exhaust it.
		store := OpenNonceStore(filepath.Join(t.TempDir(), "nonces"))
		afterExpiry := time.UnixMilli(valid.ExpiresAt).Add(time.Minute)

		_, err := Verify(valid, keys, file.HostID, store, afterExpiry)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("got %v, want ErrExpired", err)
		}

		size, err := store.Size()
		if err != nil {
			t.Fatalf("Size: %v", err)
		}
		if size != 0 {
			t.Errorf("the nonce store holds %d entries after an EXPIRED envelope was refused. "+
				"An expired envelope must not consume replay memory, or flooding dead "+
				"envelopes exhausts the store", size)
		}
	})

	t.Run("nonce before arguments", func(t *testing.T) {
		// Arguments last. A replayed envelope is refused without its arguments being
		// re-parsed, so a replay cannot be used to hammer the validators either.
		store := OpenNonceStore(filepath.Join(t.TempDir(), "nonces"))

		if _, err := Verify(valid, keys, file.HostID, store, inWindow); err != nil {
			t.Fatalf("first delivery was refused: %v", err)
		}
		if _, err := Verify(valid, keys, file.HostID, store, inWindow); !errors.Is(err, ErrReplayed) {
			t.Fatalf("second delivery: got %v, want ErrReplayed", err)
		}
	})
}

// --- acceptance 3: addressed to another host ------------------------------

func TestAnEnvelopeAddressedToAnotherHostIsRefused(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	for _, wrong := range []string{
		"",
		"another-host",
		file.HostID + "x",
		strings.ToUpper(file.HostID),
		" " + file.HostID,
		file.HostID[:len(file.HostID)-1],
	} {
		t.Run(wrong, func(t *testing.T) {
			_, err := Verify(valid, keys, wrong, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)
			if !errors.Is(err, ErrWrongHost) {
				t.Errorf("host %q: got %v, want ErrWrongHost", wrong, err)
			}
		})
	}

	// The error must not disclose the expected id. It reaches a log, and a log is
	// read by more people than hold the host's identity.
	_, err := Verify(valid, keys, "another-host", OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)
	if err != nil && strings.Contains(err.Error(), file.HostID) {
		t.Errorf("the refusal names the expected host id:\n%v", err)
	}
}

// --- acceptance 4: expired or replayed ------------------------------------

func TestExpiryIsRefusedAtEveryBoundary(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope

	cases := []struct {
		name string
		now  time.Time
		want error
	}{
		{"one millisecond before expiry", time.UnixMilli(valid.ExpiresAt - 1), nil},
		// Exactly at expiry is REFUSED. An inclusive boundary is a millisecond of
		// validity nobody reasons about, and "expires at T" reads as "not valid at T".
		{"exactly at expiry", time.UnixMilli(valid.ExpiresAt), ErrExpired},
		{"one millisecond after", time.UnixMilli(valid.ExpiresAt + 1), ErrExpired},
		{"long after", time.UnixMilli(valid.ExpiresAt).Add(24 * time.Hour), ErrExpired},
		// Clock skew: an agent whose clock is far behind sees the issue stamp in its
		// future. A small tolerance is allowed; a large one would let a signer extend
		// the replay window at will.
		{"agent clock far behind", time.UnixMilli(valid.IssuedAt).Add(-time.Hour), ErrNotYetValid},
		{"agent clock slightly behind", time.UnixMilli(valid.IssuedAt).Add(-10 * time.Second), nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Verify(valid, keys, file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), c.now)
			if c.want == nil {
				if err != nil {
					t.Errorf("got %v, want acceptance", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Errorf("got %v, want %v", err, c.want)
			}
		})
	}
}

// TestReplayAfterRestartIsRefused is required explicitly by ADR 0002: "Nonces
// persist across agent restarts for at least the validity window... Replay after
// restart is tested explicitly."
//
// An in-memory set would make replay protection a function of the agent's uptime:
// restart it — or crash it, which an attacker may be able to arrange — and every
// instruction signed in the last five minutes becomes replayable.
func TestReplayAfterRestartIsRefused(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	path := filepath.Join(t.TempDir(), "nonces")
	// The store's clock is pinned to the envelope's window. The vectors carry fixed
	// stamps so the encoding is reproducible, so a store pruning against wall-clock
	// time would drop the nonce as months-expired the moment it reloaded — and the
	// symptom would be identical to the nonce never having been written. That is the
	// confusion that made the store's clock injectable in the first place.
	clock := func() time.Time { return inWindow }

	// First agent process.
	if _, err := Verify(valid, keys, file.HostID, OpenNonceStoreAt(path, clock), inWindow); err != nil {
		t.Fatalf("first delivery was refused: %v", err)
	}

	// A NEW store over the same path is the restart: different object, no shared
	// memory, only what reached the disk.
	restarted := OpenNonceStoreAt(path, clock)
	if _, err := Verify(valid, keys, file.HostID, restarted, inWindow); !errors.Is(err, ErrReplayed) {
		t.Fatalf("after restart: got %v, want ErrReplayed. The nonce store did not survive, "+
			"so replay protection lasts only as long as the process", err)
	}

	// And a third process, to rule out the second having worked by accident because
	// of some state the second object happened to hold.
	if _, err := Verify(valid, keys, file.HostID, OpenNonceStoreAt(path, clock), inWindow); !errors.Is(err, ErrReplayed) {
		t.Error("a third process accepted the replay")
	}

	// The other half of the same property: once the window HAS passed, the nonce is
	// forgotten — which is what keeps the store bounded. Asserted here rather than
	// separately, because "it persists" and "it is eventually dropped" are the two
	// halves of one design and a test for either alone can be satisfied by a store
	// that gets the other wrong.
	afterExpiry := func() time.Time { return time.UnixMilli(valid.ExpiresAt).Add(time.Hour) }
	pruned := OpenNonceStoreAt(path, afterExpiry)
	size, err := pruned.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 0 {
		t.Errorf("the store still holds %d entries after every nonce expired; it is not bounded", size)
	}
}

// --- signature and key handling -------------------------------------------

func TestTheKeyIdCannotSelectTheVerificationKey(t *testing.T) {
	// `key_id` is attacker-controlled. If it chose the key, naming a revoked key
	// would be enough to have it used — which is the whole of the vulnerability that
	// key rotation exists to close.
	file := loadVectors(t)
	real := publicKeyFrom(t, file)
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	// A correct signature with a key_id naming a key the agent does not hold must
	// still verify: the hint is ignored, and the signature is what decides.
	lying := valid
	lying.KeyID = "a-key-that-does-not-exist"
	if _, err := Verify(lying, []AcceptedKey{{KeyID: "vector-key-1", Public: real}},
		file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow); err != nil {
		t.Errorf("a correctly signed envelope was refused because its key_id hint was wrong: %v", err)
	}

	// And a wrong signature whose key_id names a key the agent DOES hold must fail.
	forged := valid
	forged.Signature = forgeSignature(valid.Signature)
	forged.KeyID = "vector-key-1"
	if _, err := Verify(forged, []AcceptedKey{{KeyID: "vector-key-1", Public: real}},
		file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a forged signature was accepted: %v", err)
	}
}

func TestRotationOverlapAcceptsBothKeys(t *testing.T) {
	// ADR 0002: "agents accept both the outgoing and incoming key for a configured
	// period, so rotation never requires a flag-day."
	file := loadVectors(t)
	real := publicKeyFrom(t, file)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a second key: %v", err)
	}

	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	// The signing key second in the list, so passing does not depend on order.
	keys := []AcceptedKey{{KeyID: "incoming", Public: other}, {KeyID: "vector-key-1", Public: real}}
	if _, err := Verify(valid, keys, file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow); err != nil {
		t.Errorf("an envelope signed by the second accepted key was refused: %v", err)
	}
}

func TestAnAgentWithNoKeysRefusesEverything(t *testing.T) {
	// Fails closed. A range over an empty slice already falls through to "no key
	// matched", but relying on that is relying on a coincidence.
	file := loadVectors(t)
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	_, err := Verify(valid, nil, file.HostID, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("got %v, want ErrBadSignature for an agent holding no keys", err)
	}
}

func TestATamperedFieldInvalidatesTheSignature(t *testing.T) {
	// The point of signing the canonical bytes: changing any covered field must
	// break the signature. Each case names the field, so a partial encoding — one
	// that forgot to cover a field — is caught by whichever case stops failing.
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	tampered := map[string]func(Envelope) Envelope{
		"operation":      func(e Envelope) Envelope { e.Operation = "site.user.remove"; return e },
		"argument value": func(e Envelope) Envelope { e.Arguments = map[string]string{"slug": "other"}; return e },
		"argument name":  func(e Envelope) Envelope { e.Arguments = map[string]string{"other": "blog"}; return e },
		"nonce":          func(e Envelope) Envelope { e.Nonce = strings.Repeat("9", 64); return e },
		"issued_at":      func(e Envelope) Envelope { e.IssuedAt -= 1000; return e },
		"expires_at":     func(e Envelope) Envelope { e.ExpiresAt += 1000; return e },
		"target_host_id": func(e Envelope) Envelope { e.TargetHostID = "another-host"; return e },
	}

	for field, mutate := range tampered {
		t.Run(field, func(t *testing.T) {
			broken := mutate(valid)
			// The host is set to whatever the envelope claims, so a target change
			// cannot be refused as misaddressed before the signature is checked —
			// otherwise this case would pass without the signature covering the field.
			host := broken.TargetHostID

			_, err := Verify(broken, keys, host, OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)
			if !errors.Is(err, ErrBadSignature) {
				t.Errorf("changing %s did not break the signature: got %v. That field is not "+
					"covered by the canonical encoding", field, err)
			}
		})
	}
}

// --- parsing --------------------------------------------------------------

func TestParseRefusesUnknownFieldsAndTrailingData(t *testing.T) {
	// An ignored field is how a payload aimed at a future agent version gets
	// accepted by the present one — and the signature would still verify, because
	// canonicalBytes only covers fields it knows about.
	base := `{"operation":"host.inventory.collect","arguments":{},"nonce":"` +
		strings.Repeat("a", 64) + `","issued_at":1,"expires_at":2,"target_host_id":"h",` +
		`"signature":"c2ln","key_id":"k"}`

	if _, err := ParseEnvelope([]byte(base)); err != nil {
		t.Fatalf("a well-formed envelope failed to parse: %v", err)
	}

	withExtra := strings.Replace(base, `"key_id":"k"`, `"key_id":"k","escalate":true`, 1)
	if _, err := ParseEnvelope([]byte(withExtra)); !errors.Is(err, ErrMalformed) {
		t.Errorf("an unknown field was accepted: %v", err)
	}

	if _, err := ParseEnvelope([]byte(base + base)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing data was accepted: %v", err)
	}
}

func TestMalformedEnvelopesAreRefusedBeforeAnythingElse(t *testing.T) {
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope
	inWindow := time.UnixMilli(valid.IssuedAt).Add(time.Second)

	cases := map[string]func(Envelope) Envelope{
		"short nonce":         func(e Envelope) Envelope { e.Nonce = "abcd"; return e },
		"non-hex nonce":       func(e Envelope) Envelope { e.Nonce = strings.Repeat("z", 64); return e },
		"no signature":        func(e Envelope) Envelope { e.Signature = ""; return e },
		"no target":           func(e Envelope) Envelope { e.TargetHostID = ""; return e },
		"no stamps":           func(e Envelope) Envelope { e.IssuedAt, e.ExpiresAt = 0, 0; return e },
		"expiry before issue": func(e Envelope) Envelope { e.ExpiresAt = e.IssuedAt - 1; return e },
		"signature not base64": func(e Envelope) Envelope {
			e.Signature = "not base64 !!"
			return e
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Verify(mutate(valid), keys, file.HostID,
				OpenNonceStore(filepath.Join(t.TempDir(), "n")), inWindow)
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("got %v, want ErrMalformed", err)
			}
		})
	}
}

func TestAValidityWindowLongerThanTheAgentAllowsIsRefused(t *testing.T) {
	// Enforced by the AGENT, not only by the control plane. A signed envelope
	// claiming a one-year window would otherwise require a one-year nonce store on
	// this host — so how much replay memory a host holds would be decided by whoever
	// signs rather than by the host.
	file := loadVectors(t)
	keys := []AcceptedKey{{KeyID: "vector-key-1", Public: publicKeyFrom(t, file)}}
	valid := file.Vectors[1].Envelope

	// Re-signing is not possible here (no private key in this test), so the
	// signature will fail too — which means this must be checked at the freshness
	// layer directly rather than through Verify.
	long := valid
	long.ExpiresAt = long.IssuedAt + int64(24*time.Hour/time.Millisecond)

	err := checkFreshness(long, time.UnixMilli(long.IssuedAt).Add(time.Second))
	if !errors.Is(err, ErrValidityTooLong) {
		t.Errorf("got %v, want ErrValidityTooLong", err)
	}

	_ = keys
}

// forgeSignature changes one byte of the signature while keeping it valid base64.
//
// The first version flipped the LAST character, which on a 64-byte Ed25519
// signature is the "=" pad — so the result was not base64 at all and three tests
// reported ErrMalformed where they were asserting ErrBadSignature. A forgery test
// that produces unparseable input is not testing forgery.
func forgeSignature(signature string) string {
	if len(signature) < 12 {
		return "AAAA"
	}
	at := 10 // well inside the payload, never the padding
	replacement := byte('A')
	if signature[at] == 'A' {
		replacement = 'B'
	}
	return signature[:at] + string(replacement) + signature[at+1:]
}
