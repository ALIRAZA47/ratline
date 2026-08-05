// Where the connection's configuration comes from, and what it refuses (RL-M2-006).
//
// Environment variables rather than a configuration file, for now, because systemd already
// has a good answer for both — EnvironmentFile= for the values and LoadCredential= for the
// key — and inventing a parser for a file format is work that buys nothing until there is
// something to put in it that is not a scalar. The unit file RL-M2-010 installs is where
// these get set.
package transport

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// The environment the agent reads. Named as constants because two of them appear in error
// messages an operator will act on, and a typo in a message that tells somebody which
// variable to set is worse than no message.
const (
	EnvControlPlane = "RATLINE_CONTROL_PLANE"
	EnvHostID       = "RATLINE_HOST_ID"
	EnvHostKey      = "RATLINE_HOST_KEY"
	EnvCAFile       = "RATLINE_CONTROL_PLANE_CA"
)

// ErrKeyExposed means the host key is readable by somebody other than its owner.
var ErrKeyExposed = errors.New("the host key file is readable beyond its owner")

// ConfigFromEnvironment builds a Config, or explains what is missing.
//
// getenv is a parameter rather than a call to os.Getenv so that a test can drive it
// without mutating the process environment — which matters more than it looks, because
// t.Setenv makes a test unable to run in parallel and a security suite that cannot run in
// parallel gets slower until somebody deletes part of it.
func ConfigFromEnvironment(getenv func(string) string, log io.Writer) (Config, error) {
	keyPath := getenv(EnvHostKey)
	if keyPath == "" {
		return Config{}, fmt.Errorf(
			"%w: %s names the file holding this host's Ed25519 key. Enrolment writes it; "+
				"an agent without one has nothing to identify itself with",
			ErrNotConfigured, EnvHostKey)
	}

	key, err := LoadHostKey(keyPath)
	if err != nil {
		return Config{}, err
	}

	return Config{
		ControlPlane: getenv(EnvControlPlane),
		HostID:       getenv(EnvHostID),
		Key:          key,
		CAFile:       getenv(EnvCAFile),
		Log:          log,
	}, nil
}

// LoadHostKey reads an Ed25519 private key from a PKCS#8 PEM file.
//
// # The permission check is the point of this function
//
// The key IS the host's identity to the control plane. A key file readable by any local
// account means any local account can authenticate as this host, receive the instructions
// and secrets destined for its sites, and lie about its inventory and health — which is
// most of what ADR 0002 says a stolen host key buys an attacker, handed over for free by a
// file mode.
//
// So a key readable by group or other is refused rather than warned about. A warning would
// be the wrong shape: the agent would keep running, the host would look healthy, and the
// line would scroll past. The refusal names the mode and the fix.
func LoadHostKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the host key at %s: %w", ErrNotConfigured, path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf(
			"%w: %s is mode %04o. The key is this host's whole identity to the control plane, "+
				"so anybody who can read it can authenticate as this host. Fix with "+
				"chmod 0600 and chown to the agent's user",
			ErrKeyExposed, path, mode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading the host key at %s: %w", ErrNotConfigured, path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: %s is not PEM. Enrolment writes a PKCS#8 private key",
			ErrNotConfigured, path)
	}
	if block.Type != "PRIVATE KEY" {
		// Named, because "EC PRIVATE KEY" or "OPENSSH PRIVATE KEY" here means somebody
		// pointed the agent at an SSH key, which is a plausible mistake with a specific fix.
		return nil, fmt.Errorf(
			"%w: %s holds a %q block, and the host key is a PKCS#8 \"PRIVATE KEY\"",
			ErrNotConfigured, path, block.Type)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %s could not be parsed as PKCS#8: %w", ErrNotConfigured, path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		// An RSA or ECDSA key would parse and then fail to sign anything the control plane
		// accepts. Refusing here says which of the two things is wrong.
		return nil, fmt.Errorf(
			"%w: %s holds a %T. The host key is Ed25519 — the control plane verifies nothing else",
			ErrNotConfigured, path, parsed)
	}
	return key, nil
}
