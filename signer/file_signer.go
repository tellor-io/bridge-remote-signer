package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/term"
)

func init() {
	RegisterBackend("file", newFileSignerFromConfig)
}

// newFileSignerFromConfig is the BackendFactory for the file backend.
// It extracts the key_path from the raw config and creates a FileSigner.
func newFileSignerFromConfig(_ context.Context, raw map[string]any) (Signer, error) {
	keyPath, ok := raw["key_path"].(string)
	if !ok || keyPath == "" {
		return nil, errors.New("signer.key_path is required when backend is \"file\"")
	}
	pwFile, _ := raw["password_file"].(string)

	password, err := loadFilePassword(keyPath, pwFile)
	if err != nil {
		return nil, err
	}

	return NewFileSigner(keyPath, password)
}

// loadFilePassword resolves the password used to decrypt the key file.
// Precedence:
//
//   - pwFile set: read it from disk. Enforce 0600 perms (same bar as the
//     key file itself, since this file is equivalent to the key once an
//     attacker has it).
//   - pwFile empty, key file is encrypted: prompt on stderr. Fail with a
//     useful message if stdin is not a terminal (systemd, docker, CI).
//   - pwFile empty, key file is plaintext: return "" (no password needed).
func loadFilePassword(keyPath, pwFile string) (string, error) {
	if pwFile != "" {
		info, err := os.Stat(pwFile)
		if err != nil {
			return "", fmt.Errorf("cannot stat password file: %w", err)
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			return "", fmt.Errorf(
				"password file %s has permissions %04o; must not be readable by group or others (expected 0600)",
				pwFile, perm,
			)
		}
		data, err := os.ReadFile(pwFile)
		if err != nil {
			return "", fmt.Errorf("failed to read password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	encrypted, err := IsKeyFileEncrypted(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to check if key file is encrypted: %w", err)
	}
	if !encrypted {
		return "", nil
	}

	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", fmt.Errorf(
			"key file %s is encrypted but stdin is not a terminal; set signer.password_file in config",
			keyPath,
		)
	}

	fmt.Fprint(os.Stderr, "Enter password for key file: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password from terminal: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	return strings.TrimSpace(string(passBytes)), nil
}

// FileSigner implements Signer using a secp256k1 private key loaded from disk.
// The key is loaded once at startup and held in memory — it is never re-read
// from disk during operation.
type FileSigner struct {
	privateKey       *ecdsa.PrivateKey
	compressedPubKey []byte     // 33-byte compressed secp256k1 public key, cached at startup
	mu               sync.Mutex // protects against concurrent Sign calls
}

// NewFileSigner loads a private key from the given file path.
// The password parameter is only used if the key file is encrypted.
// Pass an empty string for plaintext key files.
func NewFileSigner(keyPath string, password string) (*FileSigner, error) {
	if keyPath == "" {
		return nil, errors.New("key_path is required for file signer backend")
	}

	privateKey, err := LoadPrivateKey(keyPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key from %q: %w", keyPath, err)
	}

	compressedPubKey := crypto.CompressPubkey(&privateKey.PublicKey)

	return &FileSigner{
		privateKey:       privateKey,
		compressedPubKey: compressedPubKey,
	}, nil
}

// Sign implements Signer.
// Returns a 65-byte secp256k1 signature in Ethereum format: r || s || v, where v is 27 or 28.
func (s *FileSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("Sign: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// To produce signatures compatible with both the keyring signer and the contract,
	// we must SHA256-hash the input before signing.
	hash := sha256.Sum256(msg)

	sig, err := crypto.Sign(hash[:], s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("Sign: secp256k1 signing failed: %w", err)
	}

	// go-ethereum returns v as 0 or 1 , adjust to 27 or 28 for ecrecover.
	sig[64] += 27
	return sig, nil
}

// GetPublicKey implements Signer.
// Returns a copy of the cached compressed 33-byte secp256k1 public key.
func (s *FileSigner) GetPublicKey(_ context.Context) ([]byte, error) {
	out := make([]byte, len(s.compressedPubKey))
	copy(out, s.compressedPubKey)
	return out, nil
}
