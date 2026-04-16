// go:build yubihsm
package signer

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/tellor-io/bridge-remote-signer/signer/yubihsm"
)

func init() {
	RegisterBackend("yubihsm", newYubiHSMSignerFromConfig)
}

// newYubiHSMSignerFromConfig is the BackendFactory for the YubiHSM backend.
func newYubiHSMSignerFromConfig(ctx context.Context, raw map[string]any) (Signer, error) {
	cfg, err := ParseYubiHSMConfig(raw)
	if err != nil {
		return nil, err
	}
	return NewYubiHSMSigner(ctx, cfg)
}

// YubiHSMSigner implements Signer.
type YubiHSMSigner struct {
	session          *yubihsm.Session
	keyID            uint16
	compressedPubKey []byte
	mu               sync.Mutex
}

// NewYubiHSMSigner connects to a YubiHSM2, authenticates, validates the key,
// and returns a ready-to-use signer.
func NewYubiHSMSigner(_ context.Context, cfg YubiHSMConfig) (*YubiHSMSigner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid yubihsm config: %w", err)
	}

	password, err := cfg.ResolvePassword()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve yubihsm password: %w", err)
	}

	connURL := cfg.ConnectorURL()

	authKeyID := cfg.AuthKeyID
	if authKeyID == 0 {
		authKeyID = 1 // factory default
	}

	// Connect and authenticate in one call. The wrapper handles
	// yh_init -> yh_init_connector -> yh_connect -> yh_create_session_derived -> yh_authenticate_session.
	session, err := yubihsm.Connect(connURL, uint16(authKeyID), password)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to YubiHSM at %q: %w", connURL, err)
	}

	compressedPubKey, err := fetchYubiPublicKey(session, uint16(cfg.KeyID))
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to fetch public key for 0x%04x: %w", cfg.KeyID, err)
	}

	return &YubiHSMSigner{
		session:          session,
		keyID:            uint16(cfg.KeyID),
		compressedPubKey: compressedPubKey,
	}, nil
}

// fetchYubiPublicKey retrieves the public key from the HSM
func fetchYubiPublicKey(session *yubihsm.Session, keyID uint16) ([]byte, error) {
	// fetchYubiPublicKey retrieves the public key from the HSM.
	// TODO: Verify the exact output format against Yubico SDK documentation
	// or by testing with real hardware. Based on python-yubihsm
	// and yubihsm.rs implementations, it appears to be the raw X||Y point
	// (64 bytes, no 0x04 prefix), but this needs verification.
	raw, err := session.GetPublicKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("GetPublicKey failed: %w", err)
	}

	if len(raw) != 64 {
		return nil, fmt.Errorf(
			"expected 64-byte secp256k1 uncompressed point, got %d bytes; "+
				"is this key secp256k1 (AlgoECK256)?",
			len(raw),
		)
	}

	x := new(big.Int).SetBytes(raw[:32])
	y := new(big.Int).SetBytes(raw[32:64])

	compressed := elliptic.MarshalCompressed(secp256k1.S256(), x, y)
	return compressed, nil
}

// Sign implements Signer.
func (s *YubiHSMSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("Sign: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hash := sha256.Sum256(msg)

	// SignECDSA returns DER-encoded signature bytes.
	der, err := s.session.SignECDSA(s.keyID, hash[:])
	if err != nil {
		return nil, fmt.Errorf("Sign: YubiHSM SignECDSA failed: %w", err)
	}

	// Convert DER to Ethereum format.
	sig, err := derToEthSig(der, hash[:], s.compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}

	return sig, nil
}

// GetPublicKey implements Signer.
// Returns a copy of the cached compressed 33-byte secp256k1 public key.
func (s *YubiHSMSigner) GetPublicKey(_ context.Context) ([]byte, error) {
	out := make([]byte, len(s.compressedPubKey))
	copy(out, s.compressedPubKey)
	return out, nil
}

// Close cleanly shuts down the YubiHSM session and disconnects.
// Should be called during graceful server shutdown.
func (s *YubiHSMSigner) Close() error {
	if s.session != nil {
		s.session.Close()
	}
	return nil
}
