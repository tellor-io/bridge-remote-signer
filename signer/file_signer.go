package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func init() {
	RegisterBackend("file", newFileSignerFromConfig)
}

// newFileSignerFromConfig is the BackendFactory for the file backend.
func newFileSignerFromConfig(_ context.Context, raw map[string]any) (Signer, error) {
	keyringDir, ok := raw["keyring_dir"].(string)
	if !ok || keyringDir == "" {
		return nil, errors.New("signer.keyring_dir is required when backend is \"file\"")
	}
	keyName, ok := raw["key_name"].(string)
	if !ok || keyName == "" {
		return nil, errors.New("signer.key_name is required when backend is \"file\"")
	}
	pwFile, _ := raw["password_file"].(string)

	return NewFileSigner(keyringDir, keyName, pwFile)
}

// FileSigner implements Signer using a secp256k1 private key extracted
// from a keyring.Keyring at startup
type FileSigner struct {
	privateKey       *ecdsa.PrivateKey
	compressedPubKey []byte     // 33-byte compressed secp256k1 public key, cached at startup
	mu               sync.Mutex // protects against concurrent Sign calls
}

func NewFileSigner(keyringDir, keyName, pwFile string) (*FileSigner, error) {
	if keyringDir == "" {
		return nil, errors.New("keyring_dir is required for file signer backend")
	}
	if keyName == "" {
		return nil, errors.New("key_name is required for file signer backend")
	}

	passReader, err := BuildPasswordReader(pwFile)
	if err != nil {
		return nil, err
	}
	cdc := MakeKeyringCodec()

	kr, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendFile, keyringDir, passReader, cdc)
	if err != nil {
		return nil, fmt.Errorf("open keyring: %w", err)
	}

	record, err := kr.Key(keyName)
	if err != nil {
		return nil, fmt.Errorf("get key %q from keyring at %q: %w", keyName, keyringDir, err)
	}

	keyBytes, err := ExtractSecpPrivKeyBytes(cdc, record)
	if err != nil {
		return nil, fmt.Errorf("extract %q from keyring: %w", keyName, err)
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("convert to ECDSA: %w", err)
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

// SignRaw implements Signer.
// Signs the given 32-byte hash directly without any additional hashing.
// Returns a 64-byte secp256k1 ECDSA signature (r || s), without the v byte.
// Used for Cosmos SDK tx signing where the message digest is already computed.
func (s *FileSigner) SignRaw(_ context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("SignRaw: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sig, err := crypto.Sign(msg, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("SignRaw: secp256k1 signing failed: %w", err)
	}

	// Return only the 64-byte r || s. Strip the v byte at sig[64] since Cosmos SDK
	// expects a compact 64-byte signature.
	return sig[:64], nil
}
