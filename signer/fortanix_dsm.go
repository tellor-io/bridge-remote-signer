package signer

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"encoding/asn1"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/fortanix/sdkms-client-go/sdkms"
)

func init() {
	RegisterBackend("fortanixdsm", newFortanixDSMSignerFromConfig)
}

// newFortanixDSMSignerFromConfig is the BackendFactory for the FortanixDSM backend.
func newFortanixDSMSignerFromConfig(ctx context.Context, raw map[string]any) (Signer, error) {
	apiEndpoint, ok := raw["dsm_api_endpoint"].(string)
	if !ok || apiEndpoint == "" {
		return nil, errors.New("signer.dsm_api_endpoint is required when backend is \"fortanixdsm\"")
	}
	apiKey, ok := raw["dsm_api_key"].(string)
	if !ok || apiKey == "" {
		return nil, errors.New("signer.dsm_api_key is required when backend is \"fortanixdsm\"")
	}
	keyID, ok := raw["dsm_key_id"].(string)
	keyName, ok := raw["dsm_key_name"].(string)
	if !ok || (keyID == "" && keyName == "") {
		return nil, errors.New("signer.dsm_key_id or signer.dsm_key_name is required when backend is \"fortanixdsm\"")
	}

	return NewFortanixDSMSigner(ctx, FortanixDSMConfig{
		APIEndpoint: apiEndpoint,
		APIKey:      apiKey,
		KeyID:       keyID,
		KeyName:     keyName,
	})
}

// FortanixDSMConfig holds connection details for Fortanix Data Security Manager.
type FortanixDSMConfig struct {
	APIEndpoint string `yaml:"dsm_api_endpoint"`
	APIKey      string `yaml:"dsm_api_key"`
	// KeyID is the UUID of the secp256k1 signing key in DSM.
	// Use either KeyID or KeyName, not both.
	KeyID   string `yaml:"dsm_key_id"`
	KeyName string `yaml:"dsm_key_name"`
}

type dsmClient interface {
	Sign(ctx context.Context, body sdkms.SignRequest) (*sdkms.SignResponse, error)
	GetSobject(ctx context.Context, queryParams *sdkms.GetSobjectParams, descriptor sdkms.SobjectDescriptor) (*sdkms.Sobject, error)
}

type FortanixDSMSigner struct {
	client           dsmClient
	keyDescriptor    sdkms.SobjectDescriptor
	compressedPubKey []byte // 33-byte compressed secp256k1 public key, cached at startup
	mu               sync.Mutex
}

// NewFortanixDSMSigner connects to FortanixDSM, validates the key, and returns a signer.
func NewFortanixDSMSigner(ctx context.Context, cfg FortanixDSMConfig) (*FortanixDSMSigner, error) {
	if cfg.APIEndpoint == "" {
		return nil, errors.New("dsm_api_endpoint is required")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("dsm_api_key is required")
	}
	if cfg.KeyID == "" && cfg.KeyName == "" {
		return nil, errors.New("dsm_key_id or dsm_key_name is required")
	}

	// Create the DSM client with API key authentication.
	client := sdkms.Client{
		Endpoint:   cfg.APIEndpoint,
		Auth:       sdkms.APIKey(cfg.APIKey),
		HTTPClient: http.DefaultClient,
	}

	// Build key descriptor — either by UUID or by name.
	var descriptor sdkms.SobjectDescriptor
	if cfg.KeyID != "" {
		descriptor = sdkms.SobjectDescriptor{Kid: &cfg.KeyID}
	} else {
		descriptor = sdkms.SobjectDescriptor{Name: &cfg.KeyName}
	}

	// Fetch and validate the public key at startup.
	compressedPubKey, err := fetchDSMPublicKey(ctx, &client, descriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch FortanixDSM public key: %w", err)
	}

	return &FortanixDSMSigner{
		client:           &client,
		keyDescriptor:    descriptor,
		compressedPubKey: compressedPubKey,
	}, nil
}

// fetchDSMPublicKey retrieves the public key from DSM and returns the
// 33-byte compressed secp256k1 form.
func fetchDSMPublicKey(ctx context.Context, client dsmClient, descriptor sdkms.SobjectDescriptor) ([]byte, error) {
	sobject, err := client.GetSobject(ctx, nil, descriptor)
	if err != nil {
		return nil, fmt.Errorf("GetSobject failed: %w", err)
	}

	if sobject.ObjType != sdkms.ObjectTypeEc {
		return nil, fmt.Errorf("key is not an EC key (type: %s)", sobject.ObjType)
	}
	if sobject.EllipticCurve == nil || *sobject.EllipticCurve != sdkms.EllipticCurveSecP256K1 {
		curve := "unknown"
		if sobject.EllipticCurve != nil {
			curve = string(*sobject.EllipticCurve)
		}
		return nil, fmt.Errorf("key uses curve %s; expected SecP256K1", curve)
	}

	if sobject.PubKey == nil {
		return nil, errors.New("key has no public key data")
	}

	raw := []byte(*sobject.PubKey)

	// DSM returns the public key as DER-encoded SPKI (88 bytes for secp256k1).
	// You have to parse it to extract the compressed public key.
	compressed, err := parseSpkiToSecp256k1(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSM public key: %w", err)
	}

	return compressed, nil
}

// Sign
func (s *FortanixDSMSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("Sign: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hash := sha256.Sum256(msg)
	hashSlice := hash[:]

	resp, err := s.client.Sign(ctx, sdkms.SignRequest{
		Hash:    &hashSlice,
		HashAlg: sdkms.DigestAlgorithmSha256,
		Key:     &s.keyDescriptor,
	})
	if err != nil {
		return nil, fmt.Errorf("Sign: FortanixDSM Sign call failed: %w", err)
	}

	sig, err := derToEthSig(resp.Signature, hash[:], s.compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("Sign: failed to convert DSM signature to Ethereum format: %w", err)
	}

	return sig, nil
}

// GetPublicKey
func (s *FortanixDSMSigner) GetPublicKey(_ context.Context) ([]byte, error) {
	out := make([]byte, len(s.compressedPubKey))
	copy(out, s.compressedPubKey)
	return out, nil
}

// SignRaw implements Signer.
// Signs the given 32-byte hash directly without any additional hashing.
// Returns a 64-byte secp256k1 ECDSA signature (r || s), without the v byte.
// Used for Cosmos SDK tx signing where the message digest is already computed.
func (s *FortanixDSMSigner) SignRaw(ctx context.Context, msg []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, fmt.Errorf("SignRaw: msg must be exactly 32 bytes, got %d", len(msg))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	hashSlice := msg[:]

	resp, err := s.client.Sign(ctx, sdkms.SignRequest{
		Hash:    &hashSlice,
		HashAlg: sdkms.DigestAlgorithmSha256,
		Key:     &s.keyDescriptor,
	})
	if err != nil {
		return nil, fmt.Errorf("SignRaw: FortanixDSM Sign call failed: %w", err)
	}

	sig, err := derToEthSig(resp.Signature, msg, s.compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("SignRaw: failed to convert DSM signature to Ethereum format: %w", err)
	}

	// Return only 64 bytes (r || s), strip the v byte
	return sig[:64], nil
}

// parseSpkiToSecp256k1 extracts the compressed secp256k1 public key from a
// DER-encoded SubjectPublicKeyInfo structure.
func parseSpkiToSecp256k1(der []byte) ([]byte, error) {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPKI: %w", err)
	}

	raw := spki.PublicKey.Bytes
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf("expected 65-byte uncompressed point (0x04 prefix), got %d bytes", len(raw))
	}

	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:65])

	compressed := elliptic.MarshalCompressed(secp256k1.S256(), x, y)
	return compressed, nil
}
