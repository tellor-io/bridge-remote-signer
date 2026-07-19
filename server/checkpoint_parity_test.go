package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"github.com/tellor-io/bridge-remote-signer/logging"
)

// ---- GOLDEN VECTOR (produced by the REAL layer-node encoder) ----------------
// See /tmp/layer-rs/x/bridge/keeper/golden_vector_test.go for the oracle.
const (
	goldenValidatorSetHash      = "b905fe4296342440a843dd0b0bb6f8b280661c90f895419c980d3788d4d5fd7d"
	goldenDomainSepNonMainnet   = "32db5895e769c8ddfaf31c5af9d7424b4a272a41b772e223d57620dc1936184a"
	goldenCheckpointMainnet     = "ab090e41f0bc98246cce8eb74603375dcc3721bc212a6704f2e26980d04ee0f1"
	goldenCheckpointNonMainnet  = "ec1f6f55a307b36d69a89e7e2be38dd54959434ade3b98f0711550bda98eb28f"
	goldenSig                   = "b8dbec6f118cdf8cd94cdfb499daa5621619092bbc7bde0a40dfbca3d25202043b088b44938efa379d25a0fab20972e4cb190789b7bbe2b1488a3f75e7179eb7"
	goldenNonMainnetChainID     = "layertest-4"
	goldenPowerThreshold uint64 = 116
	goldenValidatorTime  uint64 = 1700000000000 // UNIX MILLISECONDS
)

// goldenValidators returns the three fixed validators in node canonical order.
func goldenValidators() []bridgeValidator {
	a1, _ := hex.DecodeString("1111111111111111111111111111111111111111")
	a2, _ := hex.DecodeString("2222222222222222222222222222222222222222")
	a3, _ := hex.DecodeString("3333333333333333333333333333333333333333")
	return []bridgeValidator{
		{EthereumAddress: a1, Power: 100},
		{EthereumAddress: a2, Power: 50},
		{EthereumAddress: a3, Power: 25},
	}
}

// TestParity_CheckpointEncoder asserts the signer's byte-exact encoder port
// reproduces the golden vector checkpoint for BOTH the mainnet-constant and the
// non-mainnet keccak256 domain-separator variants.
func TestParity_CheckpointEncoder(t *testing.T) {
	vs := goldenValidators()
	sortBridgeValidators(vs)

	_, valsetHash, err := encodeAndHashValidatorSet(vs)
	if err != nil {
		t.Fatalf("encodeAndHashValidatorSet: %v", err)
	}
	if got := hex.EncodeToString(valsetHash); got != goldenValidatorSetHash {
		t.Fatalf("validatorSetHash mismatch:\n got  %s\n want %s", got, goldenValidatorSetHash)
	}

	// --- MAINNET (fixed "checkpoint" constant domain separator) ---
	dsMainnet, err := computeDomainSeparator(MainnetChainID)
	if err != nil {
		t.Fatalf("computeDomainSeparator mainnet: %v", err)
	}
	cpMainnet, err := encodeValsetCheckpoint(dsMainnet, goldenPowerThreshold, goldenValidatorTime, valsetHash)
	if err != nil {
		t.Fatalf("encodeValsetCheckpoint mainnet: %v", err)
	}
	if got := hex.EncodeToString(cpMainnet); got != goldenCheckpointMainnet {
		t.Fatalf("checkpoint(MAINNET) mismatch:\n got  %s\n want %s", got, goldenCheckpointMainnet)
	}
	t.Logf("checkpoint(MAINNET)    MATCH = %s", goldenCheckpointMainnet)

	// --- NON-MAINNET (keccak256(abi.encode("checkpoint", chainID))) ---
	dsNon, err := computeDomainSeparator(goldenNonMainnetChainID)
	if err != nil {
		t.Fatalf("computeDomainSeparator non-mainnet: %v", err)
	}
	if got := hex.EncodeToString(dsNon); got != goldenDomainSepNonMainnet {
		t.Fatalf("domainSeparator(non-mainnet) mismatch:\n got  %s\n want %s", got, goldenDomainSepNonMainnet)
	}
	cpNon, err := encodeValsetCheckpoint(dsNon, goldenPowerThreshold, goldenValidatorTime, valsetHash)
	if err != nil {
		t.Fatalf("encodeValsetCheckpoint non-mainnet: %v", err)
	}
	if got := hex.EncodeToString(cpNon); got != goldenCheckpointNonMainnet {
		t.Fatalf("checkpoint(non-mainnet) mismatch:\n got  %s\n want %s", got, goldenCheckpointNonMainnet)
	}
	t.Logf("checkpoint(non-mainnet) MATCH = %s", goldenCheckpointNonMainnet)
}

// fixedKeySigner is an in-test signer backed by a fixed secp256k1 private key,
// so its EVM address is deterministic (used to satisfy the self-membership gate
// and to verify the 64-byte signature byte-for-byte against the golden sig).
type fixedKeySigner struct {
	priv *ecdsa.PrivateKey
}

func newFixedKeySigner(t *testing.T, privHex string) *fixedKeySigner {
	t.Helper()
	kb, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("decode priv hex: %v", err)
	}
	priv, err := crypto.ToECDSA(kb)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	return &fixedKeySigner{priv: priv}
}

func (s *fixedKeySigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	sig, err := crypto.Sign(h[:], s.priv)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

func (s *fixedKeySigner) SignRaw(_ context.Context, msg []byte) ([]byte, error) {
	sig, err := crypto.Sign(msg, s.priv)
	if err != nil {
		return nil, err
	}
	return sig[:64], nil
}

func (s *fixedKeySigner) GetPublicKey(_ context.Context) ([]byte, error) {
	return crypto.CompressPubkey(&s.priv.PublicKey), nil
}

// TestParity_SignBridgeCheckpoint_Handler drives the full SignBridgeCheckpoint
// handler with the golden inputs and asserts the recomputed checkpoint equals
// the golden checkpoint (byte identical) and the returned signature is exactly
// 64 bytes, for both the mainnet and non-mainnet domain-separator variants.
//
// To keep the golden hash inputs byte-identical we must not alter the validator
// set, so we build the Server directly with a fixed-key signer (the golden
// vector's 0x1111...1111 key, which produces the golden 64-byte sig) and set
// selfEVMAddr to a member of the golden set (0x1111...1111) so the
// self-membership gate passes.
func TestParity_SignBridgeCheckpoint_Handler(t *testing.T) {
	log, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	sgn := newFixedKeySigner(t, "1111111111111111111111111111111111111111111111111111111111111111")

	guard, err := newCheckpointReplayGuard("")
	if err != nil {
		t.Fatalf("newCheckpointReplayGuard: %v", err)
	}
	memberAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	srv := &Server{
		signer:          sgn,
		logger:          log,
		selfEVMAddr:     memberAddr, // a member of the golden validator set
		checkpointGuard: guard,
		enabledRPCs:     map[string]bool{},
	}

	vs := goldenValidators()
	_, valsetHash, err := encodeAndHashValidatorSet(vs)
	if err != nil {
		t.Fatalf("encodeAndHashValidatorSet: %v", err)
	}
	pbValset := make([]*signerv1.BridgeValidator, len(vs))
	for i, v := range vs {
		pbValset[i] = &signerv1.BridgeValidator{EthereumAddress: v.EthereumAddress, Power: v.Power}
	}

	cases := []struct {
		name           string
		chainID        string
		wantCheckpoint string
	}{
		{"mainnet", MainnetChainID, goldenCheckpointMainnet},
		{"non-mainnet", goldenNonMainnetChainID, goldenCheckpointNonMainnet},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh replay guard per sub-case: both golden checkpoints share the
			// same validator_timestamp (they differ only by chain_id), so a
			// shared monotonic guard would (correctly) reject the second one.
			fresh, err := newCheckpointReplayGuard("")
			if err != nil {
				t.Fatalf("newCheckpointReplayGuard: %v", err)
			}
			srv.checkpointGuard = fresh

			ds, err := computeDomainSeparator(tc.chainID)
			if err != nil {
				t.Fatalf("computeDomainSeparator: %v", err)
			}
			wantCP, _ := hex.DecodeString(tc.wantCheckpoint)

			resp, err := srv.SignBridgeCheckpoint(context.Background(), &signerv1.SignBridgeCheckpointRequest{
				DomainSeparator:    ds,
				PowerThreshold:     goldenPowerThreshold,
				ValidatorTimestamp: goldenValidatorTime,
				ValidatorSetHash:   valsetHash,
				ValidatorSet:       pbValset,
				BlockHeight:        42,
				CheckpointIndex:    7,
				ChainId:            tc.chainID,
				ExpectedCheckpoint: wantCP,
				RequestId:          "parity-" + tc.name,
			})
			if err != nil {
				t.Fatalf("SignBridgeCheckpoint: %v", err)
			}

			if got := hex.EncodeToString(resp.Checkpoint); got != tc.wantCheckpoint {
				t.Fatalf("returned checkpoint mismatch:\n got  %s\n want %s", got, tc.wantCheckpoint)
			}
			if len(resp.Signature) != 64 {
				t.Fatalf("signature must be exactly 64 bytes, got %d", len(resp.Signature))
			}
			t.Logf("%s: checkpoint MATCH=%s sig_len=%d", tc.name, tc.wantCheckpoint, len(resp.Signature))

			// For mainnet, the golden sig tuple was produced with this exact key.
			if tc.name == "mainnet" {
				if got := hex.EncodeToString(resp.Signature); got != goldenSig {
					t.Fatalf("signature mismatch vs golden:\n got  %s\n want %s", got, goldenSig)
				}
				t.Logf("mainnet: 64-byte r||s MATCH golden sig")
			}
		})
	}

	// Reset guard then prove the monotonic replay guard rejects a re-send.
	freshGuard, _ := newCheckpointReplayGuard("")
	srv.checkpointGuard = freshGuard
	ds, _ := computeDomainSeparator(MainnetChainID)
	wantCP, _ := hex.DecodeString(goldenCheckpointMainnet)
	req := &signerv1.SignBridgeCheckpointRequest{
		DomainSeparator:    ds,
		PowerThreshold:     goldenPowerThreshold,
		ValidatorTimestamp: goldenValidatorTime,
		ValidatorSetHash:   valsetHash,
		ValidatorSet:       pbValset,
		ChainId:            MainnetChainID,
		ExpectedCheckpoint: wantCP,
	}
	if _, err := srv.SignBridgeCheckpoint(context.Background(), req); err != nil {
		t.Fatalf("first SignBridgeCheckpoint should succeed: %v", err)
	}
	if _, err := srv.SignBridgeCheckpoint(context.Background(), req); err == nil {
		t.Fatal("replay of same validator_timestamp must be rejected by the replay guard")
	}
}

// TestSignBridgeCheckpoint_FailClosed verifies the handler signs nothing on the
// key mismatch/membership gates.
func TestSignBridgeCheckpoint_FailClosed(t *testing.T) {
	log, _ := logging.New("error", "json")
	memberAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	vs := goldenValidators()
	_, valsetHash, _ := encodeAndHashValidatorSet(vs)
	pbValset := make([]*signerv1.BridgeValidator, len(vs))
	for i, v := range vs {
		pbValset[i] = &signerv1.BridgeValidator{EthereumAddress: v.EthereumAddress, Power: v.Power}
	}
	dsMainnet, _ := computeDomainSeparator(MainnetChainID)
	goodCP, _ := hex.DecodeString(goldenCheckpointMainnet)

	base := func() *signerv1.SignBridgeCheckpointRequest {
		return &signerv1.SignBridgeCheckpointRequest{
			DomainSeparator:    append([]byte(nil), dsMainnet...),
			PowerThreshold:     goldenPowerThreshold,
			ValidatorTimestamp: goldenValidatorTime,
			ValidatorSetHash:   append([]byte(nil), valsetHash...),
			ValidatorSet:       pbValset,
			ChainId:            MainnetChainID,
			ExpectedCheckpoint: append([]byte(nil), goodCP...),
		}
	}

	newSrv := func(self common.Address) *Server {
		g, _ := newCheckpointReplayGuard("")
		return &Server{
			signer:          newFixedKeySigner(t, "1111111111111111111111111111111111111111111111111111111111111111"),
			logger:          log,
			selfEVMAddr:     self,
			checkpointGuard: g,
			enabledRPCs:     map[string]bool{},
		}
	}

	t.Run("checkpoint mismatch is rejected", func(t *testing.T) {
		req := base()
		req.ExpectedCheckpoint[0] ^= 0xff // corrupt
		if _, err := newSrv(memberAddr).SignBridgeCheckpoint(context.Background(), req); err == nil {
			t.Fatal("expected rejection on expected_checkpoint mismatch")
		}
	})

	t.Run("non-member signer is rejected", func(t *testing.T) {
		other := common.HexToAddress("0x9999999999999999999999999999999999999999")
		if _, err := newSrv(other).SignBridgeCheckpoint(context.Background(), base()); err == nil {
			t.Fatal("expected rejection when signer is not a member of the set")
		}
	})

	t.Run("wrong power_threshold is rejected", func(t *testing.T) {
		req := base()
		req.PowerThreshold = 999
		if _, err := newSrv(memberAddr).SignBridgeCheckpoint(context.Background(), req); err == nil {
			t.Fatal("expected rejection on power_threshold mismatch")
		}
	})

	t.Run("wrong domain_separator is rejected", func(t *testing.T) {
		req := base()
		req.DomainSeparator[0] ^= 0xff
		if _, err := newSrv(memberAddr).SignBridgeCheckpoint(context.Background(), req); err == nil {
			t.Fatal("expected rejection on domain_separator mismatch")
		}
	})

	t.Run("zero power validator is rejected", func(t *testing.T) {
		req := base()
		bad := make([]*signerv1.BridgeValidator, len(pbValset))
		copy(bad, pbValset)
		bad[0] = &signerv1.BridgeValidator{EthereumAddress: pbValset[0].EthereumAddress, Power: 0}
		req.ValidatorSet = bad
		if _, err := newSrv(memberAddr).SignBridgeCheckpoint(context.Background(), req); err == nil {
			t.Fatal("expected rejection on zero-power validator")
		}
	})
}
