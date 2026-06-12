package server

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"github.com/tellor-io/bridge-remote-signer/logging"
)

// ---- GOLDEN VECTOR for the oracle attestation encoder (from the REAL node) ---
// See /tmp/layer-rs/x/bridge/keeper/golden_vector_attestation_test.go.
// Inputs reused VERBATIM. The 64-byte sig is produced by the fixed 0x11*32 key.
const (
	goldenAttQueryIDHex    = "83245f6a6a2f6458558a706270fbcc35ac3a81917602c1313d3bfa998dcc2d4b"
	goldenAttValueHex      = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	goldenAttCheckpointHex = "5c3d8e1f0a9b7c6d4e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d"
	goldenAttSnapshotHex   = "800969391dde8f3dfb8b76d4d5637b51f5b23ebb26721fc933a7b5cb6fd82124"
	goldenAttSig64Hex      = "65b243409f43168a75a5c3184dcd09f5a8f7becbefbe9f5d4f24dc32d3e6feb41f49088031676890cc6badae9d0f00275955049fc13136db00b639eec7a1da9c"

	goldenAttTimestampVal       uint64 = 1700000000000
	goldenAttAggregatePowerVal  uint64 = 175
	goldenAttPreviousTimeVal    uint64 = 1699999000000
	goldenAttNextTimeVal        uint64 = 1700001000000
	goldenAttAttestationTimeVal uint64 = 1700000500000
	goldenAttLastConsensusVal   uint64 = 1699998000000
)

func mustHexAtt(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// goldenAttestationReq builds the SignOracleAttestationRequest from the golden
// vector. value carries the ALREADY-HEX-DECODED bytes (the node hex-decodes the
// value string before ABI-packing it as dynamic bytes).
func goldenAttestationReq(t *testing.T) *signerv1.SignOracleAttestationRequest {
	t.Helper()
	return &signerv1.SignOracleAttestationRequest{
		QueryId:                mustHexAtt(t, goldenAttQueryIDHex),
		Value:                  mustHexAtt(t, goldenAttValueHex),
		Timestamp:              goldenAttTimestampVal,
		AggregatePower:         goldenAttAggregatePowerVal,
		PreviousTimestamp:      goldenAttPreviousTimeVal,
		NextTimestamp:          goldenAttNextTimeVal,
		ValsetCheckpoint:       mustHexAtt(t, goldenAttCheckpointHex),
		AttestationTimestamp:   goldenAttAttestationTimeVal,
		LastConsensusTimestamp: goldenAttLastConsensusVal,
		ExpectedSnapshot:       mustHexAtt(t, goldenAttSnapshotHex),
		RequestId:              "parity-attestation",
	}
}

// TestParity_AttestationEncoder asserts the signer's byte-exact port of
// EncodeOracleAttestationData reproduces the golden snapshot for the golden
// inputs (fixed "tellorCurrentAttestation" domain separator, dynamic value bytes,
// the 6 uint256 scalars, and the bytes32 valset checkpoint).
func TestParity_AttestationEncoder(t *testing.T) {
	snapshot, err := encodeOracleAttestation(
		mustHexAtt(t, goldenAttQueryIDHex),
		mustHexAtt(t, goldenAttValueHex),
		goldenAttTimestampVal,
		goldenAttAggregatePowerVal,
		goldenAttPreviousTimeVal,
		goldenAttNextTimeVal,
		mustHexAtt(t, goldenAttCheckpointHex),
		goldenAttAttestationTimeVal,
		goldenAttLastConsensusVal,
	)
	if err != nil {
		t.Fatalf("encodeOracleAttestation: %v", err)
	}
	if got := hex.EncodeToString(snapshot); got != goldenAttSnapshotHex {
		t.Fatalf("snapshot mismatch:\n got  %s\n want %s", got, goldenAttSnapshotHex)
	}
	t.Logf("attestation snapshot MATCH = %s", goldenAttSnapshotHex)
}

// TestParity_OracleAttestation drives the full SignOracleAttestation handler with
// the golden inputs and asserts:
//   - the returned snapshot equals the golden snapshotHash (byte identical),
//   - the signature is exactly 64 bytes and (for the fixed 0x11*32 key) equals
//     the golden sig64,
// plus a fail-closed subtest proving a corrupted expected_snapshot is rejected
// (signs nothing).
func TestParity_OracleAttestation(t *testing.T) {
	log, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	// Fixed 0x11*32 key — produces the golden 64-byte sig.
	sgn := newFixedKeySigner(t, "1111111111111111111111111111111111111111111111111111111111111111")
	srv := &Server{
		signer:      sgn,
		logger:      log,
		selfEVMAddr: common.Address{},
		enabledRPCs: map[string]bool{},
	}

	t.Run("byte-exact snapshot + 64-byte golden sig", func(t *testing.T) {
		resp, err := srv.SignOracleAttestation(context.Background(), goldenAttestationReq(t))
		if err != nil {
			t.Fatalf("SignOracleAttestation: %v", err)
		}
		if got := hex.EncodeToString(resp.Snapshot); got != goldenAttSnapshotHex {
			t.Fatalf("returned snapshot mismatch:\n got  %s\n want %s", got, goldenAttSnapshotHex)
		}
		if len(resp.Signature) != 64 {
			t.Fatalf("signature must be exactly 64 bytes, got %d", len(resp.Signature))
		}
		if got := hex.EncodeToString(resp.Signature); got != goldenAttSig64Hex {
			t.Fatalf("signature mismatch vs golden:\n got  %s\n want %s", got, goldenAttSig64Hex)
		}
		t.Logf("snapshot MATCH=%s", goldenAttSnapshotHex)
		t.Logf("64-byte r||s MATCH golden sig=%s", goldenAttSig64Hex)
	})

	t.Run("fail-closed: corrupted expected_snapshot is rejected", func(t *testing.T) {
		req := goldenAttestationReq(t)
		req.ExpectedSnapshot[0] ^= 0xff // corrupt one byte
		if _, err := srv.SignOracleAttestation(context.Background(), req); err == nil {
			t.Fatal("expected rejection on expected_snapshot mismatch (must sign nothing)")
		}
	})

	t.Run("fail-closed: bad valset_checkpoint length is rejected", func(t *testing.T) {
		req := goldenAttestationReq(t)
		req.ValsetCheckpoint = req.ValsetCheckpoint[:31] // not 32 bytes
		if _, err := srv.SignOracleAttestation(context.Background(), req); err == nil {
			t.Fatal("expected rejection on short valset_checkpoint")
		}
	})
}
