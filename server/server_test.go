package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	costx "github.com/cosmos/cosmos-sdk/types/tx"
	gogoany "github.com/cosmos/gogoproto/types/any"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/server"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

const (
	// goldenPrivKeyHex is the fixed 0x11*32 key from the golden vector; its
	// pubkey is used to verify SignTx signatures recover correctly, and its
	// EVM address (0x19e7e376e7c213b7e7e7fcdc4d0bf37c4d8e8a) is a member of the
	// golden bridge validator set so the SignBridgeCheckpoint smoke test passes.
	goldenPrivKeyHex = "1111111111111111111111111111111111111111111111111111111111111111"

	// --- SignOracleAttestation golden vector (from the real node encoder) ---
	goldenAttestationQueryIDHex           = "83245f6a6a2f6458558a706270fbcc35ac3a81917602c1313d3bfa998dcc2d4b"
	goldenAttestationValueHex             = "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	goldenAttestationCheckpointHex        = "5c3d8e1f0a9b7c6d4e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d"
	goldenAttestationSnapshotHex          = "800969391dde8f3dfb8b76d4d5637b51f5b23ebb26721fc933a7b5cb6fd82124"
	goldenAttestationSig64Hex             = "65b243409f43168a75a5c3184dcd09f5a8f7becbefbe9f5d4f24dc32d3e6feb41f49088031676890cc6badae9d0f00275955049fc13136db00b639eec7a1da9c"
	goldenAttTimestamp             uint64 = 1700000000000
	goldenAttAggregatePower        uint64 = 175
	goldenAttPreviousTime          uint64 = 1699999000000
	goldenAttNextTime              uint64 = 1700001000000
	goldenAttAttestationTime       uint64 = 1700000500000
	goldenAttLastConsensus         uint64 = 1699998000000
)

// goldenAttestationRequest builds the SignOracleAttestation request from the
// golden vector. value carries the ALREADY-HEX-DECODED bytes (the node decodes
// the 0x-prefixed value string before packing).
func goldenAttestationRequest() *signerv1.SignOracleAttestationRequest {
	queryID, _ := hex.DecodeString(goldenAttestationQueryIDHex)
	value, _ := hex.DecodeString(goldenAttestationValueHex)
	checkpoint, _ := hex.DecodeString(goldenAttestationCheckpointHex)
	snapshot, _ := hex.DecodeString(goldenAttestationSnapshotHex)
	return &signerv1.SignOracleAttestationRequest{
		QueryId:                queryID,
		Value:                  value,
		Timestamp:              goldenAttTimestamp,
		AggregatePower:         goldenAttAggregatePower,
		PreviousTimestamp:      goldenAttPreviousTime,
		NextTimestamp:          goldenAttNextTime,
		ValsetCheckpoint:       checkpoint,
		AttestationTimestamp:   goldenAttAttestationTime,
		LastConsensusTimestamp: goldenAttLastConsensus,
		ExpectedSnapshot:       snapshot,
		RequestId:              "wire-attestation",
	}
}

// goldenPubKeyHex is the compressed secp256k1 pubkey for goldenPrivKeyHex.
var goldenPubKeyHex = func() string {
	kb, _ := hex.DecodeString(goldenPrivKeyHex)
	priv, _ := crypto.ToECDSA(kb)
	return hex.EncodeToString(crypto.CompressPubkey(&priv.PublicKey))
}()

// operationAllowlist is the default SignTx allowlist used by the test server:
// reports + the two unjail operations.
var operationAllowlist = []string{
	"/layer.oracle.MsgSubmitValue",
	"/cosmos.slashing.v1beta1.MsgUnjail",
	"/layer.reporter.MsgUnjailReporter",
}

// startTestServer returns a signer client. When SIGNER_URL is set it connects to
// that live signer (see live_signer_test.go); otherwise it creates an in-memory
// mTLS gRPC server backed by the golden fixed key with the default operation
// allowlist. Authorization is by OPERATION (no per-cert CN gating), so any client
// presenting a CA-chained cert may connect; the handlers themselves enforce what
// may be signed.
func startTestServer(t *testing.T) (signerv1.BridgeSignerClient, func()) {
	if client, cleanup, ok := dialLiveSigner(t); ok {
		return client, cleanup
	}
	return startTestServerAllow(t, operationAllowlist)
}

// startTestServerAllow is startTestServer with a caller-supplied SignTx
// allowlist (pass nil/[] to exercise the empty-allowlist reject-everything path).
func startTestServerAllow(t *testing.T, allow []string) (signerv1.BridgeSignerClient, func()) {
	t.Helper()

	keyringDir, pwFile := writeKeyringWithKey(t, goldenPrivKeyHex, "test-key")
	s, err := signer.NewFileSigner(keyringDir, "test-key", pwFile)
	if err != nil {
		t.Fatalf("NewFileSigner: %v", err)
	}

	log, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	pki := newTestPKI(t)
	srv, err := server.New(s, log, server.Config{
		ListenAddr:      "127.0.0.1:0",
		MaxRecvMsgSize:  4 * 1024 * 1024,
		AllowedMsgTypes: allow,
		Credentials:     pki.serverCreds(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	go func() {
		if err := srv.ServeOn(lis); err != nil {
			// Ignore server closed errors during test cleanup.
			_ = err
		}
	}()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(pki.clientCreds("test-client")))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	client := signerv1.NewBridgeSignerClient(conn)
	cleanup := func() {
		conn.Close()
		srv.Stop()
	}
	return client, cleanup
}

// TestServer_SignRaw_Disabled proves the blind 64-byte primitive is HARD-DISABLED:
// it always returns Unimplemented regardless of input.
func TestServer_SignRaw_Disabled(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	hash := sha256.Sum256([]byte("cosmos tx sign doc bytes"))
	if _, err := client.SignRaw(context.Background(), &signerv1.SignRawRequest{Msg: hash[:]}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("SignRaw must be Unimplemented, got %v (err=%v)", status.Code(err), err)
	}
}

// TestServer_Sign_Disabled proves the blind 65-byte primitive is HARD-DISABLED:
// it always returns Unimplemented regardless of input. This closes the prior
// "Sign is a checkpoint-forgery oracle" issue — Sign is simply unreachable.
func TestServer_Sign_Disabled(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	hash := sha256.Sum256([]byte("anything"))
	if _, err := client.Sign(context.Background(), &signerv1.SignRequest{Msg: hash[:]}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("Sign must be Unimplemented, got %v (err=%v)", status.Code(err), err)
	}
}

func TestServer_GetAddress(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.GetAddress(context.Background(), &signerv1.GetAddressRequest{
		Prefix: "tellor",
	})
	if err != nil {
		t.Fatalf("GetAddress: %v", err)
	}
	if resp.Address == "" {
		t.Fatal("expected non-empty address")
	}
	// Address must start with the given prefix.
	if len(resp.Address) < 6 || resp.Address[:6] != "tellor" {
		t.Errorf("address %q does not start with 'tellor'", resp.Address)
	}
}

func TestServer_GetAddress_EmptyPrefix(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.GetAddress(context.Background(), &signerv1.GetAddressRequest{Prefix: ""})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (err=%v)", status.Code(err), err)
	}
}

// writeKeyringWithKey creates a temp file keyring containing the given hex-encoded
// secp256k1 private key and returns (keyringDir, passwordFile).
func writeKeyringWithKey(t *testing.T, privKeyHex, keyName string) (string, string) {
	t.Helper()

	const testPassword = "test-password-1234"

	dir := t.TempDir()
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(testPassword+"\n"), 0600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	passReader := strings.NewReader(strings.Repeat(testPassword+"\n", 4))
	cdc := signer.MakeKeyringCodec()
	kr, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendFile, dir, passReader, cdc)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	if err := kr.ImportPrivKeyHex(keyName, privKeyHex, "secp256k1"); err != nil {
		t.Fatalf("import priv key: %v", err)
	}
	return dir, pwFile
}

// buildSignDoc creates a minimal cosmos SignDoc containing a single message with the given type_url.
func buildSignDoc(t *testing.T, typeURL string) []byte {
	t.Helper()
	// Encode a TxBody with one Any message of the given type_url.
	body := costx.TxBody{
		Messages: []*gogoany.Any{{TypeUrl: typeURL}},
	}
	bodyBytes, err := body.Marshal()
	if err != nil {
		t.Fatalf("marshal TxBody: %v", err)
	}
	doc := costx.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: []byte{},
		ChainId:       "layertest-1",
		AccountNumber: 1,
	}
	raw, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal SignDoc: %v", err)
	}
	return raw
}

// buildEmptySignDoc creates a SignDoc whose TxBody carries ZERO messages.
func buildEmptySignDoc(t *testing.T) []byte {
	t.Helper()
	body := costx.TxBody{Messages: nil}
	bodyBytes, err := body.Marshal()
	if err != nil {
		t.Fatalf("marshal TxBody: %v", err)
	}
	doc := costx.SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: []byte{},
		ChainId:       "layertest-1",
		AccountNumber: 1,
	}
	raw, err := doc.Marshal()
	if err != nil {
		t.Fatalf("marshal SignDoc: %v", err)
	}
	return raw
}

// recoversToGoldenPubKey reports whether the 64-byte r||s signature over hash
// recovers to the golden fixed key's compressed pubkey (trying both recovery ids).
func recoversToGoldenPubKey(t *testing.T, sig, hash []byte) bool {
	t.Helper()
	expectedPubKey, err := hex.DecodeString(goldenPubKeyHex)
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}
	for _, v := range []byte{0, 1} {
		candidate := append(append([]byte(nil), sig...), v)
		pub, recErr := crypto.Ecrecover(hash, candidate)
		if recErr != nil {
			continue
		}
		x := new(big.Int).SetBytes(pub[1:33])
		y := new(big.Int).SetBytes(pub[33:65])
		key := ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
		if bytes.Equal(crypto.CompressPubkey(&key), expectedPubKey) {
			return true
		}
	}
	return false
}

// TestServer_SignTx_AllowedMsg proves SignTx signs each operation message on the
// allowlist (report submit + the two unjail operations) and that the resulting
// 64-byte signature recovers to the expected key.
func TestServer_SignTx_AllowedMsg(t *testing.T) {
	skipIfLive(t, "asserts signature recovery to the golden test key")
	client, cleanup := startTestServer(t)
	defer cleanup()

	for _, typeURL := range []string{
		"/layer.oracle.MsgSubmitValue",
		"/cosmos.slashing.v1beta1.MsgUnjail",
		"/layer.reporter.MsgUnjailReporter",
	} {
		t.Run(typeURL, func(t *testing.T) {
			signDoc := buildSignDoc(t, typeURL)
			resp, err := client.SignTx(context.Background(), &signerv1.SignTxRequest{
				SignDoc:   signDoc,
				RequestId: "test-signtx",
			})
			if err != nil {
				t.Fatalf("SignTx: %v", err)
			}
			if len(resp.Signature) != 64 {
				t.Fatalf("expected 64-byte signature, got %d", len(resp.Signature))
			}
			hash := sha256.Sum256(signDoc)
			if !recoversToGoldenPubKey(t, resp.Signature, hash[:]) {
				t.Error("SignTx: signature did not recover to expected public key")
			}
		})
	}
}

func TestServer_SignTx_BlockedMsg(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	// None of these are on the allowlist — every dangerous type must be rejected:
	// fund transfers, the bridge withdraw, staking, distribution, governance, authz.
	for _, typeURL := range []string{
		"/cosmos.bank.v1beta1.MsgSend",
		"/cosmos.bank.v1beta1.MsgMultiSend",
		"/ibc.applications.transfer.v1.MsgTransfer",
		"/layer.bridge.MsgWithdrawTokens",
		"/cosmos.staking.v1beta1.MsgDelegate",
		"/cosmos.staking.v1beta1.MsgUndelegate",
		"/cosmos.staking.v1beta1.MsgBeginRedelegate",
		"/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward",
		"/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission",
		"/cosmos.gov.v1.MsgVote",
		"/cosmos.authz.v1beta1.MsgExec",
	} {
		t.Run(typeURL, func(t *testing.T) {
			signDoc := buildSignDoc(t, typeURL)
			_, err := client.SignTx(context.Background(), &signerv1.SignTxRequest{
				SignDoc:   signDoc,
				RequestId: "test-blocked",
			})
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("expected PermissionDenied for %s, got %v (err=%v)", typeURL, status.Code(err), err)
			}
		})
	}
}

func TestServer_SignTx_EmptySignDoc(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.SignTx(context.Background(), &signerv1.SignTxRequest{SignDoc: nil})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v (err=%v)", status.Code(err), err)
	}
}

// TestServer_SignTx_ZeroMessages proves a SignDoc carrying zero messages is
// rejected (fail closed) rather than skipping the allowlist loop and getting
// signed — closes the empty-message bypass.
func TestServer_SignTx_ZeroMessages(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.SignTx(context.Background(), &signerv1.SignTxRequest{
		SignDoc:   buildEmptySignDoc(t),
		RequestId: "test-zero-msgs",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for zero-message SignDoc, got %v (err=%v)", status.Code(err), err)
	}
}

// TestServer_SignTx_EmptyAllowlist proves that with no allowed_msg_types
// configured, SignTx rejects everything — including an otherwise-common type.
func TestServer_SignTx_EmptyAllowlist(t *testing.T) {
	skipIfLive(t, "configures a server-side empty allowlist; not applicable to a live signer")
	client, cleanup := startTestServerAllow(t, nil)
	defer cleanup()

	signDoc := buildSignDoc(t, "/layer.oracle.MsgSubmitValue")
	_, err := client.SignTx(context.Background(), &signerv1.SignTxRequest{
		SignDoc:   signDoc,
		RequestId: "test-empty-allowlist",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied with empty allowlist, got %v (err=%v)", status.Code(err), err)
	}
}

// Byte-exact SignBridgeCheckpoint parity (recomputed checkpoint + 64-byte golden
// sig) is asserted by TestParity_SignBridgeCheckpoint_Handler in
// checkpoint_parity_test.go, which can set selfEVMAddr to a golden-set member.
// Over the wire, server.New derives the signer's real EVM address (which is not a
// member of the golden 0x1111/0x2222/0x3333 set), so the self-membership gate
// would correctly reject it — hence the over-the-wire checkpoint smoke lives in
// the internal parity test, not here.

// TestServer_SignOracleAttestation_OverWire drives SignOracleAttestation
// end-to-end over the mTLS transport with the golden inputs and asserts the
// recomputed snapshot and 64-byte signature match the golden vector.
func TestServer_SignOracleAttestation_OverWire(t *testing.T) {
	skipIfLive(t, "asserts the golden attestation snapshot/signature vector")
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.SignOracleAttestation(context.Background(), goldenAttestationRequest())
	if err != nil {
		t.Fatalf("SignOracleAttestation: %v", err)
	}
	if got := hex.EncodeToString(resp.Snapshot); got != goldenAttestationSnapshotHex {
		t.Fatalf("snapshot mismatch:\n got  %s\n want %s", got, goldenAttestationSnapshotHex)
	}
	if len(resp.Signature) != 64 {
		t.Fatalf("signature must be 64 bytes, got %d", len(resp.Signature))
	}
	if got := hex.EncodeToString(resp.Signature); got != goldenAttestationSig64Hex {
		t.Fatalf("signature mismatch vs golden:\n got  %s\n want %s", got, goldenAttestationSig64Hex)
	}
}

// startTestServerChainID starts a hardened test server configured with a chain
// ID, so GetChainID returns it. Mirrors startTestServerAllow (mTLS PKI).
func startTestServerChainID(t *testing.T, chainID string) (signerv1.BridgeSignerClient, func()) {
	t.Helper()

	keyringDir, pwFile := writeKeyringWithKey(t, goldenPrivKeyHex, "test-key")
	s, err := signer.NewFileSigner(keyringDir, "test-key", pwFile)
	if err != nil {
		t.Fatalf("NewFileSigner: %v", err)
	}

	log, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	pki := newTestPKI(t)
	srv, err := server.New(s, log, server.Config{
		ListenAddr:     "127.0.0.1:0",
		MaxRecvMsgSize: 4 * 1024 * 1024,
		ChainID:        chainID,
		Credentials:    pki.serverCreds(),
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	go func() {
		if err := srv.ServeOn(lis); err != nil {
			// Ignore server closed errors during test cleanup.
			_ = err
		}
	}()

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(pki.clientCreds("test-client")))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	client := signerv1.NewBridgeSignerClient(conn)
	cleanup := func() {
		conn.Close()
		srv.Stop()
	}
	return client, cleanup
}

// TestServer_GetChainID verifies the signer reports its configured chain ID.
func TestServer_GetChainID(t *testing.T) {
	skipIfLive(t, "asserts a fixed server-side chain ID")
	client, cleanup := startTestServerChainID(t, "layertest-5")
	defer cleanup()

	resp, err := client.GetChainID(context.Background(), &signerv1.GetChainIDRequest{})
	if err != nil {
		t.Fatalf("GetChainID: %v", err)
	}
	if resp.ChainId != "layertest-5" {
		t.Errorf("expected chain id 'layertest-5', got %q", resp.ChainId)
	}
}

// TestServer_GetChainID_NotConfigured verifies GetChainID returns
// FailedPrecondition when no chain ID is configured on the signer.
func TestServer_GetChainID_NotConfigured(t *testing.T) {
	skipIfLive(t, "a live signer has a chain ID configured")
	client, cleanup := startTestServer(t) // no chain id configured
	defer cleanup()

	_, err := client.GetChainID(context.Background(), &signerv1.GetChainIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition when chain id not configured, got %v", err)
	}
}
