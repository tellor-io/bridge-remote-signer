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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	signerv1 "github.com/tellor-io/bridge-remote-signer/api/gen/signer/v1"
	"github.com/tellor-io/bridge-remote-signer/logging"
	"github.com/tellor-io/bridge-remote-signer/server"
	"github.com/tellor-io/bridge-remote-signer/signer"
)

const (
	testPrivKeyHex = "8cab1593c6570db70a5f41483bd9db18498e4cde26ae1d862f06208ff8ca9475"
	testPubKeyHex  = "037545ddc4f44ede3e04636ac7523a7a27017ce1f7e70811fb5208d668b3b652d5"
	testChainID    = "tellor-test-1"
)

// startTestServer creates an in-memory gRPC server using the file signer backed by a
// temp keyring and returns a connected client along with a cleanup function.
func startTestServer(t *testing.T) (signerv1.BridgeSignerClient, func()) {
	return startTestServerChainID(t, testChainID)
}

// startTestServerChainID is startTestServer with an explicit chain ID so that
// GetChainID behaviour (configured vs. not) can be exercised.
func startTestServerChainID(t *testing.T, chainID string) (signerv1.BridgeSignerClient, func()) {
	t.Helper()

	keyringDir, pwFile := writeKeyringWithKey(t, testPrivKeyHex, "test-key")
	s, err := signer.NewFileSigner(keyringDir, "test-key", pwFile)
	if err != nil {
		t.Fatalf("NewFileSigner: %v", err)
	}

	log, err := logging.New("error", "json")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	srv := server.New(s, log, server.Config{
		ListenAddr:     "127.0.0.1:0",
		MaxRecvMsgSize: 4 * 1024 * 1024, // 4 MiB — same as gRPC default
		ChainID:        chainID,
	})

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
		grpc.WithTransportCredentials(insecure.NewCredentials()))
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

func TestServer_SignRaw(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	hash := sha256.Sum256([]byte("cosmos tx sign doc bytes"))

	resp, err := client.SignRaw(context.Background(), &signerv1.SignRawRequest{
		Msg:       hash[:],
		RequestId: "test-1",
	})
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}
	if len(resp.Signature) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(resp.Signature))
	}

	// Verify signature recovers to the expected public key.
	expectedPubKey, err := hex.DecodeString(testPubKeyHex)
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}

	recovered := false
	for _, v := range []byte{0, 1} {
		candidate := append(resp.Signature, v)
		pub, recErr := crypto.Ecrecover(hash[:], candidate)
		if recErr != nil {
			continue
		}
		x := new(big.Int).SetBytes(pub[1:33])
		y := new(big.Int).SetBytes(pub[33:65])
		key := ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
		if bytes.Equal(crypto.CompressPubkey(&key), expectedPubKey) {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Error("SignRaw: signature did not recover to expected public key")
	}
}

func TestServer_SignRaw_InvalidLength(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	_, err := client.SignRaw(context.Background(), &signerv1.SignRawRequest{
		Msg: []byte("not 32 bytes"),
	})
	if err == nil {
		t.Fatal("expected error for wrong-length input, got nil")
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
	if err == nil {
		t.Fatal("expected error for empty prefix, got nil")
	}
}

func TestServer_GetChainID(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.GetChainID(context.Background(), &signerv1.GetChainIDRequest{})
	if err != nil {
		t.Fatalf("GetChainID: %v", err)
	}
	if resp.ChainId != testChainID {
		t.Fatalf("ChainId = %q, want %q", resp.ChainId, testChainID)
	}
}

func TestServer_GetChainID_NotConfigured(t *testing.T) {
	// When no chain ID is configured, GetChainID must fail loudly with
	// FailedPrecondition rather than return an empty string.
	client, cleanup := startTestServerChainID(t, "")
	defer cleanup()

	_, err := client.GetChainID(context.Background(), &signerv1.GetChainIDRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
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
