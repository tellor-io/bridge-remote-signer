package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

const (
	testPrivKeyHex = "8cab1593c6570db70a5f41483bd9db18498e4cde26ae1d862f06208ff8ca9475"
	evmAddr        = "0xd58F4A6c7B4fD62C55D3319191F5B1B8178EFfa3"
	pubKeyHex      = "037545ddc4f44ede3e04636ac7523a7a27017ce1f7e70811fb5208d668b3b652d5"
	expectedSig    = "a9304dd7d9c48031910e8072a217eff7df789e22eb39380deb3007c7d32172895a0a1313f653e7d33996ededa0fcd3a97193c6fe849a16e99635bd66850891be"

	testKeyringPassword = "test-password-1234"
	testKeyName         = "test-bridge-key"
)

func TestFileSigner_SignAndRecover(t *testing.T) {
	expectedSigBytes, err := hex.DecodeString(expectedSig)
	requireNoError(t, err, "failed to decode expected signature")

	keyringDir, pwFile := writeKeyringWithKey(t, testPrivKeyHex, testKeyName)

	signer, err := NewFileSigner(keyringDir, testKeyName, pwFile, "")
	requireNoError(t, err, "NewFileSigner failed")

	msg := []byte("TellorLayer: Initial bridge signature A for operator tellorvaloper1test")
	msgHash := sha256.Sum256(msg)

	sig, err := signer.Sign(context.Background(), msgHash[:])
	requireNoError(t, err, "Sign failed")

	requireEqual(t, sig[:64], expectedSigBytes, "signature should not match expected signature because of different v value")
	// Verify length.
	requireLen(t, sig, 65)

	// Verify v is 27 or 28.
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("expected v=27 or v=28, got %d", sig[64])
	}

	// Recover and verify address.
	recoverable := make([]byte, 65)
	copy(recoverable, sig)
	recoverable[64] -= 27
	// because the Cosmos SDK keyring also hashes internally before signing
	doubleHash := sha256.Sum256(msgHash[:])

	pubkey, err := crypto.Ecrecover(doubleHash[:], recoverable)
	requireNoError(t, err, "Ecrecover failed")

	x := new(big.Int).SetBytes(pubkey[1:33])
	y := new(big.Int).SetBytes(pubkey[33:65])
	recoveredPubKey := ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
	recoveredAddr := crypto.PubkeyToAddress(recoveredPubKey)

	evmAddrBytes, err := hex.DecodeString(strings.TrimPrefix(evmAddr, "0x"))
	requireNoError(t, err, "failed to decode expected EVM address")
	requireEqual(t, recoveredAddr.Bytes(), evmAddrBytes, "recovered address is different from expected address")

	filePubKey, err := signer.GetPublicKey(context.Background())
	requireNoError(t, err, "GetPublicKey failed")

	expectedPubKeyBytes, err := hex.DecodeString(pubKeyHex)
	requireNoError(t, err, "failed to decode expected public key")
	requireEqual(t, filePubKey, expectedPubKeyBytes, "public key mismatch")
}

func TestFileSigner_SignRaw(t *testing.T) {
	keyringDir, pwFile := writeKeyringWithKey(t, testPrivKeyHex, testKeyName)

	signer, err := NewFileSigner(keyringDir, testKeyName, pwFile, "")
	requireNoError(t, err, "NewFileSigner failed")

	// Use a fixed 32-byte hash.
	hash := sha256.Sum256([]byte("test raw signing payload"))

	sig, err := signer.SignRaw(context.Background(), hash[:])
	requireNoError(t, err, "SignRaw failed")

	// Must be exactly 64 bytes (r || s), no v byte.
	requireLen(t, sig, 64)

	// Recover from the 64-byte signature and verify it matches the expected pubkey.
	// We need to try both possible v values (0 and 1) since SignRaw strips v.
	expectedPubKeyBytes, err := hex.DecodeString(pubKeyHex)
	requireNoError(t, err, "decode expected public key")

	recovered := false
	for _, v := range []byte{0, 1} {
		candidate := append(sig, v)
		pubKeyBytes, recErr := crypto.Ecrecover(hash[:], candidate)
		if recErr != nil {
			continue
		}
		x := new(big.Int).SetBytes(pubKeyBytes[1:33])
		y := new(big.Int).SetBytes(pubKeyBytes[33:65])
		recoveredKey := ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
		compressed := crypto.CompressPubkey(&recoveredKey)
		if bytes.Equal(compressed, expectedPubKeyBytes) {
			recovered = true
			break
		}
	}
	if !recovered {
		t.Error("SignRaw: could not recover expected public key from signature")
	}
}

func TestFileSigner_SignRaw_WrongLength(t *testing.T) {
	keyringDir, pwFile := writeKeyringWithKey(t, testPrivKeyHex, testKeyName)

	signer, err := NewFileSigner(keyringDir, testKeyName, pwFile, "")
	requireNoError(t, err, "NewFileSigner failed")

	_, err = signer.SignRaw(context.Background(), []byte("too short"))
	if err == nil {
		t.Error("expected error for wrong-length input, got nil")
	}
}

func writeKeyringWithKey(t *testing.T, keyHex, keyName string) (string, string) {
	t.Helper()

	dir := t.TempDir()
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(testKeyringPassword+"\n"), 0600); err != nil {
		t.Fatalf("write password file: %v", err)
	}

	// Repeat the password enough times to satisfy whatever read pattern
	// the keyring uses during init (it can prompt to set + confirm).
	passReader := strings.NewReader(strings.Repeat(testKeyringPassword+"\n", 4))
	cdc := MakeKeyringCodec()
	kr, err := keyring.New(sdk.KeyringServiceName(), keyring.BackendFile, dir, passReader, cdc)
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}

	if err := kr.ImportPrivKeyHex(keyName, keyHex, "secp256k1"); err != nil {
		t.Fatalf("import priv key: %v", err)
	}

	return dir, pwFile
}
