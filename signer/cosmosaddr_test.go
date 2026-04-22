package signer

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestCosmosAddresses_TellorReference verifies how layer derives addresses
func TestCosmosAddresses_TellorReference(t *testing.T) {
	// pubKeyHex corresponds to testPrivKeyHex in file_signer_test.go.
	const pubKeyHex = "037545ddc4f44ede3e04636ac7523a7a27017ce1f7e70811fb5208d668b3b652d5"
	const wantAccount = "tellor1j0dde7hxh4p5m604dwphtqfdhk4eaxlm4wyrgu"
	const wantValoper = "tellorvaloper1j0dde7hxh4p5m604dwphtqfdhk4eaxlmqpg33v"

	pub, err := hex.DecodeString(pubKeyHex)
	requireNoError(t, err, "decode pubkey")

	account, valoper, err := CosmosAddresses(pub, "tellor")
	requireNoError(t, err, "CosmosAddresses")

	if account != wantAccount {
		t.Errorf("account address mismatch\n  got:  %s\n  want: %s", account, wantAccount)
	}
	if valoper != wantValoper {
		t.Errorf("valoper address mismatch\n  got:  %s\n  want: %s", valoper, wantValoper)
	}
}

func TestCosmosAddresses_RejectsEmptyHRP(t *testing.T) {
	pub := make([]byte, 33)
	_, _, err := CosmosAddresses(pub, "")
	if err == nil {
		t.Fatal("expected error for empty HRP, got nil")
	}
	if !strings.Contains(err.Error(), "prefix must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}
