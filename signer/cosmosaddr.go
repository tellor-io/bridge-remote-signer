package signer

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // RIPEMD-160 is not recommended for new protocols, but works fine for cosmos address derivation.
)

// CosmosAddresses derives both the account and validator operator
// bech32 addresses for the given compressed secp256k1 public key.
func CosmosAddresses(compressedPubKey []byte, prefix string) (account, valoper string, err error) {
	if len(compressedPubKey) != 33 {
		return "", "", fmt.Errorf("compressed pubkey must be 33 bytes, got %d", len(compressedPubKey))
	}
	if prefix == "" {
		return "", "", errors.New("prefix must not be empty")
	}

	// Cosmos SDK address derivation for secp256k1:
	//   addr20 = RIPEMD160(SHA256(compressed_pubkey))
	sha := sha256.Sum256(compressedPubKey)
	ripe := ripemd160.New()
	ripe.Write(sha[:])
	addr20 := ripe.Sum(nil)

	addr5, err := bech32.ConvertBits(addr20, 8, 5, true)
	if err != nil {
		return "", "", fmt.Errorf("convert address to 5 bit groups: %w", err)
	}

	account, err = bech32.Encode(prefix, addr5)
	if err != nil {
		return "", "", fmt.Errorf("encode account address: %w", err)
	}
	valoper, err = bech32.Encode(prefix+"valoper", addr5)
	if err != nil {
		return "", "", fmt.Errorf("encode valoper address: %w", err)
	}
	return account, valoper, nil
}
