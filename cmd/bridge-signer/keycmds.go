package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tellor-io/bridge-remote-signer/signer"
	"golang.org/x/term"
)

// runKeygen generates a new secp256k1 private key and saves it to outPath,
// optionally encrypted with a password.
func runKeygen(outPath, passwordFile string) error {
	if outPath == "" {
		return errors.New("--out is required with --keygen")
	}
	ecdsaKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	return saveKey(crypto.FromECDSA(ecdsaKey), outPath, passwordFile)
}

// runImport reads a hex-encoded secp256k1 private key from stdin and saves
// it to outPath, optionally encrypted with a password.
func runImport(outPath, passwordFile string) error {
	if outPath == "" {
		return errors.New("--out is required with --import")
	}

	fmt.Fprint(os.Stderr, "Paste private key (hex): ")
	hexInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	hexStr := strings.TrimSpace(hexInput)
	hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")

	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}
	if _, err := crypto.ToECDSA(keyBytes); err != nil {
		return fmt.Errorf("invalid secp256k1 key: %w", err)
	}

	return saveKey(keyBytes, outPath, passwordFile)
}

// saveKey writes keyBytes to outPath. If a password is supplied (via file or
// terminal prompt), the key is encrypted; an empty password saves plaintext.
// Refuses to overwrite an existing file.
func saveKey(keyBytes []byte, outPath, passwordFile string) error {
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("file %s already exists (refusing to overwrite)", outPath)
	}

	password, err := readPassword(passwordFile)
	if err != nil {
		return err
	}

	if password != "" {
		if err := signer.EncryptAndSaveKey(keyBytes, password, outPath); err != nil {
			return fmt.Errorf("save encrypted key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Encrypted key saved to %s\n", outPath)
	} else {
		if err := signer.SavePlaintextKey(keyBytes, outPath); err != nil {
			return fmt.Errorf("save key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Key saved to %s (plaintext, no password)\n", outPath)
	}

	return printAddresses(os.Stderr, keyBytes)
}

// runExport reads a key file (encrypted or plaintext), decrypts it if
// needed, and writes the raw 64 character hex encoding of the private
// key to stdout.
func runExport(keyPath, passwordFile string) error {
	if keyPath == "" {
		return errors.New("--key is required with --export")
	}

	encrypted, err := signer.IsKeyFileEncrypted(keyPath)
	if err != nil {
		return fmt.Errorf("check key file: %w", err)
	}

	password := ""
	if encrypted {
		password, err = readPasswordForUnlock(passwordFile)
		if err != nil {
			return err
		}
		if password == "" {
			return errors.New("key file is encrypted; a password is required")
		}
	}

	privateKey, err := signer.LoadPrivateKey(keyPath, password)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	fmt.Fprintln(os.Stderr, "WARNING: emitting raw private key hex to stdout. Redirect to a file or pipe to a secure destination; anything that captures stdout gets the key.")
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(privateKey)))
	return nil
}

// runShow reads a key file (encrypted or plaintext) and prints the
// addresses derived from the key to stdout.
func runShow(keyPath, passwordFile string) error {
	if keyPath == "" {
		return errors.New("--key is required with --show")
	}

	encrypted, err := signer.IsKeyFileEncrypted(keyPath)
	if err != nil {
		return fmt.Errorf("check key file: %w", err)
	}

	password := ""
	if encrypted {
		password, err = readPasswordForUnlock(passwordFile)
		if err != nil {
			return err
		}
		if password == "" {
			return errors.New("key file is encrypted; a password is required")
		}
	}

	privateKey, err := signer.LoadPrivateKey(keyPath, password)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	return printAddresses(os.Stdout, crypto.FromECDSA(privateKey))
}

// printAddresses writes the public key hex, EVM address, Tellor
// bech32, and Tellor valoper bech32 for the given private key.
func printAddresses(w io.Writer, keyBytes []byte) error {
	ecdsaKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	compressedPub := crypto.CompressPubkey(&ecdsaKey.PublicKey)
	evmAddr := crypto.PubkeyToAddress(ecdsaKey.PublicKey)
	accAddr, valAddr, err := signer.CosmosAddresses(compressedPub, "tellor")
	if err != nil {
		return fmt.Errorf("derive tellor addresses: %w", err)
	}
	fmt.Fprintf(w, "Public key:       %s\n", hex.EncodeToString(compressedPub))
	fmt.Fprintf(w, "EVM address:      %s\n", evmAddr.Hex())
	fmt.Fprintf(w, "Tellor account:   %s\n", accAddr)
	fmt.Fprintf(w, "Tellor valoper:   %s\n", valAddr)
	return nil
}

// readPasswordForUnlock reads a password intended to decrypt an
// existing key file. Unlike readPassword it does not prompt for
// confirmation.
func readPasswordForUnlock(passwordFile string) (string, error) {
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	fmt.Fprint(os.Stderr, "Enter password to unlock key file: ")
	passBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimSpace(string(passBytes)), nil
}

// readPassword returns the password to use for key encryption. If passwordFile
// is set, it is read from disk; otherwise the user is prompted. An empty result
// from either source means "no encryption".
func readPassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return promptPassword()
}

// promptPassword prompts twice for a password and confirms they match.
// Returns "" (no encryption) if the user submits an empty password.
func promptPassword() (string, error) {
	fmt.Fprint(os.Stderr, "Enter password (leave empty for no encryption): ")
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	password := strings.TrimSpace(string(pass1))
	if password == "" {
		return "", nil
	}

	fmt.Fprint(os.Stderr, "Confirm password: ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if string(pass1) != string(pass2) {
		return "", errors.New("passwords do not match")
	}
	return password, nil
}
