package signer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/argon2"
)

// Argon2id defaults for new files (https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice FIRST RECOMMENDED).
const (
	argon2Time    = 1
	argon2Memory  = 2 * 1024 * 1024 // KiB (= 2 GiB)
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// Upper bounds accepted when loading a file (DoS guard against tampered params).
const (
	maxArgon2Time    = 10
	maxArgon2Memory  = 4 * 1024 * 1024 // KiB (= 4 GiB)
	maxArgon2Threads = 16
)

var ErrWrongPassword = errors.New("decryption failed: wrong password or corrupted file")

const envelopeVersion = 1

type kdfParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
}

type encryptedKeyFile struct {
	Version    int       `json:"version"`
	Cipher     string    `json:"cipher"`
	KDF        string    `json:"kdf"`
	KDFParams  kdfParams `json:"kdf_params"`
	Salt       string    `json:"salt"`
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
}

// buildAAD returns metadata bound into GCM so field tampering fails auth.
// Must produce identical bytes on encrypt and decrypt.
func buildAAD(ekf *encryptedKeyFile) []byte {
	return fmt.Appendf(nil,
		"v=%d|cipher=%s|kdf=%s|t=%d|m=%d|p=%d|salt=%s",
		ekf.Version, ekf.Cipher, ekf.KDF,
		ekf.KDFParams.Time, ekf.KDFParams.Memory, ekf.KDFParams.Threads,
		ekf.Salt,
	)
}

// writeFileAtomic writes via temp file + fsync + rename so a crash can't
// leave a truncated key file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".keyfile-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpPath)
		}
	}()

	if _, err = f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}

// EncryptAndSaveKey derives an AES-256 key from password via Argon2id and
// writes the key encrypted with AES-256-GCM to path (mode 0600, atomic).
func EncryptAndSaveKey(keyBytes []byte, password string, path string) error {
	if len(keyBytes) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	derivedKey := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ekf := encryptedKeyFile{
		Version: envelopeVersion,
		Cipher:  "aes-256-gcm",
		KDF:     "argon2id",
		KDFParams: kdfParams{
			Time:    argon2Time,
			Memory:  argon2Memory,
			Threads: argon2Threads,
		},
		Salt:  hex.EncodeToString(salt),
		Nonce: hex.EncodeToString(nonce),
	}

	ciphertext := gcm.Seal(nil, nonce, keyBytes, buildAAD(&ekf))
	ekf.Ciphertext = hex.EncodeToString(ciphertext)

	data, err := json.MarshalIndent(ekf, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted key: %w", err)
	}
	return writeFileAtomic(path, data, 0600)
}

// SavePlaintextKey writes the raw 32-byte key as hex (mode 0600, atomic).
func SavePlaintextKey(keyBytes []byte, path string) error {
	if len(keyBytes) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}
	hexStr := hex.EncodeToString(keyBytes) + "\n"
	return writeFileAtomic(path, []byte(hexStr), 0600)
}

// LoadPrivateKey reads a key file (encrypted JSON or plaintext hex, detected
// from the first non-whitespace byte) and returns the parsed secp256k1 key.
// password is required for encrypted files, ignored for plaintext.
func LoadPrivateKey(path string, password string) (*ecdsa.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat key file: %w", err)
	}
	// Reject group/other-readable files.
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return nil, fmt.Errorf(
			"key file %s has permissions %04o; must not be readable by group or others (expected 0600)",
			path, perm,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %w", err)
	}
	content := strings.TrimSpace(string(data))

	if len(content) > 0 && content[0] == '{' {
		return loadEncryptedKey([]byte(content), password)
	}
	return loadPlaintextKey(content)
}

// IsKeyFileEncrypted reports whether the file is in encrypted JSON format.
func IsKeyFileEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	content := strings.TrimSpace(string(data))
	return len(content) > 0 && content[0] == '{', nil
}

func loadEncryptedKey(data []byte, password string) (*ecdsa.PrivateKey, error) {
	if password == "" {
		return nil, fmt.Errorf("key file is encrypted but no password provided")
	}

	var ekf encryptedKeyFile
	if err := json.Unmarshal(data, &ekf); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}

	if ekf.Version != envelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version: %d (want %d)", ekf.Version, envelopeVersion)
	}
	if ekf.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("unsupported cipher: %s", ekf.Cipher)
	}
	if ekf.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported KDF: %s", ekf.KDF)
	}

	// Bounds check: reject corrupted/tampered params that would hang.
	p := ekf.KDFParams
	if p.Time == 0 || p.Time > maxArgon2Time ||
		p.Memory == 0 || p.Memory > maxArgon2Memory ||
		p.Threads == 0 || p.Threads > maxArgon2Threads {
		return nil, fmt.Errorf(
			"kdf_params out of range: time=%d memory=%d threads=%d",
			p.Time, p.Memory, p.Threads,
		)
	}

	salt, err := hex.DecodeString(ekf.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt hex: %w", err)
	}
	nonce, err := hex.DecodeString(ekf.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}
	ciphertext, err := hex.DecodeString(ekf.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext hex: %w", err)
	}

	derivedKey := argon2.IDKey(
		[]byte(password), salt,
		p.Time, p.Memory, p.Threads,
		argon2KeyLen,
	)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	keyBytes, err := gcm.Open(nil, nonce, ciphertext, buildAAD(&ekf))
	if err != nil {
		return nil, ErrWrongPassword
	}

	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("decrypted key must be 32 bytes, got %d", len(keyBytes))
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 private key: %w", err)
	}
	return privateKey, nil
}

func loadPlaintextKey(hexStr string) (*ecdsa.PrivateKey, error) {
	hexStr = strings.TrimPrefix(strings.ToLower(hexStr), "0x")

	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("key file contains invalid hex: %w", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(keyBytes))
	}

	privateKey, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid secp256k1 private key: %w", err)
	}
	return privateKey, nil
}
